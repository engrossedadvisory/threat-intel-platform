"""
GitHub Monitor
Searches GitHub for accidental exposure of org credentials, API keys, or domain references.
Requires GITHUB_TOKEN in platform_settings or env.

Safety design:
  - Only metadata stored (repo name, file path, URL, sanitised snippet).
  - Actual secret values are NEVER saved — the sanitiser strips them before storage.
  - Max 10 results per keyword query.
  - Rate-limit aware: checks X-RateLimit-Remaining header and backs off if needed.
"""

import hashlib
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Optional

import requests

from .base import BaseFeed

log = logging.getLogger(__name__)

REQUEST_TIMEOUT = 10  # seconds
MAX_RESULTS_PER_KEYWORD = 10
SNIPPET_CHARS = 500

# ─── Secret patterns to sanitise BEFORE storage ──────────────────────────────

_SECRET_PATTERNS = [
    re.compile(r'(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret'
               r'|auth[_-]?token|bearer)\s*[=:]\s*["\']?([A-Za-z0-9+/\-_\.]{16,})["\']?'),
    re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?(\S{8,})["\']?'),
    re.compile(r'(?i)(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*([A-Za-z0-9+/]{16,})'),
    re.compile(r'ghp_[A-Za-z0-9]{36}'),           # GitHub PAT
    re.compile(r'sk-[A-Za-z0-9]{32,}'),            # OpenAI key
    re.compile(r'AKIA[A-Z0-9]{16}'),               # AWS access key ID
    re.compile(r'(?i)-----BEGIN (RSA |EC )?PRIVATE KEY-----'),
]

# ─── Severity detection ───────────────────────────────────────────────────────

_CRITICAL_PATTERNS = re.compile(
    r'(?i)(private.?key|rsa.?key|BEGIN.PRIVATE|aws.secret|AKIA[A-Z0-9]{16}'
    r'|database.password|db.?pass|connection.?string)',
)
_HIGH_PATTERNS = re.compile(
    r'(?i)(api.?key|secret.?key|access.?token|auth.?token|client.?secret'
    r'|password|passwd|bearer)',
)


def _sanitise_snippet(text: str) -> str:
    """Strip secret values from a code snippet before it is ever stored."""
    for pat in _SECRET_PATTERNS:
        # Replace full match with a redaction placeholder
        text = pat.sub("[REDACTED]", text)
    return text[:SNIPPET_CHARS]


def _severity_from_snippet(snippet: str) -> str:
    if _CRITICAL_PATTERNS.search(snippet):
        return "critical"
    if _HIGH_PATTERNS.search(snippet):
        return "high"
    return "medium"


def _fingerprint(repo: str, path: str, keyword: str) -> str:
    """SHA-256 of repo + path + keyword for deduplication."""
    raw = f"{repo}|{path}|{keyword.lower()}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _get_token(db) -> str:
    """Read GITHUB_TOKEN from platform_settings or env."""
    try:
        from settings import get_setting
        token = get_setting("github_token", db) or os.getenv("GITHUB_TOKEN", "")
    except Exception:
        token = os.getenv("GITHUB_TOKEN", "")
    return token


def _get_db_session():
    from models import SessionLocal
    return SessionLocal()


def _rate_limit_wait(resp: requests.Response) -> None:
    """Sleep if we are approaching the GitHub search rate limit."""
    try:
        remaining = int(resp.headers.get("X-RateLimit-Remaining", 10))
        if remaining < 3:
            reset_ts = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
            wait = max(0, reset_ts - int(time.time())) + 2
            log.warning(f"[github_monitor] Rate limit low ({remaining} remaining) — waiting {wait}s.")
            time.sleep(wait)
    except Exception:
        time.sleep(5)


class GithubMonitorFeed(BaseFeed):
    """
    Searches GitHub code for references to watched keywords and domain names.
    Only metadata (repo, path, URL, sanitised snippet) is stored — never raw secrets.
    """

    name             = "github_monitor"
    interval_seconds = 7200  # 2 hours

    def fetch(self) -> list[dict[str, Any]]:
        db = _get_db_session()
        try:
            return self._fetch_with_db(db)
        finally:
            db.close()

    def _fetch_with_db(self, db) -> list[dict[str, Any]]:
        token = _get_token(db)
        if not token:
            log.debug("[github_monitor] No GITHUB_TOKEN configured — skipping.")
            return []

        # ── Load watched keywords and domains ────────────────────────────────
        try:
            from models import WatchedAsset
            assets = (
                db.query(WatchedAsset)
                .filter_by(active=True)
                .filter(WatchedAsset.asset_type.in_(["keyword", "domain"]))
                .all()
            )
            search_terms = [a.value.strip() for a in assets if a.value]
        except Exception as exc:
            log.warning(f"[github_monitor] Could not load watched assets: {exc}")
            search_terms = []

        # Env var fallback for standalone testing
        if not search_terms:
            env_kw = os.getenv("GITHUB_MONITOR_KEYWORDS", "")
            search_terms = [k.strip() for k in env_kw.split(",") if k.strip()]

        if not search_terms:
            log.debug("[github_monitor] No keywords or domains configured — nothing to search.")
            return []

        log.info(f"[github_monitor] Searching GitHub for {len(search_terms)} term(s)...")

        session = requests.Session()
        session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept":        "application/vnd.github.v3+json",
            "User-Agent":    "VantelligenceGHMonitor/1.0",
        })

        all_results: list[dict[str, Any]] = []

        for keyword in search_terms:
            results = self._search_keyword(keyword, session)
            all_results.extend(results)
            log.debug(f"[github_monitor] '{keyword}' → {len(results)} result(s).")
            time.sleep(2)  # GitHub search API allows ~10 unauthenticated, 30 authenticated req/min

        log.info(f"[github_monitor] Total results: {len(all_results)}")
        return all_results

    def _search_keyword(self, keyword: str, session: requests.Session) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        try:
            resp = session.get(
                "https://api.github.com/search/code",
                params={"q": f"{keyword} in:file", "per_page": MAX_RESULTS_PER_KEYWORD},
                timeout=REQUEST_TIMEOUT,
            )

            _rate_limit_wait(resp)

            if resp.status_code == 403:
                log.warning("[github_monitor] 403 Forbidden — check GITHUB_TOKEN scopes.")
                return results
            if resp.status_code == 422:
                log.debug(f"[github_monitor] Search term '{keyword}' rejected by GitHub (422).")
                return results
            resp.raise_for_status()

            data = resp.json()
            items = data.get("items", [])

        except requests.RequestException as exc:
            log.warning(f"[github_monitor] Search request failed for '{keyword}': {exc}")
            return results

        for item in items:
            repo_full  = item.get("repository", {}).get("full_name", "unknown/unknown")
            file_path  = item.get("path", "")
            html_url   = item.get("html_url", "")
            raw_url    = (item.get("url") or "").replace(
                "https://api.github.com/repos/", "https://raw.githubusercontent.com/"
            ).replace("/contents/", "/")

            # ── Fetch a small snippet of the file ────────────────────────────
            snippet = self._fetch_snippet(raw_url, session)
            clean_snippet = _sanitise_snippet(snippet)
            severity = _severity_from_snippet(clean_snippet)

            fp = _fingerprint(repo_full, file_path, keyword)
            results.append({
                "source_name":    "github_monitor",
                "keyword":        keyword,
                "repo":           repo_full,
                "file_path":      file_path,
                "html_url":       html_url[:1024],
                "snippet":        clean_snippet,     # sanitised — no real secrets
                "severity":       severity,
                "fingerprint":    fp,
                "discovered_at":  datetime.now(timezone.utc).isoformat(),
            })

        return results

    def _fetch_snippet(self, raw_url: str, session: requests.Session) -> str:
        """
        Download the first SNIPPET_CHARS of a raw GitHub file.
        Returns empty string on any error.
        """
        if not raw_url:
            return ""
        try:
            resp = session.get(raw_url, timeout=REQUEST_TIMEOUT, stream=True)
            if resp.status_code != 200:
                return ""
            # Read only the first SNIPPET_CHARS bytes
            content = b""
            for chunk in resp.iter_content(chunk_size=512):
                content += chunk
                if len(content) >= SNIPPET_CHARS:
                    break
            return content.decode("utf-8", errors="replace")[:SNIPPET_CHARS]
        except Exception as exc:
            log.debug(f"[github_monitor] Snippet fetch failed: {exc}")
            return ""
