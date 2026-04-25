"""
Certificate Transparency Feed
Watches crt.sh for new TLS certificates matching monitored domains.
Free, no API key required.

Useful for detecting:
  - Phishing domains that spoof your brand (e.g. login-acme.com)
  - Typosquatting variants issued a real certificate
  - Unexpected subdomains of owned domains
"""

import hashlib
import logging
import os
import time
from datetime import datetime, timezone, timedelta
from typing import Any

import requests

from .base import BaseFeed

log = logging.getLogger(__name__)

REQUEST_TIMEOUT = 10  # seconds
_CRT_URL = "https://crt.sh/"


def _get_db_session():
    """Open a fresh DB session using the same connection settings as models.py."""
    from models import SessionLocal
    return SessionLocal()


class CertTransparencyFeed(BaseFeed):
    """
    Polls crt.sh for TLS certificates matching every domain in watched_assets.
    Results include the certificate common name, issuer, validity window, and a
    SHA-256 fingerprint of the crt.sh entry id for deduplication.
    """

    name             = "cert_transparency"
    interval_seconds = 3600  # 1 hour

    def fetch(self) -> list[dict[str, Any]]:
        db = _get_db_session()
        try:
            return self._fetch_with_db(db)
        finally:
            db.close()

    def _fetch_with_db(self, db) -> list[dict[str, Any]]:
        # ── Load watched domains from DB ──────────────────────────────────────
        try:
            from models import WatchedAsset
            assets = (
                db.query(WatchedAsset)
                .filter_by(active=True, asset_type="domain")
                .all()
            )
            domains = [a.value.strip().lower() for a in assets if a.value]
        except Exception as exc:
            log.warning(f"[cert_transparency] Could not load watched domains: {exc}")
            domains = []

        # Fall back to env var for standalone testing
        if not domains:
            env_domains = os.getenv("CT_WATCH_DOMAINS", "")
            domains = [d.strip() for d in env_domains.split(",") if d.strip()]

        if not domains:
            log.debug("[cert_transparency] No domains configured — nothing to watch.")
            return []

        log.info(f"[cert_transparency] Checking {len(domains)} domain(s) on crt.sh...")
        all_certs: list[dict[str, Any]] = []

        session = requests.Session()
        session.headers["User-Agent"] = (
            "Mozilla/5.0 (compatible; VantelligenceCT/1.0; +security-research)"
        )

        # Only surface certs issued in the last 90 days to avoid noise
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)

        for domain in domains:
            certs = self._query_crtsh(domain, session, cutoff)
            all_certs.extend(certs)
            log.debug(f"[cert_transparency] '{domain}' → {len(certs)} cert(s)")
            time.sleep(1)  # polite crawl delay

        log.info(f"[cert_transparency] Found {len(all_certs)} certificate(s) across {len(domains)} domain(s).")
        return all_certs

    def _query_crtsh(
        self,
        domain: str,
        session: requests.Session,
        cutoff: datetime,
    ) -> list[dict[str, Any]]:
        """
        Query crt.sh for certificates matching *.domain and domain.
        Returns a list of cert dicts ready for the worker to process.
        """
        results: list[dict[str, Any]] = []
        try:
            resp = session.get(
                _CRT_URL,
                params={"q": f"%.{domain}", "output": "json"},
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code == 404:
                return results
            resp.raise_for_status()
            entries = resp.json()
        except requests.RequestException as exc:
            log.warning(f"[cert_transparency] crt.sh request failed for '{domain}': {exc}")
            return results
        except ValueError as exc:
            log.warning(f"[cert_transparency] JSON parse error for '{domain}': {exc}")
            return results

        seen_ids: set[int] = set()

        for entry in entries:
            crt_id = entry.get("id")
            if crt_id in seen_ids:
                continue
            seen_ids.add(crt_id)

            not_before_str = entry.get("not_before") or ""
            # Skip certs outside our lookback window
            if not_before_str:
                try:
                    nb = datetime.fromisoformat(not_before_str.replace("Z", "+00:00"))
                    # Ensure offset-aware for comparison (assume UTC if no tz)
                    if nb.tzinfo is None:
                        nb = nb.replace(tzinfo=timezone.utc)
                    if nb < cutoff:
                        continue
                except ValueError:
                    pass  # Unparseable date — include anyway

            fp = hashlib.sha256(str(crt_id).encode()).hexdigest()

            results.append({
                "domain_matched": domain,
                "common_name":    (entry.get("common_name") or "")[:255],
                "issuer":         (entry.get("issuer_name") or "")[:512],
                "not_before":     not_before_str,
                "not_after":      entry.get("not_after") or "",
                "fingerprint":    fp,
                # Pass through for worker storage
                "source_name":    "cert_transparency",
                "crt_id":         crt_id,
            })

        return results
