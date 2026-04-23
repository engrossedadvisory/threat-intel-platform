"""
Dark Web Monitor Feed
─────────────────────
Monitors publicly accessible dark web indexes for mentions of configured keywords
(typically your organisation's domains, IPs, brand names).

Sources used (in priority order):
  1. Ahmia.fi   — clearnet search engine indexing .onion sites (no Tor required)
  2. Tor SOCKS5 — direct .onion fetches via tor-proxy container (if reachable)

Safety design:
  • Only metadata is stored — titles, snippets, actor handles, record estimates.
  • A PII sanitiser strips emails, SSNs, card numbers BEFORE anything is stored.
  • Raw breach content is NEVER written to disk or the database.
  • No authentication to any dark-web site.
  • Disabled by default (DARK_WEB_ENABLED=false).
"""

import hashlib
import logging
import os
import re
import time
from typing import Optional

import requests
from bs4 import BeautifulSoup

from .base import BaseFeed

log = logging.getLogger(__name__)

# ─── Module-level defaults (env vars used as initial fallback only) ───────────
# The DarkWebFeed.configure() method overrides these at runtime from the DB.

TOR_PROXY_URL = os.getenv("TOR_PROXY_URL", "socks5h://tor-proxy:9050")

# ─── PII sanitiser ────────────────────────────────────────────────────────────

_PII_RE = [
    re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),    # email
    re.compile(r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'),                           # SSN
    re.compile(r'\b(?:\d{4}[\s\-]?){4}\b'),                                   # card number
    re.compile(r'\b\d{3}[\s.\-]?\d{3}[\s.\-]?\d{4}\b'),                       # phone (US)
    re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'),                                     # passport (rough)
    re.compile(r'\b(?:password|passwd|pwd)\s*[:=]\s*\S+', re.IGNORECASE),     # inline creds
]

def _sanitize(text: str, max_len: int = 500) -> str:
    """Strip PII patterns from text before storage. Hard-truncates to max_len."""
    for pat in _PII_RE:
        text = pat.sub("[REDACTED]", text)
    return text[:max_len]


# ─── Severity & data-type classification ─────────────────────────────────────

_SEV_CRITICAL = re.compile(
    r'\b(ssn|social.security|passport|medical.record|health.record|hipaa|'
    r'government.database|military|credit.card|cvv|full.card|bank.account|'
    r'routing.number|classified|pii.database|taxpayer)\b',
    re.IGNORECASE,
)
_SEV_HIGH = re.compile(
    r'\b(password|credential|hash|dump|breach|database.leak|full.name|'
    r'date.of.birth|dob|driver.licen|account.takeover|login|api.key|'
    r'private.key|secret.key|oauth|2fa|mfa.bypass)\b',
    re.IGNORECASE,
)
_SEV_MEDIUM = re.compile(
    r'\b(email.?list|username|phone.?number|address|ip.?address|zip.?code|'
    r'token|session|cookie|vpn|access.?log)\b',
    re.IGNORECASE,
)

_DATA_TYPE_MAP = {
    "email":    re.compile(r'\bema(?:il)?s?\b', re.IGNORECASE),
    "password": re.compile(r'\bpass(?:word)?s?\b|\bhash(?:es)?\b|\bcredential', re.IGNORECASE),
    "ssn":      re.compile(r'\bssn\b|\bsocial.security', re.IGNORECASE),
    "dob":      re.compile(r'\bdob\b|\bdate.of.birth\b', re.IGNORECASE),
    "phone":    re.compile(r'\bphone\b|\bmobile\b', re.IGNORECASE),
    "address":  re.compile(r'\baddress(?:es)?\b|\bstreet\b|\bzip\b', re.IGNORECASE),
    "card":     re.compile(r'\bcredit.card\b|\bcvv\b|\bcard.number\b', re.IGNORECASE),
    "bank":     re.compile(r'\bbank.?account\b|\brouting\b|\biban\b', re.IGNORECASE),
    "passport": re.compile(r'\bpassport\b', re.IGNORECASE),
    "medical":  re.compile(r'\bmedical\b|\bhealth(?:care)?\b|\bpatient\b|\bhipaa\b', re.IGNORECASE),
    "api_key":  re.compile(r'\bapi.?key\b|\bsecret.?key\b|\btoken\b', re.IGNORECASE),
}

def _classify(text: str) -> tuple[str, list[str]]:
    """Return (severity, [data_type, ...]) for a text snippet."""
    severity = "low"
    combined = text.lower()
    if _SEV_CRITICAL.search(combined):
        severity = "critical"
    elif _SEV_HIGH.search(combined):
        severity = "high"
    elif _SEV_MEDIUM.search(combined):
        severity = "medium"

    dtypes = [dt for dt, pat in _DATA_TYPE_MAP.items() if pat.search(combined)]
    return severity, dtypes


# ─── Record count extractor ───────────────────────────────────────────────────

_COUNT_RE = re.compile(
    r'(\d[\d,\.]+)\s*(?:k\b)?\s*(?:records?|users?|accounts?|rows?|entries|lines?|credentials?)',
    re.IGNORECASE,
)

def _extract_count(text: str) -> Optional[str]:
    m = _COUNT_RE.search(text)
    return m.group(0)[:60] if m else None


# ─── Actor handle extractor ───────────────────────────────────────────────────

_ACTOR_RE = re.compile(
    r'(?:posted?\s+by|author|seller|uploaded?\s+by|by\s+user)[:\s]+([^\s<\n\|]{3,40})',
    re.IGNORECASE,
)

def _extract_actor(text: str) -> str:
    m = _ACTOR_RE.search(text)
    return m.group(1).strip()[:50] if m else "Unknown"


# ─── Deduplication fingerprint ────────────────────────────────────────────────

def _fingerprint(source_url: str, keyword: str, title: str) -> str:
    raw = f"{source_url.strip()}|{keyword.strip().lower()}|{title.strip().lower()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:64]


# ─── HTTP sessions ────────────────────────────────────────────────────────────

def _clearnet_session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = (
        "Mozilla/5.0 (compatible; VantelligenceThreatIntel/1.0; +security-research)"
    )
    return s


def _tor_session() -> Optional[requests.Session]:
    """Return a requests.Session routed through the Tor SOCKS5 proxy, or None if unreachable."""
    try:
        s = requests.Session()
        s.proxies = {"http": TOR_PROXY_URL, "https": TOR_PROXY_URL}
        s.headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
        )
        # Quick reachability check via Tor check service
        r = s.get("https://check.torproject.org/api/ip", timeout=10)
        data = r.json()
        if data.get("IsTor"):
            log.info("[darkweb] Tor proxy reachable — running as Tor exit node.")
            return s
        log.debug("[darkweb] Tor proxy responding but IsTor=false — using anyway.")
        return s
    except Exception as exc:
        log.debug(f"[darkweb] Tor proxy unreachable ({exc}) — Tor-based sources skipped.")
        return None


# ─── Source 1: Ahmia.fi (clearnet .onion search index) ───────────────────────

def _search_ahmia(keyword: str, session: requests.Session) -> list[dict]:
    """
    Search Ahmia.fi for dark-web pages mentioning the keyword.
    Ahmia is a legitimate clearnet search engine that indexes .onion sites.
    No Tor required; no login; publicly accessible.
    """
    results = []
    try:
        resp = session.get(
            "https://ahmia.fi/search/",
            params={"q": keyword},
            timeout=20,
        )
        resp.raise_for_status()
    except Exception as exc:
        log.debug(f"[darkweb/ahmia] Search failed for '{keyword}': {exc}")
        return results

    soup = BeautifulSoup(resp.text, "html.parser")

    # Ahmia result items: <li class="result"> ... <h4><a href="...">Title</a></h4> ... <p>desc</p>
    for item in (soup.select("li.result") or soup.select("div.result"))[:12]:
        a_el    = item.select_one("h4 a") or item.select_one("a[href]")
        desc_el = item.select_one("p.description") or item.select_one("p")

        if not a_el:
            continue

        title   = a_el.get_text(strip=True)[:300] or "Untitled"
        url     = a_el.get("href", "")[:500]
        snippet = desc_el.get_text(strip=True) if desc_el else ""
        snippet = _sanitize(snippet)

        combined = f"{title} {snippet}"
        severity, dtypes = _classify(combined)
        count_est = _extract_count(combined)
        actor     = _extract_actor(combined)

        results.append({
            "source_name":     "Ahmia",
            "source_url":      url,
            "keyword_matched": keyword,
            "title":           _sanitize(title, 300),
            "snippet":         snippet,
            "actor_handle":    actor,
            "record_estimate": count_est,
            "data_types":      dtypes,
            "severity":        severity,
        })

    log.debug(f"[darkweb/ahmia] '{keyword}' → {len(results)} results")
    return results


# ─── Source 2: Tor2Web proxy fallback ────────────────────────────────────────

_TOR2WEB_GATEWAYS = [
    "https://onion.ws",
    "https://onion.pet",
]

def _search_via_tor2web(keyword: str, onion_url: str, session: requests.Session) -> list[dict]:
    """
    Fetch a specific .onion page via a tor2web clearnet gateway as fallback.
    Only fetches the listing/index page — never follows download links.
    """
    results = []
    for gw in _TOR2WEB_GATEWAYS:
        # Convert http://abc.onion/path → https://abc.onion.ws/path
        onion_host = onion_url.replace("http://", "").replace("https://", "").split("/")[0]
        path = "/" + "/".join(onion_url.split("/")[3:])
        proxy_url = f"{gw}/{onion_host}{path}?q={keyword}"
        try:
            resp = session.get(proxy_url, timeout=15)
            if resp.ok:
                soup = BeautifulSoup(resp.text, "html.parser")
                title = soup.find("title")
                title_text = title.get_text(strip=True)[:300] if title else "Unknown"
                # First paragraph as snippet
                p = soup.find("p")
                snippet = _sanitize(p.get_text(strip=True)) if p else ""

                combined = f"{title_text} {snippet}"
                severity, dtypes = _classify(combined)

                results.append({
                    "source_name":     f"Onion/{onion_host[:30]}",
                    "source_url":      onion_url[:500],
                    "keyword_matched": keyword,
                    "title":           _sanitize(title_text, 300),
                    "snippet":         snippet,
                    "actor_handle":    _extract_actor(combined),
                    "record_estimate": _extract_count(combined),
                    "data_types":      dtypes,
                    "severity":        severity,
                })
                break  # got a result, no need to try next gateway
        except Exception as exc:
            log.debug(f"[darkweb/tor2web] {gw} failed: {exc}")
    return results


# ─── Source 3: Direct .onion via Tor proxy ────────────────────────────────────


def _fetch_onion(url: str, keyword: str, tor: requests.Session) -> list[dict]:
    """Fetch a single .onion search/index page via Tor SOCKS5. Metadata only."""
    try:
        resp = tor.get(
            url,
            params={"q": keyword, "query": keyword, "search": keyword},
            timeout=45,
        )
        resp.raise_for_status()
    except Exception as exc:
        log.debug(f"[darkweb/tor] {url} failed: {exc}")
        return []

    soup   = BeautifulSoup(resp.text, "html.parser")
    results = []

    for a in soup.find_all("a", href=True)[:20]:
        title   = a.get_text(strip=True)[:200]
        href    = a["href"][:500]
        # Skip navigation / non-content links
        if len(title) < 8 or any(nav in title.lower() for nav in
                                  ("home", "about", "login", "register", "back", "next", "prev")):
            continue
        # Only keep links that contain the keyword or look like listing items
        if keyword.lower() not in title.lower() and keyword.lower() not in href.lower():
            # Check sibling text
            parent_text = a.parent.get_text(strip=True) if a.parent else ""
            if keyword.lower() not in parent_text.lower():
                continue

        snippet  = _sanitize(a.parent.get_text(strip=True) if a.parent else "")
        combined = f"{title} {snippet}"
        severity, dtypes = _classify(combined)

        results.append({
            "source_name":     url.split("/")[2][:40],   # .onion domain
            "source_url":      href if href.startswith("http") else url,
            "keyword_matched": keyword,
            "title":           _sanitize(title, 300),
            "snippet":         snippet,
            "actor_handle":    _extract_actor(combined),
            "record_estimate": _extract_count(combined),
            "data_types":      dtypes,
            "severity":        severity,
        })

    return results[:8]   # cap per source


# ─── Feed class ───────────────────────────────────────────────────────────────

class DarkWebFeed(BaseFeed):
    """Dark web monitoring feed.

    Runtime config is injected by the worker via configure() before every run,
    pulling values from the platform_settings DB table (set in the WebUI admin
    panel).  Env vars are used as fallback when no DB row exists.
    """
    name = "darkweb"

    def __init__(self):
        # Load initial config from env vars; worker will call configure() to
        # override from DB before each fetch.
        self._enabled       = False
        self._keywords:     list[str] = []
        self._onion_sources: list[str] = []
        self.interval_seconds = int(os.getenv("DARK_WEB_INTERVAL", str(6 * 3600)))

    def configure(self, settings: dict) -> None:
        """Apply runtime settings from the DB (called by worker before fetch)."""
        self._enabled = settings.get("dark_web_enabled", "false").lower() in ("1", "true", "yes")
        kw_raw        = settings.get("dark_web_keywords", "")
        self._keywords = [k.strip() for k in kw_raw.split(",") if k.strip()]
        onion_raw      = settings.get("dark_web_onion_sources", "")
        self._onion_sources = [u.strip() for u in onion_raw.split(",") if u.strip()]
        interval_raw   = settings.get("dark_web_interval", str(6 * 3600))
        try:
            self.interval_seconds = int(interval_raw)
        except (ValueError, TypeError):
            self.interval_seconds = 6 * 3600
        log.debug(
            f"[darkweb] Configured — enabled={self._enabled}, "
            f"keywords={self._keywords}, interval={self.interval_seconds}s"
        )

    def fetch(self) -> list[dict]:
        if not self._enabled:
            log.debug("[darkweb] Feed disabled via admin settings. Skipping.")
            return []

        if not self._keywords:
            log.warning("[darkweb] No keywords configured — nothing to monitor. "
                        "Add keywords in the WebUI Admin tab.")
            return []

        log.info(f"[darkweb] Scanning for {len(self._keywords)} keyword(s): {self._keywords}")

        clearnet = _clearnet_session()
        tor      = _tor_session()   # None if Tor proxy is not reachable

        all_results: list[dict] = []

        for keyword in self._keywords:
            # Source 1: Ahmia.fi (always)
            hits = _search_ahmia(keyword, clearnet)
            all_results.extend(hits)
            time.sleep(1.5)   # polite crawl delay

            # Source 2: Direct .onion sources (if Tor available)
            if tor and self._onion_sources:
                for onion_url in self._onion_sources:
                    hits = _fetch_onion(onion_url, keyword, tor)
                    all_results.extend(hits)
                    time.sleep(2)
            elif self._onion_sources and not tor:
                # Tor unavailable — try tor2web clearnet gateways as fallback
                for onion_url in self._onion_sources:
                    hits = _search_via_tor2web(keyword, onion_url, clearnet)
                    all_results.extend(hits)
                    time.sleep(1.5)

        # Add fingerprint to every result for deduplication in the worker
        for r in all_results:
            r["fingerprint"] = _fingerprint(
                r.get("source_url", ""),
                r.get("keyword_matched", ""),
                r.get("title", ""),
            )

        log.info(f"[darkweb] Scan complete — {len(all_results)} raw mentions found.")
        return all_results
