"""
Dark Web Monitor Feed
─────────────────────
Monitors publicly-accessible dark web indexes and breach intelligence services
for mentions of configured keywords (typically your org's domains, IPs, brand
names, or executive names).

Primary sources — NO Tor required (clearnet APIs / search indexes):
  1. Ahmia.fi        — clearnet .onion search engine (no auth)
  2. DarkSearch.io   — REST JSON API for dark-web content (no auth)
  3. Paste Monitor   — psbdmp.ws paste-site search API (no auth)
  4. HudsonRock      — Cavalier free OSINT API (infostealer credential exposure)
  5. IntelligenceX   — broad dark-web + breach coverage (API key optional)

Optional source — requires running Tor proxy:
  6. Direct .onion   — SOCKS5 via tor-proxy container (if reachable)

Safety design:
  • Only metadata is stored — titles, snippets, actor handles, record estimates.
  • A PII sanitiser strips emails, SSNs, card numbers BEFORE anything is stored.
  • Raw breach content is NEVER written to disk or the database.
  • No authentication to any dark-web site beyond approved API keys.
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
    r'private.key|secret.key|oauth|2fa|mfa.bypass|infostealer|stealer)\b',
    re.IGNORECASE,
)
_SEV_MEDIUM = re.compile(
    r'\b(email.?list|username|phone.?number|address|ip.?address|zip.?code|'
    r'token|session|cookie|vpn|access.?log)\b',
    re.IGNORECASE,
)

_DATA_TYPE_MAP = {
    "email":       re.compile(r'\bema(?:il)?s?\b', re.IGNORECASE),
    "password":    re.compile(r'\bpass(?:word)?s?\b|\bhash(?:es)?\b|\bcredential', re.IGNORECASE),
    "ssn":         re.compile(r'\bssn\b|\bsocial.security', re.IGNORECASE),
    "dob":         re.compile(r'\bdob\b|\bdate.of.birth\b', re.IGNORECASE),
    "phone":       re.compile(r'\bphone\b|\bmobile\b', re.IGNORECASE),
    "address":     re.compile(r'\baddress(?:es)?\b|\bstreet\b|\bzip\b', re.IGNORECASE),
    "card":        re.compile(r'\bcredit.card\b|\bcvv\b|\bcard.number\b', re.IGNORECASE),
    "bank":        re.compile(r'\bbank.?account\b|\brouting\b|\biban\b', re.IGNORECASE),
    "passport":    re.compile(r'\bpassport\b', re.IGNORECASE),
    "medical":     re.compile(r'\bmedical\b|\bhealth(?:care)?\b|\bpatient\b|\bhipaa\b', re.IGNORECASE),
    "api_key":     re.compile(r'\bapi.?key\b|\bsecret.?key\b|\btoken\b', re.IGNORECASE),
    "infostealer": re.compile(r'\bstealer\b|\binfostealer\b|\bredline\b|\brakoon\b|\bvidar\b|\blumma\b', re.IGNORECASE),
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
        r = s.get("https://check.torproject.org/api/ip", timeout=10)
        data = r.json()
        if data.get("IsTor"):
            log.info("[darkweb] Tor proxy reachable — direct .onion access enabled.")
            return s
        log.debug("[darkweb] Tor proxy responding but IsTor=false — using anyway.")
        return s
    except Exception as exc:
        log.debug(f"[darkweb] Tor proxy unreachable ({exc}) — skipping .onion sources.")
        return None


# ─── Source 1: Ahmia.fi ───────────────────────────────────────────────────────

def _search_ahmia(keyword: str, session: requests.Session) -> list[dict]:
    """Search Ahmia.fi — clearnet index of .onion sites. No key required."""
    results = []
    try:
        resp = session.get(
            "https://ahmia.fi/search/",
            params={"q": keyword},
            timeout=20,
        )
        resp.raise_for_status()
    except Exception as exc:
        log.debug(f"[darkweb/ahmia] '{keyword}': {exc}")
        return results

    soup = BeautifulSoup(resp.text, "html.parser")
    for item in (soup.select("li.result") or soup.select("div.result"))[:12]:
        a_el    = item.select_one("h4 a") or item.select_one("a[href]")
        desc_el = item.select_one("p.description") or item.select_one("p")
        if not a_el:
            continue
        title   = a_el.get_text(strip=True)[:300] or "Untitled"
        url     = a_el.get("href", "")[:500]
        snippet = _sanitize(desc_el.get_text(strip=True) if desc_el else "")
        combined = f"{title} {snippet}"
        severity, dtypes = _classify(combined)
        results.append({
            "source_name":     "Ahmia",
            "source_url":      url,
            "keyword_matched": keyword,
            "title":           _sanitize(title, 300),
            "snippet":         snippet,
            "actor_handle":    _extract_actor(combined),
            "record_estimate": _extract_count(combined),
            "data_types":      dtypes,
            "severity":        severity,
        })

    log.debug(f"[darkweb/ahmia] '{keyword}' → {len(results)} results")
    return results


# ─── Source 2: DarkSearch.io ──────────────────────────────────────────────────

def _search_darksearch(keyword: str, session: requests.Session) -> list[dict]:
    """
    DarkSearch.io REST API — indexes dark-web content and exposes a JSON search API.
    No API key required for basic queries. Rate limit: ~30 req/min.
    """
    results = []
    try:
        resp = session.get(
            "https://darksearch.io/api/search",
            params={"query": keyword, "page": 1},
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        log.debug(f"[darkweb/darksearch] '{keyword}': {exc}")
        return results

    for item in (data.get("data") or [])[:10]:
        title   = _sanitize(str(item.get("title", "") or "Untitled"), 300)
        snippet = _sanitize(str(item.get("description", "") or ""))
        url     = str(item.get("link", "") or item.get("onion", ""))[:500]
        combined = f"{title} {snippet}"
        severity, dtypes = _classify(combined)
        results.append({
            "source_name":     "DarkSearch",
            "source_url":      url,
            "keyword_matched": keyword,
            "title":           title,
            "snippet":         snippet,
            "actor_handle":    _extract_actor(combined),
            "record_estimate": _extract_count(combined),
            "data_types":      dtypes,
            "severity":        severity,
        })

    log.debug(f"[darkweb/darksearch] '{keyword}' → {len(results)} results")
    return results


# ─── Source 3: Paste Monitor (psbdmp.ws) ─────────────────────────────────────

def _search_pastes(keyword: str, session: requests.Session) -> list[dict]:
    """
    psbdmp.ws paste search API — scans Pastebin, GitHub Gist, GitLab Snippets,
    and other paste sites for keyword mentions. No API key required.
    """
    results = []
    try:
        resp = session.get(
            f"https://psbdmp.ws/api/search/v3/{requests.utils.quote(keyword)}",
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        log.debug(f"[darkweb/pastes] '{keyword}': {exc}")
        return results

    for item in (data.get("items") or [])[:8]:
        title   = _sanitize(str(item.get("title", "") or f"Paste {item.get('id', '')}"), 300)
        paste_id = str(item.get("id", ""))
        url     = f"https://psbdmp.ws/{paste_id}" if paste_id else ""
        # Pastes often contain credentials — treat as high by default unless reclassified
        severity, dtypes = _classify(title)
        if severity == "low":
            severity = "medium"   # pastes mentioning org keywords are at least medium

        results.append({
            "source_name":     "PasteMonitor",
            "source_url":      url,
            "keyword_matched": keyword,
            "title":           title,
            "snippet":         _sanitize(str(item.get("text", ""))[:200]),
            "actor_handle":    "Unknown",
            "record_estimate": None,
            "data_types":      dtypes or ["paste"],
            "severity":        severity,
        })

    log.debug(f"[darkweb/pastes] '{keyword}' → {len(results)} results")
    return results


# ─── Source 4: HudsonRock Cavalier (infostealer OSINT) ───────────────────────

def _search_hudsonrock(domain: str, session: requests.Session) -> list[dict]:
    """
    HudsonRock Cavalier free OSINT API — returns infostealer credential exposure
    data for a domain (employee machines compromised, corporate credentials found
    in stealer logs). Only runs when the keyword looks like a domain name.
    """
    results = []
    # Only query for domain-like keywords (contain a dot and no spaces)
    if "." not in domain or " " in domain:
        return results
    # Strip protocol if someone entered a URL
    domain = re.sub(r'^https?://', '', domain).split("/")[0].strip()

    try:
        resp = session.get(
            "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain",
            params={"domain": domain},
            timeout=20,
        )
        if resp.status_code == 404:
            # No data for this domain — normal, not an error
            return results
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        log.debug(f"[darkweb/hudsonrock] '{domain}': {exc}")
        return results

    employees_count  = data.get("total_corporate_credentials_count", 0) or 0
    users_count      = data.get("total_user_credentials_count", 0) or 0
    stealers         = data.get("stealers", []) or []
    total_exposed    = employees_count + users_count

    if total_exposed == 0 and not stealers:
        return results

    # Build a severity/title based on exposure size
    if employees_count > 50 or total_exposed > 200:
        severity = "critical"
    elif employees_count > 10 or total_exposed > 50:
        severity = "high"
    elif total_exposed > 0:
        severity = "medium"
    else:
        severity = "low"

    malware_families = list({s.get("malware_family", "Unknown") for s in stealers[:5]})

    title   = (f"Infostealer exposure: {total_exposed:,} credentials found for {domain} "
               f"({employees_count:,} corporate)")
    snippet = (f"Malware families: {', '.join(malware_families[:3])}. "
               f"Employee accounts exposed: {employees_count:,}. "
               f"User accounts exposed: {users_count:,}.")

    results.append({
        "source_name":     "HudsonRock",
        "source_url":      f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={domain}",
        "keyword_matched": domain,
        "title":           title[:300],
        "snippet":         _sanitize(snippet),
        "actor_handle":    "infostealer-ops",
        "record_estimate": f"{total_exposed:,} credentials",
        "data_types":      ["infostealer", "password", "email"],
        "severity":        severity,
    })

    log.debug(f"[darkweb/hudsonrock] '{domain}' → {total_exposed} exposed credentials")
    return results


# ─── Source 5: Intelligence X (optional, needs API key) ──────────────────────

def _search_intelx(keyword: str, session: requests.Session, api_key: str) -> list[dict]:
    """
    Intelligence X — broad dark web / breach data search.
    Requires an API key (free tier available at intelx.io).
    Two-step: POST to start search → GET results by search ID.
    """
    if not api_key:
        return []

    results = []
    try:
        # Step 1: Start search
        start_resp = session.post(
            "https://2.intelx.io/intelligent/search",
            json={
                "term": keyword,
                "buckets": [],
                "lookuplevel": 0,
                "maxresults": 10,
                "timeout": 5,
                "datefrom": "",
                "dateto": "",
                "sort": 4,       # sort by date desc
                "media": 0,
                "terminate": [],
            },
            headers={"x-key": api_key},
            timeout=15,
        )
        start_resp.raise_for_status()
        search_id = start_resp.json().get("id")
        if not search_id:
            return results

        # Step 2: Retrieve results (give the engine 3s to index)
        time.sleep(3)
        results_resp = session.get(
            "https://2.intelx.io/intelligent/search/result",
            params={"id": search_id, "limit": 10, "offset": 0},
            headers={"x-key": api_key},
            timeout=15,
        )
        results_resp.raise_for_status()
        items = results_resp.json().get("records") or []

    except Exception as exc:
        log.debug(f"[darkweb/intelx] '{keyword}': {exc}")
        return results

    for item in items[:10]:
        title   = _sanitize(str(item.get("name", "") or "IntelX Result"), 300)
        snippet = _sanitize(str(item.get("description", "") or ""))
        url     = str(item.get("systemid", "") or "")
        bucket  = str(item.get("bucket", ""))
        combined = f"{title} {snippet} {bucket}"
        severity, dtypes = _classify(combined)

        results.append({
            "source_name":     "IntelligenceX",
            "source_url":      f"https://intelx.io/?s={requests.utils.quote(keyword)}",
            "keyword_matched": keyword,
            "title":           title,
            "snippet":         snippet,
            "actor_handle":    _extract_actor(combined),
            "record_estimate": _extract_count(combined),
            "data_types":      dtypes,
            "severity":        severity,
        })

    log.debug(f"[darkweb/intelx] '{keyword}' → {len(results)} results")
    return results


# ─── Source 6: Direct .onion via Tor proxy ────────────────────────────────────

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

    soup    = BeautifulSoup(resp.text, "html.parser")
    results = []

    for a in soup.find_all("a", href=True)[:20]:
        title  = a.get_text(strip=True)[:200]
        href   = a["href"][:500]
        if len(title) < 8 or any(nav in title.lower() for nav in
                                  ("home", "about", "login", "register", "back", "next", "prev")):
            continue
        parent_text = a.parent.get_text(strip=True) if a.parent else ""
        if (keyword.lower() not in title.lower()
                and keyword.lower() not in href.lower()
                and keyword.lower() not in parent_text.lower()):
            continue

        snippet  = _sanitize(parent_text)
        combined = f"{title} {snippet}"
        severity, dtypes = _classify(combined)

        results.append({
            "source_name":     url.split("/")[2][:40],
            "source_url":      href if href.startswith("http") else url,
            "keyword_matched": keyword,
            "title":           _sanitize(title, 300),
            "snippet":         snippet,
            "actor_handle":    _extract_actor(combined),
            "record_estimate": _extract_count(combined),
            "data_types":      dtypes,
            "severity":        severity,
        })

    return results[:8]


# ─── Feed class ───────────────────────────────────────────────────────────────

class DarkWebFeed(BaseFeed):
    """Dark web monitoring feed.

    Runtime config is injected by the worker via configure() before every run,
    pulling values from the platform_settings DB table (set in the WebUI admin
    panel).  Env vars are used as fallback when no DB row exists.
    """
    name = "darkweb"

    def __init__(self):
        self._enabled         = False
        self._keywords:       list[str] = []
        self._onion_sources:  list[str] = []
        self._intelx_key:     str = ""
        self.interval_seconds = int(os.getenv("DARK_WEB_INTERVAL", str(6 * 3600)))

    def configure(self, settings: dict) -> None:
        """Apply runtime settings from the DB (called by worker before fetch)."""
        self._enabled = settings.get("dark_web_enabled", "false").lower() in ("1", "true", "yes")
        kw_raw        = settings.get("dark_web_keywords", "")
        self._keywords = [k.strip() for k in kw_raw.split(",") if k.strip()]
        onion_raw      = settings.get("dark_web_onion_sources", "")
        self._onion_sources = [u.strip() for u in onion_raw.split(",") if u.strip()]
        self._intelx_key   = settings.get("intelx_api_key", "") or os.getenv("INTELX_API_KEY", "")
        interval_raw   = settings.get("dark_web_interval", str(6 * 3600))
        try:
            self.interval_seconds = int(interval_raw)
        except (ValueError, TypeError):
            self.interval_seconds = 6 * 3600
        log.debug(
            f"[darkweb] Configured — enabled={self._enabled}, "
            f"keywords={self._keywords}, intelx={'yes' if self._intelx_key else 'no'}, "
            f"onion_sources={len(self._onion_sources)}, interval={self.interval_seconds}s"
        )

    def fetch(self) -> list[dict]:
        if not self._enabled:
            log.debug("[darkweb] Feed disabled via admin settings. Skipping.")
            return []

        if not self._keywords:
            log.warning("[darkweb] No keywords configured — nothing to monitor. "
                        "Add keywords in the WebUI Admin → Dark Web tab.")
            return []

        log.info(f"[darkweb] Scanning {len(self._keywords)} keyword(s) across "
                 f"clearnet dark-web engines: Ahmia, DarkSearch, Paste Monitor, "
                 f"HudsonRock, IntelligenceX{'(off)' if not self._intelx_key else ''}")

        clearnet = _clearnet_session()
        tor      = _tor_session()   # None if Tor proxy is not reachable
        all_results: list[dict] = []

        for keyword in self._keywords:
            # ── Clearnet sources (always active) ──────────────────────────────
            for fn, label in [
                (lambda k: _search_ahmia(k, clearnet),       "ahmia"),
                (lambda k: _search_darksearch(k, clearnet),  "darksearch"),
                (lambda k: _search_pastes(k, clearnet),      "pastes"),
                (lambda k: _search_hudsonrock(k, clearnet),  "hudsonrock"),
                (lambda k: _search_intelx(k, clearnet, self._intelx_key), "intelx"),
            ]:
                try:
                    hits = fn(keyword)
                    all_results.extend(hits)
                except Exception as exc:
                    log.warning(f"[darkweb/{label}] Unexpected error for '{keyword}': {exc}")
                time.sleep(1.5)   # polite crawl delay between engines

            # ── Optional: direct .onion via Tor ──────────────────────────────
            if tor and self._onion_sources:
                for onion_url in self._onion_sources:
                    try:
                        hits = _fetch_onion(onion_url, keyword, tor)
                        all_results.extend(hits)
                    except Exception as exc:
                        log.warning(f"[darkweb/tor] {onion_url}: {exc}")
                    time.sleep(2)

        # Attach deduplication fingerprint
        for r in all_results:
            r["fingerprint"] = _fingerprint(
                r.get("source_url", ""),
                r.get("keyword_matched", ""),
                r.get("title", ""),
            )

        log.info(f"[darkweb] Scan complete — {len(all_results)} raw mentions found.")
        return all_results
