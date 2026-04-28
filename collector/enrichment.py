"""
IOC Enrichment Pipeline
Enriches IOCs with VirusTotal, GreyNoise, and Shodan data.
Reads API keys from platform_settings DB table (set in Admin tab) with env var fallbacks.
Results stored in ioc_enrichments table.

API budget strategy (keeps VirusTotal free-tier usage ≤ 500 calls/day):

  IPs   → GreyNoise first (community API, no hard daily limit).
           VT only called when:
             • GreyNoise key is absent, OR
             • GreyNoise verdict is 'malicious' or 'suspicious' (confirmation), OR
             • GreyNoise verdict is 'unknown' AND daily VT budget remains.
  Domains, URLs → VT (no adequate free alternative).
  Hashes → VT (definitive file reputation source).

  Daily VT cap: VT_DAILY_LIMIT calls.  Once reached, VT is skipped for the
  rest of the calendar day.

  Cache windows:
    • Malicious / suspicious results  → re-enrich after 24 h.
    • Benign / noise / unknown results → re-enrich after 7 days.
  This dramatically cuts repeat calls for the (majority) benign IOC pool.
"""

import base64
import json
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Optional

import requests
from sqlalchemy.orm import Session
from sqlalchemy import func as _sqlfunc

from models import IOC, IOCEnrichment, SessionLocal

log = logging.getLogger(__name__)

REQUEST_TIMEOUT = 10  # seconds

# ─── Local AI configuration (Ollama) ─────────────────────────────────────────
# AI enrichment generates threat-context narratives without consuming any
# API quota — it's a free complement to VT/GreyNoise reputation scoring.
_OLLAMA_URL    = os.getenv("OLLAMA_URL", "http://ollama:11434")
_OLLAMA_MODELS = [m.strip() for m in os.getenv("OLLAMA_MODELS", "").split(",") if m.strip()]

# ─── Budget configuration ──────────────────────────────────────────────────────

VT_DAILY_LIMIT   = 450   # Hard cap; leave 50 calls as manual-investigation buffer
CACHE_HOT_HOURS  = 24    # Re-enrich malicious/suspicious after this many hours
CACHE_COLD_DAYS  = 7     # Re-enrich benign/noise/unknown after this many days


# ─── API key helpers ──────────────────────────────────────────────────────────

def _get_keys(db: Optional[Session]) -> tuple[str, str, str]:
    """Return (vt_key, gn_key, shodan_key) from DB settings with env fallbacks."""
    try:
        from settings import get_setting
        vt_key     = get_setting("enrichment_vt_key", db)     or os.getenv("VT_API_KEY", "")
        gn_key     = get_setting("enrichment_gn_key", db)     or os.getenv("GREYNOISE_API_KEY", "")
        shodan_key = get_setting("enrichment_shodan_key", db) or os.getenv("SHODAN_API_KEY", "")
    except Exception as exc:
        log.debug(f"[enrichment] settings read failed: {exc}")
        vt_key     = os.getenv("VT_API_KEY", "")
        gn_key     = os.getenv("GREYNOISE_API_KEY", "")
        shodan_key = os.getenv("SHODAN_API_KEY", "")
    return vt_key, gn_key, shodan_key


# ─── Daily VT budget tracker ──────────────────────────────────────────────────

def _vt_calls_today(db: Session) -> int:
    """Count VirusTotal enrichment rows created since UTC midnight today."""
    today_midnight = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    try:
        count = (
            db.query(_sqlfunc.count(IOCEnrichment.id))
            .filter(
                IOCEnrichment.source == "virustotal",
                IOCEnrichment.enriched_at >= today_midnight,
            )
            .scalar()
        )
        return int(count or 0)
    except Exception as exc:
        log.debug(f"[enrichment] VT budget query failed: {exc}")
        return 0


def _vt_budget_ok(db: Session) -> bool:
    """Return True if we still have VT quota remaining today."""
    used = _vt_calls_today(db)
    remaining = VT_DAILY_LIMIT - used
    if remaining <= 0:
        log.info(
            f"[enrichment] VT daily cap reached ({used}/{VT_DAILY_LIMIT}) — "
            "skipping VirusTotal until UTC midnight reset."
        )
        return False
    if remaining <= 50:
        log.warning(
            f"[enrichment] VT budget low: {used}/{VT_DAILY_LIMIT} used today "
            f"({remaining} remaining)."
        )
    return True


# ─── Cache window helpers ─────────────────────────────────────────────────────

def _cache_cutoff(verdict: Optional[str]) -> datetime:
    """
    Return the oldest enriched_at timestamp we still consider fresh.
    Malicious/suspicious results expire in 24 h; everything else in 7 days.
    """
    hot_verdicts = {"malicious", "suspicious"}
    hours = CACHE_HOT_HOURS if (verdict or "").lower() in hot_verdicts else CACHE_COLD_DAYS * 24
    return datetime.now(timezone.utc) - timedelta(hours=hours)


def _is_fresh(ioc_value: str, source: str, db: Session) -> bool:
    """
    Return True if ioc_value already has a recent enrichment from *source*
    that is still within its cache window.
    """
    try:
        row = (
            db.query(IOCEnrichment)
            .filter_by(ioc_value=ioc_value, source=source)
            .order_by(IOCEnrichment.enriched_at.desc())
            .first()
        )
        if not row:
            return False
        cutoff = _cache_cutoff(row.verdict)
        return row.enriched_at >= cutoff
    except Exception:
        return False


# ─── VirusTotal ───────────────────────────────────────────────────────────────

def _vt_enrich(value: str, ioc_type: str, api_key: str) -> Optional[dict]:
    """
    Query VirusTotal API v3 for the given IOC.
    Returns dict with score (0-100), verdict, raw_data, or None on failure.
    """
    try:
        if ioc_type in ("ip", "ip_address"):
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
        elif ioc_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{value}"
        elif ioc_type in ("hash_sha256", "hash_md5", "hash_sha1", "hash"):
            url = f"https://www.virustotal.com/api/v3/files/{value}"
        elif ioc_type == "url":
            url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        else:
            log.debug(f"[vt] Unsupported ioc_type '{ioc_type}' — skipping.")
            return None

        resp = requests.get(
            url,
            headers={"x-apikey": api_key},
            timeout=REQUEST_TIMEOUT,
        )

        if resp.status_code == 429:
            log.warning("[vt] Rate-limited (429) — VT quota may be exhausted.")
            return None

        if resp.status_code == 404:
            log.debug(f"[vt] No data for {ioc_type} '{value}' (404)")
            return {"score": 0, "verdict": "unknown", "raw_data": "{}"}

        resp.raise_for_status()
        data = resp.json()

        stats = (
            data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
        )
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        score = round((malicious / total) * 100) if total > 0 else 0

        verdict = (
            "malicious"  if score >= 50 else
            "suspicious" if score >= 10 else
            "benign"
        )

        return {
            "score":    score,
            "verdict":  verdict,
            "raw_data": json.dumps(data)[:8000],
        }

    except requests.RequestException as exc:
        log.warning(f"[vt] Request failed for '{value}': {exc}")
        return None
    except Exception as exc:
        log.error(f"[vt] Unexpected error enriching '{value}': {exc}")
        return None


# ─── GreyNoise ────────────────────────────────────────────────────────────────

def _greynoise_enrich(ip: str, api_key: str) -> Optional[dict]:
    """
    Query GreyNoise Community API for an IP address.
    Returns dict with noise, riot, classification, verdict, raw_data.
    """
    try:
        resp = requests.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={"key": api_key},
            timeout=REQUEST_TIMEOUT,
        )

        if resp.status_code == 404:
            return {
                "score":    0,
                "verdict":  "unknown",
                "raw_data": json.dumps({"message": "not found"}),
            }

        if resp.status_code == 429:
            log.warning("[greynoise] Rate-limited (429).")
            return None

        resp.raise_for_status()
        data = resp.json()

        riot           = bool(data.get("riot", False))
        classification = data.get("classification", "unknown")

        if riot:
            verdict, score = "noise", 0
        elif classification == "malicious":
            verdict, score = "malicious", 85
        elif classification == "benign":
            verdict, score = "benign", 0
        else:
            noise = bool(data.get("noise", False))
            verdict, score = "unknown", (10 if noise else 0)

        return {
            "score":    score,
            "verdict":  verdict,
            "raw_data": json.dumps(data)[:8000],
        }

    except requests.RequestException as exc:
        log.warning(f"[greynoise] Request failed for '{ip}': {exc}")
        return None
    except Exception as exc:
        log.error(f"[greynoise] Unexpected error enriching '{ip}': {exc}")
        return None


# ─── Shodan ───────────────────────────────────────────────────────────────────

def _shodan_enrich(ip: str, api_key: str) -> Optional[dict]:
    """
    Query Shodan host API for an IP address.
    Returns dict with ports, os, org, isp, country, score, verdict, raw_data.
    """
    try:
        resp = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": api_key},
            timeout=REQUEST_TIMEOUT,
        )

        if resp.status_code in (404, 400):
            return {
                "score":    0,
                "verdict":  "unknown",
                "raw_data": json.dumps({"message": "not found"}),
            }

        if resp.status_code == 429:
            log.warning("[shodan] Rate-limited (429).")
            return None

        resp.raise_for_status()
        data = resp.json()

        ports   = data.get("ports", [])
        os_name = data.get("os")
        org     = data.get("org", "Unknown")
        isp     = data.get("isp", "Unknown")
        country = data.get("country_name", "Unknown")

        sensitive_ports = {21, 22, 23, 3389, 5900, 4444, 6667, 8080, 8443}
        sensitive_hit = len(set(ports) & sensitive_ports)
        score = min(100, sensitive_hit * 10 + (5 if len(ports) > 10 else 0))
        verdict = "suspicious" if score >= 30 else "unknown"

        summary = {"ports": ports[:30], "os": os_name, "org": org,
                   "isp": isp, "country": country}
        return {
            "score":    score,
            "verdict":  verdict,
            "raw_data": json.dumps({**summary, "_full": data})[:8000],
        }

    except requests.RequestException as exc:
        log.warning(f"[shodan] Request failed for '{ip}': {exc}")
        return None
    except Exception as exc:
        log.error(f"[shodan] Unexpected error enriching '{ip}': {exc}")
        return None


# ─── Local AI context enrichment ─────────────────────────────────────────────

def _local_ai_enrich(
    ioc_value: str,
    ioc_type: str,
    malware_family: str,
    feed_context: str,
) -> Optional[dict]:
    """
    Use local Ollama to generate a 2-3 sentence threat context synopsis for an IOC.

    This replaces VirusTotal as the source of THREAT CONTEXT (what the malware
    does, how it operates, recommended defences).  VirusTotal remains the
    authoritative source of REPUTATION (is this IOC malicious right now).

    No API key, no quota, no cost — completely free.
    Returns None when Ollama is not configured or unreachable.
    """
    if not _OLLAMA_MODELS:
        return None
    # Require at least malware family or feed context to generate meaningful output
    if not malware_family and not feed_context:
        return None

    prompt = (
        "You are a threat intelligence analyst. In 2-3 concise sentences describe:\n"
        "1) What this threat does and how it typically operates\n"
        "2) The most important immediate defensive action\n\n"
        f"IOC type: {ioc_type}\n"
        + (f"Malware / threat family: {malware_family}\n" if malware_family else "")
        + (f"Feed context: {feed_context[:300]}\n" if feed_context else "")
        + "\nDo not repeat the IOC value. Be specific and actionable."
    )

    for model in _OLLAMA_MODELS:
        try:
            resp = requests.post(
                f"{_OLLAMA_URL}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False},
                timeout=25,
            )
            if resp.ok:
                text = resp.json().get("response", "").strip()
                if text:
                    log.debug(f"[local_ai] Generated synopsis for {ioc_type} ({model})")
                    return {
                        "score":    0,
                        "verdict":  "context",
                        "raw_data": json.dumps({"synopsis": text, "model": model}),
                    }
        except Exception as exc:
            log.debug(f"[local_ai] Ollama call failed ({model}): {exc}")

    return None


# ─── Persistence ──────────────────────────────────────────────────────────────

def _save_enrichment(
    ioc_value: str,
    ioc_type: str,
    source: str,
    score: float,
    verdict: str,
    raw_data: str,
    db: Session,
) -> None:
    """Upsert enrichment result (regardless of age — caller decides freshness)."""
    try:
        existing = (
            db.query(IOCEnrichment)
            .filter_by(ioc_value=ioc_value, source=source)
            .first()
        )
        now = datetime.now(timezone.utc)
        if existing:
            existing.score       = score
            existing.verdict     = verdict
            existing.raw_data    = raw_data
            existing.enriched_at = now
        else:
            db.add(IOCEnrichment(
                ioc_value   = ioc_value[:512],
                ioc_type    = ioc_type[:50],
                source      = source[:50],
                score       = score,
                verdict     = verdict,
                raw_data    = raw_data,
                enriched_at = now,
            ))
        db.commit()
    except Exception as exc:
        log.error(f"[enrichment] DB save failed for '{ioc_value}' / {source}: {exc}")
        db.rollback()


# ─── Main entry point ─────────────────────────────────────────────────────────

def enrich_ioc(ioc_value: str, ioc_type: str, db_session: Session) -> dict:
    """
    Enrich a single IOC using the smart source-routing strategy.

    Routing rules
    ─────────────
    IP addresses:
      1. GreyNoise  — always first if key present; no daily limit on community API.
      2. Shodan     — if key present.
      3. VirusTotal — only if:
           a. no GN key available, OR
           b. GN verdict is 'malicious' or 'suspicious' (cross-confirm), OR
           c. GN verdict is 'unknown' AND VT daily budget remains.
         VT is SKIPPED for IPs when GN says 'benign' or 'noise'.

    Domains / URLs:
      VirusTotal only (no free alternative with equivalent coverage).

    Hashes:
      VirusTotal only (definitive file reputation source).

    All sources: skip if a fresh cached result already exists (cache window
    varies by verdict — malicious=24 h, benign=7 days).
    """
    vt_key, gn_key, shodan_key = _get_keys(db_session)
    results: dict[str, Optional[dict]] = {}
    is_ip = ioc_type in ("ip", "ip_address")

    # ── GreyNoise (IPs only, call first) ──────────────────────────────────────
    gn_verdict: Optional[str] = None
    if is_ip and gn_key:
        if _is_fresh(ioc_value, "greynoise", db_session):
            # Retrieve cached verdict so we can use it for VT routing below
            row = (
                db_session.query(IOCEnrichment)
                .filter_by(ioc_value=ioc_value, source="greynoise")
                .order_by(IOCEnrichment.enriched_at.desc())
                .first()
            )
            gn_verdict = row.verdict if row else None
            log.debug(f"[enrichment] GN cache hit for '{ioc_value}' (verdict={gn_verdict})")
        else:
            log.debug(f"[enrichment] GreyNoise enriching IP '{ioc_value}'")
            gn = _greynoise_enrich(ioc_value, gn_key)
            if gn:
                _save_enrichment(ioc_value, ioc_type, "greynoise",
                                 gn["score"], gn["verdict"], gn["raw_data"], db_session)
                results["greynoise"] = gn
                gn_verdict = gn["verdict"]
    elif is_ip and not gn_key:
        log.debug("[enrichment] GreyNoise key not configured — skipping")

    # ── Shodan (IPs only) ─────────────────────────────────────────────────────
    if is_ip and shodan_key:
        if _is_fresh(ioc_value, "shodan", db_session):
            log.debug(f"[enrichment] Shodan cache hit for '{ioc_value}'")
        else:
            log.debug(f"[enrichment] Shodan enriching IP '{ioc_value}'")
            sh = _shodan_enrich(ioc_value, shodan_key)
            if sh:
                _save_enrichment(ioc_value, ioc_type, "shodan",
                                 sh["score"], sh["verdict"], sh["raw_data"], db_session)
                results["shodan"] = sh
    elif is_ip and not shodan_key:
        log.debug("[enrichment] Shodan key not configured — skipping")

    # ── VirusTotal ────────────────────────────────────────────────────────────
    vt_supported_types = (
        "ip", "ip_address", "domain", "hash", "hash_sha256",
        "hash_md5", "hash_sha1", "url",
    )
    if vt_key and ioc_type in vt_supported_types:

        # Decide whether VT adds value for this IOC
        _vt_needed = True
        if is_ip and gn_key:
            # GN already ran (or was cached).  Skip VT for clearly benign/noise IPs.
            if gn_verdict in ("benign", "noise"):
                log.debug(
                    f"[enrichment] Skipping VT for IP '{ioc_value}' "
                    f"— GreyNoise says '{gn_verdict}' (saving VT quota)."
                )
                _vt_needed = False
            elif gn_verdict == "unknown":
                # Unknown from GN — use VT only if budget allows
                _vt_needed = _vt_budget_ok(db_session)
            else:
                # GN malicious/suspicious — call VT for cross-confirmation
                _vt_needed = _vt_budget_ok(db_session)

        if _vt_needed:
            if _is_fresh(ioc_value, "virustotal", db_session):
                log.debug(f"[enrichment] VT cache hit for '{ioc_value}'")
            elif _vt_budget_ok(db_session):
                log.debug(f"[enrichment] VT enriching {ioc_type} '{ioc_value}'")
                vt = _vt_enrich(ioc_value, ioc_type, vt_key)
                if vt:
                    _save_enrichment(ioc_value, ioc_type, "virustotal",
                                     vt["score"], vt["verdict"], vt["raw_data"], db_session)
                    results["virustotal"] = vt

    elif not vt_key:
        log.debug("[enrichment] VT key not configured — skipping VirusTotal")

    # ── Local AI context (zero quota cost) ────────────────────────────────────
    # Generates a threat narrative using Ollama when a malware family is known.
    # Cached 7 days (context is not time-sensitive).  Runs regardless of
    # whether VT/GN returned results — context and reputation are complementary.
    if _OLLAMA_MODELS and not _is_fresh(ioc_value, "local_ai", db_session):
        try:
            ioc_row = db_session.query(IOC).filter_by(value=ioc_value).first()
            _mal_fam    = (ioc_row.malware_family or "") if ioc_row else ""
            _feed_ctx   = ""   # feed context not needed when family is known
            ai = _local_ai_enrich(ioc_value, ioc_type, _mal_fam, _feed_ctx)
            if ai:
                _save_enrichment(
                    ioc_value, ioc_type, "local_ai",
                    ai["score"], ai["verdict"], ai["raw_data"], db_session
                )
                results["local_ai"] = ai
        except Exception as exc:
            log.debug(f"[local_ai] Skipped for '{ioc_value}': {exc}")

    return results


# ─── Batch enrichment ─────────────────────────────────────────────────────────

def enrich_batch(db: Session, batch_size: int = 20) -> int:
    """
    Find IOCs that need enrichment and process them.

    IOC priority order (maximises VT budget for highest-value IOCs):
      1. Hashes  — file reputation; VT is the only source.
      2. Domains — VT-only; high threat-signal value.
      3. URLs    — VT-only.
      4. IPs     — GreyNoise+Shodan handle most; VT used selectively.

    Staleness is verdict-aware:
      Malicious/suspicious rows expire in 24 h.
      Benign/noise/unknown rows expire in 7 days.
    This keeps the daily VT call count well below 500 once the initial
    backlog is enriched.
    """
    now = datetime.now(timezone.utc)

    # Build a subquery of IOC values that already have fresh enrichments
    # (any source). An IOC is considered fully fresh if EVERY source it
    # qualifies for returned a result within the appropriate cache window.
    # Simpler approach: just skip IOCs whose MOST RECENT enrichment (any
    # source) is still within the cold-cache window AND verdict is benign.
    # For malicious/suspicious, the hot window applies.
    hot_cutoff  = now - timedelta(hours=CACHE_HOT_HOURS)
    cold_cutoff = now - timedelta(hours=CACHE_COLD_DAYS * 24)

    # Most-recent enrichment per IOC (any source)
    from sqlalchemy import text as _text
    try:
        recent = db.execute(_text("""
            SELECT DISTINCT ON (ioc_value) ioc_value, verdict, enriched_at
            FROM ioc_enrichments
            ORDER BY ioc_value, enriched_at DESC
        """)).fetchall()
    except Exception:
        recent = []

    skip_values: set[str] = set()
    for row in recent:
        verdict     = (row[1] or "").lower()
        enriched_at = row[2]
        if enriched_at is None:
            continue
        if enriched_at.tzinfo is None:
            enriched_at = enriched_at.replace(tzinfo=timezone.utc)
        cutoff = hot_cutoff if verdict in ("malicious", "suspicious") else cold_cutoff
        if enriched_at >= cutoff:
            skip_values.add(row[0])

    # Priority-ordered IOC types
    priority_types = [
        ("hash_sha256", "hash_sha1", "hash_md5", "hash"),  # hashes first — VT-only, high value
        ("domain",),                                         # domains — VT-only
        ("url",),                                            # URLs — VT-only
        ("ip", "ip_address"),                                # IPs — GN+Shodan handle most
    ]

    candidates: list[IOC] = []
    remaining = batch_size
    for type_group in priority_types:
        if remaining <= 0:
            break
        q = (
            db.query(IOC)
            .filter(IOC.ioc_type.in_(type_group))  # type: ignore[arg-type]
            .filter(IOC.value.notin_(skip_values))  # type: ignore[arg-type]
            .order_by(IOC.id.desc())
            .limit(remaining)
            .all()
        )
        candidates.extend(q)
        skip_values.update(ioc.value for ioc in q)  # avoid duplicates across groups
        remaining -= len(q)

    if not candidates:
        log.debug("[enrichment] No IOCs pending enrichment.")
        return 0

    # Log VT budget before batch
    vt_used = _vt_calls_today(db)
    log.info(
        f"[enrichment] Batch enriching {len(candidates)} IOC(s) "
        f"(VT today: {vt_used}/{VT_DAILY_LIMIT})..."
    )

    processed = 0
    for ioc in candidates:
        try:
            enrich_ioc(ioc.value, ioc.ioc_type, db)
            processed += 1
        except Exception as exc:
            log.error(f"[enrichment] Failed for IOC id={ioc.id}: {exc}")

    log.info(
        f"[enrichment] Batch done — {processed}/{len(candidates)} processed. "
        f"VT today: {_vt_calls_today(db)}/{VT_DAILY_LIMIT}."
    )
    return processed
