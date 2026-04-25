"""
IOC Enrichment Pipeline
Enriches IOCs with VirusTotal, GreyNoise, and Shodan data.
Reads API keys from platform_settings DB table (set in Admin tab) with env var fallbacks.
Results stored in ioc_enrichments table.
"""

import base64
import hashlib
import json
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Optional

import requests
from sqlalchemy.orm import Session

from models import IOC, IOCEnrichment, SessionLocal

log = logging.getLogger(__name__)

REQUEST_TIMEOUT = 10  # seconds


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
            # VT URL ID = base64url-encoded URL without padding
            url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        else:
            log.debug(f"[vt] Unsupported ioc_type '{ioc_type}' for VirusTotal — skipping.")
            return None

        resp = requests.get(
            url,
            headers={"x-apikey": api_key},
            timeout=REQUEST_TIMEOUT,
        )

        if resp.status_code == 404:
            log.debug(f"[vt] No data for {ioc_type} '{value}' (404)")
            return {"score": 0, "verdict": "unknown", "raw_data": "{}"}

        resp.raise_for_status()
        data = resp.json()

        # Extract malicious engine count
        stats = (
            data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
        )
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        score = round((malicious / total) * 100) if total > 0 else 0

        if score >= 50:
            verdict = "malicious"
        elif score >= 10:
            verdict = "suspicious"
        else:
            verdict = "benign"

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
            # IP not in GreyNoise — unknown
            return {
                "score":    0,
                "verdict":  "unknown",
                "raw_data": json.dumps({"message": "not found"}),
            }

        resp.raise_for_status()
        data = resp.json()

        noise = bool(data.get("noise", False))
        riot  = bool(data.get("riot", False))
        classification = data.get("classification", "unknown")

        if riot:
            verdict = "noise"       # known benign infrastructure (CDNs, scanners, etc.)
            score   = 0
        elif classification == "malicious":
            verdict = "malicious"
            score   = 85
        elif classification == "benign":
            verdict = "benign"
            score   = 0
        else:
            verdict = "unknown"
            score   = 10 if noise else 0

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

        if resp.status_code == 404:
            return {
                "score":    0,
                "verdict":  "unknown",
                "raw_data": json.dumps({"message": "not found"}),
            }

        resp.raise_for_status()
        data = resp.json()

        ports   = data.get("ports", [])
        os_name = data.get("os")
        org     = data.get("org", "Unknown")
        isp     = data.get("isp", "Unknown")
        country = data.get("country_name", "Unknown")

        # Simple heuristic: many open ports or sensitive ports = higher score
        sensitive_ports = {21, 22, 23, 3389, 5900, 4444, 6667, 8080, 8443}
        sensitive_hit = len(set(ports) & sensitive_ports)
        score = min(100, sensitive_hit * 10 + (5 if len(ports) > 10 else 0))
        verdict = "suspicious" if score >= 30 else "unknown"

        summary = {
            "ports":   ports[:30],
            "os":      os_name,
            "org":     org,
            "isp":     isp,
            "country": country,
        }

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
    """
    Upsert enrichment result.
    Updates an existing row if the same ioc_value+source was enriched within the
    last 24 hours; otherwise inserts a new row.
    """
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        existing = (
            db.query(IOCEnrichment)
            .filter_by(ioc_value=ioc_value, source=source)
            .filter(IOCEnrichment.enriched_at >= cutoff)
            .first()
        )
        now = datetime.now(timezone.utc)
        if existing:
            existing.score      = score
            existing.verdict    = verdict
            existing.raw_data   = raw_data
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
    Enrich a single IOC using all available sources.
    Returns a summary dict of results keyed by source name.
    Gracefully skips any source whose API key is not configured.
    """
    vt_key, gn_key, shodan_key = _get_keys(db_session)
    results: dict[str, Optional[dict]] = {}

    is_ip = ioc_type in ("ip", "ip_address")

    # ── VirusTotal (supports IP, domain, hash, URL)
    if vt_key and ioc_type in ("ip", "ip_address", "domain", "hash", "hash_sha256",
                               "hash_md5", "hash_sha1", "url"):
        log.debug(f"[enrichment] VT enriching {ioc_type} '{ioc_value}'")
        vt = _vt_enrich(ioc_value, ioc_type, vt_key)
        if vt:
            _save_enrichment(ioc_value, ioc_type, "virustotal",
                             vt["score"], vt["verdict"], vt["raw_data"], db_session)
            results["virustotal"] = vt
    elif not vt_key:
        log.debug("[enrichment] VT key not configured — skipping VirusTotal")

    # ── GreyNoise (IP-only)
    if is_ip and gn_key:
        log.debug(f"[enrichment] GreyNoise enriching IP '{ioc_value}'")
        gn = _greynoise_enrich(ioc_value, gn_key)
        if gn:
            _save_enrichment(ioc_value, ioc_type, "greynoise",
                             gn["score"], gn["verdict"], gn["raw_data"], db_session)
            results["greynoise"] = gn
    elif is_ip and not gn_key:
        log.debug("[enrichment] GreyNoise key not configured — skipping")

    # ── Shodan (IP-only)
    if is_ip and shodan_key:
        log.debug(f"[enrichment] Shodan enriching IP '{ioc_value}'")
        sh = _shodan_enrich(ioc_value, shodan_key)
        if sh:
            _save_enrichment(ioc_value, ioc_type, "shodan",
                             sh["score"], sh["verdict"], sh["raw_data"], db_session)
            results["shodan"] = sh
    elif is_ip and not shodan_key:
        log.debug("[enrichment] Shodan key not configured — skipping")

    return results


# ─── Batch enrichment ─────────────────────────────────────────────────────────

def enrich_batch(db: Session, batch_size: int = 20) -> int:
    """
    Find IOCs that have not been enriched in the last 24 hours and enrich them.
    Returns the number of IOCs processed.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

    # Subquery: IOC values that already have recent enrichments
    recently_enriched = (
        db.query(IOCEnrichment.ioc_value)
        .filter(IOCEnrichment.enriched_at >= cutoff)
        .subquery()
    )

    candidates = (
        db.query(IOC)
        .filter(IOC.value.notin_(recently_enriched))  # type: ignore[arg-type]
        .order_by(IOC.id.desc())
        .limit(batch_size)
        .all()
    )

    if not candidates:
        log.debug("[enrichment] No IOCs pending enrichment.")
        return 0

    log.info(f"[enrichment] Batch enriching {len(candidates)} IOC(s)...")
    processed = 0
    for ioc in candidates:
        try:
            enrich_ioc(ioc.value, ioc.ioc_type, db)
            processed += 1
        except Exception as exc:
            log.error(f"[enrichment] Failed to enrich IOC id={ioc.id}: {exc}")

    log.info(f"[enrichment] Batch complete — {processed}/{len(candidates)} IOC(s) enriched.")
    return processed
