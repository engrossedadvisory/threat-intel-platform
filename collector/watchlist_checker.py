"""
Watchlist Checker
Checks new IOCs and feed findings against the watched assets list.
Produces watchlist_hits rows for any matches; the alerter then fires notifications.
"""

import hashlib
import ipaddress
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import Session

from models import Base, IOC, engine as _engine

log = logging.getLogger(__name__)


# ─── watched_assets table ─────────────────────────────────────────────────────

class WatchedAsset(Base):
    """
    An asset the organisation wants to monitor.
    asset_type: domain | ip | cidr | email_domain | keyword
    """
    __tablename__ = "watched_assets"
    id         = Column(Integer, primary_key=True, index=True)
    name       = Column(String(255))          # human-readable label
    asset_type = Column(String(50), index=True)
    value      = Column(String(512), index=True)
    enabled    = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


# ─── watchlist_hits table ─────────────────────────────────────────────────────

class WatchlistHit(Base):
    """A confirmed match between an IOC (or other finding) and a watched asset."""
    __tablename__ = "watchlist_hits"
    id          = Column(Integer, primary_key=True, index=True)
    asset_id    = Column(Integer, index=True)          # FK → watched_assets.id
    ioc_value   = Column(String(512))
    ioc_type    = Column(String(50))
    source_feed = Column(String(100))
    hit_type    = Column(String(50), default="ioc_match")
    severity    = Column(String(20), default="medium")
    fingerprint = Column(String(64), unique=True, index=True)
    alerted     = Column(Boolean, default=False)
    hit_at      = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


Base.metadata.create_all(bind=_engine, tables=[
    WatchedAsset.__table__,
    WatchlistHit.__table__,
])


# ─── Matching logic ───────────────────────────────────────────────────────────

def _matches_asset(ioc_value: str, ioc_type: str, asset: WatchedAsset) -> bool:
    """
    Return True if the IOC matches the watched asset.

    Rules by asset_type:
      domain       — IOC value is or ends with ".{watched_domain}"
      ip           — exact string match
      cidr         — IOC IP falls within the CIDR range
      email_domain — IOC email ends with "@{watched_domain}"
      keyword      — case-insensitive substring match in ioc_value
    """
    atype = (asset.asset_type or "").lower().strip()
    aval  = (asset.value or "").strip()
    ival  = (ioc_value or "").strip()

    try:
        if atype == "domain":
            ival_lower = ival.lower()
            aval_lower = aval.lower().lstrip(".")
            # Exact match or subdomain
            return ival_lower == aval_lower or ival_lower.endswith("." + aval_lower)

        elif atype == "ip":
            return ival == aval

        elif atype == "cidr":
            if ioc_type not in ("ip", "ip_address"):
                return False
            try:
                network = ipaddress.ip_network(aval, strict=False)
                return ipaddress.ip_address(ival) in network
            except ValueError:
                return False

        elif atype == "email_domain":
            # IOC should look like user@domain.com
            if "@" not in ival:
                return False
            email_domain = ival.split("@", 1)[-1].lower()
            return email_domain == aval.lower().lstrip("@")

        elif atype == "keyword":
            return aval.lower() in ival.lower()

        else:
            log.debug(f"[watchlist] Unknown asset_type '{atype}' — skipping.")
            return False

    except Exception as exc:
        log.debug(f"[watchlist] Match error for asset id={asset.id}: {exc}")
        return False


# ─── Deduplication fingerprint ────────────────────────────────────────────────

def _fingerprint(asset_id: int, ioc_value: str, hit_type: str) -> str:
    """SHA-256 fingerprint for deduplicating watchlist hits."""
    raw = f"{asset_id}|{ioc_value.strip().lower()}|{hit_type}"
    return hashlib.sha256(raw.encode()).hexdigest()


# ─── Severity heuristic ───────────────────────────────────────────────────────

_CRITICAL_TYPES = {"hash_sha256", "hash_md5", "hash_sha1"}
_HIGH_FEEDS     = {"threatfox", "malwarebazaar", "otx", "darkweb"}

def _severity(ioc_type: str, source_feed: str) -> str:
    if ioc_type in _CRITICAL_TYPES:
        return "critical"
    if source_feed in _HIGH_FEEDS:
        return "high"
    return "medium"


# ─── Single-IOC check ─────────────────────────────────────────────────────────

def check_ioc_against_watchlist(
    ioc_value: str,
    ioc_type: str,
    source_feed: str,
    db: Session,
) -> list[WatchlistHit]:
    """
    Check a single IOC against every enabled watched asset.
    Persists new WatchlistHit rows for any matches (deduped via fingerprint).
    Returns the list of newly created hits.
    """
    assets = db.query(WatchedAsset).filter_by(enabled=True).all()
    if not assets:
        return []

    new_hits: list[WatchlistHit] = []

    for asset in assets:
        if not _matches_asset(ioc_value, ioc_type, asset):
            continue

        hit_type = "ioc_match"
        fp = _fingerprint(asset.id, ioc_value, hit_type)

        # Dedup: skip if we already have this fingerprint
        if db.query(WatchlistHit).filter_by(fingerprint=fp).first():
            log.debug(f"[watchlist] Duplicate hit skipped: asset={asset.id}, ioc='{ioc_value}'")
            continue

        sev = _severity(ioc_type, source_feed)
        hit = WatchlistHit(
            asset_id    = asset.id,
            ioc_value   = ioc_value[:512],
            ioc_type    = ioc_type[:50],
            source_feed = source_feed[:100],
            hit_type    = hit_type,
            severity    = sev,
            fingerprint = fp,
            alerted     = False,
            hit_at      = datetime.now(timezone.utc),
        )
        db.add(hit)
        new_hits.append(hit)
        log.info(
            f"[watchlist] HIT — asset='{asset.value}' ({asset.asset_type}), "
            f"ioc='{ioc_value}' ({ioc_type}), feed={source_feed}, severity={sev}"
        )

    if new_hits:
        try:
            db.commit()
        except Exception as exc:
            log.error(f"[watchlist] DB commit failed: {exc}")
            db.rollback()
            return []

    return new_hits


# ─── Batch check (all new IOCs above a given ID) ─────────────────────────────

def check_all_new_iocs(db: Session, since_id: int = 0) -> int:
    """
    Check all IOCs with id > since_id against the watchlist.
    Returns the total number of new hits created.
    """
    iocs = (
        db.query(IOC)
        .filter(IOC.id > since_id)
        .order_by(IOC.id.asc())
        .all()
    )

    if not iocs:
        log.debug(f"[watchlist] No new IOCs above id={since_id}.")
        return 0

    log.info(f"[watchlist] Checking {len(iocs)} IOC(s) against watchlist (since id={since_id})...")
    total_hits = 0

    for ioc in iocs:
        # Derive the source feed from the parent report if available
        source_feed = "unknown"
        try:
            if ioc.report:
                source_feed = ioc.report.source_feed or "unknown"
        except Exception:
            pass

        hits = check_ioc_against_watchlist(ioc.value, ioc.ioc_type, source_feed, db)
        total_hits += len(hits)

    if total_hits:
        log.info(f"[watchlist] Batch complete — {total_hits} new hit(s) across {len(iocs)} IOC(s).")
    else:
        log.debug(f"[watchlist] Batch complete — no hits from {len(iocs)} IOC(s).")

    return total_hits
