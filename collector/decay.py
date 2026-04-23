"""
IOC Decay — automatically reduces confidence_score on threat reports over time.
Old intel is less actionable; this prevents stale data from polluting analysis.

Decay schedule (configurable via platform_settings):
  - < 7 days:   no decay
  - 7-30 days:  reduce by 10%
  - 30-90 days: reduce by 25%
  - > 90 days:  reduce by 50%, floor at 5

The decay is applied once per day.  A `decayed` flag is set on each processed
report so the UI can visually indicate degraded confidence.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import Column, Boolean
from sqlalchemy.orm import Session

from models import ThreatReport, engine as _engine, Base

log = logging.getLogger(__name__)

# ─── Patch ThreatReport to carry a `decayed` flag ────────────────────────────
# We add the column here so it auto-migrates if missing.  Using try/except
# prevents duplicate-column errors when the column already exists in the DB.

try:
    ThreatReport.decayed = Column(Boolean, default=False)
    _engine.execute  # type: ignore[attr-defined]  # noqa: triggers AttributeError on newer SA
except Exception:
    pass

# Ensure schema changes are reflected (harmless if already present)
try:
    from sqlalchemy import text as _text
    with _engine.connect() as _conn:
        _conn.execute(
            _text(
                "ALTER TABLE threat_reports ADD COLUMN IF NOT EXISTS decayed BOOLEAN DEFAULT FALSE"
            )
        )
        _conn.commit()
except Exception:
    pass  # column may already exist or DB may not support IF NOT EXISTS; safe to ignore


# ─── Decay schedule ───────────────────────────────────────────────────────────

# Each entry: (min_age_days, max_age_days, reduction_pct, floor)
_DECAY_SCHEDULE = [
    (7,   30,  10,  5),   # 7–30 days:  -10%
    (30,  90,  25,  5),   # 30–90 days: -25%
    (90, None, 50,  5),   # >90 days:   -50%
]

FLOOR_SCORE = 5   # confidence never decays below this value


def _decay_factor(age_days: int) -> Optional[tuple[int, int]]:
    """
    Return (reduction_pct, floor) for the given age in days.
    Returns None if no decay should be applied (< 7 days).
    """
    for min_age, max_age, pct, floor in _DECAY_SCHEDULE:
        if age_days >= min_age and (max_age is None or age_days < max_age):
            return pct, floor
    return None


# ─── Main decay function ──────────────────────────────────────────────────────

def apply_decay(db: Session) -> int:
    """
    Apply time-based confidence decay to all threat reports older than 7 days.

    - Reads optional overrides from platform_settings (decay_floor, decay_enabled).
    - Updates confidence_score in place; sets decayed=True on the row.
    - Will not reduce a score below FLOOR_SCORE (or the configured floor).
    - Returns the number of reports updated.
    """
    # Check whether decay is enabled (default: on)
    try:
        from settings import get_setting
        enabled_str = get_setting("decay_enabled", db)
        if enabled_str.lower() in ("false", "0", "no", "off"):
            log.debug("[decay] Decay disabled via platform_settings — skipping.")
            return 0
        floor_str = get_setting("decay_floor", db)
        floor = int(floor_str) if floor_str.isdigit() else FLOOR_SCORE
    except Exception:
        floor = FLOOR_SCORE

    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    now    = datetime.now(timezone.utc)

    candidates = (
        db.query(ThreatReport)
        .filter(ThreatReport.created_at <= cutoff)
        .filter(ThreatReport.confidence_score > floor)
        .order_by(ThreatReport.created_at.asc())
        .all()
    )

    if not candidates:
        log.debug("[decay] No reports eligible for decay.")
        return 0

    log.info(f"[decay] Applying decay to {len(candidates)} report(s)...")
    updated = 0

    for report in candidates:
        try:
            age = (now - report.created_at.replace(tzinfo=timezone.utc)).days
        except Exception:
            # created_at may already be tz-aware
            try:
                age = (now - report.created_at).days
            except Exception:
                log.debug(f"[decay] Could not compute age for report id={report.id} — skipping.")
                continue

        factor = _decay_factor(age)
        if factor is None:
            continue

        reduction_pct, sched_floor = factor
        effective_floor = max(floor, sched_floor)

        current_score = report.confidence_score or 0
        reduction     = max(1, round(current_score * reduction_pct / 100))
        new_score     = max(effective_floor, current_score - reduction)

        if new_score == current_score:
            # Already at floor — mark as decayed but don't re-reduce
            if not getattr(report, "decayed", False):
                try:
                    report.decayed = True
                    db.commit()
                except Exception:
                    db.rollback()
            continue

        try:
            report.confidence_score = new_score
            report.decayed = True  # type: ignore[attr-defined]
            db.commit()
            updated += 1
            log.debug(
                f"[decay] Report id={report.id} age={age}d: "
                f"score {current_score} → {new_score} (-{reduction_pct}%)"
            )
        except Exception as exc:
            log.error(f"[decay] Failed to update report id={report.id}: {exc}")
            db.rollback()

    log.info(f"[decay] Done — {updated}/{len(candidates)} report(s) decayed.")
    return updated
