"""
Platform settings manager
─────────────────────────
Reads from the `platform_settings` DB table (written by the WebUI admin panel).
Falls back to environment variables when a key is absent from the table.

Usage (in a worker context where `db` is an active SQLAlchemy session):

    from settings import get_setting, get_all_settings

    enabled  = get_setting("dark_web_enabled", db) == "true"
    keywords = get_setting("dark_web_keywords", db)
"""

import os
import logging
from typing import Optional

log = logging.getLogger(__name__)

# ─── Env-var fallbacks ────────────────────────────────────────────────────────
# These are used when the platform_settings table has no row for a given key.
_ENV_FALLBACKS: dict[str, str] = {
    "dark_web_enabled":       os.getenv("DARK_WEB_ENABLED",       "false"),
    "dark_web_keywords":      os.getenv("DARK_WEB_KEYWORDS",       ""),
    "dark_web_onion_sources": os.getenv("DARK_WEB_ONION_SOURCES",  ""),
    "dark_web_interval":      os.getenv("DARK_WEB_INTERVAL",       "21600"),
    "enrichment_vt_key":      os.getenv("VT_API_KEY",          ""),
    "enrichment_gn_key":      os.getenv("GREYNOISE_API_KEY",    ""),
    "enrichment_shodan_key":  os.getenv("SHODAN_API_KEY",       ""),
    "github_token":           os.getenv("GITHUB_TOKEN",         ""),
    "alert_email_enabled":    "false",
    "smtp_host":              os.getenv("SMTP_HOST",            ""),
    "smtp_port":              os.getenv("SMTP_PORT",            "587"),
    "smtp_user":              os.getenv("SMTP_USER",            ""),
    "smtp_pass":              os.getenv("SMTP_PASS",            ""),
    "alert_from_email":       os.getenv("ALERT_FROM_EMAIL",     ""),
    "alert_to_email":         os.getenv("ALERT_TO_EMAIL",       ""),
}


def get_setting(key: str, db=None) -> str:
    """Return the value for *key*, DB row takes priority over env var fallback."""
    if db is not None:
        try:
            from models import PlatformSettings
            row = db.query(PlatformSettings).filter_by(key=key).first()
            if row and row.value is not None:
                return row.value
        except Exception as exc:
            log.debug(f"[settings] DB read failed for '{key}': {exc}")
    return _ENV_FALLBACKS.get(key, "")


def get_all_settings(db=None) -> dict[str, str]:
    """Return all known settings as a dict."""
    return {k: get_setting(k, db) for k in _ENV_FALLBACKS}


def upsert_setting(key: str, value: str, db, updated_by: str = "webui") -> None:
    """Write or update a setting in the DB.  Caller must commit the session."""
    from models import PlatformSettings
    from datetime import datetime, timezone
    row = db.query(PlatformSettings).filter_by(key=key).first()
    if row:
        row.value      = value
        row.updated_at = datetime.now(timezone.utc)
        row.updated_by = updated_by
    else:
        db.add(PlatformSettings(key=key, value=value, updated_by=updated_by))
