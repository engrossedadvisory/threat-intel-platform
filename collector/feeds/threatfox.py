"""
ThreatFox feed (abuse.ch) — structured IoCs with malware families.
API: https://threatfox-api.abuse.ch/api/v1/
Requires auth_key in the JSON body since 2024-Q3.

API key priority: DB platform_settings['abusech_api_key'] → ABUSECH_API_KEY env var.
The worker calls configure(settings) before each run to inject the latest key.
"""
import os
import requests
from .base import BaseFeed


class ThreatFoxFeed(BaseFeed):
    name = "threatfox"
    interval_seconds = 3600   # hourly

    def __init__(self):
        self._api_key = os.getenv("ABUSECH_API_KEY", "")

    def configure(self, settings: dict) -> None:
        """Inject runtime settings from the DB (called by worker before each fetch)."""
        self._api_key = settings.get("abusech_api_key", "") or os.getenv("ABUSECH_API_KEY", "")

    def fetch(self):
        payload = {"query": "get_iocs", "days": 1}
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            # abuse.ch requires auth_key in the JSON body AND accepts Auth-Key header
            payload["auth_key"] = self._api_key
            headers["Auth-Key"] = self._api_key

        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json=payload,
            headers=headers,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        # API returns {"query_status": "ok", "data": [...]} or error status
        if isinstance(data, dict) and data.get("query_status") not in ("ok", None):
            raise RuntimeError(f"ThreatFox error: {data.get('query_status')}")
        return data.get("data", []) if isinstance(data, dict) else []
