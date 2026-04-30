"""
URLhaus feed (abuse.ch) — recent malicious URLs.
API: https://urlhaus-api.abuse.ch/v1/urls/recent/
Requires Auth-Key header since 2024-Q3.

API key priority: DB platform_settings['abusech_api_key'] → ABUSECH_API_KEY env var.
The worker calls configure(settings) before each run to inject the latest key.
"""
import os
import requests
from .base import BaseFeed


class URLhausFeed(BaseFeed):
    name = "urlhaus"
    interval_seconds = 3600   # hourly

    def __init__(self):
        self._api_key = os.getenv("ABUSECH_API_KEY", "")

    def configure(self, settings: dict) -> None:
        """Inject runtime settings from the DB (called by worker before each fetch)."""
        self._api_key = settings.get("abusech_api_key", "") or os.getenv("ABUSECH_API_KEY", "")

    def fetch(self):
        headers = {}
        if self._api_key:
            headers["Auth-Key"] = self._api_key

        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            data={"limit": 200},
            headers=headers,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("urls", [])
