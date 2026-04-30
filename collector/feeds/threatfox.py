"""
ThreatFox feed (abuse.ch) — structured IoCs with malware families.
API: https://threatfox-api.abuse.ch/api/v1/
Requires auth_key in the JSON body since 2024-Q3.
Set ABUSECH_API_KEY in your .env file.
"""
import os
import requests
from .base import BaseFeed


class ThreatFoxFeed(BaseFeed):
    name = "threatfox"
    interval_seconds = 3600   # hourly

    def fetch(self):
        api_key = os.getenv("ABUSECH_API_KEY", "")
        payload = {"query": "get_iocs", "days": 1}
        if api_key:
            payload["auth_key"] = api_key

        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json=payload,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("data", [])
