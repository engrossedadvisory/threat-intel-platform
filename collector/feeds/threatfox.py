"""
ThreatFox feed (abuse.ch) — structured IoCs with malware families.
API: https://threatfox-api.abuse.ch/api/v1/
Free, no API key required.
"""
import requests
from .base import BaseFeed


class ThreatFoxFeed(BaseFeed):
    name = "threatfox"
    interval_seconds = 3600   # hourly

    def fetch(self):
        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "get_iocs", "days": 1},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("data", [])
