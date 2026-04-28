"""
URLhaus feed (abuse.ch) — recent malicious URLs.
API: https://urlhaus-api.abuse.ch/v1/urls/recent/
Free, no API key required.
"""
import requests
from .base import BaseFeed


class URLhausFeed(BaseFeed):
    name = "urlhaus"
    interval_seconds = 3600   # hourly

    def fetch(self):
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            data={"limit": 200},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("urls", [])
