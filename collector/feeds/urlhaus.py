"""
URLhaus feed (abuse.ch) — recent malicious URLs.
API: https://urlhaus-api.abuse.ch/v1/urls/recent/
Requires Auth-Key header since 2024-Q3.
Set ABUSECH_API_KEY in your .env file.
"""
import os
import requests
from .base import BaseFeed


class URLhausFeed(BaseFeed):
    name = "urlhaus"
    interval_seconds = 3600   # hourly

    def fetch(self):
        api_key = os.getenv("ABUSECH_API_KEY", "")
        headers = {}
        if api_key:
            headers["Auth-Key"] = api_key

        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            data={"limit": 200},
            headers=headers,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("urls", [])
