import os
import requests
from .base import BaseFeed

URL = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFoxFeed(BaseFeed):
    name = "threatfox"
    interval_seconds = 900

    def fetch(self):
        api_key = os.getenv("ABUSECH_API_KEY", "")
        headers = {"Auth-Key": api_key} if api_key else {}
        resp = requests.post(URL, json={"query": "get_iocs", "days": 1}, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.json().get("data") or []
