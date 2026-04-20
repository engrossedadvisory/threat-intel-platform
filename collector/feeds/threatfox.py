import os
import requests
from .base import BaseFeed

URL = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFoxFeed(BaseFeed):
    name = "threatfox"
    interval_seconds = 900

    def fetch(self):
        payload = {"query": "get_iocs", "days": 1}
        api_key = os.getenv("ABUSECH_API_KEY", "")
        if api_key:
            payload["auth_key"] = api_key
        resp = requests.post(URL, json=payload, timeout=30)
        resp.raise_for_status()
        return resp.json().get("data") or []
