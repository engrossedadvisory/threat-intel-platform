import os
import requests
from .base import BaseFeed

URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/"


class URLhausFeed(BaseFeed):
    name = "urlhaus"
    interval_seconds = 1800

    def fetch(self):
        api_key = os.getenv("ABUSECH_API_KEY", "")
        headers = {"Auth-Key": api_key} if api_key else {}
        resp = requests.get(URL, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.json().get("urls") or []
