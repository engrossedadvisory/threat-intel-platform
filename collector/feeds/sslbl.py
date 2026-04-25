import requests
from .base import BaseFeed

URL = "https://sslbl.abuse.ch/blacklist/sslblacklist.json"

class SSLBLFeed(BaseFeed):
    name = "sslbl"
    interval_seconds = 3600

    def fetch(self):
        resp = requests.get(URL, timeout=30)
        resp.raise_for_status()
        return resp.json().get("results") or []
