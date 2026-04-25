import requests
from .base import BaseFeed

URL = "https://isc.sans.edu/api/sources/attacks/20?json"

class DShieldFeed(BaseFeed):
    name = "dshield"
    interval_seconds = 3600

    def fetch(self):
        resp = requests.get(URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        # API returns {"sources": {"source": [...]} } or {"ip": [...]}
        # Try both shapes
        if "sources" in data:
            inner = data["sources"]
            if isinstance(inner, dict):
                return inner.get("source") or []
            return inner if isinstance(inner, list) else []
        if "ip" in data:
            return data["ip"] if isinstance(data["ip"], list) else []
        return []
