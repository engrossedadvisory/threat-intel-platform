import hashlib
import requests
from .base import BaseFeed

URL = "https://openphish.com/feed.txt"

class OpenPhishFeed(BaseFeed):
    name = "openphish"
    interval_seconds = 3600

    def fetch(self):
        resp = requests.get(URL, timeout=30)
        resp.raise_for_status()
        items = []
        for line in resp.text.splitlines():
            line = line.strip()
            if line.startswith("http"):
                items.append({
                    "url": line,
                    "id": hashlib.md5(line.encode()).hexdigest()[:16],
                })
        return items[:500]
