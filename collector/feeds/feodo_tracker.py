import requests
from .base import BaseFeed

URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"

class FeodoTrackerFeed(BaseFeed):
    name = "feodo_tracker"
    interval_seconds = 3600

    def fetch(self):
        resp = requests.get(URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, list) else []
