import os
import requests
from .base import BaseFeed

BASE_URL = "https://otx.alienvault.com/api/v1"


class OTXFeed(BaseFeed):
    name = "otx"
    interval_seconds = 3600

    def fetch(self):
        api_key = os.getenv("OTX_API_KEY", "")
        if not api_key:
            return []
        try:
            resp = requests.get(
                f"{BASE_URL}/pulses/subscribed",
                headers={"X-OTX-API-KEY": api_key},
                params={"limit": 20},
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json().get("results") or []
        except Exception:
            return []
