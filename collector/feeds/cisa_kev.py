import requests
from .base import BaseFeed

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CISAKEVFeed(BaseFeed):
    name = "cisa_kev"
    interval_seconds = 3600

    def fetch(self):
        resp = requests.get(URL, timeout=30)
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
        return vulns[:100]
