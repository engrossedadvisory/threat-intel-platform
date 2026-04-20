import requests
from datetime import datetime, timezone, timedelta
from .base import BaseFeed

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDFeed(BaseFeed):
    name = "nvd"
    interval_seconds = 7200

    def fetch(self):
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=7)
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "cvssV3Severity": "HIGH",
            "resultsPerPage": 50,
        }
        try:
            resp = requests.get(URL, params=params, timeout=30)
            resp.raise_for_status()
            return resp.json().get("vulnerabilities") or []
        except Exception:
            # NVD rate-limits aggressively; return empty and retry next cycle
            return []
