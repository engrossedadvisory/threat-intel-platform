import requests
from .base import BaseFeed

URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
_KEEP = {"attack-pattern", "course-of-action", "relationship"}


class MITREAttackFeed(BaseFeed):
    name = "mitre_attack"
    interval_seconds = 86400

    def fetch(self):
        resp = requests.get(URL, timeout=60)
        resp.raise_for_status()
        return [
            o for o in resp.json().get("objects", [])
            if o.get("type") in _KEEP and not o.get("revoked", False)
        ]
