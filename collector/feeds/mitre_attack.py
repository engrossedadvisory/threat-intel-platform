import requests
from .base import BaseFeed

URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


class MITREAttackFeed(BaseFeed):
    name = "mitre_attack"
    interval_seconds = 86400

    def fetch(self):
        resp = requests.get(URL, timeout=60)
        resp.raise_for_status()
        objects = resp.json().get("objects", [])
        return [
            o for o in objects
            if o.get("type") == "attack-pattern" and not o.get("revoked", False)
        ]
