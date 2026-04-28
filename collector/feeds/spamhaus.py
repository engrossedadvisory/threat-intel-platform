"""
Spamhaus DROP / EDROP feeds — IP blocks associated with spam/malware/botnet infrastructure.
DROP:  https://www.spamhaus.org/drop/drop.txt   (IPv4 CIDRs)
EDROP: https://www.spamhaus.org/drop/edrop.txt  (extended, delegated netblocks)
Free, no authentication required.
"""
import requests
from .base import BaseFeed


_DROP_URLS = [
    "https://www.spamhaus.org/drop/drop.txt",
    "https://www.spamhaus.org/drop/edrop.txt",
]


class SpamhausFeed(BaseFeed):
    name = "spamhaus"
    interval_seconds = 43200   # every 12 hours (list changes slowly)

    def fetch(self):
        items = []
        for url in _DROP_URLS:
            try:
                resp = requests.get(url, timeout=20)
                resp.raise_for_status()
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith(";"):
                        continue
                    # Format: "1.10.16.0/24 ; SBL123456"
                    parts = line.split(";", 1)
                    cidr = parts[0].strip()
                    ref  = parts[1].strip() if len(parts) > 1 else ""
                    if cidr:
                        items.append({"cidr": cidr, "sbl_ref": ref, "source_url": url})
            except Exception:
                pass
        return items
