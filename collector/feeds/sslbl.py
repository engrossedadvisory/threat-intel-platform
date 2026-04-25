"""
SSL Blacklist (SSLBL) feed — abuse.ch
──────────────────────────────────────
Pulls the list of malicious SSL certificate SHA1 fingerprints from abuse.ch.
SSLBL does not offer a JSON endpoint; the authoritative feed is CSV.

CSV columns: Listingdate, SHA1, Listingreason
No API key required.
"""
import csv
import io
import requests
from .base import BaseFeed

# abuse.ch SSLBL — CSV format (JSON endpoint does not exist)
_URL = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"


class SSLBLFeed(BaseFeed):
    name = "sslbl"
    interval_seconds = 3600

    def fetch(self) -> list:
        resp = requests.get(_URL, timeout=30)
        resp.raise_for_status()
        items = []
        reader = csv.reader(io.StringIO(resp.text))
        for row in reader:
            # Skip comment lines and header
            if not row or row[0].startswith("#"):
                continue
            # Columns: Listingdate, SHA1, Listingreason
            if len(row) < 3:
                continue
            listing_date = row[0].strip()
            sha1         = row[1].strip()
            reason       = row[2].strip()
            if not sha1 or len(sha1) != 40:
                continue
            # Derive malware family from reason string (e.g. "Dridex", "TrickBot C2")
            malware = reason.split()[0] if reason else "SSL Blacklist"
            items.append({
                "sha1_fingerprint": sha1,
                "reason":           reason,
                "listing_date":     listing_date,
                "tags":             [malware, "ssl", "certificate", "blacklist"],
            })
        return items[:500]
