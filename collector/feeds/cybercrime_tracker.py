"""
Cybercrime Tracker feed
───────────────────────
Tracks active malware command-and-control (C2) panels detected by honeypots
and community submissions.  Each record has:
  - The C2 panel URL
  - Malware family (ZeuS, Pushdo, QakBot, AgentTesla, etc.)
  - Status (online / offline)
  - First-seen date

Unlike generic URL blocklists, every IOC here is tied to a named malware
family, giving the threat actor attribution that URLhaus/ThreatFox lacked.

No API key required.
"""
import csv
import hashlib
import io
import requests
from .base import BaseFeed

# Plain-text CSV: url,date,type,status
_URL = "https://cybercrime-tracker.net/ccamlist.php"

# Fallback: RSS gives recent entries with richer descriptions
_RSS_URL = "https://cybercrime-tracker.net/rss.xml"


class CybercrimeTrackerFeed(BaseFeed):
    name = "cybercrime_tracker"
    interval_seconds = 1800

    def fetch(self) -> list:
        # Primary: CSV feed
        try:
            return self._fetch_csv()
        except Exception:
            pass
        # Fallback: RSS
        try:
            return self._fetch_rss()
        except Exception:
            return []

    # ── CSV ──────────────────────────────────────────────────────────────────
    def _fetch_csv(self) -> list:
        resp = requests.get(_URL, timeout=30)
        resp.raise_for_status()
        text = resp.text.strip()
        items = []
        reader = csv.reader(io.StringIO(text))
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            # Columns vary — try to extract url, date, malware_type, status
            if len(row) < 2:
                continue
            url_val      = row[0].strip()
            date_val     = row[1].strip() if len(row) > 1 else ""
            malware_type = row[2].strip() if len(row) > 2 else "Unknown"
            status_val   = row[3].strip() if len(row) > 3 else "unknown"
            if not url_val.startswith("http"):
                continue
            items.append({
                "url":     url_val,
                "date":    date_val,
                "malware": malware_type,
                "status":  status_val,
                "id":      hashlib.md5(url_val.encode()).hexdigest()[:16],
            })
        return items[:300]

    # ── RSS fallback ──────────────────────────────────────────────────────────
    def _fetch_rss(self) -> list:
        import xml.etree.ElementTree as ET
        resp = requests.get(_RSS_URL, timeout=30)
        resp.raise_for_status()
        root = ET.fromstring(resp.text)
        ns   = {"atom": "http://www.w3.org/2005/Atom"}
        items = []
        for item in root.iter("item"):
            title = (item.findtext("title") or "").strip()
            link  = (item.findtext("link")  or "").strip()
            desc  = (item.findtext("description") or "").strip()
            # Title format is often "MALWARE — domain.com"
            parts       = title.split("—", 1)
            malware     = parts[0].strip() if len(parts) == 2 else "Unknown"
            items.append({
                "url":     link,
                "date":    item.findtext("pubDate") or "",
                "malware": malware,
                "status":  "online",
                "desc":    desc,
                "id":      hashlib.md5(link.encode()).hexdigest()[:16],
            })
        return items[:300]
