"""
Ransomware.live feed (via ransomwatch GitHub data)
───────────────────────────────────────────────────
Pulls recent ransomware victim posts from the ransomwatch project, which
aggregates leak-site posts from active ransomware groups.

Every record carries a named threat actor (the ransomware group), a victim
organisation, country, and industry sector — the contextual depth that generic
URL/IOC feeds lack.

No API key required.
"""
import requests
from .base import BaseFeed

_URL = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
_GROUPS_URL = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json"


class RansomwareLiveFeed(BaseFeed):
    name = "ransomware_live"
    interval_seconds = 3600          # updated roughly every hour on GitHub

    def fetch(self) -> list:
        resp = requests.get(_URL, timeout=30)
        resp.raise_for_status()
        posts = resp.json()
        if not isinstance(posts, list):
            return []

        # Optionally fetch group metadata for richer descriptions
        group_meta: dict = {}
        try:
            gr = requests.get(_GROUPS_URL, timeout=15)
            if gr.ok:
                for g in gr.json():
                    gn = (g.get("name") or "").lower()
                    if gn:
                        group_meta[gn] = g
        except Exception:
            pass

        # Return only the 200 most recent posts (sorted by discovered desc)
        posts.sort(key=lambda p: p.get("discovered", ""), reverse=True)
        out = []
        for p in posts[:200]:
            gn = (p.get("group_name") or "").lower()
            p["_group_meta"] = group_meta.get(gn, {})
            out.append(p)
        return out
