"""
Threat Actor / APT Group feed.

Sources (merged):
1. MITRE ATT&CK Enterprise — intrusion-set objects (groups / nation-state actors)
   https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
2. ETDA APT Group database — ~300 named APT groups with aliases, origin, targets
   https://apt.etda.or.th/cgi-bin/getcard.cgi?g=all&o=json

Both are free and require no API key.
"""
import requests
from .base import BaseFeed


_MITRE_CTI_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
_ETDA_URL = "https://apt.etda.or.th/cgi-bin/getcard.cgi?g=all&o=json"


def _mitre_groups() -> list:
    """Return intrusion-set objects from the MITRE ATT&CK STIX bundle."""
    try:
        resp = requests.get(_MITRE_CTI_URL, timeout=60)
        resp.raise_for_status()
        objects = resp.json().get("objects", [])
        return [
            o for o in objects
            if o.get("type") == "intrusion-set" and not o.get("revoked", False)
        ]
    except Exception:
        return []


def _etda_groups() -> list:
    """Return APT group cards from ETDA."""
    try:
        resp = requests.get(_ETDA_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        # ETDA returns a dict keyed by group ID
        if isinstance(data, dict):
            return list(data.values())
        if isinstance(data, list):
            return data
    except Exception:
        pass
    return []


class APTGroupFeed(BaseFeed):
    """Aggregates named threat-actor/APT group profiles into the reports table."""
    name = "apt_groups"
    interval_seconds = 86400   # daily

    def fetch(self):
        items = []

        # ── MITRE ATT&CK groups ──────────────────────────────────────────────
        for obj in _mitre_groups():
            refs = obj.get("external_references", [])
            group_id = next(
                (r.get("external_id", "") for r in refs
                 if r.get("source_name") == "mitre-attack"),
                "",
            )
            url = next(
                (r.get("url", "") for r in refs
                 if r.get("source_name") == "mitre-attack"),
                "",
            )
            aliases = obj.get("aliases", [])
            items.append({
                "_source": "mitre",
                "group_id": group_id,
                "name": obj.get("name", "Unknown"),
                "aliases": aliases,
                "description": obj.get("description", ""),
                "url": url,
                "target_industry": "Multiple",
                "origin": "",
            })

        # ── ETDA APT groups ──────────────────────────────────────────────────
        for card in _etda_groups():
            if not isinstance(card, dict):
                continue
            name = (
                card.get("name")
                or card.get("Name")
                or card.get("title")
                or "Unknown"
            )
            aliases_raw = card.get("names") or card.get("aliases") or []
            if isinstance(aliases_raw, str):
                aliases_raw = [a.strip() for a in aliases_raw.split(",") if a.strip()]
            desc = (
                card.get("description")
                or card.get("overview")
                or card.get("comment")
                or ""
            )
            origin = (
                card.get("country")
                or card.get("origin_country")
                or card.get("sponsor")
                or ""
            )
            target = (
                card.get("target_category")
                or card.get("target_industries")
                or card.get("targets")
                or "Multiple"
            )
            if isinstance(target, list):
                target = ", ".join(str(t) for t in target)
            items.append({
                "_source": "etda",
                "group_id": card.get("id", ""),
                "name": name,
                "aliases": aliases_raw,
                "description": desc,
                "url": card.get("url", ""),
                "target_industry": str(target)[:255],
                "origin": str(origin)[:100],
            })

        return items
