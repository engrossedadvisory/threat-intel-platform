"""
Security RSS Feeds
Aggregates threat intel from public security blogs and vendor advisories.
AI-enriched via the analyzer pipeline.

Sources:
  - ESET Security Blog
  - CISA Cybersecurity Advisories
  - Palo Alto Unit 42
  - BleepingComputer
  - Krebs on Security
"""

import hashlib
import logging
import time
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from typing import Any, Optional
from xml.etree import ElementTree

import requests

from .base import BaseFeed

log = logging.getLogger(__name__)

REQUEST_TIMEOUT = 15  # seconds
MAX_ENTRIES_PER_FEED = 10
MAX_CONTENT_CHARS    = 2000
MAX_AGE_DAYS         = 7

_RSS_SOURCES = [
    ("ESET Blog",           "https://feeds.feedburner.com/eset/blog"),
    ("CISA Advisories",     "https://www.cisa.gov/news-events/cybersecurity-advisories/feed"),
    ("Unit 42",             "https://unit42.paloaltonetworks.com/feed/"),
    ("BleepingComputer",    "https://www.bleepingcomputer.com/feed/"),
    ("Krebs on Security",   "https://krebsonsecurity.com/feed/"),
]


def _parse_date(date_str: Optional[str]) -> Optional[datetime]:
    """Parse an RSS date string (RFC 2822 or ISO 8601) to a timezone-aware datetime."""
    if not date_str:
        return None
    # Try RFC 2822 (typical RSS format: "Tue, 22 Apr 2025 12:00:00 +0000")
    try:
        dt = parsedate_to_datetime(date_str)
        return dt.astimezone(timezone.utc)
    except Exception:
        pass
    # Try ISO 8601
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except Exception:
        return None


def _strip_html(text: str) -> str:
    """Very lightweight HTML tag stripper — no external deps required."""
    import re
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s{2,}", " ", text)
    return text.strip()


def _fingerprint(url: str) -> str:
    """SHA-256 of the article URL for deduplication."""
    return hashlib.sha256(url.strip().encode()).hexdigest()


def _parse_rss_xml(xml_text: str, source_name: str, cutoff: datetime) -> list[dict[str, Any]]:
    """
    Parse an RSS 2.0 or Atom feed from raw XML text.
    Returns a list of entry dicts (up to MAX_ENTRIES_PER_FEED, not older than cutoff).
    """
    results: list[dict[str, Any]] = []
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as exc:
        log.warning(f"[rss/{source_name}] XML parse error: {exc}")
        return results

    ns = {"atom": "http://www.w3.org/2005/Atom"}

    # ── RSS 2.0 ──────────────────────────────────────────────────────────────
    items = root.findall(".//item")

    # ── Atom ─────────────────────────────────────────────────────────────────
    if not items:
        items = root.findall(".//atom:entry", ns) or root.findall(".//entry")

    for item in items:
        if len(results) >= MAX_ENTRIES_PER_FEED:
            break

        def _text(tag: str, atom_tag: Optional[str] = None) -> str:
            el = item.find(tag)
            if el is None and atom_tag:
                el = item.find(atom_tag, ns) or item.find(atom_tag.split(":")[-1])
            return (el.text or "").strip() if el is not None else ""

        title   = _text("title")
        link_el = item.find("link")
        # In Atom, <link href="..."/> — no text content
        if link_el is not None:
            link = (link_el.get("href") or link_el.text or "").strip()
        else:
            link = ""

        if not link:
            continue  # No URL — skip

        pub_date = _parse_date(
            _text("pubDate") or _text("published", "atom:published") or _text("updated", "atom:updated")
        )

        if pub_date and pub_date < cutoff:
            continue  # Too old

        # Content: try description / summary / content
        raw_content = (
            _text("description") or
            _text("summary", "atom:summary") or
            _text("content", "atom:content") or
            ""
        )
        content = _strip_html(raw_content)[:MAX_CONTENT_CHARS]

        results.append({
            "source_name": source_name,
            "title":       title[:512],
            "url":         link[:1024],
            "content":     content,
            "published_at": pub_date.isoformat() if pub_date else None,
            "fingerprint": _fingerprint(link),
        })

    return results


class SecurityRSSFeed(BaseFeed):
    """
    Aggregates recent threat intelligence articles from public security RSS feeds.
    Each entry is returned as a dict for the worker to persist and AI-analyze.
    """

    name             = "rss_feeds"
    interval_seconds = 3600  # 1 hour

    def fetch(self) -> list[dict[str, Any]]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=MAX_AGE_DAYS)
        all_entries: list[dict[str, Any]] = []

        session = requests.Session()
        session.headers["User-Agent"] = (
            "Mozilla/5.0 (compatible; VantelligenceRSS/1.0; +security-research)"
        )

        for source_name, feed_url in _RSS_SOURCES:
            try:
                resp = session.get(feed_url, timeout=REQUEST_TIMEOUT)
                resp.raise_for_status()
            except requests.RequestException as exc:
                log.warning(f"[rss/{source_name}] Fetch failed: {exc}")
                time.sleep(1)
                continue

            entries = _parse_rss_xml(resp.text, source_name, cutoff)
            log.debug(f"[rss/{source_name}] {len(entries)} entries within {MAX_AGE_DAYS}-day window.")
            all_entries.extend(entries)
            time.sleep(1)  # polite crawl delay

        log.info(f"[rss_feeds] Total entries fetched: {len(all_entries)}")
        return all_entries
