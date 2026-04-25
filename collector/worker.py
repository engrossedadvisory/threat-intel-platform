import time
import logging
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from models import SessionLocal, ThreatReport, IOC, CVERecord, FeedStatus, MITRETechnique, MITREMitigation
from feeds import ALL_FEEDS
from analyzer import analyze
from enrichment import enrich_batch
from alerter import process_pending_alerts
from watchlist_checker import check_all_new_iocs
from decay import apply_decay
from threat_researcher import run_research_cycle

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

_next_run: dict[str, float] = {}


# ─── Feed status helpers ───────────────────────────────────────────────────────

def _upsert_status(db: Session, name: str, **kwargs):
    record = db.query(FeedStatus).filter_by(feed_name=name).first()
    if not record:
        record = FeedStatus(feed_name=name)
        db.add(record)
    for k, v in kwargs.items():
        setattr(record, k, v)
    db.commit()


# ─── Per-feed processors ──────────────────────────────────────────────────────

def _process_cisa_kev(db: Session, items: list) -> int:
    saved = 0
    for v in items:
        cve_id = v.get("cveID", "")
        if not cve_id or db.query(CVERecord).filter_by(cve_id=cve_id).first():
            continue
        db.add(CVERecord(
            cve_id=cve_id,
            description=v.get("shortDescription", "")[:2000],
            vendor=v.get("vendorProject", "Unknown"),
            product=v.get("product", "Unknown"),
            cisa_due_date=v.get("dueDate", ""),
            is_kev=1,
        ))
        saved += 1
    db.commit()
    return saved


def _process_threatfox(db: Session, items: list) -> int:
    import re
    from urllib.parse import urlparse
    _IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

    saved = 0
    for item in items:
        source_id = f"threatfox_{item.get('id', '')}"
        if db.query(ThreatReport).filter_by(source_id=source_id).first():
            continue

        malware   = item.get("malware_printable", "") or item.get("malware", "") or ""
        # Use malware family as a meaningful actor label when no explicit actor
        actor     = item.get("threat_actor") or malware or "Unknown"
        ioc_type  = item.get("ioc_type", "unknown")
        ioc_val   = item.get("ioc_value", "")
        tags      = item.get("tags") or []

        raw = (
            f"ThreatFox IOC: {ioc_val} (type: {ioc_type}). "
            f"Malware: {malware}. "
            f"Threat type: {item.get('threat_type', '')} \u2014 {item.get('threat_type_desc', '')}. "
            f"Confidence: {item.get('confidence_level', 0)}%. "
            f"Reporter: {item.get('reporter', 'Unknown')}. "
            f"Malware aliases: {', '.join(item.get('malware_alias', []) or [])}. "
            f"Tags: {', '.join(str(t) for t in tags)}. "
            f"First seen: {item.get('first_seen', '')}. "
            f"Last seen: {item.get('last_seen', '')}."
        )
        report = ThreatReport(
            source_feed="threatfox",
            source_id=source_id,
            threat_actor=actor,
            confidence_score=int(item.get("confidence_level") or 0),
            raw_source=raw[:2000],
            summary=f"{malware} IOC ({ioc_type}): {ioc_val[:60]}. Threat: {item.get('threat_type', '')}.",
        )
        db.add(report)
        db.flush()

        if ioc_val:
            db.add(IOC(
                report_id=report.id,
                ioc_type=ioc_type,
                value=ioc_val[:512],
                malware_family=malware,
                tags=tags,
            ))
            # ip:port → also store a clean ip IOC so geo mapping works
            if ioc_type == "ip:port" and ":" in ioc_val:
                clean_ip = ioc_val.rsplit(":", 1)[0].strip("[]")  # handle IPv6 [::1]:80
                if _IP_RE.match(clean_ip):
                    db.add(IOC(
                        report_id=report.id,
                        ioc_type="ip",
                        value=clean_ip[:512],
                        malware_family=malware,
                        tags=tags,
                    ))
            # url → also extract hostname as domain or ip IOC
            elif ioc_type == "url":
                try:
                    host = urlparse(ioc_val).hostname or ""
                    if host:
                        host_type = "ip" if _IP_RE.match(host) else "domain"
                        db.add(IOC(
                            report_id=report.id,
                            ioc_type=host_type,
                            value=host[:512],
                            malware_family=malware,
                            tags=tags,
                        ))
                except Exception:
                    pass

        saved += 1
    db.commit()
    return saved


def _process_urlhaus(db: Session, items: list) -> int:
    import re
    from urllib.parse import urlparse
    _IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

    saved = 0
    for item in items:
        source_id = f"urlhaus_{item.get('id', '')}"
        if db.query(ThreatReport).filter_by(source_id=source_id).first():
            continue

        tags    = item.get("tags") or []
        threat  = item.get("threat", "")
        malware = ", ".join(str(t) for t in tags[:3]) or threat or "Unknown"

        url_val = item.get("url", "")
        host = (item.get("host") or "").strip()
        if not host and url_val:
            try:
                from urllib.parse import urlparse as _urlparse
                host = _urlparse(url_val).hostname or ""
            except Exception:
                host = ""
        _bl = item.get("blacklists") or {}
        _bl_listed = ', '.join(k for k, v in _bl.items() if str(v).lower() == 'listed')
        raw = (
            f"URLhaus malicious URL: {url_val}. "
            f"Host: {host}. "
            f"Status: {item.get('url_status', 'unknown')}. "
            f"Threat type: {threat}. "
            f"Malware tags: {', '.join(str(t) for t in tags)}. "
            f"Reporter: {item.get('reporter', 'Unknown')}. "
            f"Date added: {item.get('date_added', '')}. "
            f"URLhaus reference: {item.get('urlhaus_reference', '')}. "
            f"Blacklisted by: {_bl_listed}."
        )
        report = ThreatReport(
            source_feed="urlhaus",
            source_id=source_id,
            threat_actor="Unknown",
            confidence_score=70,
            raw_source=raw[:2000],
            summary=f"Malicious URL ({threat}) hosted at {host}. Status: {item.get('url_status', 'unknown')}.",
        )
        db.add(report)
        db.flush()

        if url_val:
            db.add(IOC(
                report_id=report.id,
                ioc_type="url",
                value=url_val[:512],
                malware_family=malware,
                tags=tags,
            ))

        if host:
            host_type = "ip" if _IP_RE.match(host) else "domain"
            db.add(IOC(
                report_id=report.id,
                ioc_type=host_type,
                value=host[:512],
                malware_family=malware,
                tags=tags,
            ))

        saved += 1
    db.commit()
    return saved


def _process_malwarebazaar(db: Session, items: list) -> int:
    saved = 0
    for item in items:
        sha256 = item.get("sha256_hash", "")
        source_id = f"mb_{sha256}"
        if not sha256 or db.query(ThreatReport).filter_by(source_id=source_id).first():
            continue
        tags = item.get("tags") or []
        report = ThreatReport(
            source_feed="malwarebazaar",
            source_id=source_id,
            threat_actor=item.get("reporter", "Unknown"),
            confidence_score=80,
            raw_source=str(item)[:2000],
        )
        db.add(report)
        db.flush()
        db.add(IOC(
            report_id=report.id,
            ioc_type="hash_sha256",
            value=sha256,
            malware_family=item.get("signature") or (tags[0] if tags else "Unknown"),
            tags=tags,
        ))
        saved += 1
    db.commit()
    return saved


def _process_nvd(db: Session, items: list) -> int:
    saved = 0
    for vuln in items:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id or db.query(CVERecord).filter_by(cve_id=cve_id).first():
            continue
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), ""
        )
        metrics = cve.get("metrics", {})
        cvss_score, cvss_vector = None, None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                break
        db.add(CVERecord(
            cve_id=cve_id,
            description=desc[:2000],
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
        ))
        saved += 1
    db.commit()
    return saved


def _process_mitre_attack(db: Session, items: list) -> int:
    techniques: dict = {}       # stix_id -> object
    course_of_actions: dict = {}  # stix_id -> object
    relationships: list = []

    for obj in items:
        t = obj.get("type")
        if t == "attack-pattern":
            techniques[obj["id"]] = obj
        elif t == "course-of-action":
            course_of_actions[obj["id"]] = obj
        elif t == "relationship" and obj.get("relationship_type") == "mitigates":
            relationships.append(obj)

    # ── Persist techniques ────────────────────────────────────────────────────
    saved = 0
    stix_to_db_id: dict = {}   # stix_id -> mitre_techniques.id

    for stix_id, tech in techniques.items():
        tech_id = next(
            (r["external_id"] for r in tech.get("external_references", [])
             if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not tech_id:
            continue

        existing = db.query(MITRETechnique).filter_by(technique_id=tech_id).first()
        if existing:
            stix_to_db_id[stix_id] = existing.id
            continue

        tactics = ", ".join(
            p["phase_name"].replace("-", " ").title()
            for p in tech.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        )
        row = MITRETechnique(
            technique_id=tech_id,
            stix_id=stix_id,
            name=tech.get("name", ""),
            tactic=tactics,
            description=(tech.get("description") or "")[:3000],
        )
        db.add(row)
        db.flush()
        stix_to_db_id[stix_id] = row.id
        saved += 1

    db.commit()

    # ── Persist mitigations via relationship objects ───────────────────────────
    for rel in relationships:
        source = rel.get("source_ref")   # course-of-action stix id
        target = rel.get("target_ref")   # attack-pattern stix id
        db_tech_id = stix_to_db_id.get(target)
        if not db_tech_id or source not in course_of_actions:
            continue

        mit_obj = course_of_actions[source]
        mit_id = next(
            (r["external_id"] for r in mit_obj.get("external_references", [])
             if r.get("source_name") == "mitre-attack"),
            "M0000",
        )
        exists = db.query(MITREMitigation).filter_by(
            technique_fk=db_tech_id, mitigation_id=mit_id
        ).first()
        if not exists:
            db.add(MITREMitigation(
                technique_fk=db_tech_id,
                mitigation_id=mit_id,
                name=mit_obj.get("name", ""),
                description=(mit_obj.get("description") or "")[:3000],
            ))

    db.commit()
    log.info(f"  [mitre_attack] {saved} new techniques stored, {len(relationships)} relationships processed")
    return saved


def _process_otx(db: Session, items: list) -> int:
    saved = 0
    for pulse in items:
        source_id = f"otx_{pulse.get('id', '')}"
        if db.query(ThreatReport).filter_by(source_id=source_id).first():
            continue
        raw_text = (
            f"OTX Pulse: {pulse.get('name', '')}. "
            f"{pulse.get('description', '')}. "
            f"Tags: {pulse.get('tags', [])}"
        )
        intel = analyze(raw_text) or {}
        report = ThreatReport(
            source_feed="otx",
            source_id=source_id,
            threat_actor=intel.get("threat_actor", "Unknown"),
            target_industry=intel.get("target_industry", "Unknown"),
            ttps=intel.get("ttps", []),
            associated_cves=intel.get("associated_cves", []),
            confidence_score=intel.get("confidence_score", 50),
            summary=intel.get("summary", ""),
            raw_source=raw_text[:2000],
        )
        db.add(report)
        db.flush()
        for ind in (pulse.get("indicators") or [])[:20]:
            db.add(IOC(
                report_id=report.id,
                ioc_type=ind.get("type", "unknown"),
                value=str(ind.get("indicator", ""))[:512],
                tags=[],
            ))
        saved += 1
    db.commit()
    return saved


def _process_darkweb(db: Session, items: list) -> int:
    """
    Persist dark web mention metadata.
    Raw breach content is NEVER stored — only metadata extracted by the feed.
    Uses fingerprint for deduplication; updates last_seen on revisits.
    """
    from models import DarkWebMention
    from datetime import datetime, timezone
    from analyzer import analyze

    saved = 0
    now   = datetime.now(timezone.utc)

    for item in items:
        fp = item.get("fingerprint", "")
        if not fp:
            continue

        existing = db.query(DarkWebMention).filter_by(fingerprint=fp).first()
        if existing:
            existing.last_seen = now
            db.commit()
            continue

        # AI enrichment — brief summary of what this mention represents
        text_for_ai = (
            f"Dark web mention: {item.get('title', '')}. "
            f"Source: {item.get('source_name', '')}. "
            f"Snippet: {item.get('snippet', '')}. "
            f"Keyword matched: {item.get('keyword_matched', '')}."
        )
        intel = analyze(text_for_ai) or {}

        db.add(DarkWebMention(
            source_name     = item.get("source_name", "Unknown")[:200],
            source_url      = item.get("source_url", "")[:500],
            keyword_matched = item.get("keyword_matched", "")[:200],
            title           = item.get("title", "Untitled")[:500],
            snippet         = item.get("snippet", "")[:2000],
            actor_handle    = item.get("actor_handle", "Unknown")[:100],
            record_estimate = item.get("record_estimate", "")[:100] if item.get("record_estimate") else None,
            data_types      = item.get("data_types", []),
            severity        = item.get("severity", "medium")[:20],
            ai_summary      = intel.get("summary", "")[:1000],
            fingerprint     = fp,
            first_seen      = now,
            last_seen       = now,
        ))
        saved += 1

    if saved:
        db.commit()
    return saved


def _process_rss(db: Session, items: list) -> int:
    """Process RSS feed items — deduplicate by URL fingerprint, AI-enrich, store as ThreatReports."""
    saved = 0
    for item in items:
        fp = item.get("fingerprint", "")
        source_url = item.get("url", "")
        if not fp or db.query(ThreatReport).filter_by(source_id=f"rss_{fp[:50]}").first():
            continue
        raw_text = f"{item.get('title', '')}. {item.get('content', '')[:3000]}"
        intel = analyze(raw_text) or {}
        report = ThreatReport(
            source_feed="rss_feeds",
            source_id=f"rss_{fp[:50]}",
            threat_actor=intel.get("threat_actor", "Unknown"),
            target_industry=intel.get("target_industry", "Unknown"),
            ttps=intel.get("ttps", []),
            associated_cves=intel.get("associated_cves", []),
            confidence_score=intel.get("confidence_score", 40),
            summary=intel.get("summary", item.get("title", ""))[:500],
            raw_source=raw_text[:2000],
        )
        db.add(report)
        saved += 1
    db.commit()
    return saved


def _process_cert_transparency(db: Session, items: list) -> int:
    """Persist CT log entries and create watchlist hits for matching domains."""
    from models import CertMention, WatchedAsset, WatchlistHit
    import hashlib
    saved = 0
    for item in items:
        fp = item.get("fingerprint", "")
        if not fp or db.query(CertMention).filter_by(fingerprint=fp).first():
            continue
        asset = db.query(WatchedAsset).filter_by(value=item.get("domain_matched", "")).first()
        cert = CertMention(
            watched_asset_id=asset.id if asset else None,
            domain_matched=item.get("domain_matched", "")[:200],
            common_name=item.get("common_name", "")[:500],
            issuer=item.get("issuer", "")[:200],
            fingerprint=fp,
        )
        db.add(cert)
        db.flush()
        if asset:
            hit_fp = hashlib.sha256(f"cert|{asset.id}|{fp}".encode()).hexdigest()[:64]
            if not db.query(WatchlistHit).filter_by(fingerprint=hit_fp).first():
                db.add(WatchlistHit(
                    watched_asset_id=asset.id,
                    hit_type="cert",
                    severity="medium",
                    source_feed="cert_transparency",
                    matched_value=item.get("common_name", "")[:500],
                    context=f"New certificate issued by {item.get('issuer', 'Unknown')}",
                    fingerprint=hit_fp,
                ))
        saved += 1
    db.commit()
    return saved


def _process_github(db: Session, items: list) -> int:
    """Persist GitHub findings and create high-severity watchlist hits."""
    from models import GithubFinding, WatchedAsset, WatchlistHit
    import hashlib
    saved = 0
    for item in items:
        fp = item.get("fingerprint", "")
        if not fp or db.query(GithubFinding).filter_by(fingerprint=fp).first():
            continue
        db.add(GithubFinding(
            repo_full_name=item.get("repo_full_name", "")[:500],
            file_path=item.get("file_path", "")[:500],
            keyword_matched=item.get("keyword_matched", "")[:200],
            snippet=item.get("snippet", "")[:1000],
            severity=item.get("severity", "high"),
            github_url=item.get("github_url", "")[:500],
            fingerprint=fp,
        ))
        saved += 1
    db.commit()
    return saved


def _process_feodo_tracker(db: Session, items: list) -> int:
    """Feodo Tracker C2 IPs — store ip and ip:port IOCs with full botnet context."""
    import re
    _IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    saved = 0
    for item in items:
        ip      = str(item.get("ip_address", "") or "").strip()
        malware = str(item.get("malware", "Unknown") or "Unknown")
        status  = str(item.get("status", "") or "")
        port    = item.get("port")
        country = str(item.get("country", "") or "")
        if not ip or not _IP_RE.match(ip):
            continue
        source_id = f"feodo_{ip}_{malware}"
        if db.query(ThreatReport).filter_by(source_id=source_id).first():
            continue
        raw = (
            f"Feodo Tracker C2 Server: {ip} port {port}. "
            f"Malware family: {malware}. Status: {status}. "
            f"Country: {country}. "
            f"First seen: {item.get('first_seen_utc', '')}. "
            f"Last online: {item.get('last_online', '')}. "
            f"Registrar/ISP: {item.get('registrar', '')}. "
            f"This IP is a known command-and-control server for the {malware} botnet."
        )
        report = ThreatReport(
            source_feed="feodo_tracker",
            source_id=source_id,
            threat_actor=malware,
            confidence_score=90,
            raw_source=raw[:2000],
            summary=f"{malware} C2 server at {ip}:{port} ({country}). Status: {status}.",
        )
        db.add(report)
        db.flush()
        tags = [malware, "c2", "botnet"]
        db.add(IOC(report_id=report.id, ioc_type="ip",
                   value=ip, malware_family=malware, tags=tags))
        if port:
            db.add(IOC(report_id=report.id, ioc_type="ip:port",
                       value=f"{ip}:{port}", malware_family=malware, tags=tags))
        saved += 1
    db.commit()
    return saved


def _process_sslbl(db: Session, items: list) -> int:
    """SSL Blacklist — malicious SSL certificate SHA1 fingerprints."""
    saved = 0
    for item in items:
        sha1 = str(item.get("sha1_fingerprint", "") or "").strip()
        if not sha1:
            continue
        source_id = f"sslbl_{sha1}"
        if db.query(ThreatReport).filter_by(source_id=source_id).first():
            continue
        tags_list = item.get("tags") or []
        reason    = str(item.get("reason", "") or "")
        cn        = str(item.get("subject_cn", "") or "")
        issuer    = str(item.get("issuer_cn", "") or "")
        malware   = (tags_list[0] if tags_list else reason) or "SSL Blacklist"
        raw = (
            f"SSL Blacklist: Malicious SSL certificate detected. "
            f"SHA1: {sha1}. Subject CN: {cn}. Issuer: {issuer}. "
            f"Reason: {reason}. Tags: {', '.join(str(t) for t in tags_list)}. "
            f"Listed: {item.get('listing_date', '')}. "
            f"Valid until: {item.get('not_after', '')}."
        )
        report = ThreatReport(
            source_feed="sslbl",
            source_id=source_id,
            threat_actor=malware,
            confidence_score=85,
            raw_source=raw[:2000],
            summary=f"Malicious SSL cert ({reason}) for {cn} issued by {issuer}.",
        )
        db.add(report)
        db.flush()
        db.add(IOC(report_id=report.id, ioc_type="hash_sha1",
                   value=sha1, malware_family=malware, tags=tags_list))
        saved += 1
    db.commit()
    return saved


def _process_openphish(db: Session, items: list) -> int:
    """OpenPhish — community phishing URL feed."""
    import re
    from urllib.parse import urlparse
    _IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    saved = 0
    for item in items:
        url_val   = str(item.get("url", "") or "").strip()
        source_id = f"openphish_{item.get('id', '')}"
        if not url_val or db.query(ThreatReport).filter_by(source_id=source_id).first():
            continue
        try:
            host = urlparse(url_val).hostname or ""
        except Exception:
            host = ""
        raw = (
            f"OpenPhish phishing URL: {url_val}. "
            f"Host: {host}. "
            f"This URL has been confirmed as an active phishing site by the OpenPhish community feed."
        )
        report = ThreatReport(
            source_feed="openphish",
            source_id=source_id,
            threat_actor="Unknown",
            confidence_score=75,
            raw_source=raw[:2000],
            summary=f"Confirmed phishing URL targeting {host}.",
        )
        db.add(report)
        db.flush()
        db.add(IOC(report_id=report.id, ioc_type="url",
                   value=url_val[:512], malware_family="Phishing", tags=["phishing"]))
        if host:
            host_type = "ip" if _IP_RE.match(host) else "domain"
            db.add(IOC(report_id=report.id, ioc_type=host_type,
                       value=host[:512], malware_family="Phishing", tags=["phishing"]))
        saved += 1
    db.commit()
    return saved


def _process_dshield(db: Session, items: list) -> int:
    """DShield/SANS ISC — top attacking source IPs."""
    import re
    _IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    saved = 0
    for item in items:
        ip = str(item.get("ipv4") or item.get("ip") or "").strip()
        if not ip or not _IP_RE.match(ip):
            continue
        source_id = f"dshield_{ip}"
        if db.query(ThreatReport).filter_by(source_id=source_id).first():
            continue
        attacks  = item.get("attacks") or item.get("count", 0)
        country  = str(item.get("country", "") or "")
        network  = str(item.get("network", "") or "")
        asn      = str(item.get("as", "") or item.get("asname", ""))
        raw = (
            f"SANS ISC DShield top attacker: {ip}. "
            f"Attack count: {attacks}. Country: {country}. "
            f"Network: {network}. ASN: {asn}. "
            f"This IP appears in the SANS Internet Storm Center top attacking sources list."
        )
        actor = f"DShield/{country}" if country else "DShield"
        report = ThreatReport(
            source_feed="dshield",
            source_id=source_id,
            threat_actor=actor,
            confidence_score=80,
            raw_source=raw[:2000],
            summary=f"Top attacking IP {ip} ({country}), {attacks} attacks recorded by SANS ISC.",
        )
        db.add(report)
        db.flush()
        db.add(IOC(report_id=report.id, ioc_type="ip",
                   value=ip, malware_family="Scanner/Attacker",
                   tags=["scanner", "attacker", "dshield"]))
        saved += 1
    db.commit()
    return saved


def _process_ransomware_live(db: Session, items: list) -> int:
    """Ransomware.live (ransomwatch) — named groups, victim orgs, countries, sectors."""
    saved = 0
    for item in items:
        group       = str(item.get("group_name") or "Unknown Ransomware Group").strip()
        victim      = str(item.get("post_title") or item.get("victim") or "Unknown").strip()
        discovered  = str(item.get("discovered") or "").strip()
        website     = str(item.get("website") or "").strip()
        description = str(item.get("description") or "").strip()
        country     = str(item.get("country") or "").strip()
        activity    = str(item.get("activity") or "").strip()
        meta        = item.get("_group_meta") or {}

        # Unique ID: group + victim (title can repeat across time)
        import hashlib as _hl
        source_id = "rlive_" + _hl.md5((group + victim + discovered[:10]).encode()).hexdigest()[:20]
        if db.query(ThreatReport).filter_by(source_id=source_id).first():
            continue

        # Build group description from metadata if available
        meta_desc = str(meta.get("meta") or meta.get("description") or "").strip()
        raw = (
            "Ransomware.live: {group} ransomware group claimed attack on {victim}. "
            "Victim website: {website}. "
            "Country: {country}. "
            "Industry/sector: {activity}. "
            "Discovered: {discovered}. "
            "Description: {desc}. "
            "Group profile: {meta_desc}"
        ).format(
            group=group, victim=victim, website=website,
            country=country, activity=activity, discovered=discovered,
            desc=description[:400], meta_desc=meta_desc[:300],
        )

        summary = (
            "{group} ransomware attacked {victim}"
            "{country_part}{sector_part}. "
            "Discovered {discovered_short}."
        ).format(
            group=group,
            victim=victim,
            country_part=" ({})".format(country) if country else "",
            sector_part=" in the {} sector".format(activity) if activity else "",
            discovered_short=discovered[:10],
        )

        report = ThreatReport(
            source_feed="ransomware_live",
            source_id=source_id,
            threat_actor=group,
            target_industry=activity or "Unknown",
            ttps=["T1486", "T1490", "T1489"],   # Impact: Data Encrypted, Inhibit Recovery, Service Stop
            confidence_score=85,
            raw_source=raw[:2000],
            summary=summary[:500],
        )
        db.add(report)
        db.flush()

        # IOC: the victim website domain if available
        if website:
            try:
                from urllib.parse import urlparse as _up
                host = _up(website if "://" in website else "https://" + website).hostname or ""
                if host:
                    db.add(IOC(
                        report_id=report.id,
                        ioc_type="domain",
                        value=host[:512],
                        malware_family=group,
                        tags=["ransomware", group.lower(), "victim"],
                    ))
            except Exception:
                pass

        saved += 1
    db.commit()
    return saved


def _process_cybercrime_tracker(db: Session, items: list) -> int:
    """Cybercrime Tracker — active malware C2 panels with named malware families."""
    import re as _re
    from urllib.parse import urlparse as _up
    _IP_RE = _re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    saved = 0
    for item in items:
        url_val  = str(item.get("url") or "").strip()
        malware  = str(item.get("malware") or "Unknown").strip()
        status   = str(item.get("status") or "online").strip().lower()
        date_val = str(item.get("date") or "").strip()
        if not url_val or not url_val.startswith("http"):
            continue

        source_id = "cct_" + str(item.get("id", ""))
        if db.query(ThreatReport).filter_by(source_id=source_id).first():
            continue

        try:
            host = _up(url_val).hostname or ""
        except Exception:
            host = ""

        raw = (
            "Cybercrime Tracker C2 Panel: {url}. "
            "Malware family: {malware}. "
            "Panel status: {status}. "
            "Host: {host}. "
            "First seen: {date}. "
            "This is an active command-and-control panel for {malware} malware, "
            "used by operators to manage infected victims."
        ).format(
            url=url_val, malware=malware, status=status,
            host=host, date=date_val,
        )
        summary = (
            "{malware} C2 panel at {host} ({status}). "
            "Active malware command-and-control infrastructure."
        ).format(malware=malware, host=host or url_val[:40], status=status)

        report = ThreatReport(
            source_feed="cybercrime_tracker",
            source_id=source_id,
            threat_actor=malware,       # malware family IS the actor proxy here
            confidence_score=80,
            raw_source=raw[:2000],
            summary=summary[:500],
        )
        db.add(report)
        db.flush()

        tags = [malware.lower(), "c2", "panel", status]
        db.add(IOC(report_id=report.id, ioc_type="url",
                   value=url_val[:512], malware_family=malware, tags=tags))
        if host:
            host_type = "ip" if _IP_RE.match(host) else "domain"
            db.add(IOC(report_id=report.id, ioc_type=host_type,
                       value=host[:512], malware_family=malware, tags=tags))
        saved += 1
    db.commit()
    return saved


_PROCESSORS = {
    "cisa_kev":           _process_cisa_kev,
    # threatfox/urlhaus removed — replaced by ransomware_live and cybercrime_tracker
    "malwarebazaar":      _process_malwarebazaar,
    "nvd":                _process_nvd,
    "mitre_attack":       _process_mitre_attack,
    "otx":                _process_otx,
    "darkweb":            _process_darkweb,
    "rss_feeds":          _process_rss,
    "cert_transparency":  _process_cert_transparency,
    "github_monitor":     _process_github,
    "feodo_tracker":      _process_feodo_tracker,
    "sslbl":              _process_sslbl,
    "openphish":          _process_openphish,
    "dshield":            _process_dshield,
    "ransomware_live":    _process_ransomware_live,
    "cybercrime_tracker": _process_cybercrime_tracker,
}


# ─── AI TTP enrichment ────────────────────────────────────────────────────────

def _enrich_missing_ttps(db: Session, batch_size: int = 10) -> int:
    """Find threat reports with no TTPs extracted and run the AI analyzer on them.

    The analyzer tries Ollama → Claude → Gemini in order.  We only update
    records where the AI returns a non-empty ttps list so we never blank out
    an already-good record and don't keep retrying truly un-enrichable rows
    indefinitely (they'll eventually get a non-empty summary which acts as a
    signal that the analyzer ran, even if no TTPs were found).
    """
    # Fetch reports that still have an empty ttps array AND no summary yet
    # (summary is written on every successful analyze() call, so it doubles as
    # a "was tried" flag once we've attempted enrichment at least once).
    candidates = (
        db.query(ThreatReport)
        .filter(
            ThreatReport.source_feed != "mitre_attack",  # skip pure ATT&CK objects
            ThreatReport.summary.is_(None),
        )
        .order_by(ThreatReport.id.asc())
        .limit(batch_size)
        .all()
    )

    if not candidates:
        return 0

    enriched = 0
    for report in candidates:
        raw = report.raw_source or ""
        if not raw.strip():
            # Nothing to analyze — stamp an empty summary so we skip it next time
            report.summary = ""
            db.commit()
            continue

        intel = analyze(raw)
        if intel is None:
            # No AI backend available right now; leave for next cycle
            break

        report.ttps = intel.get("ttps") or []
        report.associated_cves = intel.get("associated_cves") or []
        report.summary = intel.get("summary") or ""
        # Only overwrite actor/industry if the report still has defaults
        if report.threat_actor in (None, "Unknown", ""):
            report.threat_actor = intel.get("threat_actor") or "Unknown"
        if report.target_industry in (None, "Unknown", ""):
            report.target_industry = intel.get("target_industry") or "Unknown"
        db.commit()
        enriched += 1

    if enriched:
        log.info(f"[enrichment] AI-enriched {enriched}/{len(candidates)} reports with TTPs/summaries")
    return enriched


# ─── Main loop ────────────────────────────────────────────────────────────────

def _run_feed(feed, db: Session):
    log.info(f"[{feed.name}] Collecting...")
    _upsert_status(db, feed.name, last_run=datetime.now(timezone.utc), status="running")
    try:
        # Inject live DB settings into the dark web feed before every run so
        # changes made in the WebUI admin panel take effect without a restart.
        if feed.name == "darkweb" and hasattr(feed, "configure"):
            from settings import get_all_settings
            feed.configure(get_all_settings(db))

        items = feed.fetch()
        processor = _PROCESSORS.get(feed.name)
        count = processor(db, items) if processor else 0
        log.info(f"[{feed.name}] +{count} new records from {len(items)} fetched.")
        status_rec = db.query(FeedStatus).filter_by(feed_name=feed.name).first()
        if status_rec:
            status_rec.total_records = (status_rec.total_records or 0) + count
            db.commit()
        _upsert_status(
            db, feed.name,
            last_success=datetime.now(timezone.utc),
            records_fetched=count,
            status="ok",
            error_message=None,
        )
    except Exception as exc:
        log.error(f"[{feed.name}] Error: {exc}")
        _upsert_status(db, feed.name, status="error", error_message=str(exc)[:500])


def main():
    log.info("Threat Intel Collector starting — waiting for DB...")
    time.sleep(15)

    now = time.time()
    for feed in ALL_FEEDS:
        _next_run[feed.name] = now

    while True:
        now = time.time()
        db = SessionLocal()
        try:
            for feed in ALL_FEEDS:
                if now >= _next_run.get(feed.name, 0):
                    _run_feed(feed, db)
                    _next_run[feed.name] = time.time() + feed.interval_seconds

            # After feeds, run AI enrichment on un-analyzed reports
            _enrich_missing_ttps(db, batch_size=10)

            # IOC enrichment (VirusTotal, GreyNoise, Shodan)
            try:
                enrich_batch(db, batch_size=10)
            except Exception as e:
                log.debug(f"[enrichment] skipped: {e}")

            # Check new IOCs against watchlist
            try:
                check_all_new_iocs(db)
            except Exception as e:
                log.debug(f"[watchlist] skipped: {e}")

            # Send pending alerts
            try:
                process_pending_alerts(db)
            except Exception as e:
                log.debug(f"[alerter] skipped: {e}")

            # Apply IOC decay (runs internally only once per 24h)
            try:
                apply_decay(db)
            except Exception as e:
                log.debug(f"[decay] skipped: {e}")

            # AI threat research — assess watched assets against current intel
            try:
                run_research_cycle(db)
            except Exception as e:
                log.debug(f"[researcher] skipped: {e}")
        finally:
            db.close()
        time.sleep(30)


if __name__ == "__main__":
    main()
