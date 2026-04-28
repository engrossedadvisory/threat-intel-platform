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


def _process_malwarebazaar(db: Session, items: list) -> int:
    saved = 0
    for item in items:
        sha256 = item.get("sha256_hash", "")
        source_id = f"mb_{sha256}"
        if not sha256 or db.query(ThreatReport).filter_by(source_id=source_id).first():
            continue
        tags = item.get("tags") or []
        # Use malware signature (family name) as the actor proxy — the reporter
        # field is the uploader's username, which is meaningless as a threat actor.
        _mb_family = (
            item.get("signature")
            or (tags[0] if tags else None)
            or "Unknown"
        )
        report = ThreatReport(
            source_feed="malwarebazaar",
            source_id=source_id,
            threat_actor=_mb_family,
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
        report = ThreatReport(
            source_feed="dshield",
            source_id=source_id,
            threat_actor="Unknown",   # DShield records attacking IPs, not named actors
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


def _process_urlhaus(db: Session, items: list) -> int:
    """URLhaus (abuse.ch) — recent malicious URLs with malware tags."""
    from urllib.parse import urlparse as _up
    import re as _re
    _IP_RE = _re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    saved = 0
    for item in items:
        url_val = str(item.get("url", "") or "").strip()
        uid     = str(item.get("id", "") or item.get("urlhaus_reference", "")).strip()
        if not url_val:
            continue
        source_id = f"urlhaus_{uid}" if uid else f"urlhaus_{hash(url_val)}"
        if db.query(ThreatReport).filter_by(source_id=source_id).first():
            continue
        tags_raw  = item.get("tags") or []
        malware   = (tags_raw[0] if tags_raw else None) or str(item.get("threat", "malware"))
        host      = ""
        try:
            host = _up(url_val).hostname or ""
        except Exception:
            pass
        raw = (
            f"URLhaus malicious URL: {url_val}. "
            f"Threat type: {item.get('threat', '')}. "
            f"Tags: {', '.join(str(t) for t in tags_raw)}. "
            f"Date added: {item.get('date_added', '')}. "
            f"URLhaus reference: {item.get('urlhaus_reference', '')}."
        )
        report = ThreatReport(
            source_feed="urlhaus",
            source_id=source_id,
            threat_actor="Unknown",
            confidence_score=80,
            raw_source=raw[:2000],
            summary=f"Malicious URL ({malware}) at {host or url_val[:60]}.",
        )
        db.add(report)
        db.flush()
        db.add(IOC(report_id=report.id, ioc_type="url",
                   value=url_val[:512], malware_family=malware, tags=list(tags_raw)))
        if host:
            host_type = "ip" if _IP_RE.match(host) else "domain"
            db.add(IOC(report_id=report.id, ioc_type=host_type,
                       value=host[:512], malware_family=malware, tags=list(tags_raw)))
        saved += 1
    db.commit()
    return saved


def _process_threatfox(db: Session, items: list) -> int:
    """ThreatFox (abuse.ch) — structured IoCs with malware family attribution."""
    import re as _re
    _IP_RE = _re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    saved = 0
    for item in items:
        ioc_val  = str(item.get("ioc_value", "") or item.get("ioc", "")).strip()
        ioc_type = str(item.get("ioc_type", "") or "").lower().strip()
        malware  = str(item.get("malware", "") or item.get("malware_alias", "Unknown")).strip()
        uid      = str(item.get("id", "") or "").strip()
        if not ioc_val or not uid:
            continue
        source_id = f"threatfox_{uid}"
        if db.query(ThreatReport).filter_by(source_id=source_id).first():
            continue
        # Normalise ioc_type to our schema
        _type_map = {
            "ip:port": "ip:port", "domain": "domain", "url": "url",
            "md5_hash": "hash_md5", "sha256_hash": "hash_sha256",
        }
        std_type = _type_map.get(ioc_type, ioc_type or "unknown")
        tags_raw = item.get("tags") or []
        confidence = min(100, int(item.get("confidence_level", 50) or 50))
        raw = (
            f"ThreatFox IoC: {ioc_val}. "
            f"Type: {ioc_type}. Malware: {malware}. "
            f"Confidence: {confidence}%. "
            f"First seen: {item.get('first_seen', '')}. "
            f"Reporter: {item.get('reporter', '')}. "
            f"Reference: {item.get('reference', '')}."
        )
        report = ThreatReport(
            source_feed="threatfox",
            source_id=source_id,
            threat_actor=malware,
            confidence_score=confidence,
            raw_source=raw[:2000],
            summary=f"ThreatFox {ioc_type} IoC for {malware}: {ioc_val[:80]}.",
        )
        db.add(report)
        db.flush()
        db.add(IOC(report_id=report.id, ioc_type=std_type,
                   value=ioc_val[:512], malware_family=malware, tags=list(tags_raw)))
        saved += 1
    db.commit()
    return saved


def _process_spamhaus(db: Session, items: list) -> int:
    """Spamhaus DROP/EDROP — IP CIDR blocks linked to spam/malware infrastructure."""
    saved = 0
    for item in items:
        cidr      = str(item.get("cidr", "") or "").strip()
        sbl_ref   = str(item.get("sbl_ref", "") or "").strip()
        if not cidr:
            continue
        source_id = f"spamhaus_{cidr}"
        if db.query(ThreatReport).filter_by(source_id=source_id).first():
            continue
        raw = (
            f"Spamhaus DROP blocked network: {cidr}. "
            f"SBL reference: {sbl_ref}. "
            f"Source: {item.get('source_url', '')}. "
            f"This IP block is listed on the Spamhaus Don't Route Or Peer list "
            f"as a source of spam, malware, or botnet activity."
        )
        report = ThreatReport(
            source_feed="spamhaus",
            source_id=source_id,
            threat_actor="Unknown",   # infrastructure data — not a named threat actor
            confidence_score=85,
            raw_source=raw[:2000],
            summary=f"Spamhaus blocked IP range {cidr} ({sbl_ref}).",
        )
        db.add(report)
        db.flush()
        db.add(IOC(report_id=report.id, ioc_type="cidr",
                   value=cidr[:512], malware_family="Spamhaus",
                   tags=["spam", "malware", "drop", sbl_ref]))
        saved += 1
    db.commit()
    return saved


def _process_apt_groups(db: Session, items: list) -> int:
    """MITRE ATT&CK Groups + ETDA APT database — named threat actor profiles."""
    saved = 0
    for item in items:
        name     = str(item.get("name", "Unknown") or "Unknown").strip()
        group_id = str(item.get("group_id", "") or "").strip()
        aliases  = item.get("aliases") or []
        desc     = str(item.get("description", "") or "").strip()
        origin   = str(item.get("origin", "") or "").strip()
        target   = str(item.get("target_industry", "Multiple") or "Multiple").strip()
        url      = str(item.get("url", "") or "").strip()
        source   = str(item.get("_source", "") or "").strip()

        source_id = f"aptgroup_{source}_{group_id or name[:40]}"
        if db.query(ThreatReport).filter_by(source_id=source_id).first():
            continue

        alias_str = ", ".join(str(a) for a in aliases[:10]) if aliases else ""
        raw = (
            f"Threat Actor Profile: {name}. "
            + (f"Group ID: {group_id}. " if group_id else "")
            + (f"Also known as: {alias_str}. " if alias_str else "")
            + (f"Country of origin: {origin}. " if origin else "")
            + (f"Target industries: {target}. " if target else "")
            + (f"Description: {desc[:600]}. " if desc else "")
            + (f"Reference: {url}" if url else "")
        )
        summary = (
            f"{name}"
            + (f" (aka {alias_str[:80]})" if alias_str else "")
            + (f" — {origin} threat actor" if origin else " — threat actor")
            + (f" targeting {target[:80]}" if target and target != "Multiple" else "")
            + "."
        )
        report = ThreatReport(
            source_feed="apt_groups",
            source_id=source_id,
            threat_actor=name,
            target_industry=target[:255],
            ttps=[],
            confidence_score=70,
            raw_source=raw[:2000],
            summary=summary[:500],
        )
        db.add(report)
        saved += 1
    db.commit()
    return saved


def _cleanup_bad_actor_data(db: Session) -> None:
    """One-time DB cleanup: fix existing records where infrastructure feeds were
    incorrectly stored with named threat_actor values instead of 'Unknown'.

    This covers:
    - Spamhaus records saved as "Spamhaus Listed" (old code)
    - DShield records saved as "DShield/XX" (old code)
    - Any other infra feed rows with a non-Unknown actor name

    Safe to run on every startup — uses targeted WHERE clauses, no full table scans.
    """
    from sqlalchemy import text as _text

    _infra_fixes = [
        # (feed_name, bad_actor_pattern) — wildcards for LIKE
        ("spamhaus",   "Spamhaus%"),
        ("spamhaus",   "SPAMHAUS%"),
        ("dshield",    "DShield%"),
        ("dshield",    "SANS%"),
        ("sslbl",      "SSL%"),
        ("openphish",  "Phishing%"),
        ("openphish",  "OpenPhish%"),
        ("cert_transparency", "CT%"),
        ("github_monitor",    "GitHub%"),
    ]

    # MalwareBazaar: old records used reporter username as threat_actor.
    # These are random usernames (e.g. "abuse_ch", "fr0gger"), not actor names.
    # Reset them to Unknown so re-enrichment or IOC malware_family drives attribution.
    # We detect them by excluding known malware family name patterns —
    # any short lowercase-or-underscore name without spaces is likely a username.
    try:
        result = db.execute(
            _text(
                "UPDATE threat_reports SET threat_actor = 'Unknown' "
                "WHERE source_feed = 'malwarebazaar' "
                "  AND threat_actor != 'Unknown' "
                "  AND threat_actor NOT LIKE '% %' "   # real malware names have spaces sometimes
                "  AND threat_actor REGEXP '^[a-z0-9_@.-]{2,30}$'"   # looks like a username
            )
        )
        fixed = result.rowcount
        if fixed:
            db.commit()
            log.info(f"[cleanup] Reset {fixed} malwarebazaar records with reporter usernames → 'Unknown'")
    except Exception:
        # REGEXP may not be available (SQLite dialect) — use simpler fallback
        db.rollback()
        try:
            result = db.execute(
                _text(
                    "UPDATE threat_reports SET threat_actor = 'Unknown' "
                    "WHERE source_feed = 'malwarebazaar' "
                    "  AND threat_actor != 'Unknown' "
                    "  AND LENGTH(threat_actor) < 20 "
                    "  AND LOWER(threat_actor) = threat_actor "  # all lowercase → username pattern
                )
            )
            fixed = result.rowcount
            if fixed:
                db.commit()
                log.info(f"[cleanup] Reset {fixed} malwarebazaar lowercase-username records → 'Unknown'")
        except Exception as exc2:
            log.debug(f"[cleanup] malwarebazaar fallback cleanup failed: {exc2}")
            db.rollback()

    total_fixed = 0
    for feed_name, pattern in _infra_fixes:
        try:
            result = db.execute(
                _text(
                    "UPDATE threat_reports SET threat_actor = 'Unknown' "
                    "WHERE source_feed = :feed "
                    "  AND threat_actor != 'Unknown' "
                    "  AND threat_actor LIKE :pattern"
                ),
                {"feed": feed_name, "pattern": pattern},
            )
            fixed = result.rowcount
            if fixed:
                db.commit()
                log.info(f"[cleanup] Fixed {fixed} '{feed_name}' records "
                         f"(was matching '{pattern}') → threat_actor='Unknown'")
                total_fixed += fixed
        except Exception as exc:
            log.warning(f"[cleanup] Could not fix '{feed_name}/{pattern}': {exc}")
            db.rollback()

    if total_fixed:
        log.info(f"[cleanup] Total bad actor records corrected: {total_fixed}")
    else:
        log.debug("[cleanup] No bad actor records found — DB is clean.")


def _correlate_actor_aliases(db: Session) -> int:
    """Match APT group aliases against threat reports stored as 'Unknown' actor.

    How it works:
    1. Load all apt_groups profile records and parse their aliases list from raw_source.
    2. Build an alias → canonical_name mapping (normalised for fuzzy matching).
    3. For each ThreatReport with threat_actor='Unknown', search its raw_source for
       any known alias using word-boundary regex.
    4. When a match is found, update threat_actor to the canonical group name.

    This is what fixes "all actors showing 1 report" — once aliases are correlated,
    the operational intel records are attributed to named actors rather than 'Unknown'.
    """
    import re as _re
    from sqlalchemy import text as _sql

    def _norm(name: str) -> str:
        return _re.sub(r'[\s\-_.]+', '', name).lower()

    # ── Step 1: Load all apt_groups profiles ──────────────────────────────────
    profiles = db.execute(
        _sql(
            "SELECT threat_actor, raw_source, source_id "
            "FROM threat_reports WHERE source_feed = 'apt_groups' "
            "  AND threat_actor IS NOT NULL AND threat_actor != 'Unknown'"
        )
    ).fetchall()

    if not profiles:
        log.debug("[correlate] No apt_groups profiles found — skipping alias correlation.")
        return 0

    # ── Step 2: Build alias → canonical map ───────────────────────────────────
    # Format in raw_source: "Also known as: alias1, alias2, alias3."
    _alias_re = _re.compile(r"Also known as:\s*([^.]+)\.", _re.IGNORECASE)

    # canonical_name → [all known name variants including aliases]
    actor_variants: dict[str, list[str]] = {}

    for row in profiles:
        canonical = str(row[0]).strip()
        raw = str(row[1] or "")

        variants = [canonical]

        # Extract aliases from "Also known as: ..." in raw_source
        m = _alias_re.search(raw)
        if m:
            for alias in m.group(1).split(","):
                alias = alias.strip().strip(".")
                if alias and len(alias) >= 3:
                    variants.append(alias)

        actor_variants[canonical] = variants

    # Build reverse map: normalised variant → canonical name
    # (longer canonical wins on collision to prefer full names over abbreviations)
    alias_to_canonical: dict[str, str] = {}
    for canonical, variants in actor_variants.items():
        for v in variants:
            nk = _norm(v)
            existing = alias_to_canonical.get(nk)
            if not existing or len(canonical) > len(existing):
                alias_to_canonical[nk] = canonical

    # ── Step 3: Build regex patterns for efficient searching ──────────────────
    # Group by canonical so we only need one pass per report
    # Each pattern: word-boundary anchored, case-insensitive
    # We sort by length descending so longer/more-specific names match first
    canonical_patterns: list[tuple[str, _re.Pattern]] = []
    for canonical, variants in actor_variants.items():
        # Build a single alternation regex for all variants of this actor
        escaped = sorted(
            [_re.escape(v) for v in variants if len(v) >= 3],
            key=len, reverse=True,
        )
        if not escaped:
            continue
        pattern_str = r"\b(?:" + "|".join(escaped) + r")\b"
        try:
            pat = _re.compile(pattern_str, _re.IGNORECASE)
            canonical_patterns.append((canonical, pat))
        except _re.error:
            continue

    if not canonical_patterns:
        log.debug("[correlate] No usable patterns built — skipping.")
        return 0

    log.info(f"[correlate] Built patterns for {len(canonical_patterns)} known actors.")

    # ── Step 4: Match against 'Unknown' actor reports in batches ──────────────
    updated = 0
    batch_size = 200  # process this many Unknown reports per cycle

    unknown_reports = db.execute(
        _sql(
            "SELECT id, raw_source FROM threat_reports "
            "WHERE (threat_actor = 'Unknown' OR threat_actor IS NULL) "
            "  AND source_feed NOT IN ('apt_groups', 'spamhaus', 'dshield', "
            "      'cert_transparency', 'github_monitor', 'sslbl', 'openphish', "
            "      'nvd', 'cisa_kev') "
            "  AND raw_source IS NOT NULL AND raw_source != '' "
            "ORDER BY id DESC LIMIT :limit"
        ),
        {"limit": batch_size},
    ).fetchall()

    for row in unknown_reports:
        report_id = row[0]
        raw_text  = str(row[1] or "")
        if not raw_text.strip():
            continue

        matched_canonical = None
        for canonical, pat in canonical_patterns:
            if pat.search(raw_text):
                matched_canonical = canonical
                break  # first/longest match wins

        if matched_canonical:
            try:
                db.execute(
                    _sql(
                        "UPDATE threat_reports SET threat_actor = :actor "
                        "WHERE id = :id"
                    ),
                    {"actor": matched_canonical, "id": report_id},
                )
                updated += 1
            except Exception as exc:
                log.debug(f"[correlate] Could not update report {report_id}: {exc}")

    if updated:
        db.commit()
        log.info(f"[correlate] Attributed {updated} 'Unknown' reports to named actors.")
    else:
        log.debug("[correlate] No new alias matches found in this batch.")

    return updated


_PROCESSORS = {
    "cisa_kev":           _process_cisa_kev,
    "urlhaus":            _process_urlhaus,
    "threatfox":          _process_threatfox,
    "spamhaus":           _process_spamhaus,
    "apt_groups":         _process_apt_groups,
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
    """Find threat reports with no TTPs extracted and run the multi-tier AI analyzer.

    The analyzer runs Tier-1 (primary model) then Tier-2 (secondary correlation)
    before falling back to cloud options.  We pass any matching APT group profile
    text as 'context' to the correlation pass to improve attribution quality.

    We only update records where the AI returns a non-empty ttps list or summary
    so we never blank out already-good records.  Reports with an empty summary
    after analysis won't be retried (summary acts as a "was tried" sentinel).
    """
    from sqlalchemy import text as _sql

    candidates = (
        db.query(ThreatReport)
        .filter(
            ThreatReport.source_feed != "mitre_attack",   # skip pure ATT&CK objects
            ThreatReport.source_feed != "apt_groups",     # skip actor profiles
            ThreatReport.summary.is_(None),
        )
        .order_by(ThreatReport.id.asc())
        .limit(batch_size)
        .all()
    )

    if not candidates:
        return 0

    # Build a quick actor→profile lookup for context enrichment
    # (only load once per batch call to avoid N+1 queries)
    _profile_cache: dict[str, str] = {}

    def _get_actor_context(actor_name: str) -> str:
        """Fetch the apt_groups raw_source for this actor name (normalised match)."""
        if not actor_name or actor_name == "Unknown":
            return ""
        if actor_name in _profile_cache:
            return _profile_cache[actor_name]
        row = db.execute(
            _sql(
                "SELECT raw_source FROM threat_reports "
                "WHERE source_feed = 'apt_groups' "
                "  AND LOWER(threat_actor) = LOWER(:actor) "
                "LIMIT 1"
            ),
            {"actor": actor_name},
        ).fetchone()
        ctx = str(row[0]) if row and row[0] else ""
        _profile_cache[actor_name] = ctx
        return ctx

    enriched = 0
    for report in candidates:
        raw = report.raw_source or ""
        if not raw.strip():
            report.summary = ""
            db.commit()
            continue

        # Build correlation context: actor profile + existing IOC/feed context
        context_parts = []
        actor_ctx = _get_actor_context(report.threat_actor or "")
        if actor_ctx:
            context_parts.append(f"Actor profile: {actor_ctx[:1500]}")
        if report.source_feed:
            context_parts.append(f"Source feed: {report.source_feed}")
        if report.target_industry and report.target_industry != "Unknown":
            context_parts.append(f"Known target industry: {report.target_industry}")
        context = "\n".join(context_parts)

        intel = analyze(raw, context=context)
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

        # Store attribution reasoning in a richer summary when available
        attribution = intel.get("attribution_reasoning", "")
        if attribution and attribution.lower() not in ("unknown", ""):
            existing_summary = report.summary or ""
            if attribution not in existing_summary:
                report.summary = (existing_summary + " " + attribution).strip()[:500]

        db.commit()
        enriched += 1

    if enriched:
        log.info(f"[enrichment] AI-enriched {enriched}/{len(candidates)} reports "
                 f"(multi-tier: primary + secondary correlation)")
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


def _purge_deprecated_feeds(db: Session) -> None:
    """Hard-delete all data from feeds that have been permanently removed.
    Runs once at startup so stale records never appear in the UI again.
    IOCs are deleted via ON DELETE CASCADE on the foreign key.
    NOTE: urlhaus and threatfox are ACTIVE feeds — do not add them here."""
    _deprecated: tuple = ()  # no currently deprecated feeds
    for feed_name in _deprecated:
        try:
            count = db.query(ThreatReport).filter_by(source_feed=feed_name).count()
            if count:
                db.query(ThreatReport).filter_by(source_feed=feed_name).delete(
                    synchronize_session=False
                )
                db.commit()
                log.info(f"[startup] Purged {count} deprecated '{feed_name}' records.")
            db.query(FeedStatus).filter_by(feed_name=feed_name).delete(
                synchronize_session=False
            )
            db.commit()
        except Exception as exc:
            log.warning(f"[startup] Could not purge '{feed_name}': {exc}")
            db.rollback()


def main():
    log.info("Threat Intel Collector starting — waiting for DB...")
    time.sleep(15)

    # One-time startup tasks
    _init_db = SessionLocal()
    try:
        _purge_deprecated_feeds(_init_db)
        # Fix bad actor data from old code (Spamhaus Listed, DShield/XX, etc.)
        _cleanup_bad_actor_data(_init_db)
    finally:
        _init_db.close()

    now = time.time()
    for feed in ALL_FEEDS:
        _next_run[feed.name] = now

    # Enrichment runs every 5 min to stay within the VT 500 calls/day free tier.
    _ENRICH_INTERVAL   = 300    # seconds between IOC enrichment batches
    _CORRELATE_INTERVAL = 600   # seconds between actor alias correlation passes
    _next_enrich    = 0.0       # run immediately on first loop
    _next_correlate = 60.0      # first correlation pass after 1 minute

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

            # IOC enrichment (VirusTotal, GreyNoise, Shodan) — rate-throttled
            if now >= _next_enrich:
                try:
                    enrich_batch(db, batch_size=10)
                    _next_enrich = time.time() + _ENRICH_INTERVAL
                except Exception as e:
                    log.debug(f"[enrichment] skipped: {e}")
                    _next_enrich = time.time() + _ENRICH_INTERVAL

            # Actor alias correlation — attribute 'Unknown' reports to named actors
            if now >= _next_correlate:
                try:
                    correlated = _correlate_actor_aliases(db)
                    if correlated:
                        log.info(f"[correlate] {correlated} reports attributed this cycle.")
                    _next_correlate = time.time() + _CORRELATE_INTERVAL
                except Exception as e:
                    log.debug(f"[correlate] skipped: {e}")
                    _next_correlate = time.time() + _CORRELATE_INTERVAL

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
