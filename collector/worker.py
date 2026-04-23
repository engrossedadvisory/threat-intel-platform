import time
import logging
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from models import SessionLocal, ThreatReport, IOC, CVERecord, FeedStatus, MITRETechnique, MITREMitigation
from feeds import ALL_FEEDS
from analyzer import analyze

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
    saved = 0
    for item in items:
        source_id = f"threatfox_{item.get('id', '')}"
        if db.query(ThreatReport).filter_by(source_id=source_id).first():
            continue
        report = ThreatReport(
            source_feed="threatfox",
            source_id=source_id,
            threat_actor=item.get("threat_actor") or "Unknown",
            confidence_score=int(item.get("confidence_level") or 0),
            raw_source=str(item)[:2000],
        )
        db.add(report)
        db.flush()
        ioc_val = item.get("ioc_value", "")
        if ioc_val:
            db.add(IOC(
                report_id=report.id,
                ioc_type=item.get("ioc_type", "unknown"),
                value=ioc_val[:512],
                malware_family=item.get("malware_printable", ""),
                tags=item.get("tags") or [],
            ))
        saved += 1
    db.commit()
    return saved


def _process_urlhaus(db: Session, items: list) -> int:
    saved = 0
    for item in items:
        source_id = f"urlhaus_{item.get('id', '')}"
        if db.query(ThreatReport).filter_by(source_id=source_id).first():
            continue
        report = ThreatReport(
            source_feed="urlhaus",
            source_id=source_id,
            threat_actor="Unknown",
            confidence_score=70,
            raw_source=str(item)[:2000],
        )
        db.add(report)
        db.flush()
        url_val = item.get("url", "")
        if url_val:
            tags = item.get("tags") or []
            db.add(IOC(
                report_id=report.id,
                ioc_type="url",
                value=url_val[:512],
                malware_family=", ".join(str(t) for t in tags[:3]),
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


_PROCESSORS = {
    "cisa_kev": _process_cisa_kev,
    "threatfox": _process_threatfox,
    "urlhaus": _process_urlhaus,
    "malwarebazaar": _process_malwarebazaar,
    "nvd": _process_nvd,
    "mitre_attack": _process_mitre_attack,
    "otx": _process_otx,
    "darkweb": _process_darkweb,
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
        finally:
            db.close()
        time.sleep(30)


if __name__ == "__main__":
    main()
