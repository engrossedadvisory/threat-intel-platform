import time
import logging
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from models import SessionLocal, ThreatReport, IOC, CVERecord, FeedStatus
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
    # Reference data only — log technique count, no DB persistence needed
    log.info(f"  [mitre_attack] Reference loaded: {len(items)} active techniques")
    return 0


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


_PROCESSORS = {
    "cisa_kev": _process_cisa_kev,
    "threatfox": _process_threatfox,
    "urlhaus": _process_urlhaus,
    "malwarebazaar": _process_malwarebazaar,
    "nvd": _process_nvd,
    "mitre_attack": _process_mitre_attack,
    "otx": _process_otx,
}


# ─── Main loop ────────────────────────────────────────────────────────────────

def _run_feed(feed, db: Session):
    log.info(f"[{feed.name}] Collecting...")
    _upsert_status(db, feed.name, last_run=datetime.now(timezone.utc), status="running")
    try:
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
        finally:
            db.close()
        time.sleep(30)


if __name__ == "__main__":
    main()
