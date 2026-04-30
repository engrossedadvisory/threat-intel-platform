"""
VANTELLIGENCE REST + TAXII 2.1 API
===================================
Provides authenticated access to all threat intelligence data collected by
the VANTELLIGENCE collector service.  Uses SQLAlchemy core (text() queries)
so no ORM model redefinition is needed in this service.

Authentication
--------------
Send the API key in the ``X-API-Key`` header.  Keys are stored as SHA-256
hashes in the ``api_keys`` table.  When the table is empty the server runs in
*bootstrap mode* and accepts all requests so the first key can be created via
the WebUI admin panel.

STIX 2.1 / TAXII 2.1
---------------------
Full bundle export at ``GET /api/v1/stix/bundle``.
TAXII discovery + collection serving at ``/taxii/``.
"""

import hashlib
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import stix2
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL as _URL

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

_db_url = _URL.create(
    drivername="postgresql+psycopg2",
    username=os.getenv("POSTGRES_USER", "intel_admin"),
    password=os.getenv("POSTGRES_PASSWORD", "change_me"),
    host=os.getenv("POSTGRES_HOST", "db"),
    port=5432,
    database=os.getenv("POSTGRES_DB", "threat_intel"),
)

engine = create_engine(_db_url, pool_pre_ping=True)

API_VERSION = "1.0.0"
TAXII_CONTENT_TYPE = "application/taxii+json;version=2.1"

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="VANTELLIGENCE API",
    description="Threat Intelligence REST + TAXII 2.1 API for the VANTELLIGENCE platform.",
    version=API_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _api_key_count(conn) -> int:
    row = conn.execute(text("SELECT COUNT(*) FROM api_keys WHERE active = true")).fetchone()
    return row[0] if row else 0


def verify_api_key(x_api_key: Optional[str] = Header(default=None)):
    """
    Dependency injected into every protected endpoint.
    Bootstrap mode (no keys yet) allows unauthenticated access so that the
    admin can create the first key via the UI.
    """
    with engine.connect() as conn:
        try:
            count = _api_key_count(conn)
        except Exception:
            # Table may not exist yet on a fresh deployment — allow through.
            return

        if count == 0:
            # Bootstrap mode: no keys configured yet.
            return

        if not x_api_key:
            raise HTTPException(status_code=401, detail="X-API-Key header required")

        key_hash = _sha256(x_api_key)
        row = conn.execute(
            text("SELECT id FROM api_keys WHERE key_hash = :h AND active = true"),
            {"h": key_hash},
        ).fetchone()

        if not row:
            raise HTTPException(status_code=403, detail="Invalid or inactive API key")

        # Update last_used without a full transaction overhead
        conn.execute(
            text("UPDATE api_keys SET last_used = NOW() WHERE key_hash = :h"),
            {"h": key_hash},
        )
        conn.commit()


AUTH = Depends(verify_api_key)

# ---------------------------------------------------------------------------
# Pydantic request bodies
# ---------------------------------------------------------------------------


class IOCSearchBody(BaseModel):
    value: str


class WatchlistAddBody(BaseModel):
    asset_type: str   # domain, ip, cidr, email_domain, keyword
    value: str
    label: str = ""


# ---------------------------------------------------------------------------
# Helper — row → dict
# ---------------------------------------------------------------------------


def rows_to_list(result) -> list[dict]:
    keys = list(result.keys())
    return [dict(zip(keys, row)) for row in result.fetchall()]


def row_to_dict(row, keys) -> dict:
    return dict(zip(keys, row)) if row else {}


# ---------------------------------------------------------------------------
# Root / stats
# ---------------------------------------------------------------------------


@app.get("/", tags=["info"])
def api_info(_auth=AUTH):
    """Return API metadata and high-level record counts."""
    with engine.connect() as conn:
        tables = [
            "threat_reports", "iocs", "cve_records", "mitre_techniques",
            "dark_web_mentions", "watched_assets", "watchlist_hits",
            "ioc_enrichments", "campaigns", "github_findings", "cert_mentions",
        ]
        counts = {}
        for t in tables:
            try:
                row = conn.execute(text(f"SELECT COUNT(*) FROM {t}")).fetchone()
                counts[t] = row[0]
            except Exception:
                counts[t] = 0

    return {
        "service": "VANTELLIGENCE API",
        "version": API_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "record_counts": counts,
    }


# ---------------------------------------------------------------------------
# IOCs
# ---------------------------------------------------------------------------


@app.get("/api/v1/iocs", tags=["iocs"])
def list_iocs(
    ioc_type: Optional[str] = Query(None, description="Filter by IOC type"),
    value_contains: Optional[str] = Query(None, description="Substring match on value"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _auth=AUTH,
):
    """Paginated list of IOCs with optional type and value filters."""
    conditions = ["1=1"]
    params: dict[str, Any] = {"limit": limit, "offset": offset}

    if ioc_type:
        conditions.append("ioc_type = :ioc_type")
        params["ioc_type"] = ioc_type
    if value_contains:
        conditions.append("value ILIKE :vc")
        params["vc"] = f"%{value_contains}%"

    where = " AND ".join(conditions)
    sql = text(
        f"SELECT i.*, r.source_feed, r.threat_actor FROM iocs i "
        f"LEFT JOIN threat_reports r ON r.id = i.report_id "
        f"WHERE {where} ORDER BY i.id DESC LIMIT :limit OFFSET :offset"
    )
    with engine.connect() as conn:
        result = conn.execute(sql, params)
        return {"data": rows_to_list(result), "limit": limit, "offset": offset}


@app.get("/api/v1/iocs/{ioc_id}", tags=["iocs"])
def get_ioc(ioc_id: int, _auth=AUTH):
    """Single IOC with all enrichment results attached."""
    with engine.connect() as conn:
        ioc_row = conn.execute(
            text("SELECT i.*, r.source_feed, r.threat_actor FROM iocs i "
                 "LEFT JOIN threat_reports r ON r.id = i.report_id WHERE i.id = :id"),
            {"id": ioc_id},
        ).fetchone()
        if not ioc_row:
            raise HTTPException(status_code=404, detail="IOC not found")

        ioc = dict(zip(conn.execute(
            text("SELECT i.*, r.source_feed, r.threat_actor FROM iocs i "
                 "LEFT JOIN threat_reports r ON r.id = i.report_id WHERE i.id = :id"),
            {"id": ioc_id},
        ).keys(), ioc_row))

        enrichments_result = conn.execute(
            text("SELECT * FROM ioc_enrichments WHERE ioc_value = :v ORDER BY enriched_at DESC"),
            {"v": ioc_row[4]},  # value column
        )
        ioc["enrichments"] = rows_to_list(enrichments_result)
    return ioc


@app.post("/api/v1/iocs/search", tags=["iocs"])
def search_iocs(body: IOCSearchBody, _auth=AUTH):
    """Exact-match search for an IOC value, returns matching records with enrichments."""
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT i.*, r.source_feed, r.threat_actor FROM iocs i "
                 "LEFT JOIN threat_reports r ON r.id = i.report_id "
                 "WHERE i.value = :v ORDER BY i.id DESC"),
            {"v": body.value},
        )
        iocs = rows_to_list(result)

        enrichments_result = conn.execute(
            text("SELECT * FROM ioc_enrichments WHERE ioc_value = :v ORDER BY enriched_at DESC"),
            {"v": body.value},
        )
        enrichments = rows_to_list(enrichments_result)

    return {"iocs": iocs, "enrichments": enrichments}


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


@app.get("/api/v1/reports", tags=["reports"])
def list_reports(
    source_feed: Optional[str] = Query(None),
    actor: Optional[str] = Query(None),
    min_confidence: Optional[int] = Query(None, ge=0, le=100),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _auth=AUTH,
):
    """Paginated threat reports with optional filters."""
    conditions = ["1=1"]
    params: dict[str, Any] = {"limit": limit, "offset": offset}

    if source_feed:
        conditions.append("source_feed = :sf")
        params["sf"] = source_feed
    if actor:
        conditions.append("threat_actor ILIKE :actor")
        params["actor"] = f"%{actor}%"
    if min_confidence is not None:
        conditions.append("confidence_score >= :mc")
        params["mc"] = min_confidence

    where = " AND ".join(conditions)
    sql = text(
        f"SELECT * FROM threat_reports WHERE {where} "
        f"ORDER BY created_at DESC LIMIT :limit OFFSET :offset"
    )
    with engine.connect() as conn:
        result = conn.execute(sql, params)
        return {"data": rows_to_list(result), "limit": limit, "offset": offset}


@app.get("/api/v1/reports/{report_id}", tags=["reports"])
def get_report(report_id: int, _auth=AUTH):
    """Single report with its associated IOCs."""
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT * FROM threat_reports WHERE id = :id"), {"id": report_id}
        )
        keys = list(result.keys())
        row = result.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Report not found")
        report = dict(zip(keys, row))

        iocs_result = conn.execute(
            text("SELECT * FROM iocs WHERE report_id = :id ORDER BY id"), {"id": report_id}
        )
        report["iocs"] = rows_to_list(iocs_result)
    return report


# ---------------------------------------------------------------------------
# CVEs
# ---------------------------------------------------------------------------


@app.get("/api/v1/cves", tags=["cves"])
def list_cves(
    is_kev: Optional[bool] = Query(None, description="Filter CISA KEV entries only"),
    min_cvss: Optional[float] = Query(None, ge=0.0, le=10.0),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _auth=AUTH,
):
    """Paginated CVE records."""
    conditions = ["1=1"]
    params: dict[str, Any] = {"limit": limit, "offset": offset}

    if is_kev is not None:
        conditions.append("is_kev = :kev")
        params["kev"] = 1 if is_kev else 0
    if min_cvss is not None:
        conditions.append("cvss_score >= :mc")
        params["mc"] = min_cvss

    where = " AND ".join(conditions)
    sql = text(
        f"SELECT * FROM cve_records WHERE {where} "
        f"ORDER BY cvss_score DESC NULLS LAST LIMIT :limit OFFSET :offset"
    )
    with engine.connect() as conn:
        result = conn.execute(sql, params)
        return {"data": rows_to_list(result), "limit": limit, "offset": offset}


# ---------------------------------------------------------------------------
# Threat actors
# ---------------------------------------------------------------------------


@app.get("/api/v1/actors", tags=["actors"])
def list_actors(_auth=AUTH):
    """Distinct threat actors with report counts, ordered by activity."""
    sql = text(
        "SELECT threat_actor, COUNT(*) AS report_count, "
        "MAX(created_at) AS last_seen "
        "FROM threat_reports WHERE threat_actor IS NOT NULL AND threat_actor != 'Unknown' "
        "GROUP BY threat_actor ORDER BY report_count DESC"
    )
    with engine.connect() as conn:
        result = conn.execute(sql)
        return {"data": rows_to_list(result)}


# ---------------------------------------------------------------------------
# MITRE techniques
# ---------------------------------------------------------------------------


@app.get("/api/v1/techniques", tags=["mitre"])
def list_techniques(
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _auth=AUTH,
):
    """MITRE ATT&CK techniques stored in the database."""
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT * FROM mitre_techniques ORDER BY technique_id "
                 "LIMIT :limit OFFSET :offset"),
            {"limit": limit, "offset": offset},
        )
        return {"data": rows_to_list(result), "limit": limit, "offset": offset}


# ---------------------------------------------------------------------------
# Watchlist
# ---------------------------------------------------------------------------


@app.get("/api/v1/watchlist", tags=["watchlist"])
def list_watchlist(_auth=AUTH):
    """All active watched assets."""
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT * FROM watched_assets ORDER BY created_at DESC")
        )
        return {"data": rows_to_list(result)}


@app.post("/api/v1/watchlist", tags=["watchlist"], status_code=201)
def add_watchlist(body: WatchlistAddBody, _auth=AUTH):
    """Add a new asset to the watchlist."""
    with engine.connect() as conn:
        result = conn.execute(
            text(
                "INSERT INTO watched_assets (asset_type, value, label, active, created_at) "
                "VALUES (:at, :v, :l, true, NOW()) RETURNING id"
            ),
            {"at": body.asset_type, "v": body.value, "l": body.label},
        )
        new_id = result.fetchone()[0]
        conn.commit()
    return {"id": new_id, "asset_type": body.asset_type, "value": body.value, "label": body.label}


@app.delete("/api/v1/watchlist/{asset_id}", tags=["watchlist"])
def remove_watchlist(asset_id: int, _auth=AUTH):
    """Deactivate (soft-delete) a watched asset."""
    with engine.connect() as conn:
        result = conn.execute(
            text("UPDATE watched_assets SET active = false WHERE id = :id"),
            {"id": asset_id},
        )
        conn.commit()
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Asset not found")
    return {"deleted": asset_id}


# ---------------------------------------------------------------------------
# Alerts (watchlist hits)
# ---------------------------------------------------------------------------


@app.get("/api/v1/alerts", tags=["alerts"])
def list_alerts(
    alerted: Optional[bool] = Query(None, description="Filter by alerted status"),
    severity: Optional[str] = Query(None, description="Filter by severity (high/medium/low)"),
    limit: int = Query(100, ge=1, le=1000),
    _auth=AUTH,
):
    """Watchlist hits, newest first."""
    conditions = ["1=1"]
    params: dict[str, Any] = {"limit": limit}

    if alerted is not None:
        conditions.append("h.alerted = :al")
        params["al"] = alerted
    if severity:
        conditions.append("h.severity = :sev")
        params["sev"] = severity

    where = " AND ".join(conditions)
    sql = text(
        f"SELECT h.*, a.asset_type, a.value AS asset_value, a.label "
        f"FROM watchlist_hits h "
        f"LEFT JOIN watched_assets a ON a.id = h.watched_asset_id "
        f"WHERE {where} ORDER BY h.found_at DESC LIMIT :limit"
    )
    with engine.connect() as conn:
        result = conn.execute(sql, params)
        return {"data": rows_to_list(result)}


# ---------------------------------------------------------------------------
# Campaigns
# ---------------------------------------------------------------------------


@app.get("/api/v1/campaigns", tags=["campaigns"])
def list_campaigns(_auth=AUTH):
    """All tracked threat campaigns."""
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT * FROM campaigns ORDER BY last_seen DESC NULLS LAST")
        )
        return {"data": rows_to_list(result)}


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@app.get("/api/v1/stats", tags=["info"])
def stats(_auth=AUTH):
    """Row counts for every major table — used by the dashboard."""
    tables = [
        "threat_reports", "iocs", "cve_records", "mitre_techniques",
        "dark_web_mentions", "watched_assets", "watchlist_hits",
        "ioc_enrichments", "campaigns", "github_findings",
        "cert_mentions", "alert_channels", "api_keys",
    ]
    counts: dict[str, int] = {}
    with engine.connect() as conn:
        for t in tables:
            try:
                row = conn.execute(text(f"SELECT COUNT(*) FROM {t}")).fetchone()
                counts[t] = row[0]
            except Exception:
                counts[t] = 0
    return {"timestamp": datetime.now(timezone.utc).isoformat(), "counts": counts}


# ---------------------------------------------------------------------------
# Dashboard aggregations (React frontend)
# ---------------------------------------------------------------------------

_INFRA_FEEDS = (
    "'spamhaus','dshield','cert_transparency','github_monitor',"
    "'sslbl','openphish','nvd','cisa_kev','apt_groups'"
)


@app.get("/api/v1/dashboard", tags=["dashboard"])
def dashboard(_auth=AUTH):
    """Single endpoint returning all data needed for the Dashboard page."""
    with engine.connect() as conn:

        # Activity over last 30 days: IOC count + report count per day
        activity_rows = conn.execute(text(
            "SELECT DATE(created_at) AS date, COUNT(*) AS iocs "
            "FROM iocs WHERE created_at >= NOW() - INTERVAL '30 days' "
            "GROUP BY DATE(created_at) ORDER BY date"
        )).fetchall()
        report_rows = conn.execute(text(
            "SELECT DATE(created_at) AS date, COUNT(*) AS reports "
            "FROM threat_reports WHERE created_at >= NOW() - INTERVAL '30 days' "
            "GROUP BY DATE(created_at) ORDER BY date"
        )).fetchall()
        ioc_by_day    = {str(r[0]): r[1] for r in activity_rows}
        report_by_day = {str(r[0]): r[1] for r in report_rows}
        all_days = sorted(set(ioc_by_day) | set(report_by_day))
        activity = [{"date": d, "iocs": ioc_by_day.get(d, 0),
                     "reports": report_by_day.get(d, 0)} for d in all_days]

        # Risk distribution by confidence bucket
        risk_rows = conn.execute(text(
            "SELECT "
            "  CASE WHEN confidence_score >= 90 THEN 'Critical' "
            "       WHEN confidence_score >= 75 THEN 'High' "
            "       WHEN confidence_score >= 55 THEN 'Medium' "
            "       WHEN confidence_score >= 30 THEN 'Low' "
            "       ELSE 'Info' END AS name, "
            "  COUNT(*) AS value "
            "FROM threat_reports WHERE confidence_score IS NOT NULL "
            "GROUP BY 1 ORDER BY MIN(confidence_score) DESC"
        )).fetchall()
        risk_dist = [{"name": r[0], "value": r[1]} for r in risk_rows]

        # Top operational actors (exclude infra + profile feeds)
        actor_rows = conn.execute(text(
            f"SELECT threat_actor, COUNT(*) AS report_count, "
            f"AVG(confidence_score) AS avg_conf "
            f"FROM threat_reports "
            f"WHERE threat_actor IS NOT NULL AND threat_actor != 'Unknown' "
            f"  AND source_feed NOT IN ({_INFRA_FEEDS}) "
            f"GROUP BY threat_actor HAVING COUNT(*) >= 2 "
            f"ORDER BY report_count DESC LIMIT 20"
        )).fetchall()
        top_actors = [{"threat_actor": r[0], "report_count": r[1],
                       "avg_conf": float(r[2] or 0)} for r in actor_rows]

        # Top TTPs
        ttp_rows = conn.execute(text(
            "SELECT t.technique_id, t.name, COUNT(*) AS count "
            "FROM mitre_techniques t "
            "JOIN threat_reports r ON r.ttps::text ILIKE '%' || t.technique_id || '%' "
            "WHERE r.ttps IS NOT NULL AND r.ttps != '[]' "
            "GROUP BY t.technique_id, t.name "
            "ORDER BY count DESC LIMIT 15"
        )).fetchall()
        top_ttps = [{"technique_id": r[0], "name": r[1], "count": r[2]}
                    for r in ttp_rows]

        # Recent alerts
        alert_rows = conn.execute(text(
            "SELECT h.severity, h.context, h.found_at, h.hit_type, "
            "       a.value AS asset_value, a.label "
            "FROM watchlist_hits h "
            "LEFT JOIN watched_assets a ON a.id = h.watched_asset_id "
            "ORDER BY h.found_at DESC LIMIT 20"
        )).fetchall()
        recent_alerts = [
            {"severity": r[0], "context": r[1],
             "found_at": r[2].isoformat() if r[2] else None,
             "hit_type": r[3], "asset_value": r[4], "label": r[5]}
            for r in alert_rows
        ]

    return {
        "activity":      activity,
        "risk_dist":     risk_dist,
        "top_actors":    top_actors,
        "top_ttps":      top_ttps,
        "recent_alerts": recent_alerts,
    }


@app.get("/api/v1/feed-status", tags=["dashboard"])
def feed_status(_auth=AUTH):
    """Feed health — last run time, status, error, and total records per feed."""
    with engine.connect() as conn:
        rows = conn.execute(text(
            "SELECT feed_name, status, last_run, last_success, "
            "       records_fetched, total_records, error_message "
            "FROM feed_status ORDER BY feed_name"
        )).fetchall()
        return {"data": [
            {
                "feed_name":       r[0],
                "status":          r[1],
                "last_run":        r[2].isoformat() if r[2] else None,
                "last_success":    r[3].isoformat() if r[3] else None,
                "records_fetched": r[4],
                "total_records":   r[5],
                "error_message":   r[6],
            }
            for r in rows
        ]}


@app.get("/api/v1/actors/operational", tags=["actors"])
def operational_actors(_auth=AUTH):
    """Actors split into active (operational reports) and profiles (apt_groups only)."""
    with engine.connect() as conn:
        # Active: actors with reports from operational feeds
        active_rows = conn.execute(text(
            f"SELECT r.threat_actor, COUNT(*) AS report_count, "
            f"AVG(r.confidence_score) AS avg_conf, "
            f"STRING_AGG(DISTINCT r.source_feed, ',') AS feeds, "
            f"STRING_AGG(DISTINCT r.target_industry, ',') AS target_industry "
            f"FROM threat_reports r "
            f"WHERE r.threat_actor IS NOT NULL AND r.threat_actor != 'Unknown' "
            f"  AND r.source_feed NOT IN ({_INFRA_FEEDS}) "
            f"GROUP BY r.threat_actor ORDER BY report_count DESC"
        )).fetchall()

        # Enrich active actors with profile data (aliases, origin, description)
        profile_map = {}
        profile_rows = conn.execute(text(
            "SELECT threat_actor, raw_source FROM threat_reports "
            "WHERE source_feed = 'apt_groups'"
        )).fetchall()
        import re as _re
        for pr in profile_rows:
            name = str(pr[0] or '').strip()
            raw  = str(pr[1] or '')
            if not name:
                continue
            aka = _re.search(r"Also known as: ([^.]+)\.", raw)
            ori = _re.search(r"Country of origin: ([^.]+)\.", raw)
            des = _re.search(r"Description: (.+?)(?:Reference:|$)", raw, _re.DOTALL)
            profile_map[name.lower()] = {
                "aliases":     aka.group(1).strip() if aka else "",
                "origin":      ori.group(1).strip() if ori else "",
                "description": des.group(1).strip()[:800] if des else "",
            }

        active_norms = set()
        active = []
        for r in active_rows:
            actor = str(r[0])
            norm  = actor.lower()
            active_norms.add(norm)
            prof  = profile_map.get(norm, {})
            feeds_list = [f for f in (r[3] or '').split(',') if f]
            active.append({
                "threat_actor":    actor,
                "report_count":    r[1],
                "avg_conf":        float(r[2] or 0),
                "feeds":           feeds_list,
                "target_industry": r[4] or "",
                "aliases":         prof.get("aliases", ""),
                "origin":          prof.get("origin", ""),
                "description":     prof.get("description", ""),
                "ttps":            [],
                "cves":            [],
            })

        # Profile-only: apt_groups actors not in active set
        profiles = []
        seen = set()
        for pr in profile_rows:
            name = str(pr[0] or '').strip()
            if not name or name == 'Unknown' or name.lower() in active_norms:
                continue
            if name.lower() in seen:
                continue
            seen.add(name.lower())
            raw  = str(pr[1] or '')
            aka = _re.search(r"Also known as: ([^.]+)\.", raw)
            ori = _re.search(r"Country of origin: ([^.]+)\.", raw)
            des = _re.search(r"Description: (.+?)(?:Reference:|$)", raw, _re.DOTALL)
            profiles.append({
                "threat_actor": name,
                "report_count": 0,
                "avg_conf":     70,
                "feeds":        ["apt_groups"],
                "aliases":      aka.group(1).strip() if aka else "",
                "origin":       ori.group(1).strip() if ori else "",
                "description":  des.group(1).strip()[:800] if des else "",
                "ttps":         [],
                "cves":         [],
            })

    return {"active": active, "profiles": profiles}


@app.get("/api/v1/iocs/by-type", tags=["iocs"])
def iocs_by_type(_auth=AUTH):
    """IOC counts grouped by type, for pie chart."""
    with engine.connect() as conn:
        rows = conn.execute(text(
            "SELECT ioc_type, COUNT(*) AS count "
            "FROM iocs GROUP BY ioc_type ORDER BY count DESC"
        )).fetchall()
        return {"data": [{"ioc_type": r[0], "count": r[1]} for r in rows]}


@app.get("/api/v1/iocs/activity", tags=["iocs"])
def ioc_activity(_auth=AUTH):
    """IOC counts per day for the last 30 days."""
    with engine.connect() as conn:
        rows = conn.execute(text(
            "SELECT DATE(created_at) AS date, COUNT(*) AS count "
            "FROM iocs WHERE created_at >= NOW() - INTERVAL '30 days' "
            "GROUP BY DATE(created_at) ORDER BY date"
        )).fetchall()
        return {"data": [{"date": str(r[0]), "count": r[1]} for r in rows]}


@app.get("/api/v1/ttps/usage", tags=["mitre"])
def ttp_usage(_auth=AUTH):
    """MITRE technique IDs observed in threat reports, with occurrence counts."""
    with engine.connect() as conn:
        rows = conn.execute(text(
            "SELECT t.technique_id, t.name, COUNT(*) AS count "
            "FROM mitre_techniques t "
            "JOIN threat_reports r ON r.ttps::text ILIKE '%' || t.technique_id || '%' "
            "WHERE r.ttps IS NOT NULL AND r.ttps != '[]' "
            "GROUP BY t.technique_id, t.name ORDER BY count DESC LIMIT 30"
        )).fetchall()
        return {"data": [{"technique_id": r[0], "name": r[1], "count": r[2]}
                         for r in rows]}


@app.get("/api/v1/darkweb", tags=["darkweb"])
def list_darkweb(
    severity: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    _auth=AUTH,
):
    """Dark web mentions, newest first."""
    conditions = ["1=1"]
    params: dict[str, Any] = {"limit": limit}
    if severity:
        conditions.append("severity = :sev")
        params["sev"] = severity
    where = " AND ".join(conditions)
    with engine.connect() as conn:
        result = conn.execute(
            text(f"SELECT * FROM dark_web_mentions WHERE {where} "
                 f"ORDER BY first_seen DESC LIMIT :limit"),
            params,
        )
        return {"data": rows_to_list(result)}


@app.post("/api/v1/ai/query", tags=["ai"])
def ai_query_endpoint(body: dict, _auth=AUTH):
    """Proxy a free-form prompt to the configured local AI (Ollama)."""
    import os as _os, requests as _req

    prompt   = str(body.get("prompt", "")).strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="prompt required")

    ollama_url = _os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")
    model      = _os.getenv("OLLAMA_PRIMARY_MODEL",
                  _os.getenv("OLLAMA_MODELS", "").split(",")[0].strip()
                  or _os.getenv("OLLAMA_MODEL", "llama3.2"))

    try:
        resp = _req.post(
            f"{ollama_url}/api/generate",
            json={"model": model, "prompt": prompt[:10000], "stream": False},
            timeout=180,
        )
        resp.raise_for_status()
        return {"response": resp.json().get("response", ""), "model": model}
    except Exception as exc:
        raise HTTPException(status_code=503,
            detail=f"AI backend unavailable: {exc}") from exc


@app.post("/api/v1/ai/analyze", tags=["ai"])
def ai_analyze_endpoint(body: dict, _auth=AUTH):
    """Run structured threat analysis via the local AI."""
    import os as _os, requests as _req, json as _json

    text_input = str(body.get("text", "")).strip()
    context    = str(body.get("context", ""))
    if not text_input:
        raise HTTPException(status_code=400, detail="text required")

    ollama_url = _os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")
    model      = _os.getenv("OLLAMA_PRIMARY_MODEL",
                  _os.getenv("OLLAMA_MODELS", "").split(",")[0].strip()
                  or _os.getenv("OLLAMA_MODEL", "llama3.2"))

    prompt = (
        "You are a CTI analyst. Analyze the following threat data and return a "
        "JSON object with: threat_actor, target_industry, ttps (array), "
        "associated_cves (array), confidence_score (0-100), summary (2-3 sentences).\n\n"
        f"Data:\n{text_input[:6000]}"
    )
    if context:
        prompt += f"\n\nAdditional context:\n{context[:2000]}"

    try:
        resp = _req.post(
            f"{ollama_url}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False, "format": "json"},
            timeout=180,
        )
        resp.raise_for_status()
        raw = resp.json().get("response", "{}")
        try:
            result = _json.loads(raw)
        except Exception:
            result = {"summary": raw, "confidence_score": 50}
        return result
    except Exception as exc:
        raise HTTPException(status_code=503,
            detail=f"AI backend unavailable: {exc}") from exc


# ---------------------------------------------------------------------------
# Blocklists (plain-text, suitable for firewall import)
# ---------------------------------------------------------------------------


def _plain_text(lines: list[str]) -> Response:
    return Response(content="\n".join(lines) + "\n", media_type="text/plain")


@app.get("/api/v1/blocklist/ips", tags=["blocklists"])
def blocklist_ips(_auth=AUTH):
    """Plain-text list of malicious IP IOCs, one per line."""
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT DISTINCT value FROM iocs WHERE ioc_type = 'ip' ORDER BY value")
        )
        return _plain_text([row[0] for row in result.fetchall()])


@app.get("/api/v1/blocklist/domains", tags=["blocklists"])
def blocklist_domains(_auth=AUTH):
    """Plain-text list of malicious domain IOCs, one per line."""
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT DISTINCT value FROM iocs WHERE ioc_type = 'domain' ORDER BY value")
        )
        return _plain_text([row[0] for row in result.fetchall()])


@app.get("/api/v1/blocklist/hashes", tags=["blocklists"])
def blocklist_hashes(_auth=AUTH):
    """Plain-text list of malicious file hash IOCs (MD5 + SHA-256), one per line."""
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT DISTINCT value FROM iocs "
                 "WHERE ioc_type IN ('hash_md5','hash_sha256') ORDER BY value")
        )
        return _plain_text([row[0] for row in result.fetchall()])


# ---------------------------------------------------------------------------
# STIX 2.1 builder helpers
# ---------------------------------------------------------------------------

_IOC_PATTERN_MAP = {
    "ip":         "ipv4-addr:value = '{v}'",
    "domain":     "domain-name:value = '{v}'",
    "url":        "url:value = '{v}'",
    "hash_md5":   "file:hashes.'MD5' = '{v}'",
    "hash_sha256": "file:hashes.'SHA-256' = '{v}'",
    "email":      "email-addr:value = '{v}'",
}


def _safe_dt(val) -> Optional[datetime]:
    """Coerce various datetime representations to an aware datetime or None."""
    if val is None:
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(str(val)).replace(tzinfo=timezone.utc)
    except Exception:
        return None


def ioc_to_stix_indicator(ioc: dict) -> Optional[stix2.Indicator]:
    """Convert an IOC dict to a STIX 2.1 Indicator object."""
    ioc_type = ioc.get("ioc_type", "")
    value = ioc.get("value", "")
    pattern_tmpl = _IOC_PATTERN_MAP.get(ioc_type)
    if not pattern_tmpl or not value:
        return None

    # Escape single-quotes in the value before embedding in the STIX pattern.
    safe_value = str(value).replace("'", "\\'")
    pattern = f"[{pattern_tmpl.format(v=safe_value)}]"

    created = _safe_dt(ioc.get("created_at")) or datetime.now(timezone.utc)
    labels = ["malicious-activity"]
    if ioc.get("malware_family"):
        labels.append(ioc["malware_family"].lower().replace(" ", "-"))

    try:
        return stix2.Indicator(
            id=f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, f'ioc:{ioc_type}:{value}')}",
            name=f"{ioc_type}: {value}",
            pattern=pattern,
            pattern_type="stix",
            valid_from=created,
            labels=labels,
            description=f"Source feed: {ioc.get('source_feed', 'unknown')}",
        )
    except Exception:
        return None


def actor_to_stix(actor_name: str) -> stix2.ThreatActor:
    """Create a STIX 2.1 ThreatActor for a named actor string."""
    return stix2.ThreatActor(
        id=f"threat-actor--{uuid.uuid5(uuid.NAMESPACE_URL, f'actor:{actor_name}')}",
        name=actor_name,
        labels=["threat-actor"],
    )


def cve_to_stix(cve: dict) -> stix2.Vulnerability:
    """Convert a CVE record dict to a STIX 2.1 Vulnerability."""
    external_refs = [
        stix2.ExternalReference(
            source_name="cve",
            external_id=cve["cve_id"],
            url=f"https://nvd.nist.gov/vuln/detail/{cve['cve_id']}",
        )
    ]
    cve_key = f"cve:{cve['cve_id']}"
    return stix2.Vulnerability(
        id=f"vulnerability--{uuid.uuid5(uuid.NAMESPACE_URL, cve_key)}",
        name=cve["cve_id"],
        description=cve.get("description") or "",
        external_references=external_refs,
    )


def technique_to_stix(tech: dict) -> stix2.AttackPattern:
    """Convert a MITRE technique dict to a STIX 2.1 AttackPattern."""
    ext_refs = [
        stix2.ExternalReference(
            source_name="mitre-attack",
            external_id=tech["technique_id"],
            url=f"https://attack.mitre.org/techniques/{tech['technique_id'].replace('.', '/')}",
        )
    ]
    tech_key = f"mitre:{tech['technique_id']}"
    return stix2.AttackPattern(
        id=f"attack-pattern--{uuid.uuid5(uuid.NAMESPACE_URL, tech_key)}",
        name=tech.get("name") or tech["technique_id"],
        description=tech.get("description") or "",
        external_references=ext_refs,
    )


def _build_full_bundle(conn) -> stix2.Bundle:
    """Assemble a complete STIX 2.1 bundle from the database."""
    objects: list = []

    # IOC indicators
    iocs = rows_to_list(conn.execute(
        text("SELECT i.*, r.source_feed, r.threat_actor FROM iocs i "
             "LEFT JOIN threat_reports r ON r.id = i.report_id LIMIT 5000")
    ))
    for ioc in iocs:
        obj = ioc_to_stix_indicator(ioc)
        if obj:
            objects.append(obj)

    # Threat actors (de-duplicated by name)
    actors_result = conn.execute(
        text("SELECT DISTINCT threat_actor FROM threat_reports "
             "WHERE threat_actor IS NOT NULL AND threat_actor != 'Unknown'")
    )
    seen_actors: set[str] = set()
    for row in actors_result.fetchall():
        name = row[0]
        if name and name not in seen_actors:
            objects.append(actor_to_stix(name))
            seen_actors.add(name)

    # CVEs
    cves = rows_to_list(conn.execute(text("SELECT * FROM cve_records LIMIT 2000")))
    for cve in cves:
        try:
            objects.append(cve_to_stix(cve))
        except Exception:
            pass

    # MITRE techniques
    techs = rows_to_list(conn.execute(text("SELECT * FROM mitre_techniques LIMIT 2000")))
    for tech in techs:
        try:
            objects.append(technique_to_stix(tech))
        except Exception:
            pass

    return stix2.Bundle(objects=objects, allow_custom=True)


# ---------------------------------------------------------------------------
# STIX bundle export
# ---------------------------------------------------------------------------


@app.get("/api/v1/stix/bundle", tags=["stix"])
def stix_bundle(_auth=AUTH):
    """Export a full STIX 2.1 bundle containing all IOCs, actors, CVEs, and techniques."""
    with engine.connect() as conn:
        bundle = _build_full_bundle(conn)
    return Response(
        content=bundle.serialize(pretty=True),
        media_type="application/stix+json;version=2.1",
    )


# ---------------------------------------------------------------------------
# TAXII 2.1
# ---------------------------------------------------------------------------

_COLLECTIONS = {
    "indicators": {
        "id": "indicators",
        "title": "IOC Indicators",
        "description": "All threat indicators collected by VANTELLIGENCE.",
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"],
    },
    "reports": {
        "id": "reports",
        "title": "Threat Reports",
        "description": "Threat intelligence reports with actor and TTP metadata.",
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"],
    },
    "vulnerabilities": {
        "id": "vulnerabilities",
        "title": "CVE Vulnerabilities",
        "description": "CVE records including CISA KEV entries.",
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"],
    },
    "techniques": {
        "id": "techniques",
        "title": "ATT&CK Techniques",
        "description": "MITRE ATT&CK technique catalogue.",
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"],
    },
}


def _taxii_response(data: dict) -> Response:
    return Response(content=str(data).replace("'", '"'), media_type=TAXII_CONTENT_TYPE)


@app.get("/taxii/", tags=["taxii"])
def taxii_discovery(_auth=AUTH):
    """TAXII 2.1 Discovery endpoint."""
    import json
    payload = {
        "title": "VANTELLIGENCE TAXII Server",
        "description": "TAXII 2.1 access to VANTELLIGENCE threat intelligence data.",
        "contact": "security@vantelligence.local",
        "api_roots": ["/taxii/api/"],
    }
    return Response(content=json.dumps(payload), media_type=TAXII_CONTENT_TYPE)


@app.get("/taxii/api/", tags=["taxii"])
def taxii_api_root(_auth=AUTH):
    """TAXII 2.1 API Root information."""
    import json
    payload = {
        "title": "VANTELLIGENCE Default API Root",
        "versions": ["application/taxii+json;version=2.1"],
        "max_content_length": 10485760,
    }
    return Response(content=json.dumps(payload), media_type=TAXII_CONTENT_TYPE)


@app.get("/taxii/api/collections/", tags=["taxii"])
def taxii_collections(_auth=AUTH):
    """TAXII 2.1 collection listing."""
    import json
    payload = {"collections": list(_COLLECTIONS.values())}
    return Response(content=json.dumps(payload), media_type=TAXII_CONTENT_TYPE)


@app.get("/taxii/api/collections/{collection_id}/", tags=["taxii"])
def taxii_collection_info(collection_id: str, _auth=AUTH):
    """TAXII 2.1 single collection metadata."""
    import json
    coll = _COLLECTIONS.get(collection_id)
    if not coll:
        raise HTTPException(status_code=404, detail="Collection not found")
    return Response(content=json.dumps(coll), media_type=TAXII_CONTENT_TYPE)


@app.get("/taxii/api/collections/{collection_id}/objects/", tags=["taxii"])
def taxii_collection_objects(
    collection_id: str,
    added_after: Optional[str] = Query(None, description="ISO-8601 date filter"),
    _auth=AUTH,
):
    """TAXII 2.1 collection objects — returns a STIX 2.1 bundle."""
    if collection_id not in _COLLECTIONS:
        raise HTTPException(status_code=404, detail="Collection not found")

    # Parse optional date filter
    after_dt: Optional[datetime] = None
    if added_after:
        try:
            after_dt = datetime.fromisoformat(added_after).replace(tzinfo=timezone.utc)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid added_after date format")

    objects: list = []

    with engine.connect() as conn:
        if collection_id == "indicators":
            date_clause = ""
            params: dict[str, Any] = {}
            if after_dt:
                date_clause = "WHERE i.created_at > :after"
                params["after"] = after_dt
            iocs = rows_to_list(conn.execute(
                text(f"SELECT i.*, r.source_feed, r.threat_actor FROM iocs i "
                     f"LEFT JOIN threat_reports r ON r.id = i.report_id "
                     f"{date_clause} LIMIT 5000"),
                params,
            ))
            for ioc in iocs:
                obj = ioc_to_stix_indicator(ioc)
                if obj:
                    objects.append(obj)

        elif collection_id == "reports":
            # Represent threat reports as STIX ThreatActor + Indicator bundles per actor
            date_clause = "WHERE 1=1"
            params = {}
            if after_dt:
                date_clause = "WHERE created_at > :after"
                params["after"] = after_dt
            actors_result = conn.execute(
                text(f"SELECT DISTINCT threat_actor FROM threat_reports {date_clause} "
                     f"AND threat_actor IS NOT NULL AND threat_actor != 'Unknown'"),
                params,
            )
            seen: set[str] = set()
            for row in actors_result.fetchall():
                name = row[0]
                if name and name not in seen:
                    objects.append(actor_to_stix(name))
                    seen.add(name)

        elif collection_id == "vulnerabilities":
            date_clause = ""
            params = {}
            if after_dt:
                date_clause = "WHERE created_at > :after"
                params["after"] = after_dt
            cves = rows_to_list(conn.execute(
                text(f"SELECT * FROM cve_records {date_clause} LIMIT 2000"), params
            ))
            for cve in cves:
                try:
                    objects.append(cve_to_stix(cve))
                except Exception:
                    pass

        elif collection_id == "techniques":
            techs = rows_to_list(conn.execute(text("SELECT * FROM mitre_techniques LIMIT 2000")))
            for tech in techs:
                try:
                    objects.append(technique_to_stix(tech))
                except Exception:
                    pass

    bundle = stix2.Bundle(objects=objects, allow_custom=True)
    return Response(
        content=bundle.serialize(pretty=True),
        media_type="application/stix+json;version=2.1",
    )
