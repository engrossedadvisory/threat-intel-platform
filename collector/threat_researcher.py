"""
Threat Researcher
─────────────────
Active AI agent that runs on a schedule, assesses each watched asset against
current threat intelligence, and generates daily executive briefings.

Call `run_research_cycle(db)` from the worker main loop.
"""

import json
import logging
import time
from collections import Counter
from datetime import datetime, timezone, timedelta

from sqlalchemy.orm import Session

from models import (
    ThreatReport, IOC, WatchedAsset, DarkWebMention,
    ThreatBriefing, AssetThreatProfile,
)
from analyzer import ai_query

log = logging.getLogger(__name__)

RESEARCH_INTERVAL = 3600       # seconds between cycles
_last_run: float = 0.0
_last_daily_briefing: str = ""  # ISO date string "YYYY-MM-DD"


# ─── Asset matching ────────────────────────────────────────────────────────────

def _find_asset_matches(asset: WatchedAsset,
                        recent_iocs: list,
                        recent_reports: list,
                        dw_mentions: list) -> dict:
    """Find all threat intelligence relevant to a watched asset."""
    matches: dict = {
        "iocs": [], "reports": [], "dark_web": [],
        "actors": set(), "malware_families": set(), "ttps": set(),
    }
    val   = (asset.value or "").lower()
    atype = (asset.asset_type or "").lower()

    if not val:
        return matches

    for ioc in recent_iocs:
        ioc_val = (ioc.value or "").lower()
        hit = False
        if atype in ("domain", "email_domain") and (val in ioc_val or ioc_val.endswith("." + val)):
            hit = True
        elif atype == "ip" and val == ioc_val:
            hit = True
        elif atype == "cidr":
            # simple /24 match
            prefix = ".".join(val.split(".")[:3])
            if ioc_val.startswith(prefix):
                hit = True
        elif atype == "keyword" and val in ioc_val:
            hit = True
        if hit:
            matches["iocs"].append({
                "type": ioc.ioc_type, "value": ioc.value,
                "family": ioc.malware_family or "",
            })
            if ioc.malware_family:
                matches["malware_families"].add(ioc.malware_family)

    for rpt in recent_reports:
        raw     = (rpt.raw_source or "").lower()
        summary = (rpt.summary or "").lower()
        actor   = (rpt.threat_actor or "").lower()
        if val in raw or val in summary or val in actor:
            matches["reports"].append({
                "feed": rpt.source_feed,
                "actor": rpt.threat_actor or "Unknown",
                "summary": (rpt.summary or rpt.raw_source or "")[:150],
                "ttps": rpt.ttps or [],
                "confidence": rpt.confidence_score or 0,
            })
            if rpt.threat_actor and rpt.threat_actor not in ("Unknown", ""):
                matches["actors"].add(rpt.threat_actor)
            if rpt.ttps:
                matches["ttps"].update(rpt.ttps)

    for dm in dw_mentions:
        kw    = (dm.keyword_matched or "").lower()
        title = (dm.title or "").lower()
        snip  = (dm.snippet or "").lower()
        if val in kw or val in title or val in snip:
            matches["dark_web"].append({
                "title": dm.title or "",
                "severity": dm.severity or "medium",
                "source": dm.source_name or "unknown",
                "snippet": (dm.snippet or "")[:200],
            })

    return matches


def _score_risk(matches: dict) -> int:
    """Heuristic 0–100 risk score before AI refinement."""
    score = 0
    score += min(35, len(matches["iocs"]) * 7)
    score += min(20, len(matches["reports"]) * 5)
    score += min(35, len(matches["dark_web"]) * 18)
    score += min(10, len(matches["actors"]) * 5)
    return min(100, score)


def _risk_level(score: int) -> str:
    if score >= 75: return "critical"
    if score >= 50: return "high"
    if score >= 25: return "medium"
    return "low"


# ─── AI assessment ────────────────────────────────────────────────────────────

def _ai_assess_asset(asset: WatchedAsset, matches: dict, score: int) -> dict:
    """Use AI to generate a narrative assessment and recommendations."""
    ioc_lines = "\n".join(
        "  - {}: {} ({})".format(m["type"], m["value"], m.get("family", ""))
        for m in matches["iocs"][:10]
    ) or "  None found"

    rpt_lines = "\n".join(
        "  - [{}] {}: {}".format(m["feed"], m["actor"], m["summary"][:100])
        for m in matches["reports"][:5]
    ) or "  None found"

    dw_lines = "\n".join(
        "  - [{}] {} via {}".format(m["severity"].upper(), m["title"][:80], m["source"])
        for m in matches["dark_web"][:5]
    ) or "  None found"

    actors_str   = ", ".join(matches["actors"]) or "None identified"
    malware_str  = ", ".join(matches["malware_families"]) or "None identified"
    ttps_str     = ", ".join(list(matches["ttps"])[:10]) or "None identified"

    prompt = (
        "You are a senior threat intelligence analyst. "
        "Assess the risk to the monitored asset below and provide actionable intelligence.\n\n"
        "Asset: {} — {}\n".format(asset.asset_type, asset.value) +
        "Label: {}\n".format(asset.label or "Unspecified") +
        "Heuristic Risk Score: {}/100\n\n".format(score) +
        "=== Recent threat intelligence matching this asset ===\n\n"
        "IOC Matches ({} total):\n{}\n\n".format(len(matches["iocs"]), ioc_lines) +
        "Threat Reports ({} total):\n{}\n\n".format(len(matches["reports"]), rpt_lines) +
        "Dark Web Mentions ({} total):\n{}\n\n".format(len(matches["dark_web"]), dw_lines) +
        "Threat actors observed: {}\n".format(actors_str) +
        "Malware families: {}\n".format(malware_str) +
        "MITRE ATT&CK TTPs: {}\n\n".format(ttps_str) +
        "Respond ONLY with a JSON object matching this schema exactly:\n"
        '{"risk_level":"low|medium|high|critical",'
        '"risk_score":0-100,'
        '"summary":"2-3 sentence executive summary",'
        '"key_threats":["specific threat 1","specific threat 2"],'
        '"recommendations":["defensive recommendation 1","recommendation 2","recommendation 3"],'
        '"immediate_actions":["urgent action if high/critical — empty list otherwise"]}'
    )

    result = ai_query(prompt)
    return result or {}


# ─── Daily briefing ────────────────────────────────────────────────────────────

def _generate_daily_briefing(db: Session,
                              reports: list,
                              iocs: list,
                              assets: list) -> None:
    """Generate and store an AI-written daily threat intelligence briefing."""
    today_str = datetime.now(timezone.utc).date().isoformat()

    actor_ctr   = Counter(r.threat_actor  for r in reports
                          if r.threat_actor and r.threat_actor != "Unknown")
    malware_ctr = Counter(i.malware_family for i in iocs if i.malware_family)
    feed_ctr    = Counter(r.source_feed    for r in reports)
    ioc_type_ctr = Counter(i.ioc_type     for i in iocs)

    top_actors  = [a for a, _ in actor_ctr.most_common(5)]
    top_malware = [m for m, _ in malware_ctr.most_common(5)]
    top_feeds   = [f for f, _ in feed_ctr.most_common(5)]

    # How many assets have elevated risk?
    profiles = db.query(AssetThreatProfile).all()
    at_risk  = [p for p in profiles if (p.risk_score or 0) >= 25]

    ioc_summary = ", ".join(
        "{}: {}".format(t, n) for t, n in ioc_type_ctr.most_common(6)
    ) or "none"

    top_actors_json = json.dumps(top_actors)
    briefing_title = "Daily Threat Intelligence Briefing — " + today_str

    prompt = (
        "You are a Chief Intelligence Officer writing a daily threat intelligence briefing "
        "for executive leadership and SOC management.\n\n"
        "=== Intelligence Summary — {} ===\n\n".format(today_str) +
        "Reports collected (last 24h): {}\n".format(len(reports)) +
        "IOCs collected (last 24h): {}\n".format(len(iocs)) +
        "IOC breakdown: {}\n".format(ioc_summary) +
        "Top threat actors: {}\n".format(", ".join(top_actors) or "None identified") +
        "Top malware families: {}\n".format(", ".join(top_malware) or "None identified") +
        "Most active intel sources: {}\n".format(", ".join(top_feeds)) +
        "Monitored assets with active threats: {} of {}\n\n".format(len(at_risk), len(assets)) +
        "Respond ONLY with a JSON object matching this schema exactly:\n"
        '{"title":"Daily Threat Intelligence Briefing — ' + today_str + '",'
        '"executive_summary":"3-4 sentence summary for C-suite — business impact focus",'
        '"key_findings":["specific finding 1","finding 2","finding 3","finding 4","finding 5"],'
        '"recommendations":["prioritized defensive recommendation 1","rec 2","rec 3","rec 4","rec 5"],'
        '"trending_actors":' + top_actors_json + ','
        '"risk_level":"low|medium|high|critical"}'
    )

    result = ai_query(prompt) or {}

    db.add(ThreatBriefing(
        briefing_type="daily",
        title=result.get("title", briefing_title),
        executive_summary=result.get("executive_summary", "Threat intelligence collection active. See key findings below."),
        key_findings=result.get("key_findings", []),
        recommendations=result.get("recommendations", []),
        trending_actors=top_actors,
        risk_level=result.get("risk_level", "medium"),
        ioc_count=len(iocs),
        report_count=len(reports),
        period_hours=24,
    ))
    db.commit()
    log.info("[researcher] Daily briefing stored for %s", today_str)


# ─── Main research cycle ──────────────────────────────────────────────────────

def run_research_cycle(db: Session) -> None:
    """Assess all watched assets and generate daily briefing if not done today.
    Called from the worker main loop every iteration — internally rate-limited."""
    global _last_run, _last_daily_briefing

    now = time.time()
    if now - _last_run < RESEARCH_INTERVAL:
        return
    _last_run = now

    log.info("[researcher] Starting threat research cycle …")
    cutoff = datetime.now(timezone.utc) - timedelta(hours=48)

    # Load recent intel
    recent_reports = (
        db.query(ThreatReport)
        .filter(ThreatReport.created_at >= cutoff)
        .order_by(ThreatReport.created_at.desc())
        .limit(2000)
        .all()
    )
    report_ids = [r.id for r in recent_reports]
    recent_iocs = (
        db.query(IOC).filter(IOC.report_id.in_(report_ids)).all()
        if report_ids else []
    )
    dw_mentions = (
        db.query(DarkWebMention)
        .filter(DarkWebMention.last_seen >= cutoff)
        .all()
    )

    assets = db.query(WatchedAsset).filter_by(active=True).all()
    log.info(
        "[researcher] %d assets · %d reports · %d IOCs · %d DW mentions",
        len(assets), len(recent_reports), len(recent_iocs), len(dw_mentions),
    )

    assessed = 0
    for asset in assets:
        try:
            matches = _find_asset_matches(asset, recent_iocs, recent_reports, dw_mentions)
            score   = _score_risk(matches)
            level   = _risk_level(score)

            if matches["iocs"] or matches["reports"] or matches["dark_web"]:
                ai_result = _ai_assess_asset(asset, matches, score)
                score  = int(ai_result.get("risk_score", score))
                level  = ai_result.get("risk_level", level) or level
                ai_txt = ai_result.get("summary", "")
                recs   = ai_result.get("recommendations", [])
                iact   = ai_result.get("immediate_actions", [])
            else:
                ai_txt = (
                    "No active threats matching {} detected in the last 48 hours. "
                    "Continue standard monitoring posture.".format(asset.value)
                )
                recs  = ["Maintain current monitoring baseline — no active threats detected."]
                iact  = []

            profile = db.query(AssetThreatProfile).filter_by(watched_asset_id=asset.id).first()
            if not profile:
                profile = AssetThreatProfile(watched_asset_id=asset.id)
                db.add(profile)
            profile.risk_score        = max(0, min(100, score))
            profile.risk_level        = level
            profile.matched_iocs      = [m["value"] for m in matches["iocs"][:20]]
            profile.matched_actors    = list(matches["actors"])[:10]
            profile.attack_vectors    = list(matches["ttps"])[:10]
            profile.recommendations   = recs
            profile.immediate_actions = iact
            profile.ai_assessment     = ai_txt
            profile.last_assessed     = datetime.now(timezone.utc)
            db.commit()
            assessed += 1

        except Exception as exc:
            log.error("[researcher] Error assessing asset %s: %s", asset.value, exc)
            try:
                db.rollback()
            except Exception:
                pass

    # Daily briefing — once per calendar day
    today = datetime.now(timezone.utc).date().isoformat()
    if today != _last_daily_briefing:
        try:
            _generate_daily_briefing(db, recent_reports, recent_iocs, assets)
            _last_daily_briefing = today
        except Exception as exc:
            log.error("[researcher] Briefing generation failed: %s", exc)

    log.info("[researcher] Cycle complete — %d/%d assets assessed.", assessed, len(assets))
