"""
Alerter — sends notifications for watchlist hits via Slack, Teams, and Email.
Channels configured in the alert_channels DB table (set in Admin tab).
"""

import json
import logging
import smtplib
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Optional

import requests
from sqlalchemy.orm import Session

from models import AlertChannel

log = logging.getLogger(__name__)

REQUEST_TIMEOUT = 10  # seconds


# ─── Colour helpers ───────────────────────────────────────────────────────────

_SEVERITY_COLOUR = {
    "critical": "#FF0000",
    "high":     "#FF6600",
    "medium":   "#FFCC00",
    "low":      "#36A64F",
}

_SEVERITY_TEAMS_COLOUR = {
    "critical": "attention",
    "high":     "warning",
    "medium":   "accent",
    "low":      "good",
}


# ─── Slack ────────────────────────────────────────────────────────────────────

def _send_slack(webhook_url: str, hit_row: Any, asset_row: Any) -> bool:
    """
    Post a Block Kit message to a Slack incoming webhook.
    Returns True on success, False on failure.
    """
    severity = getattr(hit_row, "severity", "medium").lower()
    color    = _SEVERITY_COLOUR.get(severity, "#FFCC00")
    ts_str   = (
        hit_row.found_at.strftime("%Y-%m-%d %H:%M UTC")
        if hasattr(hit_row, "found_at") and hit_row.found_at
        else datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    )

    payload = {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "🚨 VANTELLIGENCE Alert: Watchlist Hit",
                            "emoji": True,
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Asset:*\n{getattr(asset_row, 'value', 'Unknown')}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Matched Value:*\n`{getattr(hit_row, 'matched_value', 'Unknown')}`",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Source Feed:*\n{getattr(hit_row, 'source_feed', 'Unknown')}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Severity:*\n{severity.upper()}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Hit Type:*\n{getattr(hit_row, 'hit_type', 'ioc_match')}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Timestamp:*\n{ts_str}",
                            },
                        ],
                    },
                ],
                "fallback": (
                    f"VANTELLIGENCE Watchlist Hit — "
                    f"Asset: {getattr(asset_row, 'value', '?')} | "
                    f"IOC: {getattr(hit_row, 'matched_value', '?')} | "
                    f"Severity: {severity.upper()}"
                ),
            }
        ]
    }

    try:
        resp = requests.post(webhook_url, json=payload, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        log.info(f"[alerter/slack] Alert sent for hit id={getattr(hit_row, 'id', '?')}")
        return True
    except requests.RequestException as exc:
        log.error(f"[alerter/slack] Failed to send alert: {exc}")
        return False


# ─── Microsoft Teams ──────────────────────────────────────────────────────────

def _send_teams(webhook_url: str, hit_row: Any, asset_row: Any) -> bool:
    """
    Post an Adaptive Card to a Teams incoming webhook.
    Returns True on success, False on failure.
    """
    severity = getattr(hit_row, "severity", "medium").lower()
    color    = _SEVERITY_TEAMS_COLOUR.get(severity, "accent")
    ts_str   = (
        hit_row.found_at.strftime("%Y-%m-%d %H:%M UTC")
        if hasattr(hit_row, "found_at") and hit_row.found_at
        else datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    )

    def _fact(title: str, value: str) -> dict:
        return {"title": title, "value": value}

    payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": "🚨 VANTELLIGENCE Alert: Watchlist Hit",
                            "weight": "Bolder",
                            "size": "Large",
                            "color": color,
                            "wrap": True,
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                _fact("Asset",         getattr(asset_row, "value", "Unknown")),
                                _fact("Matched Value", getattr(hit_row, "matched_value", "Unknown")),
                                _fact("Source Feed",   getattr(hit_row, "source_feed", "Unknown")),
                                _fact("Severity",      severity.upper()),
                                _fact("Hit Type",      getattr(hit_row, "hit_type", "ioc_match")),
                                _fact("Timestamp",     ts_str),
                            ],
                        },
                    ],
                },
            }
        ],
    }

    try:
        resp = requests.post(webhook_url, json=payload, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        log.info(f"[alerter/teams] Alert sent for hit id={getattr(hit_row, 'id', '?')}")
        return True
    except requests.RequestException as exc:
        log.error(f"[alerter/teams] Failed to send alert: {exc}")
        return False


# ─── Email ────────────────────────────────────────────────────────────────────

def _send_email(config: dict, hit_row: Any, asset_row: Any) -> bool:
    """
    Send an HTML alert email via SMTP.
    Config keys: smtp_host, smtp_port, smtp_user, smtp_pass, from_addr, to_addr
    Returns True on success, False on failure.
    """
    severity = getattr(hit_row, "severity", "medium").lower()
    colour   = _SEVERITY_COLOUR.get(severity, "#FFCC00")
    ts_str   = (
        hit_row.found_at.strftime("%Y-%m-%d %H:%M UTC")
        if hasattr(hit_row, "found_at") and hit_row.found_at
        else datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    )

    rows = [
        ("Asset",         getattr(asset_row, "value", "Unknown")),
        ("Matched Value", getattr(hit_row, "matched_value", "Unknown")),
        ("Source Feed",   getattr(hit_row, "source_feed", "Unknown")),
        ("Severity",      severity.upper()),
        ("Hit Type",      getattr(hit_row, "hit_type", "ioc_match")),
        ("Timestamp",     ts_str),
    ]

    table_rows = "".join(
        f"<tr><td style='padding:6px 12px;font-weight:bold;background:#f4f4f4;border:1px solid #ddd'>{k}</td>"
        f"<td style='padding:6px 12px;border:1px solid #ddd'>{v}</td></tr>"
        for k, v in rows
    )

    html = f"""
    <html><body style='font-family:Arial,sans-serif;color:#222'>
      <h2 style='color:{colour}'>&#128680; VANTELLIGENCE Alert: Watchlist Hit</h2>
      <table style='border-collapse:collapse;min-width:400px'>
        {table_rows}
      </table>
      <p style='font-size:12px;color:#888;margin-top:20px'>
        This alert was generated automatically by the VANTELLIGENCE Threat Intelligence Platform.
      </p>
    </body></html>
    """

    subject = (
        f"[VANTELLIGENCE] {severity.upper()} Watchlist Hit — "
        f"{getattr(asset_row, 'value', 'Unknown')}"
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = config.get("from_addr", "vantelligence@localhost")
    msg["To"]      = config.get("to_addr", "")
    msg.attach(MIMEText(html, "html"))

    try:
        smtp_host = config.get("smtp_host", "localhost")
        smtp_port = int(config.get("smtp_port", 587))
        smtp_user = config.get("smtp_user", "")
        smtp_pass = config.get("smtp_pass", "")
        to_addr   = config.get("to_addr", "")

        if not to_addr:
            log.warning("[alerter/email] No to_addr configured — skipping email.")
            return False

        with smtplib.SMTP(smtp_host, smtp_port, timeout=REQUEST_TIMEOUT) as server:
            server.ehlo()
            if smtp_port != 25:
                server.starttls()
                server.ehlo()
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.sendmail(msg["From"], [to_addr], msg.as_string())

        log.info(f"[alerter/email] Alert sent to {to_addr} for hit id={getattr(hit_row, 'id', '?')}")
        return True

    except Exception as exc:
        log.error(f"[alerter/email] Failed to send alert: {exc}")
        return False


# ─── Main send_alert ──────────────────────────────────────────────────────────

def send_alert(hit_row: Any, asset_row: Any, db: Session) -> int:
    """
    Send an alert for a watchlist hit via all active configured channels.
    Returns the number of channels that successfully delivered.
    """
    channels = db.query(AlertChannel).filter_by(active=True).all()
    if not channels:
        log.debug("[alerter] No active alert channels configured.")
        return 0

    delivered = 0
    for channel in channels:
        cfg = channel.config or {}

        success = False
        ctype = (channel.channel_type or "").lower()

        if ctype == "slack":
            webhook = cfg.get("webhook_url", "")
            if webhook:
                success = _send_slack(webhook, hit_row, asset_row)
            else:
                log.warning(f"[alerter/slack] Channel id={channel.id} has no webhook_url.")

        elif ctype == "teams":
            webhook = cfg.get("webhook_url", "")
            if webhook:
                success = _send_teams(webhook, hit_row, asset_row)
            else:
                log.warning(f"[alerter/teams] Channel id={channel.id} has no webhook_url.")

        elif ctype == "email":
            success = _send_email(cfg, hit_row, asset_row)

        else:
            log.warning(f"[alerter] Unknown channel type '{ctype}' for channel id={channel.id}")

        if success:
            delivered += 1

    return delivered


# ─── Batch processor ──────────────────────────────────────────────────────────

def process_pending_alerts(db: Session) -> int:
    """
    Find watchlist hits that have not yet been alerted and send notifications
    via all active channels.  Marks each hit as alerted after successful delivery.
    Returns the number of hits processed.
    """
    from models import WatchlistHit, WatchedAsset

    pending = (
        db.query(WatchlistHit)
        .filter_by(alerted=False)
        .order_by(WatchlistHit.found_at.asc())
        .limit(100)
        .all()
    )

    if not pending:
        log.debug("[alerter] No pending alerts.")
        return 0

    log.info(f"[alerter] Processing {len(pending)} pending alert(s)...")
    processed = 0

    for hit in pending:
        try:
            # Look up the watched asset for context
            asset = db.query(WatchedAsset).filter_by(id=hit.watched_asset_id).first()
            if not asset:
                log.warning(f"[alerter] Asset id={hit.watched_asset_id} not found — skipping hit id={hit.id}")
                hit.alerted = True
                db.commit()
                continue

            delivered = send_alert(hit, asset, db)
            hit.alerted = True
            db.commit()
            processed += 1
            log.debug(f"[alerter] Hit id={hit.id} alerted via {delivered} channel(s).")

        except Exception as exc:
            log.error(f"[alerter] Error processing hit id={hit.id}: {exc}")
            db.rollback()

    log.info(f"[alerter] Done — {processed}/{len(pending)} hit(s) alerted.")
    return processed
