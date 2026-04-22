import json
import os
import re
import requests as _requests
from datetime import datetime, timezone
from typing import Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from sqlalchemy import create_engine
from streamlit_autorefresh import st_autorefresh

st.set_page_config(
    page_title="VANTELLIGENCE",
    layout="wide",
    page_icon="⬡",
    initial_sidebar_state="collapsed",
)
st_autorefresh(interval=30000, key="refresh")

from sqlalchemy.engine import URL as _URL

# ─── Professional dark theme ──────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
@import url('https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css');

/* ── Reset & base ───────────────────────────────────────────────────────── */
html, body, [class*="css"]  { font-family: 'Inter', sans-serif; }
.stApp                       { background: #050810; }
.block-container             { padding-top: 1rem !important; max-width: 1400px; }

/* ── Scrollbar ──────────────────────────────────────────────────────────── */
::-webkit-scrollbar            { width: 6px; height: 6px; }
::-webkit-scrollbar-track      { background: #0a0f1e; }
::-webkit-scrollbar-thumb      { background: #1e3a5f; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover{ background: #2a5080; }

/* ── Platform header ────────────────────────────────────────────────────── */
.platform-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 14px 24px; margin: -1rem -1rem 1.2rem -1rem;
    background: linear-gradient(135deg, #060c1a 0%, #0a1428 60%, #060c1a 100%);
    border-bottom: 1px solid #0f2040;
    box-shadow: 0 4px 24px rgba(0,0,0,0.6);
}
.platform-logo {
    font-size: 1.5rem; font-weight: 900; letter-spacing: 0.06em;
    background: linear-gradient(135deg, #38bdf8 0%, #818cf8 45%, #c084fc 100%);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    text-transform: uppercase;
}
.platform-logo span { font-weight: 400; opacity: 0.65; letter-spacing: 0.04em; }
.platform-meta {
    display: flex; align-items: center; gap: 20px;
    font-size: 0.75rem; color: #4a6080;
}
.live-badge {
    display: inline-flex; align-items: center; gap: 6px;
    background: rgba(6,214,160,0.08); border: 1px solid rgba(6,214,160,0.25);
    color: #06d6a0; padding: 3px 10px; border-radius: 20px;
    font-size: 0.7rem; font-weight: 700; letter-spacing: 0.1em;
}
.live-dot {
    width: 7px; height: 7px; background: #06d6a0; border-radius: 50%;
    animation: pulse-green 1.8s ease-in-out infinite;
}
@keyframes pulse-green {
    0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(6,214,160,0.7); }
    50%       { opacity: 0.6; box-shadow: 0 0 0 5px rgba(6,214,160,0); }
}

/* ── KPI cards ──────────────────────────────────────────────────────────── */
div[data-testid="metric-container"] {
    background: linear-gradient(145deg, #0c1628 0%, #080e1c 100%);
    border: 1px solid #142038;
    border-radius: 12px;
    padding: 18px 20px 14px;
    position: relative; overflow: hidden;
    box-shadow: 0 4px 20px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.03);
    transition: border-color 0.2s, box-shadow 0.2s;
}
div[data-testid="metric-container"]::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, transparent, #1e4080, transparent);
}
div[data-testid="metric-container"]:hover {
    border-color: #1e3a5f; box-shadow: 0 6px 28px rgba(56,189,248,0.1);
}
div[data-testid="metric-container"] > label {
    color: #4a6080 !important; font-size: 0.7rem !important;
    font-weight: 700 !important; text-transform: uppercase; letter-spacing: 0.1em;
}
div[data-testid="metric-container"] > div { color: #e2ecff !important; font-weight: 600 !important; }

/* ── Tabs ───────────────────────────────────────────────────────────────── */
div[data-testid="stTabs"] > div:first-child {
    border-bottom: 1px solid #0f2040;
    background: rgba(8,14,28,0.8);
    border-radius: 10px 10px 0 0;
    padding: 0 8px;
}
button[data-baseweb="tab"] {
    font-size: 0.78rem !important; font-weight: 600 !important;
    color: #3d5a80 !important; letter-spacing: 0.04em;
    padding: 10px 16px !important;
    transition: color 0.2s !important;
}
button[data-baseweb="tab"]:hover { color: #7aadcf !important; }
button[data-baseweb="tab"][aria-selected="true"] {
    color: #38bdf8 !important;
    border-bottom: 2px solid #38bdf8 !important;
    text-shadow: 0 0 20px rgba(56,189,248,0.5);
}

/* ── Section headings ───────────────────────────────────────────────────── */
h3, h4 { color: #c8d8f0 !important; font-weight: 700 !important; }
.section-label {
    font-size: 0.68rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.12em; color: #3d5a80;
    padding: 0 0 8px 0; margin-bottom: 12px;
    border-bottom: 1px solid #0f2040;
}

/* ── Threat cards (expanders) ───────────────────────────────────────────── */
div[data-testid="stExpander"] {
    background: linear-gradient(145deg, #0c1628 0%, #080e1c 100%);
    border: 1px solid #142038 !important;
    border-left: 3px solid #1e4080 !important;
    border-radius: 8px !important;
    margin-bottom: 5px;
    transition: border-color 0.15s, box-shadow 0.15s;
}
div[data-testid="stExpander"]:hover {
    border-color: #1e3a5f !important;
    border-left-color: #38bdf8 !important;
    box-shadow: 0 4px 20px rgba(56,189,248,0.06);
}
div[data-testid="stExpander"] summary {
    font-size: 0.84rem !important; font-weight: 500 !important;
    color: #9ab8d8 !important; padding: 10px 14px !important;
}

/* ── Dataframes ─────────────────────────────────────────────────────────── */
div[data-testid="stDataFrame"] {
    border: 1px solid #142038; border-radius: 8px;
    box-shadow: 0 2px 12px rgba(0,0,0,0.4);
}
div[data-testid="stDataFrame"] th {
    background: #0a1428 !important; color: #4a6080 !important;
    font-size: 0.72rem !important; font-weight: 700 !important;
    text-transform: uppercase; letter-spacing: 0.08em;
}

/* ── Inputs & selects ───────────────────────────────────────────────────── */
div[data-testid="stTextInput"] input,
div[data-baseweb="select"] {
    background: #0a1428 !important; border-color: #142038 !important;
    color: #c8d8f0 !important; border-radius: 8px !important;
}
div[data-testid="stTextInput"] input:focus {
    border-color: #38bdf8 !important;
    box-shadow: 0 0 0 2px rgba(56,189,248,0.15) !important;
}

/* ── Buttons ────────────────────────────────────────────────────────────── */
div[data-testid="stButton"] > button {
    background: linear-gradient(135deg, #0c1e38, #0a1428) !important;
    border: 1px solid #1e3a5f !important; color: #7aadcf !important;
    border-radius: 8px !important; font-weight: 600 !important;
    font-size: 0.8rem !important; letter-spacing: 0.02em;
    transition: all 0.2s !important;
}
div[data-testid="stButton"] > button:hover {
    background: linear-gradient(135deg, #112a50, #0d1e38) !important;
    border-color: #38bdf8 !important; color: #38bdf8 !important;
    box-shadow: 0 0 16px rgba(56,189,248,0.2) !important;
}

/* ── st.info / warning / error ──────────────────────────────────────────── */
div[data-testid="stAlert"][data-alert-type="info"] {
    background: rgba(56,189,248,0.06) !important;
    border: 1px solid rgba(56,189,248,0.2) !important;
    border-radius: 8px !important; color: #7aadcf !important;
}
div[data-testid="stAlert"][data-alert-type="warning"] {
    background: rgba(255,209,102,0.06) !important;
    border: 1px solid rgba(255,209,102,0.25) !important;
    border-radius: 8px !important;
}
div[data-testid="stAlert"][data-alert-type="error"] {
    background: rgba(255,77,109,0.08) !important;
    border: 1px solid rgba(255,77,109,0.3) !important;
    border-radius: 8px !important;
}

/* ── AI chat ────────────────────────────────────────────────────────────── */
div[data-testid="stChatMessage"] {
    background: linear-gradient(145deg, #0c1628, #080e1c) !important;
    border: 1px solid #142038 !important; border-radius: 10px !important;
    margin-bottom: 8px;
}
div[data-testid="stChatInputContainer"] {
    background: #0a1428 !important; border: 1px solid #1e3a5f !important;
    border-radius: 12px !important;
}
div[data-testid="stChatInputContainer"]:focus-within {
    border-color: #38bdf8 !important;
    box-shadow: 0 0 0 2px rgba(56,189,248,0.12) !important;
}

/* ── Sidebar ────────────────────────────────────────────────────────────── */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #060c1a 0%, #080f1e 100%);
    border-right: 1px solid #0f2040;
}

/* ── Dividers ───────────────────────────────────────────────────────────── */
hr { border: none !important; border-top: 1px solid #0f2040 !important; margin: 1.2rem 0 !important; }

/* ── Status cards (feed health) ─────────────────────────────────────────── */
.feed-card {
    background: linear-gradient(145deg, #0c1628, #080e1c);
    border: 1px solid #142038; border-left: 3px solid #1e4080;
    border-radius: 8px; padding: 12px 16px; margin-bottom: 6px;
    display: flex; align-items: center; gap: 16px;
}
.feed-card.ok    { border-left-color: #06d6a0; }
.feed-card.error { border-left-color: #ff4d6d; }
.feed-card.running { border-left-color: #38bdf8; }
.feed-card.pending { border-left-color: #ffd166; }
.feed-name { font-weight: 700; font-size: 0.82rem; color: #c8d8f0; min-width: 140px; font-family: 'JetBrains Mono', monospace; }
.feed-meta { font-size: 0.73rem; color: #3d5a80; flex: 1; }
.feed-count { font-size: 0.78rem; font-weight: 600; color: #38bdf8; font-family: 'JetBrains Mono', monospace; min-width: 80px; text-align: right; }
.feed-error { font-size: 0.72rem; color: #ff8060; margin-top: 3px; }
.status-icon { font-size: 0.85rem; flex-shrink: 0; line-height: 1; }
.status-icon.ok      { color: #06d6a0; filter: drop-shadow(0 0 4px rgba(6,214,160,0.7)); animation: pulse-green 2s infinite; }
.status-icon.error   { color: #ff4d6d; filter: drop-shadow(0 0 4px rgba(255,77,109,0.6)); }
.status-icon.running { color: #38bdf8; filter: drop-shadow(0 0 4px rgba(56,189,248,0.6)); animation: pulse-blue 1.2s infinite; }
.status-icon.pending { color: #ffd166; }
@keyframes pulse-blue {
    0%, 100% { box-shadow: 0 0 0 0 rgba(56,189,248,0.7); }
    50%       { box-shadow: 0 0 0 5px rgba(56,189,248,0); }
}

/* ── Badges ─────────────────────────────────────────────────────────────── */
.badge-critical { background: rgba(255,77,109,0.1); color: #ff4d6d; border: 1px solid rgba(255,77,109,0.4);
    padding: 2px 9px; border-radius: 20px; font-size: 0.68rem; font-weight: 800;
    font-family: 'Inter', sans-serif; letter-spacing: 0.06em; text-transform: uppercase; }
.badge-high { background: rgba(255,140,66,0.1); color: #ff8c42; border: 1px solid rgba(255,140,66,0.4);
    padding: 2px 9px; border-radius: 20px; font-size: 0.68rem; font-weight: 800;
    font-family: 'Inter', sans-serif; letter-spacing: 0.06em; text-transform: uppercase; }
.badge-medium { background: rgba(255,209,102,0.1); color: #ffd166; border: 1px solid rgba(255,209,102,0.4);
    padding: 2px 9px; border-radius: 20px; font-size: 0.68rem; font-weight: 800;
    font-family: 'Inter', sans-serif; letter-spacing: 0.06em; text-transform: uppercase; }
.badge-low { background: rgba(6,214,160,0.08); color: #06d6a0; border: 1px solid rgba(6,214,160,0.3);
    padding: 2px 9px; border-radius: 20px; font-size: 0.68rem; font-weight: 800;
    font-family: 'Inter', sans-serif; letter-spacing: 0.06em; text-transform: uppercase; }
.badge-info { background: rgba(56,189,248,0.08); color: #38bdf8; border: 1px solid rgba(56,189,248,0.3);
    padding: 2px 9px; border-radius: 20px; font-size: 0.68rem; font-weight: 800;
    font-family: 'Inter', sans-serif; letter-spacing: 0.06em; }

/* ── Tags ───────────────────────────────────────────────────────────────── */
.feed-tag { background: rgba(30,64,128,0.4); color: #5b8ed4; border: 1px solid rgba(56,130,240,0.25);
    padding: 1px 8px; border-radius: 4px; font-size: 0.68rem;
    font-family: 'JetBrains Mono', monospace; font-weight: 600; }
.ttp-tag  { background: rgba(90,58,138,0.3); color: #b48ef5; border: 1px solid rgba(139,92,246,0.3);
    padding: 1px 8px; border-radius: 4px; font-size: 0.68rem;
    font-family: 'JetBrains Mono', monospace; font-weight: 600; }
.ioc-val  { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: #7dd3fc; }

/* ── Critical glow on metric values ────────────────────────────────────── */
.metric-glow { color: #ff4d6d !important; text-shadow: 0 0 20px rgba(255,77,109,0.5); }

/* ── Bootstrap Icons sizing ─────────────────────────────────────────────── */
.bi { line-height: 1; vertical-align: -0.125em; }
.bi-sm  { font-size: 0.85rem; }
.bi-md  { font-size: 1.1rem; }
.bi-lg  { font-size: 1.4rem; }
.icon-ok      { color: #06d6a0; }
.icon-error   { color: #ff4d6d; }
.icon-running { color: #38bdf8; }
.icon-pending { color: #ffd166; }
.icon-accent  { color: #38bdf8; }
.icon-muted   { color: #3d5a80; }
.icon-purple  { color: #b48ef5; }
</style>
""", unsafe_allow_html=True)

# ─── Database ─────────────────────────────────────────────────────────────────
_DB_URL = _URL.create(
    drivername="postgresql+psycopg2",
    username=os.getenv("POSTGRES_USER", "intel_admin"),
    password=os.getenv("POSTGRES_PASSWORD", "change_me"),
    host=os.getenv("POSTGRES_HOST", "db"),
    port=5432,
    database=os.getenv("POSTGRES_DB", "threat_intel"),
)


@st.cache_resource
def get_engine():
    return create_engine(_DB_URL, pool_pre_ping=True)


@st.cache_data(ttl=15)
def load_data():
    engine = get_engine()
    try:
        reports = pd.read_sql(
            "SELECT * FROM threat_reports ORDER BY created_at DESC LIMIT 500", engine
        )
        iocs = pd.read_sql("SELECT * FROM iocs ORDER BY id DESC LIMIT 5000", engine)
        cves = pd.read_sql(
            "SELECT * FROM cve_records ORDER BY created_at DESC LIMIT 500", engine
        )
        feed_status = pd.read_sql("SELECT * FROM feed_status ORDER BY feed_name", engine)
        return reports, iocs, cves, feed_status
    except Exception as exc:
        st.error(f"Database error: {exc}")
        return pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), pd.DataFrame()


@st.cache_data(ttl=60)
def load_attack_data():
    engine = get_engine()
    try:
        techniques = pd.read_sql(
            "SELECT * FROM mitre_techniques ORDER BY technique_id", engine
        )
        mitigations = pd.read_sql(
            """SELECT mm.mitigation_id, mm.name, mm.description,
                      mt.technique_id, mt.name AS tech_name, mt.tactic
               FROM mitre_mitigations mm
               JOIN mitre_techniques mt ON mm.technique_fk = mt.id
               ORDER BY mt.technique_id, mm.mitigation_id""",
            engine,
        )
        return techniques, mitigations
    except Exception:
        return pd.DataFrame(), pd.DataFrame()


# ─── Helpers ──────────────────────────────────────────────────────────────────
_PLOTLY_DARK = dict(
    template="plotly_dark",
    paper_bgcolor="#070b14",
    plot_bgcolor="#0d1526",
    font_color="#c9d1d9",
    margin=dict(l=20, r=20, t=40, b=20),
)


def _severity_badge(score: int) -> str:
    if score >= 90:
        return f'<span class="badge-critical">CRITICAL</span>'
    if score >= 70:
        return f'<span class="badge-high">HIGH</span>'
    if score >= 40:
        return f'<span class="badge-medium">MEDIUM</span>'
    return f'<span class="badge-low">LOW</span>'


def _cvss_badge(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return '<span class="badge-info">N/A</span>'
    if s >= 9.0:
        return f'<span class="badge-critical">CVSS {s:.1f}</span>'
    if s >= 7.0:
        return f'<span class="badge-high">CVSS {s:.1f}</span>'
    if s >= 4.0:
        return f'<span class="badge-medium">CVSS {s:.1f}</span>'
    return f'<span class="badge-low">CVSS {s:.1f}</span>'


def _enrichment_links(ioc_type: str, value: str) -> str:
    """Return HTML enrichment links for an IOC based on its type."""
    vt = f"https://www.virustotal.com/gui/search/{value}"
    links = [f'<a href="{vt}" target="_blank">VirusTotal</a>']
    t = ioc_type.lower()
    if "ip" in t:
        links.append(f'<a href="https://www.abuseipdb.com/check/{value}" target="_blank">AbuseIPDB</a>')
        links.append(f'<a href="https://www.shodan.io/host/{value}" target="_blank">Shodan</a>')
        links.append(f'<a href="https://otx.alienvault.com/indicator/ip/{value}" target="_blank">OTX</a>')
    elif "domain" in t or "url" in t:
        links.append(f'<a href="https://urlscan.io/search/#{value}" target="_blank">URLScan</a>')
        links.append(f'<a href="https://otx.alienvault.com/indicator/domain/{value}" target="_blank">OTX</a>')
    elif "hash" in t:
        links.append(f'<a href="https://bazaar.abuse.ch/browse.php?search=sha256%3A{value}" target="_blank">MalwareBazaar</a>')
        links.append(f'<a href="https://otx.alienvault.com/indicator/file/{value}" target="_blank">OTX</a>')
    return " · ".join(links)


def _ttp_map(reports: pd.DataFrame) -> dict:
    counts: dict = {}
    for _, row in reports.iterrows():
        raw = row.get("ttps") or []
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except Exception:
                raw = []
        actor = str(row.get("threat_actor") or "Unknown")
        for t in (raw or []):
            e = counts.setdefault(t, {"count": 0, "actors": set()})
            e["count"] += 1
            e["actors"].add(actor)
    return counts


# ─── AI Analyst ───────────────────────────────────────────────────────────────
_OLLAMA_URL    = os.getenv("OLLAMA_URL",    "http://host.docker.internal:11434")
_LMSTUDIO_URL  = os.getenv("LMSTUDIO_URL",  "")
_LMSTUDIO_MDL  = os.getenv("LMSTUDIO_MODEL", "local-model")
_CLAUDE_KEY    = os.getenv("CLAUDE_API_KEY", "")
_GEMINI_KEY    = os.getenv("GEMINI_API_KEY", "")

_raw = os.getenv("OLLAMA_MODELS") or os.getenv("OLLAMA_MODEL", "llama3.2")
_LOCAL_MODELS: list = [m.strip() for m in _raw.split(",") if m.strip()]

_ANALYST_SYSTEM = """\
You are an expert Cyber Threat Intelligence (CTI) analyst with deep knowledge of MITRE ATT&CK,
CVE databases, IOC analysis, and threat actor tradecraft. You have access to a live threat
intelligence database summarised below. Answer clearly and concisely. Reference ATT&CK IDs
(e.g. T1566.001) and CVE IDs where relevant. Give actionable, prioritised recommendations when
asked. Say so honestly if the data is insufficient rather than speculating.

Current database snapshot:
{context}"""


def _build_context(reports, iocs, cves, techniques_df) -> str:
    lines = []
    if not reports.empty:
        by_feed = reports.groupby("source_feed").size().to_dict()
        lines.append("THREAT REPORTS BY FEED: " + ", ".join(f"{k}={v}" for k, v in by_feed.items()))
        lines.append(f"TOTAL REPORTS: {len(reports)}")
        actors = reports["threat_actor"].dropna().value_counts().head(10).to_dict()
        if actors:
            lines.append("TOP THREAT ACTORS: " + ", ".join(f"{a}({c})" for a, c in actors.items()))
        ttp_counts: dict = {}
        for _, row in reports.iterrows():
            raw = row.get("ttps") or []
            if isinstance(raw, str):
                try:
                    raw = json.loads(raw)
                except Exception:
                    raw = []
            for t in (raw or []):
                ttp_counts[t] = ttp_counts.get(t, 0) + 1
        if ttp_counts:
            top = sorted(ttp_counts.items(), key=lambda x: -x[1])[:15]
            lines.append("TOP OBSERVED TTPS: " + ", ".join(f"{t}({c})" for t, c in top))
        recent = reports[reports["summary"].notna() & (reports["summary"] != "")].head(10)
        if not recent.empty:
            lines.append("\nRECENT THREAT SUMMARIES:")
            for _, row in recent.iterrows():
                lines.append(
                    f"  [{str(row.get('source_feed','?')).upper()}] "
                    f"{row.get('threat_actor','?')}: {str(row.get('summary',''))[:200]}"
                )
    if not iocs.empty:
        by_type = iocs.groupby("ioc_type").size().to_dict()
        lines.append("\nIOCS BY TYPE: " + ", ".join(f"{k}={v}" for k, v in by_type.items()))
    if not cves.empty:
        kev = int((cves["is_kev"] == 1).sum()) if "is_kev" in cves else 0
        crit = int((cves["cvss_score"].fillna(0) >= 9.0).sum()) if "cvss_score" in cves else 0
        lines.append(f"\nCVES: {len(cves)} total, {kev} CISA-KEV, {crit} CVSS≥9")
        hi = cves[cves["cvss_score"].fillna(0) >= 9.0].head(5) if "cvss_score" in cves.columns else pd.DataFrame()
        for _, r in hi.iterrows():
            lines.append(f"  {r.get('cve_id','?')} CVSS={r.get('cvss_score','?')} {r.get('vendor','?')}/{r.get('product','?')}")
    if not techniques_df.empty:
        lines.append(f"\nMITRE ATT&CK TECHNIQUES IN DB: {len(techniques_df)}")
    return "\n".join(lines)


def _ollama_up() -> bool:
    try:
        return _requests.get(f"{_OLLAMA_URL}/api/tags", timeout=2).ok
    except Exception:
        return False


def _lmstudio_up() -> bool:
    if not _LMSTUDIO_URL:
        return False
    try:
        return _requests.get(f"{_LMSTUDIO_URL}/v1/models", timeout=2).ok
    except Exception:
        return False


def _analyst_ollama_model(messages: list, model: str) -> Optional[str]:
    prompt = "\n\n".join(
        f"{'Assistant' if m['role'] == 'assistant' else 'User'}: {m['content']}"
        for m in messages
    ) + "\n\nAssistant:"
    try:
        resp = _requests.post(
            f"{_OLLAMA_URL}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=90,
        )
        resp.raise_for_status()
        return resp.json().get("response", "").strip() or None
    except Exception:
        return None


def _analyst_ollama(messages: list) -> Optional[str]:
    """Try each configured local Ollama model; skip instantly if server is down."""
    if not _ollama_up():
        return None
    for model in _LOCAL_MODELS:
        reply = _analyst_ollama_model(messages, model)
        if reply:
            return reply
    return None


def _analyst_lmstudio(messages: list) -> Optional[str]:
    """OpenAI-compatible chat via LM Studio (or any local server)."""
    if not _lmstudio_up():
        return None
    try:
        chat_msgs = [m for m in messages if m["role"] != "system"]
        system    = next((m["content"] for m in messages if m["role"] == "system"), "")
        payload   = ([{"role": "system", "content": system}] + chat_msgs) if system else chat_msgs
        resp = _requests.post(
            f"{_LMSTUDIO_URL}/v1/chat/completions",
            json={"model": _LMSTUDIO_MDL, "messages": payload,
                  "temperature": 0.2, "max_tokens": 1500},
            timeout=90,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip() or None
    except Exception:
        return None


def _analyst_claude(messages: list) -> Optional[str]:
    if not _CLAUDE_KEY:
        return None
    try:
        import anthropic
        client     = anthropic.Anthropic(api_key=_CLAUDE_KEY)
        system_msg = next((m["content"] for m in messages if m["role"] == "system"), "")
        chat_msgs  = [m for m in messages if m["role"] != "system"]
        result = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1500,
            system=system_msg,
            messages=chat_msgs,
        )
        return result.content[0].text.strip() or None
    except Exception:
        return None


def _analyst_gemini(messages: list) -> Optional[str]:
    if not _GEMINI_KEY:
        return None
    try:
        from google import genai
        client   = genai.Client(api_key=_GEMINI_KEY)
        combined = "\n\n".join(m["content"] for m in messages)
        result   = client.models.generate_content(model="gemini-2.0-flash", contents=combined)
        return result.text.strip() or None
    except Exception:
        return None


def analyst_reply(messages: list) -> str:
    """Local-first: Ollama models → LM Studio → Claude → Gemini.
    Cloud APIs only reached if every local option is down or returns nothing."""
    for fn in (_analyst_ollama, _analyst_lmstudio, _analyst_claude, _analyst_gemini):
        reply = fn(messages)
        if reply:
            return reply
    return (
        "⚠️ No AI backend is reachable. "
        "Set OLLAMA_MODELS in .env (e.g. llama3.2,mistral,phi3), "
        "or configure CLAUDE_API_KEY / GEMINI_API_KEY as a cloud fallback."
    )


# ─── Load data ────────────────────────────────────────────────────────────────
reports, iocs, cves, feed_status = load_data()
techniques_df, mitigations_df = load_attack_data()

# ─── Platform header ──────────────────────────────────────────────────────────
_now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
_enriched = int((reports["summary"].notna() & (reports["summary"] != "")).sum()) if not reports.empty else 0
st.markdown(f"""
<div class="platform-header">
  <div>
    <div class="platform-logo">VAN<span>TELLIGENCE</span></div>
    <div style="font-size:0.65rem;color:#2a4060;margin-top:4px;font-family:'JetBrains Mono',monospace;letter-spacing:0.18em;">
      SEE EVERY THREAT. BEFORE IT SEES YOU.
    </div>
  </div>
  <div class="platform-meta">
    <span style="font-family:'JetBrains Mono',monospace">{_now_utc} UTC</span>
    <span class="live-badge"><span class="live-dot"></span>LIVE</span>
  </div>
</div>
""", unsafe_allow_html=True)

# ─── Top KPI strip ────────────────────────────────────────────────────────────
k1, k2, k3, k4, k5, k6 = st.columns(6)
kev_count  = int((cves["is_kev"] == 1).sum()) if not cves.empty and "is_kev" in cves else 0
crit_cves  = int((cves["cvss_score"].fillna(0) >= 9.0).sum()) if not cves.empty and "cvss_score" in cves else 0
active_f   = int((feed_status["status"] == "ok").sum()) if not feed_status.empty else 0
total_f    = len(feed_status)
ttp_usage  = _ttp_map(reports)

with k1: st.metric("Threat Reports",  f"{len(reports):,}")
with k2: st.metric("IOCs Tracked",    f"{len(iocs):,}")
with k3: st.metric("CVEs Monitored",  f"{len(cves):,}")
with k4: st.metric("CISA KEV",        f"{kev_count:,}")
with k5: st.metric("CVSS ≥ 9.0",      f"{crit_cves:,}")
with k6: st.metric("Active Feeds",    f"{active_f} / {total_f}")

st.divider()

# ─── Tabs ─────────────────────────────────────────────────────────────────────
(tab_dash, tab_feed, tab_actors, tab_iocs,
 tab_cves, tab_attack, tab_analyst, tab_health) = st.tabs([
    "◈  Dashboard", "◉  Threat Feed", "⬡  Actors",
    "⊙  IOC Hunt",  "◆  CVE Tracker",
    "⬢  ATT&CK",    "⊕  AI Analyst",  "◎  Feed Health",
])


# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
with tab_dash:
    st.markdown('<p class="section-label"><i class="bi bi-grid-3x3-gap-fill bi-sm"></i>&nbsp; Executive Overview</p>', unsafe_allow_html=True)

    if reports.empty:
        st.info("Collector is initialising feeds — check back in a few minutes.")
    else:
        row1_l, row1_r = st.columns(2)

        # ── Threat reports by source (bar) ────────────────────────────────────
        with row1_l:
            st.markdown("#### Threat Reports by Source")
            by_src = reports.groupby("source_feed").size().reset_index(name="count")
            by_src = by_src.sort_values("count", ascending=True)
            fig = px.bar(
                by_src, x="count", y="source_feed", orientation="h",
                color="count",
                color_continuous_scale=[[0, "#1a3a6a"], [1, "#38bdf8"]],
                labels={"source_feed": "", "count": "Reports"},
            )
            fig.update_coloraxes(showscale=False)
            fig.update_layout(**_PLOTLY_DARK)
            fig.update_traces(hovertemplate="%{y}: %{x} reports<extra></extra>")
            st.plotly_chart(fig, use_container_width=True)

        # ── IOC type distribution (donut) ─────────────────────────────────────
        with row1_r:
            st.markdown("#### IOC Type Distribution")
            if not iocs.empty:
                by_type = iocs.groupby("ioc_type").size().reset_index(name="count")
                fig2 = px.pie(
                    by_type, names="ioc_type", values="count", hole=0.55,
                    color_discrete_sequence=px.colors.sequential.Blues_r,
                )
                fig2.update_layout(**_PLOTLY_DARK, showlegend=True)
                fig2.update_traces(textposition="outside", textinfo="percent+label",
                                   hovertemplate="%{label}: %{value:,}<extra></extra>")
                st.plotly_chart(fig2, use_container_width=True)
            else:
                st.info("No IOC data yet.")

        row2_l, row2_r = st.columns(2)

        # ── Confidence score histogram ─────────────────────────────────────────
        with row2_l:
            st.markdown("#### Threat Report Confidence Distribution")
            scores = reports["confidence_score"].dropna()
            fig3 = px.histogram(
                scores, nbins=20,
                color_discrete_sequence=["#38bdf8"],
                labels={"value": "Confidence Score", "count": "Reports"},
            )
            fig3.update_layout(**_PLOTLY_DARK)
            fig3.update_traces(hovertemplate="Score %{x}: %{y} reports<extra></extra>")
            st.plotly_chart(fig3, use_container_width=True)

        # ── Top MITRE tactics ─────────────────────────────────────────────────
        with row2_r:
            st.markdown("#### Top Observed ATT&CK Tactics")
            if ttp_usage and not techniques_df.empty:
                obs = techniques_df[techniques_df["technique_id"].isin(ttp_usage.keys())].copy()
                obs["count"] = obs["technique_id"].map(lambda t: ttp_usage.get(t, {}).get("count", 0))
                tac_counts: dict = {}
                for _, row in obs.iterrows():
                    for tac in str(row.get("tactic") or "Unknown").split(","):
                        tac = tac.strip() or "Unknown"
                        tac_counts[tac] = tac_counts.get(tac, 0) + row["count"]
                tdf = pd.DataFrame(list(tac_counts.items()), columns=["Tactic", "Count"]).sort_values("Count")
                fig4 = px.bar(
                    tdf, x="Count", y="Tactic", orientation="h",
                    color="Count",
                    color_continuous_scale=[[0, "#2d1060"], [1, "#b48ef5"]],
                )
                fig4.update_coloraxes(showscale=False)
                fig4.update_layout(**_PLOTLY_DARK)
                st.plotly_chart(fig4, use_container_width=True)
            else:
                st.info("ATT&CK TTP mapping populates as the AI enrichment runs.")

        # ── CVSS severity breakdown ────────────────────────────────────────────
        if not cves.empty and "cvss_score" in cves.columns:
            st.markdown("#### CVE Severity Breakdown")
            def _sev(s):
                try:
                    v = float(s)
                    if v >= 9.0: return "Critical"
                    if v >= 7.0: return "High"
                    if v >= 4.0: return "Medium"
                    return "Low"
                except Exception:
                    return "Unknown"
            cves_copy = cves.copy()
            cves_copy["severity"] = cves_copy["cvss_score"].apply(_sev)
            sev_counts = cves_copy["severity"].value_counts().reset_index()
            sev_counts.columns = ["Severity", "Count"]
            color_map = {"Critical": "#ff4d6d", "High": "#ff8c42",
                         "Medium": "#ffd166", "Low": "#06d6a0", "Unknown": "#5d7199"}
            fig5 = px.bar(
                sev_counts, x="Severity", y="Count",
                color="Severity", color_discrete_map=color_map,
                category_orders={"Severity": ["Critical", "High", "Medium", "Low", "Unknown"]},
            )
            fig5.update_layout(**_PLOTLY_DARK, showlegend=False)
            st.plotly_chart(fig5, use_container_width=True)

        # ── Recent critical events ─────────────────────────────────────────────
        st.markdown("#### Recent High-Confidence Threats")
        hi_conf = reports[reports["confidence_score"].fillna(0) >= 70].head(5)
        if hi_conf.empty:
            st.info("No high-confidence threats yet.")
        else:
            for _, row in hi_conf.iterrows():
                ts = row["created_at"].strftime("%Y-%m-%d %H:%M") if hasattr(row["created_at"], "strftime") else "?"
                actor = row.get("threat_actor") or "Unknown"
                conf  = int(row.get("confidence_score") or 0)
                feed  = str(row.get("source_feed", "")).upper()
                summary = str(row.get("summary") or "")
                st.markdown(
                    f'<span class="feed-tag">{feed}</span> &nbsp;'
                    f'<b>{actor}</b> &nbsp; {_severity_badge(conf)} &nbsp;'
                    f'<span style="color:#5d7199;font-size:0.78rem">{ts} UTC</span><br/>'
                    f'<span style="font-size:0.85rem;color:#9aabb8">{summary[:180]}</span>',
                    unsafe_allow_html=True,
                )
                st.markdown("---")


# ══════════════════════════════════════════════════════════════════════════════
# THREAT FEED
# ══════════════════════════════════════════════════════════════════════════════
with tab_feed:
    st.markdown('<p class="section-label"><i class="bi bi-lightning-fill bi-sm icon-error"></i>&nbsp; Active Threat Reports</p>', unsafe_allow_html=True)

    if reports.empty:
        st.info("Collector is initialising feeds — check back in a few minutes.")
    else:
        fc1, fc2, fc3 = st.columns([2, 2, 1])
        with fc1:
            sources  = sorted(reports["source_feed"].dropna().unique().tolist())
            feed_filter = st.multiselect("Source", options=sources, key="ff_src")
        with fc2:
            actors_list = sorted([a for a in reports["threat_actor"].dropna().unique() if a != "Unknown"])
            actor_filter = st.multiselect("Threat Actor", options=actors_list, key="ff_act")
        with fc3:
            min_conf = st.slider("Min Confidence", 0, 100, 0, key="ff_conf")

        filtered = reports.copy()
        if feed_filter:  filtered = filtered[filtered["source_feed"].isin(feed_filter)]
        if actor_filter: filtered = filtered[filtered["threat_actor"].isin(actor_filter)]
        filtered = filtered[filtered["confidence_score"].fillna(0) >= min_conf]

        st.caption(f"Showing {min(len(filtered), 50)} of {len(filtered)} reports")

        for _, row in filtered.head(50).iterrows():
            ts    = row["created_at"].strftime("%Y-%m-%d %H:%M") if hasattr(row["created_at"], "strftime") else "?"
            actor = row.get("threat_actor") or "Unknown"
            conf  = int(row.get("confidence_score") or 0)
            feed  = str(row.get("source_feed", "")).upper()
            ttps  = row.get("ttps") or []
            if isinstance(ttps, str):
                try: ttps = json.loads(ttps)
                except Exception: ttps = []

            label = f"[{ts}]  {actor}  ·  {feed}  ·  Confidence {conf}%"
            with st.expander(label):
                st.markdown(
                    _severity_badge(conf) + f'&nbsp; <span class="feed-tag">{feed}</span>',
                    unsafe_allow_html=True,
                )
                summary = row.get("summary")
                if summary:
                    st.markdown(f"> {summary}")

                col_l, col_r = st.columns(2)
                with col_l:
                    if ttps:
                        tags = " ".join(f'<span class="ttp-tag">{t}</span>' for t in ttps[:8])
                        st.markdown(f"**TTPs:** {tags}", unsafe_allow_html=True)
                    cve_list = row.get("associated_cves") or []
                    if isinstance(cve_list, str):
                        try: cve_list = json.loads(cve_list)
                        except Exception: cve_list = []
                    if cve_list:
                        st.markdown("**CVEs:** " + "  ".join(f"`{c}`" for c in cve_list[:5]))
                with col_r:
                    report_iocs = iocs[iocs["report_id"] == row["id"]]
                    if not report_iocs.empty:
                        st.markdown(f"**IOCs ({len(report_iocs)}):**")
                        cols = [c for c in ["ioc_type", "value", "malware_family"] if c in report_iocs.columns]
                        st.dataframe(report_iocs[cols].head(8), use_container_width=True, hide_index=True)

                raw = str(row.get("raw_source") or "")
                if st.toggle("Show raw source", key=f"raw_{row['id']}"):
                    st.code(raw[:800] + ("…" if len(raw) > 800 else ""), language="text")


# ══════════════════════════════════════════════════════════════════════════════
# THREAT ACTORS
# ══════════════════════════════════════════════════════════════════════════════
with tab_actors:
    st.markdown('<p class="section-label"><i class="bi bi-person-badge-fill bi-sm icon-accent"></i>&nbsp; Threat Actor Profiles</p>', unsafe_allow_html=True)

    if reports.empty:
        st.info("No threat data yet.")
    else:
        # Aggregate by actor
        actor_data = []
        for actor, grp in reports[reports["threat_actor"] != "Unknown"].groupby("threat_actor"):
            all_ttps: set = set()
            all_cves: set = set()
            all_feeds: set = set(grp["source_feed"].dropna().tolist())
            industries: dict = {}
            for _, row in grp.iterrows():
                raw_t = row.get("ttps") or []
                if isinstance(raw_t, str):
                    try: raw_t = json.loads(raw_t)
                    except Exception: raw_t = []
                all_ttps.update(raw_t or [])
                raw_c = row.get("associated_cves") or []
                if isinstance(raw_c, str):
                    try: raw_c = json.loads(raw_c)
                    except Exception: raw_c = []
                all_cves.update(raw_c or [])
                ind = str(row.get("target_industry") or "Unknown")
                if ind != "Unknown":
                    industries[ind] = industries.get(ind, 0) + 1
            actor_data.append({
                "actor": actor,
                "reports": len(grp),
                "avg_conf": int(grp["confidence_score"].fillna(0).mean()),
                "ttps": sorted(all_ttps),
                "cves": sorted(all_cves),
                "feeds": sorted(all_feeds),
                "industries": industries,
            })

        actor_data.sort(key=lambda x: -x["reports"])

        if not actor_data:
            st.info("Actor profiles populate as the AI enrichment runs (may take a few cycles).")
        else:
            # Top actors bar chart
            adf = pd.DataFrame([{"Actor": a["actor"], "Reports": a["reports"],
                                  "Avg Confidence": a["avg_conf"]} for a in actor_data[:20]])
            fig_a = px.bar(
                adf.sort_values("Reports"), x="Reports", y="Actor", orientation="h",
                color="Avg Confidence",
                color_continuous_scale=[[0, "#1a3a6a"], [0.5, "#38bdf8"], [1, "#ff4d6d"]],
                labels={"Actor": "", "Reports": "Report Count"},
            )
            fig_a.update_layout(**_PLOTLY_DARK, height=max(250, 30 * len(adf)))
            st.plotly_chart(fig_a, use_container_width=True)

            st.markdown("#### Actor Details")
            for a in actor_data:
                badge = _severity_badge(a["avg_conf"])
                with st.expander(f"**{a['actor']}** — {a['reports']} report(s)"):
                    c1, c2, c3 = st.columns(3)
                    with c1:
                        st.markdown("**Confidence**")
                        st.markdown(badge, unsafe_allow_html=True)
                    with c2:
                        st.markdown("**Sources**")
                        for f in a["feeds"]:
                            st.markdown(f'<span class="feed-tag">{f.upper()}</span>', unsafe_allow_html=True)
                    with c3:
                        if a["industries"]:
                            st.markdown("**Target Industries**")
                            for ind, cnt in sorted(a["industries"].items(), key=lambda x: -x[1]):
                                st.caption(f"{ind} ({cnt})")

                    if a["ttps"]:
                        st.markdown("**Observed TTPs**")
                        tags = " ".join(f'<span class="ttp-tag">{t}</span>' for t in a["ttps"][:20])
                        st.markdown(tags, unsafe_allow_html=True)

                    if a["cves"]:
                        st.markdown("**Associated CVEs**")
                        st.markdown("  ".join(f"`{c}`" for c in a["cves"][:10]))

                    # IOCs attributed to this actor
                    actor_reports = reports[reports["threat_actor"] == a["actor"]]
                    actor_iocs = iocs[iocs["report_id"].isin(actor_reports["id"])]
                    if not actor_iocs.empty:
                        st.markdown(f"**IOCs ({min(len(actor_iocs), 20)} shown)**")
                        cols = [c for c in ["ioc_type", "value", "malware_family"] if c in actor_iocs.columns]
                        st.dataframe(actor_iocs[cols].head(20), use_container_width=True, hide_index=True)


# ══════════════════════════════════════════════════════════════════════════════
# IOC HUNT
# ══════════════════════════════════════════════════════════════════════════════
with tab_iocs:
    st.markdown('<p class="section-label"><i class="bi bi-search bi-sm icon-accent"></i>&nbsp; IOC Hunt &amp; Enrichment</p>', unsafe_allow_html=True)

    if iocs.empty:
        st.info("No IOCs collected yet.")
    else:
        sc1, sc2, sc3 = st.columns([3, 2, 1])
        with sc1:
            search = st.text_input("Search IP, domain, hash, URL…", key="ioc_search")
        with sc2:
            ioc_types = sorted(iocs["ioc_type"].dropna().unique().tolist())
            type_filter = st.multiselect("IOC Type", options=ioc_types, key="ioc_type_f")
        with sc3:
            fam_search = st.text_input("Malware Family", key="ioc_fam")

        fi = iocs.copy()
        if search:
            fi = fi[fi["value"].str.contains(search, case=False, na=False)]
        if type_filter:
            fi = fi[fi["ioc_type"].isin(type_filter)]
        if fam_search:
            fi = fi[fi["malware_family"].str.contains(fam_search, case=False, na=False)]

        st.caption(f"{len(fi):,} IOCs match · showing first 200")

        # Enrichment table with external links
        if not fi.empty:
            for _, row in fi.head(200).iterrows():
                itype = str(row.get("ioc_type", ""))
                val   = str(row.get("value", ""))
                fam   = str(row.get("malware_family") or "")
                links = _enrichment_links(itype, val)
                st.markdown(
                    f'<span class="badge-info">{itype}</span> &nbsp;'
                    f'<span class="ioc-val">{val}</span>'
                    + (f' &nbsp; <span style="color:#6e7fa3;font-size:0.78rem">({fam})</span>' if fam else "")
                    + f'<br/><span style="font-size:0.75rem;color:#3d5a80"><i class="bi bi-box-arrow-up-right"></i> {links}</span>',
                    unsafe_allow_html=True,
                )
        st.divider()

        display_cols = [c for c in ["ioc_type", "value", "malware_family", "tags"] if c in fi.columns]
        csv = fi[display_cols].to_csv(index=False).encode()
        st.download_button("↓  Export as CSV", csv, "iocs_export.csv", "text/csv")


# ══════════════════════════════════════════════════════════════════════════════
# CVE TRACKER
# ══════════════════════════════════════════════════════════════════════════════
with tab_cves:
    st.markdown('<p class="section-label"><i class="bi bi-bug-fill bi-sm icon-error"></i>&nbsp; CVE Tracker</p>', unsafe_allow_html=True)

    if cves.empty:
        st.info("CVE data loading from CISA KEV and NVD feeds…")
    else:
        cc1, cc2, cc3 = st.columns(3)
        with cc1:
            kev_only = st.checkbox("CISA KEV only", key="cve_kev")
        with cc2:
            min_cvss = st.slider("Min CVSS", 0.0, 10.0, 0.0, 0.1, key="cve_cvss")
        with cc3:
            vendor_search = st.text_input("Vendor / Product", key="cve_vendor")

        fc = cves.copy()
        if kev_only and "is_kev" in fc.columns:
            fc = fc[fc["is_kev"] == 1]
        if min_cvss > 0 and "cvss_score" in fc.columns:
            fc = fc[fc["cvss_score"].fillna(0) >= min_cvss]
        if vendor_search:
            mask = (
                fc["vendor"].str.contains(vendor_search, case=False, na=False) |
                fc["product"].str.contains(vendor_search, case=False, na=False)
            )
            fc = fc[mask]

        # CVSS scatter
        if "cvss_score" in fc.columns and not fc.empty:
            plot_df = fc[fc["cvss_score"].notna()].copy()
            if not plot_df.empty:
                def _sev_label(s):
                    if s >= 9: return "Critical"
                    if s >= 7: return "High"
                    if s >= 4: return "Medium"
                    return "Low"
                plot_df["Severity"] = plot_df["cvss_score"].apply(_sev_label)
                plot_df["label"] = plot_df["cve_id"]
                fig_c = px.scatter(
                    plot_df.head(200), x="label", y="cvss_score",
                    color="Severity",
                    color_discrete_map={"Critical": "#ff4d6d", "High": "#ff8c42",
                                        "Medium": "#ffd166", "Low": "#06d6a0"},
                    hover_data=["vendor", "product"],
                    labels={"label": "CVE ID", "cvss_score": "CVSS Score"},
                    size_max=10,
                )
                fig_c.update_layout(**_PLOTLY_DARK, height=300,
                                    xaxis=dict(tickangle=45, tickfont=dict(size=8)))
                st.plotly_chart(fig_c, use_container_width=True)

        st.caption(f"{len(fc):,} CVEs match")
        dcols = [c for c in ["cve_id", "cvss_score", "vendor", "product",
                              "cisa_due_date", "is_kev", "description"] if c in fc.columns]
        st.dataframe(
            fc[dcols].head(200),
            use_container_width=True, hide_index=True,
            column_config={
                "is_kev":     st.column_config.CheckboxColumn("KEV"),
                "cvss_score": st.column_config.NumberColumn("CVSS", format="%.1f"),
                "description": st.column_config.TextColumn("Description", width="large"),
            },
        )
        csv_c = fc[dcols].to_csv(index=False).encode()
        st.download_button("↓  Export CVEs as CSV", csv_c, "cves_export.csv", "text/csv")


# ══════════════════════════════════════════════════════════════════════════════
# ATT&CK MAPPING
# ══════════════════════════════════════════════════════════════════════════════
with tab_attack:
    st.markdown('<p class="section-label"><i class="bi bi-diagram-3-fill bi-sm icon-purple"></i>&nbsp; MITRE ATT&amp;CK Mapping &amp; Remediation</p>', unsafe_allow_html=True)

    if techniques_df.empty:
        st.info("ATT&CK data not loaded yet — collector populates this on its first 24-hour cycle.")
    else:
        observed_ids = set(ttp_usage.keys())
        obs_tech = techniques_df[techniques_df["technique_id"].isin(observed_ids)].copy()

        am1, am2, am3, am4 = st.columns(4)
        with am1: st.metric("Techniques in DB", len(techniques_df))
        with am2: st.metric("Observed in Threats", len(obs_tech))
        unique_tactics = set(
            t.strip()
            for row in obs_tech["tactic"].dropna()
            for t in str(row).split(",") if t.strip()
        )
        with am3: st.metric("Tactics Covered", len(unique_tactics))
        with am4: st.metric("Mitigations Available", len(mitigations_df))

        st.divider()

        # ── ATT&CK heatmap ────────────────────────────────────────────────────
        if not obs_tech.empty:
            st.markdown("#### Technique Heat Map by Tactic")
            rows = []
            for _, row in obs_tech.iterrows():
                tid   = row["technique_id"]
                count = ttp_usage.get(tid, {}).get("count", 0)
                for tac in str(row.get("tactic") or "Unknown").split(","):
                    rows.append({"Technique": tid, "Tactic": tac.strip(), "Count": count,
                                 "Name": row.get("name", tid)})
            hdf = pd.DataFrame(rows)
            if not hdf.empty:
                fig_h = px.density_heatmap(
                    hdf, x="Tactic", y="Count", z="Count",
                    histfunc="sum", color_continuous_scale="Blues",
                    labels={"Count": "Threat Count"},
                )
                fig_h.update_layout(**_PLOTLY_DARK, height=300)
                st.plotly_chart(fig_h, use_container_width=True)

        # ── Observed techniques ────────────────────────────────────────────────
        st.markdown("#### Observed Techniques")
        if obs_tech.empty:
            st.info("TTPs populate as the AI enrichment runs. Come back after a few collector cycles.")
        else:
            obs_tech["threat_count"] = obs_tech["technique_id"].map(
                lambda t: ttp_usage.get(t, {}).get("count", 0)
            )
            obs_tech["actors"] = obs_tech["technique_id"].map(
                lambda t: ", ".join(sorted(ttp_usage.get(t, {}).get("actors", set())))
            )
            obs_tech = obs_tech.sort_values("threat_count", ascending=False)

            for _, tech in obs_tech.iterrows():
                tid = tech["technique_id"]
                with st.expander(
                    f"**{tid}** — {tech['name']}  |  "
                    f"Tactic: {tech.get('tactic','?')}  |  "
                    f"Seen {tech['threat_count']}×"
                ):
                    cl, cr = st.columns([2, 3])
                    with cl:
                        st.markdown(f"**Actors:** {tech['actors'] or 'Unknown'}")
                        desc = str(tech.get("description") or "")
                        st.markdown(f"**Description:** {desc[:500]}{'…' if len(desc) > 500 else ''}")
                        st.markdown(
                            f"[↗ MITRE ATT&CK](https://attack.mitre.org/techniques/{tid.replace('.','/')})"
                        )
                    with cr:
                        tm = mitigations_df[mitigations_df["technique_id"] == tid]
                        if tm.empty:
                            st.info("No specific mitigations mapped.")
                        else:
                            st.markdown(f"**{len(tm)} Mitigation(s):**")
                            for _, mit in tm.iterrows():
                                with st.container():
                                    st.markdown(
                                        f'<i class="bi bi-shield-check icon-ok bi-sm"></i> <span class="ttp-tag">{mit["mitigation_id"]}</span> '
                                        f'**{mit["name"]}**',
                                        unsafe_allow_html=True,
                                    )
                                    md = str(mit.get("description") or "")
                                    st.caption(md[:350] + ("…" if len(md) > 350 else ""))

        st.divider()

        # ── Full remediation lookup ────────────────────────────────────────────
        st.markdown("#### Full Remediation Lookup")
        options = [f"{r['technique_id']} — {r['name']}" for _, r in techniques_df.iterrows()]
        selected = st.selectbox("Select any technique", ["— select —"] + options, key="atk_sel")
        if selected and selected != "— select —":
            sel_id = selected.split(" — ")[0]
            t = techniques_df[techniques_df["technique_id"] == sel_id].iloc[0]
            st.markdown(f"### {t['technique_id']} — {t['name']}")
            st.markdown(f"**Tactic(s):** {t.get('tactic','?')}")
            st.markdown(str(t.get("description") or ""))
            st.markdown(f"[↗ MITRE Reference](https://attack.mitre.org/techniques/{sel_id.replace('.','/')})")
            mits = mitigations_df[mitigations_df["technique_id"] == sel_id]
            if mits.empty:
                st.info("No mitigations mapped for this technique.")
            else:
                st.markdown(f"#### {len(mits)} Recommended Mitigation(s)")
                for _, m in mits.iterrows():
                    with st.expander(f"◈ {m['mitigation_id']}  {m['name']}"):
                        st.markdown(str(m.get("description") or ""))
                        st.markdown(
                            f"[↗ View on MITRE](https://attack.mitre.org/mitigations/{m['mitigation_id']})"
                        )


# ══════════════════════════════════════════════════════════════════════════════
# AI ANALYST
# ══════════════════════════════════════════════════════════════════════════════
with tab_analyst:
    st.markdown('<p class="section-label"><i class="bi bi-cpu-fill bi-sm icon-accent"></i>&nbsp; AI Threat Intelligence Analyst</p>', unsafe_allow_html=True)

    # ── Backend status (live health checks) ───────────────────────────────────
    ollama_ok   = _ollama_up()
    lmstudio_ok = _lmstudio_up()

    chain = []
    # Show exactly what was loaded from the env so the user can verify
    model_list = ", ".join(_LOCAL_MODELS)
    ok_icon  = '<i class="bi bi-circle-fill icon-ok"  style="font-size:0.55rem"></i>'
    off_icon = '<i class="bi bi-circle-fill icon-muted" style="font-size:0.55rem"></i>'
    cld_icon = '<i class="bi bi-cloud-fill icon-accent" style="font-size:0.7rem"></i>'
    chain.append(
        (f"{ok_icon} Ollama [{model_list}]" if ollama_ok else f"{off_icon} Ollama offline [{model_list}]")
    )
    if _LMSTUDIO_URL:
        chain.append((ok_icon if lmstudio_ok else off_icon) + f" LM Studio [{_LMSTUDIO_MDL}]")
    if _CLAUDE_KEY:
        chain.append(f"{cld_icon} Claude (fallback)")
    if _GEMINI_KEY:
        chain.append(f"{cld_icon} Gemini (fallback)")

    st.markdown(
        '<div style="background:rgba(56,189,248,0.05);border:1px solid rgba(56,189,248,0.15);'
        'border-radius:8px;padding:8px 14px;font-size:0.78rem;color:#4a6080;">'
        '<i class="bi bi-cpu bi-sm icon-accent"></i>&nbsp; <strong style="color:#7aadcf">AI chain (local first):</strong>&nbsp; '
        + '  <span style="color:#1e3a5f">›</span>  '.join(chain) + '</div>',
        unsafe_allow_html=True,
    )

    any_backend = ollama_ok or lmstudio_ok or bool(_CLAUDE_KEY) or bool(_GEMINI_KEY)
    if not any_backend:
        st.error(
            "**No AI backend reachable.** "
            "Add `OLLAMA_MODELS=modelname` to `/opt/threat-intel-platform/.env` "
            "and run `sudo docker compose up -d` on the server, "
            "or set `CLAUDE_API_KEY` / `GEMINI_API_KEY` as a cloud fallback."
        )

    if "analyst_messages" not in st.session_state:
        st.session_state.analyst_messages = []

    _ctx = _build_context(reports, iocs, cves, techniques_df)

    # ── Starter question buttons (shown only on empty conversation) ───────────
    if not st.session_state.analyst_messages:
        st.markdown('<span style="font-size:0.78rem;font-weight:700;color:#3d5a80;text-transform:uppercase;letter-spacing:0.1em"><i class="bi bi-stars bi-sm icon-accent"></i>&nbsp; Suggested questions</span>', unsafe_allow_html=True)
        starters = [
            "What are the most active threat actors right now?",
            "Which ATT&CK tactics are most commonly observed?",
            "List the critical CVEs and recommended patches.",
            "What malware families appear most frequently?",
            "Which industries are being targeted the most?",
            "What TTPs should I prioritise for detection rules?",
            "Give me an executive summary of current threats.",
        ]
        cols = st.columns(2)
        for i, q in enumerate(starters):
            if cols[i % 2].button(q, key=f"starter_{i}", use_container_width=True):
                # Store the question; the response logic below will pick it up
                st.session_state.analyst_messages.append({"role": "user", "content": q})
                st.rerun()

    # ── Render conversation history ────────────────────────────────────────────
    for msg in st.session_state.analyst_messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # ── Generate a response if the last message is from the user ─────────────
    # This handles BOTH chat_input submissions AND starter button clicks
    # (starter buttons rerun the page with a pending user message but no reply).
    needs_reply = (
        bool(st.session_state.analyst_messages)
        and st.session_state.analyst_messages[-1]["role"] == "user"
    )
    if needs_reply and any_backend:
        system_content = _ANALYST_SYSTEM.format(context=_ctx)
        llm_messages = [{"role": "system", "content": system_content}]
        for m in st.session_state.analyst_messages[-10:]:
            llm_messages.append({"role": m["role"], "content": m["content"]})

        with st.chat_message("assistant"):
            with st.spinner("Analysing threat data…"):
                reply = analyst_reply(llm_messages)
            st.markdown(reply)

        st.session_state.analyst_messages.append({"role": "assistant", "content": reply})

    # ── Chat input for follow-up questions ────────────────────────────────────
    if user_input := st.chat_input("Ask anything about your threat intelligence…"):
        st.session_state.analyst_messages.append({"role": "user", "content": user_input})
        st.rerun()   # rerun so the message renders, then needs_reply fires above

    # ── Clear button ──────────────────────────────────────────────────────────
    if st.session_state.analyst_messages:
        if st.button("✕  Clear conversation", key="clear_analyst"):
            st.session_state.analyst_messages = []
            st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# FEED HEALTH
# ══════════════════════════════════════════════════════════════════════════════
with tab_health:
    st.markdown('<p class="section-label"><i class="bi bi-broadcast bi-sm icon-ok"></i>&nbsp; Feed Health &amp; Status</p>', unsafe_allow_html=True)

    if feed_status.empty:
        st.info("No feed status yet — collector may still be starting.")
    else:
        # Summary chart
        status_counts = feed_status["status"].value_counts().reset_index()
        status_counts.columns = ["Status", "Count"]
        color_map_s = {"ok": "#06d6a0", "error": "#ff4d6d",
                       "running": "#38bdf8", "pending": "#ffd166"}
        fig_s = px.bar(
            status_counts, x="Status", y="Count",
            color="Status", color_discrete_map=color_map_s,
        )
        fig_s.update_layout(**_PLOTLY_DARK, height=200, showlegend=False)
        st.plotly_chart(fig_s, use_container_width=True)

        st.divider()
        for _, row in feed_status.iterrows():
            status   = str(row.get("status", "pending"))
            last_run = (
                row["last_run"].strftime("%Y-%m-%d %H:%M:%S")
                if pd.notna(row.get("last_run")) and hasattr(row["last_run"], "strftime")
                else "Never"
            )
            last_ok = (
                row["last_success"].strftime("%Y-%m-%d %H:%M:%S")
                if pd.notna(row.get("last_success")) and hasattr(row["last_success"], "strftime")
                else "—"
            )
            total    = int(row.get("total_records") or 0)
            recent   = int(row.get("records_fetched") or 0)
            err      = str(row.get("error_message") or "")
            err_html = f'<div class="feed-error"><i class="bi bi-exclamation-triangle-fill"></i> {err[:120]}</div>' if err else ""
            _si = {"ok": "check-circle-fill", "error": "x-circle-fill",
                   "running": "arrow-repeat", "pending": "clock"}.get(status, "circle")
            st.markdown(f"""
<div class="feed-card {status}">
  <i class="bi bi-{_si} status-icon {status}"></i>
  <div class="feed-name">{str(row['feed_name']).upper()}</div>
  <div class="feed-meta">
    Last run: {last_run} &nbsp;·&nbsp; Last success: {last_ok}
    {err_html}
  </div>
  <div class="feed-count">+{recent:,} / {total:,}</div>
</div>""", unsafe_allow_html=True)
