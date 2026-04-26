import json
import os
import re
import requests as _requests
from collections import Counter
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
    initial_sidebar_state="expanded",
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
    display: flex; align-items: baseline; gap: 0;
    font-size: 1.65rem; font-weight: 900; letter-spacing: 0.06em;
    text-transform: uppercase; line-height: 1;
}
.logo-van {
    color: #ffffff;
    font-weight: 900;
    text-shadow:
        0 0  6px #38bdf8,
        0 0 14px #38bdf8,
        0 0 28px rgba(56,189,248,0.7),
        0 0 55px rgba(56,189,248,0.35),
        0 0 90px rgba(56,189,248,0.15);
}
/* CRITICAL: filter and background-clip:text CANNOT be on the same element —
   filter creates a new compositing layer over the transparent fill, making
   the text invisible. Split into a glow wrapper + inner gradient span. */
.logo-telligence-wrap {
    display: inline;
    filter: drop-shadow(0 0 7px rgba(167,139,250,0.9))
            drop-shadow(0 0 18px rgba(192,132,252,0.45));
}
.logo-telligence {
    font-weight: 900;
    background: linear-gradient(100deg, #60d4ff 0%, #a78bfa 50%, #e879f9 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}
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

/* ── Threat ticker ──────────────────────────────────────────────────────── */
.ticker-wrap {
    width: 100%; overflow: hidden;
    background: linear-gradient(90deg, #060c1a 0%, #0a0f1e 50%, #060c1a 100%);
    border-top: 1px solid #0f2040; border-bottom: 1px solid #0f2040;
    padding: 5px 0; margin-bottom: 12px;
}
.ticker-track {
    display: inline-flex; white-space: nowrap;
    animation: ticker-scroll 90s linear infinite;
}
.ticker-track:hover { animation-play-state: paused; }
@keyframes ticker-scroll {
    0%   { transform: translateX(0); }
    100% { transform: translateX(-50%); }
}
.ticker-item {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 0 28px; font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem; color: #3d5a80;
}
.ticker-item .ti-type  { color: #38bdf8; font-weight: 700; }
.ticker-item .ti-val   { color: #7dd3fc; }
.ticker-item .ti-sep   { color: #1e3a5f; margin: 0 8px; }
.ticker-item.critical .ti-val { color: #ff4d6d; }
.ticker-item.high     .ti-val { color: #ff8c42; }

/* ── Threat feed cards ─────────────────────────────────────────────────── */
.tf-card {
    background: linear-gradient(145deg, #0c1628 0%, #080e1c 100%);
    border: 1px solid #142038; border-left: 4px solid #1e4080;
    border-radius: 10px; padding: 12px 18px; margin-bottom: 4px;
    display: flex; align-items: center; gap: 14px;
    transition: border-color .15s, box-shadow .15s;
    cursor: pointer;
}
.tf-card:hover { border-left-color: #38bdf8; box-shadow: 0 4px 24px rgba(56,189,248,0.08); }
.tf-card.sev-critical { border-left-color: #ff4d6d; }
.tf-card.sev-high     { border-left-color: #ff8c42; }
.tf-card.sev-medium   { border-left-color: #ffd166; }
.tf-card-left  { display:flex; align-items:center; gap:8px; min-width:180px; }
.tf-card-actor { flex:1; font-weight:600; font-size:0.84rem; color:#c8d8f0; }
.tf-card-right { display:flex; align-items:center; gap:10px; }
.tf-conf-bar   { width:60px; height:5px; background:#0f2040; border-radius:3px; overflow:hidden; }
.tf-conf-fill  { height:100%; background:linear-gradient(90deg,#1e4080,#38bdf8); border-radius:3px; transition:width .3s; }
.tf-conf-val   { font-family:'JetBrains Mono',monospace; font-size:0.74rem; color:#38bdf8; min-width:32px; }
.tf-ts         { font-family:'JetBrains Mono',monospace; font-size:0.7rem; color:#3d5a80; }

/* ── Glassmorphism metric cards ─────────────────────────────────────────── */
div[data-testid="metric-container"] {
    backdrop-filter: blur(12px) !important;
    background: linear-gradient(145deg,rgba(14,26,56,0.85),rgba(8,14,28,0.9)) !important;
    box-shadow: 0 4px 20px rgba(0,0,0,0.5), 0 0 0 1px rgba(56,189,248,0.04),
                inset 0 1px 0 rgba(255,255,255,0.04) !important;
}
div[data-testid="metric-container"]:hover {
    box-shadow: 0 6px 32px rgba(56,189,248,0.12), 0 0 0 1px rgba(56,189,248,0.15),
                inset 0 1px 0 rgba(255,255,255,0.06) !important;
    transform: translateY(-1px);
    transition: all 0.2s ease;
}

/* ── Critical alert pulse ──────────────────────────────────────────────── */
.critical-pulse {
    animation: critical-glow 2s ease-in-out infinite;
}
@keyframes critical-glow {
    0%, 100% { box-shadow: 0 0 8px rgba(255,77,109,0.4), inset 0 0 8px rgba(255,77,109,0.05); }
    50%       { box-shadow: 0 0 24px rgba(255,77,109,0.7), inset 0 0 12px rgba(255,77,109,0.1); }
}

/* ── Neon glow on open-alerts metric ───────────────────────────────────── */
.alert-glow > div > div {
    color: #ff4d6d !important;
    text-shadow: 0 0 12px rgba(255,77,109,0.6), 0 0 24px rgba(255,77,109,0.3);
}

/* ── Chart container styling ────────────────────────────────────────────── */
div[data-testid="stPlotlyChart"] > div {
    border-radius: 10px;
    border: 1px solid #0f2040;
    overflow: hidden;
}

/* ── Section label enhancement ─────────────────────────────────────────── */
.section-label {
    background: linear-gradient(90deg, rgba(56,189,248,0.06) 0%, transparent 100%);
    border-left: 3px solid #38bdf8 !important;
    padding-left: 10px !important;
    border-radius: 0 4px 4px 0;
}

/* ── Stat glow card ────────────────────────────────────────────────────── */
.stat-glow-card {
    background: linear-gradient(145deg, #0c1628, #080e1c);
    border: 1px solid #142038; border-radius: 10px;
    padding: 14px 18px; margin-bottom: 8px;
    position: relative; overflow: hidden;
}
.stat-glow-card::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 1px;
    background: linear-gradient(90deg, transparent, #38bdf8, transparent);
    opacity: 0.5;
}
.stat-glow-card .sgc-label {
    font-size: 0.65rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.12em; color: #3d5a80; margin-bottom: 4px;
}
.stat-glow-card .sgc-value {
    font-size: 1.6rem; font-weight: 800; font-family: 'JetBrains Mono', monospace;
    color: #38bdf8; line-height: 1;
    text-shadow: 0 0 20px rgba(56,189,248,0.4);
}
.stat-glow-card .sgc-sub {
    font-size: 0.68rem; color: #3d5a80; margin-top: 3px;
}

/* ── Risk gauge styling ─────────────────────────────────────────────────── */
.risk-gauge-wrap {
    background: linear-gradient(145deg,#0a1020,#060c1a);
    border: 1px solid #142038; border-radius: 12px;
    padding: 8px; overflow: hidden;
}

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

/* ── Dark Web Monitor ───────────────────────────────────────────────────── */
.dw-header {
    background: linear-gradient(135deg, #0a0614 0%, #100820 60%, #0a0614 100%);
    border: 1px solid #2d1458; border-radius: 10px;
    padding: 16px 20px; margin-bottom: 16px;
    display: flex; align-items: center; gap: 14px;
}
.dw-tor-badge {
    display: inline-flex; align-items: center; gap: 6px;
    background: rgba(149,76,233,0.1); border: 1px solid rgba(149,76,233,0.35);
    color: #b48ef5; padding: 3px 12px; border-radius: 20px;
    font-size: 0.7rem; font-weight: 700; letter-spacing: 0.1em;
}
.dw-tor-dot {
    width: 7px; height: 7px; background: #954ce9; border-radius: 50%;
    animation: pulse-purple 2s ease-in-out infinite;
}
@keyframes pulse-purple {
    0%,100% { opacity:1; box-shadow: 0 0 0 0 rgba(149,76,233,0.7); }
    50%      { opacity:0.6; box-shadow: 0 0 0 5px rgba(149,76,233,0); }
}
.dw-mention-card {
    background: linear-gradient(145deg, #0e0a1c, #0a0614);
    border: 1px solid #1e1040; border-left: 3px solid #2d1458;
    border-radius: 8px; padding: 14px 18px; margin-bottom: 6px;
    transition: border-color .15s, box-shadow .15s;
}
.dw-mention-card:hover {
    border-color: #3d1a80 !important;
    border-left-color: #954ce9 !important;
    box-shadow: 0 4px 20px rgba(149,76,233,0.08);
}
.dw-mention-card.critical { border-left-color: #ff4d6d !important; }
.dw-mention-card.high     { border-left-color: #ff8c42 !important; }
.dw-mention-card.medium   { border-left-color: #ffd166 !important; }
.dw-mention-card.low      { border-left-color: #06d6a0 !important; }
.dw-title { font-size:0.88rem; font-weight:600; color:#d0baff; margin-bottom:4px; }
.dw-meta  { font-size:0.72rem; color:#4a3a6a; font-family:'JetBrains Mono',monospace; }
.dw-snippet { font-size:0.78rem; color:#7060a0; margin-top:6px; font-style:italic; }
.dw-actor { font-size:0.72rem; color:#b48ef5; font-family:'JetBrains Mono',monospace; }
.kw-pill {
    display:inline-block; background:rgba(149,76,233,0.12);
    border:1px solid rgba(149,76,233,0.3); color:#b48ef5;
    padding:3px 10px; border-radius:20px; font-size:0.72rem;
    font-family:'JetBrains Mono',monospace; margin:2px;
}

/* ── Watchlist & Alerts ─────────────────────────────────────────────────── */
.watchlist-card {
    background: linear-gradient(145deg, #0c1628, #080e1c);
    border: 1px solid #142038; border-left: 3px solid #1e4080;
    border-radius: 8px; padding: 12px 16px; margin-bottom: 5px;
    display: flex; align-items: center; gap: 14px;
    transition: border-color .15s, box-shadow .15s;
}
.watchlist-card:hover { border-left-color: #38bdf8; box-shadow: 0 4px 16px rgba(56,189,248,0.07); }
.watchlist-card.domain { border-left-color: #38bdf8; }
.watchlist-card.ip     { border-left-color: #06d6a0; }
.watchlist-card.cidr   { border-left-color: #ffd166; }
.watchlist-card.email_domain { border-left-color: #b48ef5; }
.watchlist-card.keyword      { border-left-color: #ff8c42; }
.wl-type  { font-family:'JetBrains Mono',monospace; font-size:0.68rem; font-weight:700;
            text-transform:uppercase; color:#3d5a80; min-width:90px; }
.wl-value { font-family:'JetBrains Mono',monospace; font-size:0.83rem; color:#7dd3fc; flex:1; }
.wl-label { font-size:0.72rem; color:#5a7fa8; }
.alert-card {
    background: linear-gradient(145deg, #0e1a0c, #080e0c);
    border: 1px solid #1a3020; border-left: 3px solid #06d6a0;
    border-radius: 8px; padding: 13px 17px; margin-bottom: 6px;
}
.alert-card.critical { border-left-color: #ff4d6d !important; background: linear-gradient(145deg,#1a0a10,#0e0608) !important; }
.alert-card.high     { border-left-color: #ff8c42 !important; }
.alert-card.medium   { border-left-color: #ffd166 !important; }
.alert-title { font-size:0.85rem; font-weight:600; color:#c8e8c0; margin-bottom:4px; }
.alert-meta  { font-size:0.72rem; color:#3d5a4a; font-family:'JetBrains Mono',monospace; }
.alert-ctx   { font-size:0.78rem; color:#5a7a5a; margin-top:5px; font-style:italic; }
/* ── Campaign cards ─────────────────────────────────────────────────────── */
.campaign-card {
    background: linear-gradient(145deg, #0d1220, #080e1c);
    border: 1px solid #1a2840; border-left: 4px solid #60a5fa;
    border-radius: 10px; padding: 16px 20px; margin-bottom: 8px;
    transition: border-color .15s, box-shadow .15s;
}
.campaign-card:hover { border-left-color: #93c5fd; box-shadow: 0 4px 20px rgba(96,165,250,0.08); }
.campaign-name { font-size:1rem; font-weight:700; color:#bfdbfe; margin-bottom:4px; }
.campaign-meta { font-size:0.72rem; color:#3d5a80; font-family:'JetBrains Mono',monospace; }
.campaign-desc { font-size:0.82rem; color:#7a9cc0; margin-top:7px; }
/* ── Enrichment inline badges ───────────────────────────────────────────── */
.enrich-vt   { background:rgba(255,77,109,0.1); color:#ff8080; border:1px solid rgba(255,77,109,0.3);
    padding:2px 8px; border-radius:20px; font-size:0.66rem; font-weight:700;
    font-family:'JetBrains Mono',monospace; margin-right:4px; }
.enrich-gn   { background:rgba(6,214,160,0.1); color:#06d6a0; border:1px solid rgba(6,214,160,0.3);
    padding:2px 8px; border-radius:20px; font-size:0.66rem; font-weight:700;
    font-family:'JetBrains Mono',monospace; margin-right:4px; }
.enrich-sh   { background:rgba(180,142,245,0.1); color:#b48ef5; border:1px solid rgba(180,142,245,0.3);
    padding:2px 8px; border-radius:20px; font-size:0.66rem; font-weight:700;
    font-family:'JetBrains Mono',monospace; margin-right:4px; }
/* ── Admin settings panel ───────────────────────────────────────────────── */
.admin-section {
    background: linear-gradient(145deg, #0c1628, #080e1c);
    border: 1px solid #142038; border-radius: 10px;
    padding: 20px 24px; margin-bottom: 18px;
}
.admin-section-title {
    font-size: 0.8rem; font-weight: 800; text-transform: uppercase;
    letter-spacing: 0.12em; color: #38bdf8;
    display: flex; align-items: center; gap: 8px;
    padding-bottom: 12px; margin-bottom: 16px;
    border-bottom: 1px solid #0f2040;
}
.admin-save-success {
    background: rgba(6,214,160,0.08); border: 1px solid rgba(6,214,160,0.3);
    border-radius: 8px; padding: 10px 16px;
    color: #06d6a0; font-size: 0.82rem; font-weight: 600;
    display: flex; align-items: center; gap: 8px;
}
.admin-hint {
    font-size: 0.72rem; color: #3d5a80; margin-top: 4px;
    font-family: 'JetBrains Mono', monospace;
}

/* ── Sidebar navigation ─────────────────────────────────────────────────── */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #060c1a 0%, #080e1c 100%) !important;
    border-right: 1px solid #0f2040 !important;
    min-width: 190px !important;
    max-width: 210px !important;
}
section[data-testid="stSidebar"] > div:first-child { padding-top: 0.5rem; }
/* Sidebar nav buttons — secondary = plain text link style */
section[data-testid="stSidebar"] .stButton > button[kind="secondary"] {
    background: transparent !important;
    border: none !important;
    border-radius: 6px !important;
    color: #7a9cc0 !important;
    font-size: 0.82rem !important;
    font-weight: 500 !important;
    text-align: left !important;
    padding: 5px 10px !important;
    margin: 1px 0 !important;
    box-shadow: none !important;
}
section[data-testid="stSidebar"] .stButton > button[kind="secondary"]:hover {
    background: rgba(56,189,248,0.07) !important;
    color: #c8d8f0 !important;
    border: none !important;
}
/* Sidebar nav buttons — primary = active page highlight */
section[data-testid="stSidebar"] .stButton > button[kind="primary"] {
    background: rgba(56,189,248,0.12) !important;
    border: 1px solid rgba(56,189,248,0.3) !important;
    border-radius: 6px !important;
    color: #38bdf8 !important;
    font-size: 0.82rem !important;
    font-weight: 700 !important;
    text-align: left !important;
    padding: 5px 10px !important;
    margin: 1px 0 !important;
    box-shadow: 0 0 12px rgba(56,189,248,0.08) !important;
}
/* Ticker quick-access table */
.ticker-click-hint {
    font-size: 0.65rem; color: #2a4060; text-align: center;
    letter-spacing: 0.08em; text-transform: uppercase; padding: 2px 0 4px;
}
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


_DEPRECATED_FEEDS = ("urlhaus", "threatfox")

@st.cache_data(ttl=15)
def load_data():
    engine = get_engine()
    try:
        # Exclude permanently removed feeds
        _excl = ",".join("'" + f + "'" for f in _DEPRECATED_FEEDS)
        reports = pd.read_sql(
            "SELECT * FROM threat_reports "
            "WHERE source_feed NOT IN (" + _excl + ") "
            "ORDER BY created_at DESC LIMIT 500",
            engine,
        )
        # Load all IOCs except from permanently removed feeds
        iocs = pd.read_sql(
            "SELECT i.* FROM iocs i "
            "JOIN threat_reports tr ON i.report_id = tr.id "
            "WHERE tr.source_feed NOT IN (" + _excl + ") "
            "ORDER BY i.id DESC LIMIT 5000",
            engine,
        )
        cves = pd.read_sql(
            "SELECT * FROM cve_records ORDER BY created_at DESC LIMIT 500", engine
        )
        feed_status = pd.read_sql(
            "SELECT * FROM feed_status "
            "WHERE feed_name NOT IN (" + _excl + ") "
            "ORDER BY feed_name",
            engine,
        )
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


@st.cache_data(ttl=30)
def load_darkweb_data():
    """Load dark web mentions — metadata only, no breach content."""
    engine = get_engine()
    try:
        df = pd.read_sql(
            """SELECT id, source_name, source_url, keyword_matched, title,
                      snippet, actor_handle, record_estimate, data_types,
                      severity, ai_summary, first_seen, last_seen
               FROM dark_web_mentions
               ORDER BY first_seen DESC LIMIT 500""",
            engine,
        )
        return df
    except Exception:
        # Table may not exist yet if collector hasn't run
        return pd.DataFrame()


@st.cache_data(ttl=20)
def load_watchlist_data():
    """Load watched assets and recent hits."""
    engine = get_engine()
    try:
        assets = pd.read_sql(
            "SELECT * FROM watched_assets ORDER BY created_at DESC", engine
        )
        hits = pd.read_sql(
            """SELECT wh.id, wh.watched_asset_id, wh.hit_type, wh.severity,
                      wh.source_feed, wh.matched_value, wh.context,
                      wh.alerted, wh.found_at,
                      wa.value  AS asset_value,
                      wa.asset_type,
                      wa.label
               FROM watchlist_hits wh
               JOIN watched_assets wa ON wh.watched_asset_id = wa.id
               ORDER BY wh.found_at DESC LIMIT 500""",
            engine,
        )
        return assets, hits
    except Exception:
        return pd.DataFrame(), pd.DataFrame()


@st.cache_data(ttl=20)
def load_campaigns_data():
    """Load campaigns."""
    engine = get_engine()
    try:
        return pd.read_sql(
            "SELECT * FROM campaigns ORDER BY first_seen DESC LIMIT 200", engine
        )
    except Exception:
        return pd.DataFrame()


@st.cache_data(ttl=30)
def load_enrichment_map(ioc_values: tuple) -> dict:
    """Return a dict of ioc_value → enrichment row for the given values."""
    if not ioc_values:
        return {}
    engine = get_engine()
    try:
        from sqlalchemy import text
        placeholders = ", ".join(f":v{i}" for i in range(len(ioc_values)))
        params = {f"v{i}": v for i, v in enumerate(ioc_values)}
        with engine.connect() as conn:
            rows = conn.execute(
                text(f"SELECT * FROM ioc_enrichments WHERE ioc_value IN ({placeholders})"),
                params,
            ).fetchall()
        return {r._mapping["ioc_value"]: dict(r._mapping) for r in rows}
    except Exception:
        return {}


@st.cache_data(ttl=120)
def load_feed_history() -> pd.DataFrame:
    """Load per-feed daily record counts for sparkline rendering."""
    engine = get_engine()
    try:
        return pd.read_sql(
            """SELECT source_feed, DATE_TRUNC('day', created_at) AS day, COUNT(*) AS cnt
               FROM threat_reports
               WHERE created_at >= NOW() - INTERVAL '7 days'
               GROUP BY source_feed, day
               ORDER BY source_feed, day""",
            engine,
        )
    except Exception:
        return pd.DataFrame()


@st.cache_data(ttl=3600)
def geolocate_ips(ip_tuple: tuple) -> tuple:
    """Batch geolocate IPs.  Returns (DataFrame, error_string).

    Accepts plain IPs, ip:port strings, and IPv6 [addr]:port notation.
    Private/loopback addresses are silently skipped.
    """
    import re as _re
    _IP_RE = _re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

    def _extract_ip(raw: str) -> str:
        raw = raw.strip()
        # [::1]:port  IPv6
        if raw.startswith("["):
            return raw[1:raw.find("]")]
        # ip:port
        if _IP_RE.match(raw.rsplit(":", 1)[0]):
            return raw.rsplit(":", 1)[0]
        return raw

    _PRIVATE = ("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                 "172.2", "127.", "0.", "169.254.", "::1", "fc", "fd")

    seen: set = set()
    public: list = []
    for raw in ip_tuple:
        ip = _extract_ip(str(raw))
        if not _IP_RE.match(ip):
            continue
        if ip in seen or ip.startswith(_PRIVATE):
            continue
        seen.add(ip)
        public.append(ip)
        if len(public) >= 80:
            break

    if not public:
        return pd.DataFrame(), "No public IP IOCs collected yet."
    last_err = "unknown error"
    for url in ["http://ip-api.com/batch"]:
        try:
            payload = [{"query": ip, "fields": "query,country,countryCode,lat,lon,isp,org,status"}
                       for ip in public]
            resp = _requests.post(url, json=payload, timeout=12,
                                  headers={"Content-Type": "application/json"})
            resp.raise_for_status()
            rows = [r for r in resp.json()
                    if r.get("status") == "success" and r.get("lat")]
            if rows:
                return pd.DataFrame(rows), ""
            last_err = "All IPs returned non-success status (private ranges or unknown)"
        except Exception as exc:
            last_err = str(exc)
    return pd.DataFrame(), last_err


@st.cache_data(ttl=1800)
def extract_ips_from_iocs(ioc_rows: tuple) -> tuple:
    """Extract candidate IPs from url/ip:port/ip IOC values for geo mapping.
    ioc_rows is a tuple of (ioc_type, value) tuples.
    Returns a tuple of unique IP strings.
    """
    import re as _re
    from urllib.parse import urlparse as _urlparse
    _IP_RE = _re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

    ips: set = set()
    for ioc_type, value in ioc_rows:
        t = str(ioc_type).lower()
        v = str(value).strip()
        if t in ("ip", "ipv4"):
            if _IP_RE.match(v):
                ips.add(v)
        elif t == "ip:port" and ":" in v:
            candidate = v.rsplit(":", 1)[0].strip("[]")
            if _IP_RE.match(candidate):
                ips.add(candidate)
        elif t in ("url",):
            try:
                host = _urlparse(v).hostname or ""
                if _IP_RE.match(host):
                    ips.add(host)
            except Exception:
                pass
    return tuple(ips)


def _build_network_graph(reports_df, iocs_df=None):
    """Threat relationship network: feeds → actors → TTPs → industries.
    Always renders — falls back gracefully when enrichment is sparse."""
    import math

    node_x, node_y, node_labels, node_colors, node_sizes, node_hover = [], [], [], [], [], []
    edge_x, edge_y = [], []
    positions: dict = {}

    def _place(key, label, color, size, hover, ring_r, idx, total):
        if key in positions:
            return
        ang = 2 * math.pi * idx / max(total, 1)
        x, y = math.cos(ang) * ring_r, math.sin(ang) * ring_r
        positions[key] = (x, y)
        node_x.append(x); node_y.append(y); node_labels.append(label)
        node_colors.append(color); node_sizes.append(size); node_hover.append(hover)

    def _edge(a, b):
        if a in positions and b in positions:
            ax, ay = positions[a]; bx, by = positions[b]
            edge_x.extend([ax, bx, None]); edge_y.extend([ay, by, None])

    # Ring 1 – source feeds (always present, r=2.5)
    feeds = reports_df["source_feed"].dropna().unique().tolist()
    for i, f in enumerate(feeds[:8]):
        _place(f"feed:{f}", f.upper(), "#38bdf8", 14,
               f"Feed: {f}", 2.5, i, len(feeds[:8]))

    # Ring 2 – known actors (r=1.0, inner cluster)
    actor_series = (reports_df[reports_df["threat_actor"].notna()
                               & (reports_df["threat_actor"] != "Unknown")]
                    .groupby("threat_actor").size().nlargest(6))
    for i, (actor, cnt) in enumerate(actor_series.items()):
        ak = "actor:" + actor
        _place(ak, actor, "#ff4d6d", 20,
               f"<b>Actor:</b> {actor}<br>{cnt} reports", 1.0, i, len(actor_series))
        actor_feeds = reports_df[reports_df["threat_actor"] == actor]["source_feed"].dropna().unique()
        for feed in actor_feeds[:2]:
            _edge(ak, f"feed:{feed}")

    # Ring 3 – top TTPs (r=4.5)
    all_ttps: dict = {}
    actor_ttp_map: dict = {}
    for _, r in reports_df.iterrows():
        raw = r.get("ttps") or []
        if isinstance(raw, str):
            try: raw = json.loads(raw)
            except Exception: raw = []
        actor = str(r.get("threat_actor") or "Unknown")
        for t in (raw or []):
            all_ttps[t] = all_ttps.get(t, 0) + 1
            actor_ttp_map.setdefault(actor, set()).add(t)
    top_ttps = sorted(all_ttps.items(), key=lambda kv: -kv[1])[:10]
    for i, (ttp, cnt) in enumerate(top_ttps):
        tk = "ttp:" + ttp
        _place(tk, ttp, "#b48ef5", 11,
               f"<b>TTP:</b> {ttp}<br>{cnt} reports", 4.5, i, len(top_ttps))
        # connect to actors that use this TTP
        for actor, actor_ttps in actor_ttp_map.items():
            if ttp in actor_ttps and "actor:" + actor in positions:
                _edge(tk, "actor:" + actor)
                break
        # connect to feed if no actor matched
        if not any(positions.get("actor:" + a) for a in actor_ttp_map if ttp in actor_ttp_map[a]):
            if feeds:
                _edge(tk, f"feed:{feeds[0]}")

    # Ring 4 – target industries (r=6.5)
    ind_series = (reports_df[reports_df["target_industry"].notna()
                              & (reports_df["target_industry"] != "Unknown")]
                  .groupby("target_industry").size().nlargest(5))
    for i, (ind, cnt) in enumerate(ind_series.items()):
        ik = "ind:" + ind
        _place(ik, ind[:18], "#06d6a0", 10,
               f"<b>Industry:</b> {ind}<br>{cnt} reports", 6.5, i, len(ind_series))
        ind_actors = reports_df[reports_df["target_industry"] == ind]["threat_actor"].dropna().unique()
        for a in ind_actors[:1]:
            _edge(ik, "actor:" + a)
        if ik not in [k for k in positions if positions[k]]:
            pass  # already placed

    # Fallback annotation when there is truly nothing
    if not node_x:
        fig = go.Figure()
        fig.add_annotation(text="Relationship data populates as AI enrichment runs",
                           xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False,
                           font=dict(color="#3d5a80", size=13))
        fig.update_layout(paper_bgcolor="#070b14", plot_bgcolor="#070b14", height=300,
                          margin=dict(l=0, r=0, t=0, b=0),
                          xaxis=dict(visible=False), yaxis=dict(visible=False))
        return fig

    legend_items = [
        ("●", "#38bdf8", "Feeds"),
        ("●", "#ff4d6d", "Actors"),
        ("●", "#b48ef5", "TTPs"),
        ("●", "#06d6a0", "Industries"),
    ]
    annotations = [
        dict(x=0.02 + j * 0.18, y=1.04, xref="paper", yref="paper",
             text=f'<span style="color:{c};font-size:14px">{sym}</span> '
                  f'<span style="color:#6e7fa3;font-size:11px">{lbl}</span>',
             showarrow=False, align="left")
        for j, (sym, c, lbl) in enumerate(legend_items)
    ]

    fig = go.Figure([
        go.Scatter(x=edge_x, y=edge_y, mode="lines",
                   line=dict(width=0.8, color="rgba(56,189,248,0.15)"),
                   hoverinfo="none"),
        go.Scatter(x=node_x, y=node_y, mode="markers+text",
                   marker=dict(size=node_sizes, color=node_colors,
                               line=dict(width=1.5, color="#050810"), opacity=0.92),
                   text=node_labels, textposition="top center",
                   textfont=dict(size=8, color="#c8d8f0"),
                   hovertext=node_hover, hoverinfo="text"),
    ])
    fig.update_layout(
        paper_bgcolor="#070b14", plot_bgcolor="#070b14",
        showlegend=False, height=380,
        margin=dict(l=10, r=10, t=30, b=10),
        annotations=annotations,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-9, 9]),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-9, 9]),
    )
    return fig


# ─── Admin: platform settings (read/write) ────────────────────────────────────

# Default values shown in the UI when the table has no row yet
_SETTINGS_DEFAULTS: dict[str, str] = {
    "dark_web_enabled":       "false",
    "dark_web_keywords":      "",
    "dark_web_onion_sources": "",
    "dark_web_interval":      "21600",
    # Enrichment API keys
    "enrichment_vt_key":      "",
    "enrichment_gn_key":      "",
    "enrichment_shodan_key":  "",
    # GitHub monitoring
    "github_token":           "",
    # Alert channels
    "alert_email_enabled":    "false",
    "smtp_host":              "",
    "smtp_port":              "587",
    "smtp_user":              "",
    "smtp_pass":              "",
    "alert_from_email":       "",
    "alert_to_email":         "",
    "alert_slack_webhook":    "",
    "alert_teams_webhook":    "",
}


@st.cache_data(ttl=5)
def load_platform_settings() -> dict[str, str]:
    """Read all platform settings from the DB (short TTL so changes propagate quickly)."""
    engine = get_engine()
    settings = dict(_SETTINGS_DEFAULTS)
    try:
        from sqlalchemy import text
        with engine.connect() as conn:
            rows = conn.execute(text("SELECT key, value FROM platform_settings")).fetchall()
        for key, value in rows:
            settings[key] = value or ""
    except Exception:
        pass   # table may not exist on first boot; defaults are fine
    return settings


@st.cache_data(ttl=60)
def load_threat_advisor_data() -> tuple:
    """Load latest briefing and all asset threat profiles."""
    try:
        from sqlalchemy import text as _sa_text
        with engine.connect() as _conn:
            # Latest briefing
            briefing_df = pd.read_sql(
                "SELECT * FROM threat_briefings ORDER BY generated_at DESC LIMIT 1",
                _conn,
            )
            # All asset profiles joined with watched assets
            profiles_df = pd.read_sql(
                """SELECT atp.*, wa.value AS asset_value, wa.asset_type,
                          wa.label AS asset_label
                   FROM asset_threat_profiles atp
                   JOIN watched_assets wa ON atp.watched_asset_id = wa.id
                   WHERE wa.active = true
                   ORDER BY atp.risk_score DESC""",
                _conn,
            )
        return briefing_df, profiles_df
    except Exception:
        return pd.DataFrame(), pd.DataFrame()


@st.cache_data(ttl=30)
def load_org_risk_score() -> int:
    """Compute overall org risk as the max asset risk score (0-100)."""
    try:
        with engine.connect() as _conn:
            row = pd.read_sql(
                "SELECT COALESCE(MAX(risk_score), 0) AS max_risk FROM asset_threat_profiles",
                _conn,
            )
            return int(row.iloc[0]["max_risk"]) if not row.empty else 0
    except Exception:
        return 0


def save_platform_settings(updates: dict[str, str]) -> bool:
    """Upsert settings into the DB and bust the cache so the next read is fresh."""
    engine = get_engine()
    try:
        from sqlalchemy import text
        with engine.connect() as conn:
            for key, value in updates.items():
                conn.execute(
                    text("""
                        INSERT INTO platform_settings (key, value, updated_at, updated_by)
                        VALUES (:k, :v, NOW(), 'webui')
                        ON CONFLICT (key) DO UPDATE
                        SET value = EXCLUDED.value,
                            updated_at = NOW(),
                            updated_by = 'webui'
                    """),
                    {"k": key, "v": value},
                )
            conn.commit()
        load_platform_settings.clear()   # invalidate Streamlit cache
        return True
    except Exception as exc:
        st.error(f"Failed to save settings: {exc}")
        return False


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


def _set_drill(entity_type: str, entity_value: str,
               target_tab_idx: int | None = None,
               target_tab_name: str = "",
               **context) -> None:
    """
    Store a drill-down context in session state and navigate to the target page.
    Uses sidebar radio session state — 100% reliable, no JS required.
    """
    st.session_state["drill_context"] = {
        "entity_type":    entity_type,
        "entity_value":   entity_value,
        "target_tab_idx": target_tab_idx,
        "target_tab_name": target_tab_name,
        **context,
    }
    # Set the nav filter keys from context
    for k, v in context.items():
        st.session_state[k] = v
    # Navigate — set active_page to drive the sidebar radio selector
    if target_tab_name:
        st.session_state["active_page"] = target_tab_name
    st.rerun()


# Keep _go_to_tab as a thin alias used by existing call sites
def _go_to_tab(tab_idx: int, **filters) -> None:
    entity_type  = "Feed" if "nav_feed_filter" in filters else \
                   "Actor" if "nav_actor_filter" in filters else \
                   "IOC" if ("nav_ioc_value" in filters or "nav_ioc_type" in filters or "nav_ioc_country" in filters) else \
                   "Tactic" if "nav_attack_tactic" in filters else \
                   "CVE" if "nav_cve_severity" in filters else \
                   "Watchlist"
    entity_value = (
        filters.get("nav_feed_filter") or
        filters.get("nav_actor_filter") or
        filters.get("nav_ioc_value") or
        filters.get("nav_ioc_type") or
        filters.get("nav_ioc_country") or
        filters.get("nav_attack_tactic") or
        filters.get("nav_cve_severity") or
        filters.get("nav_watchlist_date") or ""
    )
    tab_names = {
        0: "Dashboard", 1: "Threat Advisor", 2: "Threat Feed", 3: "Actors",
        4: "IOC Hunt", 5: "CVE Tracker", 6: "ATT&CK", 7: "AI Analyst",
        8: "Dark Web", 9: "Watchlist", 10: "Alerts", 11: "Campaigns",
        12: "Feed Health", 13: "Admin",
    }
    _set_drill(entity_type, entity_value,
               target_tab_idx=tab_idx,
               target_tab_name=tab_names.get(tab_idx, ""),
               **filters)


@st.cache_data(ttl=1800, show_spinner=False)
def _drill_ai_analysis(entity_type: str, entity_value: str, context: str) -> str:
    """
    Generate a full threat analysis with mitigations for any drill-down entity.
    Cached 30 min per unique (type, value, context) combination.
    """
    prompt = (
        "You are a senior threat intelligence analyst. Provide a structured "
        "analysis of the following threat entity based on known intelligence.\n\n"
        f"Entity Type: {entity_type}\n"
        f"Entity: {entity_value}\n"
        + (f"Context: {context}\n" if context else "")
        + "\nRespond in this exact markdown format:\n\n"
        "## Threat Summary\n"
        "[2-3 sentences: what this threat is, who uses it, and its objective]\n\n"
        "## Known Attack Patterns\n"
        "[Bullet list of observed TTPs or behaviors]\n\n"
        "## Immediate Mitigation Steps\n"
        "[Numbered list of 4-5 specific defensive actions to take right now]\n\n"
        "## Strategic Recommendations\n"
        "[2-3 longer-term defensive posture improvements]\n\n"
        "Be specific, concise, and directly actionable."
    )
    return analyst_reply([{"role": "user", "content": prompt}])


def _render_drill_panel() -> None:
    """
    Render the Drill Panel between the KPI strip and tabs.
    Appears only when drill_context is set in session state.
    Shows AI threat analysis + mitigations + a jump-to-tab button.
    """
    ctx = st.session_state.get("drill_context")
    if not ctx:
        return

    etype  = ctx.get("entity_type", "Entity")
    evalue = ctx.get("entity_value", "")
    tname  = ctx.get("target_tab_name", "")
    tidx   = ctx.get("target_tab_idx")
    extra  = {k: v for k, v in ctx.items()
              if k not in ("entity_type", "entity_value", "target_tab_idx", "target_tab_name")}
    context_str = " | ".join(f"{k}: {v}" for k, v in extra.items() if v)

    st.markdown(
        '<div style="background:rgba(6,214,160,0.04);border:1px solid #06d6a030;'
        'border-left:4px solid #38bdf8;border-radius:8px;padding:14px 18px;margin:8px 0 12px 0">',
        unsafe_allow_html=True,
    )
    hdr_l, hdr_r = st.columns([8, 1])
    with hdr_l:
        st.markdown(
            f'<p style="margin:0;font-size:0.68rem;color:#3d5a80;text-transform:uppercase;'
            f'letter-spacing:0.1em"><i class="bi bi-crosshair2"></i>&nbsp; Threat Intelligence Detail</p>'
            f'<p style="margin:2px 0 0 0;font-size:1rem;color:#38bdf8;font-weight:700">'
            f'{etype}: <span style="color:#c8d8f0;font-family:monospace">{evalue}</span></p>',
            unsafe_allow_html=True,
        )
    with hdr_r:
        if st.button("✕ Close", key="close_drill_panel"):
            st.session_state.pop("drill_context", None)
            st.rerun()

    ai_col, nav_col = st.columns([4, 1])

    with ai_col:
        with st.spinner("Generating AI threat analysis and mitigations…"):
            analysis = _drill_ai_analysis(etype, evalue, context_str)
        if analysis.startswith("⚠️"):
            st.warning(analysis)
        else:
            st.markdown(analysis)

    with nav_col:
        st.markdown(
            '<p style="font-size:0.7rem;color:#3d5a80;text-transform:uppercase;'
            'letter-spacing:0.08em;margin-bottom:8px">Quick Links</p>',
            unsafe_allow_html=True,
        )
        # Enrichment links for IOC types
        if etype == "IOC" and evalue:
            ioc_type = extra.get("nav_ioc_type", "")
            st.markdown(
                _enrichment_links(ioc_type, evalue),
                unsafe_allow_html=True,
            )
        # Jump-to-tab button
        if tname and tidx is not None:
            st.markdown('<div style="margin-top:12px">', unsafe_allow_html=True)
            if st.button(
                f"Open in {tname} →",
                key="drill_jump_tab",
                type="primary",
                use_container_width=True,
            ):
                # Navigate via sidebar radio session state
                st.session_state["active_page"] = tname
                # Set the filter keys so the target page pre-filters
                for k, v in extra.items():
                    st.session_state[k] = v
                st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)


def _nav_banner(label: str, clear_key: str, *state_keys: str) -> None:
    """Dismissible banner shown at the top of a tab after navigation."""
    col_txt, col_btn = st.columns([9, 1])
    with col_txt:
        st.info(label)
    with col_btn:
        if st.button("✕ Clear", key=clear_key):
            for k in state_keys:
                st.session_state.pop(k, None)
            st.rerun()


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


@st.cache_data(ttl=3600, show_spinner=False)
def ai_ioc_synopsis(ioc_type: str, ioc_value: str, malware_family: str,
                    source_feed: str, report_summary: str, actor: str) -> str:
    """Ask the AI for a 2–3 sentence threat synopsis for a single IOC.
    Cached for 1 hour per unique IOC so repeated clicks are instant."""
    prompt = (
        "You are a threat intelligence analyst. Provide a concise 2-3 sentence "
        "threat synopsis for the following indicator of compromise. "
        "Cover: what the malware/threat does, how it typically operates, "
        "and the recommended immediate defensive action. Be specific and actionable.\n\n"
        f"IOC Type: {ioc_type}\n"
        f"IOC Value: {ioc_value}\n"
        f"Malware / Threat Family: {malware_family}\n"
        f"Source Feed: {source_feed}\n"
        + (f"Threat Actor: {actor}\n" if actor and actor != "Unknown" else "")
        + (f"Feed Summary: {report_summary[:300]}\n" if report_summary else "")
        + "\nSynopsis:"
    )
    messages = [{"role": "user", "content": prompt}]
    reply = analyst_reply(messages)
    # Strip leading "Synopsis:" if the model echoed it back
    return reply.replace("Synopsis:", "").strip()


# ─── Load data ────────────────────────────────────────────────────────────────
reports, iocs, cves, feed_status = load_data()
techniques_df, mitigations_df = load_attack_data()
darkweb_df = load_darkweb_data()
watchlist_df, hits_df = load_watchlist_data()
campaigns_df = load_campaigns_data()
_briefing_df, _profiles_df = load_threat_advisor_data()
_org_risk = load_org_risk_score()

# ─── Platform header ──────────────────────────────────────────────────────────
_now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
_enriched = int((reports["summary"].notna() & (reports["summary"] != "")).sum()) if not reports.empty else 0
st.markdown(f"""
<div class="platform-header">
  <div style="display:flex;align-items:center;gap:16px;">
    <!--
      SVG Logo: hexagonal targeting reticle with V mark.
      No <defs> / url() refs — direct stroke colors only so Streamlit's
      HTML sanitizer does not strip the elements.
    -->
    <svg width="46" height="46" viewBox="0 0 46 46" fill="none"
         xmlns="http://www.w3.org/2000/svg" style="flex-shrink:0;overflow:visible;">
      <!-- Outer hexagon -->
      <polygon points="23,2 41,12 41,34 23,44 5,34 5,12"
               stroke="#38bdf8" stroke-width="1.5" fill="none" opacity="0.95"/>
      <!-- Inner hexagon -->
      <polygon points="23,9 36,16.5 36,29.5 23,37 10,29.5 10,16.5"
               stroke="#818cf8" stroke-width="0.6" fill="none" opacity="0.35"/>
      <!-- Corner accent ticks — top 3 (cyan) -->
      <line x1="23" y1="2"  x2="23" y2="7"   stroke="#38bdf8" stroke-width="2.2" stroke-linecap="round"/>
      <line x1="41" y1="12" x2="37.5" y2="14" stroke="#38bdf8" stroke-width="2.2" stroke-linecap="round"/>
      <line x1="5"  y1="12" x2="8.5"  y2="14" stroke="#38bdf8" stroke-width="2.2" stroke-linecap="round"/>
      <!-- Corner accent ticks — bottom 3 (purple) -->
      <line x1="23" y1="44" x2="23" y2="39"   stroke="#c084fc" stroke-width="2.2" stroke-linecap="round"/>
      <line x1="41" y1="34" x2="37.5" y2="32" stroke="#c084fc" stroke-width="2.2" stroke-linecap="round"/>
      <line x1="5"  y1="34" x2="8.5"  y2="32" stroke="#c084fc" stroke-width="2.2" stroke-linecap="round"/>
      <!-- V mark: soft purple halo layer then bright cyan foreground -->
      <path d="M13 14 L23 33 L33 14"
            stroke="#818cf8" stroke-width="5" fill="none"
            stroke-linecap="round" stroke-linejoin="round" opacity="0.25"/>
      <path d="M13 14 L23 33 L33 14"
            stroke="#38bdf8" stroke-width="2.5" fill="none"
            stroke-linecap="round" stroke-linejoin="round"/>
      <!-- Centre crosshair dot -->
      <circle cx="23" cy="23" r="1.8" fill="#818cf8" opacity="0.6"/>
    </svg>
    <!-- Wordmark -->
    <div>
      <div class="platform-logo">
        <span class="logo-van">VAN</span><span class="logo-telligence-wrap"><span class="logo-telligence">TELLIGENCE</span></span>
      </div>
      <div style="font-size:0.6rem;color:#5a7fa8;margin-top:5px;font-family:'JetBrains Mono',monospace;letter-spacing:0.22em;text-transform:uppercase;">
        SEE EVERY THREAT. BEFORE IT SEES YOU.
      </div>
    </div>
  </div>
  <div class="platform-meta">
    <span style="font-family:'JetBrains Mono',monospace">{_now_utc} UTC</span>
    <span class="live-badge"><span class="live-dot"></span>LIVE</span>
  </div>
</div>
""", unsafe_allow_html=True)

# ─── Live Threat Ticker ───────────────────────────────────────────────────────
if not iocs.empty:
    _ticker_iocs = iocs.head(30)
    _ticker_items = []
    for _, _ti in _ticker_iocs.iterrows():
        _ti_type = str(_ti.get("ioc_type", "IOC")).upper()
        _ti_val  = str(_ti.get("value", ""))[:50]
        _ti_feed = str(_ti.get("source_feed") or _ti.get("feed") or "")
        _ti_fam  = str(_ti.get("malware_family") or "")
        _sev_cls = "critical" if _ti_fam else "high"
        _ticker_items.append(
            f'<span class="ticker-item {_sev_cls}">'
            f'<span class="ti-type">[{_ti_type}]</span>'
            f'<span class="ti-val">{_ti_val}</span>'
            f'<span class="ti-sep">·</span>'
            f'<span style="color:#3d5a80;font-size:0.68rem">{_ti_feed}</span>'
            + (f'<span class="ti-sep">·</span><span style="color:#c084fc;font-size:0.68rem">{_ti_fam}</span>' if _ti_fam else '') +
            f'</span>'
        )
    _ticker_html_items = "".join(_ticker_items)
    # Scrolling ticker — hover to pause
    st.markdown(
        f'<div class="ticker-wrap"><div class="ticker-track">'
        f'{_ticker_html_items}{_ticker_html_items}'
        f'</div></div>',
        unsafe_allow_html=True,
    )
    # ── Clickable quick-access strip below ticker ─────────────────────────────
    st.markdown('<div class="ticker-click-hint">▼ Click any IOC below to investigate</div>', unsafe_allow_html=True)
    _ticker_df = _ticker_iocs[
        [c for c in ["ioc_type", "value", "malware_family", "source_feed"] if c in _ticker_iocs.columns]
    ].copy()
    _ticker_df.columns = [c.replace("_", " ").title() for c in _ticker_df.columns]
    _ticker_sel = st.dataframe(
        _ticker_df,
        use_container_width=True,
        hide_index=True,
        height=160,
        on_select="rerun",
        selection_mode="single-row",
        key="ticker_row_select",
    )
    if _ticker_sel and _ticker_sel.selection and _ticker_sel.selection.rows:
        _t_row = _ticker_iocs.iloc[_ticker_sel.selection.rows[0]]
        _t_val  = str(_t_row.get("value", ""))
        _t_type = str(_t_row.get("ioc_type", ""))
        _t_fam  = str(_t_row.get("malware_family", ""))
        if _t_val:
            _go_to_tab(4,
                       nav_ioc_value=_t_val,
                       nav_ioc_type=_t_type,
                       nav_ioc_family=_t_fam)

# ─── Top KPI strip ────────────────────────────────────────────────────────────
k1, k2, k3, k4, k5, k6, k7 = st.columns(7)
kev_count  = int((cves["is_kev"] == 1).sum()) if not cves.empty and "is_kev" in cves else 0
crit_cves  = int((cves["cvss_score"].fillna(0) >= 9.0).sum()) if not cves.empty and "cvss_score" in cves else 0
active_f   = int((feed_status["status"] == "ok").sum()) if not feed_status.empty else 0
total_f    = len(feed_status)
ttp_usage  = _ttp_map(reports)
open_hits  = int((hits_df["alerted"] == False).sum()) if not hits_df.empty and "alerted" in hits_df.columns else 0

with k1: st.metric("Threat Reports",  f"{len(reports):,}")
with k2: st.metric("IOCs Tracked",    f"{len(iocs):,}")
with k3: st.metric("CVEs Monitored",  f"{len(cves):,}")
with k4: st.metric("CISA KEV",        f"{kev_count:,}")
with k5: st.metric("CVSS ≥ 9.0",      f"{crit_cves:,}")
with k6: st.metric("Active Feeds",    f"{active_f} / {total_f}")
with k7: st.metric("⚑ Open Alerts",   f"{open_hits:,}")

st.divider()

# Drill Panel intentionally NOT auto-rendered here.
# AI analysis is opt-in via buttons within each target tab.

# ─── Sidebar navigation ───────────────────────────────────────────────────────
_NAV_PAGES = [
    "Dashboard", "Threat Advisor", "Threat Feed", "Actors",
    "IOC Hunt", "CVE Tracker", "ATT&CK", "AI Analyst", "Dark Web",
    "Watchlist", "Alerts", "Campaigns", "Feed Health", "Admin",
]
_NAV_ICONS = {
    "Dashboard": "◈", "Threat Advisor": "⊛", "Threat Feed": "◉",
    "Actors": "⬡", "IOC Hunt": "⊙", "CVE Tracker": "◆",
    "ATT&CK": "⬢", "AI Analyst": "⊕", "Dark Web": "◉",
    "Watchlist": "⚑", "Alerts": "⊜", "Campaigns": "⬦",
    "Feed Health": "◎", "Admin": "⚙",
}
if "active_page" not in st.session_state:
    st.session_state["active_page"] = "Dashboard"

with st.sidebar:
    st.markdown(
        '<div style="padding:10px 4px 6px;font-size:0.65rem;font-weight:800;'
        'text-transform:uppercase;letter-spacing:0.14em;color:#1e3a5f;'
        'border-bottom:1px solid #0f2040;margin-bottom:8px;">Navigation</div>',
        unsafe_allow_html=True,
    )
    for _pg in _NAV_PAGES:
        _icon = _NAV_ICONS.get(_pg, "◈")
        _is_active = (st.session_state["active_page"] == _pg)
        _clicked = st.button(
            f"{_icon}  {_pg}",
            key=f"_nav_btn_{_pg}",
            use_container_width=True,
            type="primary" if _is_active else "secondary",
        )
        if _clicked:
            st.session_state["active_page"] = _pg
            st.rerun()

active_page = st.session_state["active_page"]


# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
if active_page == "Dashboard":
    st.markdown('<p class="section-label"><i class="bi bi-grid-3x3-gap-fill bi-sm"></i>&nbsp; Executive Overview</p>', unsafe_allow_html=True)

    if reports.empty and iocs.empty and cves.empty:
        st.info("Collector is initialising feeds — check back in a few minutes.")
    else:
        # ── Risk Gauge Row ────────────────────────────────────────────────────
        _risk_score = min(100, (crit_cves * 8 + kev_count * 5 + len(iocs) // 100 + open_hits * 10))
        if _risk_score >= 85:
            _risk_label = "CRITICAL"
        elif _risk_score >= 60:
            _risk_label = "HIGH"
        elif _risk_score >= 30:
            _risk_label = "MEDIUM"
        else:
            _risk_label = "LOW"

        _rg1, _rg2, _rg3 = st.columns(3)

        with _rg1:
            st.markdown('<div class="risk-gauge-wrap">', unsafe_allow_html=True)
            _fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=_risk_score,
                title={"text": f"Platform Threat Level<br><span style='font-size:0.8rem;color:#ff4d6d'>{_risk_label}</span>", "font": {"size": 13, "color": "#c8d8f0"}},
                gauge={
                    "axis": {"range": [0, 100], "tickcolor": "#3d5a80"},
                    "bar": {"color": "#ff4d6d" if _risk_score >= 85 else ("#ff8c42" if _risk_score >= 60 else ("#ffd166" if _risk_score >= 30 else "#06d6a0"))},
                    "bgcolor": "#0a1428",
                    "bordercolor": "#142038",
                    "steps": [
                        {"range": [0, 30],  "color": "rgba(6,214,160,0.08)"},
                        {"range": [30, 60], "color": "rgba(255,209,102,0.08)"},
                        {"range": [60, 85], "color": "rgba(255,140,66,0.1)"},
                        {"range": [85, 100],"color": "rgba(255,77,109,0.12)"},
                    ],
                    "threshold": {"line": {"color": "#ff4d6d", "width": 2}, "thickness": 0.75, "value": _risk_score},
                },
                number={"font": {"color": "#38bdf8", "size": 36}},
            ))
            _fig_gauge.update_layout(paper_bgcolor="#060c1a", font_color="#c8d8f0",
                                     margin=dict(l=20, r=20, t=50, b=10), height=200)
            st.plotly_chart(_fig_gauge, use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)

        with _rg2:
            # Mini stat glow cards
            _active_actors = int(reports[reports["threat_actor"] != "Unknown"]["threat_actor"].nunique()) if not reports.empty else 0
            _malware_fams = int(iocs["malware_family"].dropna().nunique()) if not iocs.empty and "malware_family" in iocs.columns else 0
            try:
                _enrich_engine = get_engine()
                _enrich_count_df = pd.read_sql("SELECT COUNT(*) AS cnt FROM ioc_enrichments", _enrich_engine)
                _enrich_count = int(_enrich_count_df["cnt"].iloc[0]) if not _enrich_count_df.empty else 0
            except Exception:
                _enrich_count = 0
            st.markdown(f"""
<div class="stat-glow-card">
  <div class="sgc-label">Active Threat Actors</div>
  <div class="sgc-value">{_active_actors}</div>
  <div class="sgc-sub">distinct non-Unknown actors in reports</div>
</div>
<div class="stat-glow-card">
  <div class="sgc-label">Malware Families</div>
  <div class="sgc-value">{_malware_fams}</div>
  <div class="sgc-sub">distinct families across IOCs</div>
</div>
<div class="stat-glow-card">
  <div class="sgc-label">Enriched IOCs</div>
  <div class="sgc-value">{_enrich_count:,}</div>
  <div class="sgc-sub">records in ioc_enrichments table</div>
</div>""", unsafe_allow_html=True)

        with _rg3:
            st.markdown("#### Top 5 CISA KEV CVEs")
            if not cves.empty and "is_kev" in cves.columns:
                _kev_top = cves[cves["is_kev"] == 1].sort_values("cvss_score", ascending=False).head(5)
                if not _kev_top.empty:
                    for _, _krow in _kev_top.iterrows():
                        _k_id = str(_krow.get("cve_id", "?"))
                        _k_score = _krow.get("cvss_score")
                        _k_vendor = str(_krow.get("vendor", ""))
                        _k_badge = _cvss_badge(_k_score)
                        st.markdown(
                            f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">'
                            f'{_k_badge} <span style="font-family:\'JetBrains Mono\',monospace;font-size:0.78rem;color:#7dd3fc">{_k_id}</span>'
                            f'<span style="font-size:0.72rem;color:#3d5a80">{_k_vendor}</span></div>',
                            unsafe_allow_html=True,
                        )
                else:
                    st.info("No CISA KEV records yet.")
            else:
                st.info("CVE data loading…")

        st.divider()

        # ── Row 1: Threat velocity timeline + IOC type donut ─────────────────
        row1_l, row1_r = st.columns([3, 2])

        with row1_l:
            st.markdown("#### Threat Ingestion Timeline (30 days)")
            if not reports.empty and "created_at" in reports.columns:
                _tl = reports.copy()
                _tl["date"] = pd.to_datetime(_tl["created_at"], utc=True, errors="coerce").dt.floor("D")
                _tl = _tl[_tl["date"] >= (pd.Timestamp.now(tz="UTC") - pd.Timedelta(days=30))]
                _tl_grp = _tl.groupby(["date", "source_feed"]).size().reset_index(name="count")
                if not _tl_grp.empty:
                    fig_tl = px.area(
                        _tl_grp, x="date", y="count", color="source_feed",
                        labels={"date": "", "count": "Reports", "source_feed": "Feed"},
                        color_discrete_sequence=px.colors.qualitative.Bold,
                    )
                    fig_tl.update_layout(**_PLOTLY_DARK, height=240, showlegend=True,
                                         legend=dict(orientation="h", y=-0.25))
                    fig_tl.update_traces(hovertemplate="%{x|%b %d}: %{y}<extra>%{fullData.name}</extra>")
                    fig_tl.update_layout(clickmode="event+select")
                    _tl_sel = st.plotly_chart(fig_tl, on_select="rerun",
                                              use_container_width=True, key="dash_timeline")
                    _drill_tl_feed = None
                    if _tl_sel and _tl_sel.selection and _tl_sel.selection.points:
                        _tl_pt = _tl_sel.selection.points[0]
                        _drill_tl_feed = (
                            _tl_pt.get("customdata", [None])[0]
                            if _tl_pt.get("customdata") else None
                        )
                        if not _drill_tl_feed:
                            _tl_src_order = _tl_grp["source_feed"].unique().tolist()
                            _tl_ti = _tl_pt.get("curveNumber", -1)
                            if 0 <= _tl_ti < len(_tl_src_order):
                                _drill_tl_feed = _tl_src_order[_tl_ti]
                    if _drill_tl_feed:
                        _go_to_tab(2, nav_feed_filter=_drill_tl_feed)  # Threat Feed
                    else:
                        st.caption("Click an area or point to open that feed in Threat Feed")
                else:
                    st.info("No timeline data in last 30 days.")
            else:
                st.info("No threat report data yet.")

        with row1_r:
            st.markdown("#### IOC Type Distribution")
            if not iocs.empty:
                by_type = iocs.groupby("ioc_type").size().reset_index(name="count")
                fig2 = px.pie(
                    by_type, names="ioc_type", values="count", hole=0.55,
                    color_discrete_sequence=["#38bdf8","#818cf8","#c084fc","#fb923c","#34d399","#f87171"],
                )
                fig2.update_layout(**_PLOTLY_DARK, height=240, showlegend=True,
                                    legend=dict(orientation="h", y=-0.25))
                fig2.update_traces(textposition="inside", textinfo="percent",
                                   hovertemplate="<b>%{label}</b><br>%{value:,} IOCs (%{percent})<extra></extra>")
                fig2.update_layout(clickmode="event+select")
                _ioc_sel = st.plotly_chart(fig2, on_select="rerun",
                                           use_container_width=True, key="dash_ioc_pie")
                _drill_ioc_type = None
                if _ioc_sel and _ioc_sel.selection and _ioc_sel.selection.points:
                    _drill_ioc_type = _ioc_sel.selection.points[0].get("label")
                if _drill_ioc_type:
                    _go_to_tab(4, nav_ioc_type=_drill_ioc_type)  # IOC Hunt
                else:
                    _top_ioc_type = by_type.sort_values("count", ascending=False).iloc[0]["ioc_type"] if not by_type.empty else ""
                    st.caption(f"Click a slice to open that IOC type in IOC Hunt · Largest: **{_top_ioc_type}**")
            else:
                st.info("No IOC data yet.")

        st.divider()

        # ── Row 2: Threat actor bar + ATT&CK tactics ─────────────────────────
        row2_l, row2_r = st.columns(2)

        with row2_l:
            st.markdown("#### Top Threat Actors by Report Count")
            if not reports.empty:
                _actor_counts = (
                    reports[reports["threat_actor"].notna() & (reports["threat_actor"] != "Unknown")]
                    .groupby("threat_actor").agg(
                        Reports=("id", "count"),
                        Avg_Conf=("confidence_score", "mean"),
                    ).reset_index().sort_values("Reports", ascending=True).tail(15)
                )
                if not _actor_counts.empty:
                    fig_a = px.bar(
                        _actor_counts, x="Reports", y="threat_actor", orientation="h",
                        color="Avg_Conf",
                        color_continuous_scale=[[0,"#1a3a6a"],[0.5,"#38bdf8"],[1,"#ff4d6d"]],
                        labels={"threat_actor": "", "Reports": "Reports", "Avg_Conf": "Avg Confidence"},
                        custom_data=["Avg_Conf"],
                    )
                    fig_a.update_coloraxes(showscale=False)
                    fig_a.update_layout(**_PLOTLY_DARK, height=320, clickmode="event+select")
                    fig_a.update_traces(
                        hovertemplate="<b>%{y}</b><br>%{x} reports · Avg conf: %{customdata[0]:.0f}%<extra></extra>"
                    )
                    _actor_sel = st.plotly_chart(fig_a, on_select="rerun",
                                                 use_container_width=True, key="dash_actor_bar")
                    _drill_actor = None
                    if _actor_sel and _actor_sel.selection and _actor_sel.selection.points:
                        _drill_actor = _actor_sel.selection.points[0].get("y")
                    if _drill_actor:
                        _go_to_tab(3, nav_actor_filter=_drill_actor)  # Actors tab
                    else:
                        st.caption("Click a bar to open that actor's profile")
                else:
                    st.info("Actor data populates as AI enrichment runs.")
            else:
                st.info("No report data yet.")

        with row2_r:
            st.markdown("#### Top Observed ATT&CK Tactics")
            if ttp_usage and not techniques_df.empty:
                obs = techniques_df[techniques_df["technique_id"].isin(ttp_usage.keys())].copy()
                obs["count"] = obs["technique_id"].map(
                    lambda t: ttp_usage.get(t, {}).get("count", 0) if isinstance(ttp_usage.get(t), dict) else ttp_usage.get(t, 0)
                )
                tac_counts: dict = {}
                for _, _r in obs.iterrows():
                    for tac in str(_r.get("tactic") or "Unknown").split(","):
                        tac = tac.strip() or "Unknown"
                        tac_counts[tac] = tac_counts.get(tac, 0) + _r["count"]
                tdf = pd.DataFrame(list(tac_counts.items()), columns=["Tactic", "Count"]).sort_values("Count")
                fig4 = px.bar(
                    tdf, x="Count", y="Tactic", orientation="h",
                    color="Count",
                    color_continuous_scale=[[0,"#2d1060"],[0.5,"#7c3aed"],[1,"#c084fc"]],
                )
                fig4.update_coloraxes(showscale=False)
                fig4.update_layout(**_PLOTLY_DARK, height=320, clickmode="event+select")
                fig4.update_traces(hovertemplate="<b>%{y}</b>: %{x} observations<extra></extra>")
                _tac_sel = st.plotly_chart(fig4, on_select="rerun",
                                           use_container_width=True, key="dash_tac_bar")
                _drill_tactic = None
                if _tac_sel and _tac_sel.selection and _tac_sel.selection.points:
                    _drill_tactic = _tac_sel.selection.points[0].get("y")
                if _drill_tactic:
                    _go_to_tab(6, nav_attack_tactic=_drill_tactic)  # ATT&CK tab
                else:
                    st.caption("Click a bar to open that tactic in ATT&CK")
            else:
                st.info("ATT&CK TTP mapping populates as the AI enrichment runs.")

        st.divider()

        # ── World Map IOC Heatmap ─────────────────────────────────────────────
        st.markdown("#### IOC Geolocation Map")
        # Collect IPs from: plain ip, ip:port, and URL-embedded hosts
        _geo_ioc_rows = tuple(
            zip(iocs["ioc_type"].fillna("").tolist(),
                iocs["value"].fillna("").tolist())
        ) if not iocs.empty else ()
        _ip_iocs = extract_ips_from_iocs(_geo_ioc_rows) if _geo_ioc_rows else ()
        _geo_df, _geo_err = geolocate_ips(_ip_iocs) if _ip_iocs else (pd.DataFrame(), "No IP IOCs collected yet.")
        if not _geo_df.empty:
            # Country frequency for bubble sizing
            _country_cnt = _geo_df["countryCode"].value_counts().to_dict()
            _geo_df["count"] = _geo_df["countryCode"].map(_country_cnt).fillna(1)
            _fig_map = px.scatter_geo(
                _geo_df,
                lat="lat", lon="lon", size="count",
                hover_name="country",
                hover_data={"query": True, "isp": True, "org": True,
                            "lat": False, "lon": False, "count": False, "countryCode": False},
                projection="natural earth",
                size_max=30,
            )
            _fig_map.update_traces(marker=dict(color="#38bdf8", opacity=0.80,
                                               line=dict(width=0.5, color="#0a1428")))
            _fig_map.update_geos(
                bgcolor="#050810", landcolor="#0d1a30", oceancolor="#050810",
                lakecolor="#050810", coastlinecolor="#1e3a5f",
                showframe=False, showcoastlines=True, showland=True,
                showcountries=True, countrycolor="#0f2040",
            )
            _fig_map.update_layout(
                paper_bgcolor="#050810", margin=dict(l=0, r=0, t=0, b=0),
                height=360, font_color="#c8d8f0",
            )
            _fig_map.update_layout(clickmode="event+select")
            _map_sel = st.plotly_chart(_fig_map, on_select="rerun",
                                       use_container_width=True, key="dash_geo_map")
            _drill_map_country = None
            if _map_sel and _map_sel.selection and _map_sel.selection.points:
                _map_pt = _map_sel.selection.points[0]
                _map_pt_idx = _map_pt.get("point_index", -1)
                if 0 <= _map_pt_idx < len(_geo_df):
                    _drill_map_country = _geo_df.iloc[_map_pt_idx]["country"]
            _top_countries = _geo_df["country"].value_counts().head(5)
            _cc_parts = [f"**{c}** {n}" for c, n in _top_countries.items()]
            if _drill_map_country:
                # Also pass the list of IPs so IOC Hunt can filter to them
                _country_ip_list = _geo_df[_geo_df["country"] == _drill_map_country]["query"].tolist()
                _go_to_tab(4, nav_ioc_country=_drill_map_country,
                           nav_ioc_country_ips=_country_ip_list)  # IOC Hunt
            else:
                st.caption("Top origins: " + " \u00b7 ".join(_cc_parts) + " \u00b7 Click a bubble to open those IPs in IOC Hunt")
        else:
            # Offline fallback: country bar from available CVE data
            st.markdown(
                f'<div style="background:rgba(56,189,248,0.04);border:1px solid #0f2040;'
                f'border-radius:8px;padding:10px 14px;font-size:0.78rem;color:#3d5a80;">'
                f'<i class="bi bi-globe2"></i>&nbsp; Geo lookup unavailable: {_geo_err}<br>'
                f'<span style="font-size:0.7rem;">Map will populate once IP IOCs are collected '
                f'and the container can reach ip-api.com.</span></div>',
                unsafe_allow_html=True,
            )
            # Show IOC count breakdown as fallback visual
            if not iocs.empty:
                _ioc_src = iocs.groupby("ioc_type").size().reset_index(name="count")
                _fig_fall = px.bar(_ioc_src, x="ioc_type", y="count",
                                   color="count",
                                   color_continuous_scale=[[0,"#1a3a6a"],[1,"#38bdf8"]],
                                   labels={"ioc_type": "IOC Type", "count": "Count"})
                _fig_fall.update_coloraxes(showscale=False)
                _fig_fall.update_layout(**_PLOTLY_DARK, height=220, showlegend=False)
                st.plotly_chart(_fig_fall, use_container_width=True)

        st.divider()

        # ── Actor Relationship Network Graph ──────────────────────────────────
        if not reports.empty:
            st.markdown("#### Threat Actor Relationship Network")
            _net_fig = _build_network_graph(reports, iocs)
            _net_fig.update_layout(clickmode="event+select")
            _net_sel = st.plotly_chart(_net_fig, on_select="rerun",
                                       use_container_width=True, key="dash_network")
            _drill_node = None
            if _net_sel and _net_sel.selection and _net_sel.selection.points:
                _np = _net_sel.selection.points[0]
                _drill_node = _np.get("text") or _np.get("hovertext") or ""
            if _drill_node and _drill_node.strip():
                _drill_node_clean = str(_drill_node).strip()
                _known_feeds  = set(reports["source_feed"].dropna().unique())
                _known_actors = set(reports["threat_actor"].dropna().unique())
                if _drill_node_clean in _known_feeds:
                    _go_to_tab(2, nav_feed_filter=_drill_node_clean)    # Threat Feed
                elif _drill_node_clean in _known_actors:
                    _go_to_tab(3, nav_actor_filter=_drill_node_clean)   # Actors
                else:
                    _go_to_tab(6, nav_attack_tactic=_drill_node_clean)  # ATT&CK (TTP)
            else:
                st.caption("Click any node to open its detail page — Red=actors · Cyan=feeds · Purple=TTPs · Green=industries")
            st.divider()

        # ── Row 3: CVE severity + Watchlist alert trend ───────────────────────
        row3_l, row3_r = st.columns(2)

        with row3_l:
            st.markdown("#### CVE Severity Breakdown")
            if not cves.empty and "cvss_score" in cves.columns:
                def _sev_label(s):
                    try:
                        v = float(s)
                        if v >= 9.0: return "Critical"
                        if v >= 7.0: return "High"
                        if v >= 4.0: return "Medium"
                        return "Low"
                    except Exception:
                        return "Unknown"
                cves_copy = cves.copy()
                cves_copy["Severity"] = cves_copy["cvss_score"].apply(_sev_label)
                sev_counts = cves_copy["Severity"].value_counts().reset_index()
                sev_counts.columns = ["Severity", "Count"]
                _sev_colors = {"Critical":"#ff4d6d","High":"#ff8c42","Medium":"#ffd166","Low":"#06d6a0","Unknown":"#5d7199"}
                fig5 = px.bar(
                    sev_counts, x="Severity", y="Count",
                    color="Severity", color_discrete_map=_sev_colors,
                    category_orders={"Severity":["Critical","High","Medium","Low","Unknown"]},
                )
                fig5.update_layout(**_PLOTLY_DARK, showlegend=False, height=260, clickmode="event+select")
                fig5.update_traces(hovertemplate="<b>%{x}</b>: %{y:,} CVEs<extra></extra>")
                _cve_sel = st.plotly_chart(fig5, on_select="rerun",
                                           use_container_width=True, key="dash_cve_bar")
                _drill_sev = None
                if _cve_sel and _cve_sel.selection and _cve_sel.selection.points:
                    _drill_sev = _cve_sel.selection.points[0].get("x")
                if _drill_sev:
                    _go_to_tab(5, nav_cve_severity=_drill_sev)  # CVE Tracker
                else:
                    _kev_pct = f"{(kev_count/len(cves)*100):.1f}%" if len(cves) > 0 else "—"
                    st.caption(f"Click a bar to open that severity in CVE Tracker · {kev_count:,} CISA KEV ({_kev_pct})")
            else:
                st.info("CVE data loading…")

        with row3_r:
            st.markdown("#### Watchlist Alert Trend (14 days)")
            if not hits_df.empty and "found_at" in hits_df.columns:
                _hit_tl = hits_df.copy()
                _hit_tl["date"] = pd.to_datetime(_hit_tl["found_at"], utc=True, errors="coerce").dt.floor("D")
                _hit_14 = _hit_tl[_hit_tl["date"] >= (pd.Timestamp.now(tz="UTC") - pd.Timedelta(days=14))]
                _hit_grp = _hit_14.groupby(["date","severity"]).size().reset_index(name="count") if not _hit_14.empty else pd.DataFrame()
                if not _hit_grp.empty:
                    _hit_colors = {"critical":"#ff4d6d","high":"#ff8c42","medium":"#ffd166","low":"#06d6a0"}
                    fig_h = px.bar(
                        _hit_grp, x="date", y="count", color="severity",
                        color_discrete_map=_hit_colors, barmode="stack",
                        labels={"date":"","count":"Hits","severity":"Severity"},
                    )
                    fig_h.update_layout(**_PLOTLY_DARK, height=260)
                    fig_h.update_traces(hovertemplate="%{x|%b %d}: %{y} hits<extra>%{fullData.name}</extra>")
                    fig_h.update_layout(clickmode="event+select")
                    _hit_bar_sel = st.plotly_chart(fig_h, on_select="rerun",
                                                   use_container_width=True, key="dash_hit_trend")
                    if _hit_bar_sel and _hit_bar_sel.selection and _hit_bar_sel.selection.points:
                        _hbpt = _hit_bar_sel.selection.points[0]
                        _drill_hit_date = str(_hbpt.get("x", ""))[:10]
                        if _drill_hit_date:
                            _go_to_tab(9, nav_watchlist_date=_drill_hit_date)  # Watchlist
                    else:
                        st.caption(f"{open_hits:,} unacknowledged · Click a bar to open that day in Watchlist")
                else:
                    st.info("No watchlist hits in the last 14 days.")
            else:
                st.info("No watchlist hits yet — add assets in ⚑ Watchlist to start monitoring.")

        st.divider()

        # ── Row 4: Source breakdown drilldown + confidence histogram ──────────
        row4_l, row4_r = st.columns([2, 3])

        with row4_l:
            st.markdown("#### Reports by Source")
            if not reports.empty:
                by_src = reports.groupby("source_feed").size().reset_index(name="count").sort_values("count", ascending=True)
                fig_src = px.bar(
                    by_src, x="count", y="source_feed", orientation="h",
                    color="count",
                    color_continuous_scale=[[0,"#1a3a6a"],[1,"#38bdf8"]],
                    labels={"source_feed":"","count":"Reports"},
                )
                fig_src.update_coloraxes(showscale=False)
                fig_src.update_layout(**_PLOTLY_DARK, height=280, clickmode="event+select")
                fig_src.update_traces(hovertemplate="%{y}: %{x} reports<extra></extra>")
                _src_bar_sel = st.plotly_chart(fig_src, on_select="rerun",
                                               use_container_width=True, key="dash_src_bar")
                _src_drill = "All"
                if _src_bar_sel and _src_bar_sel.selection and _src_bar_sel.selection.points:
                    _sbpt = _src_bar_sel.selection.points[0]
                    _src_drill = _sbpt.get("y") or "All"
                st.caption("Click a bar to drill into that feed's reports")
            else:
                _src_drill = "All"

        with row4_r:
            st.markdown("#### Confidence Distribution")
            if not reports.empty:
                _drill_reps = reports if _src_drill == "All" else reports[reports["source_feed"] == _src_drill]
                scores = _drill_reps["confidence_score"].dropna()
                fig3 = px.histogram(
                    scores, nbins=20,
                    color_discrete_sequence=["#38bdf8"],
                    labels={"value":"Confidence Score","count":"Reports"},
                )
                fig3.update_layout(**_PLOTLY_DARK, height=280)
                fig3.update_traces(hovertemplate="Score %{x}: %{y} reports<extra></extra>")
                st.plotly_chart(fig3, use_container_width=True)
                st.caption(
                    f"Showing {len(_drill_reps):,} reports"
                    + (f" from **{_src_drill}**" if _src_drill != "All" else " across all sources")
                )
            else:
                st.info("No report data yet.")

        st.divider()

        # ── Row 5: Recent critical threats (drillable) ────────────────────────
        st.markdown('<p class="section-label"><i class="bi bi-exclamation-octagon-fill bi-sm icon-error"></i>&nbsp; Recent High-Confidence Threats</p>', unsafe_allow_html=True)

        _dash_conf_min = st.slider("Min confidence to display", 0, 100, 60, key="dash_conf_min")
        hi_conf = reports[reports["confidence_score"].fillna(0) >= _dash_conf_min].head(10)

        if hi_conf.empty:
            st.info(f"No threats with confidence ≥ {_dash_conf_min} yet.")
        else:
            for _, row in hi_conf.iterrows():
                ts    = row["created_at"].strftime("%Y-%m-%d %H:%M") if hasattr(row["created_at"], "strftime") else "?"
                actor = row.get("threat_actor") or "Unknown"
                conf  = int(row.get("confidence_score") or 0)
                feed  = str(row.get("source_feed", "")).upper()
                summary = str(row.get("summary") or "")
                ttps  = row.get("ttps") or []
                if isinstance(ttps, str):
                    try: ttps = json.loads(ttps)
                    except Exception: ttps = []
                cve_list = row.get("associated_cves") or []
                if isinstance(cve_list, str):
                    try: cve_list = json.loads(cve_list)
                    except Exception: cve_list = []
                _label = f"[{ts}]  {actor}  ·  {feed}  ·  Confidence {conf}%"
                with st.expander(_label):
                    _dc1, _dc2 = st.columns([2, 1])
                    with _dc1:
                        st.markdown(
                            _severity_badge(conf) + f' &nbsp; <span class="feed-tag">{feed}</span>',
                            unsafe_allow_html=True,
                        )
                        if summary:
                            st.markdown(f"> {summary}")
                        if ttps:
                            tags = " ".join(f'<span class="ttp-tag">{t}</span>' for t in ttps[:8])
                            st.markdown(f"**TTPs:** {tags}", unsafe_allow_html=True)
                    with _dc2:
                        if cve_list:
                            st.markdown("**Associated CVEs:**")
                            for _cv in cve_list[:5]:
                                st.markdown(f"`{_cv}`")
                        _r_iocs = iocs[iocs["report_id"] == row["id"]] if not iocs.empty else pd.DataFrame()
                        if not _r_iocs.empty:
                            st.markdown(f"**{len(_r_iocs)} IOC(s):**")
                            for _, _io in _r_iocs.head(5).iterrows():
                                st.markdown(
                                    f'<span class="badge-info">{_io.get("ioc_type","")}</span> '
                                    f'<span class="ioc-val">{str(_io.get("value",""))[:60]}</span>',
                                    unsafe_allow_html=True,
                                )


# ══════════════════════════════════════════════════════════════════════════════
# THREAT FEED
# ══════════════════════════════════════════════════════════════════════════════
elif active_page == "Threat Feed":
    st.markdown('<p class="section-label"><i class="bi bi-lightning-fill bi-sm icon-error"></i>&nbsp; Active Threat Reports</p>', unsafe_allow_html=True)

    # Nav context from dashboard chart
    if "nav_feed_filter" in st.session_state:
        _nff = st.session_state["nav_feed_filter"]
        _ff_bc1, _ff_bc2 = st.columns([9, 1])
        with _ff_bc1:
            st.info(f"Drilled from Dashboard — Feed: **{_nff}**")
        with _ff_bc2:
            if st.button("✕ Clear", key="clear_nav_feed"):
                st.session_state.pop("nav_feed_filter", None)
                st.rerun()
        st.session_state.setdefault("ff_src", [_nff])
        # Opt-in AI summary for this feed
        _feed_ai_key = f"feed_ai_{_nff}"
        if _feed_ai_key not in st.session_state:
            if st.button(f"Generate AI Analysis for {_nff} feed", key=f"btn_{_feed_ai_key}", type="primary"):
                _feed_rpts = reports[reports["source_feed"] == _nff]
                _ctx = f"{len(_feed_rpts)} reports. Actors: {', '.join(_feed_rpts['threat_actor'].dropna().unique()[:5])}."
                with st.spinner("Generating feed threat analysis…"):
                    st.session_state[_feed_ai_key] = _drill_ai_analysis("Threat Feed", _nff, _ctx)
                st.rerun()
        else:
            st.markdown(st.session_state[_feed_ai_key])
            if st.button("Clear Analysis", key=f"clr_{_feed_ai_key}"):
                del st.session_state[_feed_ai_key]
                st.rerun()

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

            if conf >= 90:
                _sev_cls = "critical"
            elif conf >= 70:
                _sev_cls = "high"
            elif conf >= 40:
                _sev_cls = "medium"
            else:
                _sev_cls = "low"

            _sev_label_txt = _sev_cls.upper()
            _conf_pct = min(conf, 100)

            # Rich styled card header
            st.markdown(f"""
<div class="tf-card sev-{_sev_cls}">
  <div class="tf-card-left">
    <span class="badge-{_sev_cls}">{_sev_label_txt}</span>
    <span class="feed-tag">{feed}</span>
  </div>
  <div class="tf-card-actor">{actor}</div>
  <div class="tf-card-right">
    <div class="tf-conf-bar"><div class="tf-conf-fill" style="width:{_conf_pct}%"></div></div>
    <span class="tf-conf-val">{conf}%</span>
    <span class="tf-ts">{ts}</span>
  </div>
</div>""", unsafe_allow_html=True)

            with st.expander("Details", expanded=False):
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
elif active_page == "Actors":
    st.markdown('<p class="section-label"><i class="bi bi-person-badge-fill bi-sm icon-accent"></i>&nbsp; Threat Actor Profiles</p>', unsafe_allow_html=True)

    # Pinned actor from chart drill-down
    _pinned_actor = st.session_state.get("nav_actor_filter")
    if _pinned_actor:
        col_lbl, col_clr = st.columns([9, 1])
        with col_lbl:
            st.info(f"Navigated from Dashboard — Actor: **{_pinned_actor}**")
        with col_clr:
            if st.button("✕ Clear", key="clear_nav_actor"):
                st.session_state.pop("nav_actor_filter", None)
                st.rerun()

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

        # Pinned actor sorts to top
        actor_data.sort(key=lambda x: (0 if x["actor"] == _pinned_actor else 1, -x["reports"]))

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
                badge      = _severity_badge(a["avg_conf"])
                is_pinned  = (a["actor"] == _pinned_actor)
                with st.expander(f"**{a['actor']}** — {a['reports']} report(s)", expanded=is_pinned):
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
                    actor_reports_df = reports[reports["threat_actor"] == a["actor"]]
                    actor_iocs_df    = iocs[iocs["report_id"].isin(actor_reports_df["id"])]
                    if not actor_iocs_df.empty:
                        st.markdown(f"**IOCs ({min(len(actor_iocs_df), 20)} shown)**")
                        cols = [c for c in ["ioc_type", "value", "malware_family"] if c in actor_iocs_df.columns]
                        st.dataframe(actor_iocs_df[cols].head(20), use_container_width=True, hide_index=True)

                    # Opt-in AI analysis button
                    _ai_key = f"actor_ai_{a['actor']}"
                    context_str = (
                        f"TTPs: {', '.join(a['ttps'][:10])}. "
                        f"CVEs: {', '.join(a['cves'][:5])}. "
                        f"Feeds: {', '.join(a['feeds'])}. "
                        f"Industries: {', '.join(a['industries'].keys())}."
                    )
                    if _ai_key not in st.session_state:
                        if st.button(
                            f"Generate AI Analysis for {a['actor']}",
                            key=f"btn_{_ai_key}",
                            type="primary",
                        ):
                            with st.spinner("Generating threat analysis…"):
                                st.session_state[_ai_key] = _drill_ai_analysis(
                                    "Threat Actor", a["actor"], context_str
                                )
                            st.rerun()
                    else:
                        st.markdown("---")
                        st.markdown(st.session_state[_ai_key])
                        if st.button("Clear Analysis", key=f"clr_{_ai_key}"):
                            del st.session_state[_ai_key]
                            st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# IOC HUNT
# ══════════════════════════════════════════════════════════════════════════════
elif active_page == "IOC Hunt":
    st.markdown('<p class="section-label"><i class="bi bi-search bi-sm icon-accent"></i>&nbsp; IOC Hunt &amp; Enrichment</p>', unsafe_allow_html=True)

    # Nav banner when jumping from a dashboard chart
    # ── Pinned IOC from chart/ticker drill-down ───────────────────────────────
    _pinned_ioc_value   = st.session_state.get("nav_ioc_value")
    _pinned_ioc_type    = st.session_state.get("nav_ioc_type")
    _pinned_ioc_country = st.session_state.get("nav_ioc_country")
    _pinned_ioc_family  = st.session_state.get("nav_ioc_family", "")

    if _pinned_ioc_value or _pinned_ioc_type or _pinned_ioc_country:
        # Determine the focused IOC row(s)
        if _pinned_ioc_value and not iocs.empty:
            _focused_iocs = iocs[iocs["value"] == _pinned_ioc_value]
        elif _pinned_ioc_type and not iocs.empty:
            _focused_iocs = iocs[iocs["ioc_type"] == _pinned_ioc_type]
        elif _pinned_ioc_country and not iocs.empty:
            # Country filter: match IPs geolocated to that country (stored in nav state)
            _country_ips = st.session_state.get("nav_ioc_country_ips", [])
            if _country_ips:
                # Build a set of base IPs (strip port, trailing path) for flexible matching
                _country_ip_set = set()
                for _cip in _country_ips:
                    _country_ip_set.add(str(_cip).split(":")[0].strip())
                    _country_ip_set.add(str(_cip).strip())
                # Strip port from IOC values for comparison
                _ioc_base_ips = iocs["value"].str.split(":").str[0].str.strip()
                _focused_iocs = iocs[
                    iocs["value"].isin(_country_ip_set) | _ioc_base_ips.isin(_country_ip_set)
                ]
                # Fallback: filter by ioc_type == 'ip' if nothing matched
                if _focused_iocs.empty and "ioc_type" in iocs.columns:
                    _focused_iocs = iocs[iocs["ioc_type"].str.lower().str.contains("ip", na=False)].head(50)
            else:
                _focused_iocs = iocs.head(0)
        else:
            _focused_iocs = iocs.head(0)

        # Determine label
        if _pinned_ioc_value:
            _focus_label = f"IOC: **{_pinned_ioc_value}**" + (f" ({_pinned_ioc_type})" if _pinned_ioc_type else "")
        elif _pinned_ioc_type:
            _focus_label = f"IOC Type: **{_pinned_ioc_type}** — {len(_focused_iocs):,} matching IOCs"
        else:
            _focus_label = f"Country: **{_pinned_ioc_country}** — {len(_focused_iocs):,} IOCs"

        # Banner + clear
        _bc1, _bc2 = st.columns([9, 1])
        with _bc1:
            st.info(f"Drilled from Dashboard — {_focus_label}")
        with _bc2:
            if st.button("✕ Clear", key="clear_nav_ioc"):
                for _k in ("nav_ioc_value", "nav_ioc_type", "nav_ioc_country",
                           "nav_ioc_family", "nav_ioc_country_ips"):
                    st.session_state.pop(_k, None)
                st.rerun()

        # Show the focused IOC(s) prominently
        if not _focused_iocs.empty:
            _fcols = [c for c in ["ioc_type", "value", "malware_family", "tags", "source_feed"]
                      if c in _focused_iocs.columns]
            st.dataframe(_focused_iocs[_fcols].head(50),
                         use_container_width=True, hide_index=True)

            # Opt-in AI analysis
            _ioc_ai_key = f"ioc_ai_{_pinned_ioc_value or _pinned_ioc_type or _pinned_ioc_country}"
            if _ioc_ai_key not in st.session_state:
                if st.button("Generate AI Analysis", key=f"btn_{_ioc_ai_key}", type="primary"):
                    _first = _focused_iocs.iloc[0]
                    _ctx = (
                        f"Type: {_first.get('ioc_type','')}. "
                        f"Family: {_first.get('malware_family','Unknown')}. "
                        f"Feed: {_first.get('source_feed','')}."
                    )
                    with st.spinner("Generating threat analysis…"):
                        st.session_state[_ioc_ai_key] = _drill_ai_analysis(
                            "IOC",
                            _pinned_ioc_value or _pinned_ioc_type or _pinned_ioc_country,
                            _ctx,
                        )
                    st.rerun()
            else:
                st.markdown(st.session_state[_ioc_ai_key])
                if st.button("Clear Analysis", key=f"clr_{_ioc_ai_key}"):
                    del st.session_state[_ioc_ai_key]
                    st.rerun()

        st.divider()

    if iocs.empty:
        st.info("No IOCs collected yet.")
    else:
        # ── URL / Domain Intelligence Overview ───────────────────────────────
        from urllib.parse import urlparse as _urlparse_ioc
        import re as _re_ioc

        _url_iocs  = iocs[iocs["ioc_type"] == "url"].copy()
        _dom_iocs  = iocs[iocs["ioc_type"] == "domain"].copy()
        _ip_iocs_h = iocs[iocs["ioc_type"].isin(["ip", "ip:port"])].copy()

        _total_url  = len(_url_iocs)
        _total_dom  = len(_dom_iocs)
        _total_ips  = len(_ip_iocs_h)
        _total_hash = len(iocs[iocs["ioc_type"].str.contains("hash|md5|sha", case=False, na=False)])

        # Summary stat row
        _is1, _is2, _is3, _is4, _is5 = st.columns(5)
        _is1.metric("Total IOCs", f"{len(iocs):,}")
        _is2.metric("URLs", f"{_total_url:,}")
        _is3.metric("Domains", f"{_total_dom:,}")
        _is4.metric("IPs", f"{_total_ips:,}")
        _is5.metric("Hashes", f"{_total_hash:,}")

        st.divider()

        # ── URL Intelligence Panel ────────────────────────────────────────────
        if _total_url > 0 or _total_dom > 0:
            st.markdown('<p class="section-label"><i class="bi bi-globe2 bi-sm icon-accent"></i>&nbsp; URL &amp; Domain Intelligence</p>', unsafe_allow_html=True)
            _ui_col1, _ui_col2 = st.columns(2)

            # ── Left: Top hosting domains from URL IOCs ───────────────────────
            with _ui_col1:
                st.markdown("**Top Hosting Domains**")
                # Extract hostname from URL values
                _extracted_domains: list = []
                for _u in _url_iocs["value"].dropna().head(2000):
                    try:
                        _h = _urlparse_ioc(str(_u)).hostname or ""
                        if _h:
                            _extracted_domains.append(_h)
                    except Exception:
                        pass
                # Also include domain IOCs directly
                _extracted_domains += _dom_iocs["value"].dropna().head(1000).tolist()

                if _extracted_domains:
                    import collections
                    _dom_counts = collections.Counter(_extracted_domains).most_common(15)
                    _dom_df = pd.DataFrame(_dom_counts, columns=["domain", "count"])
                    _fig_dom = px.bar(
                        _dom_df, x="count", y="domain", orientation="h",
                        color="count",
                        color_continuous_scale=[[0, "#0d2a4a"], [0.5, "#1e5fa8"], [1, "#38bdf8"]],
                        labels={"domain": "", "count": "IOC count"},
                    )
                    _fig_dom.update_coloraxes(showscale=False)
                    _fig_dom.update_layout(**_PLOTLY_DARK, height=350,
                                          showlegend=False,
                                          yaxis=dict(autorange="reversed"))
                    _fig_dom.update_traces(texttemplate="%{x}", textposition="outside",
                                           textfont_size=10, textfont_color="#c8d8f0")
                    _dom_sel = st.plotly_chart(_fig_dom, on_select="rerun",
                                               use_container_width=True, key="ioc_dom_bar")
                    _drill_dom = None
                    if _dom_sel and _dom_sel.selection and _dom_sel.selection.points:
                        _drill_dom = _dom_sel.selection.points[0].get("y")
                    if _drill_dom:
                        _dom_filter_iocs = _url_iocs[
                            _url_iocs["value"].str.contains(_drill_dom, case=False, na=False)
                        ]
                        _dom_filter_iocs = pd.concat([
                            _dom_filter_iocs,
                            _dom_iocs[_dom_iocs["value"].str.contains(_drill_dom, case=False, na=False)]
                        ])
                        st.markdown(
                            f'<div class="metric-card" style="border-left:3px solid #38bdf8">'
                            f'<b style="color:#c8d8f0">{_drill_dom}</b> — '
                            f'{len(_dom_filter_iocs)} IOC(s)</div>',
                            unsafe_allow_html=True)
                        _dcols = [c for c in ["ioc_type", "value", "malware_family"] if c in _dom_filter_iocs.columns]
                        st.dataframe(_dom_filter_iocs[_dcols].head(30),
                                     use_container_width=True, hide_index=True)
                    else:
                        st.caption("Click a domain bar to see its IOCs")
                else:
                    st.info("Domain extraction pending — URL IOCs will populate this once collected.")

            # ── Right: Malware family distribution for URL/domain IOCs ────────
            with _ui_col2:
                st.markdown("**Malware Families (URL/Domain IOCs)**")
                _fam_pool = pd.concat([_url_iocs, _dom_iocs])
                _fam_pool = _fam_pool[_fam_pool["malware_family"].fillna("") != ""]
                if not _fam_pool.empty:
                    # Explode comma-separated families
                    _fam_series = (
                        _fam_pool["malware_family"]
                        .dropna()
                        .apply(lambda x: [f.strip() for f in str(x).split(",") if f.strip()])
                    )
                    _fam_flat = [f for sublist in _fam_series for f in sublist]
                    import collections as _col2
                    _fam_counts = _col2.Counter(_fam_flat).most_common(15)
                    _fam_df = pd.DataFrame(_fam_counts, columns=["family", "count"])
                    _fig_fam = px.bar(
                        _fam_df, x="count", y="family", orientation="h",
                        color="count",
                        color_continuous_scale=[[0, "#1a0a30"], [0.5, "#7c3aed"], [1, "#c084fc"]],
                        labels={"family": "", "count": "Occurrences"},
                    )
                    _fig_fam.update_coloraxes(showscale=False)
                    _fig_fam.update_layout(**_PLOTLY_DARK, height=350,
                                           showlegend=False,
                                           yaxis=dict(autorange="reversed"))
                    _fam_sel = st.plotly_chart(_fig_fam, on_select="rerun",
                                               use_container_width=True, key="ioc_fam_bar")
                    _drill_fam = None
                    if _fam_sel and _fam_sel.selection and _fam_sel.selection.points:
                        _drill_fam = _fam_sel.selection.points[0].get("y")
                    if _drill_fam:
                        _fam_hits = iocs[
                            iocs["malware_family"].str.contains(_drill_fam, case=False, na=False)
                        ]
                        st.markdown(
                            f'<div class="metric-card" style="border-left:3px solid #c084fc">'
                            f'<b style="color:#c8d8f0">{_drill_fam}</b> — '
                            f'{len(_fam_hits)} IOC(s)</div>',
                            unsafe_allow_html=True)
                        _fcols = [c for c in ["ioc_type", "value", "malware_family"] if c in _fam_hits.columns]
                        st.dataframe(_fam_hits[_fcols].head(30),
                                     use_container_width=True, hide_index=True)
                    else:
                        st.caption("Click a malware family to see its IOCs")
                else:
                    st.info("Malware family data will appear once URL/domain IOCs are tagged.")

            # ── URL status breakdown + recent malicious URLs ──────────────────
            if not _url_iocs.empty:
                with st.expander(f"◉  Recent Malicious URLs  ({min(_total_url, 50)} shown)", expanded=False):
                    _url_display = _url_iocs[["value", "malware_family"]].head(50).copy()
                    _url_display.columns = ["URL", "Malware Family"]
                    # Linkify URLs in a custom HTML table
                    _url_rows_html = ""
                    for _, _ur in _url_display.iterrows():
                        _uval = str(_ur["URL"])
                        _ufam = str(_ur["Malware Family"]) if _ur["Malware Family"] else ""
                        _ufam_badge = f'<span class="badge-medium">{_ufam}</span>' if _ufam else ""
                        # Truncate for display
                        _udisplay = _uval[:80] + "…" if len(_uval) > 80 else _uval
                        _url_rows_html += (
                            f'<tr>'
                            f'<td style="font-family:monospace;font-size:0.75rem;color:#38bdf8;max-width:420px;word-break:break-all">'
                            f'<a href="{_uval}" target="_blank" rel="noopener noreferrer" '
                            f'style="color:#38bdf8;text-decoration:none">{_udisplay}</a></td>'
                            f'<td style="padding-left:12px">{_ufam_badge}</td>'
                            f'</tr>'
                        )
                    st.markdown(
                        f'<table style="width:100%;border-collapse:collapse">'
                        f'<thead><tr>'
                        f'<th style="text-align:left;color:#6e7fa3;font-size:0.75rem;padding-bottom:4px">URL</th>'
                        f'<th style="text-align:left;color:#6e7fa3;font-size:0.75rem;padding-left:12px">Family</th>'
                        f'</tr></thead><tbody>{_url_rows_html}</tbody></table>',
                        unsafe_allow_html=True,
                    )

            # ── IP intel from URL-embedded hosts + geo mini-map ───────────────
            _ioc_rows_for_geo = tuple(
                zip(iocs["ioc_type"].fillna("").tolist(),
                    iocs["value"].fillna("").tolist())
            )
            _hunt_ips = extract_ips_from_iocs(_ioc_rows_for_geo)
            if _hunt_ips:
                with st.expander(f"◉  IP Geolocation  ({len(_hunt_ips)} unique IPs from all IOC types)", expanded=False):
                    _hgeo_df, _hgeo_err = geolocate_ips(_hunt_ips)
                    if not _hgeo_df.empty:
                        _hcc = _hgeo_df["countryCode"].value_counts().to_dict()
                        _hgeo_df["count"] = _hgeo_df["countryCode"].map(_hcc).fillna(1)
                        _fig_hmap = px.scatter_geo(
                            _hgeo_df, lat="lat", lon="lon", size="count",
                            hover_name="country",
                            hover_data={"query": True, "isp": True, "org": True,
                                        "lat": False, "lon": False,
                                        "count": False, "countryCode": False},
                            projection="natural earth", size_max=28,
                        )
                        _fig_hmap.update_traces(
                            marker=dict(color="#38bdf8", opacity=0.80,
                                        line=dict(width=0.5, color="#0a1428")))
                        _fig_hmap.update_geos(
                            bgcolor="#050810", landcolor="#0d1a30",
                            oceancolor="#050810", lakecolor="#050810",
                            coastlinecolor="#1e3a5f", showframe=False,
                            showcoastlines=True, showland=True,
                            showcountries=True, countrycolor="#0f2040",
                        )
                        _fig_hmap.update_layout(
                            paper_bgcolor="#050810",
                            margin=dict(l=0, r=0, t=0, b=0),
                            height=320, font_color="#c8d8f0",
                        )
                        _fig_hmap.update_layout(clickmode="event+select")
                        _hmap_sel = st.plotly_chart(_fig_hmap, on_select="rerun",
                                                    use_container_width=True, key="hunt_geo_map")
                        _drill_hmap_country = None
                        if _hmap_sel and _hmap_sel.selection and _hmap_sel.selection.points:
                            _hmpt = _hmap_sel.selection.points[0]
                            _hmpt_idx = _hmpt.get("point_index", -1)
                            if 0 <= _hmpt_idx < len(_hgeo_df):
                                _drill_hmap_country = _hgeo_df.iloc[_hmpt_idx]["country"]
                        if _drill_hmap_country:
                            _hmap_ips = set(_hgeo_df[_hgeo_df["country"] == _drill_hmap_country]["query"].tolist())
                            _hmap_iocs = iocs[iocs["value"].isin(_hmap_ips)]
                            st.markdown(
                                f'<div class="metric-card" style="border-left:3px solid #38bdf8">'
                                f'\U0001f30d <b style="color:#c8d8f0">{_drill_hmap_country}</b> \u2014 '
                                f'{len(_hmap_ips)} IP(s) \u00b7 {len(_hmap_iocs)} IOC(s)</div>',
                                unsafe_allow_html=True)
                            _hmc = [c for c in ["ioc_type","value","malware_family"] if c in _hmap_iocs.columns]
                            st.dataframe(_hmap_iocs[_hmc].head(20),
                                         use_container_width=True, hide_index=True)
                        _htop = _hgeo_df["country"].value_counts().head(6)
                        _hparts = [f"**{c}** {n}" for c, n in _htop.items()]
                        st.caption("Top origins: " + " · ".join(_hparts))
                        # Country detail table
                        _hcountry_df = _hgeo_df[["country", "countryCode", "query", "isp", "org"]].copy()
                        _hcountry_df.columns = ["Country", "Code", "IP", "ISP", "Org"]
                        st.dataframe(_hcountry_df, use_container_width=True, hide_index=True)
                    else:
                        st.info(f"Geo lookup: {_hgeo_err}")

            st.divider()

        # ── Search / Filter / Enrichment Table ───────────────────────────────
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

        # Load enrichment scores for displayed IOCs
        _ioc_vals = tuple(fi["value"].head(200).tolist()) if not fi.empty else ()
        _enrich_map = load_enrichment_map(_ioc_vals) if _ioc_vals else {}

        # Enrichment table with external links and enrichment badges
        if not fi.empty:
            for _, row in fi.head(200).iterrows():
                itype = str(row.get("ioc_type", ""))
                val   = str(row.get("value", ""))
                fam   = str(row.get("malware_family") or "")
                links = _enrichment_links(itype, val)
                # Build enrichment badge HTML
                _enr = _enrich_map.get(val, {})
                _enr_html = ""
                if _enr:
                    _vt = _enr.get("vt_malicious_count")
                    _gn = _enr.get("greynoise_classification")
                    _sh_ports = _enr.get("shodan_ports")
                    if _vt is not None:
                        _vt_color = "critical" if int(_vt) >= 5 else ("medium" if int(_vt) > 0 else "low")
                        _enr_html += f'<span class="badge-{_vt_color}" title="VirusTotal detections">VT {_vt}</span> '
                    if _gn:
                        _gn_cls = str(_gn).lower()
                        _gn_cls_map = {"malicious": "critical", "benign": "low", "unknown": "info"}
                        _gn_badge = _gn_cls_map.get(_gn_cls, "info")
                        _enr_html += f'<span class="badge-{_gn_badge}" title="GreyNoise">GN {_gn}</span> '
                    if _sh_ports:
                        _ports = str(_sh_ports)[:30]
                        _enr_html += f'<span class="badge-medium" title="Shodan open ports">⊞ {_ports}</span> '
                st.markdown(
                    f'<span class="badge-info">{itype}</span> &nbsp;'
                    f'<span class="ioc-val">{val}</span>'
                    + (f' &nbsp; <span style="color:#6e7fa3;font-size:0.78rem">({fam})</span>' if fam else "")
                    + (f' &nbsp; {_enr_html}' if _enr_html else "")
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
elif active_page == "CVE Tracker":
    st.markdown('<p class="section-label"><i class="bi bi-bug-fill bi-sm icon-error"></i>&nbsp; CVE Tracker</p>', unsafe_allow_html=True)

    # Nav banner when jumping from a dashboard chart
    if "nav_cve_severity" in st.session_state:
        _ncvs = st.session_state["nav_cve_severity"]
        _cve_bc1, _cve_bc2 = st.columns([9, 1])
        with _cve_bc1:
            st.info(f"Drilled from Dashboard — Severity: **{_ncvs}** CVEs")
        with _cve_bc2:
            if st.button("✕ Clear", key="clear_nav_cve"):
                st.session_state.pop("nav_cve_severity", None)
                st.rerun()
        _cve_ai_key = f"cve_ai_{_ncvs}"
        if _cve_ai_key not in st.session_state:
            if st.button(f"Generate AI Analysis for {_ncvs} CVEs",
                         key=f"btn_{_cve_ai_key}", type="primary"):
                with st.spinner("Generating CVE threat analysis…"):
                    st.session_state[_cve_ai_key] = _drill_ai_analysis(
                        "CVE Severity", _ncvs,
                        f"Focus on {_ncvs}-severity vulnerabilities and their exploitation patterns."
                    )
                st.rerun()
        else:
            st.markdown(st.session_state[_cve_ai_key])
            if st.button("Clear Analysis", key=f"clr_{_cve_ai_key}"):
                del st.session_state[_cve_ai_key]
                st.rerun()
        # Pre-populate CVSS slider for that severity tier
        _sev_cvss = {"Critical": 9.0, "High": 7.0, "Medium": 4.0, "Low": 0.0}.get(_ncvs, 0.0)
        st.session_state.setdefault("cve_cvss", _sev_cvss)

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
                fig_c.update_layout(**_PLOTLY_DARK, height=300, clickmode="event+select",
                                    xaxis=dict(tickangle=45, tickfont=dict(size=8)))
                _cve_sc_sel = st.plotly_chart(fig_c, on_select="rerun",
                                              use_container_width=True, key="cve_cvss_scatter")
                if _cve_sc_sel and _cve_sc_sel.selection and _cve_sc_sel.selection.points:
                    _scpt = _cve_sc_sel.selection.points[0]
                    _drill_cve_id = _scpt.get("x") or ""
                    if _drill_cve_id:
                        _dcve = fc[fc["cve_id"] == _drill_cve_id]
                        if not _dcve.empty:
                            _dcve_row = _dcve.iloc[0]
                            st.markdown(
                                f'<div class="metric-card" style="border-left:3px solid #ff8c42">'
                                f'<b style="color:#c8d8f0">{_drill_cve_id}</b> '
                                f'CVSS {_dcve_row.get("cvss_score","?")} \u2014 '
                                f'{_dcve_row.get("vendor","?")} / {_dcve_row.get("product","?")}'
                                f'</div>', unsafe_allow_html=True)
                            st.markdown(
                                f'<div style="font-size:0.82rem;color:#8aa0c0;padding:6px 0">'
                                f'{str(_dcve_row.get("description","No description available."))[:800]}'
                                f'</div>', unsafe_allow_html=True)
                            if _dcve_row.get("cisa_due_date"):
                                st.markdown(
                                    f'<span class="badge-critical">CISA KEV due: {_dcve_row["cisa_due_date"]}</span>',
                                    unsafe_allow_html=True)
                else:
                    st.caption("Click any dot to read the full CVE description")

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
elif active_page == "ATT&CK":
    st.markdown('<p class="section-label"><i class="bi bi-diagram-3-fill bi-sm icon-purple"></i>&nbsp; MITRE ATT&amp;CK Mapping &amp; Remediation</p>', unsafe_allow_html=True)

    # Nav banner when jumping from a dashboard chart
    if "nav_attack_tactic" in st.session_state:
        _nat = st.session_state["nav_attack_tactic"]
        _atk_bc1, _atk_bc2 = st.columns([9, 1])
        with _atk_bc1:
            st.info(f"Drilled from Dashboard — Tactic / TTP: **{_nat}**")
        with _atk_bc2:
            if st.button("✕ Clear", key="clear_nav_attack"):
                st.session_state.pop("nav_attack_tactic", None)
                st.rerun()
        _atk_ai_key = f"attack_ai_{_nat}"
        if _atk_ai_key not in st.session_state:
            if st.button(f"Generate AI Analysis for {_nat}",
                         key=f"btn_{_atk_ai_key}", type="primary"):
                with st.spinner("Generating ATT&CK analysis…"):
                    st.session_state[_atk_ai_key] = _drill_ai_analysis(
                        "ATT&CK Tactic", _nat,
                        f"Explain the {_nat} tactic, observed techniques, and defensive mitigations."
                    )
                st.rerun()
        else:
            st.markdown(st.session_state[_atk_ai_key])
            if st.button("Clear Analysis", key=f"clr_{_atk_ai_key}"):
                del st.session_state[_atk_ai_key]
                st.rerun()

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
                _nav_pivot = hdf.pivot_table(
                    index="Technique", columns="Tactic", values="Count",
                    aggfunc="sum", fill_value=0,
                )
                _nav_tactics = sorted(_nav_pivot.columns.tolist())
                _nav_pivot = _nav_pivot[_nav_tactics]
                _nav_height = max(300, 30 * len(_nav_pivot))
                fig_h = go.Figure(go.Heatmap(
                    z=_nav_pivot.values.tolist(),
                    x=_nav_tactics,
                    y=_nav_pivot.index.tolist(),
                    colorscale=[[0,"#0a1428"],[0.3,"#1e3a6a"],[0.6,"#2563eb"],[0.85,"#7c3aed"],[1,"#dc2626"]],
                    showscale=True,
                    hovertemplate="Technique: %{y}<br>Tactic: %{x}<br>Count: %{z}<extra></extra>",
                ))
                fig_h.update_layout(**_PLOTLY_DARK, height=_nav_height, clickmode="event+select")
                _nav_sel = st.plotly_chart(fig_h, on_select="rerun",
                                           use_container_width=True, key="attack_nav_grid")
                _drill_tid = None
                if _nav_sel and _nav_sel.selection and _nav_sel.selection.points:
                    _drill_tid = _nav_sel.selection.points[0].get("y")
                if _drill_tid and not techniques_df.empty:
                    _dt = techniques_df[techniques_df["technique_id"] == _drill_tid]
                    if not _dt.empty:
                        _dt_row = _dt.iloc[0]
                        _dt_cnt = ttp_usage.get(_drill_tid, {}).get("count", 0) if isinstance(ttp_usage.get(_drill_tid), dict) else ttp_usage.get(_drill_tid, 0)
                        st.markdown(
                            f'<div class="section-label"><i class="bi bi-bullseye icon-purple"></i>'
                            f'&nbsp; <b>{_drill_tid}</b> — {_dt_row["name"]} '
                            f'<span style="color:#38bdf8">({_dt_cnt}× observed)</span></div>',
                            unsafe_allow_html=True)
                        _nav_c1, _nav_c2 = st.columns([2, 3])
                        with _nav_c1:
                            st.markdown(f"**Tactic(s):** {_dt_row.get('tactic','?')}")
                            _desc = str(_dt_row.get("description") or "")
                            st.markdown(_desc[:400] + ("…" if len(_desc) > 400 else ""))
                            st.markdown(f"[↗ MITRE ATT&CK](https://attack.mitre.org/techniques/{_drill_tid.replace('.','/') })")
                        with _nav_c2:
                            if not mitigations_df.empty:
                                _mits = mitigations_df[mitigations_df["technique_id"] == _drill_tid]
                                if not _mits.empty:
                                    st.markdown(f"**{len(_mits)} Mitigation(s):**")
                                    for _, _m in _mits.head(5).iterrows():
                                        st.markdown(
                                            f'<span class="ttp-tag">{_m["mitigation_id"]}</span> '
                                            f'<b style="color:#c8d8f0">{_m["name"]}</b>',
                                            unsafe_allow_html=True)
                else:
                    st.caption("Click any cell to see technique details and mitigations · Color = observation frequency")

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
elif active_page == "AI Analyst":
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
            "Generate a Sigma detection rule for the most common TTP observed.",
        ]
        cols = st.columns(2)
        for i, q in enumerate(starters):
            if cols[i % 2].button(q, key=f"starter_{i}", use_container_width=True):
                # Store the question; the response logic below will pick it up
                st.session_state.analyst_messages.append({"role": "user", "content": q})
                st.rerun()

    # ── Sigma rule quick-generate ─────────────────────────────────────────────
    with st.expander("◆  Quick-generate Sigma detection rules", expanded=False):
        st.markdown(
            '<span style="font-size:0.78rem;color:#5a7fa8;">Generate YAML Sigma rules from your top observed TTPs — '
            'ready to import into Splunk, Elastic, or any Sigma-compatible SIEM.</span>',
            unsafe_allow_html=True,
        )
        _sigma_c1, _sigma_c2 = st.columns([3, 1])
        with _sigma_c1:
            _top_ttps = sorted(ttp_usage.items(), key=lambda x: -(x[1].get("count", 0) if isinstance(x[1], dict) else int(x[1])))[:10]
            _ttp_opts = [f"{t} ({v.get('count',0) if isinstance(v, dict) else v}×)" for t, v in _top_ttps]
            _sel_ttp  = st.selectbox("Select TTP to generate rule for", ["— choose —"] + _ttp_opts, key="sigma_sel")
        with _sigma_c2:
            st.markdown("<br>", unsafe_allow_html=True)
            _sigma_btn = st.button("Generate Sigma Rule", key="sigma_btn", use_container_width=True)
        if _sigma_btn and _sel_ttp and _sel_ttp != "— choose —":
            _ttp_id = _sel_ttp.split(" ")[0]
            _sigma_prompt = (
                f"Generate a complete, production-ready Sigma YAML detection rule for MITRE ATT&CK technique {_ttp_id}. "
                "Include: title, id (random UUID), status: experimental, description, references (MITRE URL), "
                "logsource (product: windows or linux as appropriate), detection with condition, "
                "falsepositives list, level (critical/high/medium/low), and tags (attack.technique). "
                "Output ONLY valid YAML, no explanations."
            )
            st.session_state.analyst_messages.append({"role": "user", "content": _sigma_prompt})
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
# DARK WEB MONITOR
# ══════════════════════════════════════════════════════════════════════════════
elif active_page == "Dark Web":
    # Read from DB-backed platform settings (Admin tab writes here)
    # Fall back to env var only if DB has never been written
    _dw_cfg = load_platform_settings()
    _dw_enabled = _dw_cfg.get("dark_web_enabled", "false").lower() in ("1", "true", "yes")
    _dw_keywords_raw = _dw_cfg.get("dark_web_keywords", "") or os.getenv("DARK_WEB_KEYWORDS", "")
    _dw_keywords = [k.strip() for k in _dw_keywords_raw.split(",") if k.strip()]

    # ── Header ────────────────────────────────────────────────────────────────
    st.markdown("""
<div class="dw-header">
  <svg width="36" height="36" viewBox="0 0 36 36" fill="none" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <linearGradient id="dwg" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#954ce9"/>
        <stop offset="100%" stop-color="#c084fc"/>
      </linearGradient>
      <filter id="dwglow">
        <feGaussianBlur stdDeviation="1.5" result="b"/>
        <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
      </filter>
    </defs>
    <circle cx="18" cy="18" r="16" stroke="url(#dwg)" stroke-width="1.2" fill="none" filter="url(#dwglow)"/>
    <circle cx="18" cy="18" r="10" stroke="url(#dwg)" stroke-width="0.7" fill="none" opacity="0.4"/>
    <circle cx="18" cy="18" r="4"  stroke="url(#dwg)" stroke-width="0.7" fill="none" opacity="0.3"/>
    <line x1="18" y1="2"  x2="18" y2="8"  stroke="#954ce9" stroke-width="1.8" stroke-linecap="round"/>
    <line x1="18" y1="28" x2="18" y2="34" stroke="#c084fc" stroke-width="1.8" stroke-linecap="round"/>
    <line x1="2"  y1="18" x2="8"  y2="18" stroke="#954ce9" stroke-width="1.8" stroke-linecap="round"/>
    <line x1="28" y1="18" x2="34" y2="18" stroke="#c084fc" stroke-width="1.8" stroke-linecap="round"/>
  </svg>
  <div>
    <div style="font-size:1.1rem;font-weight:800;color:#d0baff;letter-spacing:0.05em;text-transform:uppercase;">
      Dark Web Monitor
    </div>
    <div style="font-size:0.62rem;color:#5a3a80;font-family:'JetBrains Mono',monospace;letter-spacing:0.15em;margin-top:3px;">
      METADATA ONLY &nbsp;·&nbsp; NO BREACH CONTENT STORED &nbsp;·&nbsp; DEFENSIVE RESEARCH
    </div>
  </div>
  <div style="margin-left:auto;display:flex;gap:10px;align-items:center;">
    <span class="dw-tor-badge"><span class="dw-tor-dot"></span>TOR PROXY</span>
  </div>
</div>
""", unsafe_allow_html=True)

    # ── Config banner ─────────────────────────────────────────────────────────
    if not _dw_enabled:
        st.info(
            "**Dark Web Monitor is not yet enabled.** "
            "Open the **⚙ Admin** tab (far right of the tab strip above), "
            "toggle **Enable Dark Web Monitoring**, add your keywords, and click **Save**. "
            "Changes take effect on the collector's next run — no server restart needed."
        )
    else:
        if _dw_keywords:
            kw_pills = "".join(f'<span class="kw-pill">{k}</span>' for k in _dw_keywords)
            st.markdown(
                f'<div style="margin-bottom:12px;">Monitoring: {kw_pills}</div>',
                unsafe_allow_html=True,
            )

    # ── KPI strip ─────────────────────────────────────────────────────────────
    dw1, dw2, dw3, dw4 = st.columns(4)
    if not darkweb_df.empty:
        total_mentions   = len(darkweb_df)
        critical_high    = int(darkweb_df["severity"].isin(["critical", "high"]).sum())
        from datetime import timedelta
        _24h_ago = pd.Timestamp.now(tz="UTC") - timedelta(hours=24)
        # Ensure first_seen is tz-aware for comparison
        _fs = pd.to_datetime(darkweb_df["first_seen"], utc=True, errors="coerce")
        new_24h = int((_fs >= _24h_ago).sum())
        unique_kw = int(darkweb_df["keyword_matched"].nunique())
    else:
        total_mentions = critical_high = new_24h = unique_kw = 0

    with dw1: st.metric("Total Mentions",    f"{total_mentions:,}")
    with dw2: st.metric("Critical / High",   f"{critical_high:,}")
    with dw3: st.metric("New (24 h)",        f"{new_24h:,}")
    with dw4: st.metric("Keywords Watched",  f"{unique_kw:,}" if not darkweb_df.empty else f"{len(_dw_keywords):,}")

    st.divider()

    if darkweb_df.empty:
        if _dw_enabled:
            st.info("No dark web mentions found yet — the collector will scan at its next scheduled interval.")
    else:
        # ── Alert ticker for critical/high ────────────────────────────────────
        _alerts = darkweb_df[darkweb_df["severity"].isin(["critical", "high"])].head(5)
        if not _alerts.empty:
            st.markdown('<p class="section-label"><i class="bi bi-exclamation-triangle-fill bi-sm icon-error"></i>&nbsp; Active Alerts</p>', unsafe_allow_html=True)
            for _, row in _alerts.iterrows():
                sev    = str(row.get("severity", "medium"))
                kw     = str(row.get("keyword_matched", ""))
                ttl    = str(row.get("title", ""))[:120]
                src    = str(row.get("source_name", ""))
                ts     = row.get("first_seen")
                ts_str = ts.strftime("%Y-%m-%d %H:%M") if hasattr(ts, "strftime") else "—"
                badge  = f'<span class="badge-{sev}">{sev.upper()}</span>'
                st.markdown(f"""
<div class="dw-mention-card {sev}">
  <div class="dw-title">{badge}&nbsp; {ttl}</div>
  <div class="dw-meta">
    <i class="bi bi-broadcast"></i> {src} &nbsp;·&nbsp;
    <i class="bi bi-key-fill icon-purple"></i> {kw} &nbsp;·&nbsp;
    <i class="bi bi-clock icon-muted"></i> {ts_str}
  </div>
</div>""", unsafe_allow_html=True)
            st.divider()

        # ── Timeline chart ────────────────────────────────────────────────────
        st.markdown('<p class="section-label"><i class="bi bi-graph-up bi-sm icon-purple"></i>&nbsp; Mention Timeline</p>', unsafe_allow_html=True)
        _timeline_df = darkweb_df.copy()
        _timeline_df["date"] = pd.to_datetime(_timeline_df["first_seen"], utc=True, errors="coerce").dt.floor("D")
        _tl = _timeline_df.groupby(["date", "severity"]).size().reset_index(name="count")
        if not _tl.empty:
            _sev_colors = {"critical": "#ff4d6d", "high": "#ff8c42", "medium": "#ffd166", "low": "#06d6a0"}
            fig_tl = px.bar(
                _tl, x="date", y="count", color="severity",
                color_discrete_map=_sev_colors,
                labels={"date": "Date", "count": "Mentions", "severity": "Severity"},
                barmode="stack",
            )
            fig_tl.update_layout(**_PLOTLY_DARK, height=220)
            fig_tl.update_traces(hovertemplate="%{x|%b %d}: %{y} mentions<extra></extra>")
            st.plotly_chart(fig_tl, use_container_width=True)

        # ── Severity & keyword breakdown ──────────────────────────────────────
        col_sev, col_kw = st.columns(2)
        with col_sev:
            st.markdown("#### By Severity")
            sev_counts = darkweb_df["severity"].value_counts().reset_index()
            sev_counts.columns = ["Severity", "Count"]
            _sc = {"critical": "#ff4d6d", "high": "#ff8c42", "medium": "#ffd166", "low": "#06d6a0"}
            fig_sev = px.pie(
                sev_counts, names="Severity", values="Count", hole=0.55,
                color="Severity", color_discrete_map=_sc,
            )
            fig_sev.update_layout(**_PLOTLY_DARK, height=260, showlegend=True)
            fig_sev.update_traces(textposition="outside", textinfo="percent+label",
                                  hovertemplate="%{label}: %{value}<extra></extra>")
            st.plotly_chart(fig_sev, use_container_width=True)

        with col_kw:
            st.markdown("#### Hits per Keyword")
            kw_counts = darkweb_df["keyword_matched"].value_counts().reset_index()
            kw_counts.columns = ["Keyword", "Hits"]
            fig_kw = px.bar(
                kw_counts, x="Hits", y="Keyword", orientation="h",
                color="Hits", color_continuous_scale=[[0, "#2d1458"], [1, "#954ce9"]],
            )
            fig_kw.update_coloraxes(showscale=False)
            fig_kw.update_layout(**_PLOTLY_DARK, height=260)
            st.plotly_chart(fig_kw, use_container_width=True)

        st.divider()

        # ── Filters ──────────────────────────────────────────────────────────
        st.markdown('<p class="section-label"><i class="bi bi-funnel-fill bi-sm icon-purple"></i>&nbsp; Mention Details</p>', unsafe_allow_html=True)
        _fc1, _fc2, _fc3 = st.columns([2, 2, 2])
        with _fc1:
            _sev_filter = st.multiselect(
                "Severity", ["critical", "high", "medium", "low"],
                default=["critical", "high", "medium", "low"],
                key="dw_sev_filter",
            )
        with _fc2:
            _kw_opts = ["All"] + sorted(darkweb_df["keyword_matched"].dropna().unique().tolist())
            _kw_filter = st.selectbox("Keyword", _kw_opts, key="dw_kw_filter")
        with _fc3:
            _src_opts = ["All"] + sorted(darkweb_df["source_name"].dropna().unique().tolist())
            _src_filter = st.selectbox("Source", _src_opts, key="dw_src_filter")

        _filtered = darkweb_df[darkweb_df["severity"].isin(_sev_filter)]
        if _kw_filter != "All":
            _filtered = _filtered[_filtered["keyword_matched"] == _kw_filter]
        if _src_filter != "All":
            _filtered = _filtered[_filtered["source_name"] == _src_filter]

        st.caption(f"Showing {len(_filtered):,} of {len(darkweb_df):,} mentions")

        # ── Mention cards ─────────────────────────────────────────────────────
        for _, row in _filtered.head(50).iterrows():
            sev         = str(row.get("severity", "medium"))
            title_txt   = str(row.get("title", "Untitled"))[:200]
            source_name = str(row.get("source_name", ""))
            source_url  = str(row.get("source_url", ""))
            keyword     = str(row.get("keyword_matched", ""))
            actor       = str(row.get("actor_handle", "Unknown"))
            rec_est     = row.get("record_estimate")
            snippet_txt = str(row.get("snippet", ""))[:300]
            ai_sum      = str(row.get("ai_summary", ""))
            dtypes_raw  = row.get("data_types") or []
            dtypes_list = dtypes_raw if isinstance(dtypes_raw, list) else []
            ts          = row.get("first_seen")
            ts_str      = ts.strftime("%Y-%m-%d %H:%M UTC") if hasattr(ts, "strftime") else "—"
            badge_html  = f'<span class="badge-{sev}">{sev.upper()}</span>'
            dtype_html  = " ".join(f'<span class="feed-tag">{d}</span>' for d in dtypes_list[:6])
            rec_html    = f'&nbsp;·&nbsp;<i class="bi bi-database icon-muted"></i> {rec_est}' if rec_est else ""

            with st.expander(f"{sev.upper()[:1]} · {title_txt[:100]}", expanded=False):
                st.markdown(f"""
<div>
  <div style="margin-bottom:8px;">{badge_html} &nbsp; {dtype_html}</div>
  <div class="dw-meta" style="margin-bottom:6px;">
    <i class="bi bi-broadcast icon-purple"></i>&nbsp;<strong>{source_name}</strong>
    &nbsp;·&nbsp;<i class="bi bi-clock icon-muted"></i>&nbsp;{ts_str}
    {rec_html}
  </div>
  {'<div class="dw-actor"><i class="bi bi-person-fill icon-purple"></i>&nbsp;Actor: ' + actor + '</div>' if actor not in ('Unknown', '') else ''}
  {'<div class="dw-snippet">' + snippet_txt + '</div>' if snippet_txt else ''}
  {'<div style="margin-top:8px;padding:8px 12px;background:rgba(149,76,233,0.06);border-radius:6px;font-size:0.78rem;color:#9070b0;"><i class="bi bi-cpu icon-purple"></i>&nbsp;<strong>AI Analysis:</strong> ' + ai_sum + '</div>' if ai_sum else ''}
</div>""", unsafe_allow_html=True)
                if source_url and (".onion" in source_url or source_url.startswith("http")):
                    st.markdown(
                        f'<div style="margin-top:8px;"><i class="bi bi-box-arrow-up-right icon-muted"></i>'
                        f'&nbsp;<a href="{source_url}" target="_blank" style="color:#6040a0;font-size:0.75rem;">'
                        f'View source (opens in new tab)</a></div>',
                        unsafe_allow_html=True,
                    )

        if _filtered.empty:
            st.info("No mentions match the current filters.")


# ══════════════════════════════════════════════════════════════════════════════
# WATCHLIST
# ══════════════════════════════════════════════════════════════════════════════
elif active_page == "Watchlist":
    st.markdown('<p class="section-label"><i class="bi bi-crosshair bi-sm icon-accent"></i>&nbsp; Asset Watchlist</p>', unsafe_allow_html=True)

    # Nav banner when jumping from a dashboard chart
    if "nav_watchlist_date" in st.session_state:
        _nwd = st.session_state["nav_watchlist_date"]
        _wl_bc1, _wl_bc2 = st.columns([9, 1])
        with _wl_bc1:
            st.info(f"Drilled from Dashboard — Watchlist hits on: **{_nwd}**")
        with _wl_bc2:
            if st.button("✕ Clear", key="clear_nav_wl"):
                st.session_state.pop("nav_watchlist_date", None)
                st.rerun()

    wl_c1, wl_c2 = st.columns([3, 1])
    with wl_c2:
        st.markdown("#### Add Asset")
        _new_type  = st.selectbox("Type", ["domain", "ip", "cidr", "email_domain", "keyword"], key="wl_new_type")
        _new_value = st.text_input("Value", placeholder="acmecorp.com / 1.2.3.4 / 10.0.0.0/8", key="wl_new_val")
        _new_label = st.text_input("Label (optional)", placeholder="Primary domain", key="wl_new_label")
        if st.button("➕  Add to Watchlist", key="wl_add", use_container_width=True, type="primary"):
            if _new_value.strip():
                try:
                    from sqlalchemy import text as _text
                    _engine = get_engine()
                    with _engine.connect() as _conn:
                        _conn.execute(_text(
                            """INSERT INTO watched_assets (asset_type, value, label, active)
                               VALUES (:t, :v, :l, true)
                               ON CONFLICT DO NOTHING"""
                        ), {"t": _new_type, "v": _new_value.strip(), "l": _new_label.strip() or None})
                        _conn.commit()
                    load_watchlist_data.clear()
                    st.success(f"Added {_new_type}: {_new_value.strip()}")
                    st.rerun()
                except Exception as _e:
                    st.error(f"Failed: {_e}")
            else:
                st.warning("Value cannot be empty.")

    with wl_c1:
        if watchlist_df.empty:
            st.info("No assets being watched yet. Add your first asset using the form →")
        else:
            # Type filter
            _wl_types = ["All"] + sorted(watchlist_df["asset_type"].dropna().unique().tolist())
            _wl_type_filter = st.selectbox("Filter by type", _wl_types, key="wl_type_filter")
            _wl_show = watchlist_df if _wl_type_filter == "All" else watchlist_df[watchlist_df["asset_type"] == _wl_type_filter]

            # Summary pills
            _type_counts = watchlist_df["asset_type"].value_counts()
            _pill_html = "".join(
                f'<span class="kw-pill">{t} ({c})</span>'
                for t, c in _type_counts.items()
            )
            st.markdown(f'<div style="margin-bottom:12px;">{_pill_html}</div>', unsafe_allow_html=True)

            for _, asset in _wl_show.iterrows():
                _atype = str(asset.get("asset_type", ""))
                _aval  = str(asset.get("value", ""))        # column is "value" in watched_assets
                _albl  = str(asset.get("label") or "")
                _aid   = asset.get("id")
                _active = bool(asset.get("active", True))

                _hit_count = int((hits_df["watched_asset_id"] == _aid).sum()) if not hits_df.empty and "watched_asset_id" in hits_df.columns else 0

                _btn_key = f"wl_del_{_aid}"
                col_card, col_del = st.columns([10, 1])
                with col_card:
                    st.markdown(f"""
<div class="watchlist-card {_atype}">
  <div class="wl-type">{_atype}</div>
  <div>
    <div class="wl-value">{_aval}</div>
    {'<div class="wl-label">' + _albl + '</div>' if _albl else ''}
  </div>
  <div style="margin-left:auto;text-align:right;">
    <span class="{'badge-critical' if _hit_count > 0 else 'badge-info'}" title="Total hits">{_hit_count} hit{'s' if _hit_count != 1 else ''}</span>
    {'<span class="badge-low" style="margin-left:4px;">ACTIVE</span>' if _active else '<span class="badge-medium" style="margin-left:4px;">PAUSED</span>'}
  </div>
</div>""", unsafe_allow_html=True)
                with col_del:
                    if st.button("✕", key=_btn_key, help="Remove from watchlist"):
                        try:
                            from sqlalchemy import text as _text
                            _engine = get_engine()
                            with _engine.connect() as _conn:
                                _conn.execute(_text("DELETE FROM watched_assets WHERE id = :id"), {"id": int(_aid)})
                                _conn.commit()
                            load_watchlist_data.clear()
                            st.rerun()
                        except Exception as _e:
                            st.error(str(_e))


# ══════════════════════════════════════════════════════════════════════════════
# ALERTS
# ══════════════════════════════════════════════════════════════════════════════
elif active_page == "Alerts":
    st.markdown('<p class="section-label"><i class="bi bi-bell-fill bi-sm icon-error"></i>&nbsp; Watchlist Alerts</p>', unsafe_allow_html=True)

    if hits_df.empty:
        st.info(
            "No watchlist hits yet. Once the collector detects matches between your "
            "watched assets (⚑ Watchlist tab) and incoming IOC feeds, alerts appear here."
        )
    else:
        from datetime import timedelta as _td
        # KPI strip
        al1, al2, al3, al4 = st.columns(4)
        _total_hits   = len(hits_df)
        _open_hits    = int((hits_df["alerted"] == False).sum()) if "alerted" in hits_df.columns else _total_hits
        _crit_hits    = int(hits_df["severity"].isin(["critical", "high"]).sum()) if "severity" in hits_df.columns else 0
        _24h_cut      = pd.Timestamp.now(tz="UTC") - _td(hours=24)
        _hit_ts       = pd.to_datetime(hits_df.get("found_at", pd.Series(dtype="object")), utc=True, errors="coerce")
        _new_24h_hits = int((_hit_ts >= _24h_cut).sum())
        with al1: st.metric("Total Hits",     f"{_total_hits:,}")
        with al2: st.metric("Unacknowledged", f"{_open_hits:,}")
        with al3: st.metric("Critical / High",f"{_crit_hits:,}")
        with al4: st.metric("New (24 h)",     f"{_new_24h_hits:,}")

        st.divider()

        # Filters
        _af1, _af2, _af3 = st.columns(3)
        with _af1:
            _sev_opts = sorted(hits_df["severity"].dropna().unique().tolist()) if "severity" in hits_df.columns else []
            _al_sev = st.multiselect("Severity", _sev_opts, default=_sev_opts, key="al_sev")
        with _af2:
            _at_opts = ["All"] + sorted(hits_df["asset_type"].dropna().unique().tolist()) if "asset_type" in hits_df.columns else ["All"]
            _al_type = st.selectbox("Asset Type", _at_opts, key="al_type")
        with _af3:
            _al_unack = st.checkbox("Unacknowledged only", value=False, key="al_unack")

        _fhits = hits_df.copy()
        if _al_sev and "severity" in _fhits.columns:
            _fhits = _fhits[_fhits["severity"].isin(_al_sev)]
        if _al_type != "All" and "asset_type" in _fhits.columns:
            _fhits = _fhits[_fhits["asset_type"] == _al_type]
        if _al_unack and "alerted" in _fhits.columns:
            _fhits = _fhits[_fhits["alerted"] == False]

        st.caption(f"Showing {min(len(_fhits), 100)} of {len(_fhits):,} hits")

        for _, hit in _fhits.head(100).iterrows():
            _sev     = str(hit.get("severity", "medium"))
            _aval    = str(hit.get("asset_value", ""))   # aliased from wa.value
            _atype   = str(hit.get("asset_type", ""))
            _albl    = str(hit.get("label") or "")
            _ioc_val = str(hit.get("matched_value", "")) # model col: matched_value
            _src     = str(hit.get("source_feed", ""))   # model col: source_feed
            _ctx     = str(hit.get("context") or "")[:300]  # model col: context
            _ts      = hit.get("found_at")               # model col: found_at
            _ts_str  = _ts.strftime("%Y-%m-%d %H:%M UTC") if hasattr(_ts, "strftime") else "—"
            _badge   = f'<span class="badge-{_sev}">{_sev.upper()}</span>'
            _alerted = bool(hit.get("alerted", False))
            _alerted_html = '<span style="font-size:0.68rem;color:#3d5a80;margin-left:8px;">✓ sent</span>' if _alerted else ""

            st.markdown(f"""
<div class="alert-card {_sev}">
  <div class="alert-title">{_badge}{_alerted_html} &nbsp; <span class="wl-type">{_atype}</span> <span style="color:#c8d8f0">{_aval}</span>
    {(' · <span style="color:#5a7fa8;font-size:0.78rem;">' + _albl + '</span>') if _albl else ''}
  </div>
  <div class="alert-meta">
    <i class="bi bi-crosshair"></i>&nbsp;IOC: <span class="ioc-val">{_ioc_val}</span> &nbsp;·&nbsp;
    <i class="bi bi-broadcast"></i>&nbsp;{_src} &nbsp;·&nbsp;
    <i class="bi bi-clock"></i>&nbsp;{_ts_str}
  </div>
  {'<div class="alert-ctx">' + _ctx + '</div>' if _ctx else ''}
</div>""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# CAMPAIGNS
# ══════════════════════════════════════════════════════════════════════════════
elif active_page == "Campaigns":
    st.markdown('<p class="section-label"><i class="bi bi-diagram-2-fill bi-sm icon-accent"></i>&nbsp; Campaign Tracker</p>', unsafe_allow_html=True)

    cam_c1, cam_c2 = st.columns([3, 1])
    with cam_c2:
        st.markdown("#### New Campaign")
        _cam_name  = st.text_input("Campaign name", key="cam_name_in", placeholder="Operation ShadowVault")
        _cam_actor = st.text_input("Threat actor", key="cam_actor_in", placeholder="APT28")
        _cam_obj   = st.text_input("Objective", key="cam_obj_in",   placeholder="Espionage / Data exfil")
        _cam_status = st.selectbox("Status", ["active", "monitoring", "resolved"], key="cam_status_in")
        _cam_desc  = st.text_area("Description", key="cam_desc_in", height=80)
        if st.button("➕  Create Campaign", key="cam_create", use_container_width=True, type="primary"):
            if _cam_name.strip():
                try:
                    from sqlalchemy import text as _text
                    _engine = get_engine()
                    with _engine.connect() as _conn:
                        # "objective" not a column — prepend to description
                        _obj_txt = _cam_obj.strip()
                        _desc_txt = _cam_desc.strip()
                        if _obj_txt and _desc_txt:
                            _full_desc = f"Objective: {_obj_txt}\n\n{_desc_txt}"
                        elif _obj_txt:
                            _full_desc = f"Objective: {_obj_txt}"
                        else:
                            _full_desc = _desc_txt or None
                        _conn.execute(_text(
                            """INSERT INTO campaigns (name, threat_actor, status, description, first_seen)
                               VALUES (:n, :a, :s, :d, NOW())
                               ON CONFLICT DO NOTHING"""
                        ), {"n": _cam_name.strip(), "a": _cam_actor.strip() or None,
                            "s": _cam_status, "d": _full_desc})
                        _conn.commit()
                    load_campaigns_data.clear()
                    st.success("Campaign created.")
                    st.rerun()
                except Exception as _e:
                    st.error(f"Failed: {_e}")
            else:
                st.warning("Campaign name is required.")

    with cam_c1:
        if campaigns_df.empty:
            st.info("No campaigns tracked yet. Create your first campaign using the form →")
        else:
            # Summary metrics
            _cm1, _cm2, _cm3 = st.columns(3)
            _active_camp = int((campaigns_df["status"] == "active").sum()) if "status" in campaigns_df.columns else 0
            with _cm1: st.metric("Total Campaigns", len(campaigns_df))
            with _cm2: st.metric("Active",          _active_camp)
            with _cm3: st.metric("Actors Tracked",  int(campaigns_df["threat_actor"].dropna().nunique()) if "threat_actor" in campaigns_df.columns else 0)

            st.divider()

            _stat_filter = st.selectbox("Filter by status", ["All", "active", "monitoring", "resolved"], key="cam_stat_filter")
            _cam_show = campaigns_df if _stat_filter == "All" else campaigns_df[campaigns_df["status"] == _stat_filter]

            for _, camp in _cam_show.iterrows():
                _cname   = str(camp.get("name", "Unnamed Campaign"))
                _cactor  = str(camp.get("threat_actor") or "Unknown")
                _cobj    = ""   # no separate objective column; merged into description
                _cstat   = str(camp.get("status", "unknown"))
                _cdesc   = str(camp.get("description") or "")
                _cstart  = camp.get("first_seen")
                _clast   = camp.get("last_seen")
                _cs_str  = _cstart.strftime("%Y-%m-%d") if hasattr(_cstart, "strftime") else "?"
                _cl_str  = _clast.strftime("%Y-%m-%d") if hasattr(_clast, "strftime") else "ongoing"
                _stat_color = {"active": "#ff4d6d", "monitoring": "#ffd166", "resolved": "#06d6a0"}.get(_cstat, "#38bdf8")

                st.markdown(f"""
<div class="campaign-card">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">
    <div class="campaign-name">{_cname}</div>
    <span style="font-size:0.68rem;font-weight:800;text-transform:uppercase;letter-spacing:0.08em;
                 padding:2px 10px;border-radius:20px;background:rgba(0,0,0,0.3);
                 border:1px solid {_stat_color};color:{_stat_color};">{_cstat.upper()}</span>
  </div>
  <div class="campaign-meta">
    <i class="bi bi-person-badge-fill" style="color:#60a5fa"></i>&nbsp;{_cactor}
    {('&nbsp;·&nbsp;<i class="bi bi-bullseye"></i>&nbsp;' + _cobj) if _cobj else ''}
    &nbsp;·&nbsp;<i class="bi bi-calendar3"></i>&nbsp;{_cs_str} → {_cl_str}
  </div>
  {'<div class="campaign-desc">' + _cdesc[:300] + ('…' if len(_cdesc) > 300 else '') + '</div>' if _cdesc else ''}
</div>""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# THREAT ADVISOR
# ══════════════════════════════════════════════════════════════════════════════
elif active_page == "Threat Advisor":
    st.markdown(
        '<p class="section-label">'
        '<i class="bi bi-cpu-fill bi-sm icon-accent"></i>'
        '&nbsp; AI Threat Advisor &mdash; Proactive Asset Intelligence</p>',
        unsafe_allow_html=True,
    )

    # ── Prerequisites status panel ────────────────────────────────────────────
    _pre_feeds_ok   = not reports.empty
    _pre_assets_ok  = not (load_watchlist_data()[0].empty if callable(load_watchlist_data) else True)
    _pre_briefing   = not _briefing_df.empty
    _pre_profiles   = not _profiles_df.empty

    # Check AI backend availability
    _pre_ai_ok = bool(
        os.getenv("CLAUDE_API_KEY", "") or
        os.getenv("GEMINI_API_KEY", "") or
        os.getenv("OLLAMA_URL", "")
    )

    _all_good = _pre_feeds_ok and _pre_assets_ok

    if not _all_good:
        st.markdown(
            '<div style="background:rgba(255,209,102,0.07);border:1px solid #ffd166;'
            'border-radius:8px;padding:14px 18px;margin-bottom:12px">',
            unsafe_allow_html=True,
        )
        st.markdown("**⚙ Setup Checklist** — complete these steps to activate the Threat Advisor")

        def _chk(ok: bool, label: str, fix: str = ""):
            icon  = '<i class="bi bi-check-circle-fill icon-ok" style="font-size:0.9rem"></i>' if ok else '<i class="bi bi-circle" style="font-size:0.9rem;color:#ffd166"></i>'
            color = "#06d6a0" if ok else "#ffd166"
            note  = (
                ' <span style="font-size:0.72rem;color:#3d5a80">— ' + fix + "</span>"
                if fix and not ok else ""
            )
            st.markdown(
                '<div style="font-size:0.83rem;color:' + color + ';padding:2px 0">'
                + icon + "&nbsp; " + label + note + "</div>",
                unsafe_allow_html=True,
            )

        _feed_count = len(reports) if not reports.empty else 0
        _chk(_pre_feeds_ok,
             "Threat feeds have collected data  (" + str(_feed_count) + " reports)",
             "Feeds run automatically — check ◎ Feed Health tab for status")

        try:
            _wa_df, _ = load_watchlist_data()
            _asset_count = len(_wa_df) if not _wa_df.empty else 0
        except Exception:
            _asset_count = 0
        _chk(_asset_count > 0,
             "Watched assets added to Watchlist  (" + str(_asset_count) + " assets)",
             "Go to ⚑ Watchlist tab → add your domains, IPs, company names, or keywords")

        _chk(_pre_ai_ok,
             "AI backend configured  (Ollama / Claude / Gemini)",
             "Set CLAUDE_API_KEY or GEMINI_API_KEY in .env, or run Ollama locally — "
             "briefings generate without AI but assessments will be heuristic only")

        _chk(_pre_briefing,
             "First daily briefing generated",
             "Happens automatically after feeds collect data — or click Research Now below")

        _chk(_pre_profiles,
             "Asset threat profiles assessed",
             "Requires watched assets + at least one feed cycle to complete")

        st.markdown("</div>", unsafe_allow_html=True)

    # ── Research Now button ───────────────────────────────────────────────────
    _adv_col_btn, _adv_col_info = st.columns([1, 4])
    with _adv_col_btn:
        if st.button("⟳  Research Now", key="adv_refresh", type="primary"):
            # Write a flag to platform_settings so the collector bypasses its
            # 1-hour rate limit and runs a research cycle on next loop (≤30 s).
            try:
                with get_engine().begin() as _rc:
                    _rc.execute(
                        __import__("sqlalchemy").text(
                            "INSERT INTO platform_settings (key, value, updated_by) "
                            "VALUES ('research_requested', 'true', 'webui') "
                            "ON CONFLICT (key) DO UPDATE SET value='true', "
                            "updated_at=now(), updated_by='webui'"
                        )
                    )
                st.success("✓ Research cycle queued — results appear within ~30 seconds. "
                           "Refresh this tab after a moment.", icon="🔬")
            except Exception as _re:
                st.warning("Could not queue research: " + str(_re))
            load_threat_advisor_data.clear()
            load_org_risk_score.clear()

    with _adv_col_info:
        _last_research_str = ""
        if not _profiles_df.empty and "last_assessed" in _profiles_df.columns:
            try:
                _lr = pd.to_datetime(_profiles_df["last_assessed"].max(), utc=True)
                _last_research_str = "Last run: " + _lr.strftime("%Y-%m-%d %H:%M UTC") + " · "
            except Exception:
                pass
        st.markdown(
            '<span style="font-size:0.8rem;color:#3d5a80">'
            + _last_research_str +
            'The AI agent runs automatically every hour, matching your watched assets against '
            'all live threat feeds. <b>Research Now</b> triggers an immediate cycle '
            '(results in ≤30 s).</span>',
            unsafe_allow_html=True,
        )

    st.divider()

    # ── Org-wide risk gauge row ───────────────────────────────────────────────
    _adv_r1, _adv_r2, _adv_r3, _adv_r4 = st.columns(4)

    _risk_color_map = {
        "critical": "#ff4d6d", "high": "#ff8c42",
        "medium": "#ffd166", "low": "#06d6a0",
    }

    def _risk_level_from_score(s: int) -> str:
        if s >= 75: return "critical"
        if s >= 50: return "high"
        if s >= 25: return "medium"
        return "low"

    _org_risk_level = _risk_level_from_score(_org_risk)
    _org_risk_color = _risk_color_map.get(_org_risk_level, "#38bdf8")

    with _adv_r1:
        _fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=_org_risk,
            title={"text": "Org Risk Score", "font": {"color": "#8aa0c0", "size": 13}},
            number={"font": {"color": _org_risk_color, "size": 32}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": "#1e3a5f"},
                "bar": {"color": _org_risk_color, "thickness": 0.3},
                "bgcolor": "#050810",
                "bordercolor": "#1e3a5f",
                "steps": [
                    {"range": [0, 25],  "color": "#051520"},
                    {"range": [25, 50], "color": "#0a2030"},
                    {"range": [50, 75], "color": "#1a1505"},
                    {"range": [75, 100], "color": "#1f0508"},
                ],
                "threshold": {"line": {"color": _org_risk_color, "width": 3},
                              "thickness": 0.8, "value": _org_risk},
            },
        ))
        _fig_gauge.update_layout(
            paper_bgcolor="#050810", font_color="#c8d8f0",
            height=200, margin=dict(l=20, r=20, t=30, b=10),
        )
        st.plotly_chart(_fig_gauge, use_container_width=True)

    _at_risk_count = len(_profiles_df[_profiles_df["risk_score"] >= 25]) if not _profiles_df.empty else 0
    _crit_count    = len(_profiles_df[_profiles_df["risk_level"] == "critical"]) if not _profiles_df.empty else 0
    _total_assets  = len(_profiles_df) if not _profiles_df.empty else 0
    _briefing_time = ""
    if not _briefing_df.empty and "generated_at" in _briefing_df.columns:
        try:
            _bt = pd.to_datetime(_briefing_df.iloc[0]["generated_at"], utc=True)
            _briefing_time = _bt.strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            pass

    with _adv_r2:
        st.markdown(
            '<div class="metric-card">'
            '<div style="font-size:0.75rem;color:#6e7fa3">Assets at Risk</div>'
            '<div style="font-size:2rem;font-weight:700;color:#ff8c42">'
            + str(_at_risk_count) +
            '</div>'
            '<div style="font-size:0.7rem;color:#3d5a80">of ' + str(_total_assets) + ' monitored</div>'
            '</div>',
            unsafe_allow_html=True,
        )
    with _adv_r3:
        _crit_color = "#ff4d6d" if _crit_count > 0 else "#06d6a0"
        st.markdown(
            '<div class="metric-card">'
            '<div style="font-size:0.75rem;color:#6e7fa3">Critical Alerts</div>'
            '<div style="font-size:2rem;font-weight:700;color:' + _crit_color + '">'
            + str(_crit_count) +
            '</div>'
            '<div style="font-size:0.7rem;color:#3d5a80">require immediate action</div>'
            '</div>',
            unsafe_allow_html=True,
        )
    with _adv_r4:
        st.markdown(
            '<div class="metric-card">'
            '<div style="font-size:0.75rem;color:#6e7fa3">Last Briefing</div>'
            '<div style="font-size:0.9rem;font-weight:600;color:#38bdf8;padding-top:6px">'
            + (_briefing_time or "Pending…") +
            '</div>'
            '<div style="font-size:0.7rem;color:#3d5a80">auto-generated daily</div>'
            '</div>',
            unsafe_allow_html=True,
        )

    st.divider()

    # ── Asset risk profile cards ──────────────────────────────────────────────
    st.markdown('<p class="section-label"><i class="bi bi-crosshair bi-sm icon-accent"></i>&nbsp; Asset Threat Profiles</p>', unsafe_allow_html=True)

    if _profiles_df.empty:
        st.info(
            "No threat profiles yet — the AI research agent runs every hour. "
            "Add assets in **⚑ Watchlist** and click **Research Now** above."
        )
    else:
        # Sort: critical first
        _severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        _profiles_sorted = _profiles_df.copy()
        _profiles_sorted["_sev_ord"] = _profiles_sorted["risk_level"].map(
            lambda x: _severity_order.get(str(x).lower(), 4)
        )
        _profiles_sorted = _profiles_sorted.sort_values(["_sev_ord", "risk_score"], ascending=[True, False])

        for _, _prof in _profiles_sorted.iterrows():
            _rl    = str(_prof.get("risk_level", "low")).lower()
            _rs    = int(_prof.get("risk_score", 0) or 0)
            _aval  = str(_prof.get("asset_value", ""))
            _atype = str(_prof.get("asset_type", ""))
            _albl  = str(_prof.get("asset_label", "") or "")
            _ai_txt = str(_prof.get("ai_assessment", "") or "")
            _recs   = _prof.get("recommendations") or []
            _iacts  = _prof.get("immediate_actions") or []
            _actors = _prof.get("matched_actors") or []
            _miocs  = _prof.get("matched_iocs") or []
            _ttps   = _prof.get("attack_vectors") or []
            _last   = str(_prof.get("last_assessed", "") or "")[:16]

            _rc = _risk_color_map.get(_rl, "#38bdf8")
            _rgb_str = (
                "255,77,109" if _rl == "critical" else
                "255,140,66" if _rl == "high" else
                "255,209,102" if _rl == "medium" else
                "6,214,160"
            )
            _border_style = (
                "border-left:4px solid " + _rc + ";"
                "background:rgba(" + _rgb_str + ",0.04);"
            )

            _type_icon = {
                "domain": '<i class="bi bi-globe2 icon-accent"></i>', "ip": '<i class="bi bi-hdd-network icon-accent"></i>', "cidr": '<i class="bi bi-diagram-2 icon-accent"></i>',
                "email_domain": '<i class="bi bi-envelope-fill icon-accent"></i>', "keyword": '<i class="bi bi-key-fill icon-purple"></i>',
            }.get(_atype, '<i class="bi bi-pin-fill icon-accent"></i>')

            _expander_label = (
                _type_icon + "  " + _aval +
                ("  ·  " + _albl if _albl else "") +
                "   【" + _rl.upper() + " — " + str(_rs) + "/100】"
            )

            with st.expander(
                label=_expander_label,
                expanded=(_rl in ("critical", "high")),
            ):
                st.markdown(
                    '<div style="' + _border_style + 'border-radius:6px;padding:10px 14px;margin-bottom:8px">',
                    unsafe_allow_html=True,
                )

                _pc1, _pc2 = st.columns([3, 2])
                with _pc1:
                    # Risk bar
                    _fig_mini = go.Figure(go.Bar(
                        x=[_rs], y=["Risk"], orientation="h",
                        marker_color=_rc, showlegend=False,
                    ))
                    _fig_mini.update_xaxes(range=[0, 100], showgrid=False, showticklabels=True)
                    _fig_mini.update_yaxes(showticklabels=False)
                    _fig_mini.update_layout(
                        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                        height=55, margin=dict(l=0, r=0, t=5, b=5),
                        font_color="#c8d8f0",
                    )
                    st.plotly_chart(_fig_mini, use_container_width=True)

                    if _ai_txt:
                        st.markdown(
                            '<p style="font-size:0.83rem;color:#8aa0c0;line-height:1.5">'
                            + _ai_txt + '</p>',
                            unsafe_allow_html=True,
                        )

                with _pc2:
                    if _actors:
                        _act_str = ", ".join(str(a) for a in _actors[:4])
                        st.markdown(
                            '<div style="font-size:0.75rem;color:#ff8c42;margin-bottom:4px">'
                            '<i class="bi bi-exclamation-triangle-fill icon-error" style="font-size:0.75rem"></i>&nbsp;Actors: <b>' + _act_str + '</b></div>',
                            unsafe_allow_html=True,
                        )
                    if _miocs:
                        _ioc_badges = ", ".join(
                            '<span class="ioc-val">' + str(v)[:30] + '</span>'
                            for v in _miocs[:4]
                        )
                        st.markdown(
                            '<div style="font-size:0.72rem;color:#6e7fa3">'
                            'Matched IOCs: ' + _ioc_badges +
                            '</div>',
                            unsafe_allow_html=True,
                        )
                    if _ttps:
                        st.markdown(
                            '<div style="font-size:0.72rem;color:#c084fc;margin-top:4px">'
                            'TTPs: ' + ", ".join(str(t) for t in _ttps[:6]) +
                            '</div>',
                            unsafe_allow_html=True,
                        )

                # Immediate actions (red banner if present)
                if _iacts:
                    for _ia in _iacts[:3]:
                        st.markdown(
                            '<div style="background:rgba(255,77,109,0.12);border:1px solid #ff4d6d;'
                            'border-radius:4px;padding:5px 10px;font-size:0.78rem;'
                            'color:#ff8080;margin:3px 0">'
                            '<i class="bi bi-exclamation-octagon-fill icon-error"></i>&nbsp;' + str(_ia) + '</div>',
                            unsafe_allow_html=True,
                        )

                # Recommendations
                if _recs:
                    st.markdown(
                        '<div style="font-size:0.75rem;color:#6e7fa3;margin-top:6px">'
                        '<b>Recommendations:</b></div>',
                        unsafe_allow_html=True,
                    )
                    for _rec in _recs[:5]:
                        st.markdown(
                            '<div style="font-size:0.78rem;color:#8aa0c0;padding:2px 0 2px 10px">'
                            '→ ' + str(_rec) + '</div>',
                            unsafe_allow_html=True,
                        )

                st.markdown('</div>', unsafe_allow_html=True)
                st.caption("Last assessed: " + _last + " UTC")

    st.divider()

    # ── Daily Briefing Panel ──────────────────────────────────────────────────
    st.markdown('<p class="section-label"><i class="bi bi-newspaper bi-sm icon-accent"></i>&nbsp; Latest Intelligence Briefing</p>', unsafe_allow_html=True)

    if _briefing_df.empty:
        st.info("First briefing will be generated within the hour, or click **Research Now** above.")
    else:
        _br = _briefing_df.iloc[0]
        _br_risk     = str(_br.get("risk_level", "medium")).lower()
        _br_rc       = _risk_color_map.get(_br_risk, "#38bdf8")
        _br_title    = str(_br.get("title", "Threat Intelligence Briefing"))
        _br_summary  = str(_br.get("executive_summary", ""))
        _br_findings = _br.get("key_findings") or []
        _br_recs     = _br.get("recommendations") or []
        _br_actors   = _br.get("trending_actors") or []
        _br_iocs     = int(_br.get("ioc_count", 0) or 0)
        _br_rpts     = int(_br.get("report_count", 0) or 0)

        # Header card
        st.markdown(
            '<div style="background:linear-gradient(135deg,#0a1428,#0d1a30);'
            'border:1px solid ' + _br_rc + ';border-radius:10px;padding:16px 20px;margin-bottom:14px">'
            '<div style="display:flex;justify-content:space-between;align-items:center">'
            '<span style="font-size:1rem;font-weight:700;color:#c8d8f0">' + _br_title + '</span>'
            '<span style="background:' + _br_rc + '22;color:' + _br_rc + ';'
            'border:1px solid ' + _br_rc + ';border-radius:4px;padding:2px 10px;'
            'font-size:0.72rem;font-weight:700">' + _br_risk.upper() + '</span>'
            '</div>'
            '<div style="font-size:0.82rem;color:#8aa0c0;margin-top:8px;line-height:1.6">'
            + _br_summary +
            '</div>'
            '<div style="margin-top:8px;font-size:0.72rem;color:#3d5a80">'
            + str(_br_iocs) + ' IOCs · ' + str(_br_rpts) + ' reports analysed · '
            + _briefing_time +
            '</div>'
            '</div>',
            unsafe_allow_html=True,
        )

        _bf1, _bf2 = st.columns(2)

        with _bf1:
            st.markdown('<p style="font-size:0.85rem;font-weight:700;color:#c8d8f0"><i class="bi bi-search icon-accent"></i>&nbsp; Key Findings</p>', unsafe_allow_html=True)
            if _br_findings:
                for _idx, _f in enumerate(_br_findings, 1):
                    st.markdown(
                        '<div style="font-size:0.8rem;color:#8aa0c0;padding:3px 0">'
                        '<span style="color:' + _br_rc + ';font-weight:700">' + str(_idx) + '.&nbsp;</span>'
                        + str(_f) + '</div>',
                        unsafe_allow_html=True,
                    )
            else:
                st.caption("Analysis pending — no AI backend configured or no data yet.")

        with _bf2:
            st.markdown('<p style="font-size:0.85rem;font-weight:700;color:#c8d8f0"><i class="bi bi-shield-check icon-ok"></i>&nbsp; Defensive Recommendations</p>', unsafe_allow_html=True)
            if _br_recs:
                for _rec in _br_recs[:5]:
                    st.markdown(
                        '<div style="font-size:0.8rem;color:#8aa0c0;padding:3px 0">'
                        '→&nbsp;' + str(_rec) + '</div>',
                        unsafe_allow_html=True,
                    )
            if _br_actors:
                st.markdown('<p style="font-size:0.85rem;font-weight:700;color:#c8d8f0"><i class="bi bi-person-badge-fill icon-error"></i>&nbsp; Trending Threat Actors</p>', unsafe_allow_html=True)
                _actor_html = " &nbsp; ".join(
                    '<span class="badge-critical">' + str(a) + '</span>'
                    for a in _br_actors[:6]
                )
                st.markdown(_actor_html, unsafe_allow_html=True)

    st.divider()

    # ── Threat Actor Intelligence ─────────────────────────────────────────────
    st.markdown('<p class="section-label"><i class="bi bi-person-badge-fill bi-sm icon-error"></i>&nbsp; Threat Actor Intelligence</p>', unsafe_allow_html=True)
    if not reports.empty and "threat_actor" in reports.columns:
        _ta_df = (
            reports[reports["threat_actor"].notna() & (reports["threat_actor"] != "Unknown")]
            .groupby("threat_actor")
            .agg(
                reports=("id", "count"),
                avg_confidence=("confidence_score", "mean"),
                latest=("created_at", "max"),
                feeds=("source_feed", lambda x: ", ".join(sorted(set(x))[:3])),
            )
            .reset_index()
            .sort_values("reports", ascending=False)
            .head(20)
        )

        if not _ta_df.empty:
            _ta_c1, _ta_c2 = st.columns([3, 2])

            with _ta_c1:
                _fig_ta = px.bar(
                    _ta_df.head(12), x="reports", y="threat_actor",
                    orientation="h",
                    color="avg_confidence",
                    color_continuous_scale=[[0, "#1a0a30"], [0.5, "#7c3aed"], [1, "#c084fc"]],
                    labels={"threat_actor": "", "reports": "Reports",
                            "avg_confidence": "Avg Confidence"},
                )
                _fig_ta.update_coloraxes(showscale=True, colorbar=dict(
                    title="Conf", len=0.5, thickness=10,
                    tickfont=dict(color="#6e7fa3", size=9),
                ))
                _fig_ta.update_layout(**_PLOTLY_DARK, height=360,
                                      yaxis=dict(autorange="reversed"))
                _fig_ta.update_layout(clickmode="event+select")
                _ta_sel = st.plotly_chart(_fig_ta, on_select="rerun",
                                          use_container_width=True, key="adv_actor_bar")
                _drill_ta = None
                if _ta_sel and _ta_sel.selection and _ta_sel.selection.points:
                    _drill_ta = _ta_sel.selection.points[0].get("y")

            with _ta_c2:
                if _drill_ta:
                    _ta_rpts = reports[reports["threat_actor"] == _drill_ta]
                    _ta_iocs = iocs[iocs["report_id"].isin(_ta_rpts["id"])] if not iocs.empty and "report_id" in iocs.columns else pd.DataFrame()
                    _ta_ttp_all: list = []
                    for _tval in _ta_rpts["ttps"].dropna():
                        if isinstance(_tval, list):
                            _ta_ttp_all.extend(_tval)
                    st.markdown(
                        '<div class="metric-card" style="border-left:3px solid #c084fc">'
                        '<b style="color:#c8d8f0">' + str(_drill_ta) + '</b><br>'
                        '<span style="font-size:0.75rem;color:#6e7fa3">'
                        + str(len(_ta_rpts)) + ' reports · '
                        + str(len(_ta_iocs)) + ' IOCs · '
                        + str(len(set(_ta_ttp_all))) + ' unique TTPs</span>'
                        '</div>',
                        unsafe_allow_html=True,
                    )
                    if _ta_ttp_all:
                        _ttp_ctr = Counter(_ta_ttp_all).most_common(8)
                        _ttp_df  = pd.DataFrame(_ttp_ctr, columns=["ttp", "count"])
                        _fig_ttp = px.bar(
                            _ttp_df, x="count", y="ttp", orientation="h",
                            color="count",
                            color_continuous_scale=[[0,"#0d1a30"],[1,"#818cf8"]],
                            labels={"ttp": "", "count": "Obs"},
                        )
                        _fig_ttp.update_coloraxes(showscale=False)
                        _fig_ttp.update_layout(**_PLOTLY_DARK, height=240,
                                               yaxis=dict(autorange="reversed"))
                        st.plotly_chart(_fig_ttp, use_container_width=True)
                    _ta_ioc_cols = [c for c in ["ioc_type", "value", "malware_family"]
                                    if c in _ta_iocs.columns]
                    if _ta_ioc_cols:
                        st.dataframe(_ta_iocs[_ta_ioc_cols].head(10),
                                     use_container_width=True, hide_index=True)
                else:
                    st.markdown(
                        '<div class="metric-card" style="text-align:center;padding:30px">'
                        '<div><i class="bi bi-person-circle" style="font-size:2.5rem;color:#c084fc"></i></div>'
                        '<div style="font-size:0.8rem;color:#3d5a80;margin-top:8px">'
                        'Click an actor bar to see their IOCs, TTPs, and campaign history'
                        '</div></div>',
                        unsafe_allow_html=True,
                    )
        else:
            st.info("Threat actor data will populate as the AI enrichment processes reports.")
    else:
        st.info("No threat reports yet — feeds are initialising.")

    st.divider()

    # ── Kill Chain Phase Distribution ─────────────────────────────────────────
    st.markdown('<p class="section-label"><i class="bi bi-diagram-3-fill bi-sm icon-purple"></i>&nbsp; Kill Chain Phase Distribution</p>', unsafe_allow_html=True)
    _kc_map = {
        "T1595": "Reconnaissance", "T1592": "Reconnaissance", "T1589": "Reconnaissance",
        "T1598": "Weaponisation", "T1587": "Weaponisation", "T1588": "Weaponisation",
        "T1566": "Delivery", "T1190": "Exploitation", "T1203": "Exploitation",
        "T1059": "Installation", "T1055": "Installation", "T1543": "Installation",
        "T1071": "C2", "T1572": "C2", "T1090": "C2",
        "T1041": "Exfiltration", "T1567": "Exfiltration",
        "T1486": "Actions on Obj.", "T1490": "Actions on Obj.",
    }
    _kc_order = ["Reconnaissance","Weaponisation","Delivery","Exploitation",
                 "Installation","C2","Exfiltration","Actions on Obj."]

    if not reports.empty:
        _all_ttps: list = []
        for _tval in reports["ttps"].dropna():
            if isinstance(_tval, list):
                _all_ttps.extend(_tval)

        if _all_ttps:
            _kc_counts: dict = {k: 0 for k in _kc_order}
            for _t in _all_ttps:
                _prefix = str(_t)[:5]
                for _tid, _phase in _kc_map.items():
                    if _prefix == _tid or str(_t).startswith(_tid):
                        _kc_counts[_phase] = _kc_counts.get(_phase, 0) + 1
                        break

            _kc_df = pd.DataFrame([
                {"phase": k, "count": v, "order": i}
                for i, (k, v) in enumerate(_kc_counts.items())
            ])
            _kc_colors = ["#38bdf8","#818cf8","#c084fc","#fb923c",
                          "#f87171","#ff4d6d","#ffd166","#06d6a0"]
            _kc_df_sorted = _kc_df.sort_values("order")
            _fig_kc = px.bar(
                _kc_df_sorted, x="count", y="phase",
                orientation="h",
                color="phase",
                color_discrete_sequence=_kc_colors,
            )
            _fig_kc.update_layout(**_PLOTLY_DARK, height=320, showlegend=False)
            st.plotly_chart(_fig_kc, use_container_width=True)
            st.caption("Lockheed Martin Cyber Kill Chain — mapped from MITRE ATT&CK TTPs")
        else:
            st.info("Kill chain mapping populates as AI enrichment processes reports and extracts TTPs.")
    else:
        st.info("No threat data yet.")

    st.divider()

    # ── MITRE ATT&CK Mitigation Playbook ─────────────────────────────────────
    st.markdown('<p class="section-label"><i class="bi bi-shield-check bi-sm icon-ok"></i>&nbsp; MITRE ATT&amp;CK Mitigation Playbook</p>', unsafe_allow_html=True)
    st.markdown(
        '<p style="font-size:0.8rem;color:#6e7fa3">Defensive controls mapped to '
        'TTPs observed across all active threat reports. '
        'Prioritised by observation frequency.</p>',
        unsafe_allow_html=True,
    )

    try:
        _mit_engine = get_engine()
        _mit_sql = """
            SELECT m.mitigation_id, m.name, m.description,
                   COUNT(DISTINCT r.id) AS report_count,
                   ARRAY_AGG(DISTINCT r.threat_actor) FILTER (WHERE r.threat_actor IS NOT NULL
                       AND r.threat_actor <> 'Unknown') AS actors
            FROM mitre_mitigations m
            JOIN mitre_ttp_mitigations tm ON tm.mitigation_id = m.id
            JOIN (
                SELECT r.id, r.threat_actor,
                       UNNEST(r.ttps) AS ttp_id
                FROM threat_reports r
                WHERE r.created_at > NOW() - INTERVAL '14 days'
            ) r ON r.ttp_id = tm.ttp_id
            GROUP BY m.mitigation_id, m.name, m.description
            ORDER BY report_count DESC
            LIMIT 12
        """
        _mit_df = pd.read_sql(_mit_sql, _mit_engine)
    except Exception as _me:
        _mit_df = pd.DataFrame()

    if _mit_df.empty:
        # Fallback: show generic top mitigations based on observed TTP prefixes
        _obs_ttps: list = []
        if not reports.empty:
            for _tv in reports["ttps"].dropna():
                if isinstance(_tv, list):
                    _obs_ttps.extend(_tv)

        _GENERIC_MITS = {
            "M1049": ("Antivirus/Antimalware", "Deploy and maintain endpoint antivirus with up-to-date signatures and behavioural detection."),
            "M1031": ("Network Intrusion Prevention", "Use network IDS/IPS to detect and block malicious network traffic patterns."),
            "M1050": ("Exploit Protection", "Enable OS-level exploit mitigations (ASLR, DEP, CFG). Use application whitelisting."),
            "M1035": ("Limit Access to Resource Over Network", "Apply network segmentation and restrict unnecessary lateral movement paths."),
            "M1017": ("User Training", "Conduct phishing awareness training and regular security awareness programmes."),
            "M1041": ("Encrypt Sensitive Information", "Encrypt data at rest and in transit. Enforce TLS 1.2+ across all services."),
            "M1026": ("Privileged Account Management", "Implement least-privilege. Audit privileged accounts. Enforce PAM solutions."),
            "M1032": ("Multi-factor Authentication", "Require MFA on all externally-facing services and privileged interfaces."),
            "M1030": ("Network Segmentation", "Segment networks to contain lateral movement. Enforce micro-segmentation where possible."),
            "M1021": ("Restrict Web-Based Content", "Block access to malicious domains. Enforce category-based web filtering."),
        }
        _ttp_mit_map = {
            "T1566": ["M1049","M1017","M1021"],
            "T1190": ["M1050","M1030","M1031"],
            "T1059": ["M1049","M1050","M1026"],
            "T1486": ["M1041","M1053","M1049"],
            "T1071": ["M1031","M1030","M1021"],
            "T1041": ["M1031","M1041","M1030"],
            "T1055": ["M1049","M1050","M1026"],
            "T1078": ["M1032","M1026","M1017"],
        }
        _mit_scores: dict = {}
        for _ot in _obs_ttps:
            for _prefix, _mits in _ttp_mit_map.items():
                if str(_ot).startswith(_prefix):
                    for _m in _mits:
                        _mit_scores[_m] = _mit_scores.get(_m, 0) + 1
        _sorted_mits = sorted(_mit_scores.items(), key=lambda x: x[1], reverse=True)[:8]
        if not _sorted_mits and _GENERIC_MITS:
            _sorted_mits = [(k, 0) for k in list(_GENERIC_MITS.keys())[:6]]

        if _sorted_mits:
            _mc1, _mc2 = st.columns(2)
            for _mi_idx, (_mid, _mcount) in enumerate(_sorted_mits):
                _mname, _mdesc = _GENERIC_MITS.get(_mid, (_mid, "See MITRE ATT&CK for details."))
                _col = _mc1 if _mi_idx % 2 == 0 else _mc2
                with _col:
                    st.markdown(
                        '<div style="background:rgba(6,214,160,0.05);border:1px solid #06d6a022;'
                        'border-left:3px solid #06d6a0;border-radius:6px;padding:10px 14px;'
                        'margin-bottom:8px">'
                        '<div style="display:flex;justify-content:space-between">'
                        '<span style="font-size:0.8rem;font-weight:700;color:#06d6a0">'
                        + _mid + ' — ' + _mname + '</span>'
                        + (
                            '<span style="font-size:0.7rem;color:#3d5a80;background:#0a1428;'
                            'border-radius:3px;padding:1px 6px">' +
                            str(_mcount) + ' obs</span>' if _mcount > 0 else ''
                        ) +
                        '</div>'
                        '<div style="font-size:0.75rem;color:#6e7fa3;margin-top:4px;line-height:1.5">'
                        + _mdesc + '</div>'
                        '</div>',
                        unsafe_allow_html=True,
                    )
        else:
            st.info("Mitigation playbook populates once threat feeds have collected TTPs.")
    else:
        _mc1, _mc2 = st.columns(2)
        for _mi_idx, (_, _mrow) in enumerate(_mit_df.iterrows()):
            _col = _mc1 if _mi_idx % 2 == 0 else _mc2
            _mactors = [a for a in (_mrow.get("actors") or []) if a][:3]
            _mactor_str = ", ".join(_mactors) if _mactors else ""
            with _col:
                st.markdown(
                    '<div style="background:rgba(6,214,160,0.05);border:1px solid #06d6a022;'
                    'border-left:3px solid #06d6a0;border-radius:6px;padding:10px 14px;'
                    'margin-bottom:8px">'
                    '<div style="display:flex;justify-content:space-between">'
                    '<span style="font-size:0.8rem;font-weight:700;color:#06d6a0">'
                    + str(_mrow["mitigation_id"]) + ' — ' + str(_mrow["name"]) + '</span>'
                    '<span style="font-size:0.7rem;color:#3d5a80;background:#0a1428;'
                    'border-radius:3px;padding:1px 6px">'
                    + str(int(_mrow["report_count"])) + ' reports</span>'
                    '</div>'
                    '<div style="font-size:0.75rem;color:#6e7fa3;margin-top:4px;line-height:1.5">'
                    + str(_mrow["description"])[:220] + ('…' if len(str(_mrow["description"])) > 220 else '') +
                    '</div>'
                    + (
                        '<div style="font-size:0.7rem;color:#ff8c42;margin-top:3px"><i class="bi bi-lightning-fill icon-error" style="font-size:0.7rem"></i>&nbsp;' + _mactor_str + '</div>'
                        if _mactor_str else ''
                    ) +
                    '</div>',
                    unsafe_allow_html=True,
                )

    st.divider()

    # ── Cross-Feed Threat Correlation ─────────────────────────────────────────
    st.markdown('<p class="section-label"><i class="bi bi-share-fill bi-sm icon-accent"></i>&nbsp; Cross-Feed Threat Correlation</p>', unsafe_allow_html=True)
    st.markdown(
        '<p style="font-size:0.8rem;color:#6e7fa3">Threat actors and malware families '
        'observed across multiple independent feeds — highest-confidence signals.</p>',
        unsafe_allow_html=True,
    )

    if not reports.empty and "threat_actor" in reports.columns and "source_feed" in reports.columns:
        _xfeed_df = (
            reports[
                reports["threat_actor"].notna() &
                (reports["threat_actor"] != "") &
                (reports["threat_actor"] != "Unknown")
            ]
            .groupby("threat_actor")["source_feed"]
            .apply(lambda x: sorted(set(x)))
            .reset_index()
        )
        _xfeed_df.columns = ["threat_actor", "feeds"]
        _xfeed_df["feed_count"] = _xfeed_df["feeds"].apply(len)
        _xfeed_multi = _xfeed_df[_xfeed_df["feed_count"] >= 2].sort_values("feed_count", ascending=False).head(10)

        if not _xfeed_multi.empty:
            _xf_c1, _xf_c2 = st.columns([3, 2])
            with _xf_c1:
                _fig_xf = px.bar(
                    _xfeed_multi, x="feed_count", y="threat_actor",
                    orientation="h",
                    color="feed_count",
                    color_continuous_scale=[[0,"#0d1a30"],[0.5,"#38bdf8"],[1,"#06d6a0"]],
                    labels={"threat_actor": "", "feed_count": "Feeds Corroborating"},
                    title="Multi-Feed Corroboration",
                )
                _fig_xf.update_coloraxes(showscale=False)
                _fig_xf.update_layout(**_PLOTLY_DARK, height=300, yaxis=dict(autorange="reversed"))
                _fig_xf.update_layout(clickmode="event+select")
                _xf_sel = st.plotly_chart(_fig_xf, on_select="rerun",
                                           use_container_width=True, key="xfeed_bar")
                _drill_xf = None
                if _xf_sel and _xf_sel.selection and _xf_sel.selection.points:
                    _drill_xf = _xf_sel.selection.points[0].get("y")

            with _xf_c2:
                if _drill_xf:
                    _xf_row = _xfeed_multi[_xfeed_multi["threat_actor"] == _drill_xf]
                    if not _xf_row.empty:
                        _xf_feeds = _xf_row.iloc[0]["feeds"]
                        _xf_cnt   = _xf_row.iloc[0]["feed_count"]
                        st.markdown(
                            '<div class="metric-card" style="border-left:3px solid #38bdf8">'
                            '<b style="color:#c8d8f0;font-size:0.95rem">' + str(_drill_xf) + '</b><br>'
                            '<span style="font-size:0.7rem;color:#38bdf8">'
                            + str(_xf_cnt) + ' independent feeds confirm this actor</span><br><br>'
                            + "".join(
                                '<div style="font-size:0.75rem;color:#6e7fa3;padding:2px 0">'
                                '✓ ' + f + '</div>' for f in _xf_feeds
                            ) +
                            '</div>',
                            unsafe_allow_html=True,
                        )
                        _xf_rpts = reports[reports["threat_actor"] == _drill_xf]
                        _xf_ioc_df = iocs[iocs["report_id"].isin(_xf_rpts["id"])] if not iocs.empty else pd.DataFrame()
                        if not _xf_ioc_df.empty:
                            _xf_show = [c for c in ["ioc_type","value","malware_family","tags"] if c in _xf_ioc_df.columns]
                            st.dataframe(_xf_ioc_df[_xf_show].head(8), use_container_width=True, hide_index=True)
                else:
                    st.markdown(
                        '<div class="metric-card" style="text-align:center;padding:24px">'
                        '<div><i class="bi bi-share-fill" style="font-size:2rem;color:#38bdf8"></i></div>'
                        '<div style="font-size:0.8rem;color:#3d5a80;margin-top:8px">'
                        'Click a bar to see which feeds corroborate the actor and matched IOCs'
                        '</div></div>',
                        unsafe_allow_html=True,
                    )
        else:
            st.info(
                "Cross-feed correlation requires threat actors seen across ≥2 feeds. "
                "More data will appear as feeds run."
            )

    else:
        st.info("Threat data is still loading.")

    st.divider()

    # ── AI-Generated Threat Actor Profiles ───────────────────────────────────
    st.markdown('<p class="section-label"><i class="bi bi-cpu-fill bi-sm icon-accent"></i>&nbsp; AI-Generated Threat Actor Profiles</p>', unsafe_allow_html=True)
    st.markdown(
        '<p style="font-size:0.8rem;color:#6e7fa3">On-demand AI profiles for the most '
        'active actors seen in your feeds. Includes attribution, TTPs, and sector targeting.</p>',
        unsafe_allow_html=True,
    )

    if not reports.empty and "threat_actor" in reports.columns:
        _top_actors_for_profile = (
            reports[
                reports["threat_actor"].notna() &
                (reports["threat_actor"] != "") &
                (reports["threat_actor"] != "Unknown")
            ]
            .groupby("threat_actor")["id"]
            .count()
            .sort_values(ascending=False)
            .head(6)
            .index.tolist()
        )

        if _top_actors_for_profile:
            _prof_sel = st.selectbox(
                "Select actor to profile:",
                ["— choose —"] + _top_actors_for_profile,
                key="actor_profile_select",
            )
            if _prof_sel and _prof_sel != "— choose —":
                _ap_rpts = reports[reports["threat_actor"] == _prof_sel]
                _ap_feeds = sorted(set(_ap_rpts["source_feed"].dropna()))
                _ap_ttps_raw: list = []
                for _tv in _ap_rpts["ttps"].dropna():
                    if isinstance(_tv, list):
                        _ap_ttps_raw.extend(_tv)
                _ap_ttps_unique = sorted(set(_ap_ttps_raw))[:10]

                _ap_col1, _ap_col2 = st.columns([1, 2])
                with _ap_col1:
                    st.markdown(
                        '<div class="metric-card">'
                        '<div style="font-size:1.1rem;font-weight:700;color:#c084fc">' + _prof_sel + '</div>'
                        '<div style="font-size:0.75rem;color:#6e7fa3;margin-top:6px">Reports: <b style="color:#c8d8f0">' + str(len(_ap_rpts)) + '</b></div>'
                        '<div style="font-size:0.75rem;color:#6e7fa3">Feeds: <b style="color:#c8d8f0">' + ", ".join(_ap_feeds[:3]) + '</b></div>'
                        '<div style="font-size:0.75rem;color:#6e7fa3;margin-top:6px"><b>TTPs observed:</b></div>'
                        + "".join('<div style="font-size:0.72rem;color:#818cf8;padding:1px 0">• ' + t + '</div>' for t in _ap_ttps_unique) +
                        '</div>',
                        unsafe_allow_html=True,
                    )
                with _ap_col2:
                    # Try to load cached profile from asset_threat_profiles
                    _cached_profile = None
                    if not _profiles_df.empty:
                        # Check if any asset's ai_assessment mentions this actor
                        _actor_lower = _prof_sel.lower()
                        for _, _pr in _profiles_df.iterrows():
                            _actors_list = _pr.get("matched_actors") or []
                            if any(_actor_lower in str(a).lower() for a in _actors_list):
                                _cached_profile = str(_pr.get("ai_assessment") or "")
                                break

                    if _cached_profile:
                        st.markdown(
                            '<div style="background:rgba(192,132,252,0.06);border:1px solid #7c3aed33;'
                            'border-radius:8px;padding:12px 16px">'
                            '<div style="font-size:0.7rem;color:#6e7fa3;margin-bottom:6px"><i class="bi bi-cpu-fill" style="color:#38bdf8"></i>&nbsp;AI Assessment (cached)</div>'
                            '<div style="font-size:0.82rem;color:#8aa0c0;line-height:1.6">'
                            + _cached_profile[:800] + ('…' if len(_cached_profile) > 800 else '') +
                            '</div></div>',
                            unsafe_allow_html=True,
                        )
                    else:
                        # Show what we know from data
                        _ap_malware = sorted(set(
                            str(m) for m in _ap_rpts["malware_family"].dropna()
                            if m and m != "Unknown"
                        ))[:5] if "malware_family" in _ap_rpts.columns else []

                        _ap_countries = sorted(set(
                            str(c) for c in _ap_rpts.get("geo_country", pd.Series()).dropna()
                            if c
                        ))[:4] if "geo_country" in _ap_rpts.columns else []

                        st.markdown(
                            '<div style="background:rgba(192,132,252,0.06);border:1px solid #7c3aed33;'
                            'border-radius:8px;padding:12px 16px">'
                            '<div style="font-size:0.7rem;color:#6e7fa3;margin-bottom:6px"><i class="bi bi-bar-chart-fill" style="color:#38bdf8"></i>&nbsp;Intelligence Summary</div>'
                            + (
                                '<div style="font-size:0.78rem;color:#8aa0c0;margin-bottom:4px">'
                                '<b style="color:#c084fc">Malware families:</b> ' + ", ".join(_ap_malware) + '</div>'
                                if _ap_malware else ''
                            )
                            + (
                                '<div style="font-size:0.78rem;color:#8aa0c0;margin-bottom:4px">'
                                '<b style="color:#c084fc">Victim countries:</b> ' + ", ".join(_ap_countries) + '</div>'
                                if _ap_countries else ''
                            )
                            + '<div style="font-size:0.78rem;color:#6e7fa3;margin-top:8px">'
                            '<i class="bi bi-lightbulb-fill" style="color:#ffd166"></i>&nbsp;Add assets to the Watchlist and click <b>Research Now</b> to generate '
                            'a full AI-written profile with attribution, impact assessment, and '
                            'sector-specific mitigations for this actor.'
                            '</div>'
                            '</div>',
                            unsafe_allow_html=True,
                        )
        else:
            st.info("No named threat actors in current data — feeds are collecting.")
    else:
        st.info("No threat data yet.")


# ══════════════════════════════════════════════════════════════════════════════
# FEED HEALTH
# ══════════════════════════════════════════════════════════════════════════════
elif active_page == "Feed Health":
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

        _feed_history_df = load_feed_history()

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
            _fh_col, _spark_col = st.columns([5, 1])
            with _fh_col:
                st.markdown(f"""
<div class="feed-card {status}">
  <i class="bi bi-{_si} status-icon {status}"></i>
  <div class="feed-name">{str(row["feed_name"]).upper()}</div>
  <div class="feed-meta">
    Last run: {last_run} &nbsp;·&nbsp; Last success: {last_ok}
    {err_html}
  </div>
  <div class="feed-count">+{recent:,} / {total:,}</div>
</div>""", unsafe_allow_html=True)
            with _spark_col:
                _fname = str(row.get("feed_name", ""))
                if not _feed_history_df.empty and "source_feed" in _feed_history_df.columns:
                    _spark_data = _feed_history_df[_feed_history_df["source_feed"] == _fname]
                    if not _spark_data.empty:
                        _fig_spark = px.line(
                            _spark_data, x="day", y="cnt",
                            color_discrete_sequence=["#38bdf8"],
                        )
                        _fig_spark.update_layout(
                            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                            margin=dict(l=0, r=0, t=0, b=0), height=60,
                            xaxis=dict(visible=False), yaxis=dict(visible=False),
                            showlegend=False,
                        )
                        _fig_spark.update_traces(line=dict(width=1.5))
                        st.plotly_chart(_fig_spark, use_container_width=True)


# ══════════════════════════════════════════════════════════════════════════════
# ADMIN SETTINGS
# ══════════════════════════════════════════════════════════════════════════════
elif active_page == "Admin":
    st.markdown('<p class="section-label"><i class="bi bi-gear-fill bi-sm icon-accent"></i>&nbsp; Platform Administration</p>', unsafe_allow_html=True)

    _cfg = load_platform_settings()

    # ── Dark Web Monitor ──────────────────────────────────────────────────────
    st.markdown("""
<div class="admin-section">
  <div class="admin-section-title">
    <i class="bi bi-incognito bi-md"></i> Dark Web Monitor
  </div>
</div>""", unsafe_allow_html=True)

    # We render the actual controls outside the HTML block so Streamlit widgets work
    with st.container():
        adm_c1, adm_c2 = st.columns([1, 3])

        with adm_c1:
            dw_enabled_val = _cfg.get("dark_web_enabled", "false").lower() == "true"
            dw_toggle = st.toggle(
                "Enable Dark Web Monitoring",
                value=dw_enabled_val,
                key="adm_dw_toggle",
                help="When enabled, the collector scans Ahmia.fi and configured .onion sources at the set interval.",
            )

        with adm_c2:
            _interval_hours = int(_cfg.get("dark_web_interval", "21600")) // 3600
            dw_interval = st.slider(
                "Scan interval (hours)",
                min_value=1, max_value=72,
                value=_interval_hours,
                key="adm_dw_interval",
                help="How often the collector scans. 6 hours is recommended.",
            )

        st.markdown("**Keywords to Monitor** — one per line (your domain, brand name, IP ranges, etc.)")
        _kw_current = "\n".join(k for k in _cfg.get("dark_web_keywords", "").split(",") if k.strip())
        dw_keywords_input = st.text_area(
            "Keywords",
            value=_kw_current,
            height=120,
            placeholder="acmecorp.com\nacme corporation\n192.168.1.0/24",
            key="adm_dw_keywords",
            label_visibility="collapsed",
        )
        st.markdown('<div class="admin-hint">Each line is treated as one search term. Match your domain, brand names, key IP ranges, or known credential patterns (e.g. @yourdomain.com).</div>', unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("**.onion Sources** — one URL per line *(optional)*")
        _onion_current = "\n".join(u for u in _cfg.get("dark_web_onion_sources", "").split(",") if u.strip())
        dw_onion_input = st.text_area(
            "Onion sources",
            value=_onion_current,
            height=90,
            placeholder="http://example.onion/search\nhttp://anotherindex.onion",
            key="adm_dw_onion",
            label_visibility="collapsed",
        )
        st.markdown('<div class="admin-hint">Publicly accessible .onion index/search pages (no login required). Leave blank to use Ahmia.fi only.</div>', unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        save_col, status_col = st.columns([1, 3])
        with save_col:
            if st.button("◈  Save Dark Web Settings", key="adm_dw_save", type="primary"):
                new_keywords = ",".join(
                    k.strip() for k in dw_keywords_input.splitlines() if k.strip()
                )
                new_onions = ",".join(
                    u.strip() for u in dw_onion_input.splitlines() if u.strip()
                )
                ok = save_platform_settings({
                    "dark_web_enabled":       "true" if dw_toggle else "false",
                    "dark_web_keywords":      new_keywords,
                    "dark_web_onion_sources": new_onions,
                    "dark_web_interval":      str(dw_interval * 3600),
                })
                if ok:
                    st.session_state["adm_save_ok"] = True
                    st.rerun()

        with status_col:
            if st.session_state.get("adm_save_ok"):
                st.markdown("""
<div class="admin-save-success">
  <i class="bi bi-check-circle-fill"></i>
  Settings saved — collector will apply changes on its next run cycle.
</div>""", unsafe_allow_html=True)
                st.session_state["adm_save_ok"] = False

    st.divider()

    # ── Current settings summary ──────────────────────────────────────────────
    st.markdown('<p class="section-label"><i class="bi bi-sliders bi-sm icon-muted"></i>&nbsp; Current Configuration</p>', unsafe_allow_html=True)

    _fresh = load_platform_settings()
    _kw_display = [k for k in _fresh.get("dark_web_keywords", "").split(",") if k.strip()]
    _onion_display = [u for u in _fresh.get("dark_web_onion_sources", "").split(",") if u.strip()]
    _status_color = "#06d6a0" if _fresh.get("dark_web_enabled") == "true" else "#ff4d6d"
    _status_label = "ENABLED" if _fresh.get("dark_web_enabled") == "true" else "DISABLED"
    _interval_disp = int(_fresh.get("dark_web_interval", "21600")) // 3600

    cfg_a, cfg_b, cfg_c = st.columns(3)
    with cfg_a:
        st.markdown(f"""
<div style="background:#0c1628;border:1px solid #142038;border-radius:8px;padding:14px 18px;">
  <div style="font-size:0.68rem;color:#3d5a80;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:6px;">Status</div>
  <div style="font-size:1.1rem;font-weight:800;color:{_status_color};letter-spacing:0.08em;">{_status_label}</div>
</div>""", unsafe_allow_html=True)
    with cfg_b:
        st.markdown(f"""
<div style="background:#0c1628;border:1px solid #142038;border-radius:8px;padding:14px 18px;">
  <div style="font-size:0.68rem;color:#3d5a80;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:6px;">Scan Interval</div>
  <div style="font-size:1.1rem;font-weight:800;color:#38bdf8;">Every {_interval_disp}h</div>
</div>""", unsafe_allow_html=True)
    with cfg_c:
        st.markdown(f"""
<div style="background:#0c1628;border:1px solid #142038;border-radius:8px;padding:14px 18px;">
  <div style="font-size:0.68rem;color:#3d5a80;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:6px;">Keywords / Sources</div>
  <div style="font-size:1.1rem;font-weight:800;color:#38bdf8;">{len(_kw_display)} keywords &nbsp;·&nbsp; {len(_onion_display)} .onion</div>
</div>""", unsafe_allow_html=True)

    if _kw_display:
        st.markdown("<br>", unsafe_allow_html=True)
        kw_pill_html = "".join(f'<span class="kw-pill">{k}</span>' for k in _kw_display)
        st.markdown(f'<div><span style="font-size:0.72rem;color:#3d5a80;text-transform:uppercase;letter-spacing:0.1em;font-weight:700;">Active Keywords:</span><br>{kw_pill_html}</div>', unsafe_allow_html=True)

    # ── IOC Enrichment API Keys ───────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
<div class="admin-section">
  <div class="admin-section-title">
    <i class="bi bi-shield-check bi-md"></i> IOC Enrichment API Keys
  </div>
</div>""", unsafe_allow_html=True)
    with st.container():
        _enr_c1, _enr_c2, _enr_c3 = st.columns(3)
        with _enr_c1:
            _vt_val = _cfg.get("enrichment_vt_key", "")
            _vt_key = st.text_input(
                "VirusTotal API Key",
                value=_vt_val,
                type="password",
                key="adm_vt_key",
                help="v3 API key from virustotal.com — enriches IPs, domains, hashes, URLs",
            )
        with _enr_c2:
            _gn_val = _cfg.get("enrichment_gn_key", "")
            _gn_key = st.text_input(
                "GreyNoise API Key",
                value=_gn_val,
                type="password",
                key="adm_gn_key",
                help="Community or Enterprise key from greynoise.io — IP noise classification",
            )
        with _enr_c3:
            _sh_val = _cfg.get("enrichment_shodan_key", "")
            _sh_key = st.text_input(
                "Shodan API Key",
                value=_sh_val,
                type="password",
                key="adm_sh_key",
                help="API key from shodan.io — host scanning & open ports",
            )
        _enr_c4, _enr_c5 = st.columns([2, 2])
        with _enr_c4:
            _gh_val = _cfg.get("github_token", "")
            _gh_key = st.text_input(
                "GitHub Token (for secret scanning)",
                value=_gh_val,
                type="password",
                key="adm_gh_token",
                help="Personal access token from github.com — read:repo scope for code search",
            )

        _enr_save_col, _enr_status_col = st.columns([1, 3])
        with _enr_save_col:
            if st.button("◈  Save Enrichment Keys", key="adm_enr_save", type="primary"):
                ok2 = save_platform_settings({
                    "enrichment_vt_key":     _vt_key.strip(),
                    "enrichment_gn_key":     _gn_key.strip(),
                    "enrichment_shodan_key": _sh_key.strip(),
                    "github_token":          _gh_key.strip(),
                })
                if ok2:
                    st.session_state["adm_enr_save_ok"] = True
                    st.rerun()
        with _enr_status_col:
            if st.session_state.get("adm_enr_save_ok"):
                st.markdown("""
<div class="admin-save-success">
  <i class="bi bi-check-circle-fill"></i> Enrichment keys saved — collector will use them on next run.
</div>""", unsafe_allow_html=True)
                st.session_state["adm_enr_save_ok"] = False

    # ── Alert Channels ────────────────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
<div class="admin-section">
  <div class="admin-section-title">
    <i class="bi bi-bell-fill bi-md"></i> Alert Channels
  </div>
</div>""", unsafe_allow_html=True)
    with st.container():
        st.markdown("**Slack / Teams Webhooks**")
        _sl_c1, _sl_c2 = st.columns(2)
        with _sl_c1:
            _slack_wh = st.text_input(
                "Slack Incoming Webhook URL",
                value=_cfg.get("alert_slack_webhook", ""),
                type="password",
                key="adm_slack_wh",
                help="https://hooks.slack.com/services/…",
            )
        with _sl_c2:
            _teams_wh = st.text_input(
                "Microsoft Teams Webhook URL",
                value=_cfg.get("alert_teams_webhook", ""),
                type="password",
                key="adm_teams_wh",
                help="Power Automate or Connector URL for your Teams channel",
            )

        st.markdown("<br>**Email Alerts (SMTP)**", unsafe_allow_html=True)
        _email_enabled_val = _cfg.get("alert_email_enabled", "false").lower() == "true"
        _email_toggle = st.toggle("Enable email alerts", value=_email_enabled_val, key="adm_email_toggle")
        _em_c1, _em_c2, _em_c3 = st.columns(3)
        with _em_c1:
            _smtp_host = st.text_input("SMTP Host", value=_cfg.get("smtp_host", ""), key="adm_smtp_host", placeholder="smtp.gmail.com")
            _smtp_port = st.text_input("SMTP Port", value=_cfg.get("smtp_port", "587"), key="adm_smtp_port")
        with _em_c2:
            _smtp_user = st.text_input("SMTP Username", value=_cfg.get("smtp_user", ""), key="adm_smtp_user")
            _smtp_pass = st.text_input("SMTP Password", value=_cfg.get("smtp_pass", ""), type="password", key="adm_smtp_pass")
        with _em_c3:
            _from_email = st.text_input("From Email", value=_cfg.get("alert_from_email", ""), key="adm_from_email")
            _to_email   = st.text_input("To Email",   value=_cfg.get("alert_to_email", ""),   key="adm_to_email")
        st.markdown('<div class="admin-hint">Alerts are sent for Critical and High severity watchlist hits. STARTTLS is used automatically.</div>', unsafe_allow_html=True)

        _alc_save_col, _alc_status_col = st.columns([1, 3])
        with _alc_save_col:
            if st.button("◈  Save Alert Channels", key="adm_alc_save", type="primary"):
                ok3 = save_platform_settings({
                    "alert_slack_webhook": _slack_wh.strip(),
                    "alert_teams_webhook": _teams_wh.strip(),
                    "alert_email_enabled": "true" if _email_toggle else "false",
                    "smtp_host":           _smtp_host.strip(),
                    "smtp_port":           _smtp_port.strip(),
                    "smtp_user":           _smtp_user.strip(),
                    "smtp_pass":           _smtp_pass.strip(),
                    "alert_from_email":    _from_email.strip(),
                    "alert_to_email":      _to_email.strip(),
                })
                if ok3:
                    st.session_state["adm_alc_save_ok"] = True
                    st.rerun()
        with _alc_status_col:
            if st.session_state.get("adm_alc_save_ok"):
                st.markdown("""
<div class="admin-save-success">
  <i class="bi bi-check-circle-fill"></i> Alert channels saved — active on next collector cycle.
</div>""", unsafe_allow_html=True)
                st.session_state["adm_alc_save_ok"] = False

    # ── REST API Key Management ───────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
<div class="admin-section">
  <div class="admin-section-title">
    <i class="bi bi-key-fill bi-md"></i> REST API Keys
  </div>
</div>""", unsafe_allow_html=True)
    with st.container():
        st.markdown(
            '<span style="font-size:0.78rem;color:#5a7fa8;">API keys grant external tools (SIEMs, SOARs, firewalls) '
            'access to the VANTELLIGENCE REST API and TAXII 2.1 feed. '
            'Keys are stored as SHA-256 hashes — copy the raw key immediately after creation.</span>',
            unsafe_allow_html=True,
        )
        # Show existing keys
        try:
            from sqlalchemy import text as _text
            _engine = get_engine()
            _api_keys_df = pd.read_sql(
                "SELECT id, label, permissions, created_at, last_used, active FROM api_keys ORDER BY created_at DESC",
                _engine,
            )
        except Exception:
            _api_keys_df = pd.DataFrame()

        if not _api_keys_df.empty:
            for _, _ak in _api_keys_df.iterrows():
                _ak_active = bool(_ak.get("active", True))
                _lu = _ak.get("last_used")
                _lu_str = _lu.strftime("%Y-%m-%d %H:%M") if hasattr(_lu, "strftime") else "Never"
                _ca = _ak.get("created_at")
                _ca_str = _ca.strftime("%Y-%m-%d") if hasattr(_ca, "strftime") else "?"
                _perms = str(_ak.get("permissions") or "read")
                _ak_id = _ak.get("id")
                _ak_col, _ak_del_col = st.columns([10, 1])
                with _ak_col:
                    _ak_name = _ak["label"]
                    _ak_status_badge = (
                        "&nbsp;<span class='badge-low'>ACTIVE</span>"
                        if _ak_active else
                        "&nbsp;<span class='badge-medium'>REVOKED</span>"
                    )
                    st.markdown(
                        f'<div style="background:#0c1628;border:1px solid #142038;border-radius:8px;padding:10px 16px;margin-bottom:5px;">'
                        f'<span style="font-weight:700;color:#c8d8f0;">{_ak_name}</span>'
                        f'&nbsp;&nbsp;<span class="feed-tag">{_perms}</span>'
                        f'{_ak_status_badge}'
                        f'<span style="float:right;font-size:0.72rem;color:#3d5a80;">Created {_ca_str} &nbsp;·&nbsp; Last used: {_lu_str}</span>'
                        f'</div>',
                        unsafe_allow_html=True,
                    )
                with _ak_del_col:
                    if st.button("✕", key=f"ak_del_{_ak_id}", help="Revoke key"):
                        try:
                            with _engine.connect() as _conn:
                                _conn.execute(_text("UPDATE api_keys SET active = false WHERE id = :id"), {"id": int(_ak_id)})
                                _conn.commit()
                            st.rerun()
                        except Exception as _e:
                            st.error(str(_e))
        else:
            st.info("No API keys yet. Generate one below.")

        st.markdown("<br>**Generate a new API key**")
        _nk_c1, _nk_c2, _nk_c3 = st.columns([2, 1, 1])
        with _nk_c1:
            _new_key_name = st.text_input("Key name / description", key="adm_new_key_name", placeholder="Splunk SIEM integration")
        with _nk_c2:
            _new_key_perms = st.selectbox("Permissions", ["read", "read,taxii", "read,write", "admin"], key="adm_new_key_perms")
        with _nk_c3:
            st.markdown("<br>", unsafe_allow_html=True)
            _gen_key_btn = st.button("⊞  Generate Key", key="adm_gen_key", use_container_width=True, type="primary")

        if _gen_key_btn and _new_key_name.strip():
            import secrets as _secrets
            import hashlib as _hashlib
            from sqlalchemy import text as _text
            _raw_key   = "vip_" + _secrets.token_hex(32)
            _key_hash  = _hashlib.sha256(_raw_key.encode()).hexdigest()
            try:
                _engine = get_engine()
                with _engine.connect() as _conn:
                    _conn.execute(_text(
                        """INSERT INTO api_keys (label, key_hash, key_prefix, permissions, active)
                           VALUES (:n, :h, :kp, :p, true)"""
                    ), {"n": _new_key_name.strip(), "h": _key_hash,
                        "kp": _raw_key[:8], "p": [_new_key_perms]})
                    _conn.commit()
                st.success("Key generated! Copy it now — it will not be shown again:")
                st.code(_raw_key, language="text")
                st.markdown(
                    f'<div class="admin-hint">SHA-256: {_key_hash[:32]}…</div>',
                    unsafe_allow_html=True,
                )
                _api_p = os.getenv("API_PORT", "8000")
                st.markdown(
                    f"**Usage:** `curl -H 'X-API-Key: {_raw_key[:20]}…' "
                    f"http://your-server:{_api_p}/api/v1/iocs`",
                    unsafe_allow_html=True,
                )
            except Exception as _e:
                st.error(f"Failed to store key: {_e}")

        # API endpoint quick-reference
        st.divider()
        _api_port = os.getenv("API_PORT", "8000")
        st.markdown(f"""
<div style="background:#0c1628;border:1px solid #142038;border-radius:10px;padding:16px 20px;">
  <div style="font-size:0.72rem;font-weight:800;text-transform:uppercase;letter-spacing:0.12em;color:#38bdf8;margin-bottom:12px;">
    <i class="bi bi-code-slash"></i>&nbsp; REST API Quick Reference &nbsp;·&nbsp; port {_api_port}
  </div>
  <div style="font-family:'JetBrains Mono',monospace;font-size:0.74rem;color:#5a7fa8;line-height:2;">
    <span style="color:#38bdf8">GET</span>  /api/v1/iocs &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; IOC list (filter: type, value, limit)<br>
    <span style="color:#38bdf8">GET</span>  /api/v1/reports &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Threat reports<br>
    <span style="color:#38bdf8">GET</span>  /api/v1/cves &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; CVE records (filter: min_cvss, kev_only)<br>
    <span style="color:#38bdf8">GET</span>  /api/v1/actors &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Threat actor profiles<br>
    <span style="color:#38bdf8">GET</span>  /api/v1/watchlist &nbsp;&nbsp;&nbsp;&nbsp; Watched assets<br>
    <span style="color:#38bdf8">GET</span>  /api/v1/alerts &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Watchlist hits<br>
    <span style="color:#38bdf8">GET</span>  /api/v1/stix/bundle &nbsp;&nbsp; STIX 2.1 bundle export<br>
    <span style="color:#38bdf8">GET</span>  /api/v1/blocklist/ips &nbsp; IP blocklist (plain text)<br>
    <span style="color:#38bdf8">GET</span>  /api/v1/blocklist/domains Domain blocklist<br>
    <span style="color:#06d6a0">TAX</span>  /taxii/ &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; TAXII 2.1 discovery endpoint<br>
    <span style="color:#b48ef5">DOC</span>  /docs &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Swagger UI (interactive API browser)
  </div>
</div>""", unsafe_allow_html=True)
