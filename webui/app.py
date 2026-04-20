import os
from datetime import datetime, timezone

import pandas as pd
import streamlit as st
from sqlalchemy import create_engine
from streamlit_autorefresh import st_autorefresh

st.set_page_config(page_title="Threat Intel Platform", layout="wide", page_icon="🛡️")
st_autorefresh(interval=30000, key="refresh")

DATABASE_URL = os.getenv("DATABASE_URL") or (
    f"postgresql://{os.getenv('POSTGRES_USER','intel_admin')}"
    f":{os.getenv('POSTGRES_PASSWORD','change_me')}"
    f"@{os.getenv('POSTGRES_HOST','db')}:5432"
    f"/{os.getenv('POSTGRES_DB','threat_intel')}"
)


@st.cache_resource
def get_engine():
    return create_engine(DATABASE_URL, pool_pre_ping=True)


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


# ─── Header ───────────────────────────────────────────────────────────────────
st.title("🛡️ Threat Intelligence Platform")
st.caption(
    f"Live OSINT — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC · "
    "Auto-refreshes every 30s"
)

reports, iocs, cves, feed_status = load_data()

# ─── Top metrics ──────────────────────────────────────────────────────────────
c1, c2, c3, c4, c5 = st.columns(5)
with c1:
    st.metric("Threat Reports", len(reports))
with c2:
    st.metric("IOCs Tracked", len(iocs))
with c3:
    st.metric("CVEs Monitored", len(cves))
with c4:
    kev_count = int((cves["is_kev"] == 1).sum()) if not cves.empty and "is_kev" in cves else 0
    st.metric("CISA KEV", kev_count)
with c5:
    active = int((feed_status["status"] == "ok").sum()) if not feed_status.empty else 0
    total = len(feed_status)
    st.metric("Active Feeds", f"{active} / {total}")

st.divider()

# ─── Tabs ─────────────────────────────────────────────────────────────────────
tab_feed, tab_iocs, tab_cves, tab_health = st.tabs(
    ["🚨 Threat Feed", "🔍 IOC Search", "⚠️ CVE Tracker", "📊 Feed Health"]
)


# ── Threat Feed ───────────────────────────────────────────────────────────────
with tab_feed:
    st.subheader("Active Threat Reports")

    if reports.empty:
        st.info("Collector is initializing feeds — check back in a few minutes.")
    else:
        col_a, col_b = st.columns(2)
        with col_a:
            sources = sorted(reports["source_feed"].dropna().unique().tolist())
            feed_filter = st.multiselect("Filter by Source", options=sources)
        with col_b:
            min_conf = st.slider("Min Confidence Score", 0, 100, 0)

        filtered = reports.copy()
        if feed_filter:
            filtered = filtered[filtered["source_feed"].isin(feed_filter)]
        filtered = filtered[filtered["confidence_score"] >= min_conf]

        st.caption(f"Showing {min(len(filtered), 50)} of {len(filtered)} reports")

        for _, row in filtered.head(50).iterrows():
            ts = (
                row["created_at"].strftime("%Y-%m-%d %H:%M")
                if hasattr(row["created_at"], "strftime")
                else str(row["created_at"])
            )
            actor = row.get("threat_actor") or "Unknown"
            industry = row.get("target_industry") or "Unknown"
            conf = int(row.get("confidence_score") or 0)
            feed = str(row.get("source_feed", "")).upper()

            label = f"[{ts}] [{feed}]  {actor}  →  {industry}  |  Confidence: {conf}%"
            with st.expander(label):
                summary = row.get("summary")
                if summary:
                    st.markdown(f"**Summary:** {summary}")

                col_l, col_r = st.columns(2)
                with col_l:
                    ttps = row.get("ttps") or []
                    if ttps:
                        st.markdown("**MITRE TTPs:** " + "  ".join(f"`{t}`" for t in ttps[:6]))
                    cve_list = row.get("associated_cves") or []
                    if cve_list:
                        st.markdown("**CVEs:** " + "  ".join(f"`{c}`" for c in cve_list[:5]))

                with col_r:
                    report_iocs = iocs[iocs["report_id"] == row["id"]]
                    if not report_iocs.empty:
                        st.markdown(f"**IOCs ({len(report_iocs)}):**")
                        display = [c for c in ["ioc_type", "value", "malware_family"] if c in report_iocs.columns]
                        st.dataframe(report_iocs[display].head(10), use_container_width=True, hide_index=True)

                raw = str(row.get("raw_source") or "")
                st.code(raw[:600] + ("…" if len(raw) > 600 else ""), language="text")


# ── IOC Search ────────────────────────────────────────────────────────────────
with tab_iocs:
    st.subheader("IOC Search & Export")

    if iocs.empty:
        st.info("No IOCs collected yet.")
    else:
        col_a, col_b = st.columns(2)
        with col_a:
            search = st.text_input("Search value (IP, domain, hash, URL…)")
        with col_b:
            ioc_types = sorted(iocs["ioc_type"].dropna().unique().tolist())
            type_filter = st.multiselect("Filter by Type", options=ioc_types)

        filtered_iocs = iocs.copy()
        if search:
            filtered_iocs = filtered_iocs[
                filtered_iocs["value"].str.contains(search, case=False, na=False)
            ]
        if type_filter:
            filtered_iocs = filtered_iocs[filtered_iocs["ioc_type"].isin(type_filter)]

        st.caption(f"{len(filtered_iocs)} IOCs match")
        display_cols = [c for c in ["ioc_type", "value", "malware_family", "tags"] if c in filtered_iocs.columns]
        st.dataframe(filtered_iocs[display_cols].head(500), use_container_width=True, hide_index=True)

        csv = filtered_iocs[display_cols].to_csv(index=False).encode()
        st.download_button("⬇ Export as CSV", csv, "iocs_export.csv", "text/csv")


# ── CVE Tracker ───────────────────────────────────────────────────────────────
with tab_cves:
    st.subheader("CVE Tracker")

    if cves.empty:
        st.info("CVE data is loading from CISA KEV and NVD feeds…")
    else:
        col_a, col_b = st.columns(2)
        with col_a:
            kev_only = st.checkbox("CISA KEV only", value=False)
        with col_b:
            min_cvss = st.slider("Min CVSS Score", 0.0, 10.0, 0.0, 0.1)

        filtered_cves = cves.copy()
        if kev_only and "is_kev" in filtered_cves.columns:
            filtered_cves = filtered_cves[filtered_cves["is_kev"] == 1]
        if min_cvss > 0 and "cvss_score" in filtered_cves.columns:
            filtered_cves = filtered_cves[filtered_cves["cvss_score"].fillna(0) >= min_cvss]

        display_cols = [
            c for c in ["cve_id", "cvss_score", "vendor", "product", "cisa_due_date", "is_kev", "description"]
            if c in filtered_cves.columns
        ]
        st.dataframe(
            filtered_cves[display_cols].head(200),
            use_container_width=True,
            hide_index=True,
            column_config={
                "is_kev": st.column_config.CheckboxColumn("CISA KEV"),
                "cvss_score": st.column_config.NumberColumn("CVSS", format="%.1f"),
                "description": st.column_config.TextColumn("Description", width="large"),
            },
        )

        csv = filtered_cves[display_cols].to_csv(index=False).encode()
        st.download_button("⬇ Export CVEs as CSV", csv, "cves_export.csv", "text/csv")


# ── Feed Health ───────────────────────────────────────────────────────────────
with tab_health:
    st.subheader("Feed Health & Status")

    if feed_status.empty:
        st.info("No feed status yet — collector may still be starting.")
    else:
        for _, row in feed_status.iterrows():
            icon = {"ok": "✅", "error": "❌", "running": "🔄", "pending": "⏳"}.get(
                str(row.get("status", "")), "❓"
            )
            last_run = (
                row["last_run"].strftime("%Y-%m-%d %H:%M:%S")
                if pd.notna(row.get("last_run")) and hasattr(row["last_run"], "strftime")
                else "Never"
            )
            col_a, col_b, col_c, col_d = st.columns([2, 3, 1, 4])
            with col_a:
                st.markdown(f"{icon} **{str(row['feed_name']).upper()}**")
            with col_b:
                st.caption(f"Last run: {last_run}")
            with col_c:
                st.caption(f"Total: {int(row.get('total_records') or 0)}")
            with col_d:
                err = row.get("error_message")
                if err:
                    st.caption(f"⚠️ {str(err)[:120]}")
