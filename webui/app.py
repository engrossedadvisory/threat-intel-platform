import json
import os
from datetime import datetime, timezone

import pandas as pd
import streamlit as st
from sqlalchemy import create_engine, text
from streamlit_autorefresh import st_autorefresh

st.set_page_config(page_title="Threat Intel Platform", layout="wide", page_icon="🛡️")
st_autorefresh(interval=30000, key="refresh")

from sqlalchemy.engine import URL as _URL

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
            """
            SELECT mm.mitigation_id, mm.name, mm.description,
                   mt.technique_id, mt.name AS tech_name, mt.tactic
            FROM mitre_mitigations mm
            JOIN mitre_techniques mt ON mm.technique_fk = mt.id
            ORDER BY mt.technique_id, mm.mitigation_id
            """,
            engine,
        )
        return techniques, mitigations
    except Exception:
        return pd.DataFrame(), pd.DataFrame()


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
tab_feed, tab_iocs, tab_cves, tab_attack, tab_health = st.tabs(
    ["🚨 Threat Feed", "🔍 IOC Search", "⚠️ CVE Tracker", "🗺️ ATT&CK Mapping", "📊 Feed Health"]
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


# ── ATT&CK Mapping & Remediation ─────────────────────────────────────────────
with tab_attack:
    st.subheader("MITRE ATT&CK Mapping & Remediation")

    techniques_df, mitigations_df = load_attack_data()

    if techniques_df.empty:
        st.info(
            "ATT&CK data not yet loaded — the collector populates this on its first "
            "MITRE ATT&CK cycle (runs once every 24 h). Check back shortly."
        )
    else:
        # ── Build TTP usage map from threat reports ────────────────────────────
        ttp_usage: dict = {}   # technique_id -> {count, actors}
        for _, row in reports.iterrows():
            raw_ttps = row.get("ttps") or []
            if isinstance(raw_ttps, str):
                try:
                    raw_ttps = json.loads(raw_ttps)
                except Exception:
                    raw_ttps = []
            actor = str(row.get("threat_actor") or "Unknown")
            for ttp in (raw_ttps or []):
                entry = ttp_usage.setdefault(ttp, {"count": 0, "actors": set()})
                entry["count"] += 1
                entry["actors"].add(actor)

        observed_ids = set(ttp_usage.keys())
        observed_techniques = techniques_df[techniques_df["technique_id"].isin(observed_ids)].copy()

        # ── Top metrics ───────────────────────────────────────────────────────
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.metric("Techniques in DB", len(techniques_df))
        with m2:
            st.metric("Observed in Threats", len(observed_techniques))
        with m3:
            unique_tactics = set(
                t.strip()
                for tactic_str in observed_techniques["tactic"].dropna()
                for t in tactic_str.split(",")
                if t.strip()
            )
            st.metric("Tactics Covered", len(unique_tactics))
        with m4:
            st.metric("Mitigations Available", len(mitigations_df))

        st.divider()

        # ── Tactic distribution chart ──────────────────────────────────────────
        if not observed_techniques.empty:
            st.markdown("#### Threat Activity by ATT&CK Tactic")
            tactic_counts: dict = {}
            for _, row in observed_techniques.iterrows():
                tid = row["technique_id"]
                count = ttp_usage.get(tid, {}).get("count", 0)
                for tactic in str(row.get("tactic") or "Unknown").split(","):
                    tactic = tactic.strip() or "Unknown"
                    tactic_counts[tactic] = tactic_counts.get(tactic, 0) + count

            tactic_df = (
                pd.DataFrame(list(tactic_counts.items()), columns=["Tactic", "Threat Count"])
                .sort_values("Threat Count", ascending=False)
            )
            st.bar_chart(tactic_df.set_index("Tactic"))
            st.divider()

        # ── Observed techniques with remediation drill-down ───────────────────
        st.markdown("#### Techniques Observed in Threat Reports")
        if observed_techniques.empty:
            st.info(
                "No ATT&CK TTPs extracted yet. TTPs are populated by the AI analyzer "
                "when processing OTX pulses or other enriched feeds."
            )
        else:
            observed_techniques["threat_count"] = observed_techniques["technique_id"].map(
                lambda tid: ttp_usage.get(tid, {}).get("count", 0)
            )
            observed_techniques["actors"] = observed_techniques["technique_id"].map(
                lambda tid: ", ".join(sorted(ttp_usage.get(tid, {}).get("actors", set())))
            )
            observed_techniques = observed_techniques.sort_values("threat_count", ascending=False)

            for _, tech in observed_techniques.iterrows():
                tid = tech["technique_id"]
                label = (
                    f"**{tid}** — {tech['name']}  |  "
                    f"Tactic: {tech.get('tactic','?')}  |  "
                    f"Seen in {tech['threat_count']} report(s)"
                )
                with st.expander(label):
                    col_l, col_r = st.columns([2, 3])
                    with col_l:
                        st.markdown(f"**Actors:** {tech['actors'] or 'Unknown'}")
                        desc = str(tech.get("description") or "")
                        st.markdown(f"**Description:** {desc[:600]}{'…' if len(desc) > 600 else ''}")
                        st.markdown(
                            f"[View on MITRE ATT&CK](https://attack.mitre.org/techniques/{tid.replace('.', '/')})",
                        )
                    with col_r:
                        tech_mits = mitigations_df[mitigations_df["technique_id"] == tid]
                        if tech_mits.empty:
                            st.info("No specific mitigations mapped for this technique.")
                        else:
                            st.markdown(f"**{len(tech_mits)} MITRE Mitigation(s):**")
                            for _, mit in tech_mits.iterrows():
                                with st.container():
                                    st.markdown(f"🛡️ `{mit['mitigation_id']}` **{mit['name']}**")
                                    mit_desc = str(mit.get("description") or "")
                                    st.caption(
                                        mit_desc[:400] + ("…" if len(mit_desc) > 400 else "")
                                    )

        st.divider()

        # ── Full remediation reference lookup ─────────────────────────────────
        st.markdown("#### Full Remediation Reference")
        all_tech_options = [
            f"{row['technique_id']} — {row['name']}"
            for _, row in techniques_df.iterrows()
        ]
        selected = st.selectbox(
            "Look up any technique",
            options=["— select —"] + all_tech_options,
            key="attack_lookup",
        )
        if selected and selected != "— select —":
            sel_id = selected.split(" — ")[0]
            tech_row = techniques_df[techniques_df["technique_id"] == sel_id]
            if not tech_row.empty:
                t = tech_row.iloc[0]
                st.markdown(f"### {t['technique_id']} — {t['name']}")
                st.markdown(f"**Tactic(s):** {t.get('tactic','Unknown')}")
                st.markdown("**Description:**")
                st.markdown(str(t.get("description") or "No description available."))
                st.markdown(
                    f"[🔗 MITRE ATT&CK Reference](https://attack.mitre.org/techniques/{sel_id.replace('.', '/')})"
                )
                st.divider()
                tech_mits = mitigations_df[mitigations_df["technique_id"] == sel_id]
                if tech_mits.empty:
                    st.info("No mitigations mapped for this technique in the current ATT&CK dataset.")
                else:
                    st.markdown(f"#### Recommended Mitigations ({len(tech_mits)})")
                    for _, mit in tech_mits.iterrows():
                        with st.expander(f"🛡️ `{mit['mitigation_id']}` {mit['name']}"):
                            st.markdown(str(mit.get("description") or ""))
                            st.markdown(
                                f"[View mitigation on MITRE ATT&CK](https://attack.mitre.org/mitigations/{mit['mitigation_id']})"
                            )


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
