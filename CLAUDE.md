# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the Platform

```bash
# First-time setup (copies to /opt/threat-intel-platform, builds images, starts services)
sudo ./install.sh

# Day-to-day (from project root)
docker compose up -d          # start all services
docker compose down           # stop
docker compose down -v        # stop and wipe DB
docker compose logs -f collector   # stream collector logs
docker compose build          # rebuild images after code changes
```

Dashboard is at http://localhost:8501 (or `WEBUI_PORT` from `.env`).

There are no tests or linting pipelines in this project.

## Environment

Copy `.env.example` to `.env` and fill in secrets before running:
- `POSTGRES_*` — database credentials
- `CLAUDE_API_KEY`, `GEMINI_API_KEY` — cloud AI fallbacks
- `OLLAMA_URL`, `OLLAMA_MODEL` — local Ollama endpoint (primary AI)
- `ABUSECH_API_KEY`, `OTX_API_KEY` — OSINT feed credentials

## Architecture

Three Docker containers share two networks: `db_net` (internal, postgres ↔ collector) and `app_net` (postgres ↔ webui):

```
[7 OSINT APIs] → collector/worker.py → PostgreSQL ← webui/app.py → browser
                       ↓
               collector/analyzer.py (Ollama → Claude → Gemini fallback chain)
```

**Collector** (`collector/worker.py`): 30-second poll loop. Runs each feed on its configured interval (900s–86400s), then calls `_enrich_missing_ttps()` to AI-enrich any reports that lack TTPs/summaries. Feed implementations live in `collector/feeds/` and extend `BaseFeed` from `base.py`. `ALL_FEEDS` in `feeds/__init__.py` is the authoritative list.

**AI Enrichment** (`collector/analyzer.py`): Tries Ollama first, then Claude (`claude-haiku-4-5-20251001`), then Gemini. Extracts structured JSON: `threat_actor`, `industry`, `ttps` (MITRE IDs), `associated_cves`, `confidence_score`. Updates `threat_reports` in place.

**WebUI** (`webui/app.py`): Single Streamlit file (~645 lines), 6 tabs: Threat Feed, IOC Search, CVE Tracker, ATT&CK Mapping, AI Analyst (multi-turn chat with DB context), Feed Health. Data loaders use `@st.cache_data` with 30s TTL; page auto-refreshes every 30s via `streamlit-autorefresh`.

**Database** (`collector/models.py`): SQLAlchemy ORM — `ThreatReport`, `IOC`, `CVERecord`, `FeedStatus`, `MITRETechnique`, `MITREMitigation`. Always use `URL.create()` (not string interpolation) for DB connection strings — passwords can contain special characters.

## Key Patterns

- Adding a new feed: create `collector/feeds/myfeed.py` extending `BaseFeed`, then add an instance to `ALL_FEEDS` in `collector/feeds/__init__.py`. The worker loop picks it up automatically.
- Feed health is tracked in `feed_status` table via upsert in `worker.py`; the Feed Health tab reads this directly.
- The AI analyst chat in the WebUI sends a DB snapshot as system context on every request — keep that snapshot query performant.
