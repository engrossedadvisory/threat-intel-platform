#!/usr/bin/env bash
# Threat Intelligence Platform — Setup & Launch Script
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[ERR ]${NC}  $*" >&2; exit 1; }
header()  { echo -e "\n${BOLD}${BLUE}$*${NC}"; }

echo ""
echo -e "${BOLD}  ╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}  ║       Threat Intelligence Platform — Installer          ║${NC}"
echo -e "${BOLD}  ║       Legal OSINT Sources Only                          ║${NC}"
echo -e "${BOLD}  ╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ─── 1. Prerequisites ─────────────────────────────────────────────────────────
header "1/5  Checking prerequisites"

command -v docker  >/dev/null 2>&1 || die "Docker not found. Install from https://docs.docker.com/get-docker/"
command -v git     >/dev/null 2>&1 || die "git not found. Install git and re-run."
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 not found. Update Docker Desktop or install the compose plugin."
ok "Docker and git are available."

# Check Docker daemon is running
docker info >/dev/null 2>&1 || die "Docker daemon is not running. Start Docker and re-run."
ok "Docker daemon is running."

# ─── 2. Environment file ──────────────────────────────────────────────────────
header "2/5  Configuring environment"

if [ ! -f .env ]; then
    cp .env.example .env
    info "Created .env from .env.example"

    # Prompt for a secure DB password
    echo ""
    read -rsp "$(echo -e ${BLUE}Enter a strong database password${NC}: )" DB_PASS
    echo ""
    if [ -n "$DB_PASS" ]; then
        # Update both the POSTGRES_PASSWORD and DATABASE_URL lines
        sed -i.bak \
            -e "s|change_me_strong_password|${DB_PASS}|g" \
            .env && rm -f .env.bak
        ok "Database password set."
    else
        warn "Using default password — change POSTGRES_PASSWORD in .env before exposing this to a network."
    fi

    echo ""
    echo -e "${YELLOW}Optional API keys (press Enter to skip any):${NC}"
    echo ""

    read -rsp "Claude API key (https://console.anthropic.com/): " CLAUDE_KEY; echo ""
    [ -n "$CLAUDE_KEY" ] && sed -i.bak "s|^CLAUDE_API_KEY=.*|CLAUDE_API_KEY=${CLAUDE_KEY}|" .env && rm -f .env.bak

    read -rsp "Gemini API key (https://aistudio.google.com/): " GEMINI_KEY; echo ""
    [ -n "$GEMINI_KEY" ] && sed -i.bak "s|^GEMINI_API_KEY=.*|GEMINI_API_KEY=${GEMINI_KEY}|" .env && rm -f .env.bak

    read -rsp "AlienVault OTX API key (https://otx.alienvault.com/api): " OTX_KEY; echo ""
    [ -n "$OTX_KEY" ] && sed -i.bak "s|^OTX_API_KEY=.*|OTX_API_KEY=${OTX_KEY}|" .env && rm -f .env.bak

    ok ".env configured."
else
    ok ".env already exists — skipping configuration."
fi

# ─── 3. Ollama advisory ───────────────────────────────────────────────────────
header "3/5  Ollama (local AI) check"

if command -v ollama >/dev/null 2>&1; then
    OLLAMA_MODEL=$(grep "^OLLAMA_MODEL=" .env | cut -d= -f2 || echo "llama3.2")
    info "Ollama found. Pulling model: ${OLLAMA_MODEL}"
    ollama pull "$OLLAMA_MODEL" || warn "Could not pull ${OLLAMA_MODEL} — pull it manually with: ollama pull ${OLLAMA_MODEL}"
    ok "Ollama model ready."
else
    warn "Ollama not installed locally. The collector will fall back to Claude or Gemini API."
    warn "To install Ollama: https://ollama.com  — then run: ollama pull llama3.2"
fi

# ─── 4. Git repository ────────────────────────────────────────────────────────
header "4/5  Initializing git repository"

if [ ! -d .git ]; then
    git init
    git add .
    git commit -m "feat: initial commit — Threat Intelligence Platform

Sources: CISA KEV, ThreatFox, URLhaus, MalwareBazaar, NVD, MITRE ATT&CK, AlienVault OTX
Stack: PostgreSQL + Python collector + Streamlit dashboard + Docker Compose
AI: Ollama (local) with Claude / Gemini cloud fallbacks"
    ok "Git repository initialized with initial commit."
else
    ok "Git repository already initialized."
fi

# ─── 5. Build and launch ──────────────────────────────────────────────────────
header "5/5  Building and launching containers"

info "Building Docker images (first build may take 2-3 minutes)…"
docker compose build

info "Starting services in the background…"
docker compose up -d

# Wait briefly then show status
sleep 3
echo ""
docker compose ps
echo ""

ok "Platform is running!"
echo ""
echo -e "  ${BOLD}Dashboard:${NC}  http://localhost:8501"
echo -e "  ${BOLD}Logs:${NC}       docker compose logs -f collector"
echo -e "  ${BOLD}Stop:${NC}       docker compose down"
echo -e "  ${BOLD}Wipe data:${NC}  docker compose down -v"
echo ""
echo -e "  ${YELLOW}Feeds begin collecting immediately. The dashboard updates every 30 seconds.${NC}"
echo -e "  ${YELLOW}CISA KEV and ThreatFox data appear first (~1 minute).${NC}"
echo ""
