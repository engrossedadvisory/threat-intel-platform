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
INSTALL_DIR="/opt/threat-intel-platform"

# ─── Relocate to /opt if not already there ────────────────────────────────────
if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
    info "Copying project to ${INSTALL_DIR}..."
    mkdir -p "$INSTALL_DIR"
    cp -r "$SCRIPT_DIR"/. "$INSTALL_DIR"/
    ok "Project installed to ${INSTALL_DIR}."
    SCRIPT_DIR="$INSTALL_DIR"
fi

cd "$SCRIPT_DIR"

# Returns the first free TCP port at or above $1
find_free_port() {
    local port="${1:-8501}"
    while ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":${port}$" \
       || lsof -iTCP:"${port}" -sTCP:LISTEN -t >/dev/null 2>&1; do
        port=$(( port + 1 ))
    done
    echo "$port"
}

# ─── 1. Prerequisites ─────────────────────────────────────────────────────────
header "1/5  Checking prerequisites"

[ "$(id -u)" -eq 0 ] || die "Run this script with sudo: sudo ./install.sh"
command -v docker >/dev/null 2>&1 || die "Docker not found. Install from https://docs.docker.com/get-docker/"
command -v git    >/dev/null 2>&1 || die "git not found. Install git and re-run."
docker info >/dev/null 2>&1       || die "Docker daemon is not running. Run: systemctl start docker"
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 not found. Run: apt install docker-compose-plugin"
ok "Docker and git are available."

# ─── 2. Environment file ──────────────────────────────────────────────────────
header "2/5  Configuring environment"

if [ ! -f .env ]; then
    cp .env.example .env
    info "Created .env from .env.example"

    echo ""
    read -rsp "$(echo -e ${BLUE}Enter a strong database password${NC}: )" DB_PASS
    echo ""
    if [ -n "$DB_PASS" ]; then
        sed -i.bak -e "s|change_me_strong_password|${DB_PASS}|g" .env && rm -f .env.bak
        ok "Database password set."
    else
        warn "Using default password — change POSTGRES_PASSWORD in .env before exposing to a network."
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
    ollama pull "$OLLAMA_MODEL" || warn "Could not pull ${OLLAMA_MODEL} — run manually: ollama pull ${OLLAMA_MODEL}"
    ok "Ollama model ready."
else
    warn "Ollama not installed. The collector will fall back to Claude or Gemini API."
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

# Resolve a free port and persist it to .env so compose picks it up
WEBUI_PORT=$(find_free_port 8501)
if grep -q "^WEBUI_PORT=" .env 2>/dev/null; then
    sed -i.bak "s|^WEBUI_PORT=.*|WEBUI_PORT=${WEBUI_PORT}|" .env && rm -f .env.bak
else
    echo "WEBUI_PORT=${WEBUI_PORT}" >> .env
fi
info "Dashboard will be served on port ${WEBUI_PORT}."

info "Building Docker images (first build may take 2-3 minutes)…"
docker compose build

info "Starting services in the background…"
docker compose up -d

sleep 3
echo ""
docker compose ps
echo ""

ok "Platform is running!"
echo ""
echo -e "  ${BOLD}Dashboard:${NC}  http://$(hostname -I | awk '{print $1}'):${WEBUI_PORT}"
echo -e "  ${BOLD}Logs:${NC}       docker compose -f ${INSTALL_DIR}/docker-compose.yml logs -f collector"
echo -e "  ${BOLD}Stop:${NC}       docker compose -f ${INSTALL_DIR}/docker-compose.yml down"
echo -e "  ${BOLD}Wipe data:${NC}  docker compose -f ${INSTALL_DIR}/docker-compose.yml down -v"
echo ""
echo -e "  ${YELLOW}Feeds begin collecting immediately. The dashboard updates every 30 seconds.${NC}"
echo -e "  ${YELLOW}CISA KEV and ThreatFox data appear first (~1 minute).${NC}"
echo ""
