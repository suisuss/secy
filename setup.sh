#!/usr/bin/env bash
# setup.sh — Install, uninstall, start, and stop secy.
#
# Usage:
#   ./setup.sh install     Full installation (build image, start services, setup notifications)
#   ./setup.sh uninstall   Remove everything (stop services, remove images, remove notifications)
#   ./setup.sh start       Start all secy services
#   ./setup.sh stop        Stop all secy services
#   ./setup.sh status      Show status of all components
#   ./setup.sh doctor      Check prerequisites and diagnose issues
#
set -euo pipefail

SECY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Colors ────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "${GREEN}[secy]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[secy]${RESET} $*"; }
error()   { echo -e "${RED}[secy]${RESET} $*" >&2; }
header()  { echo ""; echo -e "${BOLD}$*${RESET}"; echo ""; }

# ══════════════════════════════════════════════════════════════════
# DOCTOR — prerequisite checks
# ══════════════════════════════════════════════════════════════════

doctor() {
    header "secy doctor — checking prerequisites"

    local issues=0

    # Docker
    if command -v docker &>/dev/null; then
        local docker_ver
        docker_ver="$(docker --version 2>/dev/null | head -1)"
        info "Docker: ${docker_ver}"

        if docker info &>/dev/null; then
            info "Docker daemon: running"
        else
            error "Docker daemon: not running or no permission"
            warn "  Try: sudo systemctl start docker"
            warn "  Or add user to docker group: sudo usermod -aG docker \$USER"
            issues=$((issues + 1))
        fi
    else
        error "Docker: not installed"
        warn "  Install: https://docs.docker.com/engine/install/"
        issues=$((issues + 1))
    fi

    # Docker Compose
    if docker compose version &>/dev/null 2>&1; then
        local compose_ver
        compose_ver="$(docker compose version 2>/dev/null | head -1)"
        info "Compose: ${compose_ver}"
    else
        error "Docker Compose: not found"
        warn "  Install: https://docs.docker.com/compose/install/"
        issues=$((issues + 1))
    fi

    # Authentication
    local auth_method="none"
    if [[ -f "${SECY_DIR}/.env" ]] && grep -q "^ANTHROPIC_API_KEY=" "${SECY_DIR}/.env" 2>/dev/null; then
        local key
        key="$(grep '^ANTHROPIC_API_KEY=' "${SECY_DIR}/.env" | cut -d= -f2)"
        if [[ -n "$key" ]] && [[ "$key" != "sk-ant-..." ]]; then
            auth_method="api-key"
            info "Auth: API key found in .env"
        fi
    fi
    if [[ -f "${HOME}/.claude/.credentials.json" ]]; then
        if [[ "$auth_method" == "none" ]]; then
            auth_method="oauth"
        fi
        info "Auth: OAuth credentials found at ~/.claude/.credentials.json"
    fi
    if [[ "$auth_method" == "none" ]]; then
        error "Auth: no credentials found"
        warn "  Option A: Log in with Claude CLI: claude login"
        warn "  Option B: Create .env with ANTHROPIC_API_KEY=sk-ant-..."
        issues=$((issues + 1))
    fi

    # inotify-tools (for notifications)
    if command -v inotifywait &>/dev/null; then
        info "inotify-tools: installed"
    else
        warn "inotify-tools: not installed (needed for desktop notifications)"
        warn "  Install: sudo apt install inotify-tools"
    fi

    # libnotify (for notifications)
    if command -v notify-send &>/dev/null; then
        info "libnotify-bin: installed"
    else
        warn "libnotify-bin: not installed (needed for desktop notifications)"
        warn "  Install: sudo apt install libnotify-bin"
    fi

    # Disk space
    local avail_mb
    avail_mb="$(df -m "${SECY_DIR}" 2>/dev/null | awk 'NR==2{print $4}')"
    if [[ -n "$avail_mb" ]]; then
        if [[ "$avail_mb" -lt 2048 ]]; then
            warn "Disk: ${avail_mb}MB available (recommend 2GB+)"
        else
            info "Disk: ${avail_mb}MB available"
        fi
    fi

    # Issues directory
    if [[ -d "${SECY_DIR}/issues" ]]; then
        local owner
        owner="$(stat -c%U "${SECY_DIR}/issues" 2>/dev/null || echo "?")"
        if [[ "$owner" == "$(whoami)" ]]; then
            info "Issues dir: OK (owned by $(whoami))"
        else
            warn "Issues dir: owned by ${owner} — notifications may not work"
            warn "  Fix: sudo chown \$USER:\$USER ${SECY_DIR}/issues"
        fi
    else
        info "Issues dir: will be created on install"
    fi

    echo ""
    if [[ $issues -eq 0 ]]; then
        info "All prerequisites met. Ready to install."
    else
        error "${issues} issue(s) found. Fix them before running ./setup.sh install"
    fi

    return $issues
}

# ══════════════════════════════════════════════════════════════════
# INSTALL
# ══════════════════════════════════════════════════════════════════

do_install() {
    header "secy install"

    # ── 1. Prerequisites ──────────────────────────────────────────
    info "Checking prerequisites..."
    if ! doctor; then
        echo ""
        error "Fix prerequisites before installing."
        exit 1
    fi

    # ── 2. Create host directories ────────────────────────────────
    header "Creating directories"
    mkdir -p "${SECY_DIR}/issues"
    info "issues/ directory ready"

    # ── 3. Build Docker image ─────────────────────────────────────
    header "Building Docker image"
    info "This may take a few minutes on first build..."
    docker compose -f "${SECY_DIR}/docker-compose.yml" build

    info "Image built successfully"

    # ── 4. Start daemon services ──────────────────────────────────
    header "Starting services"
    _start_containers

    # ── 5. Verify containers ──────────────────────────────────────
    info "Waiting for services to start..."
    sleep 3
    _check_containers

    # ── 6. Install notifications ──────────────────────────────────
    header "Setting up desktop notifications"

    local has_notify_deps=true
    command -v inotifywait &>/dev/null || has_notify_deps=false
    command -v notify-send &>/dev/null || has_notify_deps=false

    if $has_notify_deps; then
        "${SECY_DIR}/scripts/setup-notify.sh"
    else
        warn "Skipping notifications — install inotify-tools and libnotify-bin first"
        warn "Then run: ./scripts/setup-notify.sh"
    fi

    # ── 7. Summary ────────────────────────────────────────────────
    header "Installation complete"
    do_status
    echo ""
    info "Commands:"
    info "  ./setup.sh status     Check everything"
    info "  ./setup.sh stop       Stop all services"
    info "  ./setup.sh start      Start all services"
    info "  ./setup.sh uninstall  Remove everything"
}

# ══════════════════════════════════════════════════════════════════
# UNINSTALL
# ══════════════════════════════════════════════════════════════════

do_uninstall() {
    header "secy uninstall"

    # ── 1. Stop notifications ─────────────────────────────────────
    info "Removing desktop notifications..."
    if [[ -x "${SECY_DIR}/scripts/setup-notify.sh" ]]; then
        "${SECY_DIR}/scripts/setup-notify.sh" --uninstall 2>/dev/null || true
    fi

    # ── 2. Stop and remove containers ─────────────────────────────
    info "Stopping containers..."
    docker compose -f "${SECY_DIR}/docker-compose.yml" down 2>/dev/null || true

    # ── 3. Remove volumes ─────────────────────────────────────────
    echo ""
    read -rp "Remove secy-state volume? This deletes all patrol history and findings. [y/N] " answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        docker compose -f "${SECY_DIR}/docker-compose.yml" down -v 2>/dev/null || true
        info "Volumes removed"
    else
        info "Volumes kept"
    fi

    # ── 4. Remove images ──────────────────────────────────────────
    echo ""
    read -rp "Remove Docker images? You'll need to rebuild on next install. [y/N] " answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        docker rmi secy 2>/dev/null || true
        docker rmi secy-threatlab 2>/dev/null || true
        info "Images removed"
    else
        info "Images kept"
    fi

    # ── 5. Clean up issue files ───────────────────────────────────
    echo ""
    read -rp "Remove issue files in ./issues/? [y/N] " answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        rm -f "${SECY_DIR}"/issues/*.md
        info "Issues cleaned"
    else
        info "Issues kept"
    fi

    echo ""
    info "Uninstall complete"
}

# ══════════════════════════════════════════════════════════════════
# START
# ══════════════════════════════════════════════════════════════════

do_start() {
    header "secy start"

    # Check image exists
    if ! docker image inspect secy &>/dev/null; then
        error "secy image not found. Run ./setup.sh install first."
        exit 1
    fi

    _start_containers

    # Start notification service
    if systemctl --user is-enabled secy-notify &>/dev/null 2>&1; then
        systemctl --user start secy-notify 2>/dev/null || true
        info "Notification watcher started"
    fi

    sleep 2
    do_status
}

# ══════════════════════════════════════════════════════════════════
# STOP
# ══════════════════════════════════════════════════════════════════

do_stop() {
    header "secy stop"

    # Stop containers
    info "Stopping containers..."
    docker compose -f "${SECY_DIR}/docker-compose.yml" stop 2>/dev/null || true
    info "Containers stopped"

    # Stop notification service
    if systemctl --user is-active secy-notify &>/dev/null 2>&1; then
        systemctl --user stop secy-notify 2>/dev/null || true
        info "Notification watcher stopped"
    fi

    echo ""
    info "All services stopped. Run ./setup.sh start to resume."
}

# ══════════════════════════════════════════════════════════════════
# STATUS
# ══════════════════════════════════════════════════════════════════

do_status() {
    header "secy status"

    # ── Docker image ──────────────────────────────────────────────
    echo -e "${BOLD}Image:${RESET}"
    if docker image inspect secy &>/dev/null; then
        local image_created
        image_created="$(docker image inspect secy --format '{{.Created}}' 2>/dev/null | cut -d. -f1)"
        info "  secy image: built ${image_created}"
    else
        error "  secy image: not built"
    fi
    echo ""

    # ── Containers ────────────────────────────────────────────────
    echo -e "${BOLD}Containers:${RESET}"
    local containers="secy-secy-watch-1 secy-secy-patrol-1 secy-secy-c2-1"
    for container in $containers; do
        local short_name="${container#secy-secy-}"
        short_name="${short_name%-1}"
        local status
        status="$(docker inspect -f '{{.State.Status}}' "$container" 2>/dev/null | head -1 || true)"
        [[ -z "$status" ]] && status="not created"

        if [[ "$status" == "running" ]]; then
            local uptime
            uptime="$(docker inspect -f '{{.State.StartedAt}}' "$container" 2>/dev/null | cut -d. -f1)"
            info "  ${short_name}: running (since ${uptime})"
        else
            error "  ${short_name}: ${status}"
        fi
    done
    echo ""

    # ── Notifications ─────────────────────────────────────────────
    echo -e "${BOLD}Notifications:${RESET}"
    if systemctl --user is-active --quiet secy-notify 2>/dev/null; then
        info "  secy-notify service: running"
    elif systemctl --user is-enabled --quiet secy-notify 2>/dev/null; then
        warn "  secy-notify service: enabled but not running"
    else
        warn "  secy-notify service: not installed"
    fi

    local cron_tag="secy-notify-healthcheck"
    if crontab -l 2>/dev/null | grep -q "$cron_tag"; then
        info "  cron healthcheck: installed"
    else
        warn "  cron healthcheck: not installed"
    fi
    echo ""

    # ── Issues ────────────────────────────────────────────────────
    echo -e "${BOLD}Issues:${RESET}"
    if [[ -d "${SECY_DIR}/issues" ]]; then
        local count
        count="$(find "${SECY_DIR}/issues" -maxdepth 1 -name '*.md' -type f 2>/dev/null | wc -l)"
        info "  ${count} issue(s) on file in ./issues/"
    else
        warn "  issues/ directory not found"
    fi

    # ── Auth ──────────────────────────────────────────────────────
    echo ""
    echo -e "${BOLD}Auth:${RESET}"
    if [[ -f "${SECY_DIR}/.env" ]] && grep -q "^ANTHROPIC_API_KEY=" "${SECY_DIR}/.env" 2>/dev/null; then
        local key
        key="$(grep '^ANTHROPIC_API_KEY=' "${SECY_DIR}/.env" | cut -d= -f2)"
        if [[ -n "$key" ]] && [[ "$key" != "sk-ant-..." ]]; then
            info "  API key: configured in .env"
        fi
    fi
    if [[ -f "${HOME}/.claude/.credentials.json" ]]; then
        info "  OAuth: credentials present"
    fi
}

# ══════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════

_start_containers() {
    info "Starting watch, patrol, and c2 services..."
    docker compose -f "${SECY_DIR}/docker-compose.yml" up -d secy-watch secy-patrol secy-c2
    info "Containers started"
}

_check_containers() {
    local containers="secy-secy-watch-1 secy-secy-patrol-1 secy-secy-c2-1"
    local all_running=true
    for container in $containers; do
        local status
        status="$(docker inspect -f '{{.State.Status}}' "$container" 2>/dev/null | head -1 || true)"
        [[ -z "$status" ]] && status="missing"
        local short_name="${container#secy-secy-}"
        short_name="${short_name%-1}"

        if [[ "$status" == "running" ]]; then
            info "  ${short_name}: running"
        else
            error "  ${short_name}: ${status}"
            all_running=false
        fi
    done

    if ! $all_running; then
        error "Some services failed to start. Check: docker compose logs"
        exit 1
    fi
}

# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════

main() {
    case "${1:-}" in
        install)
            do_install
            ;;
        uninstall)
            do_uninstall
            ;;
        start)
            do_start
            ;;
        stop)
            do_stop
            ;;
        status)
            do_status
            ;;
        doctor)
            doctor
            ;;
        --help|-h|"")
            echo -e "${BOLD}secy — Autonomous Security Monitor${RESET}"
            echo ""
            echo "Usage: ./setup.sh <command>"
            echo ""
            echo "Commands:"
            echo "  install     Build image, start services, setup notifications"
            echo "  uninstall   Stop everything, optionally remove data and images"
            echo "  start       Start all secy services"
            echo "  stop        Stop all secy services"
            echo "  status      Show status of all components"
            echo "  doctor      Check prerequisites and diagnose issues"
            echo ""
            echo "One-shot scans (after install):"
            echo "  docker compose run --rm secy audit       Full security sweep"
            echo "  docker compose run --rm secy baseline    Capture system baseline"
            echo "  docker compose run --rm secy monitor     Compare to baseline"
            ;;
        *)
            error "Unknown command: $1"
            echo "Run ./setup.sh --help for usage"
            exit 1
            ;;
    esac
}

main "$@"
