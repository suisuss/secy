#!/usr/bin/env bash
# setup-notify.sh — Install secy desktop notification watcher.
# Sets up: systemd user service (autostart) + hourly cron health check.
#
# Usage: ./scripts/setup-notify.sh
#        ./scripts/setup-notify.sh --uninstall
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECY_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

SERVICE_NAME="secy-notify"
SERVICE_FILE="${SERVICE_NAME}.service"
SYSTEMD_USER_DIR="${HOME}/.config/systemd/user"
CRON_TAG="# secy-notify-healthcheck"

# ── Colors ────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

info()  { echo -e "${GREEN}[setup]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[setup]${RESET} $*"; }
error() { echo -e "${RED}[setup]${RESET} $*" >&2; }

# ── Dependency check ──────────────────────────────────────────────

check_deps() {
    local missing=()
    command -v inotifywait &>/dev/null || missing+=("inotify-tools")
    command -v notify-send &>/dev/null || missing+=("libnotify-bin")
    command -v systemctl &>/dev/null   || { error "systemd not found"; exit 1; }

    if [[ ${#missing[@]} -gt 0 ]]; then
        warn "Missing packages: ${missing[*]}"
        echo ""
        read -rp "Install with apt? [y/N] " answer
        if [[ "$answer" =~ ^[Yy]$ ]]; then
            sudo apt install -y "${missing[@]}"
        else
            error "Cannot continue without: ${missing[*]}"
            exit 1
        fi
    fi
}

# ── Install ───────────────────────────────────────────────────────

install_service() {
    info "Installing systemd user service..."

    mkdir -p "$SYSTEMD_USER_DIR"
    cp "${SCRIPT_DIR}/${SERVICE_FILE}" "${SYSTEMD_USER_DIR}/${SERVICE_FILE}"

    systemctl --user daemon-reload
    systemctl --user enable "$SERVICE_NAME"
    systemctl --user start "$SERVICE_NAME"

    if systemctl --user is-active --quiet "$SERVICE_NAME"; then
        info "Service started: ${SERVICE_NAME}"
    else
        error "Service failed to start. Check: systemctl --user status ${SERVICE_NAME}"
        exit 1
    fi
}

install_cron() {
    info "Installing hourly health check cron..."

    local cron_line="0 * * * * DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/\$(id -u)/bus DISPLAY=:0 ${SCRIPT_DIR}/notify-healthcheck.sh ${CRON_TAG}"

    # Remove existing entry if present, then add
    local existing
    existing="$(crontab -l 2>/dev/null || true)"

    if echo "$existing" | grep -qF "$CRON_TAG"; then
        # Replace existing
        existing="$(echo "$existing" | grep -vF "$CRON_TAG")"
    fi

    echo "${existing}
${cron_line}" | crontab -

    info "Cron installed: hourly health check"
}

# ── Uninstall ─────────────────────────────────────────────────────

uninstall() {
    info "Uninstalling secy-notify..."

    # Stop and disable service
    if systemctl --user is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl --user stop "$SERVICE_NAME"
    fi
    systemctl --user disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "${SYSTEMD_USER_DIR}/${SERVICE_FILE}"
    systemctl --user daemon-reload

    info "Service removed"

    # Remove cron entry
    local existing
    existing="$(crontab -l 2>/dev/null || true)"
    if echo "$existing" | grep -qF "$CRON_TAG"; then
        echo "$existing" | grep -vF "$CRON_TAG" | crontab -
        info "Cron entry removed"
    fi

    info "Uninstall complete"
}

# ── Main ──────────────────────────────────────────────────────────

main() {
    case "${1:-}" in
        --uninstall)
            uninstall
            exit 0
            ;;
        --help|-h)
            echo "secy notify setup"
            echo ""
            echo "Usage:"
            echo "  ./scripts/setup-notify.sh              Install service + cron"
            echo "  ./scripts/setup-notify.sh --uninstall   Remove service + cron"
            echo ""
            echo "Installs:"
            echo "  ~/.config/systemd/user/secy-notify.service  (starts on login)"
            echo "  crontab entry: hourly health check with alert if service is down"
            exit 0
            ;;
    esac

    echo -e "${BOLD}secy notification watcher setup${RESET}"
    echo ""

    check_deps
    install_service
    install_cron

    echo ""
    info "Setup complete. secy-notify will:"
    info "  - Start automatically on login"
    info "  - Send desktop notifications when new issues appear in ./issues/"
    info "  - Self-heal hourly via cron (alerts if it was down)"
    echo ""
    info "Commands:"
    info "  systemctl --user status ${SERVICE_NAME}    Check status"
    info "  systemctl --user restart ${SERVICE_NAME}   Restart"
    info "  ./scripts/setup-notify.sh --uninstall      Remove everything"
}

main "$@"
