#!/usr/bin/env bash
# notify-healthcheck.sh — Hourly watchdog for secy infrastructure.
# Checks: notify service, patrol/watch/c2 Docker containers.
# Intended for cron: 0 * * * * /path/to/notify-healthcheck.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECY_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG_FILE="${SCRIPT_DIR}/.notify-healthcheck.log"

# Rotate log if > 100KB
if [[ -f "$LOG_FILE" ]] && [[ "$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)" -gt 102400 ]]; then
    mv "$LOG_FILE" "${LOG_FILE}.1" 2>/dev/null || true
fi

log() {
    echo "$(date -Iseconds) $*" >> "$LOG_FILE"
}

alert() {
    local title="$1" body="$2"
    if command -v notify-send &>/dev/null; then
        notify-send \
            --app-name="secy" \
            --urgency="critical" \
            --icon="dialog-error" \
            --expire-time=0 \
            "$title" \
            "$body"
    fi
    log "ALERT: ${title} — ${body}"
}

issues=0

# ── 1. Notify service ────────────────────────────────────────────

if systemctl --user is-active --quiet "secy-notify.service" 2>/dev/null; then
    log "OK: secy-notify.service is running"
else
    systemctl --user start "secy-notify.service" 2>/dev/null || true
    alert "secy: Notification Watcher Was Down" \
        "secy-notify.service was not running. Restart attempted.\nSecurity alerts may have been missed.\nCheck: systemctl --user status secy-notify"
    issues=$((issues + 1))
fi

# ── 2. Docker containers ─────────────────────────────────────────

if command -v docker &>/dev/null; then
    containers="secy-secy-watch-1 secy-secy-patrol-1 secy-secy-c2-1"
    down_list=""

    for container in $containers; do
        cstatus="$(docker inspect -f '{{.State.Status}}' "$container" 2>/dev/null | head -1 || true)"
        [[ -z "$cstatus" ]] && cstatus="missing"
        short_name="${container#secy-secy-}"
        short_name="${short_name%-1}"

        if [[ "$cstatus" == "running" ]]; then
            log "OK: ${short_name} container is running"
        else
            down_list="${down_list} ${short_name}=${cstatus}"
            issues=$((issues + 1))
        fi
    done

    if [[ -n "$down_list" ]]; then
        # Attempt restart
        cd "$SECY_DIR"
        docker compose up -d --no-build 2>/dev/null || true

        alert "secy: Docker Containers Down" \
            "Containers not running:${down_list}\nRestart attempted via docker compose up -d.\nCheck: docker compose ps"
    fi
else
    log "SKIP: docker not found, skipping container checks"
fi

# ── Summary ───────────────────────────────────────────────────────

if [[ $issues -eq 0 ]]; then
    log "HEALTHY: all checks passed"
fi
