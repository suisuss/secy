#!/usr/bin/env bash
# notify.sh — Watch ./issues/ for new findings and send desktop notifications.
# Runs on the host (not inside Docker). Requires inotify-tools and libnotify-bin.
#
# Usage:
#   ./scripts/notify.sh              # foreground
#   ./scripts/notify.sh --daemon     # background (writes PID to ./scripts/.notify.pid)
#   ./scripts/notify.sh --stop       # stop background watcher
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECY_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ISSUES_DIR="${SECY_DIR}/issues"
PID_FILE="${SCRIPT_DIR}/.notify.pid"

# Notification settings
URGENCY_MAP_critical="critical"
URGENCY_MAP_warning="normal"
URGENCY_MAP_info="low"
ICON="dialog-warning"
APP_NAME="secy"
EXPIRE_MS=0  # 0 = persistent until dismissed

# ── Dependency check ──────────────────────────────────────────────

check_deps() {
    local missing=()
    command -v inotifywait &>/dev/null || missing+=("inotify-tools")
    command -v notify-send &>/dev/null || missing+=("libnotify-bin")

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Missing dependencies: ${missing[*]}"
        echo "Install with: sudo apt install ${missing[*]}"
        exit 1
    fi
}

# ── Parse issue file ──────────────────────────────────────────────

# Extract title (first H1) and severity from an issue markdown file.
parse_issue() {
    local file="$1"
    local title="" severity="warning"

    while IFS= read -r line; do
        # Title: first line starting with "# "
        if [[ -z "$title" ]] && [[ "$line" == "# "* ]]; then
            title="${line#\# }"
        fi
        # Severity: "- **Severity**: <value>"
        if [[ "$line" == *"**Severity**"*:* ]]; then
            severity="$(echo "$line" | sed 's/.*: *//; s/ *$//')"
        fi
        # Stop after we have both
        [[ -n "$title" ]] && [[ "$severity" != "warning" || "$line" == *"Severity"* ]] && break
    done < "$file"

    echo "${severity}|${title}"
}

# Map severity string to notify-send urgency level
severity_to_urgency() {
    case "$1" in
        critical) echo "critical" ;;
        warning)  echo "normal" ;;
        info)     echo "low" ;;
        *)        echo "normal" ;;
    esac
}

# Map severity to icon
severity_to_icon() {
    case "$1" in
        critical) echo "dialog-error" ;;
        warning)  echo "dialog-warning" ;;
        info)     echo "dialog-information" ;;
        *)        echo "dialog-warning" ;;
    esac
}

# ── Send notification ─────────────────────────────────────────────

send_notification() {
    local file="$1"
    local parsed urgency icon
    parsed="$(parse_issue "$file")"

    local severity="${parsed%%|*}"
    local title="${parsed#*|}"
    local urgency
    urgency="$(severity_to_urgency "$severity")"
    icon="$(severity_to_icon "$severity")"

    # Fallback title
    [[ -z "$title" ]] && title="$(basename "$file" .md)"

    local body="Severity: ${severity}\nFile: $(basename "$file")"

    notify-send \
        --app-name="$APP_NAME" \
        --urgency="$urgency" \
        --icon="$icon" \
        --expire-time="$EXPIRE_MS" \
        "secy: ${title}" \
        "$body"

    echo "[notify] $(date -Iseconds) ${severity} — ${title}"
}

# ── Watcher loop ──────────────────────────────────────────────────

watch_issues() {
    mkdir -p "$ISSUES_DIR"
    echo "[notify] Watching ${ISSUES_DIR} for new findings..."

    # Process existing files on first run (optional — remove if noisy)
    # for f in "${ISSUES_DIR}"/*.md; do
    #     [[ -f "$f" ]] && send_notification "$f"
    # done

    inotifywait -m -e close_write -e moved_to --format '%f' "$ISSUES_DIR" | \
    while IFS= read -r filename; do
        # Only process markdown files
        [[ "$filename" == *.md ]] || continue

        local filepath="${ISSUES_DIR}/${filename}"
        [[ -f "$filepath" ]] || continue

        # Small delay to ensure file is fully written
        sleep 0.2

        send_notification "$filepath"
    done
}

# ── Daemon management ─────────────────────────────────────────────

start_daemon() {
    if [[ -f "$PID_FILE" ]]; then
        local old_pid
        old_pid="$(cat "$PID_FILE")"
        if kill -0 "$old_pid" 2>/dev/null; then
            echo "Watcher already running (PID ${old_pid})"
            exit 1
        fi
        rm -f "$PID_FILE"
    fi

    echo "[notify] Starting in background..."
    nohup "$0" > "${SCRIPT_DIR}/.notify.log" 2>&1 &
    local pid=$!
    echo "$pid" > "$PID_FILE"
    echo "[notify] Started (PID ${pid}). Log: ${SCRIPT_DIR}/.notify.log"
}

stop_daemon() {
    if [[ ! -f "$PID_FILE" ]]; then
        echo "No watcher running (no PID file)"
        exit 1
    fi

    local pid
    pid="$(cat "$PID_FILE")"
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid"
        echo "[notify] Stopped watcher (PID ${pid})"
    else
        echo "[notify] Process ${pid} not running (stale PID file)"
    fi
    rm -f "$PID_FILE"
}

# ── Demo mode ─────────────────────────────────────────────────────

demo() {
    echo "[notify] Sending demo notifications..."

    notify-send \
        --app-name="$APP_NAME" \
        --urgency="critical" \
        --icon="dialog-error" \
        --expire-time=0 \
        "secy: Supply Chain RAT Detected" \
        "Severity: critical\nPython process /tmp/ld.py beaconing to 142.11.206.73:8000 every 60s\nProcess chain: npm -> sh -> python3 (postinstall payload)\n4 modules triggered: netthreats, tmpexec, proctree, mountsec"

    sleep 1

    notify-send \
        --app-name="$APP_NAME" \
        --urgency="normal" \
        --icon="dialog-warning" \
        --expire-time=0 \
        "secy: Verify WhatsApp Archive Sender" \
        "Severity: warning\nZIP archive from Unknown sender in Downloads\nFile: WhatsApp Unknown 2026-01-15 at 8.22.22 PM.zip"

    sleep 1

    notify-send \
        --app-name="$APP_NAME" \
        --urgency="low" \
        --icon="dialog-information" \
        --expire-time=0 \
        "secy: /tmp Missing noexec Mount Option" \
        "Severity: info\n/tmp is not mounted with noexec — dropped payloads can execute directly\nRun: mount -o remount,noexec,nosuid,nodev /tmp"

    echo "[notify] 3 demo notifications sent."
}

# ── Main ──────────────────────────────────────────────────────────

main() {
    case "${1:-}" in
        --daemon)
            check_deps
            start_daemon
            ;;
        --stop)
            stop_daemon
            ;;
        --demo)
            check_deps
            demo
            ;;
        --help|-h)
            echo "secy notify — Desktop notifications for security findings"
            echo ""
            echo "Usage:"
            echo "  ./scripts/notify.sh              Watch issues/ (foreground)"
            echo "  ./scripts/notify.sh --daemon      Watch issues/ (background)"
            echo "  ./scripts/notify.sh --stop        Stop background watcher"
            echo "  ./scripts/notify.sh --demo        Send demo notifications"
            echo ""
            echo "Dependencies: inotify-tools, libnotify-bin"
            echo "  sudo apt install inotify-tools libnotify-bin"
            ;;
        *)
            check_deps
            watch_issues
            ;;
    esac
}

main "$@"
