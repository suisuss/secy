#!/usr/bin/env bash
# agent/lib/secy-common.sh — Foundation shared by all secy modes

set -euo pipefail

AGENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${SREAD_ROOT:-}" ]]; then
    SREAD_ROOT="$(cd "${AGENT_DIR}/../sread" && pwd)"
fi
export SREAD_ROOT

source "${AGENT_DIR}/conf/agent.conf"

# ── Logging ──────────────────────────────────────────────────────
# Usage: secy_log "tag" "message"
#   secy_log "watch" "Starting scan"  →  [secy:watch 2026-...] Starting scan
#   secy_log "" "Starting audit"      →  [secy 2026-...] Starting audit

SECY_LOG_DIR="${STATE_DIR}"
SECY_LOG_MAX_SIZE=1048576  # 1MB

secy_log() {
    local tag="$1"; shift
    local prefix
    if [[ -n "$tag" ]]; then
        prefix="[secy:${tag} $(date -Iseconds)]"
    else
        prefix="[secy $(date -Iseconds)]"
    fi
    local msg="${prefix} $*"
    echo "$msg" >&2

    # Persistent file logging (best-effort)
    local logfile="${SECY_LOG_DIR}/secy.log"
    if [[ -d "$SECY_LOG_DIR" ]]; then
        if [[ -f "$logfile" ]] && [[ "$(stat -c%s "$logfile" 2>/dev/null || echo 0)" -gt $SECY_LOG_MAX_SIZE ]]; then
            mv "$logfile" "${logfile}.1" 2>/dev/null || true
        fi
        echo "$msg" >> "$logfile" 2>/dev/null || true
    fi
}

# ── Preflight (common checks) ───────────────────────────────────

preflight_core() {
    if [[ $EUID -ne 0 ]]; then
        secy_log "" "ERROR: secy must run as root (run inside Docker container)"
        exit 1
    fi
    if [[ ! -d "/host/etc" ]]; then
        secy_log "" "ERROR: Host filesystem not found at /host"
        secy_log "" "       Run via: docker compose run secy <mode>"
        exit 1
    fi
}

# ── Claude invocation ────────────────────────────────────────────
# Usage: invoke_claude "$system_prompt" "$prompt" "$budget"
# Probes srt, invokes claude with stream-json, pipes through format-stream.sh.
# Returns the raw stream-json output on stdout.

invoke_claude() {
    local system_prompt="$1"
    local prompt="$2"
    local budget="$3"

    local claude_cmd=(claude)
    if command -v srt &>/dev/null; then
        if srt -- echo srt-ok >/dev/null 2>&1; then
            claude_cmd=(srt claude)
            secy_log "" "Using srt sandbox"
        else
            secy_log "" "srt available but sandbox failed (Docker is the sandbox boundary)"
        fi
    else
        secy_log "" "Running without srt (Docker is the sandbox boundary)"
    fi

    local stream_formatter="${AGENT_DIR}/lib/format-stream.sh"
    local raw_json
    raw_json="$(mktemp)"
    trap 'rm -f "$raw_json"' RETURN

    "${claude_cmd[@]}" \
        --dangerously-skip-permissions \
        --print \
        --verbose \
        --output-format stream-json \
        --model "$CLAUDE_MODEL" \
        --max-budget-usd "$budget" \
        --tools "$ALLOWED_TOOLS" \
        --system-prompt "$system_prompt" \
        -p "$prompt" \
        | tee "$raw_json" \
        | bash "$stream_formatter" >&2 || true

    cat "$raw_json"
}

# ── Daemon utilities ─────────────────────────────────────────────
# Used by watch.sh and patrol.sh — not by the Ralph loop modes.

SECY_DAEMON_RUNNING=true

daemon_init() {
    SECY_DAEMON_RUNNING=true
    trap '_daemon_cleanup' SIGTERM SIGINT SIGHUP
}

_daemon_cleanup() {
    SECY_DAEMON_RUNNING=false
    secy_log "" "Shutting down (received signal)"
}

interruptible_sleep() {
    local seconds="$1"
    local i=0
    while [[ "$SECY_DAEMON_RUNNING" == "true" ]] && [[ $i -lt $seconds ]]; do
        sleep 1
        (( i++ )) || true
    done
}
