#!/usr/bin/env bash
# agent/c2.sh — C2 supervisory correlation daemon
#
# Monitors state/findings/ for new reports from watch and patrol,
# debounces rapid-fire events, and invokes Claude to correlate
# findings across services and issue runtime directives.
#
# Usage:
#   c2.sh [--no-claude] [--poll-interval N] [--debounce N]

set -euo pipefail

AGENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${AGENT_DIR}/lib/c2-common.sh"
source "${AGENT_DIR}/lib/inotify-watch.sh"

# ── Flag parsing ─────────────────────────────────────────────────

NO_CLAUDE=false
POLL_OVERRIDE=""
DEBOUNCE_OVERRIDE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-claude)
            NO_CLAUDE=true
            shift
            ;;
        --poll-interval)
            if [[ $# -lt 2 ]] || ! [[ "$2" =~ ^[0-9]+$ ]]; then
                echo "ERROR: --poll-interval requires a numeric value" >&2; exit 1
            fi
            POLL_OVERRIDE="$2"
            shift 2
            ;;
        --debounce)
            if [[ $# -lt 2 ]] || ! [[ "$2" =~ ^[0-9]+$ ]]; then
                echo "ERROR: --debounce requires a numeric value" >&2; exit 1
            fi
            DEBOUNCE_OVERRIDE="$2"
            shift 2
            ;;
        --help|-h)
            echo "secy c2 — Supervisory correlation daemon"
            echo ""
            echo "Usage: secy c2 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --no-claude        Log new findings but skip Claude analysis"
            echo "  --poll-interval N  Override poll interval in seconds (default: ${C2_POLL_INTERVAL})"
            echo "  --debounce N       Override debounce interval in seconds (default: ${C2_DEBOUNCE_INTERVAL})"
            echo ""
            echo "Monitors state/findings/ for new reports from watch and patrol."
            echo "Correlates across services and issues runtime directives."
            exit 0
            ;;
        *)
            echo "ERROR: Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

if [[ -n "$POLL_OVERRIDE" ]]; then
    C2_POLL_INTERVAL="$POLL_OVERRIDE"
fi
if [[ -n "$DEBOUNCE_OVERRIDE" ]]; then
    C2_DEBOUNCE_INTERVAL="$DEBOUNCE_OVERRIDE"
fi

# ── Preflight ────────────────────────────────────────────────────

preflight_c2() {
    preflight_core

    if [[ "$NO_CLAUDE" != "true" ]]; then
        if ! command -v claude &>/dev/null; then
            secy_log "c2" "WARNING: claude not found — falling back to --no-claude mode"
            NO_CLAUDE=true
        fi
    fi
}

# ── Event handling ───────────────────────────────────────────────
#
# Pending findings accumulate between Claude invocations.
# Debounce prevents rapid-fire when patrol generates multiple findings
# simultaneously (e.g., during init scan).

declare -a _C2_PENDING=()
_C2_LAST_ANALYSIS=0

on_findings_event() {
    local event="$1"
    local filename="$2"

    # On inotify events, check if the specific file is a new finding
    if [[ "$event" != "POLL" ]] && [[ -n "$filename" ]]; then
        # Only care about .md files
        if [[ "$filename" == *.md ]] && ! is_finding_processed "$filename"; then
            # Skip our own reports
            if [[ "$filename" != c2-* ]]; then
                _C2_PENDING+=("$filename")
                secy_log "c2" "New finding detected: ${filename} (${#_C2_PENDING[@]} pending)"
            fi
        fi
    fi

    # On poll events (or periodically), do a full scan for any missed findings
    if [[ "$event" == "POLL" ]]; then
        local new_findings
        new_findings="$(scan_new_findings)"
        if [[ -n "$new_findings" ]]; then
            while IFS= read -r fname; do
                [[ -n "$fname" ]] || continue
                # Check if already in pending list
                local already_pending=false
                for p in "${_C2_PENDING[@]}"; do
                    if [[ "$p" == "$fname" ]]; then
                        already_pending=true
                        break
                    fi
                done
                if [[ "$already_pending" != "true" ]]; then
                    _C2_PENDING+=("$fname")
                    secy_log "c2" "New finding (poll): ${fname} (${#_C2_PENDING[@]} pending)"
                fi
            done <<< "$new_findings"
        fi
    fi

    # Check if we should trigger analysis
    if [[ ${#_C2_PENDING[@]} -eq 0 ]]; then
        return
    fi

    if [[ "$NO_CLAUDE" == "true" ]]; then
        secy_log "c2" "Findings pending but Claude disabled — marking as processed"
        for fname in "${_C2_PENDING[@]}"; do
            mark_finding_processed "$fname"
        done
        _C2_PENDING=()
        return
    fi

    # Debounce: wait until enough time has passed since last analysis
    local now
    now="$(date +%s)"
    local elapsed=$(( now - _C2_LAST_ANALYSIS ))

    if [[ $elapsed -lt $C2_DEBOUNCE_INTERVAL ]]; then
        local remaining=$(( C2_DEBOUNCE_INTERVAL - elapsed ))
        secy_log "c2" "Debounce: ${#_C2_PENDING[@]} pending, ${remaining}s until next analysis window"
        return
    fi

    # Trigger analysis
    secy_log "c2" "Triggering analysis: ${#_C2_PENDING[@]} pending finding(s)"
    run_c2_analysis _C2_PENDING
    _C2_LAST_ANALYSIS="$(date +%s)"
    _C2_PENDING=()
}

# ── Main daemon loop ─────────────────────────────────────────────

main() {
    preflight_c2
    init_c2_state
    daemon_init

    secy_log "c2" "C2 supervisory daemon starting"
    secy_log "c2" "  Poll interval: ${C2_POLL_INTERVAL}s"
    secy_log "c2" "  Debounce:      ${C2_DEBOUNCE_INTERVAL}s"
    secy_log "c2" "  Budget:        \$${C2_REVIEW_BUDGET_USD}"
    secy_log "c2" "  Context window: ${C2_CONTEXT_WINDOW}"
    secy_log "c2" "  Claude:        $(if [[ "$NO_CLAUDE" == "true" ]]; then echo "disabled"; else echo "enabled"; fi)"
    secy_log "c2" "  Watching:      ${C2_FINDINGS_DIR}"

    watch_directory_loop \
        "$C2_FINDINGS_DIR" \
        "on_findings_event" \
        "$C2_POLL_INTERVAL" \
        "c2"

    secy_log "c2" "C2 supervisory daemon stopped"
}

main
