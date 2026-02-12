#!/usr/bin/env bash
# agent/patrol.sh — Persistent autonomous security monitoring daemon
#
# Continuously runs sread modules on a schedule, detects changes between
# runs, and periodically invokes Claude to review meaningful diffs.
#
# Usage:
#   patrol.sh [--no-claude] [--tick-interval N] [--review-interval N]

set -euo pipefail

AGENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${AGENT_DIR}/lib/patrol-common.sh"

# ── Flag parsing ─────────────────────────────────────────────────

NO_CLAUDE=false
TICK_OVERRIDE=""
REVIEW_OVERRIDE=""
BUDGET_OVERRIDE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-claude)
            NO_CLAUDE=true
            shift
            ;;
        --tick-interval)
            TICK_OVERRIDE="$2"
            shift 2
            ;;
        --review-interval)
            REVIEW_OVERRIDE="$2"
            shift 2
            ;;
        --review-budget)
            BUDGET_OVERRIDE="$2"
            shift 2
            ;;
        --help|-h)
            echo "secy patrol — Persistent autonomous security monitoring"
            echo ""
            echo "Usage: secy patrol [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --no-claude           Run modules and diff only, skip Claude review"
            echo "  --tick-interval N     Main loop tick in seconds (default: ${PATROL_TICK_INTERVAL})"
            echo "  --review-interval N   Claude review interval in seconds (default: ${PATROL_REVIEW_INTERVAL})"
            echo "  --review-budget N     Budget per Claude review in USD (default: ${PATROL_REVIEW_BUDGET_USD})"
            echo ""
            echo "Runs sread modules on a configurable schedule, diffs output between"
            echo "runs, and invokes Claude to analyze accumulated changes."
            echo ""
            echo "Schedule: ${PATROL_STATE_DIR}/schedule.conf"
            echo "State:    ${PATROL_STATE_DIR}/"
            exit 0
            ;;
        *)
            echo "ERROR: Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# Apply overrides
if [[ -n "$TICK_OVERRIDE" ]]; then
    PATROL_TICK_INTERVAL="$TICK_OVERRIDE"
fi
if [[ -n "$REVIEW_OVERRIDE" ]]; then
    PATROL_REVIEW_INTERVAL="$REVIEW_OVERRIDE"
fi
if [[ -n "$BUDGET_OVERRIDE" ]]; then
    PATROL_REVIEW_BUDGET_USD="$BUDGET_OVERRIDE"
fi

# ── Preflight ────────────────────────────────────────────────────

preflight_patrol() {
    if [[ $EUID -ne 0 ]]; then
        patrol_log "ERROR: patrol must run as root (run inside Docker container)"
        exit 1
    fi

    if [[ ! -d "/host/etc" ]]; then
        patrol_log "ERROR: Host filesystem not found at /host"
        exit 1
    fi

    if ! command -v sread &>/dev/null; then
        patrol_log "ERROR: sread not found in PATH"
        exit 1
    fi

    if [[ "$NO_CLAUDE" != "true" ]]; then
        if ! command -v claude &>/dev/null; then
            patrol_log "WARNING: claude not found — falling back to --no-claude mode"
            NO_CLAUDE=true
        fi
    fi
}

# ── Signal handling ──────────────────────────────────────────────

RUNNING=true

cleanup() {
    RUNNING=false
    patrol_log "Shutting down (received signal)"
}

trap cleanup SIGTERM SIGINT SIGHUP

# ── Main daemon loop ─────────────────────────────────────────────

main() {
    preflight_patrol
    init_patrol_state
    load_schedule

    if [[ ${#SCHED_MODULES[@]} -eq 0 ]]; then
        patrol_log "ERROR: No valid modules in schedule — nothing to patrol"
        exit 1
    fi

    patrol_log "Patrol daemon starting"
    patrol_log "  Tick interval:   ${PATROL_TICK_INTERVAL}s"
    patrol_log "  Review interval: ${PATROL_REVIEW_INTERVAL}s"
    patrol_log "  Review budget:   \$${PATROL_REVIEW_BUDGET_USD}"
    patrol_log "  Modules:         ${#SCHED_MODULES[@]}"
    patrol_log "  Claude:          $(if [[ "$NO_CLAUDE" == "true" ]]; then echo "disabled"; else echo "enabled"; fi)"

    # Phase 1: Init — run all modules once if no prior state
    run_init_scan

    # Phase 2+3: Continuous loop — run due modules, review diffs
    while [[ "$RUNNING" == "true" ]]; do
        local now
        now="$(date +%s)"
        local modules_run=0

        # Check each scheduled module
        for i in "${!SCHED_MODULES[@]}"; do
            [[ "$RUNNING" == "true" ]] || break

            local module="${SCHED_MODULES[$i]}"
            local interval="${SCHED_INTERVALS[$i]}"
            local priority="${SCHED_PRIORITIES[$i]}"

            local last_run
            last_run="$(get_last_run_time "$module")"
            local elapsed=$(( now - last_run ))

            if [[ $elapsed -ge $interval ]]; then
                run_module "$module" "$priority" || true
                (( modules_run++ ))
            fi
        done

        if [[ $modules_run -gt 0 ]]; then
            patrol_log "Tick: ran ${modules_run} module(s)"
        fi

        # Phase 3: Review gate — invoke Claude if meaningful diffs accumulated
        if [[ "$NO_CLAUDE" != "true" ]]; then
            if should_review "$PATROL_REVIEW_INTERVAL"; then
                run_claude_review "$PATROL_REVIEW_BUDGET_USD"
            fi
        fi

        # Interruptible sleep (tick interval)
        local i=0
        while [[ "$RUNNING" == "true" ]] && [[ $i -lt $PATROL_TICK_INTERVAL ]]; do
            sleep 1
            (( i++ ))
        done
    done

    patrol_log "Patrol daemon stopped"
}

main
