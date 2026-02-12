#!/usr/bin/env bash
# secy — Autonomous security monitoring agent
#
# Uses the Ralph pattern: a bash loop spawning fresh Claude Code instances
# with filesystem-based memory. Each iteration gets a clean context window,
# reads state from disk, runs sread modules, and writes findings.
#
# Usage:
#   secy baseline    Capture what "normal" looks like
#   secy audit       Full security sweep with anomaly analysis
#   secy monitor     Compare current state against baseline

set -euo pipefail

AGENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${AGENT_DIR}/lib/agent-common.sh"

# ── Usage ─────────────────────────────────────────────────────────

usage() {
    echo "secy — Autonomous security monitoring agent"
    echo ""
    echo "Usage: secy <mode>"
    echo ""
    echo "Modes:"
    echo "  baseline    Capture current system state as the 'normal' reference"
    echo "  audit       Full security audit — run all modules, analyze, report"
    echo "  monitor     Compare current state against baseline, flag deviations"
    echo "  watch       Continuously monitor Downloads for malware (daemon)"
    echo "  patrol      Persistent security monitoring — scheduled scans + AI review (daemon)"
    echo ""
    echo "Watch options:"
    echo "  watch --no-claude        Hash-check only, skip AI analysis"
    echo "  watch --poll-interval N  Override poll interval (default: 5s)"
    echo ""
    echo "Patrol options:"
    echo "  patrol --no-claude          Run modules and diff only, skip AI review"
    echo "  patrol --tick-interval N    Main loop tick in seconds (default: 10)"
    echo "  patrol --review-interval N  Claude review interval in seconds (default: 1800)"
    echo ""
    echo "State directory: ${STATE_DIR}"
    echo "Agent prompt:    ${AGENT_DIR}/AGENT.md"
}

# ── Main loop ─────────────────────────────────────────────────────

run_agent() {
    local mode="$1"
    local max_iterations

    case "$mode" in
        baseline) max_iterations=$BASELINE_MAX_ITERATIONS ;;
        audit)    max_iterations=$AUDIT_MAX_ITERATIONS ;;
        monitor)  max_iterations=$MONITOR_MAX_ITERATIONS ;;
        *)
            echo "ERROR: Unknown mode '${mode}'" >&2
            usage >&2
            exit 1
            ;;
    esac

    # Monitor mode requires a baseline
    if [[ "$mode" == "monitor" ]] && [[ ! -f "${STATE_DIR}/baseline/baseline.meta" ]]; then
        secy_log "" "ERROR: No baseline found. Run 'secy baseline' first."
        exit 1
    fi

    preflight_check
    ensure_state_dirs
    acquire_lock
    trap release_lock EXIT

    local timestamp
    timestamp="$(date +%Y-%m-%d-%H%M%S)"

    # Reset progress for this run
    : > "${STATE_DIR}/progress.md"

    local agent_prompt="${AGENT_DIR}/AGENT.md"
    if [[ ! -f "$agent_prompt" ]]; then
        secy_log "" "ERROR: Agent prompt not found at ${agent_prompt}"
        exit 1
    fi

    secy_log "" "Starting ${mode} (max ${max_iterations} iterations)"

    local completed=false

    for i in $(seq 1 "$max_iterations"); do
        secy_log "" "Iteration ${i}/${max_iterations}"

        local prompt
        prompt="$(assemble_prompt "$mode" "$i" "$max_iterations" "$timestamp")"

        local system_prompt
        system_prompt="$(cat "$agent_prompt")"

        local output
        output="$(invoke_claude "$system_prompt" "$prompt" "$MAX_BUDGET_USD")"

        if check_completion "$output"; then
            secy_log "" "Agent signaled completion at iteration ${i}"
            completed=true
            break
        fi

        if [[ $i -lt $max_iterations ]]; then
            secy_log "" "Sleeping ${ITERATION_SLEEP}s before next iteration"
            sleep "$ITERATION_SLEEP"
        fi
    done

    if [[ "$completed" != "true" ]]; then
        secy_log "" "WARNING: Agent did not signal completion within ${max_iterations} iterations"
    fi

    # Print summary if a findings file was created
    local findings_pattern="${STATE_DIR}/findings/${mode}-${timestamp}.md"
    if [[ -f "$findings_pattern" ]]; then
        echo ""
        echo "================================================================"
        echo "  FINDINGS SUMMARY"
        echo "================================================================"
        echo ""
        # Print the Summary and Critical Findings sections
        sed -n '/^## Summary$/,/^## [^C]/p' "$findings_pattern" | head -n -1
        echo ""
        # Count findings by severity
        local critical warning info
        critical=$(grep -c '^\### \[CRITICAL' "$findings_pattern" 2>/dev/null || echo 0)
        warning=$(grep -c '^\### \[WARN' "$findings_pattern" 2>/dev/null || echo 0)
        info=$(grep -c '^\### \[INFO' "$findings_pattern" 2>/dev/null || echo 0)
        echo "  Critical: ${critical}  Warnings: ${warning}  Info: ${info}"
        echo "  Full report: ${findings_pattern}"
        echo ""
    elif [[ "$mode" == "baseline" ]]; then
        echo ""
        secy_log "" "Baseline captured to ${STATE_DIR}/baseline/"
    fi

    secy_log "" "Done"
}

# ── Entry point ───────────────────────────────────────────────────

if [[ $# -eq 0 ]] || [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
    usage
    exit 0
fi

# Daemon modes have their own lifecycle — delegate entirely
if [[ "$1" == "watch" ]]; then
    exec "${AGENT_DIR}/watch.sh" "${@:2}"
fi

if [[ "$1" == "patrol" ]]; then
    exec "${AGENT_DIR}/patrol.sh" "${@:2}"
fi

run_agent "$1"
