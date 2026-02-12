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
    echo ""
    echo "Watch options:"
    echo "  watch --no-claude        Hash-check only, skip AI analysis"
    echo "  watch --poll-interval N  Override poll interval (default: 5s)"
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
        log_agent "ERROR: No baseline found. Run 'secy baseline' first."
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
        log_agent "ERROR: Agent prompt not found at ${agent_prompt}"
        exit 1
    fi

    log_agent "Starting ${mode} (max ${max_iterations} iterations)"

    local completed=false

    for i in $(seq 1 "$max_iterations"); do
        log_agent "Iteration ${i}/${max_iterations}"

        local prompt
        prompt="$(assemble_prompt "$mode" "$i" "$max_iterations" "$timestamp")"

        local system_prompt
        system_prompt="$(cat "$agent_prompt")"

        # Build claude command — use srt wrapper if available and working
        local claude_cmd="claude"
        if command -v srt &>/dev/null; then
            if srt -- echo srt-ok >/dev/null 2>&1; then
                claude_cmd="srt claude"
                log_agent "Using srt sandbox"
            else
                log_agent "srt available but sandbox failed (Docker is the sandbox boundary)"
            fi
        else
            log_agent "Running without srt (Docker is the sandbox boundary)"
        fi

        local stream_formatter="${AGENT_DIR}/lib/format-stream.sh"

        local raw_json
        raw_json="$(mktemp)"

        $claude_cmd \
            --dangerously-skip-permissions \
            --print \
            --verbose \
            --output-format stream-json \
            --model "$CLAUDE_MODEL" \
            --max-budget-usd "$MAX_BUDGET_USD" \
            --tools "$ALLOWED_TOOLS" \
            --system-prompt "$system_prompt" \
            -p "$prompt" \
            | tee "$raw_json" \
            | bash "$stream_formatter" >&2 || true

        local output
        output="$(cat "$raw_json")"
        rm -f "$raw_json"

        if check_completion "$output"; then
            log_agent "Agent signaled completion at iteration ${i}"
            completed=true
            break
        fi

        if [[ $i -lt $max_iterations ]]; then
            log_agent "Sleeping ${ITERATION_SLEEP}s before next iteration"
            sleep "$ITERATION_SLEEP"
        fi
    done

    if [[ "$completed" != "true" ]]; then
        log_agent "WARNING: Agent did not signal completion within ${max_iterations} iterations"
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
        log_agent "Baseline captured to ${STATE_DIR}/baseline/"
    fi

    log_agent "Done"
}

# ── Entry point ───────────────────────────────────────────────────

if [[ $# -eq 0 ]] || [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
    usage
    exit 0
fi

# Watch mode has its own daemon lifecycle — delegate entirely
if [[ "$1" == "watch" ]]; then
    exec "${AGENT_DIR}/watch.sh" "${@:2}"
fi

run_agent "$1"
