#!/usr/bin/env bash
# agent/lib/patrol-common.sh — Shared utilities for the patrol daemon

source "${BASH_SOURCE[0]%/*}/secy-common.sh"

PATROL_STATE_DIR="${STATE_DIR}/patrol"
PATROL_SCHEDULE="${PATROL_STATE_DIR}/schedule.conf"
PATROL_RUNS_DIR="${PATROL_STATE_DIR}/runs"
PATROL_DIFFS_DIR="${PATROL_STATE_DIR}/diffs"
PATROL_LAST_REVIEW="${PATROL_STATE_DIR}/last-review.ts"
PATROL_FINDINGS_DIR="${STATE_DIR}/findings"

# ── Default schedule ─────────────────────────────────────────────
#
# Written to schedule.conf on first run. Editable by user.
# Format: module  interval_seconds  priority

DEFAULT_SCHEDULE="# secy patrol schedule — edit to customize
# module       interval_seconds  priority
ports          300               high
services       600               medium
spyproc        300               high
kmod           600               high
preload        600               high
cron           600               high
users          900               medium
sysctl         900               medium
firewall       900               medium
setuid         900               medium
world          1800              low
packages       3600              low
pkgverify      3600              low
tamper         3600              low
autostart      1800              medium
netconn        300               high
desktop        1800              low
surveil        1800              low"

# ── State directory management ───────────────────────────────────

init_patrol_state() {
    mkdir -p "$PATROL_STATE_DIR"
    mkdir -p "$PATROL_RUNS_DIR"
    mkdir -p "$PATROL_DIFFS_DIR"
    mkdir -p "$PATROL_FINDINGS_DIR"

    if [[ ! -f "$PATROL_SCHEDULE" ]]; then
        echo "$DEFAULT_SCHEDULE" > "$PATROL_SCHEDULE"
        secy_log "patrol" "Wrote default schedule to ${PATROL_SCHEDULE}"
    fi

    secy_log "patrol" "State initialized at ${PATROL_STATE_DIR}"
}

# ── Schedule parsing ─────────────────────────────────────────────
#
# Populates parallel arrays: SCHED_MODULES, SCHED_INTERVALS, SCHED_PRIORITIES

declare -a SCHED_MODULES=()
declare -a SCHED_INTERVALS=()
declare -a SCHED_PRIORITIES=()

load_schedule() {
    SCHED_MODULES=()
    SCHED_INTERVALS=()
    SCHED_PRIORITIES=()

    while IFS= read -r line; do
        # Skip comments and blank lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// /}" ]] && continue

        local module interval priority
        read -r module interval priority <<< "$line"

        [[ -z "$module" ]] && continue
        [[ -z "$interval" ]] && continue

        # Validate interval is numeric
        if ! [[ "$interval" =~ ^[0-9]+$ ]]; then
            secy_log "patrol" "WARNING: Non-numeric interval '${interval}' for module '${module}' — skipping"
            continue
        fi

        # Validate module name (alphanumeric, hyphens, underscores only)
        if ! [[ "$module" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            secy_log "patrol" "WARNING: Invalid module name '${module}' — skipping"
            continue
        fi

        # Validate module exists (check file directly — sread has no per-module --help)
        local mod_file="${SREAD_ROOT}/lib/modules/${module}.sh"
        if [[ ! -f "$mod_file" ]]; then
            secy_log "patrol" "WARNING: Unknown module '${module}' in schedule — skipping"
            continue
        fi

        SCHED_MODULES+=("$module")
        SCHED_INTERVALS+=("$interval")
        SCHED_PRIORITIES+=("${priority:-medium}")
    done < "$PATROL_SCHEDULE"

    secy_log "patrol" "Loaded ${#SCHED_MODULES[@]} modules from schedule"
}

# ── Module execution ─────────────────────────────────────────────

get_last_run_time() {
    local module="$1"
    local latest="${PATROL_RUNS_DIR}/${module}/latest.out"

    if [[ -f "$latest" ]]; then
        stat -c%Y "$latest" 2>/dev/null || echo 0
    else
        echo 0
    fi
}

run_module() {
    local module="$1"
    local priority="$2"
    local module_dir="${PATROL_RUNS_DIR}/${module}"

    mkdir -p "$module_dir"

    local latest="${module_dir}/latest.out"
    local previous="${module_dir}/previous.out"

    # Rotate: latest → previous
    if [[ -f "$latest" ]]; then
        mv "$latest" "$previous"
    fi

    # Execute the sread module
    local exit_code=0
    sread "$module" > "$latest" 2>/dev/null || exit_code=$?

    if [[ $exit_code -ne 0 ]] && [[ ! -s "$latest" ]]; then
        secy_log "patrol" "WARNING: Module '${module}' failed (exit ${exit_code})"
        # Restore previous as latest so we don't lose state
        if [[ -f "$previous" ]]; then
            mv "$previous" "$latest"
        fi
        return 1
    fi

    # Diff against previous run
    if [[ -f "$previous" ]]; then
        local diff_output=""
        diff_output="$(diff -u "$previous" "$latest" 2>/dev/null)" || true

        if [[ -n "$diff_output" ]]; then
            local timestamp
            timestamp="$(date +%s)"
            local diff_file="${PATROL_DIFFS_DIR}/${module}-${timestamp}.diff"

            # Write diff with metadata header
            {
                echo "# Module: ${module}"
                echo "# Priority: ${priority}"
                echo "# Time: $(date -Iseconds)"
                echo "---"
                echo "$diff_output"
            } > "$diff_file"

            secy_log "patrol" "Change detected: ${module} (${priority} priority)"
            return 0
        fi
    else
        secy_log "patrol" "First run for module '${module}' — baseline captured"
    fi

    return 0
}

# ── Init scan ────────────────────────────────────────────────────
#
# Run all modules once on first start to populate baseline outputs.

run_init_scan() {
    secy_log "patrol" "Running initial scan (populating baselines for all modules)"

    local count=0
    local total=${#SCHED_MODULES[@]}

    for i in "${!SCHED_MODULES[@]}"; do
        local module="${SCHED_MODULES[$i]}"
        local priority="${SCHED_PRIORITIES[$i]}"
        local module_dir="${PATROL_RUNS_DIR}/${module}"

        mkdir -p "$module_dir"

        # Only run if no latest.out exists
        if [[ ! -f "${module_dir}/latest.out" ]]; then
            (( count++ )) || true
            secy_log "patrol" "Init scan [${count}/${total}]: ${module}"
            sread "$module" > "${module_dir}/latest.out" 2>/dev/null || {
                secy_log "patrol" "WARNING: Init scan failed for '${module}'"
            }
        fi
    done

    if [[ $count -eq 0 ]]; then
        secy_log "patrol" "All modules already have baseline data — skipping init scan"
    else
        secy_log "patrol" "Init scan complete: ${count} module(s) baselined"
    fi
}

# ── Review gate ──────────────────────────────────────────────────

has_pending_diffs() {
    for f in "${PATROL_DIFFS_DIR}"/*.diff; do
        [[ -f "$f" ]] && return 0
    done
    return 1
}

has_high_priority_diff() {
    for f in "${PATROL_DIFFS_DIR}"/*.diff; do
        [[ -f "$f" ]] || continue
        if head -3 "$f" | grep -q '^# Priority: high'; then
            return 0
        fi
    done
    return 1
}

get_last_review_time() {
    if [[ -f "$PATROL_LAST_REVIEW" ]]; then
        cat "$PATROL_LAST_REVIEW" 2>/dev/null || echo 0
    else
        echo 0
    fi
}

should_review() {
    local review_interval="$1"

    # Must have at least one diff
    has_pending_diffs || return 1

    # Immediate review if a high-priority module changed
    if has_high_priority_diff; then
        return 0
    fi

    # Otherwise, review if the interval has elapsed
    local last_review now elapsed
    last_review="$(get_last_review_time)"
    now="$(date +%s)"
    elapsed=$(( now - last_review ))

    [[ $elapsed -ge $review_interval ]]
}

mark_review_done() {
    date +%s > "$PATROL_LAST_REVIEW"
}

# ── Claude review ────────────────────────────────────────────────

assemble_diffs() {
    local output=""
    local count=0

    for f in "${PATROL_DIFFS_DIR}"/*.diff; do
        [[ -f "$f" ]] || continue
        (( count++ )) || true
        output+="$(cat "$f")"
        output+=$'\n\n'
    done

    echo "$output"
}

count_pending_diffs() {
    local count=0
    for f in "${PATROL_DIFFS_DIR}"/*.diff; do
        [[ -f "$f" ]] && { (( count++ )) || true; }
    done
    echo "$count"
}

clear_reviewed_diffs() {
    rm -f "${PATROL_DIFFS_DIR}"/*.diff 2>/dev/null || true
}

run_claude_review() {
    local review_budget="$1"
    local diff_count
    diff_count="$(count_pending_diffs)"

    secy_log "patrol" "Starting Claude review of ${diff_count} diff(s)"

    local diffs
    diffs="$(assemble_diffs)"

    local timestamp
    timestamp="$(date +%Y-%m-%d-%H%M%S)"
    local findings_file="${PATROL_FINDINGS_DIR}/patrol-${timestamp}.md"

    local patrol_prompt="${AGENT_DIR}/PATROL.md"
    if [[ ! -f "$patrol_prompt" ]]; then
        secy_log "patrol" "ERROR: Patrol prompt not found at ${patrol_prompt}"
        return 1
    fi

    local system_prompt
    system_prompt="$(cat "$patrol_prompt")"

    local prompt="## Patrol Review Task

${diff_count} security module(s) detected changes since their last run. Review the diffs below and assess each change.

### Accumulated Diffs

\`\`\`
${diffs}
\`\`\`

### Instructions

1. For each diff, explain what changed and whether it is benign or suspicious
2. Assign a severity: CRITICAL, WARNING, or INFO
3. If multiple diffs are related, connect the dots
4. Write your findings report to: ${findings_file}
5. Output SECY_COMPLETE when done
"

    invoke_claude "$system_prompt" "$prompt" "$review_budget" > /dev/null

    if [[ -f "$findings_file" ]]; then
        secy_log "patrol" "Review complete: ${findings_file}"
    else
        secy_log "patrol" "WARNING: Claude did not write findings to ${findings_file}"
    fi

    # Clear reviewed diffs and mark review done
    clear_reviewed_diffs
    mark_review_done
}
