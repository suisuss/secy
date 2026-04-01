#!/usr/bin/env bash
# agent/lib/patrol-common.sh — Shared utilities for the patrol daemon

source "${BASH_SOURCE[0]%/*}/secy-common.sh"

PATROL_STATE_DIR="${STATE_DIR}/patrol"
PATROL_SCHEDULE="${PATROL_STATE_DIR}/schedule.conf"
PATROL_RUNS_DIR="${PATROL_STATE_DIR}/runs"
PATROL_DIFFS_DIR="${PATROL_STATE_DIR}/diffs"
PATROL_LAST_REVIEW="${PATROL_STATE_DIR}/last-review.ts"
PATROL_FINDINGS_DIR="${STATE_DIR}/findings"
PATROL_SCHEDULE_OVERRIDE="${STATE_DIR}/directives/schedule-override.conf"
PATROL_DIRECTIVES_DIR="${STATE_DIR}/directives/active"
PATROL_DIRECTIVES_APPLIED="${STATE_DIR}/directives/applied"

# Track mtime of last-loaded schedule override
_PATROL_OVERRIDE_MTIME=0

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
netthreats     120               high
tmpexec        120               high
proctree       300               high
mountsec       3600              medium
secyhealth     1800              high
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

# ── Directive reload ─────────────────────────────────────────────
#
# C2 writes directives that adjust patrol behavior at runtime.
# Two mechanisms:
#   1. schedule-override.conf — persistent overrides (module.field=value)
#   2. active/*.directive — one-shot directive files, moved to applied/ after processing

check_directives() {
    # Check schedule override file
    _check_schedule_override

    # Process individual directive files
    _process_directive_files
}

_check_schedule_override() {
    [[ -f "$PATROL_SCHEDULE_OVERRIDE" ]] || return 0

    local current_mtime
    current_mtime="$(stat -c%Y "$PATROL_SCHEDULE_OVERRIDE" 2>/dev/null || echo 0)"

    if [[ "$current_mtime" -le "$_PATROL_OVERRIDE_MTIME" ]]; then
        return 0
    fi

    _PATROL_OVERRIDE_MTIME="$current_mtime"
    secy_log "patrol" "Reloading schedule overrides from ${PATROL_SCHEDULE_OVERRIDE}"
    apply_schedule_overrides "$PATROL_SCHEDULE_OVERRIDE"
}

# Parse override format: module.field=value
# Supported fields: interval, priority
apply_schedule_overrides() {
    local file="$1"

    while IFS= read -r line; do
        # Skip comments and blank lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// /}" ]] && continue

        local key value
        key="$(echo "$line" | cut -d'=' -f1 | tr -d '[:space:]')"
        value="$(echo "$line" | cut -d'=' -f2-)"
        value="$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

        # Parse module.field
        local module field
        module="$(echo "$key" | cut -d'.' -f1)"
        field="$(echo "$key" | cut -d'.' -f2)"

        [[ -n "$module" ]] && [[ -n "$field" ]] || continue

        # Find the module in our schedule arrays
        local found=false
        for i in "${!SCHED_MODULES[@]}"; do
            if [[ "${SCHED_MODULES[$i]}" == "$module" ]]; then
                case "$field" in
                    interval)
                        if [[ "$value" =~ ^[0-9]+$ ]]; then
                            SCHED_INTERVALS[$i]="$value"
                            secy_log "patrol" "Override: ${module}.interval=${value}"
                        fi
                        ;;
                    priority)
                        if [[ "$value" =~ ^(high|medium|low)$ ]]; then
                            SCHED_PRIORITIES[$i]="$value"
                            secy_log "patrol" "Override: ${module}.priority=${value}"
                        fi
                        ;;
                esac
                found=true
                break
            fi
        done

        if [[ "$found" != "true" ]]; then
            secy_log "patrol" "WARNING: Override for unknown module '${module}' — ignoring"
        fi
    done < "$file"
}

_process_directive_files() {
    [[ -d "$PATROL_DIRECTIVES_DIR" ]] || return 0

    for dfile in "${PATROL_DIRECTIVES_DIR}"/*.directive; do
        [[ -f "$dfile" ]] || continue

        local basename
        basename="$(basename "$dfile")"
        secy_log "patrol" "Processing directive: ${basename}"

        # Capture what we're about to apply
        local applied_changes=""
        local apply_errors=""

        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line// /}" ]] && continue

            local key value
            key="$(echo "$line" | cut -d'=' -f1 | tr -d '[:space:]')"
            value="$(echo "$line" | cut -d'=' -f2-)"
            value="$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

            local module field
            module="$(echo "$key" | cut -d'.' -f1)"
            field="$(echo "$key" | cut -d'.' -f2)"

            [[ -n "$module" ]] && [[ -n "$field" ]] || continue

            local found=false
            for i in "${!SCHED_MODULES[@]}"; do
                if [[ "${SCHED_MODULES[$i]}" == "$module" ]]; then
                    local old_val=""
                    case "$field" in
                        interval)
                            if [[ "$value" =~ ^[0-9]+$ ]]; then
                                old_val="${SCHED_INTERVALS[$i]}"
                                SCHED_INTERVALS[$i]="$value"
                                applied_changes+="  ${module}.${field}: ${old_val} -> ${value}\n"
                                secy_log "patrol" "Override: ${module}.interval=${value}"
                            else
                                apply_errors+="  ${module}.${field}: invalid value '${value}'\n"
                            fi
                            ;;
                        priority)
                            if [[ "$value" =~ ^(high|medium|low)$ ]]; then
                                old_val="${SCHED_PRIORITIES[$i]}"
                                SCHED_PRIORITIES[$i]="$value"
                                applied_changes+="  ${module}.${field}: ${old_val} -> ${value}\n"
                                secy_log "patrol" "Override: ${module}.priority=${value}"
                            else
                                apply_errors+="  ${module}.${field}: invalid value '${value}'\n"
                            fi
                            ;;
                        *)
                            apply_errors+="  ${module}.${field}: unknown field\n"
                            ;;
                    esac
                    found=true
                    break
                fi
            done

            if [[ "$found" != "true" ]]; then
                apply_errors+="  ${module}.${field}: unknown module\n"
                secy_log "patrol" "WARNING: Override for unknown module '${module}' — ignoring"
            fi
        done < "$dfile"

        # Move to applied/
        mkdir -p "$PATROL_DIRECTIVES_APPLIED"
        mv "$dfile" "${PATROL_DIRECTIVES_APPLIED}/${basename}" 2>/dev/null || true

        # Write application report
        {
            echo "# Directive Application Report"
            echo ""
            echo "- **Directive**: ${basename}"
            echo "- **Service**: patrol"
            echo "- **Timestamp**: $(date -Iseconds)"
            echo "- **Status**: $(if [[ -n "$apply_errors" ]]; then echo "partial"; else echo "applied"; fi)"
            echo ""
            if [[ -n "$applied_changes" ]]; then
                echo "## Changes Applied"
                echo ""
                printf "%b" "$applied_changes"
                echo ""
            fi
            if [[ -n "$apply_errors" ]]; then
                echo "## Errors"
                echo ""
                printf "%b" "$apply_errors"
                echo ""
            fi
            if [[ -z "$applied_changes" ]] && [[ -z "$apply_errors" ]]; then
                echo "## Result"
                echo ""
                echo "  No actionable entries found in directive."
                echo ""
            fi
        } > "${PATROL_DIRECTIVES_APPLIED}/${basename}.report"

        secy_log "patrol" "Directive applied: ${basename} (report written)"
    done
}
