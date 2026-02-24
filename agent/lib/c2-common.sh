#!/usr/bin/env bash
# agent/lib/c2-common.sh — C2 supervisory agent utilities
#
# Provides state management, finding tracking, context assembly,
# and Claude invocation for the C2 correlation layer.

source "${BASH_SOURCE[0]%/*}/secy-common.sh"

C2_STATE_DIR="${STATE_DIR}/c2"
C2_PROCESSED_DB="${C2_STATE_DIR}/processed.db"
C2_PROGRESS="${C2_STATE_DIR}/progress.md"
C2_FINDINGS_DIR="${STATE_DIR}/findings"
C2_DIRECTIVES_DIR="${STATE_DIR}/directives"
C2_ISSUES_DIR="${STATE_DIR}/issues"

# ── State management ────────────────────────────────────────────

init_c2_state() {
    mkdir -p "$C2_STATE_DIR"
    mkdir -p "$C2_FINDINGS_DIR"
    mkdir -p "$C2_ISSUES_DIR"
    mkdir -p "${C2_DIRECTIVES_DIR}/active"
    mkdir -p "${C2_DIRECTIVES_DIR}/applied"
    touch "$C2_PROCESSED_DB"

    if [[ ! -f "$C2_PROGRESS" ]]; then
        cat > "$C2_PROGRESS" <<'EOF'
# C2 Progress Notes

_No investigations yet._
EOF
    fi

    secy_log "c2" "State initialized at ${C2_STATE_DIR}"
}

# ── Processed finding tracking ──────────────────────────────────
#
# Format: <filename>\t<processed_timestamp>
# One entry per line, tab-delimited.

is_finding_processed() {
    local filename="$1"
    grep -qF "${filename}	" "$C2_PROCESSED_DB" 2>/dev/null
}

mark_finding_processed() {
    local filename="$1"
    local timestamp
    timestamp="$(date -Iseconds)"
    printf '%s\t%s\n' "$filename" "$timestamp" >> "$C2_PROCESSED_DB"
}

# Scan findings/ for unprocessed reports.
# Returns a list of filenames (basenames) that haven't been processed.
scan_new_findings() {
    local findings=()

    for f in "${C2_FINDINGS_DIR}"/*.md; do
        [[ -f "$f" ]] || continue
        local basename
        basename="$(basename "$f")"

        # Skip our own reports (self-reference prevention)
        [[ "$basename" == c2-* ]] && {
            # Ensure self-reports are marked processed
            is_finding_processed "$basename" || mark_finding_processed "$basename"
            continue
        }

        if ! is_finding_processed "$basename"; then
            findings+=("$basename")
        fi
    done

    printf '%s\n' "${findings[@]}"
}

# ── Timestamp extraction ─────────────────────────────────────────
#
# Finding filenames embed timestamps: watch-triage-2026-02-13-143022.md,
# patrol-2026-02-13-143022.md, watch-2026-02-13-143022-critical.md.
# Extract these for sorting and display.

# Returns a sortable timestamp (YYYY-MM-DD-HHMMSS) from a finding filename,
# or the file's mtime as fallback.
_extract_finding_timestamp() {
    local filename="$1"

    # Match YYYY-MM-DD-HHMMSS anywhere in the filename
    if [[ "$filename" =~ ([0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{6}) ]]; then
        echo "${BASH_REMATCH[1]}"
        return
    fi

    # Fallback: file mtime
    local filepath="${C2_FINDINGS_DIR}/${filename}"
    if [[ -f "$filepath" ]]; then
        date -d "@$(stat -c%Y "$filepath")" +%Y-%m-%d-%H%M%S 2>/dev/null || echo "0000-00-00-000000"
    else
        echo "0000-00-00-000000"
    fi
}

# Format a YYYY-MM-DD-HHMMSS string into human-readable ISO-ish form
_format_timestamp() {
    local ts="$1"
    # 2026-02-13-143022 → 2026-02-13 14:30:22
    if [[ "$ts" =~ ^([0-9]{4}-[0-9]{2}-[0-9]{2})-([0-9]{2})([0-9]{2})([0-9]{2})$ ]]; then
        echo "${BASH_REMATCH[1]} ${BASH_REMATCH[2]}:${BASH_REMATCH[3]}:${BASH_REMATCH[4]}"
    else
        echo "$ts"
    fi
}

# Derive service name from finding filename
_extract_finding_source() {
    local filename="$1"
    case "$filename" in
        watch-triage-*) echo "watch (AI triage)" ;;
        watch-*)        echo "watch (alert)" ;;
        patrol-*)       echo "patrol (review)" ;;
        c2-*)           echo "c2" ;;
        *)              echo "unknown" ;;
    esac
}

# Sort an array of filenames by embedded timestamp (oldest first).
# Outputs sorted filenames, one per line.
_sort_findings_by_time() {
    local -n arr_ref=$1
    local tmp_list=()

    for fname in "${arr_ref[@]}"; do
        local ts
        ts="$(_extract_finding_timestamp "$fname")"
        tmp_list+=("${ts}	${fname}")
    done

    printf '%s\n' "${tmp_list[@]}" | sort -t$'\t' -k1 | cut -d$'\t' -f2
}

# ── Issue management ─────────────────────────────────────────────
#
# Issues are the human-facing output of C2. Each issue is a markdown file
# in state/issues/ with a numeric ID and short slug. An issue exists = open.
# The user deletes or moves the file to resolve it.
#
# Filename format: <NNN>-<slug>.md  (e.g., 001-suspicious-binary-activation.md)
# Claude writes these directly; we provide the next ID and path.

# Returns the next available issue ID (zero-padded to 3 digits)
next_issue_id() {
    local max=0
    for f in "${C2_ISSUES_DIR}"/*.md; do
        [[ -f "$f" ]] || continue
        local basename
        basename="$(basename "$f" .md)"
        local num="${basename%%-*}"
        # Strip leading zeros for arithmetic
        num="$((10#$num))" 2>/dev/null || continue
        if [[ $num -gt $max ]]; then
            max=$num
        fi
    done
    printf '%04d' $(( max + 1 ))
}

# List open issues (filenames only). Returns one per line.
list_open_issues() {
    for f in "${C2_ISSUES_DIR}"/*.md; do
        [[ -f "$f" ]] || continue
        basename "$f"
    done
}

# Count open issues
count_open_issues() {
    local count=0
    for f in "${C2_ISSUES_DIR}"/*.md; do
        [[ -f "$f" ]] && (( count++ )) || true
    done
    echo "$count"
}

# ── Context assembly ────────────────────────────────────────────
#
# Builds the user prompt for C2's Claude invocation.
# Includes: new findings (full, chronological), recent history
# (summaries, chronological), patrol schedule, directives, progress.

assemble_c2_context() {
    local -n pending_ref=$1
    local context=""

    # Section 1: New findings (full content, sorted oldest→newest)
    context+="## New Findings (Trigger)

"

    local sorted_new
    sorted_new="$(_sort_findings_by_time pending_ref)"

    local count=0
    while IFS= read -r filename; do
        [[ -n "$filename" ]] || continue
        (( count++ )) || true
        if [[ $count -gt $C2_MAX_FINDINGS_PER_REVIEW ]]; then
            context+="_(${#pending_ref[@]} total findings; showing first ${C2_MAX_FINDINGS_PER_REVIEW})_

"
            break
        fi
        local filepath="${C2_FINDINGS_DIR}/${filename}"
        if [[ -f "$filepath" ]]; then
            local ts source
            ts="$(_format_timestamp "$(_extract_finding_timestamp "$filename")")"
            source="$(_extract_finding_source "$filename")"
            context+="### ${filename}
- **Created**: ${ts}
- **Source**: ${source}

\`\`\`
$(cat "$filepath")
\`\`\`

"
        fi
    done <<< "$sorted_new"

    # Section 2: Recent historical findings (summaries, sorted newest→oldest)
    context+="## Recent Historical Context

"
    local history_count=0
    # Collect processed findings (excluding c2 self-reports and current pending)
    local history_candidates=()
    if [[ -s "$C2_PROCESSED_DB" ]]; then
        while IFS=$'\t' read -r fname _ts; do
            [[ "$fname" == c2-* ]] && continue
            history_candidates+=("$fname")
        done < "$C2_PROCESSED_DB"
    fi

    if [[ ${#history_candidates[@]} -gt 0 ]]; then
        # Sort by finding timestamp (newest first), take context window
        local sorted_history
        sorted_history="$(_sort_findings_by_time history_candidates)"
        # Reverse for newest-first, then take C2_CONTEXT_WINDOW
        sorted_history="$(echo "$sorted_history" | tac | head -n "$C2_CONTEXT_WINDOW")"

        while IFS= read -r filename; do
            [[ -n "$filename" ]] || continue
            local filepath="${C2_FINDINGS_DIR}/${filename}"
            if [[ -f "$filepath" ]]; then
                (( history_count++ )) || true
                local ts source
                ts="$(_format_timestamp "$(_extract_finding_timestamp "$filename")")"
                source="$(_extract_finding_source "$filename")"
                context+="### ${filename} (historical)
- **Created**: ${ts}
- **Source**: ${source}

\`\`\`
$(head -10 "$filepath")
...
\`\`\`

"
            fi
        done <<< "$sorted_history"
    fi

    if [[ $history_count -eq 0 ]]; then
        context+="_No historical findings._

"
    fi

    # Section 3: Current patrol schedule
    local schedule_file="${STATE_DIR}/patrol/schedule.conf"
    if [[ -f "$schedule_file" ]]; then
        context+="## Current Patrol Schedule

\`\`\`
$(cat "$schedule_file")
\`\`\`

"
    fi

    # Section 4: Active directives
    context+="## Active Directives

"
    local has_directives=false
    if [[ -f "${C2_DIRECTIVES_DIR}/schedule-override.conf" ]]; then
        context+="### Schedule Overrides
\`\`\`
$(cat "${C2_DIRECTIVES_DIR}/schedule-override.conf")
\`\`\`

"
        has_directives=true
    fi
    if [[ -f "${C2_DIRECTIVES_DIR}/watch-config.conf" ]]; then
        context+="### Watch Config
\`\`\`
$(cat "${C2_DIRECTIVES_DIR}/watch-config.conf")
\`\`\`

"
        has_directives=true
    fi
    if [[ "$has_directives" != "true" ]]; then
        context+="_No active directives._

"
    fi

    # Section 5: Directive application reports (from services)
    context+="## Directive Application Reports

"
    local report_count=0
    local applied_dir="${C2_DIRECTIVES_DIR}/applied"
    if [[ -d "$applied_dir" ]]; then
        for rfile in "${applied_dir}"/*.report; do
            [[ -f "$rfile" ]] || continue
            (( report_count++ )) || true
            local rname
            rname="$(basename "$rfile")"
            context+="### ${rname}

\`\`\`
$(cat "$rfile")
\`\`\`

"
        done
    fi
    if [[ $report_count -eq 0 ]]; then
        context+="_No directive application reports._

"
    fi

    # Section 6: Open issues
    context+="## Open Issues

"
    local issue_count=0
    for ifile in "${C2_ISSUES_DIR}"/*.md; do
        [[ -f "$ifile" ]] || continue
        (( issue_count++ )) || true
        local iname
        iname="$(basename "$ifile")"
        context+="### ${iname}

\`\`\`
$(cat "$ifile")
\`\`\`

"
    done
    if [[ $issue_count -eq 0 ]]; then
        context+="_No open issues._

"
    fi

    # Section 7: C2 progress notes
    if [[ -f "$C2_PROGRESS" ]]; then
        context+="## C2 Progress Notes

\`\`\`
$(cat "$C2_PROGRESS")
\`\`\`

"
    fi

    echo "$context"
}

# ── Claude invocation ───────────────────────────────────────────

run_c2_analysis() {
    local -n findings_ref=$1

    local timestamp
    timestamp="$(date +%Y-%m-%d-%H%M%S)"
    local findings_file="${C2_FINDINGS_DIR}/c2-${timestamp}.md"
    local directives_dir="${C2_DIRECTIVES_DIR}"
    local issues_dir="${C2_ISSUES_DIR}"
    local issue_id
    issue_id="$(next_issue_id)"

    secy_log "c2" "Starting C2 analysis of ${#findings_ref[@]} finding(s)"

    # Assemble context
    local context
    context="$(assemble_c2_context findings_ref)"

    local c2_prompt="${AGENT_DIR}/C2.md"
    if [[ ! -f "$c2_prompt" ]]; then
        secy_log "c2" "ERROR: C2 prompt not found at ${c2_prompt}"
        return 1
    fi

    local system_prompt
    system_prompt="$(cat "$c2_prompt")"

    local prompt
    prompt="## C2 Correlation Review

${#findings_ref[@]} new finding(s) from subordinate services require cross-service analysis.

${context}

### Instructions

1. Review the new findings in context of historical data and current system state
2. Identify cross-service correlations, temporal patterns, and escalation chains
3. If any finding warrants human attention, create an issue:
   - Write to: ${issues_dir}/<ID>-<slug>.md (next available ID: ${issue_id})
   - Use sequential IDs: ${issue_id}, $(printf '%04d' $(( 10#${issue_id} + 1 ))), etc. if creating multiple
   - Do not duplicate an existing open issue — update it instead if new evidence applies
4. Issue directives if investigation or schedule changes are warranted:
   - Schedule overrides: write to ${directives_dir}/schedule-override.conf
   - Watch config: write to ${directives_dir}/watch-config.conf
   - One-shot directives: write to ${directives_dir}/active/<name>.directive
5. Update your progress notes at: ${C2_PROGRESS}
6. Write your correlation report to: ${findings_file}
7. Output SECY_COMPLETE when done
"

    invoke_claude "$system_prompt" "$prompt" "$C2_REVIEW_BUDGET_USD" > /dev/null

    # Mark all triggering findings as processed
    for filename in "${findings_ref[@]}"; do
        mark_finding_processed "$filename"
    done

    # Immediately mark our own report as processed (self-reference prevention)
    if [[ -f "$findings_file" ]]; then
        mark_finding_processed "$(basename "$findings_file")"
        secy_log "c2" "Analysis complete: ${findings_file}"
    else
        secy_log "c2" "WARNING: Claude did not write findings to ${findings_file}"
    fi
}
