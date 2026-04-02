# Structured auth.log analysis — brute force, logins, sudo, account changes
# Usage: sread authlog [--hours N]

source "${SREAD_ROOT}/lib/redact.sh"

run() {
    require_root

    local root=""
    [[ -d "/host/etc" ]] && root="/host"

    local hours=24
    if [[ "${1:-}" == "--hours" ]] && [[ -n "${2:-}" ]]; then
        if [[ "${2}" =~ ^[0-9]+$ ]]; then
            hours="$2"
        else
            echo "ERROR: --hours requires a numeric value" >&2
            exit 1
        fi
    fi

    local authlog="${root}/var/log/auth.log"
    local authlog_rotated="${root}/var/log/auth.log.1"

    if [[ ! -f "$authlog" ]]; then
        section_header "AUTH LOG ANALYSIS"
        echo "  (file not found: ${authlog#"$root"})"
        return 0
    fi

    section_header "AUTH LOG ANALYSIS (last ${hours}h)"

    # Build date prefixes for the time window.
    # Syslog format: "Mon DD" (e.g., "Apr  1" or "Mar 31").
    # We generate prefixes for each day in the window to handle boundaries.
    local -a date_patterns=()
    for (( i=0; i<hours/24+1; i++ )); do
        local prefix
        prefix="$(date -d "${i} days ago" '+%b %e' 2>/dev/null)" || continue
        # Collapse double-space for single-digit days to match syslog format
        date_patterns+=("$prefix")
    done

    if [[ ${#date_patterns[@]} -eq 0 ]]; then
        # Fallback: just use today
        date_patterns+=("$(date '+%b %e')")
    fi

    # Build grep pattern for date matching
    local date_grep
    date_grep="$(printf '%s\n' "${date_patterns[@]}" | sed 's/^ *//' | paste -sd'|')"

    # Collect relevant log lines (safety cap at 50000 lines)
    local log_data
    log_data="$(tail -50000 "$authlog" 2>/dev/null)"

    # If primary log is small and rotated log exists, prepend it
    local line_count
    line_count="$(echo "$log_data" | wc -l)"
    if [[ "$line_count" -lt 100 ]] && [[ -f "$authlog_rotated" ]]; then
        local rotated_data
        rotated_data="$(tail -50000 "$authlog_rotated" 2>/dev/null)"
        log_data="${rotated_data}"$'\n'"${log_data}"
    fi

    # Filter to time window
    local filtered
    filtered="$(echo "$log_data" | grep -E "^(${date_grep})" 2>/dev/null)" || filtered=""

    if [[ -z "$filtered" ]]; then
        echo "  (no log entries found in last ${hours}h)"
        return 0
    fi

    # ── SSH failed passwords ────────────────────────────────────────
    echo "--- SSH failed password summary ---"
    local failed_lines
    failed_lines="$(echo "$filtered" | grep "Failed password" 2>/dev/null)" || failed_lines=""

    if [[ -n "$failed_lines" ]]; then
        local total_failed
        total_failed="$(echo "$failed_lines" | wc -l)"
        echo "  Total failed attempts: ${total_failed}"

        local unique_ips
        unique_ips="$(echo "$failed_lines" | grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' | sort | uniq -c | sort -rn)"
        local ip_count
        ip_count="$(echo "$unique_ips" | wc -l)"
        echo "  Unique source IPs: ${ip_count}"
        echo ""

        # Show top offenders (>5 attempts)
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local count ip
            read -r count ip <<< "$line"
            if [[ "$count" -gt 5 ]]; then
                echo "  [!] ${ip}: ${count} failures" | redact_output
            else
                echo "  ${ip}: ${count} failures" | redact_output
            fi
        done <<< "$unique_ips"
    else
        echo "  (none detected)"
    fi
    echo ""

    # ── Successful SSH logins ───────────────────────────────────────
    echo "--- Successful SSH logins ---"
    local accepted_lines
    accepted_lines="$(echo "$filtered" | grep -E "Accepted (password|publickey|keyboard-interactive)" 2>/dev/null)" || accepted_lines=""

    if [[ -n "$accepted_lines" ]]; then
        # Aggregate by user+IP+method
        echo "$accepted_lines" | grep -oE 'Accepted (\S+) for (\S+) from (\S+)' | \
            sort | uniq -c | sort -rn | while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local count rest
            read -r count rest <<< "$line"
            echo "  [!] ${rest} (${count} times)" | redact_output
        done
    else
        echo "  (none detected)"
    fi
    echo ""

    # ── Brute force followed by success (same IP) ──────────────────
    echo "--- Brute force then success (same IP) ---"
    local brute_then_success=0

    if [[ -n "$failed_lines" ]] && [[ -n "$accepted_lines" ]]; then
        local failed_ips accepted_ips overlap
        failed_ips="$(echo "$failed_lines" | grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' | sort -u)"
        accepted_ips="$(echo "$accepted_lines" | grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' | sort -u)"
        overlap="$(comm -12 <(echo "$failed_ips") <(echo "$accepted_ips"))" || overlap=""

        if [[ -n "$overlap" ]]; then
            while IFS= read -r ip; do
                [[ -z "$ip" ]] && continue
                local fail_count
                fail_count="$(echo "$failed_lines" | grep -c "from ${ip}" 2>/dev/null)" || fail_count=0
                local accept_detail
                accept_detail="$(echo "$accepted_lines" | grep "from ${ip}" | grep -oE 'Accepted (\S+) for (\S+)' | head -1)"
                echo "  [!] ${ip}: ${fail_count} failures then ${accept_detail}" | redact_output
                brute_then_success=$((brute_then_success + 1))
            done <<< "$overlap"
        fi
    fi
    [[ "$brute_then_success" -eq 0 ]] && echo "  (none detected)"
    echo ""

    # ── Sudo usage ──────────────────────────────────────────────────
    echo "--- Sudo usage ---"
    local sudo_lines
    sudo_lines="$(echo "$filtered" | grep -E 'sudo:.*COMMAND=' 2>/dev/null)" || sudo_lines=""

    if [[ -n "$sudo_lines" ]]; then
        echo "$sudo_lines" | grep -oE 'sudo:\s+\S+' | awk -F: '{gsub(/^[[:space:]]+/,"",$2); print $2}' | \
            sort | uniq -c | sort -rn | while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local count user
            read -r count user <<< "$line"
            echo "  ${user}: ${count} commands" | redact_output
        done
    else
        echo "  (none detected)"
    fi
    echo ""

    # ── Su sessions ─────────────────────────────────────────────────
    echo "--- Su sessions ---"
    local su_lines
    su_lines="$(echo "$filtered" | grep -E 'su\[.*\]:.*session opened' 2>/dev/null)" || su_lines=""

    if [[ -n "$su_lines" ]]; then
        echo "$su_lines" | grep -oE 'session opened for user \S+ by \S+' | \
            sort | uniq -c | sort -rn | while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local count rest
            read -r count rest <<< "$line"
            echo "  [!] ${rest} (${count} times)" | redact_output
        done
    else
        echo "  (none detected)"
    fi
    echo ""

    # ── Account changes ─────────────────────────────────────────────
    echo "--- Account changes ---"
    local acct_lines
    acct_lines="$(echo "$filtered" | grep -E 'useradd|usermod|userdel|passwd|groupadd|groupmod|groupdel' 2>/dev/null)" || acct_lines=""

    if [[ -n "$acct_lines" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            echo "  [!] ${line}" | redact_output
        done <<< "$acct_lines"
    else
        echo "  (none detected)"
    fi
    echo ""

    # ── Summary ─────────────────────────────────────────────────────
    echo "--- Summary ---"
    local total_failed_count=0 total_accepted_count=0 total_sudo_count=0 total_su_count=0 total_acct_count=0
    [[ -n "$failed_lines" ]] && total_failed_count="$(echo "$failed_lines" | wc -l)"
    [[ -n "$accepted_lines" ]] && total_accepted_count="$(echo "$accepted_lines" | wc -l)"
    [[ -n "$sudo_lines" ]] && total_sudo_count="$(echo "$sudo_lines" | wc -l)"
    [[ -n "$su_lines" ]] && total_su_count="$(echo "$su_lines" | wc -l)"
    [[ -n "$acct_lines" ]] && total_acct_count="$(echo "$acct_lines" | wc -l)"

    echo "  Failed SSH: ${total_failed_count}"
    echo "  Successful SSH: ${total_accepted_count}"
    echo "  Brute-then-success: ${brute_then_success}"
    echo "  Sudo invocations: ${total_sudo_count}"
    echo "  Su sessions: ${total_su_count}"
    echo "  Account changes: ${total_acct_count}"

    log_ok "Auth log analysis complete"
}
