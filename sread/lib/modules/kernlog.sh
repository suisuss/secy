# Kernel log analysis — module loads, segfaults, OOM, USB, network, firewall
# Usage: sread kernlog [--hours N]

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

    local kernlog="${root}/var/log/kern.log"
    local kernlog_rotated="${root}/var/log/kern.log.1"
    local syslog="${root}/var/log/syslog"

    section_header "KERNEL LOG ANALYSIS (last ${hours}h)"

    if [[ ! -f "$kernlog" ]] && [[ ! -f "$syslog" ]]; then
        echo "  (no kernel log found: tried ${kernlog#"$root"} and ${syslog#"$root"})"
        return 0
    fi

    # Build date prefixes for syslog-format time window
    local -a date_patterns=()
    for (( i=0; i<hours/24+1; i++ )); do
        local prefix
        prefix="$(date -d "${i} days ago" '+%b %e' 2>/dev/null)" || continue
        date_patterns+=("$prefix")
    done
    [[ ${#date_patterns[@]} -eq 0 ]] && date_patterns+=("$(date '+%b %e')")

    local date_grep
    date_grep="$(printf '%s\n' "${date_patterns[@]}" | sed 's/^ *//' | paste -sd'|')"

    # Collect kernel log lines
    local log_data=""
    if [[ -f "$kernlog" ]]; then
        log_data="$(tail -50000 "$kernlog" 2>/dev/null)"
        # Include rotated log if primary is small
        local line_count
        line_count="$(echo "$log_data" | wc -l)"
        if [[ "$line_count" -lt 100 ]] && [[ -f "$kernlog_rotated" ]]; then
            local rotated
            rotated="$(tail -50000 "$kernlog_rotated" 2>/dev/null)"
            log_data="${rotated}"$'\n'"${log_data}"
        fi
    elif [[ -f "$syslog" ]]; then
        # Fallback: extract kernel messages from syslog
        log_data="$(tail -100000 "$syslog" 2>/dev/null | grep ' kernel: ')"
    fi

    # Filter to time window
    local filtered
    filtered="$(echo "$log_data" | grep -E "^(${date_grep})" 2>/dev/null)" || filtered=""

    if [[ -z "$filtered" ]]; then
        echo "  (no kernel log entries in last ${hours}h)"
        return 0
    fi

    # ── Kernel module load events ───────────────────────────────────
    echo "--- Kernel module load events ---"
    local mod_lines
    mod_lines="$(echo "$filtered" | grep -iE 'module.*(loaded|registered|init)|insmod|modprobe' 2>/dev/null)" || mod_lines=""

    if [[ -n "$mod_lines" ]]; then
        # Extract module names and deduplicate
        echo "$mod_lines" | grep -oiE '(module \S+ |insmod \S+|modprobe \S+)' | \
            sort -u | while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            echo "  [!] ${line}" | redact_output
        done
    else
        echo "  (none detected)"
    fi
    echo ""

    # ── Segfaults ───────────────────────────────────────────────────
    echo "--- Segfaults ---"
    local segfault_lines
    segfault_lines="$(echo "$filtered" | grep 'segfault at' 2>/dev/null)" || segfault_lines=""

    if [[ -n "$segfault_lines" ]]; then
        local total_segfaults
        total_segfaults="$(echo "$segfault_lines" | wc -l)"
        echo "  Total: ${total_segfaults}"
        echo ""

        # Aggregate by binary path
        echo "$segfault_lines" | grep -oE 'in \S+' | awk '{print $2}' | \
            sort | uniq -c | sort -rn | while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local count binary
            read -r count binary <<< "$line"
            echo "  ${binary}: ${count}" | redact_output
        done
    else
        echo "  (none detected)"
    fi
    echo ""

    # ── OOM kills ───────────────────────────────────────────────────
    echo "--- OOM kills ---"
    local oom_lines
    oom_lines="$(echo "$filtered" | grep -iE 'out of memory|oom-kill|killed process' 2>/dev/null)" || oom_lines=""

    if [[ -n "$oom_lines" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            # Extract the key info: process name and memory stats
            echo "  [!] ${line}" | redact_output
        done <<< "$oom_lines"
    else
        echo "  (none detected)"
    fi
    echo ""

    # ── USB device events ───────────────────────────────────────────
    echo "--- USB device events ---"
    local usb_lines
    usb_lines="$(echo "$filtered" | grep -iE 'new usb device|usb [0-9].*:.*product|usb disconnect' 2>/dev/null)" || usb_lines=""

    if [[ -n "$usb_lines" ]]; then
        echo "$usb_lines" | grep -oiE '(new usb device found.*|product: .*|usb disconnect.*)' | \
            sort -u | while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            echo "  [!] ${line}" | redact_output
        done
    else
        echo "  (none detected)"
    fi
    echo ""

    # ── Network interface changes ───────────────────────────────────
    echo "--- Network interface changes ---"
    local net_lines
    net_lines="$(echo "$filtered" | grep -iE 'link up|link down|entered promiscuous|left promiscuous|entered forwarding|carrier (up|down)' 2>/dev/null)" || net_lines=""

    if [[ -n "$net_lines" ]]; then
        # Deduplicate similar events
        echo "$net_lines" | grep -oiE '\S+: link (up|down).*|entered promiscuous mode|left promiscuous mode|entered forwarding state' | \
            sort | uniq -c | sort -rn | while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local count event
            read -r count event <<< "$line"
            if echo "$event" | grep -qi 'promiscuous'; then
                echo "  [!] ${event} (${count} times)" | redact_output
            else
                echo "  ${event} (${count} times)" | redact_output
            fi
        done
    else
        echo "  (none detected)"
    fi
    echo ""

    # ── Firewall blocks ─────────────────────────────────────────────
    echo "--- Firewall blocks ---"
    local fw_lines
    fw_lines="$(echo "$filtered" | grep -iE 'UFW BLOCK|iptables.*DROP|nft.*drop|IN=.*OUT=.*SRC=.*DPT=' 2>/dev/null)" || fw_lines=""

    if [[ -n "$fw_lines" ]]; then
        local total_blocks
        total_blocks="$(echo "$fw_lines" | wc -l)"
        echo "  Total: ${total_blocks}"
        echo ""

        # Aggregate by source IP
        echo "  Top sources:"
        echo "$fw_lines" | grep -oE 'SRC=[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk -F= '{print $2}' | \
            sort | uniq -c | sort -rn | head -10 | while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local count ip
            read -r count ip <<< "$line"
            echo "    ${ip}: ${count} blocks" | redact_output
        done
    else
        echo "  (none detected)"
    fi
    echo ""

    # ── Summary ─────────────────────────────────────────────────────
    echo "--- Summary ---"
    local mod_count=0 seg_count=0 oom_count=0 usb_count=0 net_count=0 fw_count=0
    [[ -n "$mod_lines" ]] && mod_count="$(echo "$mod_lines" | wc -l)"
    [[ -n "$segfault_lines" ]] && seg_count="$(echo "$segfault_lines" | wc -l)"
    [[ -n "$oom_lines" ]] && oom_count="$(echo "$oom_lines" | wc -l)"
    [[ -n "$usb_lines" ]] && usb_count="$(echo "$usb_lines" | wc -l)"
    [[ -n "$net_lines" ]] && net_count="$(echo "$net_lines" | wc -l)"
    [[ -n "$fw_lines" ]] && fw_count="$(echo "$fw_lines" | wc -l)"

    echo "  Module loads: ${mod_count}"
    echo "  Segfaults: ${seg_count}"
    echo "  OOM kills: ${oom_count}"
    echo "  USB events: ${usb_count}"
    echo "  Network changes: ${net_count}"
    echo "  Firewall blocks: ${fw_count}"

    log_ok "Kernel log analysis complete"
}
