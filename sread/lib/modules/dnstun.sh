# Detect DNS tunneling tools, rogue DNS listeners, and suspicious DNS configuration
# Usage: sread dnstun

run() {
    require_root

    local proc="/proc"
    [[ -d "/host/proc" ]] && proc="/host/proc"
    local root=""
    [[ -d "/host/etc" ]] && root="/host"

    # Use host PID 1's network namespace for accurate results
    local net_root="${proc}/net"
    if [[ -d "${proc}/1/net" ]]; then
        net_root="${proc}/1/net"
    fi

    section_header "DNS TUNNELING DETECTION"

    echo "NOTE: Full DNS tunneling detection requires packet capture (tcpdump/tshark)."
    echo "      This module detects tools, rogue listeners, and config anomalies."
    echo ""

    # ── Known DNS tunneling tool processes ──────────────────────────
    echo "--- DNS tunneling tool processes ---"
    local tunnel_tools="iodine|iodined|dns2tcp|dns2tcpd|dnscat2|dnscat|tuns|dnscapy|dnschef|dnstt|dnsrebind"
    local tunnel_procs=0
    for pid_dir in "${proc}"/[0-9]*; do
        [[ -f "${pid_dir}/cmdline" ]] || continue
        local cmdline
        cmdline="$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null)" || continue
        [[ -z "$cmdline" ]] && continue

        if echo "$cmdline" | grep -qiE "$tunnel_tools"; then
            local pid comm
            pid="$(basename "$pid_dir")"
            comm="$(cat "${pid_dir}/comm" 2>/dev/null || echo "?")"
            echo "  [!] PID ${pid} (${comm}): ${cmdline}"
            tunnel_procs=$((tunnel_procs + 1))
        fi
    done
    [[ $tunnel_procs -eq 0 ]] && echo "  (none detected)"
    echo ""

    # ── Rogue DNS listeners ────────────────────────────────────────
    # Parse /proc/net/udp for local port 53 (0035 hex). Legitimate
    # resolvers (systemd-resolved, dnsmasq, unbound) are allowlisted.
    echo "--- Rogue DNS listeners (UDP port 53) ---"
    local udp_file="${net_root}/udp"
    local dns_known="^(systemd-resolve|dnsmasq|unbound|named|pdns|pdns_recursor|pihole-FTL|coredns|bind9)$"
    local rogue_dns=0
    if [[ -f "$udp_file" ]]; then
        while IFS= read -r line; do
            [[ "$line" == *"local_address"* ]] && continue
            local local_hex
            local_hex="$(echo "$line" | awk '{print $2}')"
            local local_port="${local_hex##*:}"
            # Port 53 = 0x0035
            [[ "$local_port" != "0035" ]] && continue

            local inode
            inode="$(echo "$line" | awk '{print $10}')"
            local proc_name="?"
            if [[ "$inode" != "0" ]]; then
                proc_name="$(_find_dns_proc "$proc" "$inode")"
            fi

            local proc_comm="${proc_name%%/*}"
            if echo "$proc_comm" | grep -qiE "$dns_known"; then
                echo "  ${local_hex} (${proc_name}) — known resolver"
            else
                echo "  [!] ${local_hex} (${proc_name}) — NOT a known resolver"
                rogue_dns=$((rogue_dns + 1))
            fi
        done < "$udp_file"
        [[ $rogue_dns -eq 0 ]] && [[ $tunnel_procs -eq 0 ]] && echo "  (no rogue DNS listeners)"
    else
        echo "  (cannot read ${udp_file})"
    fi
    echo ""

    # ── Suspicious resolv.conf ─────────────────────────────────────
    echo "--- resolv.conf analysis ---"
    local resolv="${root}/etc/resolv.conf"
    local known_dns="^(127\.0\.0\.1|127\.0\.0\.53|::1|8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|1\.0\.0\.1|9\.9\.9\.9|149\.112\.112\.112|208\.67\.222\.222|208\.67\.220\.220)$"
    local suspect_ns=0
    if [[ -f "$resolv" ]]; then
        while IFS= read -r line; do
            # Skip comments and empty lines
            [[ "$line" == \#* ]] && continue
            [[ -z "$line" ]] && continue
            if [[ "$line" =~ ^nameserver[[:space:]]+(.+)$ ]]; then
                local ns="${BASH_REMATCH[1]}"
                # Trim whitespace
                ns="$(echo "$ns" | xargs)"
                if echo "$ns" | grep -qE "$known_dns"; then
                    echo "  nameserver ${ns} (known-good)"
                else
                    echo "  [!] nameserver ${ns} (not in known-good list)"
                    suspect_ns=$((suspect_ns + 1))
                fi
            fi
        done < "$resolv"
    else
        echo "  (resolv.conf not found)"
    fi
    echo ""

    # ── Tunneling tools on disk ────────────────────────────────────
    echo "--- DNS tunneling tools on disk ---"
    local tool_bins="iodine iodined dns2tcp dns2tcpd dnscat2 dnscat tuns dnscapy dnschef dnstt"
    local search_dirs=("${root}/usr/bin" "${root}/usr/sbin" "${root}/usr/local/bin" "${root}/usr/local/sbin")
    local tools_found=0
    for tool in $tool_bins; do
        for dir in "${search_dirs[@]}"; do
            if [[ -f "${dir}/${tool}" ]]; then
                echo "  [!] ${dir}/${tool}"
                tools_found=$((tools_found + 1))
            fi
        done
    done
    [[ $tools_found -eq 0 ]] && echo "  (none found)"
    echo ""

    # ── Summary ────────────────────────────────────────────────────
    echo "--- Summary ---"
    echo "  Tunneling tool processes: ${tunnel_procs}"
    echo "  Rogue DNS listeners: ${rogue_dns}"
    echo "  Suspicious nameservers: ${suspect_ns}"
    echo "  Tunneling tools on disk: ${tools_found}"

    echo ""
    log_ok "DNS tunneling scan complete (procs: ${tunnel_procs}, rogue: ${rogue_dns}, suspect_ns: ${suspect_ns}, tools: ${tools_found})"
}

# ── Helpers ──────────────────────────────────────────────────────────

# Find process name by socket inode (same pattern as netconn.sh)
_find_dns_proc() {
    local proc_root="$1"
    local target_inode="$2"
    for pid_dir in "${proc_root}"/[0-9]*; do
        [[ -d "${pid_dir}/fd" ]] || continue
        for fd in "${pid_dir}"/fd/*; do
            local link
            link="$(readlink "$fd" 2>/dev/null)" || continue
            if [[ "$link" == "socket:[${target_inode}]" ]]; then
                local comm
                comm="$(cat "${pid_dir}/comm" 2>/dev/null || echo "?")"
                local pid
                pid="$(basename "$pid_dir")"
                echo "${comm}/${pid}"
                return 0
            fi
        done
    done
    echo "?/?"
}
