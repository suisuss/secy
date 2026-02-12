# Analyze established network connections for suspicious outbound traffic
# Usage: sread netconn [--raw]

run() {
    require_root

    local show_raw=false
    [[ "${1:-}" == "--raw" ]] && show_raw=true

    local proc="/proc"
    [[ -d "/host/proc" ]] && proc="/host/proc"

    section_header "NETWORK CONNECTION ANALYSIS"

    # /proc/net/tcp is network-namespace-scoped. Inside a container,
    # even /host/proc/net/tcp shows container networking. To get host
    # network data, read through a host PID's network namespace.
    local net_root="${proc}/net"
    if [[ -d "/host/proc/1/net" ]]; then
        net_root="/host/proc/1/net"
    fi

    # ── Parse /proc/net/tcp for established connections ──────────────
    local tcp_file="${net_root}/tcp"
    local tcp6_file="${net_root}/tcp6"

    if $show_raw; then
        echo "--- Raw /proc/net/tcp ---"
        if [[ -f "$tcp_file" ]]; then
            cat "$tcp_file" | sed 's/^/  /'
        fi
        echo ""
        if [[ -f "$tcp6_file" ]]; then
            echo "--- Raw /proc/net/tcp6 ---"
            cat "$tcp6_file" | sed 's/^/  /'
        fi
        echo ""
    fi

    echo "--- Established TCP connections ---"
    if [[ -f "$tcp_file" ]]; then
        # State 01 = ESTABLISHED in /proc/net/tcp
        local estab_count=0
        while read -r line; do
            # Skip header
            [[ "$line" == *"local_address"* ]] && continue
            local state
            state="$(echo "$line" | awk '{print $4}')"
            [[ "$state" != "01" ]] && continue

            local local_hex remote_hex inode_field
            local_hex="$(echo "$line" | awk '{print $2}')"
            remote_hex="$(echo "$line" | awk '{print $3}')"
            inode_field="$(echo "$line" | awk '{print $10}')"

            # Decode hex IP:port (little-endian for IP on x86)
            local local_ip local_port remote_ip remote_port
            local_ip="$(_decode_hex_ip "${local_hex%%:*}")"
            local_port="$((16#${local_hex##*:}))"
            remote_ip="$(_decode_hex_ip "${remote_hex%%:*}")"
            remote_port="$((16#${remote_hex##*:}))"

            # Find owning process via inode
            local proc_name="?"
            if [[ "$inode_field" != "0" ]]; then
                proc_name="$(_find_proc_by_inode "$proc" "$inode_field")"
            fi

            echo "  ${local_ip}:${local_port} -> ${remote_ip}:${remote_port} (${proc_name})"
            estab_count=$((estab_count + 1))
        done < "$tcp_file"
        [[ $estab_count -eq 0 ]] && echo "  (no established connections)"
        echo "  Total: ${estab_count}"
    else
        echo "  (cannot read ${tcp_file})"
    fi
    echo ""

    # ── Listening on 0.0.0.0 (network-exposed) ──────────────────────
    echo "--- Listening on all interfaces (0.0.0.0) ---"
    if [[ -f "$tcp_file" ]]; then
        local exposed=0
        while read -r line; do
            [[ "$line" == *"local_address"* ]] && continue
            local state
            state="$(echo "$line" | awk '{print $4}')"
            # 0A = LISTEN
            [[ "$state" != "0A" ]] && continue

            local local_hex inode_field
            local_hex="$(echo "$line" | awk '{print $2}')"
            inode_field="$(echo "$line" | awk '{print $10}')"

            local local_ip local_port
            local_ip="$(_decode_hex_ip "${local_hex%%:*}")"
            local_port="$((16#${local_hex##*:}))"

            # Only flag services listening on all interfaces
            [[ "$local_ip" != "0.0.0.0" ]] && continue

            local proc_name="?"
            if [[ "$inode_field" != "0" ]]; then
                proc_name="$(_find_proc_by_inode "$proc" "$inode_field")"
            fi

            echo "  [!] 0.0.0.0:${local_port} (${proc_name})"
            exposed=$((exposed + 1))
        done < "$tcp_file"
        [[ $exposed -eq 0 ]] && echo "  (none — all services bound to localhost)"
    fi
    echo ""

    # ── Unusual outbound ports ───────────────────────────────────────
    echo "--- Connections to unusual remote ports ---"
    local common_ports="22 53 80 443 8080 8443 993 995 587 465 143 110 25"
    if [[ -f "$tcp_file" ]]; then
        local unusual=0
        while read -r line; do
            [[ "$line" == *"local_address"* ]] && continue
            local state
            state="$(echo "$line" | awk '{print $4}')"
            [[ "$state" != "01" ]] && continue

            local remote_hex inode_field
            remote_hex="$(echo "$line" | awk '{print $3}')"
            inode_field="$(echo "$line" | awk '{print $10}')"

            local remote_ip remote_port
            remote_ip="$(_decode_hex_ip "${remote_hex%%:*}")"
            remote_port="$((16#${remote_hex##*:}))"

            # Skip loopback and LAN
            [[ "$remote_ip" == 127.* ]] && continue
            [[ "$remote_ip" == 192.168.* ]] && continue
            [[ "$remote_ip" == 10.* ]] && continue
            [[ "$remote_ip" == 172.1[6-9].* ]] && continue
            [[ "$remote_ip" == 172.2[0-9].* ]] && continue
            [[ "$remote_ip" == 172.3[0-1].* ]] && continue

            # Check if port is common
            local is_common=false
            for p in $common_ports; do
                [[ "$remote_port" -eq "$p" ]] && { is_common=true; break; }
            done
            if ! $is_common; then
                local proc_name="?"
                if [[ "$inode_field" != "0" ]]; then
                    proc_name="$(_find_proc_by_inode "$proc" "$inode_field")"
                fi
                echo "  [!] -> ${remote_ip}:${remote_port} (${proc_name})"
                unusual=$((unusual + 1))
            fi
        done < "$tcp_file"
        [[ $unusual -eq 0 ]] && echo "  (none detected — all outbound to standard ports)"
    fi

    echo ""
    log_ok "Network connection analysis complete"
}

# ── Helpers ──────────────────────────────────────────────────────────

# Decode /proc/net/tcp hex IP (little-endian on x86) to dotted quad
_decode_hex_ip() {
    local hex="$1"
    # Pad to 8 chars
    while [[ ${#hex} -lt 8 ]]; do hex="0${hex}"; done
    printf "%d.%d.%d.%d" \
        "0x${hex:6:2}" "0x${hex:4:2}" "0x${hex:2:2}" "0x${hex:0:2}"
}

# Find process name by socket inode
_find_proc_by_inode() {
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
