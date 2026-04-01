# Detect network-level threats: suspicious process connections, beaconing, tmp execution
# Usage: sread netthreats [--state-dir /path]

run() {
    require_root

    local state_dir=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --state-dir)
                state_dir="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    local proc="/proc"
    [[ -d "/host/proc" ]] && proc="/host/proc"

    # Use host PID 1's network namespace for accurate results
    local net_root="${proc}/net"
    if [[ -d "${proc}/1/net" ]]; then
        net_root="${proc}/1/net"
    fi

    section_header "NETWORK THREAT DETECTION"

    # ── Allowed outbound ports ──────────────────────────────────────
    # Strict allowlist. Anything outside this hitting a non-RFC1918 IP
    # is flagged. This would catch the axios RAT on port 8000.
    local allowed_ports="22 53 80 443"

    local tcp_file="${net_root}/tcp"

    # ── 1. Outbound connections to non-allowed ports ────────────────
    echo "--- Outbound to non-allowed ports (allowed: ${allowed_ports}) ---"
    local blocked_count=0
    if [[ -f "$tcp_file" ]]; then
        while IFS= read -r line; do
            [[ "$line" == *"local_address"* ]] && continue
            local state
            state="$(echo "$line" | awk '{print $4}')"
            # 01=ESTABLISHED, 02=SYN_SENT — catch both
            [[ "$state" != "01" ]] && [[ "$state" != "02" ]] && continue

            local remote_hex inode_field
            remote_hex="$(echo "$line" | awk '{print $3}')"
            inode_field="$(echo "$line" | awk '{print $10}')"

            local remote_ip remote_port
            remote_ip="$(_decode_hex_ip "${remote_hex%%:*}")"
            remote_port="$((16#${remote_hex##*:}))"

            # Skip loopback and private ranges
            [[ "$remote_ip" == 127.* ]] && continue
            [[ "$remote_ip" == 192.168.* ]] && continue
            [[ "$remote_ip" == 10.* ]] && continue
            [[ "$remote_ip" == 172.1[6-9].* ]] && continue
            [[ "$remote_ip" == 172.2[0-9].* ]] && continue
            [[ "$remote_ip" == 172.3[0-1].* ]] && continue
            [[ "$remote_ip" == 0.0.0.0 ]] && continue

            local is_allowed=false
            for p in $allowed_ports; do
                [[ "$remote_port" -eq "$p" ]] && { is_allowed=true; break; }
            done

            if ! $is_allowed; then
                local proc_info
                proc_info="$(_get_proc_details "$proc" "$inode_field")"
                echo "  [!] -> ${remote_ip}:${remote_port} ${proc_info}"
                blocked_count=$((blocked_count + 1))
            fi
        done < "$tcp_file"
    fi
    [[ $blocked_count -eq 0 ]] && echo "  (none — all outbound on allowed ports)"
    echo ""

    # ── 2. Processes connecting from suspicious locations ───────────
    # Binaries running from /tmp, /dev/shm, /var/tmp, or dot-prefixed
    # hidden paths making network connections are highly suspicious.
    # The axios ld.py ran from /tmp/ld.py.
    echo "--- Network-active processes from suspicious paths ---"
    local suspect_proc_count=0
    local suspicious_dirs="^(/tmp/|/dev/shm/|/var/tmp/|/home/[^/]+/\.)"

    if [[ -f "$tcp_file" ]]; then
        # Collect inodes of all established/syn_sent connections
        local -A conn_inodes=()
        while IFS= read -r line; do
            [[ "$line" == *"local_address"* ]] && continue
            local state
            state="$(echo "$line" | awk '{print $4}')"
            [[ "$state" != "01" ]] && [[ "$state" != "02" ]] && continue
            local inode
            inode="$(echo "$line" | awk '{print $10}')"
            [[ "$inode" != "0" ]] && conn_inodes["$inode"]=1
        done < "$tcp_file"

        # Walk processes, check if they own any connection socket and run from suspicious path
        for pid_dir in "${proc}"/[0-9]*; do
            [[ -d "${pid_dir}/fd" ]] || continue
            [[ -f "${pid_dir}/cmdline" ]] || continue

            local exe
            exe="$(readlink "${pid_dir}/exe" 2>/dev/null)" || continue

            # Check if exe path is suspicious
            local exe_clean="${exe% (deleted)}"
            if ! [[ "$exe_clean" =~ $suspicious_dirs ]]; then
                continue
            fi

            # Check if this process owns any network connection
            local has_conn=false
            for fd in "${pid_dir}"/fd/*; do
                local link
                link="$(readlink "$fd" 2>/dev/null)" || continue
                if [[ "$link" == socket:* ]]; then
                    local sock_inode="${link#socket:[}"
                    sock_inode="${sock_inode%]}"
                    if [[ -n "${conn_inodes[$sock_inode]+x}" ]]; then
                        has_conn=true
                        break
                    fi
                fi
            done

            if $has_conn; then
                local pid comm cmdline ppid parent_comm
                pid="$(basename "$pid_dir")"
                comm="$(cat "${pid_dir}/comm" 2>/dev/null || echo "?")"
                cmdline="$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null || echo "?")"
                ppid="$(grep '^PPid:' "${pid_dir}/status" 2>/dev/null | awk '{print $2}')" || ppid="?"
                parent_comm="$(cat "${proc}/${ppid}/comm" 2>/dev/null || echo "?")"

                echo "  [!] PID ${pid} (${comm}) exe=${exe_clean}"
                echo "      cmdline: ${cmdline}"
                echo "      parent: PID ${ppid} (${parent_comm})"
                suspect_proc_count=$((suspect_proc_count + 1))
            fi
        done
    fi
    [[ $suspect_proc_count -eq 0 ]] && echo "  (none — no network-active processes from /tmp, /dev/shm, or hidden paths)"
    echo ""

    # ── 3. Interpreters with network connections and no terminal ────
    # A python/node/perl process making outbound connections with no
    # controlling terminal is a strong RAT indicator.
    echo "--- Detached interpreters with network connections ---"
    local detached_count=0
    local interpreters="python|python3|perl|ruby|node|lua"

    if [[ -f "$tcp_file" ]]; then
        for pid_dir in "${proc}"/[0-9]*; do
            [[ -f "${pid_dir}/cmdline" ]] || continue
            local comm
            comm="$(cat "${pid_dir}/comm" 2>/dev/null)" || continue

            # Only check interpreters
            if ! echo "$comm" | grep -qiE "^(${interpreters})"; then
                continue
            fi

            # Check for controlling terminal (field 7 in /proc/pid/stat)
            local tty_nr
            tty_nr="$(awk '{print $7}' "${pid_dir}/stat" 2>/dev/null)" || continue
            # tty_nr 0 means no controlling terminal
            [[ "$tty_nr" != "0" ]] && continue

            # Check if this process owns any connection
            [[ -d "${pid_dir}/fd" ]] || continue
            local has_conn=false
            for fd in "${pid_dir}"/fd/*; do
                local link
                link="$(readlink "$fd" 2>/dev/null)" || continue
                if [[ "$link" == socket:* ]]; then
                    local sock_inode="${link#socket:[}"
                    sock_inode="${sock_inode%]}"
                    if [[ -n "${conn_inodes[$sock_inode]+x}" ]]; then
                        has_conn=true
                        break
                    fi
                fi
            done

            if $has_conn; then
                local pid cmdline exe ppid parent_comm
                pid="$(basename "$pid_dir")"
                cmdline="$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null || echo "?")"
                exe="$(readlink "${pid_dir}/exe" 2>/dev/null || echo "?")"
                ppid="$(grep '^PPid:' "${pid_dir}/status" 2>/dev/null | awk '{print $2}')" || ppid="?"
                parent_comm="$(cat "${proc}/${ppid}/comm" 2>/dev/null || echo "?")"

                echo "  [!] PID ${pid} (${comm}) — no terminal, has network connection"
                echo "      exe: ${exe}"
                echo "      cmdline: ${cmdline}"
                echo "      parent: PID ${ppid} (${parent_comm})"
                detached_count=$((detached_count + 1))
            fi
        done
    fi
    [[ $detached_count -eq 0 ]] && echo "  (none — all network-active interpreters have a controlling terminal)"
    echo ""

    # ── 4. Beacon detection (requires state across runs) ────────────
    # Track (remote_ip:port, process) tuples. If the same tuple appears
    # in 3+ consecutive runs, flag as beaconing.
    echo "--- Beacon detection (repeat connections across runs) ---"
    local beacon_count=0

    if [[ -n "$state_dir" ]] && [[ -d "$state_dir" ]]; then
        local beacon_state="${state_dir}/netthreats-beacons.dat"
        local current_tuples=""

        # Build current connection tuples
        if [[ -f "$tcp_file" ]]; then
            while IFS= read -r line; do
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

                # Skip loopback/private
                [[ "$remote_ip" == 127.* ]] && continue
                [[ "$remote_ip" == 192.168.* ]] && continue
                [[ "$remote_ip" == 10.* ]] && continue
                [[ "$remote_ip" == 172.1[6-9].* ]] && continue
                [[ "$remote_ip" == 172.2[0-9].* ]] && continue
                [[ "$remote_ip" == 172.3[0-1].* ]] && continue

                local proc_name="?"
                if [[ "$inode_field" != "0" ]]; then
                    proc_name="$(_find_proc_by_inode "$proc" "$inode_field")"
                    proc_name="${proc_name%%/*}"
                fi

                current_tuples="${current_tuples}${remote_ip}:${remote_port}|${proc_name}"$'\n'
            done < "$tcp_file"
        fi

        # Sort and deduplicate
        current_tuples="$(echo "$current_tuples" | sort -u | grep -v '^$')"

        if [[ -f "$beacon_state" ]]; then
            # Compare with previous state — find tuples that persist
            while IFS='|' read -r tuple count; do
                [[ -z "$tuple" ]] && continue
                if echo "$current_tuples" | grep -q "^${tuple}|"; then
                    local new_count=$((count + 1))
                    echo "${tuple}|${new_count}" >> "${beacon_state}.tmp"
                    if [[ $new_count -ge 3 ]]; then
                        local b_proc
                        b_proc="$(echo "$current_tuples" | grep "^${tuple}|" | head -1 | cut -d'|' -f2)"
                        echo "  [!] ${tuple} (${b_proc}) — seen in ${new_count} consecutive scans"
                        beacon_count=$((beacon_count + 1))
                    fi
                fi
            done < "$beacon_state"

            # Add new tuples not in previous state
            while IFS='|' read -r addr proc_name; do
                [[ -z "$addr" ]] && continue
                if ! grep -q "^${addr}|" "${beacon_state}" 2>/dev/null; then
                    echo "${addr}|1" >> "${beacon_state}.tmp"
                fi
            done <<< "$current_tuples"

            mv "${beacon_state}.tmp" "$beacon_state" 2>/dev/null || true
        else
            # First run — seed state file
            while IFS='|' read -r addr proc_name; do
                [[ -z "$addr" ]] && continue
                echo "${addr}|1"
            done <<< "$current_tuples" > "$beacon_state"
            echo "  (first run — seeding beacon state, will detect on subsequent runs)"
        fi
    else
        echo "  (no --state-dir provided — beacon tracking disabled)"
        echo "  hint: patrol passes this automatically"
    fi
    [[ $beacon_count -eq 0 ]] && [[ -n "$state_dir" ]] && [[ -f "${state_dir}/netthreats-beacons.dat" ]] && \
        echo "  (no repeat beacons detected)"
    echo ""

    # ── 5. Reverse DNS on flagged IPs ──────────────────────────────
    # Attempt reverse lookup on IPs from non-allowed-port connections.
    # No-result or very new domains are additional indicators.
    echo "--- Reverse DNS on flagged destinations ---"
    local rdns_count=0
    if [[ $blocked_count -gt 0 ]] && command -v getent &>/dev/null; then
        # Re-scan for flagged IPs
        while IFS= read -r line; do
            [[ "$line" == *"local_address"* ]] && continue
            local state
            state="$(echo "$line" | awk '{print $4}')"
            [[ "$state" != "01" ]] && [[ "$state" != "02" ]] && continue

            local remote_hex
            remote_hex="$(echo "$line" | awk '{print $3}')"
            local remote_ip remote_port
            remote_ip="$(_decode_hex_ip "${remote_hex%%:*}")"
            remote_port="$((16#${remote_hex##*:}))"

            [[ "$remote_ip" == 127.* ]] && continue
            [[ "$remote_ip" == 192.168.* ]] && continue
            [[ "$remote_ip" == 10.* ]] && continue
            [[ "$remote_ip" == 172.1[6-9].* ]] && continue
            [[ "$remote_ip" == 172.2[0-9].* ]] && continue
            [[ "$remote_ip" == 172.3[0-1].* ]] && continue

            local is_allowed=false
            for p in $allowed_ports; do
                [[ "$remote_port" -eq "$p" ]] && { is_allowed=true; break; }
            done

            if ! $is_allowed; then
                local hostname
                hostname="$(getent hosts "$remote_ip" 2>/dev/null | awk '{print $2}')" || hostname=""
                if [[ -n "$hostname" ]]; then
                    echo "  ${remote_ip} -> ${hostname}"
                else
                    echo "  ${remote_ip} -> (no PTR record — suspicious)"
                fi
                rdns_count=$((rdns_count + 1))
            fi
        done < "$tcp_file"
    elif [[ $blocked_count -eq 0 ]]; then
        echo "  (no flagged IPs to look up)"
    else
        echo "  (getent not available — skipping reverse DNS)"
    fi
    echo ""

    # ── Summary ─────────────────────────────────────────────────────
    echo "--- Summary ---"
    echo "  Non-allowed port connections: ${blocked_count}"
    echo "  Processes from suspicious paths: ${suspect_proc_count}"
    echo "  Detached interpreters with network: ${detached_count}"
    echo "  Beacon patterns detected: ${beacon_count}"

    echo ""
    log_ok "Network threat scan complete (blocked_ports: ${blocked_count}, suspect_procs: ${suspect_proc_count}, detached: ${detached_count}, beacons: ${beacon_count})"
}

# ── Helpers ──────────────────────────────────────────────────────────

_decode_hex_ip() {
    local hex="$1"
    while [[ ${#hex} -lt 8 ]]; do hex="0${hex}"; done
    printf "%d.%d.%d.%d" \
        "0x${hex:6:2}" "0x${hex:4:2}" "0x${hex:2:2}" "0x${hex:0:2}"
}

_find_proc_by_inode() {
    local proc_root="$1"
    local target_inode="$2"
    for pid_dir in "${proc_root}"/[0-9]*; do
        [[ -d "${pid_dir}/fd" ]] || continue
        for fd in "${pid_dir}"/fd/*; do
            local link
            link="$(readlink "$fd" 2>/dev/null)" || continue
            if [[ "$link" == "socket:[${target_inode}]" ]]; then
                local comm pid
                comm="$(cat "${pid_dir}/comm" 2>/dev/null || echo "?")"
                pid="$(basename "$pid_dir")"
                echo "${comm}/${pid}"
                return 0
            fi
        done
    done
    echo "?/?"
}

_get_proc_details() {
    local proc_root="$1"
    local target_inode="$2"
    [[ "$target_inode" == "0" ]] && { echo "(inode 0)"; return; }

    for pid_dir in "${proc_root}"/[0-9]*; do
        [[ -d "${pid_dir}/fd" ]] || continue
        for fd in "${pid_dir}"/fd/*; do
            local link
            link="$(readlink "$fd" 2>/dev/null)" || continue
            if [[ "$link" == "socket:[${target_inode}]" ]]; then
                local pid comm exe cmdline ppid parent_comm
                pid="$(basename "$pid_dir")"
                comm="$(cat "${pid_dir}/comm" 2>/dev/null || echo "?")"
                exe="$(readlink "${pid_dir}/exe" 2>/dev/null || echo "?")"
                cmdline="$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null || echo "?")"
                ppid="$(grep '^PPid:' "${pid_dir}/status" 2>/dev/null | awk '{print $2}')" || ppid="?"
                parent_comm="$(cat "${proc_root}/${ppid}/comm" 2>/dev/null || echo "?")"
                echo "(${comm}/${pid} exe=${exe} parent=${parent_comm}/${ppid})"
                return 0
            fi
        done
    done
    echo "(?/?)"
}
