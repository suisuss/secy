# Detect surveillance-related processes (keyloggers, screen recorders, RATs)
# Usage: sread spyproc [--deep]

run() {
    require_root

    local deep=false
    [[ "${1:-}" == "--deep" ]] && deep=true

    # Resolve host proc path (container vs bare-metal)
    local proc="/proc"
    [[ -d "/host/proc" ]] && proc="/host/proc"

    section_header "SURVEILLANCE PROCESS SCAN"

    # ── Known spyware process names ──────────────────────────────────
    # Keyloggers
    local keyloggers="logkeys|lkl|pykeylogger|xspy|xkeysnail|screenkey|keysniffer|keysnail"
    # Screen recorders (non-standard / hidden)
    local screenrec="recordmydesktop|simplescreenrecorder|vokoscreen|kazam|peek"
    # Remote access tools
    local rats="teamviewer|anydesk|rustdesk|x11vnc|tigervnc|tightvnc|wayvnc|xrdp|vino-server|remmina"
    # Sniffers and injection
    local sniffers="tcpdump|wireshark|tshark|ettercap|bettercap|mitmproxy|sslstrip"
    # Debugger/tracer attachments
    local tracers="strace|ltrace|sysdig|bpftrace"

    local all_patterns="${keyloggers}|${screenrec}|${rats}|${sniffers}|${tracers}"

    echo "--- Known surveillance process scan ---"
    local found=0
    for pid_dir in "${proc}"/[0-9]*; do
        [[ -f "${pid_dir}/cmdline" ]] || continue
        local cmdline
        cmdline="$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null)" || continue
        [[ -z "$cmdline" ]] && continue

        if echo "$cmdline" | grep -qiE "$all_patterns"; then
            local pid comm
            pid="$(basename "$pid_dir")"
            comm="$(cat "${pid_dir}/comm" 2>/dev/null || echo "?")"
            local uid_line
            uid_line="$(grep '^Uid:' "${pid_dir}/status" 2>/dev/null || echo "Uid: ?")"
            echo "  [!] PID ${pid} (${comm}) uid=${uid_line##*:	}"
            echo "      ${cmdline}"
            found=$((found + 1))
        fi
    done
    [[ $found -eq 0 ]] && echo "  (none detected)"
    echo ""

    # ── Deleted binaries and memfd execution ──────────────────────────
    # A process whose /proc/[pid]/exe points to a deleted file or a memfd
    # is running code that no longer exists on disk. Legitimate software
    # rarely does this; fileless malware relies on it.
    echo "--- Deleted binaries and memfd execution ---"
    local deleted=0
    local memfd=0
    for pid_dir in "${proc}"/[0-9]*; do
        # Skip kernel threads (empty cmdline)
        [[ -s "${pid_dir}/cmdline" ]] || continue
        local exe
        exe="$(readlink "${pid_dir}/exe" 2>/dev/null)" || continue

        local pid comm
        if [[ "$exe" == *" (deleted)" ]]; then
            pid="$(basename "$pid_dir")"
            comm="$(cat "${pid_dir}/comm" 2>/dev/null || echo "?")"
            echo "  [!] PID ${pid} (${comm}) exe points to deleted binary"
            echo "      ${exe}"
            deleted=$((deleted + 1))
        elif [[ "$exe" == /memfd:* ]]; then
            pid="$(basename "$pid_dir")"
            comm="$(cat "${pid_dir}/comm" 2>/dev/null || echo "?")"
            echo "  [!] PID ${pid} (${comm}) running from memfd (memory-only execution)"
            echo "      ${exe}"
            memfd=$((memfd + 1))
        fi
    done
    [[ $((deleted + memfd)) -eq 0 ]] && echo "  (none detected)"
    echo ""

    # ── Ptrace attachments ───────────────────────────────────────────
    echo "--- Ptrace attachments (TracerPid != 0) ---"
    local traced=0
    for pid_dir in "${proc}"/[0-9]*; do
        [[ -f "${pid_dir}/status" ]] || continue
        local tracer_pid
        tracer_pid="$(grep '^TracerPid:' "${pid_dir}/status" 2>/dev/null | awk '{print $2}')" || continue
        if [[ -n "$tracer_pid" ]] && [[ "$tracer_pid" -ne 0 ]]; then
            local pid comm tracer_comm
            pid="$(basename "$pid_dir")"
            comm="$(cat "${pid_dir}/comm" 2>/dev/null || echo "?")"
            tracer_comm="$(cat "${proc}/${tracer_pid}/comm" 2>/dev/null || echo "?")"
            echo "  [!] PID ${pid} (${comm}) is being traced by PID ${tracer_pid} (${tracer_comm})"
            traced=$((traced + 1))
        fi
    done
    [[ $traced -eq 0 ]] && echo "  (none detected)"
    echo ""

    # ── /dev/input readers ───────────────────────────────────────────
    echo "--- Processes reading /dev/input (potential keyloggers) ---"
    local input_readers=0
    for pid_dir in "${proc}"/[0-9]*; do
        [[ -d "${pid_dir}/fd" ]] || continue
        local pid
        pid="$(basename "$pid_dir")"
        # Skip kernel threads
        [[ -f "${pid_dir}/cmdline" ]] || continue
        [[ -s "${pid_dir}/cmdline" ]] || continue

        local has_input=false
        for fd in "${pid_dir}"/fd/*; do
            local target
            target="$(readlink "$fd" 2>/dev/null)" || continue
            if [[ "$target" == /dev/input/* ]]; then
                has_input=true
                break
            fi
        done

        if $has_input; then
            local comm
            comm="$(cat "${pid_dir}/comm" 2>/dev/null || echo "?")"
            # Xorg/Xwayland and libinput legitimately read input devices
            case "$comm" in
                Xorg|Xwayland|libinput*|mutter*|gnome-shell|kwin*|sway|weston) continue ;;
            esac
            local cmdline
            cmdline="$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null || echo "?")"
            echo "  [!] PID ${pid} (${comm}) has /dev/input fd open"
            echo "      ${cmdline}"
            input_readers=$((input_readers + 1))
        fi
    done
    [[ $input_readers -eq 0 ]] && echo "  (none detected — only expected display servers hold input fds)"
    echo ""

    # ── Deep scan: all processes with open network sockets ───────────
    if $deep; then
        echo "--- Deep: processes with raw/packet sockets ---"
        local raw_found=0
        for pid_dir in "${proc}"/[0-9]*; do
            [[ -d "${pid_dir}/fd" ]] || continue
            local pid
            pid="$(basename "$pid_dir")"
            for fd in "${pid_dir}"/fd/*; do
                local target
                target="$(readlink "$fd" 2>/dev/null)" || continue
                if [[ "$target" == socket:* ]]; then
                    # Check if it's a raw or packet socket
                    local inode="${target#socket:[}"
                    inode="${inode%]}"
                    if grep -q "$inode" "${proc}/net/raw" 2>/dev/null || \
                       grep -q "$inode" "${proc}/net/packet" 2>/dev/null; then
                        local comm
                        comm="$(cat "${pid_dir}/comm" 2>/dev/null || echo "?")"
                        echo "  [!] PID ${pid} (${comm}) holds raw/packet socket (inode ${inode})"
                        raw_found=$((raw_found + 1))
                        break
                    fi
                fi
            done
        done
        [[ $raw_found -eq 0 ]] && echo "  (none detected)"
    fi

    echo ""
    log_ok "Process scan complete (found: ${found} suspicious, ${deleted} deleted-exe, ${memfd} memfd, ${traced} traced, ${input_readers} input readers)"
}
