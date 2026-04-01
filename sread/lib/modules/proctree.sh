# Detect suspicious process ancestry chains and orphaned daemons
# Usage: sread proctree

run() {
    require_root

    local proc="/proc"
    [[ -d "/host/proc" ]] && proc="/host/proc"

    section_header "PROCESS TREE ANOMALY DETECTION"

    # ── 1. Orphaned processes (reparented to PID 1) ────────────────
    # Processes that were deliberately detached from their parent
    # (via nohup, setsid, double-fork) get reparented to PID 1.
    # Legitimate daemons do this, but so does malware like the axios
    # RAT which used nohup to survive terminal close.
    #
    # We flag orphans that are NOT known system services.
    echo "--- Orphaned user processes (PPID=1, non-service) ---"
    local orphan_count=0
    local known_daemons="^(systemd|dbus-daemon|polkitd|rtkit-daemon|udisksd|upowerd|NetworkManager|wpa_supplicant|bluetoothd|cupsd|cron|atd|rsyslogd|sshd|agetty|login|gdm|lightdm|sddm|pipewire|pulseaudio|wireplumber|gnome-session|gnome-shell|plasmashell|kwin|Xorg|Xwayland|dockerd|containerd|snapd|unattended-upgr|thermald|irqbalance|accounts-daemon|power-profiles-|switcheroo-cont|low-memory-moni|iio-sensor-prox|fwupd|packagekitd|colord|geoclue|gvfsd|at-spi|xdg-|gnome-keyring|ssh-agent|gpg-agent|dconf-service|gsd-|evolution-|tracker-|gvfs-|zeitgeist|bamfdaemon|indicator-|ibus-|fcitx|nm-applet|blueman|cbatticon)$"

    for pid_dir in "${proc}"/[0-9]*; do
        [[ -f "${pid_dir}/status" ]] || continue
        [[ -f "${pid_dir}/cmdline" ]] || continue

        local cmdline_check
        cmdline_check="$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null)" || continue
        [[ -z "${cmdline_check// /}" ]] && continue

        local ppid
        ppid="$(grep '^PPid:' "${pid_dir}/status" 2>/dev/null | awk '{print $2}')" || continue

        # Only interested in processes whose parent is PID 1 (or the host's init)
        [[ "$ppid" != "1" ]] && continue

        local pid comm exe cmdline uid_line
        pid="$(basename "$pid_dir")"
        # Skip PID 1 itself
        [[ "$pid" == "1" ]] && continue

        comm="$(cat "${pid_dir}/comm" 2>/dev/null || echo "?")"

        # Skip known daemons
        if echo "$comm" | grep -qiE "$known_daemons"; then
            continue
        fi

        exe="$(readlink "${pid_dir}/exe" 2>/dev/null || echo "?")"
        cmdline="$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null || echo "?")"
        uid_line="$(grep '^Uid:' "${pid_dir}/status" 2>/dev/null | awk '{print $2}')" || uid_line="?"

        # Check if it has a controlling terminal
        local tty_nr="?"
        local stat_line
        stat_line="$(cat "${pid_dir}/stat" 2>/dev/null)" || true
        if [[ -n "$stat_line" ]]; then
            local stat_rest="${stat_line##*) }"
            local stat_arr
            read -ra stat_arr <<< "$stat_rest"
            # stat_arr[4] = tty_nr (after stripping comm)
            [[ ${#stat_arr[@]} -ge 5 ]] && tty_nr="${stat_arr[4]}"
        fi

        local tty_tag=""
        [[ "$tty_nr" == "0" ]] && tty_tag=" [no terminal]"

        echo "  [!] PID ${pid} (${comm}) PPID=1 uid=${uid_line}${tty_tag}"
        echo "      exe: ${exe}"
        echo "      cmdline: ${cmdline}"
        orphan_count=$((orphan_count + 1))
    done
    [[ $orphan_count -eq 0 ]] && echo "  (none — all PID-1 children are known system services)"
    echo ""

    # ── 2. Suspicious parent-child chains ──────────────────────────
    # Flag process chains that match known attack patterns:
    #   - node -> sh -> python (supply chain dropper pattern)
    #   - npm -> sh -> curl/wget (download-and-execute)
    #   - any pkg manager -> interpreter (postinstall payload)
    echo "--- Suspicious parent-child chains ---"
    local chain_count=0
    local pkg_managers="^(npm|npx|yarn|pnpm|pip|pip3|cargo|gem|composer|go|maven|gradle|poetry|pdm|uv)$"
    local interpreters="^(python|python3|perl|ruby|node|lua|php)$"
    local downloaders="^(curl|wget|fetch|aria2c)$"
    local shells="^(sh|bash|dash|zsh|fish|csh|tcsh)$"

    for pid_dir in "${proc}"/[0-9]*; do
        [[ -f "${pid_dir}/cmdline" ]] || continue
        local cmdline_check
        cmdline_check="$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null)" || continue
        [[ -z "${cmdline_check// /}" ]] && continue

        local comm
        comm="$(cat "${pid_dir}/comm" 2>/dev/null)" || continue

        # Only look at interpreters and downloaders as leaf processes
        local is_interesting=false
        if echo "$comm" | grep -qiE "$interpreters"; then
            is_interesting=true
        elif echo "$comm" | grep -qiE "$downloaders"; then
            is_interesting=true
        fi
        $is_interesting || continue

        # Walk up the process tree (max 5 levels)
        local chain="$comm"
        local current_pid
        current_pid="$(basename "$pid_dir")"
        local suspicious=false
        local has_pkg_manager=false
        local has_shell=false
        local depth=0

        local walk_pid="$current_pid"
        while [[ $depth -lt 5 ]]; do
            local parent_pid
            parent_pid="$(grep '^PPid:' "${proc}/${walk_pid}/status" 2>/dev/null | awk '{print $2}')" || break
            [[ -z "$parent_pid" ]] && break
            [[ "$parent_pid" == "0" ]] || [[ "$parent_pid" == "1" ]] && break

            local parent_comm
            parent_comm="$(cat "${proc}/${parent_pid}/comm" 2>/dev/null)" || break

            chain="${parent_comm} -> ${chain}"

            if echo "$parent_comm" | grep -qiE "$pkg_managers"; then
                has_pkg_manager=true
            fi
            if echo "$parent_comm" | grep -qiE "$shells"; then
                has_shell=true
            fi

            walk_pid="$parent_pid"
            depth=$((depth + 1))
        done

        # Flag: package manager spawned shell spawned interpreter/downloader
        if $has_pkg_manager && $has_shell; then
            suspicious=true
        fi
        # Flag: package manager directly spawned a downloader
        if $has_pkg_manager && echo "$comm" | grep -qiE "$downloaders"; then
            suspicious=true
        fi

        if $suspicious; then
            local pid cmdline exe
            pid="$(basename "$pid_dir")"
            cmdline="$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null || echo "?")"
            exe="$(readlink "${pid_dir}/exe" 2>/dev/null || echo "?")"

            echo "  [!] ${chain}"
            echo "      PID ${pid}: ${cmdline}"
            echo "      exe: ${exe}"
            chain_count=$((chain_count + 1))
        fi
    done
    [[ $chain_count -eq 0 ]] && echo "  (none — no suspicious parent-child chains detected)"
    echo ""

    # ── 3. Session leader processes without a terminal ─────────────
    # A session leader (SID == PID) with no controlling terminal that
    # is NOT a known daemon is suspicious. This is exactly what setsid
    # creates — a process that survives terminal hangup.
    echo "--- Session leaders without terminal (setsid/double-fork) ---"
    local setsid_count=0

    for pid_dir in "${proc}"/[0-9]*; do
        [[ -f "${pid_dir}/stat" ]] || continue
        [[ -f "${pid_dir}/cmdline" ]] || continue
        local cmdline_check
        cmdline_check="$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null)" || continue
        [[ -z "${cmdline_check// /}" ]] && continue

        local pid
        pid="$(basename "$pid_dir")"

        # Parse /proc/PID/stat carefully: the comm field (field 2) is
        # wrapped in parentheses and may contain spaces. Strip it first,
        # then parse the remaining numeric fields.
        local stat_line
        stat_line="$(cat "${pid_dir}/stat" 2>/dev/null)" || continue
        # Remove everything up to and including the last ')' (end of comm)
        local stat_rest="${stat_line##*) }"
        local stat_arr
        read -ra stat_arr <<< "$stat_rest"
        # stat_arr[0]=state, [1]=ppid, [2]=pgrp, [3]=session, [4]=tty_nr
        [[ ${#stat_arr[@]} -lt 5 ]] && continue

        local sid="${stat_arr[3]}"
        local tty_nr="${stat_arr[4]}"

        # Session leader = SID matches PID, no terminal
        [[ "$sid" != "$pid" ]] && continue
        [[ "$tty_nr" != "0" ]] && continue

        local ppid
        ppid="$(grep '^PPid:' "${pid_dir}/status" 2>/dev/null | awk '{print $2}')" || continue
        [[ "$ppid" == "0" ]] && continue

        local comm
        comm="$(cat "${pid_dir}/comm" 2>/dev/null || echo "?")"

        # Skip known daemons
        if echo "$comm" | grep -qiE "$known_daemons"; then
            continue
        fi

        # Skip if already reported as orphan (PPID=1) — but only if
        # not also a session leader, since session leaders are the
        # specific setsid/double-fork technique
        local ppid_tag=""
        [[ "$ppid" == "1" ]] && ppid_tag=" (orphaned)"

        local exe cmdline
        exe="$(readlink "${pid_dir}/exe" 2>/dev/null || echo "?")"
        cmdline="$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null || echo "?")"

        echo "  [!] PID ${pid} (${comm}) — session leader, no terminal, PPID=${ppid}${ppid_tag}"
        echo "      exe: ${exe}"
        echo "      cmdline: ${cmdline}"
        setsid_count=$((setsid_count + 1))
    done
    [[ $setsid_count -eq 0 ]] && echo "  (none detected)"
    echo ""

    # ── Summary ─────────────────────────────────────────────────────
    echo "--- Summary ---"
    echo "  Orphaned user processes: ${orphan_count}"
    echo "  Suspicious process chains: ${chain_count}"
    echo "  Detached session leaders: ${setsid_count}"

    echo ""
    log_ok "Process tree scan complete (orphans: ${orphan_count}, chains: ${chain_count}, setsid: ${setsid_count})"
}
