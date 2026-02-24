# Detect X11/display server threats (keylogging, Xauthority exposure, clipjacking)
# Usage: sread display

run() {
    require_root

    local root=""
    [[ -d "/host/etc" ]] && root="/host"
    local proc="/proc"
    [[ -d "/host/proc" ]] && proc="/host/proc"

    section_header "DISPLAY SERVER THREAT SCAN"

    # ── Detect session type ────────────────────────────────────────────
    echo "--- Session type ---"
    local session_type="unknown"
    local x11_running=false
    local wayland_running=false

    if [[ -d "${root}/tmp/.X11-unix" ]]; then
        local x_sockets
        x_sockets="$(ls "${root}/tmp/.X11-unix/" 2>/dev/null | wc -l | tr -d ' ')"
        if [[ "$x_sockets" -gt 0 ]]; then
            x11_running=true
            echo "  X11 sockets found: ${x_sockets} in /tmp/.X11-unix/"
        fi
    fi

    # Check for Wayland compositors
    for pid_dir in "${proc}"/[0-9]*; do
        [[ -f "${pid_dir}/cmdline" ]] || continue
        local cmdline
        cmdline="$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null)" || continue
        [[ -z "$cmdline" ]] && continue
        if echo "$cmdline" | grep -qiE "sway|weston|mutter.*wayland|gnome-shell.*wayland|kwin_wayland|Hyprland|river|cage|labwc"; then
            wayland_running=true
            break
        fi
    done

    if $x11_running && $wayland_running; then
        session_type="X11 + Wayland (mixed)"
    elif $x11_running; then
        session_type="X11"
    elif $wayland_running; then
        session_type="Wayland"
    fi
    echo "  Session type: ${session_type}"

    # Check for XWayland (X11 compatibility layer inside Wayland)
    for pid_dir in "${proc}"/[0-9]*; do
        [[ -f "${pid_dir}/comm" ]] || continue
        local comm
        comm="$(cat "${pid_dir}/comm" 2>/dev/null)" || continue
        if [[ "$comm" == "Xwayland" ]]; then
            echo "  XWayland is running (X11 apps can run under Wayland)"
            break
        fi
    done
    echo ""

    # ── 11.1 X11 keylogging via DISPLAY access ────────────────────────
    echo "--- 11.1 X11 keylogger tools in process list ---"
    local keylog_patterns="xinput|xspy|xdotool|xev|logkeys"
    local keylog_found=0
    for pid_dir in "${proc}"/[0-9]*; do
        [[ -f "${pid_dir}/cmdline" ]] || continue
        local cmdline
        cmdline="$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null)" || continue
        [[ -z "$cmdline" ]] && continue

        if echo "$cmdline" | grep -qiE "$keylog_patterns"; then
            local pid comm
            pid="$(basename "$pid_dir")"
            comm="$(cat "${pid_dir}/comm" 2>/dev/null || echo "?")"
            local uid_line
            uid_line="$(grep '^Uid:' "${pid_dir}/status" 2>/dev/null | awk '{print $2}')" || uid_line="?"
            echo "  [!] PID ${pid} (${comm}) uid=${uid_line}"
            echo "      ${cmdline}"
            keylog_found=$((keylog_found + 1))
        fi
    done
    [[ $keylog_found -eq 0 ]] && echo "  (none detected)"
    echo ""

    echo "--- 11.1 DISPLAY env in non-GUI processes ---"
    local gui_procs="Xorg|Xwayland|gnome-shell|plasmashell|kwin|mutter|sway|weston|Hyprland|river|cage|labwc|gdm|sddm|lightdm|xdm|startx|xinit|dbus-daemon|dbus-broker|pipewire|pulseaudio|wireplumber|gsd-|gnome-session|xfce4-session|mate-session|cinnamon-session|plasma_session|firefox|chromium|chrome|brave|code|electron|nautilus|thunar|dolphin|nemo|gedit|kate|evince|eog|totem|vlc|mpv|gimp|inkscape|libreoffice|thunderbird"
    local display_found=0
    for pid_dir in "${proc}"/[0-9]*; do
        [[ -f "${pid_dir}/cmdline" ]] || continue
        local cmdline
        cmdline="$(cat "${pid_dir}/cmdline" 2>/dev/null)" || continue
        [[ -z "$cmdline" ]] && continue

        local comm
        comm="$(cat "${pid_dir}/comm" 2>/dev/null)" || continue

        # Skip known GUI processes
        if echo "$comm" | grep -qiE "$gui_procs"; then
            continue
        fi

        # Check environ for DISPLAY=
        local env_data
        env_data="$(tr '\0' '\n' < "${pid_dir}/environ" 2>/dev/null)" || continue
        local display_val
        display_val="$(echo "$env_data" | grep '^DISPLAY=' || true)"
        [[ -z "$display_val" ]] && continue

        # Non-GUI process with DISPLAY set — report it
        local pid
        pid="$(basename "$pid_dir")"
        local cmdline_readable
        cmdline_readable="$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null || echo "?")"
        echo "  [!] PID ${pid} (${comm}): ${display_val}"
        echo "      ${cmdline_readable}"
        display_found=$((display_found + 1))

        # Cap output to avoid flooding
        if [[ $display_found -ge 20 ]]; then
            echo "  ... (capped at 20 findings, more may exist)"
            break
        fi
    done
    [[ $display_found -eq 0 ]] && echo "  (none detected)"
    echo ""

    # ── 11.2 Xauthority permission exposure ────────────────────────────
    echo "--- 11.2 Xauthority file permissions ---"
    local xauth_found=0
    local xauth_bad=0

    # Check standard locations: /home/*/.Xauthority and /root/.Xauthority
    local search_dirs=()
    [[ -d "${root}/home" ]] && search_dirs+=("${root}/home")
    [[ -d "${root}/root" ]] && search_dirs+=("${root}/root")

    for search_dir in "${search_dirs[@]}"; do
        local xauth_files
        xauth_files="$(find "$search_dir" -maxdepth 2 -name '.Xauthority' -type f 2>/dev/null || true)"
        [[ -z "$xauth_files" ]] && continue

        echo "$xauth_files" | while read -r xauth_file; do
            [[ -f "$xauth_file" ]] || continue
            local perms
            perms="$(stat -c '%a' "$xauth_file" 2>/dev/null || true)"
            [[ -z "$perms" ]] && continue
            local owner
            owner="$(stat -c '%U' "$xauth_file" 2>/dev/null || echo "?")"
            local display_path="${xauth_file#${root}}"

            if [[ "$perms" != "600" ]]; then
                echo "  [!] ${display_path} (owner=${owner}, perms=${perms}) -- should be 600"
            else
                echo "  ${display_path} (owner=${owner}, perms=${perms}) -- ok"
            fi
        done
        # Count outside subshell
        local count
        count="$(echo "$xauth_files" | wc -l | tr -d ' ')"
        xauth_found=$((xauth_found + count))
        local bad_count
        bad_count="$(echo "$xauth_files" | while read -r f; do
            [[ -f "$f" ]] || continue
            local p
            p="$(stat -c '%a' "$f" 2>/dev/null || true)"
            [[ "$p" != "600" ]] && [[ -n "$p" ]] && echo "bad"
        done | wc -l | tr -d ' ')"
        xauth_bad=$((xauth_bad + bad_count))
    done
    [[ $xauth_found -eq 0 ]] && echo "  (no .Xauthority files found)"
    echo ""

    echo "--- 11.2 Non-standard XAUTHORITY paths in running processes ---"
    local xauth_env_found=0
    for pid_dir in "${proc}"/[0-9]*; do
        [[ -f "${pid_dir}/cmdline" ]] || continue
        local cmdline_check
        cmdline_check="$(cat "${pid_dir}/cmdline" 2>/dev/null)" || continue
        [[ -z "$cmdline_check" ]] && continue

        local env_data
        env_data="$(tr '\0' '\n' < "${pid_dir}/environ" 2>/dev/null)" || continue
        local xauth_val
        xauth_val="$(echo "$env_data" | grep '^XAUTHORITY=' || true)"
        [[ -z "$xauth_val" ]] && continue

        local xauth_path="${xauth_val#XAUTHORITY=}"
        # Standard paths are $HOME/.Xauthority or /run/user/*/gdm/Xauthority
        if [[ "$xauth_path" == *"/.Xauthority" ]] || [[ "$xauth_path" == /run/user/*/gdm/Xauthority ]] || [[ "$xauth_path" == /run/user/*/.mutter-Xwaylandauth.* ]]; then
            continue
        fi

        local pid comm
        pid="$(basename "$pid_dir")"
        comm="$(cat "${pid_dir}/comm" 2>/dev/null || echo "?")"
        echo "  [!] PID ${pid} (${comm}): ${xauth_val}"
        xauth_env_found=$((xauth_env_found + 1))
    done
    [[ $xauth_env_found -eq 0 ]] && echo "  (none detected)"
    echo ""

    # ── 11.3 Clipboard monitoring (clipjacking) ───────────────────────
    echo "--- 11.3 Clipboard tool processes ---"
    local clip_tools="xclip|xsel|wl-paste|wl-copy|parcellite|clipit|clipman"
    local clip_allowlist="^(klipper|gpaste|CopyQ|clipman|org\.kde\.klipper|org\.gnome\.GPaste)$"
    local clip_found=0
    local clip_suspicious=0

    for pid_dir in "${proc}"/[0-9]*; do
        [[ -f "${pid_dir}/cmdline" ]] || continue
        local cmdline
        cmdline="$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null)" || continue
        [[ -z "$cmdline" ]] && continue

        if echo "$cmdline" | grep -qiE "$clip_tools"; then
            local pid comm
            pid="$(basename "$pid_dir")"
            comm="$(cat "${pid_dir}/comm" 2>/dev/null || echo "?")"

            # Check if known-good clipboard manager running standalone
            if echo "$comm" | grep -qiE "$clip_allowlist"; then
                echo "  PID ${pid} (${comm}): known clipboard manager"
                clip_found=$((clip_found + 1))
                continue
            fi

            # Check ancestry and open fds for network tools (exfiltration signal)
            local has_network=false
            local net_tools="curl|wget|nc|ncat|socat|netcat"

            # Check parent chain for network tools
            local check_pid="$pid"
            local depth=0
            while [[ "$check_pid" -gt 1 ]] && [[ $depth -lt 5 ]]; do
                local parent_cmdline
                parent_cmdline="$(tr '\0' ' ' < "${proc}/${check_pid}/cmdline" 2>/dev/null)" || break
                if echo "$parent_cmdline" | grep -qiE "$net_tools"; then
                    has_network=true
                    break
                fi
                local ppid
                ppid="$(grep '^PPid:' "${proc}/${check_pid}/status" 2>/dev/null | awk '{print $2}')" || break
                [[ -z "$ppid" ]] && break
                check_pid="$ppid"
                depth=$((depth + 1))
            done

            # Check open fds for network sockets
            if ! $has_network && [[ -d "${pid_dir}/fd" ]]; then
                for fd in "${pid_dir}"/fd/*; do
                    local target
                    target="$(readlink "$fd" 2>/dev/null)" || continue
                    if [[ "$target" == socket:* ]]; then
                        local inode="${target#socket:[}"
                        inode="${inode%]}"
                        if grep -q "$inode" "${proc}/net/tcp" 2>/dev/null || \
                           grep -q "$inode" "${proc}/net/tcp6" 2>/dev/null; then
                            has_network=true
                            break
                        fi
                    fi
                done
            fi

            if $has_network; then
                echo "  [!] PID ${pid} (${comm}): clipboard tool WITH network access (potential exfiltration)"
                echo "      ${cmdline}"
                clip_suspicious=$((clip_suspicious + 1))
            else
                echo "  [!] PID ${pid} (${comm}): clipboard tool running"
                echo "      ${cmdline}"
            fi
            clip_found=$((clip_found + 1))
        fi
    done

    # Also check known clipboard managers by comm name
    for pid_dir in "${proc}"/[0-9]*; do
        [[ -f "${pid_dir}/comm" ]] || continue
        local comm
        comm="$(cat "${pid_dir}/comm" 2>/dev/null)" || continue
        if echo "$comm" | grep -qiE "$clip_allowlist"; then
            # Only report if not already caught above
            local cmdline
            cmdline="$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null)" || continue
            if ! echo "$cmdline" | grep -qiE "$clip_tools"; then
                local pid
                pid="$(basename "$pid_dir")"
                echo "  PID ${pid} (${comm}): known clipboard manager"
                clip_found=$((clip_found + 1))
            fi
        fi
    done
    [[ $clip_found -eq 0 ]] && echo "  (none detected)"
    echo ""

    echo "--- 11.3 Clipboard in cron and autostart ---"
    local clip_persist=0
    local clip_patterns="xclip|xsel|wl-paste|wl-copy|parcellite|clipit|clipman|clipboard"

    # Check system crontab and cron directories
    for cron_file in "${root}/etc/crontab" "${root}/etc/cron.d"/*; do
        [[ -f "$cron_file" ]] || continue
        local matches
        matches="$(grep -inE "$clip_patterns" "$cron_file" 2>/dev/null || true)"
        if [[ -n "$matches" ]]; then
            local display_path="${cron_file#${root}}"
            echo "  [!] ${display_path}:"
            echo "$matches" | sed 's/^/      /' || true
            clip_persist=$((clip_persist + 1))
        fi
    done

    # Check user crontabs
    local spool_dir="${root}/var/spool/cron/crontabs"
    if [[ -d "$spool_dir" ]]; then
        for f in "${spool_dir}"/*; do
            [[ -f "$f" ]] || continue
            local matches
            matches="$(grep -inE "$clip_patterns" "$f" 2>/dev/null || true)"
            if [[ -n "$matches" ]]; then
                local user
                user="$(basename "$f")"
                echo "  [!] User crontab (${user}):"
                echo "$matches" | sed 's/^/      /' || true
                clip_persist=$((clip_persist + 1))
            fi
        done
    fi

    # Check XDG autostart entries
    local autostart_dirs=("${root}/etc/xdg/autostart")
    local homes="${root}/home"
    if [[ -d "$homes" ]]; then
        for home in "${homes}"/*/; do
            [[ -d "${home}.config/autostart" ]] && autostart_dirs+=("${home}.config/autostart")
        done
    fi
    [[ -d "${root}/root/.config/autostart" ]] && autostart_dirs+=("${root}/root/.config/autostart")

    for adir in "${autostart_dirs[@]}"; do
        [[ -d "$adir" ]] || continue
        for desktop_file in "${adir}"/*.desktop; do
            [[ -f "$desktop_file" ]] || continue
            local exec_line
            exec_line="$(grep '^Exec=' "$desktop_file" 2>/dev/null | head -1 || true)"
            if echo "$exec_line" | grep -qiE "$clip_patterns"; then
                local display_path="${desktop_file#${root}}"
                echo "  [!] Autostart: ${display_path}"
                echo "      ${exec_line}"
                clip_persist=$((clip_persist + 1))
            fi
        done
    done

    # Check systemd user services
    if [[ -d "$homes" ]]; then
        for home in "${homes}"/*/; do
            local user_units="${home}.config/systemd/user"
            [[ -d "$user_units" ]] || continue
            for unit_file in "${user_units}"/*.service "${user_units}"/*/*.service; do
                [[ -f "$unit_file" ]] || continue
                local matches
                matches="$(grep -inE "$clip_patterns" "$unit_file" 2>/dev/null || true)"
                if [[ -n "$matches" ]]; then
                    local display_path="${unit_file#${root}}"
                    echo "  [!] Systemd user service: ${display_path}"
                    echo "$matches" | sed 's/^/      /' || true
                    clip_persist=$((clip_persist + 1))
                fi
            done
        done
    fi

    [[ $clip_persist -eq 0 ]] && echo "  (none detected)"

    echo ""
    log_ok "Display threat scan complete (keylog_tools: ${keylog_found}, display_env: ${display_found}, xauth_bad: ${xauth_bad}, xauth_nonstandard: ${xauth_env_found}, clip_procs: ${clip_found}, clip_suspicious: ${clip_suspicious}, clip_persist: ${clip_persist})"
}
