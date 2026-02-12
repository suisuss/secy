# Detect desktop-level surveillance (remote desktop, screen sharing, browser extensions)
# Usage: sread desktop

run() {
    require_root

    local root=""
    [[ -d "/host/etc" ]] && root="/host"
    local proc="/proc"
    [[ -d "/host/proc" ]] && proc="/host/proc"

    section_header "DESKTOP SURVEILLANCE SCAN"

    # ── Remote desktop / VNC processes ───────────────────────────────
    echo "--- Remote desktop & screen sharing processes ---"
    local rd_patterns="xrdp|vino|x11vnc|tigervnc|tightvnc|wayvnc|teamviewer|anydesk|rustdesk|remmina|xfreerdp|nomachine|nxserver|chrome-remote-desktop"
    local rd_found=0
    for pid_dir in "${proc}"/[0-9]*; do
        [[ -f "${pid_dir}/cmdline" ]] || continue
        local cmdline
        cmdline="$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null)" || continue
        [[ -z "$cmdline" ]] && continue

        if echo "$cmdline" | grep -qiE "$rd_patterns"; then
            local pid comm
            pid="$(basename "$pid_dir")"
            comm="$(cat "${pid_dir}/comm" 2>/dev/null || echo "?")"
            echo "  [!] PID ${pid} (${comm}): ${cmdline}"
            rd_found=$((rd_found + 1))
        fi
    done
    [[ $rd_found -eq 0 ]] && echo "  (none detected)"
    echo ""

    # ── Screen recording processes ───────────────────────────────────
    echo "--- Active screen recording ---"
    local rec_patterns="ffmpeg.*x11grab|ffmpeg.*screen|gst-launch.*screen|recordmydesktop|simplescreenrecorder|obs-ffmpeg|vokoscreen|kazam|peek"
    local rec_found=0
    for pid_dir in "${proc}"/[0-9]*; do
        [[ -f "${pid_dir}/cmdline" ]] || continue
        local cmdline
        cmdline="$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null)" || continue
        [[ -z "$cmdline" ]] && continue

        if echo "$cmdline" | grep -qiE "$rec_patterns"; then
            local pid comm
            pid="$(basename "$pid_dir")"
            comm="$(cat "${pid_dir}/comm" 2>/dev/null || echo "?")"
            echo "  [!] PID ${pid} (${comm}): ${cmdline}"
            rec_found=$((rec_found + 1))
        fi
    done
    [[ $rec_found -eq 0 ]] && echo "  (none detected)"
    echo ""

    # ── GNOME extensions ─────────────────────────────────────────────
    echo "--- GNOME shell extensions ---"
    local ext_found=false
    # System extensions
    local sys_ext_dir="${root}/usr/share/gnome-shell/extensions"
    if [[ -d "$sys_ext_dir" ]]; then
        echo "  System extensions:"
        for ext in "${sys_ext_dir}"/*/; do
            [[ -d "$ext" ]] || continue
            local name
            name="$(basename "$ext")"
            echo "    ${name}"
        done
        ext_found=true
    fi
    # Per-user extensions
    local homes="${root}/home"
    if [[ -d "$homes" ]]; then
        for home in "${homes}"/*/; do
            [[ -d "$home" ]] || continue
            local user_ext="${home}.local/share/gnome-shell/extensions"
            [[ -d "$user_ext" ]] || continue
            local user
            user="$(basename "$home")"
            echo "  User extensions (${user}):"
            for ext in "${user_ext}"/*/; do
                [[ -d "$ext" ]] || continue
                local name desc
                name="$(basename "$ext")"
                desc=""
                if [[ -f "${ext}/metadata.json" ]]; then
                    desc="$(grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' "${ext}/metadata.json" 2>/dev/null | head -1 | sed 's/.*"name"[[:space:]]*:[[:space:]]*"//' | sed 's/"$//' || true)"
                fi
                echo "    ${name}${desc:+ (${desc})}"
            done
            ext_found=true
        done
    fi
    $ext_found || echo "  (none found)"
    echo ""

    # ── GNOME remote desktop settings ────────────────────────────────
    echo "--- GNOME remote desktop config ---"
    if command -v gsettings &>/dev/null; then
        warn_if_container
        local rdp_enabled
        rdp_enabled="$(gsettings get org.gnome.desktop.remote-desktop.rdp enable 2>/dev/null || echo "unavailable")"
        local vnc_enabled
        vnc_enabled="$(gsettings get org.gnome.desktop.remote-desktop.vnc enable 2>/dev/null || echo "unavailable")"
        echo "  RDP enabled: ${rdp_enabled}"
        echo "  VNC enabled: ${vnc_enabled}"
        if [[ "$rdp_enabled" == "true" ]] || [[ "$vnc_enabled" == "true" ]]; then
            echo "  [!] Remote desktop is ENABLED"
        fi
    else
        # Fallback: check dconf database files
        local found_rd=false
        if [[ -d "$homes" ]]; then
            for home in "${homes}"/*/; do
                local dconf_db="${home}.config/dconf/user"
                [[ -f "$dconf_db" ]] || continue
                if strings "$dconf_db" 2>/dev/null | grep -qi "remote-desktop"; then
                    local user
                    user="$(basename "$home")"
                    echo "  [!] User ${user}: dconf contains remote-desktop settings"
                    found_rd=true
                fi
            done
        fi
        $found_rd || echo "  (gsettings not available, no remote-desktop dconf entries found)"
    fi
    echo ""

    # ── Browser extensions ───────────────────────────────────────────
    echo "--- Browser extensions ---"
    local homes="${root}/home"
    if [[ -d "$homes" ]]; then
        for home in "${homes}"/*/; do
            [[ -d "$home" ]] || continue
            local user
            user="$(basename "$home")"

            # Chromium-based browsers
            for browser_name in "BraveSoftware/Brave-Browser" "google-chrome" "chromium" "microsoft-edge"; do
                local ext_dir="${home}.config/${browser_name}/Default/Extensions"
                [[ -d "$ext_dir" ]] || continue
                local label="${browser_name%%/*}"
                echo "  ${user} / ${label}:"
                for ext_id_dir in "${ext_dir}"/*/; do
                    [[ -d "$ext_id_dir" ]] || continue
                    local ext_id
                    ext_id="$(basename "$ext_id_dir")"
                    # Find manifest.json in latest version subdir
                    local manifest
                    manifest="$(find "$ext_id_dir" -name "manifest.json" -maxdepth 2 2>/dev/null | head -1 || true)"
                    local ext_name="(unknown)"
                    if [[ -n "$manifest" ]] && [[ -f "$manifest" ]]; then
                        ext_name="$(_extract_extension_name "$manifest" "$ext_id_dir")"
                    fi
                    echo "    ${ext_id}: ${ext_name}"
                done
            done

            # Firefox
            local ff_dir="${home}.mozilla/firefox"
            if [[ -d "$ff_dir" ]]; then
                for profile in "${ff_dir}"/*/; do
                    [[ -d "${profile}/extensions" ]] || continue
                    echo "  ${user} / Firefox ($(basename "$profile")):"
                    ls "${profile}/extensions/" 2>/dev/null | sed 's/^/    /'
                done
            fi
        done
    else
        echo "  (no home directories found)"
    fi

    echo ""
    log_ok "Desktop surveillance scan complete (remote_desktop: ${rd_found}, screen_rec: ${rec_found})"
}

# ── Helpers ──────────────────────────────────────────────────────────

# Extract readable extension name from manifest.json (handles __MSG_ localization)
_extract_extension_name() {
    local manifest="$1"
    local ext_dir="$2"
    local raw_name
    raw_name="$(grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' "$manifest" 2>/dev/null | head -1 | sed 's/.*"name"[[:space:]]*:[[:space:]]*"//' | sed 's/"$//' || true)"

    if [[ "$raw_name" == __MSG_* ]]; then
        # Try to resolve from _locales/en/messages.json
        local msg_key="${raw_name#__MSG_}"
        msg_key="${msg_key%__}"
        local locale_file
        locale_file="$(find "$ext_dir" -path "*/_locales/en*/messages.json" 2>/dev/null | head -1 || true)"
        if [[ -n "$locale_file" ]] && [[ -f "$locale_file" ]]; then
            local resolved
            resolved="$(grep -A1 "\"${msg_key}\"" "$locale_file" 2>/dev/null | grep '"message"' | sed 's/.*"message"[[:space:]]*:[[:space:]]*"//' | sed 's/".*//' || true)"
            [[ -n "$resolved" ]] && raw_name="$resolved"
        fi
    fi

    echo "${raw_name:-unknown}"
}
