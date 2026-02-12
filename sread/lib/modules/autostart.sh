# Enumerate autostart persistence mechanisms (XDG, systemd user units, init.d)
# Usage: sread autostart

run() {
    require_root

    local root=""
    [[ -d "/host/etc" ]] && root="/host"

    section_header "AUTOSTART & PERSISTENCE"

    # ── XDG autostart (system-wide) ──────────────────────────────────
    echo "--- System XDG autostart (/etc/xdg/autostart/) ---"
    local sys_autostart="${root}/etc/xdg/autostart"
    if [[ -d "$sys_autostart" ]]; then
        local count
        count="$(find "$sys_autostart" -name '*.desktop' 2>/dev/null | wc -l | tr -d ' ')"
        echo "  Entries: ${count}"
        for f in "${sys_autostart}"/*.desktop; do
            [[ -f "$f" ]] || continue
            local name exec hidden
            name="$(grep '^Name=' "$f" 2>/dev/null | head -1 | cut -d= -f2- || true)"
            exec="$(grep '^Exec=' "$f" 2>/dev/null | head -1 | cut -d= -f2- || true)"
            hidden="$(grep '^Hidden=' "$f" 2>/dev/null | head -1 | cut -d= -f2- || true)"
            [[ "$hidden" == "true" ]] && continue
            echo "  $(basename "$f"): ${name:-?} -> ${exec:-?}"
        done
    else
        echo "  (directory not found)"
    fi
    echo ""

    # ── XDG autostart (per-user) ─────────────────────────────────────
    echo "--- Per-user XDG autostart (~/.config/autostart/) ---"
    local homes_dir="${root}/home"
    local user_found=0
    if [[ -d "$homes_dir" ]]; then
        for home in "${homes_dir}"/*/; do
            [[ -d "$home" ]] || continue
            local user_autostart="${home}.config/autostart"
            [[ -d "$user_autostart" ]] || continue
            local user
            user="$(basename "$home")"
            local entries
            entries="$(find "$user_autostart" -name '*.desktop' 2>/dev/null)"
            if [[ -n "$entries" ]]; then
                echo "  User: ${user}"
                echo "$entries" | while read -r f; do
                    local name exec
                    name="$(grep '^Name=' "$f" 2>/dev/null | head -1 | cut -d= -f2- || true)"
                    exec="$(grep '^Exec=' "$f" 2>/dev/null | head -1 | cut -d= -f2- || true)"
                    echo "    $(basename "$f"): ${name:-?} -> ${exec:-?}"
                done
                user_found=$((user_found + 1))
            fi
        done
    fi
    # Also check root
    local root_autostart="${root}/root/.config/autostart"
    if [[ -d "$root_autostart" ]]; then
        local entries
        entries="$(find "$root_autostart" -name '*.desktop' 2>/dev/null)"
        if [[ -n "$entries" ]]; then
            echo "  User: root"
            echo "$entries" | while read -r f; do
                local name exec
                name="$(grep '^Name=' "$f" 2>/dev/null | head -1 | cut -d= -f2-)"
                exec="$(grep '^Exec=' "$f" 2>/dev/null | head -1 | cut -d= -f2-)"
                echo "    $(basename "$f"): ${name:-?} -> ${exec:-?}"
            done
            user_found=$((user_found + 1))
        fi
    fi
    [[ $user_found -eq 0 ]] && echo "  (no user autostart entries found)"
    echo ""

    # ── Systemd user services ────────────────────────────────────────
    echo "--- Systemd user services ---"
    if command -v systemctl &>/dev/null; then
        warn_if_container
        echo "  Active user services:"
        systemctl --user list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | sed 's/^/    /' || echo "    (unable to query — may need user session)"
        echo ""
        echo "  Enabled user services:"
        systemctl --user list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null | sed 's/^/    /' || echo "    (unable to query)"
    else
        # Fallback: scan unit file directories
        echo "  (systemctl not available — scanning unit file paths)"
        for home in "${homes_dir}"/*/; do
            [[ -d "$home" ]] || continue
            local user_units="${home}.config/systemd/user"
            [[ -d "$user_units" ]] || continue
            local user
            user="$(basename "$home")"
            echo "  User: ${user}"
            find "$user_units" -name '*.service' 2>/dev/null | while read -r f; do
                echo "    $(basename "$f")"
                grep -E '^(ExecStart|Description)=' "$f" 2>/dev/null | sed 's/^/      /' || true
            done
        done
    fi
    echo ""

    # ── rc.local and init.d ──────────────────────────────────────────
    echo "--- rc.local ---"
    local rc_local="${root}/etc/rc.local"
    if [[ -f "$rc_local" ]]; then
        if [[ -x "$rc_local" ]]; then
            echo "  [!] /etc/rc.local exists and is executable:"
            grep -v '^\s*#\|^\s*$' "$rc_local" 2>/dev/null | sed 's/^/      /' || true
        else
            echo "  /etc/rc.local exists but is NOT executable (inactive)"
        fi
    else
        echo "  (not present)"
    fi
    echo ""

    echo "--- Non-standard init.d scripts ---"
    local initd="${root}/etc/init.d"
    if [[ -d "$initd" ]]; then
        # Check if running inside container — use host dpkg info if available
        local dpkg_info="${root}/var/lib/dpkg/info"
        if [[ -d "$dpkg_info" ]]; then
            # Cross-reference init.d scripts against host package .list files
            for f in "${initd}"/*; do
                [[ -f "$f" ]] || continue
                local base
                base="$(basename "$f")"
                [[ "$base" == "README" ]] && continue
                # Strip /host prefix for matching against .list file contents
                local match_path="/etc/init.d/${base}"
                if ! grep -rql "^${match_path}$" "${dpkg_info}/" 2>/dev/null; then
                    echo "  [!] ${base} — not owned by any package"
                fi
            done
        elif command -v dpkg &>/dev/null; then
            for f in "${initd}"/*; do
                [[ -f "$f" ]] || continue
                local base
                base="$(basename "$f")"
                [[ "$base" == "README" ]] && continue
                if ! dpkg -S "/etc/init.d/${base}" &>/dev/null 2>&1; then
                    echo "  [!] ${base} — not owned by any package"
                fi
            done
        else
            ls -la "$initd" 2>/dev/null | sed 's/^/  /'
        fi
    else
        echo "  (directory not found)"
    fi

    echo ""
    log_ok "Autostart scan complete"
}
