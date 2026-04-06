# Enumerate users, groups, last logins, and sudo configuration
# Usage: sread users

source "${SREAD_ROOT}/lib/redact.sh"

run() {
    require_root

    section_header "USER ACCOUNTS"

    echo "--- System users (uid < 1000) ---"
    awk -F: '$3 < 1000 {printf "  %-20s uid=%-6s shell=%s\n", $1, $3, $7}' /etc/passwd 2>/dev/null
    echo ""

    echo "--- Human users (uid >= 1000) ---"
    awk -F: '$3 >= 1000 && $3 < 65534 {printf "  %-20s uid=%-6s home=%-20s shell=%s\n", $1, $3, $6, $7}' /etc/passwd 2>/dev/null
    echo ""

    echo "--- Users with login shell ---"
    grep -v '/nologin\|/false\|/sync' /etc/passwd 2>/dev/null | awk -F: '{printf "  %-20s %s\n", $1, $7}'
    echo ""

    echo "--- Group memberships (human users) ---"
    awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd 2>/dev/null | while read -r user; do
        groups "$user" 2>/dev/null | sed 's/^/  /'
    done
    echo ""

    echo "--- Sudoers configuration ---"
    if [[ -f /etc/sudoers ]]; then
        # Show sudoers but redact any passwords/tokens
        grep -v '^\s*#\|^\s*$' /etc/sudoers 2>/dev/null | redact_output | sed 's/^/  /'
    fi
    if [[ -d /etc/sudoers.d ]]; then
        echo ""
        echo "  Drop-in files in /etc/sudoers.d/:"
        for f in /etc/sudoers.d/*; do
            [[ -f "$f" ]] || continue
            echo "  --- $(basename "$f") ---"
            grep -v '^\s*#\|^\s*$' "$f" 2>/dev/null | redact_output | sed 's/^/    /'
        done
    fi
    echo ""

    # ── Active root sessions ──────────────────────────────────────────
    # On a developer workstation, root should almost never have an
    # interactive session. Flag any active root login from utmp, any
    # root session in loginctl, and any UID-0 process holding a
    # controlling terminal that looks like an interactive shell.

    local proc="/proc"
    [[ -d "/host/proc" ]] && proc="/host/proc"
    local root=""
    [[ -d "/host/etc" ]] && root="/host"

    echo "--- Active root sessions (who) ---"
    local root_sessions=0
    local who_output
    if [[ -f "${root}/var/run/utmp" ]]; then
        who_output="$(who "${root}/var/run/utmp" 2>/dev/null)" || who_output=""
    else
        who_output="$(who 2>/dev/null)" || who_output=""
    fi
    if [[ -n "$who_output" ]]; then
        local root_lines
        root_lines="$(echo "$who_output" | awk '$1 == "root" {print}')" || root_lines=""
        if [[ -n "$root_lines" ]]; then
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                echo "  [!] ${line}"
                root_sessions=$((root_sessions + 1))
            done <<< "$root_lines"
        fi
    fi
    [[ $root_sessions -eq 0 ]] && echo "  (none -- no active root login sessions)"
    echo ""

    echo "--- Active root sessions (loginctl) ---"
    local loginctl_root=0
    if command -v loginctl &>/dev/null; then
        local sessions_output
        sessions_output="$(loginctl list-sessions --no-legend --no-pager 2>/dev/null)" || sessions_output=""
        if [[ -n "$sessions_output" ]]; then
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                local session_id user_field
                session_id="$(echo "$line" | awk '{print $1}')"
                user_field="$(echo "$line" | awk '{print $3}')"
                if [[ "$user_field" == "root" ]]; then
                    local session_detail
                    session_detail="$(loginctl show-session "$session_id" --no-pager 2>/dev/null | grep -E '^(Id|Name|Service|Type|State|TTY|Remote|RemoteHost)=' | tr '\n' ' ')" || session_detail=""
                    echo "  [!] Root session: ${session_detail}"
                    loginctl_root=$((loginctl_root + 1))
                fi
            done <<< "$sessions_output"
        fi
    else
        echo "  (loginctl not available)"
    fi
    [[ $loginctl_root -eq 0 ]] && echo "  (none -- no root sessions in loginctl)"
    echo ""

    echo "--- Active root shells (UID 0 with controlling terminal) ---"
    local root_shells=0
    local shell_names="^(bash|sh|dash|zsh|fish|csh|tcsh|ksh|mksh)$"
    local known_root_procs="^(agetty|login|sshd|su|sudo|gdm|lightdm|sddm|polkitd|systemd|init|cron|atd)$"
    for pid_dir in "${proc}"/[0-9]*; do
        [[ -f "${pid_dir}/status" ]] || continue
        [[ -f "${pid_dir}/cmdline" ]] || continue

        local cmdline_check
        cmdline_check="$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null)" || continue
        [[ -z "${cmdline_check// /}" ]] && continue

        # Check UID -- only interested in root (0)
        local uid_real
        uid_real="$(awk '/^Uid:/{print $2}' "${pid_dir}/status" 2>/dev/null)" || continue
        [[ "$uid_real" != "0" ]] && continue

        # Check for controlling terminal (tty_nr != 0 in /proc/PID/stat)
        local stat_line
        stat_line="$(cat "${pid_dir}/stat" 2>/dev/null)" || continue
        local stat_rest="${stat_line##*) }"
        local stat_arr
        read -ra stat_arr <<< "$stat_rest"
        [[ ${#stat_arr[@]} -lt 5 ]] && continue
        local tty_nr="${stat_arr[4]}"
        [[ "$tty_nr" == "0" ]] && continue

        local pid comm
        pid="$(basename "$pid_dir")"
        comm="$(cat "${pid_dir}/comm" 2>/dev/null || echo "?")"

        # Skip known root service processes that legitimately hold a TTY
        if echo "$comm" | grep -qiE "$known_root_procs"; then
            continue
        fi

        # Flag shells explicitly, report others as potentially suspicious
        local tag="process"
        if echo "$comm" | grep -qiE "$shell_names"; then
            tag="interactive shell"
        fi

        # Decode TTY number: major = tty_nr >> 8, minor = tty_nr & 0xff
        local tty_major=$(( tty_nr >> 8 ))
        local tty_minor=$(( tty_nr & 0xFF ))
        local tty_name="tty${tty_major}:${tty_minor}"
        # pts devices: major 136+
        if [[ $tty_major -ge 136 ]]; then
            tty_name="pts/$((tty_minor + (tty_major - 136) * 256))"
        elif [[ $tty_major -eq 4 ]]; then
            tty_name="tty${tty_minor}"
        fi

        echo "  [!] PID ${pid} (${comm}) -- root ${tag} on ${tty_name}"
        echo "      ${cmdline_check}"
        root_shells=$((root_shells + 1))
    done
    [[ $root_shells -eq 0 ]] && echo "  (none -- no UID 0 interactive processes with a terminal)"
    echo ""

    echo "--- Last logins ---"
    last -n 20 2>/dev/null || true
    echo ""

    echo "--- Failed login attempts ---"
    lastb -n 20 2>/dev/null || log_warn "lastb not available or requires root"
}
