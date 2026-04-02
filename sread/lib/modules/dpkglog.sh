# Package operations log analysis — installs, removals, suspicious tools
# Usage: sread dpkglog [--days N]

source "${SREAD_ROOT}/lib/redact.sh"

run() {
    require_root

    local root=""
    [[ -d "/host/etc" ]] && root="/host"

    local days=7
    if [[ "${1:-}" == "--days" ]] && [[ -n "${2:-}" ]]; then
        if [[ "${2}" =~ ^[0-9]+$ ]]; then
            days="$2"
        else
            echo "ERROR: --days requires a numeric value" >&2
            exit 1
        fi
    fi

    local dpkg_log="${root}/var/log/dpkg.log"
    local dpkg_log_rotated="${root}/var/log/dpkg.log.1"
    local apt_history="${root}/var/log/apt/history.log"

    section_header "PACKAGE OPERATIONS LOG (last ${days} days)"

    if [[ ! -f "$dpkg_log" ]]; then
        echo "  (file not found: ${dpkg_log#"$root"})"
        return 0
    fi

    # Calculate cutoff date
    local cutoff
    cutoff="$(date -d "${days} days ago" '+%Y-%m-%d' 2>/dev/null)" || cutoff="1970-01-01"

    # Collect log lines from primary and rotated log
    local log_data
    log_data="$(cat "$dpkg_log" 2>/dev/null)"
    if [[ -f "$dpkg_log_rotated" ]]; then
        local rotated_data
        rotated_data="$(cat "$dpkg_log_rotated" 2>/dev/null)"
        log_data="${rotated_data}"$'\n'"${log_data}"
    fi

    # Filter to time window (dpkg.log format: YYYY-MM-DD HH:MM:SS ...)
    local filtered
    filtered="$(echo "$log_data" | awk -v cutoff="$cutoff" '$1 >= cutoff')" || filtered=""

    if [[ -z "$filtered" ]]; then
        echo "  (no package operations in last ${days} days)"
        return 0
    fi

    # ── Operation counts ────────────────────────────────────────────
    echo "--- Operation summary ---"
    local installs upgrades removals purges
    installs="$(echo "$filtered" | grep -c ' install ' 2>/dev/null)" || installs=0
    upgrades="$(echo "$filtered" | grep -c ' upgrade ' 2>/dev/null)" || upgrades=0
    removals="$(echo "$filtered" | grep -c ' remove ' 2>/dev/null)" || removals=0
    purges="$(echo "$filtered" | grep -c ' purge ' 2>/dev/null)" || purges=0

    echo "  Installs: ${installs}"
    echo "  Upgrades: ${upgrades}"
    echo "  Removals: ${removals}"
    echo "  Purges: ${purges}"
    echo ""

    # ── Recent installs ─────────────────────────────────────────────
    echo "--- Installed packages ---"
    local install_lines
    install_lines="$(echo "$filtered" | grep ' install ' 2>/dev/null)" || install_lines=""

    if [[ -n "$install_lines" ]]; then
        # dpkg.log install lines: YYYY-MM-DD HH:MM:SS install package:arch version
        echo "$install_lines" | awk '{print $1, $2, $3, $4, $5}' | while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local pkg
            pkg="$(echo "$line" | awk '{print $4}' | cut -d: -f1)"
            if _is_suspicious_pkg "$pkg"; then
                echo "  [!] ${line}" | redact_output
            else
                echo "  ${line}" | redact_output
            fi
        done
    else
        echo "  (none)"
    fi
    echo ""

    # ── Recent removals ─────────────────────────────────────────────
    echo "--- Removed packages ---"
    local remove_lines
    remove_lines="$(echo "$filtered" | grep -E ' (remove|purge) ' 2>/dev/null)" || remove_lines=""

    if [[ -n "$remove_lines" ]]; then
        echo "$remove_lines" | awk '{print $1, $2, $3, $4, $5}' | while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local pkg
            pkg="$(echo "$line" | awk '{print $4}' | cut -d: -f1)"
            if _is_security_pkg "$pkg"; then
                echo "  [!] ${line} (security tool removed)" | redact_output
            else
                echo "  ${line}" | redact_output
            fi
        done
    else
        echo "  (none)"
    fi
    echo ""

    # ── APT command history ─────────────────────────────────────────
    echo "--- APT command history ---"
    if [[ -f "$apt_history" ]]; then
        # Parse multi-line blocks: Start-Date, Commandline, Requested-By
        local in_window=false
        local current_date="" current_cmd="" current_user=""

        while IFS= read -r line; do
            if [[ "$line" =~ ^Start-Date:\ (.+) ]]; then
                current_date="${BASH_REMATCH[1]}"
                local entry_date="${current_date%% *}"
                if [[ "$entry_date" > "$cutoff" ]] || [[ "$entry_date" == "$cutoff" ]]; then
                    in_window=true
                else
                    in_window=false
                fi
                current_cmd=""
                current_user=""
            elif [[ "$in_window" == "true" ]]; then
                if [[ "$line" =~ ^Commandline:\ (.+) ]]; then
                    current_cmd="${BASH_REMATCH[1]}"
                elif [[ "$line" =~ ^Requested-By:\ (.+) ]]; then
                    current_user="${BASH_REMATCH[1]}"
                elif [[ "$line" =~ ^End-Date: ]]; then
                    if [[ -n "$current_cmd" ]]; then
                        local user_info=""
                        [[ -n "$current_user" ]] && user_info=" (user=${current_user})"
                        echo "  [!] ${current_date}: ${current_cmd}${user_info}" | redact_output
                    fi
                fi
            fi
        done < "$apt_history"
    else
        echo "  (file not found: ${apt_history#"$root"})"
    fi
    echo ""

    # ── Suspicious patterns ─────────────────────────────────────────
    echo "--- Suspicious patterns ---"
    local suspicious_output=""

    # Check for pentesting/network tools installed
    if [[ -n "$install_lines" ]]; then
        local installed_pkgs
        installed_pkgs="$(echo "$install_lines" | awk '{print $4}' | cut -d: -f1)"
        while IFS= read -r pkg; do
            [[ -z "$pkg" ]] && continue
            if _is_suspicious_pkg "$pkg"; then
                suspicious_output+="  [!] Suspicious tool installed: ${pkg}"$'\n'
            fi
        done <<< "$installed_pkgs"
    fi

    # Check for security tool removals
    if [[ -n "$remove_lines" ]]; then
        local removed_pkgs
        removed_pkgs="$(echo "$remove_lines" | awk '{print $4}' | cut -d: -f1)"
        while IFS= read -r pkg; do
            [[ -z "$pkg" ]] && continue
            if _is_security_pkg "$pkg"; then
                suspicious_output+="  [!] Security tool removed: ${pkg}"$'\n'
            fi
        done <<< "$removed_pkgs"
    fi

    # Check for unusual hour installs (00:00-06:00)
    if [[ -n "$install_lines" ]]; then
        local odd_hour_installs
        odd_hour_installs="$(echo "$install_lines" | awk '{split($2,t,":"); if (t[1]+0 < 6) print $0}')" || odd_hour_installs=""
        if [[ -n "$odd_hour_installs" ]]; then
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                local pkg
                pkg="$(echo "$line" | awk '{print $4}' | cut -d: -f1)"
                local time_part
                time_part="$(echo "$line" | awk '{print $2}')"
                suspicious_output+="  [!] Package installed at unusual hour (${time_part}): ${pkg}"$'\n'
            done <<< "$odd_hour_installs"
        fi
    fi

    if [[ -n "$suspicious_output" ]]; then
        printf '%s' "$suspicious_output"
    else
        echo "  (none detected)"
    fi
    echo ""

    # ── Summary ─────────────────────────────────────────────────────
    echo "--- Summary ---"
    local total=$((installs + upgrades + removals + purges))
    echo "  Total operations: ${total}"
    echo "  Installs: ${installs}"
    echo "  Upgrades: ${upgrades}"
    echo "  Removals: ${removals}"
    echo "  Purges: ${purges}"

    log_ok "Package operations log analysis complete"
}

# ── Helper: check if package is a known pentesting/network tool ─────
_is_suspicious_pkg() {
    local pkg="$1"
    case "$pkg" in
        nmap|netcat|netcat-openbsd|netcat-traditional|ncat|socat|\
        masscan|hydra|john|hashcat|wireshark|wireshark-qt|tshark|\
        tcpdump|ettercap-common|ettercap-graphical|ettercap-text-only|\
        bettercap|sqlmap|gobuster|nikto|metasploit-framework|\
        aircrack-ng|mitmproxy|sslstrip|responder|impacket-scripts|\
        bloodhound|mimikatz|crackmapexec|enum4linux|smbclient|\
        proxychains|proxychains4|tor)
            return 0 ;;
        *)
            return 1 ;;
    esac
}

# ── Helper: check if package is a security tool ────────────────────
_is_security_pkg() {
    local pkg="$1"
    case "$pkg" in
        ufw|apparmor|fail2ban|clamav|clamav-daemon|\
        aide|rkhunter|chkrootkit|tripwire|ossec-hids|\
        auditd|libpam-modules|libpam-pwquality|\
        unattended-upgrades|apt-listchanges)
            return 0 ;;
        *)
            return 1 ;;
    esac
}
