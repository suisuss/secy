# Detect credential exposure in process environments, command lines, and swap/core dumps
# Usage: sread credexpose

source "${SREAD_ROOT}/lib/redact.sh"

run() {
    require_root

    local proc="/proc"
    [[ -d "/host/proc" ]] && proc="/host/proc"
    local root=""
    [[ -d "/host/etc" ]] && root="/host"

    section_header "CREDENTIAL EXPOSURE SCAN"

    # ── 9.1 Credentials in process environment (/proc/[pid]/environ) ──
    echo "--- Credentials in process environments ---"
    local env_cred_procs=0
    local env_cred_vars=0
    local cred_env_pattern='^(PASSWORD|SECRET|TOKEN|API_KEY|CREDENTIAL|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|STRIPE_SECRET_KEY)='
    local cred_env_pattern_mid='_(PASSWORD|SECRET|TOKEN|API_KEY|CREDENTIAL)='
    local db_url_pattern='^DATABASE_URL=.*://[^:]+:[^@]+@'

    for pid_dir in "${proc}"/[0-9]*; do
        [[ -f "${pid_dir}/environ" ]] || continue
        local pid
        pid="$(basename "$pid_dir")"
        local environ_lines
        environ_lines="$({ tr '\0' '\n' < "${pid_dir}/environ"; } 2>/dev/null || true)"
        [[ -z "$environ_lines" ]] && continue

        local matched_vars=""
        local match_count=0

        while IFS= read -r envline; do
            [[ -z "$envline" ]] && continue
            local varname="${envline%%=*}"

            if echo "$envline" | grep -qiE "$cred_env_pattern" || \
               echo "$envline" | grep -qiE "$cred_env_pattern_mid" || \
               echo "$envline" | grep -qiE "$db_url_pattern"; then
                matched_vars="${matched_vars}${matched_vars:+, }${varname}"
                match_count=$((match_count + 1))
            fi
        done <<< "$environ_lines"

        if [[ $match_count -gt 0 ]]; then
            local comm
            comm="$(cat "${pid_dir}/comm" 2>/dev/null || echo "?")"
            echo "  [!] PID ${pid} (${comm}): ${match_count} credential variable(s) in environ" | redact_output
            echo "      Variables: ${matched_vars}" | redact_output
            env_cred_procs=$((env_cred_procs + 1))
            env_cred_vars=$((env_cred_vars + match_count))
        fi
    done
    [[ $env_cred_procs -eq 0 ]] && echo "  (none detected)"
    echo ""

    # ── 9.2 Credentials in process command line (/proc/[pid]/cmdline) ──
    # Note: cmdlines are world-readable via /proc and ps(1), making this
    # strictly worse than environ exposure — any unprivileged user can see them.
    echo "--- Credentials in process command lines ---"
    local cmd_cred_procs=0

    for pid_dir in "${proc}"/[0-9]*; do
        [[ -f "${pid_dir}/cmdline" ]] || continue
        local pid
        pid="$(basename "$pid_dir")"
        local cmdline
        cmdline="$({ tr '\0' ' ' < "${pid_dir}/cmdline"; } 2>/dev/null || true)"
        [[ -z "$cmdline" ]] && continue

        local finding=""

        # --password=VALUE, --token=VALUE, --secret=VALUE, --api-key=VALUE
        if echo "$cmdline" | grep -qiE '\-\-password=|\-\-token=|\-\-secret=|\-\-api-key='; then
            finding="credential in long-form argument (--password=, --token=, etc.)"
        # -p VALUE where VALUE is not a flag (common mysql/postgres pattern)
        elif echo "$cmdline" | grep -qE '\s-p\s+[^-]'; then
            # Only flag if this looks like a database/auth tool
            local comm
            comm="$(cat "${pid_dir}/comm" 2>/dev/null || echo "?")"
            case "$comm" in
                mysql*|psql|mongo*|redis-cli|ldap*|curl|wget|sshpass)
                    finding="-p argument (likely inline password for ${comm})"
                    ;;
            esac
        fi

        # -u user:pass pattern (curl-style)
        if echo "$cmdline" | grep -qE '\s-u\s+[^[:space:]]+:[^[:space:]]+'; then
            finding="${finding:+${finding}; }user:password in -u argument"
        fi

        if [[ -n "$finding" ]]; then
            local comm
            comm="$(cat "${pid_dir}/comm" 2>/dev/null || echo "?")"
            echo "  [!] PID ${pid} (${comm}): ${finding}" | redact_output
            echo "      cmdline: ${cmdline}" | redact_output
            cmd_cred_procs=$((cmd_cred_procs + 1))
        fi
    done
    [[ $cmd_cred_procs -eq 0 ]] && echo "  (none detected)"
    echo ""

    # ── 9.3 Swap and core dump credential leakage ─────────────────────
    echo "--- Core dump configuration ---"
    local core_issues=0

    # suid_dumpable: 0=disabled, 1=enabled (unsafe), 2=suidsafe
    local suid_dumpable
    suid_dumpable="$(cat "${proc}/sys/fs/suid_dumpable" 2>/dev/null || echo "?")"
    if [[ "$suid_dumpable" == "1" ]]; then
        echo "  [!] suid_dumpable = 1 (ENABLED) — setuid processes can produce core dumps"
        echo "      Core dumps from privileged processes may contain credentials"
        echo "      Recommended: set to 0 (disabled) or 2 (suidsafe)"
        core_issues=$((core_issues + 1))
    else
        echo "  suid_dumpable = ${suid_dumpable} (OK)"
    fi

    # core_pattern
    local core_pattern
    core_pattern="$(cat "${proc}/sys/kernel/core_pattern" 2>/dev/null || echo "?")"
    echo "  core_pattern = ${core_pattern}"
    if [[ "$core_pattern" != "|"* ]]; then
        # File-based pattern — check if target directory is world-readable
        local core_dir
        core_dir="$(dirname "${core_pattern}" 2>/dev/null || echo ".")"
        if [[ "$core_dir" == "." ]]; then
            core_dir="(process cwd)"
        fi
        local core_dir_resolved="${root}${core_dir}"
        if [[ -d "$core_dir_resolved" ]]; then
            local dir_perms
            dir_perms="$(stat -c '%a' "$core_dir_resolved" 2>/dev/null || echo "?")"
            local world_bits="${dir_perms: -1}"
            if [[ "$world_bits" =~ [4567] ]]; then
                echo "  [!] Core dump directory ${core_dir} is world-readable (perms: ${dir_perms})"
                echo "      Core dumps may contain credentials from process memory"
                core_issues=$((core_issues + 1))
            fi
        fi
    fi
    echo ""

    # Core limits in limits.conf
    echo "--- Core dump limits ---"
    local limits_file="${root}/etc/security/limits.conf"
    if [[ -f "$limits_file" ]]; then
        local core_limits
        core_limits="$(grep -v '^#' "$limits_file" 2>/dev/null | grep -i 'core' || true)"
        if [[ -n "$core_limits" ]]; then
            echo "  Configured core limits:"
            echo "$core_limits" | sed 's/^/      /'
        else
            echo "  (no explicit core limits in limits.conf — system defaults apply)"
        fi
    else
        echo "  (limits.conf not found)"
    fi
    echo ""

    # Existing core dumps
    echo "--- Existing core dumps ---"
    local core_count=0
    local core_dirs=("${root}/var/crash" "${root}/var/lib/systemd/coredump")
    for cdir in "${core_dirs[@]}"; do
        if [[ -d "$cdir" ]]; then
            local cores
            cores="$(find "$cdir" -type f 2>/dev/null || true)"
            if [[ -n "$cores" ]]; then
                local count
                count="$(echo "$cores" | wc -l)"
                echo "  [!] ${count} core dump(s) found in ${cdir#${root}}:"
                echo "$cores" | head -5 | sed "s|^${root}||" | sed 's/^/      /'
                [[ $count -gt 5 ]] && echo "      ... and $((count - 5)) more"
                core_count=$((core_count + count))
            fi
        fi
    done
    # Also check for core.* files in common locations
    local stray_cores
    stray_cores="$(find "${root}/tmp" "${root}/var/tmp" -maxdepth 2 -name 'core' -o -name 'core.*' 2>/dev/null | head -10 || true)"
    if [[ -n "$stray_cores" ]]; then
        local stray_count
        stray_count="$(echo "$stray_cores" | wc -l)"
        echo "  [!] ${stray_count} stray core dump(s) in tmp directories:"
        echo "$stray_cores" | sed "s|^${root}||" | sed 's/^/      /'
        core_count=$((core_count + stray_count))
    fi
    [[ $core_count -eq 0 ]] && echo "  (none found)"
    echo ""

    # Swap encryption check
    echo "--- Swap encryption ---"
    local swap_issues=0
    local swaps_file="${proc}/swaps"
    if [[ -f "$swaps_file" ]]; then
        local swap_devs
        swap_devs="$(tail -n +2 "$swaps_file" 2>/dev/null | awk '{print $1}' || true)"
        if [[ -z "$swap_devs" ]]; then
            echo "  (no swap active — no risk of credential leakage to swap)"
        else
            while IFS= read -r swap_dev; do
                [[ -z "$swap_dev" ]] && continue
                local dev_basename
                dev_basename="$(basename "$swap_dev")"
                local encrypted=false

                # Check if the swap device is a dm-crypt / LUKS device
                if [[ "$dev_basename" == dm-* ]]; then
                    # Device mapper — likely encrypted
                    local dm_name
                    dm_name="$(cat "/sys/block/${dev_basename}/dm/name" 2>/dev/null || echo "$dev_basename")"
                    if [[ -d "/host/sys/block/${dev_basename}/dm" ]]; then
                        dm_name="$(cat "/host/sys/block/${dev_basename}/dm/name" 2>/dev/null || echo "$dev_basename")"
                    fi
                    echo "  ${swap_dev} -> dm:${dm_name} (likely encrypted)"
                    encrypted=true
                elif [[ -e "${root}/etc/crypttab" ]]; then
                    # Check if swap device is referenced in crypttab
                    if grep -q "$dev_basename" "${root}/etc/crypttab" 2>/dev/null; then
                        echo "  ${swap_dev} (referenced in crypttab — likely encrypted)"
                        encrypted=true
                    fi
                fi

                # Check for zram (compressed, in-memory — no disk persistence)
                if [[ "$dev_basename" == zram* ]]; then
                    echo "  ${swap_dev} (zram — in-memory, no disk persistence)"
                    encrypted=true
                fi

                if ! $encrypted; then
                    echo "  [!] ${swap_dev} — NOT encrypted"
                    echo "      Credentials in process memory may leak to unencrypted swap"
                    swap_issues=$((swap_issues + 1))
                fi
            done <<< "$swap_devs"
        fi
    else
        echo "  (cannot read ${swaps_file})"
    fi
    echo ""

    echo ""
    log_ok "Credential exposure scan complete (env_procs: ${env_cred_procs}, env_vars: ${env_cred_vars}, cmdline_procs: ${cmd_cred_procs}, core_issues: ${core_issues}, core_dumps: ${core_count}, unencrypted_swap: ${swap_issues})"
}
