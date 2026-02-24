# Detect privilege escalation vectors: sudo misconfig, file capabilities, polkit rules
# Usage: sread privesc

source "${SREAD_ROOT}/lib/redact.sh"

run() {
    require_root

    local root=""
    [[ -d "/host/etc" ]] && root="/host"

    section_header "PRIVILEGE ESCALATION VECTORS"

    # ── 10.1 Sudo NOPASSWD with GTFOBins ──────────────────────────────
    echo "--- Sudo NOPASSWD with GTFOBins ---"

    local gtfobins=(
        vim vi nano less more man find awk python python3 perl ruby node
        lua nmap docker env ftp git pip apt yum zip tar rsync bash sh
        dash zsh tee wget curl
    )
    local gtfo_pattern
    gtfo_pattern="$(IFS='|'; echo "${gtfobins[*]}")"

    local sudoers_files=()
    [[ -f "${root}/etc/sudoers" ]] && sudoers_files+=("${root}/etc/sudoers")
    if [[ -d "${root}/etc/sudoers.d" ]]; then
        while IFS= read -r f; do
            sudoers_files+=("$f")
        done < <(find "${root}/etc/sudoers.d" -type f 2>/dev/null || true)
    fi

    local nopasswd_gtfo=0
    local nopasswd_all=0

    if [[ ${#sudoers_files[@]} -eq 0 ]]; then
        echo "  (no sudoers files found)"
    else
        for sf in "${sudoers_files[@]}"; do
            local nopasswd_lines
            nopasswd_lines="$(grep -i 'NOPASSWD' "$sf" 2>/dev/null || true)"
            [[ -z "$nopasswd_lines" ]] && continue

            while IFS= read -r line; do
                # Skip comments
                [[ "$line" =~ ^[[:space:]]*# ]] && continue

                if echo "$line" | grep -qiE 'NOPASSWD[[:space:]]*:[[:space:]]*ALL'; then
                    echo "  [!] CRITICAL: NOPASSWD ALL in ${sf}:"
                    echo "$line" | redact_output | sed 's/^/      /'
                    nopasswd_all=$((nopasswd_all + 1))
                elif echo "$line" | grep -qiE "(^|/)($gtfo_pattern)(\s|$|,)"; then
                    echo "  [!] GTFOBins candidate with NOPASSWD in ${sf}:"
                    echo "$line" | redact_output | sed 's/^/      /'
                    nopasswd_gtfo=$((nopasswd_gtfo + 1))
                fi
            done <<< "$nopasswd_lines"
        done
        [[ $nopasswd_all -eq 0 ]] && [[ $nopasswd_gtfo -eq 0 ]] && echo "  (none detected)"
    fi
    echo ""

    # ── 10.2 Sudo env_keep preserving injection vars ──────────────────
    echo "--- Sudo env_keep injection variables ---"

    local dangerous_vars="LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|PERL5LIB|RUBYLIB|NODE_PATH|CLASSPATH"
    local env_findings=0

    for sf in "${sudoers_files[@]}"; do
        # Check for dangerous env_keep entries
        local env_keep_lines
        env_keep_lines="$(grep -iE 'env_keep' "$sf" 2>/dev/null || true)"
        if [[ -n "$env_keep_lines" ]]; then
            while IFS= read -r line; do
                [[ "$line" =~ ^[[:space:]]*# ]] && continue
                if echo "$line" | grep -qiE "$dangerous_vars"; then
                    echo "  [!] Dangerous env_keep in ${sf}:"
                    echo "$line" | redact_output | sed 's/^/      /'
                    env_findings=$((env_findings + 1))
                fi
            done <<< "$env_keep_lines"
        fi

        # Check for env_reset disabled
        local no_env_reset
        no_env_reset="$(grep -iE 'Defaults.*!env_reset' "$sf" 2>/dev/null || true)"
        if [[ -n "$no_env_reset" ]]; then
            while IFS= read -r line; do
                [[ "$line" =~ ^[[:space:]]*# ]] && continue
                echo "  [!] env_reset DISABLED in ${sf}:"
                echo "$line" | redact_output | sed 's/^/      /'
                env_findings=$((env_findings + 1))
            done <<< "$no_env_reset"
        fi
    done
    [[ $env_findings -eq 0 ]] && echo "  (none detected)"
    echo ""

    # ── 10.3 File capabilities on binaries ─────────────────────────────
    echo "--- File capabilities on binaries ---"

    local dangerous_caps="cap_setuid|cap_setgid|cap_dac_override|cap_dac_read_search|cap_sys_admin|cap_sys_ptrace|cap_sys_module|cap_net_raw"

    # Known-good allowlist: binary|capability
    local -A allowlist=(
        ["/usr/bin/ping|cap_net_raw"]="1"
        ["/usr/bin/mtr-packet|cap_net_raw"]="1"
    )

    local cap_findings=0
    local cap_dirs=("${root}/usr/bin" "${root}/usr/sbin" "${root}/usr/local/bin" "${root}/opt")

    if command -v getcap &>/dev/null; then
        for cap_dir in "${cap_dirs[@]}"; do
            [[ -d "$cap_dir" ]] || continue
            local cap_output
            cap_output="$(getcap -r "$cap_dir" 2>/dev/null || true)"
            [[ -z "$cap_output" ]] && continue

            while IFS= read -r line; do
                [[ -z "$line" ]] && continue

                # Extract binary path and capabilities
                local bin_path cap_str
                bin_path="${line%% *}"
                cap_str="${line#* }"

                # Strip the root prefix for allowlist lookup
                local lookup_path="$bin_path"
                [[ -n "$root" ]] && lookup_path="${bin_path#${root}}"

                # Check each dangerous capability
                local flagged=false
                for cap in cap_setuid cap_setgid cap_dac_override cap_dac_read_search cap_sys_admin cap_sys_ptrace cap_sys_module cap_net_raw; do
                    if echo "$cap_str" | grep -qi "$cap"; then
                        local key="${lookup_path}|${cap}"
                        if [[ -z "${allowlist[$key]:-}" ]]; then
                            flagged=true
                            break
                        fi
                    fi
                done

                if $flagged; then
                    echo "  [!] ${line}"
                    cap_findings=$((cap_findings + 1))
                fi
            done <<< "$cap_output"
        done
        [[ $cap_findings -eq 0 ]] && echo "  (none detected)"
    else
        echo "  (getcap not available)"
    fi
    echo ""

    # ── 10.4 Polkit rule manipulation ──────────────────────────────────
    echo "--- Polkit rules ---"

    local polkit_dir="${root}/etc/polkit-1/rules.d"
    local polkit_legacy="${root}/etc/polkit-1/localauthority"
    local polkit_findings=0

    if [[ -d "$polkit_dir" ]]; then
        local rule_files
        rule_files="$(find "$polkit_dir" -name '*.rules' -type f 2>/dev/null || true)"

        if [[ -z "$rule_files" ]]; then
            echo "  (no rules files found)"
        else
            while IFS= read -r rf; do
                local unpackaged=false
                # Check if the file belongs to an installed package
                if command -v dpkg &>/dev/null; then
                    if ! dpkg -S "$rf" &>/dev/null; then
                        unpackaged=true
                    fi
                elif command -v rpm &>/dev/null; then
                    if ! rpm -qf "$rf" &>/dev/null; then
                        unpackaged=true
                    fi
                fi

                # Check for overly permissive rules
                local permissive
                permissive="$(grep -nE 'Result\.YES|Result\.AUTH_SELF' "$rf" 2>/dev/null || true)"

                if $unpackaged; then
                    echo "  [!] Unpackaged rule: ${rf}"
                    polkit_findings=$((polkit_findings + 1))
                    if [[ -n "$permissive" ]]; then
                        echo "$permissive" | sed 's/^/      /'
                    fi
                elif [[ -n "$permissive" ]]; then
                    echo "  [!] Permissive rule in ${rf}:"
                    echo "$permissive" | sed 's/^/      /'
                    polkit_findings=$((polkit_findings + 1))
                fi
            done <<< "$rule_files"
        fi
    else
        echo "  (polkit rules.d not found)"
    fi

    # Legacy polkit directory
    if [[ -d "$polkit_legacy" ]]; then
        echo ""
        echo "--- Legacy polkit localauthority ---"
        local legacy_files
        legacy_files="$(find "$polkit_legacy" -type f 2>/dev/null || true)"
        if [[ -n "$legacy_files" ]]; then
            while IFS= read -r lf; do
                local unpackaged=false
                if command -v dpkg &>/dev/null; then
                    if ! dpkg -S "$lf" &>/dev/null; then
                        unpackaged=true
                    fi
                elif command -v rpm &>/dev/null; then
                    if ! rpm -qf "$lf" &>/dev/null; then
                        unpackaged=true
                    fi
                fi

                if $unpackaged; then
                    echo "  [!] Unpackaged legacy rule: ${lf}"
                    polkit_findings=$((polkit_findings + 1))
                fi
            done <<< "$legacy_files"
        else
            echo "  (no legacy rules found)"
        fi
    fi

    [[ $polkit_findings -eq 0 ]] && echo "  (none detected)" 2>/dev/null || true
    echo ""

    log_ok "Privilege escalation scan complete (nopasswd_all: ${nopasswd_all}, nopasswd_gtfo: ${nopasswd_gtfo}, env_keep: ${env_findings}, capabilities: ${cap_findings}, polkit: ${polkit_findings})"
}
