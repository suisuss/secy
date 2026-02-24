# Detect userland persistence via SSH keys, systemd drop-ins, git hooks, and D-Bus hijacking
# Usage: sread userpersist

run() {
    require_root

    local root=""
    [[ -d "/host/etc" ]] && root="/host"

    local homes_dir="${root}/home"
    local ssh_findings=0
    local dropins_found=0
    local generators_found=0
    local git_findings=0
    local dbus_findings=0

    section_header "USERLAND PERSISTENCE (1.12-1.15)"

    # ================================================================
    # 1.12 — SSH authorized_keys persistence
    # ================================================================

    echo "--- SSH authorized_keys per user ---"
    local all_homes=()
    if [[ -d "$homes_dir" ]]; then
        for h in "${homes_dir}"/*/; do
            [[ -d "$h" ]] && all_homes+=("$h")
        done
    fi
    [[ -d "${root}/root" ]] && all_homes+=("${root}/root/")

    local ak_users_checked=0
    for home in "${all_homes[@]}"; do
        local user
        user="$(basename "$home")"
        local ak="${home}.ssh/authorized_keys"
        [[ -f "$ak" ]] || continue
        ak_users_checked=$((ak_users_checked + 1))

        local key_count
        key_count="$(grep -cE '^(ssh-|ecdsa-|sk-)' "$ak" 2>/dev/null || echo 0)"

        # Check permissions
        local perms
        perms="$(stat -c '%a' "$ak" 2>/dev/null || true)"
        if [[ -n "$perms" && "$perms" != "600" && "$perms" != "644" ]]; then
            echo "  [!] ${user}: ${ak} has permissions ${perms} (expected 600 or 644)"
            ssh_findings=$((ssh_findings + 1))
        fi

        # Check for forced commands
        local forced
        forced="$(grep -c '^command="' "$ak" 2>/dev/null || echo 0)"
        if [[ "$forced" -gt 0 ]]; then
            echo "  [!] ${user}: ${forced} key(s) with forced command= option"
            grep '^command="' "$ak" 2>/dev/null | sed 's/^/      /'
            ssh_findings=$((ssh_findings + 1))
        fi

        # Check for non-standard options (from=, restrict, no-pty, etc.)
        local option_keys
        option_keys="$(grep -cE '^(from=|restrict|no-pty|no-agent-forwarding|no-port-forwarding|no-X11-forwarding|environment=|permitopen=)' "$ak" 2>/dev/null || echo 0)"
        if [[ "$option_keys" -gt 0 ]]; then
            echo "  [!] ${user}: ${option_keys} key(s) with non-standard options"
            grep -E '^(from=|restrict|no-pty|no-agent-forwarding|no-port-forwarding|no-X11-forwarding|environment=|permitopen=)' "$ak" 2>/dev/null | sed 's/^/      /'
            ssh_findings=$((ssh_findings + 1))
        fi

        echo "  ${user}: ${key_count} key(s) in authorized_keys (perms: ${perms:-?})"
    done
    [[ $ak_users_checked -eq 0 ]] && echo "  (no authorized_keys files found)"
    echo ""

    echo "--- SSHD AuthorizedKeysFile configuration ---"
    local sshd_main="${root}/etc/ssh/sshd_config"
    local ak_path_findings=0
    if [[ -f "$sshd_main" ]]; then
        local ak_setting
        ak_setting="$(grep -iE '^\s*AuthorizedKeysFile' "$sshd_main" 2>/dev/null | grep -v '^\s*#' || true)"
        if [[ -n "$ak_setting" ]]; then
            # Default is .ssh/authorized_keys — flag anything else
            if ! echo "$ak_setting" | grep -qE '\.ssh/authorized_keys'; then
                echo "  [!] Non-standard AuthorizedKeysFile in sshd_config:"
                echo "      ${ak_setting}"
                ak_path_findings=$((ak_path_findings + 1))
                ssh_findings=$((ssh_findings + 1))
            else
                echo "  sshd_config: ${ak_setting}"
            fi
        else
            echo "  (using default .ssh/authorized_keys)"
        fi
    else
        echo "  (sshd_config not found)"
    fi

    # Check sshd_config.d drop-ins
    local sshd_d="${root}/etc/ssh/sshd_config.d"
    if [[ -d "$sshd_d" ]]; then
        for conf in "${sshd_d}"/*.conf; do
            [[ -f "$conf" ]] || continue
            local ak_line
            ak_line="$(grep -iE '^\s*AuthorizedKeysFile' "$conf" 2>/dev/null | grep -v '^\s*#' || true)"
            if [[ -n "$ak_line" ]]; then
                echo "  [!] AuthorizedKeysFile override in $(basename "$conf"):"
                echo "      ${ak_line}"
                ssh_findings=$((ssh_findings + 1))
            fi
        done
    fi
    echo ""

    # ================================================================
    # 1.13 — Systemd drop-in overrides
    # ================================================================

    echo "--- Systemd drop-in overrides (/etc/systemd/system/*.d/) ---"
    local systemd_dir="${root}/etc/systemd/system"
    if [[ -d "$systemd_dir" ]]; then
        for dropin_dir in "${systemd_dir}"/*.d; do
            [[ -d "$dropin_dir" ]] || continue
            for override in "${dropin_dir}"/*.conf; do
                [[ -f "$override" ]] || continue
                local unit_name
                unit_name="$(basename "$(dirname "$override")" | sed 's/\.d$//')"
                local exec_replace
                exec_replace="$(grep -E '^\s*ExecStart\s*=' "$override" 2>/dev/null | grep -v '^\s*#' || true)"
                if [[ -n "$exec_replace" ]]; then
                    echo "  [!] ${unit_name}: ExecStart override in $(basename "$override")"
                    echo "$exec_replace" | sed 's/^/      /'
                    dropins_found=$((dropins_found + 1))
                else
                    echo "  ${unit_name}: $(basename "$override") (no ExecStart replacement)"
                fi
            done
        done
        [[ $dropins_found -eq 0 ]] && echo "  (no ExecStart overrides detected)"
    else
        echo "  (directory not found)"
    fi
    echo ""

    echo "--- Systemd generators (non-package) ---"
    local gen_dirs=(
        "${root}/etc/systemd/system-generators"
        "${root}/etc/systemd/user-generators"
    )
    local dpkg_info="${root}/var/lib/dpkg/info"
    for gen_dir in "${gen_dirs[@]}"; do
        [[ -d "$gen_dir" ]] || continue
        local dir_label="${gen_dir#"$root"}"
        for gen in "${gen_dir}"/*; do
            [[ -f "$gen" ]] || continue
            local gen_base
            gen_base="$(basename "$gen")"
            local gen_path="${dir_label}/${gen_base}"
            local owned=0
            if [[ -d "$dpkg_info" ]]; then
                if grep -rql "^${gen_path}$" "${dpkg_info}/" 2>/dev/null; then
                    owned=1
                fi
            elif command -v dpkg &>/dev/null; then
                if dpkg -S "${gen_path}" &>/dev/null 2>&1; then
                    owned=1
                fi
            fi
            if [[ $owned -eq 0 ]]; then
                echo "  [!] ${gen_path} — not owned by any package"
                generators_found=$((generators_found + 1))
            fi
        done
    done
    [[ $generators_found -eq 0 ]] && echo "  (no unpackaged generators detected)"
    echo ""

    # ================================================================
    # 1.14 — Git hook persistence
    # ================================================================

    echo "--- Global git hook paths ---"
    # System-wide gitconfig
    local sys_gitconfig="${root}/etc/gitconfig"
    if [[ -f "$sys_gitconfig" ]]; then
        local hooks_path
        hooks_path="$(grep -E '^\s*hooksPath\s*=' "$sys_gitconfig" 2>/dev/null | grep -v '^\s*#' | head -1 || true)"
        if [[ -n "$hooks_path" ]]; then
            echo "  [!] System gitconfig (/etc/gitconfig) sets core.hooksPath:"
            echo "      ${hooks_path}"
            git_findings=$((git_findings + 1))
        else
            echo "  /etc/gitconfig: no custom hooksPath"
        fi
    else
        echo "  /etc/gitconfig: not present"
    fi

    # Per-user gitconfig
    for home in "${all_homes[@]}"; do
        local user
        user="$(basename "$home")"
        local user_gitconfig="${home}.gitconfig"
        [[ -f "$user_gitconfig" ]] || continue
        local hooks_path
        hooks_path="$(grep -E '^\s*hooksPath\s*=' "$user_gitconfig" 2>/dev/null | grep -v '^\s*#' | head -1 || true)"
        if [[ -n "$hooks_path" ]]; then
            echo "  [!] ${user} (~/.gitconfig) sets core.hooksPath:"
            echo "      ${hooks_path}"
            git_findings=$((git_findings + 1))
        fi
    done
    echo ""

    echo "--- Git URL rewriting rules ---"
    local rewrite_found=0
    local gitconfigs=()
    [[ -f "$sys_gitconfig" ]] && gitconfigs+=("$sys_gitconfig")
    for home in "${all_homes[@]}"; do
        [[ -f "${home}.gitconfig" ]] && gitconfigs+=("${home}.gitconfig")
    done

    for gc in "${gitconfigs[@]}"; do
        local rewrites
        rewrites="$(grep -E '^\s*insteadOf\s*=' "$gc" 2>/dev/null | grep -v '^\s*#' || true)"
        if [[ -n "$rewrites" ]]; then
            local label="${gc#"$root"}"
            echo "  [!] ${label} contains url.*.insteadOf rules:"
            # Show the url section context
            grep -B1 -E '^\s*insteadOf\s*=' "$gc" 2>/dev/null | sed 's/^/      /'
            rewrite_found=$((rewrite_found + 1))
            git_findings=$((git_findings + 1))
        fi
    done
    [[ $rewrite_found -eq 0 ]] && echo "  (none detected)"
    echo ""

    # ================================================================
    # 1.15 — D-Bus service hijacking
    # ================================================================

    echo "--- User D-Bus session services ---"
    local user_dbus_count=0
    for home in "${all_homes[@]}"; do
        local user
        user="$(basename "$home")"
        local user_dbus="${home}.local/share/dbus-1/services"
        [[ -d "$user_dbus" ]] || continue
        for svc in "${user_dbus}"/*.service; do
            [[ -f "$svc" ]] || continue
            local svc_name
            svc_name="$(grep '^Name=' "$svc" 2>/dev/null | head -1 | cut -d= -f2- || true)"
            local svc_exec
            svc_exec="$(grep '^Exec=' "$svc" 2>/dev/null | head -1 | cut -d= -f2- || true)"
            echo "  ${user}: $(basename "$svc") -> Name=${svc_name:-?} Exec=${svc_exec:-?}"
            user_dbus_count=$((user_dbus_count + 1))

            # Check for shadowing: same Name= in system services with different Exec=
            if [[ -n "$svc_name" ]]; then
                local sys_dbus="${root}/usr/share/dbus-1/services"
                if [[ -d "$sys_dbus" ]]; then
                    local sys_match
                    sys_match="$(grep -rl "^Name=${svc_name}$" "$sys_dbus" 2>/dev/null | head -1 || true)"
                    if [[ -n "$sys_match" ]]; then
                        local sys_exec
                        sys_exec="$(grep '^Exec=' "$sys_match" 2>/dev/null | head -1 | cut -d= -f2- || true)"
                        if [[ "$svc_exec" != "$sys_exec" ]]; then
                            echo "  [!] SHADOW: user service '${svc_name}' overrides system service"
                            echo "      User Exec:   ${svc_exec:-?}"
                            echo "      System Exec: ${sys_exec:-?}"
                            dbus_findings=$((dbus_findings + 1))
                        fi
                    fi
                fi
            fi
        done
    done
    [[ $user_dbus_count -eq 0 ]] && echo "  (no user session services found)"
    echo ""

    echo "--- D-Bus system policies (overly permissive) ---"
    local dbus_system_d="${root}/etc/dbus-1/system.d"
    local permissive_policies=0
    if [[ -d "$dbus_system_d" ]]; then
        for policy in "${dbus_system_d}"/*.conf; do
            [[ -f "$policy" ]] || continue
            # Flag policies that allow send/receive for any user (user="*") or have no user restriction
            local wide_allow
            wide_allow="$(grep -E '<allow\s+.*send_destination=' "$policy" 2>/dev/null | grep -v 'user="root"' | grep -v '^\s*<!--' || true)"
            if echo "$wide_allow" | grep -qE 'user="\*"' 2>/dev/null; then
                echo "  [!] $(basename "$policy"): allows any user to send:"
                echo "$wide_allow" | sed 's/^/      /'
                permissive_policies=$((permissive_policies + 1))
                dbus_findings=$((dbus_findings + 1))
            fi
        done
        [[ $permissive_policies -eq 0 ]] && echo "  (no overly permissive policies detected)"
    else
        echo "  (directory not found)"
    fi

    echo ""
    log_ok "Userland persistence scan complete (ssh: ${ssh_findings}, dropins: ${dropins_found}, generators: ${generators_found}, git: ${git_findings}, dbus: ${dbus_findings})"
}
