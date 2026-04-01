# Check secy notification infrastructure: systemd service and cron health check
# Usage: sread secyhealth

run() {
    local root=""
    [[ -d "/host/home" ]] && root="/host"

    section_header "SECY NOTIFICATION HEALTH"

    # Discover the user's home directory
    local user_home=""
    if [[ -n "$root" ]]; then
        # Inside container — find the primary non-root user's home
        for d in "${root}"/home/*/; do
            [[ -d "$d" ]] || continue
            user_home="${d%/}"
            break
        done
    else
        user_home="${HOME}"
    fi

    if [[ -z "$user_home" ]]; then
        log_error "Cannot determine user home directory"
        return
    fi

    local username
    username="$(basename "$user_home")"

    # ── 1. Systemd user service ────────────────────────────────────
    echo "--- secy-notify systemd service ---"
    local service_file="${user_home}/.config/systemd/user/secy-notify.service"
    local service_issues=0

    if [[ -f "$service_file" ]]; then
        echo "  Unit file: present"

        # Check if enabled (look for symlink in wants dir)
        local wants_dir="${user_home}/.config/systemd/user/graphical-session.target.wants"
        if [[ -L "${wants_dir}/secy-notify.service" ]]; then
            echo "  Enabled: yes"
        else
            echo "  [!] Enabled: no — service will not start on login"
            service_issues=$((service_issues + 1))
        fi

        # Check if ExecStart path exists
        local exec_path
        exec_path="$(grep '^ExecStart=' "$service_file" 2>/dev/null | sed 's/^ExecStart=//' | sed "s|%h|${user_home}|g")"
        if [[ -n "$exec_path" ]] && [[ -x "${root}${exec_path}" ]]; then
            echo "  ExecStart: ${exec_path} (exists, executable)"
        elif [[ -n "$exec_path" ]]; then
            echo "  [!] ExecStart: ${exec_path} (missing or not executable)"
            service_issues=$((service_issues + 1))
        fi
    else
        echo "  [!] Unit file: NOT FOUND at ${service_file#${root}}"
        echo "      Run: ./scripts/setup-notify.sh"
        service_issues=$((service_issues + 1))
    fi
    echo ""

    # ── 2. Cron health check ──────────────────────────────────────
    echo "--- secy-notify cron health check ---"
    local cron_issues=0
    local cron_tag="secy-notify-healthcheck"

    # Read user's crontab. Inside container, read the spool file directly.
    local crontab_content=""
    local cron_spool="${root}/var/spool/cron/crontabs/${username}"
    if [[ -f "$cron_spool" ]]; then
        crontab_content="$(cat "$cron_spool" 2>/dev/null || true)"
    elif [[ -z "$root" ]]; then
        crontab_content="$(crontab -l 2>/dev/null || true)"
    fi

    if echo "$crontab_content" | grep -q "$cron_tag"; then
        echo "  Cron entry: present"

        # Verify the healthcheck script exists
        local healthcheck_path
        healthcheck_path="$(echo "$crontab_content" | grep "$cron_tag" | grep -oP '\S+/notify-healthcheck\.sh')"
        if [[ -n "$healthcheck_path" ]]; then
            local full_path="${root}${healthcheck_path}"
            if [[ -x "$full_path" ]]; then
                echo "  Script: ${healthcheck_path} (exists, executable)"
            elif [[ -f "$full_path" ]]; then
                echo "  [!] Script: ${healthcheck_path} (exists but NOT executable)"
                cron_issues=$((cron_issues + 1))
            else
                echo "  [!] Script: ${healthcheck_path} (NOT FOUND)"
                cron_issues=$((cron_issues + 1))
            fi
        fi
    else
        echo "  [!] Cron entry: NOT FOUND"
        echo "      Run: ./scripts/setup-notify.sh"
        cron_issues=$((cron_issues + 1))
    fi
    echo ""

    # ── 3. Issues directory ────────────────────────────────────────
    echo "--- Issues directory ---"
    local issues_dir=""
    # Default data location: ~/.local/share/secy
    local data_dir="${user_home}/.local/share/secy"
    if [[ -d "${data_dir}/issues" ]]; then
        issues_dir="${data_dir}/issues"
    fi

    if [[ -n "$issues_dir" ]] && [[ -d "$issues_dir" ]]; then
        local owner perms
        owner="$(stat -c%U "$issues_dir" 2>/dev/null || echo "?")"
        perms="$(stat -c%a "$issues_dir" 2>/dev/null || echo "?")"
        local issue_count
        issue_count="$(find "$issues_dir" -maxdepth 1 -name '*.md' -type f 2>/dev/null | wc -l)"
        echo "  Path: ${issues_dir#${root}}"
        echo "  Owner: ${owner}, mode: ${perms}"
        echo "  Issues on file: ${issue_count}"

        if [[ "$owner" == "root" ]]; then
            echo "  [!] Owned by root — notify.sh may not be able to read new files"
        fi
    elif [[ -n "$issues_dir" ]]; then
        echo "  [!] Issues directory not found: ${issues_dir#${root}}"
    else
        echo "  (could not determine issues directory path)"
    fi
    echo ""

    # ── Summary ────────────────────────────────────────────────────
    echo "--- Summary ---"
    echo "  Service issues: ${service_issues}"
    echo "  Cron issues: ${cron_issues}"

    local total=$((service_issues + cron_issues))
    if [[ $total -eq 0 ]]; then
        echo "  Notification infrastructure: OK"
    else
        echo "  [!] Notification infrastructure: DEGRADED (${total} issue(s))"
    fi

    echo ""
    log_ok "Notification health check complete (service_issues: ${service_issues}, cron_issues: ${cron_issues})"
}
