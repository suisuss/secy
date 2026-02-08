# List cron jobs for all users
# Usage: secy cron

source "${SECY_ROOT}/lib/redact.sh"

run() {
    require_root

    section_header "CRON JOBS"

    echo "--- System crontab (/etc/crontab) ---"
    if [[ -f /etc/crontab ]]; then
        grep -v '^\s*#\|^\s*$' /etc/crontab 2>/dev/null | redact_output | sed 's/^/  /'
    else
        echo "  (not found)"
    fi
    echo ""

    echo "--- Cron directories ---"
    for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        if [[ -d "$dir" ]]; then
            echo "  ${dir}/:"
            ls -la "$dir" 2>/dev/null | sed 's/^/    /'
        fi
    done
    echo ""

    echo "--- User crontabs ---"
    local spool_dir="/var/spool/cron/crontabs"
    if [[ -d "$spool_dir" ]]; then
        for f in "${spool_dir}"/*; do
            [[ -f "$f" ]] || continue
            local user
            user="$(basename "$f")"
            echo "  User: ${user}"
            grep -v '^\s*#\|^\s*$' "$f" 2>/dev/null | redact_output | sed 's/^/    /'
            echo ""
        done
    else
        echo "  (spool directory not found or empty)"
    fi

    echo "--- Systemd timers ---"
    if command -v systemctl &>/dev/null; then
        systemctl list-timers --all --no-pager 2>/dev/null | sed 's/^/  /'
    fi
}
