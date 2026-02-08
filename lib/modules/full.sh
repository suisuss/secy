# Run all audit modules and produce a combined report
# Usage: secy full

run() {
    require_root

    local start
    start="$(date -Iseconds)"

    echo "================================================================"
    echo "  SECY FULL SECURITY AUDIT REPORT"
    echo "  Host: $(hostname)"
    echo "  Date: ${start}"
    echo "  Kernel: $(uname -r)"
    echo "  OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
    echo "================================================================"

    local modules=(ports services packages users firewall sysctl cron setuid world)
    for mod in "${modules[@]}"; do
        if [[ -f "${SECY_ROOT}/lib/modules/${mod}.sh" ]]; then
            log_info "Running module: ${mod}"
            "${SECY_ROOT}/bin/secy" "$mod" 2>&1 || log_warn "Module '${mod}' exited with errors"
        fi
    done

    echo ""
    echo "================================================================"
    echo "  AUDIT COMPLETE"
    echo "  Started: ${start}"
    echo "  Finished: $(date -Iseconds)"
    echo "================================================================"
}
