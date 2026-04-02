# Read system logs with redaction
# Usage: sread logs [auth|syslog|journal|kern] [--lines N]

source "${SREAD_ROOT}/lib/redact.sh"

run() {
    local log_type="${1:-auth}"
    shift || true
    local lines=100

    if [[ "${1:-}" == "--lines" ]] && [[ -n "${2:-}" ]]; then
        lines="$2"
        # Cap at 1000 lines to prevent excessive output
        if [[ "$lines" -gt 1000 ]]; then
            log_warn "Capping output at 1000 lines"
            lines=1000
        fi
    fi

    require_root

    # Resolve host filesystem path (container vs bare-metal)
    local root=""
    [[ -d "/host/etc" ]] && root="/host"

    section_header "LOGS: ${log_type} (last ${lines} lines)"

    case "$log_type" in
        auth)
            if [[ -f "${root}/var/log/auth.log" ]]; then
                tail -n "$lines" "${root}/var/log/auth.log" 2>/dev/null | redact_output
            elif command -v journalctl &>/dev/null; then
                journalctl -u ssh -u sshd --no-pager -n "$lines" 2>/dev/null | redact_output
            else
                log_error "No auth log found"
            fi
            ;;
        syslog)
            if [[ -f "${root}/var/log/syslog" ]]; then
                tail -n "$lines" "${root}/var/log/syslog" 2>/dev/null | redact_output
            elif command -v journalctl &>/dev/null; then
                journalctl --no-pager -n "$lines" 2>/dev/null | redact_output
            else
                log_error "No syslog found"
            fi
            ;;
        journal)
            if command -v journalctl &>/dev/null; then
                journalctl --no-pager -n "$lines" 2>/dev/null | redact_output
            else
                log_error "journalctl not available"
            fi
            ;;
        kern)
            if [[ -f "${root}/var/log/kern.log" ]]; then
                tail -n "$lines" "${root}/var/log/kern.log" 2>/dev/null | redact_output
            elif command -v journalctl &>/dev/null; then
                journalctl -k --no-pager -n "$lines" 2>/dev/null | redact_output
            else
                log_error "No kernel log found"
            fi
            ;;
        *)
            log_error "Unknown log type: '${log_type}'"
            echo "Available: auth, syslog, journal, kern"
            exit 1
            ;;
    esac
}
