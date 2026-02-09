# List open ports, listening services, and active connections
# Usage: sread ports [--all]

run() {
    warn_if_container

    local show_all=false
    [[ "${1:-}" == "--all" ]] && show_all=true

    section_header "LISTENING PORTS"

    if command -v ss &>/dev/null; then
        echo "--- TCP listeners ---"
        ss -tlnp 2>/dev/null || true
        echo ""
        echo "--- UDP listeners ---"
        ss -ulnp 2>/dev/null || true
    elif command -v netstat &>/dev/null; then
        echo "--- TCP listeners ---"
        netstat -tlnp 2>/dev/null || true
        echo ""
        echo "--- UDP listeners ---"
        netstat -ulnp 2>/dev/null || true
    else
        log_error "Neither ss nor netstat found"
        exit 1
    fi

    if $show_all; then
        echo ""
        echo "--- All connections ---"
        ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null || true
    fi
}
