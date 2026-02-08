# List systemd services and their states
# Usage: secy services [--failed]

run() {
    local filter=""
    [[ "${1:-}" == "--failed" ]] && filter="--state=failed"

    section_header "SYSTEMD SERVICES"

    if ! command -v systemctl &>/dev/null; then
        log_error "systemctl not found — is this a systemd system?"
        exit 1
    fi

    if [[ -n "$filter" ]]; then
        echo "--- Failed units ---"
        systemctl list-units --type=service --state=failed --no-pager --no-legend 2>/dev/null || true
    else
        echo "--- Enabled services ---"
        systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null || true
        echo ""
        echo "--- Running services ---"
        systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null || true
        echo ""
        echo "--- Failed services ---"
        systemctl list-units --type=service --state=failed --no-pager --no-legend 2>/dev/null || true
    fi
}
