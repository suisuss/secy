# Run all surveillance detection modules
# Usage: sread surveil

run() {
    require_root

    local start
    start="$(date -Iseconds)"

    echo "================================================================"
    echo "  SREAD SURVEILLANCE DETECTION SWEEP"
    echo "  Host: $(hostname)"
    echo "  Date: ${start}"
    echo "  Kernel: $(uname -r)"
    echo "================================================================"

    local modules=(spyproc preload kmod ebpf autostart netconn desktop xattr)
    for mod in "${modules[@]}"; do
        if [[ -f "${SREAD_ROOT}/lib/modules/${mod}.sh" ]]; then
            log_info "Running module: ${mod}"
            "${SREAD_ROOT}/bin/sread" "$mod" 2>&1 || log_warn "Module '${mod}' exited with errors"
        fi
    done

    echo ""
    echo "================================================================"
    echo "  SURVEILLANCE SWEEP COMPLETE"
    echo "  Started: ${start}"
    echo "  Finished: $(date -Iseconds)"
    echo "================================================================"
}
