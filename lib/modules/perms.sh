# Inspect file/directory permissions without reading content
# Usage: secy perms <path> [path...]

run() {
    if [[ $# -eq 0 ]]; then
        log_error "Usage: secy perms <path> [path...]"
        exit 1
    fi

    require_root

    for target in "$@"; do
        if [[ ! -e "$target" ]]; then
            log_error "Path does not exist: ${target}"
            continue
        fi

        section_header "PERMS: ${target}"

        echo "--- stat ---"
        stat "$target" 2>/dev/null
        echo ""

        # ACLs if available
        if command -v getfacl &>/dev/null; then
            echo "--- ACL ---"
            getfacl "$target" 2>/dev/null || echo "  (no ACL or not supported)"
            echo ""
        fi

        # Extended attributes
        if command -v lsattr &>/dev/null && [[ -f "$target" ]]; then
            echo "--- attributes ---"
            lsattr "$target" 2>/dev/null || echo "  (not supported on this filesystem)"
            echo ""
        fi
    done
}
