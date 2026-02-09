# Read config files with redaction and blocklist enforcement
# Usage: sread files <path> [path...]

source "${SREAD_ROOT}/lib/blocklist.sh"
source "${SREAD_ROOT}/lib/redact.sh"

run() {
    if [[ $# -eq 0 ]]; then
        log_error "Usage: sread files <path> [path...]"
        exit 1
    fi

    require_root

    for target in "$@"; do
        assert_path_allowed "$target"
        assert_regular_file "$target"
        assert_mimetype_allowed "$target"

        section_header "FILE: ${target}"

        # Show metadata first
        echo "--- metadata ---"
        stat --format="  owner: %U:%G  mode: %a  size: %s  modified: %y" "$target" 2>/dev/null || true
        echo ""

        # Show content with redaction
        echo "--- content (redacted) ---"
        cat "$target" 2>/dev/null | redact_output
        echo ""
    done
}
