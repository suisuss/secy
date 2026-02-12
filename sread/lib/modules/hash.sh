# Compute SHA256/MD5 hashes of files
# Usage: sread hash <path> [path...]
#        sread hash --md5 <path> [path...]

source "${SREAD_ROOT}/lib/blocklist.sh"

run() {
    local algo="sha256"

    # Parse flags
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --md5)    algo="md5"; shift ;;
            --sha256) algo="sha256"; shift ;;
            --help|-h)
                echo "Usage: sread hash [--md5|--sha256] <path> [path...]"
                echo ""
                echo "Compute cryptographic hashes of files."
                echo "Default algorithm: sha256"
                echo ""
                echo "Options:"
                echo "  --sha256   SHA-256 hash (default)"
                echo "  --md5      MD5 hash"
                return 0
                ;;
            *)  break ;;
        esac
    done

    if [[ $# -eq 0 ]]; then
        log_error "Usage: sread hash [--md5|--sha256] <path> [path...]"
        exit 1
    fi

    local hash_cmd
    case "$algo" in
        sha256) hash_cmd="sha256sum" ;;
        md5)    hash_cmd="md5sum" ;;
    esac

    if ! command -v "$hash_cmd" &>/dev/null; then
        log_error "Required command not found: ${hash_cmd}"
        exit 1
    fi

    for target in "$@"; do
        # Respect path blocklist (no hashing /etc/shadow etc.)
        assert_path_allowed "$target"

        # Must be a regular file
        assert_regular_file "$target"

        # NOTE: Intentionally skips MIME whitelist — must hash binaries
        local hash
        hash="$("$hash_cmd" "$target" 2>/dev/null | awk '{print $1}')" || {
            log_error "Failed to hash: ${target}"
            continue
        }

        echo "${hash}  ${target}"
    done
}
