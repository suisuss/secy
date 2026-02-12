# Check file hashes against local malware hash database
# Usage: sread hashlookup <sha256_hash> [hash...]
#        sread hashlookup --file <path> [path...]

source "${SREAD_ROOT}/lib/blocklist.sh"

# Database location — baked in at Docker build time
HASH_DB="${SREAD_ROOT}/data/malware-sha256.txt"
# Container override (Dockerfile installs here)
if [[ -f /usr/local/lib/sread/data/malware-sha256.txt ]]; then
    HASH_DB="/usr/local/lib/sread/data/malware-sha256.txt"
fi

_lookup_hash() {
    local hash="$1"

    # Normalize to lowercase
    hash="$(echo "$hash" | tr '[:upper:]' '[:lower:]')"

    # Validate it looks like a SHA256 hash
    if [[ ! "$hash" =~ ^[0-9a-f]{64}$ ]]; then
        log_error "Invalid SHA256 hash: ${hash}"
        return 1
    fi

    if [[ ! -f "$HASH_DB" ]]; then
        echo "[NO_DB]  ${hash}  (malware hash database not found at ${HASH_DB})"
        return 0
    fi

    # Use look(1) for O(log n) binary search on sorted file
    if command -v look &>/dev/null; then
        if look "$hash" "$HASH_DB" | grep -q "^${hash}$"; then
            echo "[MATCH]  ${hash}"
            return 0
        else
            echo "[CLEAN]  ${hash}"
            return 0
        fi
    else
        # Fallback to grep (linear scan)
        if grep -q "^${hash}$" "$HASH_DB" 2>/dev/null; then
            echo "[MATCH]  ${hash}"
        else
            echo "[CLEAN]  ${hash}"
        fi
        return 0
    fi
}

run() {
    local file_mode=false

    # Parse flags
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --file|-f) file_mode=true; shift ;;
            --help|-h)
                echo "Usage: sread hashlookup <sha256_hash> [hash...]"
                echo "       sread hashlookup --file <path> [path...]"
                echo ""
                echo "Check SHA256 hashes against the local malware hash database."
                echo "Uses look(1) for O(log n) binary search on the sorted DB."
                echo ""
                echo "Options:"
                echo "  --file, -f   Hash files first, then look up the hashes"
                echo ""
                echo "Output:"
                echo "  [MATCH]  hash  — Hash found in malware database"
                echo "  [CLEAN]  hash  — Hash not found in malware database"
                echo "  [NO_DB]  hash  — Database file not found"
                echo ""
                echo "Database: ${HASH_DB}"
                if [[ -f "$HASH_DB" ]]; then
                    local count
                    count="$(wc -l < "$HASH_DB" | tr -d ' ')"
                    echo "Entries:  ${count}"
                fi
                return 0
                ;;
            *)  break ;;
        esac
    done

    if [[ $# -eq 0 ]]; then
        log_error "Usage: sread hashlookup [--file] <hash|path> [...]"
        exit 1
    fi

    if [[ "$file_mode" == "true" ]]; then
        # Hash each file, then look up
        for target in "$@"; do
            assert_path_allowed "$target"
            assert_regular_file "$target"

            local hash
            hash="$(sha256sum "$target" 2>/dev/null | awk '{print $1}')" || {
                log_error "Failed to hash: ${target}"
                continue
            }

            local result
            result="$(_lookup_hash "$hash")"
            # Append filename to output
            echo "${result}  ${target}"
        done
    else
        # Direct hash lookup
        for hash in "$@"; do
            _lookup_hash "$hash"
        done
    fi
}
