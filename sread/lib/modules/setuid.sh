# Find setuid and setgid binaries on the system
# Usage: sread setuid [--path /search/root]

run() {
    require_root

    local search_root="/"
    if [[ "${1:-}" == "--path" ]] && [[ -n "${2:-}" ]]; then
        search_root="$2"
    fi

    section_header "SETUID/SETGID BINARIES"

    echo "--- Setuid files (SUID) ---"
    find "$search_root" -perm -4000 -type f 2>/dev/null | while read -r f; do
        ls -la "$f" 2>/dev/null | sed 's/^/  /'
    done
    echo ""

    echo "--- Setgid files (SGID) ---"
    find "$search_root" -perm -2000 -type f 2>/dev/null | while read -r f; do
        ls -la "$f" 2>/dev/null | sed 's/^/  /'
    done
}
