# Find world-writable files and directories
# Usage: secy world [--path /search/root]

run() {
    require_root

    local search_root="/"
    if [[ "${1:-}" == "--path" ]] && [[ -n "${2:-}" ]]; then
        search_root="$2"
    fi

    section_header "WORLD-WRITABLE FILES/DIRS"

    echo "--- World-writable directories (excluding /tmp, /var/tmp, /dev/shm, /run) ---"
    find "$search_root" -type d -perm -0002 \
        -not -path "/tmp/*" -not -path "/var/tmp/*" -not -path "/dev/shm/*" \
        -not -path "/proc/*" -not -path "/sys/*" -not -path "/run/*" \
        2>/dev/null | while read -r f; do
        ls -ld "$f" 2>/dev/null | sed 's/^/  /'
    done
    echo ""

    echo "--- World-writable files (excluding /tmp, /var/tmp, /dev/shm, /run) ---"
    find "$search_root" -type f -perm -0002 \
        -not -path "/tmp/*" -not -path "/var/tmp/*" -not -path "/dev/shm/*" \
        -not -path "/proc/*" -not -path "/sys/*" -not -path "/run/*" \
        2>/dev/null | while read -r f; do
        ls -la "$f" 2>/dev/null | sed 's/^/  /'
    done
}
