# List installed packages and their versions
# Usage: sread packages [--search <pattern>]

run() {
    section_header "INSTALLED PACKAGES"

    local search=""
    if [[ "${1:-}" == "--search" ]] && [[ -n "${2:-}" ]]; then
        search="$2"
    fi

    if command -v dpkg &>/dev/null; then
        echo "--- Package manager: dpkg/apt ---"
        if [[ -n "$search" ]]; then
            dpkg -l "*${search}*" 2>/dev/null || echo "  No packages matching '${search}'"
        else
            dpkg -l 2>/dev/null
        fi
    elif command -v rpm &>/dev/null; then
        echo "--- Package manager: rpm ---"
        if [[ -n "$search" ]]; then
            rpm -qa "*${search}*" 2>/dev/null || echo "  No packages matching '${search}'"
        else
            rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null | sort
        fi
    elif command -v pacman &>/dev/null; then
        echo "--- Package manager: pacman ---"
        if [[ -n "$search" ]]; then
            pacman -Qs "$search" 2>/dev/null || echo "  No packages matching '${search}'"
        else
            pacman -Q 2>/dev/null
        fi
    else
        log_warn "No recognized package manager found"
    fi

    echo ""
    echo "--- Package count ---"
    local count
    count="$(dpkg -l 2>/dev/null | grep '^ii' | wc -l || rpm -qa 2>/dev/null | wc -l || pacman -Q 2>/dev/null | wc -l || echo 'unknown')"
    echo "  Total installed: ${count}"
}
