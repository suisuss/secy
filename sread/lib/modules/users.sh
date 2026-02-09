# Enumerate users, groups, last logins, and sudo configuration
# Usage: sread users

source "${SREAD_ROOT}/lib/redact.sh"

run() {
    require_root

    section_header "USER ACCOUNTS"

    echo "--- System users (uid < 1000) ---"
    awk -F: '$3 < 1000 {printf "  %-20s uid=%-6s shell=%s\n", $1, $3, $7}' /etc/passwd 2>/dev/null
    echo ""

    echo "--- Human users (uid >= 1000) ---"
    awk -F: '$3 >= 1000 && $3 < 65534 {printf "  %-20s uid=%-6s home=%-20s shell=%s\n", $1, $3, $6, $7}' /etc/passwd 2>/dev/null
    echo ""

    echo "--- Users with login shell ---"
    grep -v '/nologin\|/false\|/sync' /etc/passwd 2>/dev/null | awk -F: '{printf "  %-20s %s\n", $1, $7}'
    echo ""

    echo "--- Group memberships (human users) ---"
    awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd 2>/dev/null | while read -r user; do
        groups "$user" 2>/dev/null | sed 's/^/  /'
    done
    echo ""

    echo "--- Sudoers configuration ---"
    if [[ -f /etc/sudoers ]]; then
        # Show sudoers but redact any passwords/tokens
        grep -v '^\s*#\|^\s*$' /etc/sudoers 2>/dev/null | redact_output | sed 's/^/  /'
    fi
    if [[ -d /etc/sudoers.d ]]; then
        echo ""
        echo "  Drop-in files in /etc/sudoers.d/:"
        for f in /etc/sudoers.d/*; do
            [[ -f "$f" ]] || continue
            echo "  --- $(basename "$f") ---"
            grep -v '^\s*#\|^\s*$' "$f" 2>/dev/null | redact_output | sed 's/^/    /'
        done
    fi
    echo ""

    echo "--- Last logins ---"
    last -n 20 2>/dev/null || true
    echo ""

    echo "--- Failed login attempts ---"
    lastb -n 20 2>/dev/null || log_warn "lastb not available or requires root"
}
