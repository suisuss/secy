# Dump firewall rules (iptables and/or nftables)
# Usage: sread firewall

run() {
    require_root
    warn_if_container

    section_header "FIREWALL RULES"

    # nftables
    if command -v nft &>/dev/null; then
        echo "--- nftables ruleset ---"
        nft list ruleset 2>/dev/null || echo "  (no nft rules or nft not active)"
        echo ""
    fi

    # iptables
    if command -v iptables &>/dev/null; then
        echo "--- iptables (IPv4) ---"
        echo "  Filter table:"
        iptables -L -n -v 2>/dev/null | sed 's/^/    /' || echo "    (not available)"
        echo ""
        echo "  NAT table:"
        iptables -t nat -L -n -v 2>/dev/null | sed 's/^/    /' || echo "    (not available)"
        echo ""
    fi

    # ip6tables
    if command -v ip6tables &>/dev/null; then
        echo "--- ip6tables (IPv6) ---"
        ip6tables -L -n -v 2>/dev/null | sed 's/^/    /' || echo "    (not available)"
        echo ""
    fi

    # ufw (if present)
    if command -v ufw &>/dev/null; then
        echo "--- ufw status ---"
        ufw status verbose 2>/dev/null | sed 's/^/    /' || echo "    (not available)"
        echo ""
    fi
}
