# Dump kernel parameters with security-relevant highlights
# Usage: sread sysctl [--security]

run() {
    warn_if_container

    local security_only=false
    [[ "${1:-}" == "--security" ]] && security_only=true

    section_header "KERNEL PARAMETERS"

    # sysctl is typically in /sbin or /usr/sbin
    local sysctl_bin=""
    if command -v sysctl &>/dev/null; then
        sysctl_bin="sysctl"
    elif [[ -x /sbin/sysctl ]]; then
        sysctl_bin="/sbin/sysctl"
    elif [[ -x /usr/sbin/sysctl ]]; then
        sysctl_bin="/usr/sbin/sysctl"
    else
        log_error "sysctl not found"
        exit 1
    fi

    if $security_only; then
        echo "--- Security-relevant parameters ---"
        local params=(
            # Note: some parameters may not exist on all kernels
            "net.ipv4.ip_forward"
            "net.ipv4.conf.all.accept_redirects"
            "net.ipv4.conf.all.send_redirects"
            "net.ipv4.conf.all.accept_source_route"
            "net.ipv4.conf.all.log_martians"
            "net.ipv4.conf.default.accept_redirects"
            "net.ipv4.conf.default.accept_source_route"
            "net.ipv4.tcp_syncookies"
            "net.ipv4.icmp_echo_ignore_broadcasts"
            "net.ipv4.icmp_ignore_bogus_error_responses"
            "net.ipv6.conf.all.accept_redirects"
            "net.ipv6.conf.all.accept_source_route"
            "net.ipv6.conf.default.accept_redirects"
            "net.ipv6.conf.default.accept_source_route"
            "kernel.randomize_va_space"
            "kernel.exec-shield"
            "kernel.kptr_restrict"
            "kernel.dmesg_restrict"
            "kernel.perf_event_paranoid"
            "kernel.yama.ptrace_scope"
            "fs.protected_hardlinks"
            "fs.protected_symlinks"
            "fs.suid_dumpable"
        )
        for param in "${params[@]}"; do
            local val
            val="$($sysctl_bin -n "$param" 2>/dev/null)" || val="(not set)"
            printf "  %-50s = %s\n" "$param" "$val"
        done
    else
        $sysctl_bin -a 2>/dev/null | sort || true
    fi
}
