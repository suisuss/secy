#!/usr/bin/env bash
# harden.sh — Apply critical security fixes from secy audit
# Run with: sudo bash scripts/harden.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo: sudo bash $0"
    exit 1
fi

echo "=== Fix 1: Enable ptrace protections ==="
current=$(cat /proc/sys/kernel/yama/ptrace_scope)
echo "  Current ptrace_scope: ${current}"
if [[ "$current" == "0" ]]; then
    # Uncomment the setting in Brave's config
    if [[ -f /etc/sysctl.d/30-brave.conf ]]; then
        sed -i 's/^#kernel.yama.ptrace_scope = 1/kernel.yama.ptrace_scope = 1/' /etc/sysctl.d/30-brave.conf
        echo "  Uncommented ptrace_scope in /etc/sysctl.d/30-brave.conf"
    else
        echo "kernel.yama.ptrace_scope = 1" > /etc/sysctl.d/99-ptrace.conf
        echo "  Created /etc/sysctl.d/99-ptrace.conf"
    fi
    sysctl -w kernel.yama.ptrace_scope=1
    echo "  Applied: ptrace_scope = 1"
else
    echo "  Already set to ${current}, skipping"
fi

echo ""
echo "=== Fix 2: Enable firewall (ufw) ==="
if command -v ufw &>/dev/null; then
    status=$(ufw status | head -1)
    echo "  Current: ${status}"
    if echo "$status" | grep -qi "inactive"; then
        ufw default deny incoming
        ufw default allow outgoing
        ufw --force enable
        echo "  Enabled ufw with default deny incoming / allow outgoing"
    else
        echo "  Already active, skipping"
    fi
    ufw status verbose
else
    echo "  ufw not found, installing..."
    apt-get update -qq && apt-get install -y -qq ufw
    ufw default deny incoming
    ufw default allow outgoing
    ufw --force enable
    echo "  Installed and enabled ufw"
    ufw status verbose
fi

echo ""
echo "=== Verification ==="
echo "  ptrace_scope: $(cat /proc/sys/kernel/yama/ptrace_scope)"
echo "  ufw: $(ufw status | head -1)"
echo ""
echo "Done."
