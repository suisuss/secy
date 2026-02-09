#!/usr/bin/env bash
# Tests for the blocklist module

set -euo pipefail

SREAD_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export SREAD_ROOT
source "${SREAD_ROOT}/lib/blocklist.sh"

PASS=0
FAIL=0
inc_pass() { PASS=$((PASS + 1)); }
inc_fail() { FAIL=$((FAIL + 1)); }

assert_blocked() {
    local path="$1"
    if is_path_blocked "$path"; then
        echo "  PASS: blocked '${path}'"
        inc_pass
    else
        echo "  FAIL: expected '${path}' to be blocked"
        inc_fail
    fi
}

assert_allowed() {
    local path="$1"
    if is_path_blocked "$path"; then
        echo "  FAIL: expected '${path}' to be allowed"
        inc_fail
    else
        echo "  PASS: allowed '${path}'"
        inc_pass
    fi
}

echo "=== Blocklist Tests ==="
echo ""

echo "-- Should be BLOCKED --"
assert_blocked "/etc/shadow"
assert_blocked "/etc/shadow-"
assert_blocked "/etc/gshadow"
assert_blocked "/proc/kcore"
assert_blocked "/dev/mem"

echo ""
echo "-- Should be ALLOWED --"
assert_allowed "/etc/ssh/sshd_config"
assert_allowed "/etc/passwd"
assert_allowed "/etc/hosts"
assert_allowed "/etc/fstab"
assert_allowed "/var/log/auth.log"
assert_allowed "/etc/apt/sources.list"

echo ""
echo "-- Glob patterns: ** (recursive) --"
assert_blocked "/opt/app/credentials.json"
assert_blocked "/home/user/project/secrets.yml"
assert_blocked "/var/lib/app/.secret.conf"

echo ""
echo "-- Glob patterns: * (single segment) --"
assert_blocked "/home/user/.ssh/id_ed25519"
assert_blocked "/home/user/.ssh/work_id_ed25519"
assert_blocked "/etc/ssh/ssh_host_rsa_key"
assert_blocked "/etc/ssh/ssh_host_ecdsa_key"
assert_blocked "/home/user/.env"
assert_blocked "/home/user/.env.production"

echo ""
echo "-- /host prefix (Docker context) --"
assert_blocked "/host/etc/shadow"
assert_blocked "/host/etc/shadow-"
assert_blocked "/host/proc/kcore"
assert_blocked "/host/home/user/.ssh/id_ed25519"
assert_blocked "/host/opt/app/credentials.json"
assert_allowed "/host/etc/passwd"
assert_allowed "/host/etc/ssh/sshd_config"
assert_allowed "/host/var/log/auth.log"

echo ""
echo "-- Should NOT over-match --"
assert_allowed "/etc/shadow.bak"
assert_allowed "/etc/ssh/sshd_config"
assert_allowed "/home/user/.bashrc"
assert_allowed "/home/user/.ssh/config"
assert_allowed "/opt/app/config.json"

echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
