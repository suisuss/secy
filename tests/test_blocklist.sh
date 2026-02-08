#!/usr/bin/env bash
# Tests for the blocklist module

set -euo pipefail

SECY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export SECY_ROOT
source "${SECY_ROOT}/lib/blocklist.sh"

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
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
