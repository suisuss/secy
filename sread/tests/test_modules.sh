#!/usr/bin/env bash
# Integration tests for sread modules (runs without sudo — tests structure only)

set -euo pipefail

SREAD_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SREAD_BIN="${SREAD_ROOT}/bin/sread"

PASS=0
FAIL=0
inc_pass() { PASS=$((PASS + 1)); }
inc_fail() { FAIL=$((FAIL + 1)); }

assert_exits_zero() {
    local desc="$1"
    shift
    if "$@" &>/dev/null; then
        echo "  PASS: ${desc}"
        inc_pass
    else
        echo "  FAIL: ${desc} (exit code: $?)"
        inc_fail
    fi
}

assert_exits_nonzero() {
    local desc="$1"
    shift
    if "$@" &>/dev/null; then
        echo "  FAIL: ${desc} (expected failure but got success)"
        inc_fail
    else
        echo "  PASS: ${desc}"
        inc_pass
    fi
}

assert_output_contains() {
    local desc="$1"
    local expected="$2"
    shift 2
    local output
    output="$("$@" 2>&1)" || true
    if echo "$output" | grep -qF "$expected"; then
        echo "  PASS: ${desc}"
        inc_pass
    else
        echo "  FAIL: ${desc} (output missing '${expected}')"
        inc_fail
    fi
}

echo "=== Module Structure Tests ==="
echo ""

echo "-- Help and info --"
assert_exits_zero "sread --help" "$SREAD_BIN" --help
assert_exits_zero "sread --version" "$SREAD_BIN" --version
assert_exits_zero "sread --capabilities" "$SREAD_BIN" --capabilities
assert_output_contains "version string" "sread v" "$SREAD_BIN" --version

echo ""
echo "-- Unknown module --"
assert_exits_nonzero "unknown module fails" "$SREAD_BIN" nonexistent

echo ""
echo "-- Argument injection blocked --"
assert_exits_nonzero "semicolon blocked" "$SREAD_BIN" files "/etc/passwd;cat /etc/shadow"
assert_exits_nonzero "pipe blocked" "$SREAD_BIN" files "/etc/passwd|cat"
assert_exits_nonzero "backtick blocked" "$SREAD_BIN" files '/etc/`whoami`'
assert_exits_nonzero "dollar-paren blocked" "$SREAD_BIN" files '/etc/$(whoami)'

echo ""
echo "-- Modules that don't need root --"
assert_exits_zero "services module" "$SREAD_BIN" services
assert_exits_zero "packages module" "$SREAD_BIN" packages
assert_exits_zero "sysctl module" "$SREAD_BIN" sysctl --security

echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
