#!/usr/bin/env bash
# Integration tests for secy modules (runs without sudo — tests structure only)

set -euo pipefail

SECY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECY_BIN="${SECY_ROOT}/bin/secy"

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
assert_exits_zero "secy --help" "$SECY_BIN" --help
assert_exits_zero "secy --version" "$SECY_BIN" --version
assert_exits_zero "secy --capabilities" "$SECY_BIN" --capabilities
assert_output_contains "version string" "secy v" "$SECY_BIN" --version

echo ""
echo "-- Unknown module --"
assert_exits_nonzero "unknown module fails" "$SECY_BIN" nonexistent

echo ""
echo "-- Argument injection blocked --"
assert_exits_nonzero "semicolon blocked" "$SECY_BIN" files "/etc/passwd;cat /etc/shadow"
assert_exits_nonzero "pipe blocked" "$SECY_BIN" files "/etc/passwd|cat"
assert_exits_nonzero "backtick blocked" "$SECY_BIN" files '/etc/`whoami`'
assert_exits_nonzero "dollar-paren blocked" "$SECY_BIN" files '/etc/$(whoami)'

echo ""
echo "-- Modules that don't need root --"
assert_exits_zero "services module" "$SECY_BIN" services
assert_exits_zero "packages module" "$SECY_BIN" packages
assert_exits_zero "sysctl module" "$SECY_BIN" sysctl --security

echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
