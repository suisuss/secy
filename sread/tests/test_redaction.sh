#!/usr/bin/env bash
# Tests for the redaction engine

set -euo pipefail

SREAD_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export SREAD_ROOT
source "${SREAD_ROOT}/lib/redact.sh"

PASS=0
FAIL=0
inc_pass() { PASS=$((PASS + 1)); }
inc_fail() { FAIL=$((FAIL + 1)); }

assert_redacted() {
    local input="$1"
    local forbidden="$2"
    local desc="$3"
    local output
    output="$(echo "$input" | redact_output)"

    if echo "$output" | grep -qF "$forbidden"; then
        echo "  FAIL: ${desc}"
        echo "    input:     ${input}"
        echo "    output:    ${output}"
        echo "    should not contain: ${forbidden}"
        inc_fail
    else
        echo "  PASS: ${desc}"
        inc_pass
    fi
}

assert_unchanged() {
    local input="$1"
    local desc="$2"
    local output
    output="$(echo "$input" | redact_output)"

    if [[ "$output" == "$input" ]]; then
        echo "  PASS: ${desc}"
        inc_pass
    else
        echo "  FAIL: ${desc} (was modified)"
        echo "    input:  ${input}"
        echo "    output: ${output}"
        inc_fail
    fi
}

echo "=== Redaction Tests ==="
echo ""

echo "-- Should be redacted --"
assert_redacted "password=hunter2" "hunter2" "password in config"
assert_redacted "API_KEY=sk-1234567890abcdef" "sk-1234567890abcdef" "API key"
assert_redacted "token: abc123secret" "abc123secret" "token value"
assert_redacted "postgres://admin:s3cret@localhost/db" "admin:s3cret" "connection string"
assert_redacted "Authorization: Bearer eyJhbGciOi" "eyJhbGciOi" "bearer token"
assert_redacted "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456ghi789" "eyJhbGciOiJIUzI1NiJ9" "JWT token"
assert_redacted "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn" "ghp_ABCDEFGHIJ" "GitHub personal access token"
assert_redacted "SECRET_KEY=aVeryLongBase64EncodedSecretKeyValueThatShouldBeRedacted+/==" "aVeryLongBase64" "base64 secret key"

echo ""
echo "-- Should NOT be redacted --"
assert_unchanged "PermitRootLogin no" "sshd config directive"
assert_unchanged "Port 22" "port number"
assert_unchanged "ListenAddress 0.0.0.0" "listen address"

echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
