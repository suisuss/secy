#!/usr/bin/env bash
# secy/lib/redact.sh — Output redaction engine

set -euo pipefail

SECY_ROOT="${SECY_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
source "${SECY_ROOT}/lib/common.sh"

# Build a sed script file from the redact_patterns config.
# Each line in the config is: PATTERN|||REPLACEMENT
# Delimiter: ASCII SOH (\x01) — cannot appear in text file content,
# avoids collisions with ~ (home paths), @ (emails), / (paths).
_build_sed_file() {
    local patterns_file="${SECY_CONF}/redact_patterns"
    local sed_file="$1"

    if [[ ! -f "$patterns_file" ]]; then
        log_warn "Redaction patterns not found: ${patterns_file}"
        return 1
    fi

    > "$sed_file"

    local delim=$'\x01'

    while IFS= read -r line; do
        # Skip comments and blanks
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// /}" ]] && continue

        local pattern replacement
        pattern="${line%%\|\|\|*}"
        replacement="${line##*\|\|\|}"

        [[ -z "$pattern" ]] && continue

        # Write as a sed command using SOH delimiter
        echo "s${delim}${pattern}${delim}${replacement}${delim}gi" >> "$sed_file"
    done < "$patterns_file"

    [[ -s "$sed_file" ]]
}

# Cached sed script path — built once per process, reused across calls.
_REDACT_SED_FILE=""

_ensure_sed_file() {
    if [[ -n "$_REDACT_SED_FILE" ]] && [[ -s "$_REDACT_SED_FILE" ]]; then
        return 0
    fi
    _REDACT_SED_FILE="$(mktemp /tmp/secy-redact.XXXXXX)"
    if ! _build_sed_file "$_REDACT_SED_FILE"; then
        rm -f "$_REDACT_SED_FILE"
        _REDACT_SED_FILE=""
        return 1
    fi
}

# Cleanup is best-effort. The file is small and lives in /tmp.
# Callers that need deterministic cleanup can call this explicitly.
redact_cleanup() {
    [[ -n "$_REDACT_SED_FILE" ]] && rm -f "$_REDACT_SED_FILE"
    _REDACT_SED_FILE=""
}

# Pipe stdin through the redaction engine.
# Usage: some_command | redact_output
redact_output() {
    if ! _ensure_sed_file; then
        cat
        return
    fi
    sed -Ef "$_REDACT_SED_FILE" 2>/dev/null || cat
}

# Redact a string directly (not streaming)
redact_string() {
    echo "$1" | redact_output
}
