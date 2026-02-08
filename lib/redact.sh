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

# Pipe stdin through the redaction engine.
# Usage: some_command | redact_output
redact_output() {
    local sed_file
    sed_file="$(mktemp /tmp/secy-redact.XXXXXX)"
    trap "rm -f '$sed_file'" RETURN

    if ! _build_sed_file "$sed_file"; then
        cat
        return
    fi

    # Apply all patterns via sed script file
    sed -Ef "$sed_file" 2>/dev/null || cat
}

# Redact a string directly (not streaming)
redact_string() {
    echo "$1" | redact_output
}
