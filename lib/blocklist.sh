#!/usr/bin/env bash
# sread/lib/blocklist.sh — Path blocking logic

set -euo pipefail

SREAD_ROOT="${SREAD_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
source "${SREAD_ROOT}/lib/common.sh"

# Load blocked paths from config, ignoring comments and blank lines
_load_blocked_paths() {
    local blocked_file="${SREAD_CONF}/blocked_paths"
    if [[ ! -f "$blocked_file" ]]; then
        log_warn "Blocked paths config not found: ${blocked_file}"
        return
    fi
    grep -v '^\s*#' "$blocked_file" | grep -v '^\s*$'
}

# Resolve a path to its absolute canonical form, following symlinks.
# This prevents bypass via ../  or symlinks pointing into blocked dirs.
_resolve_path() {
    local target="$1"
    if [[ -e "$target" ]]; then
        readlink -f "$target"
    else
        # File doesn't exist — resolve parent dir + filename
        local dir base
        dir="$(cd "$(dirname "$target")" 2>/dev/null && pwd)" || dir="$(dirname "$target")"
        base="$(basename "$target")"
        echo "${dir}/${base}"
    fi
}

# Convert a blocklist glob pattern to an ERE regex.
# Handles ** (match any path), * (match within one segment), and ? (single char).
_glob_to_regex() {
    local glob="$1"
    local regex=""
    local i=0
    local len=${#glob}

    while (( i < len )); do
        local c="${glob:$i:1}"
        case "$c" in
            '*')
                if [[ "${glob:$((i+1)):1}" == '*' ]]; then
                    # ** matches any path segment(s)
                    regex+=".*"
                    (( i += 2 ))
                    # Skip trailing / after ** (e.g., **/)
                    [[ "${glob:$i:1}" == '/' ]] && (( i++ ))
                    continue
                else
                    # * matches within one path segment (no /)
                    regex+="[^/]*"
                fi
                ;;
            '?') regex+="[^/]" ;;
            '.'|'+'|'('|')'|'['|']'|'{'|'}'|'^'|'$'|'|')
                regex+="\\${c}" ;;
            '/') regex+="/" ;;
            *)   regex+="$c" ;;
        esac
        (( i++ ))
    done

    echo "^${regex}$"
}

# Check if a path matches any blocked pattern.
# Returns 0 (true) if blocked, 1 (false) if allowed.
# Strips a leading /host prefix so patterns written for bare paths
# (e.g. /etc/shadow) also match /host/etc/shadow in Docker context.
is_path_blocked() {
    local target="$1"
    local resolved
    resolved="$(_resolve_path "$target")"

    # Normalize: strip /host prefix for matching (keep original for display)
    local normalized="$resolved"
    if [[ "$normalized" == /host/* ]]; then
        normalized="${normalized#/host}"
    fi

    local pattern
    while IFS= read -r pattern; do
        [[ -z "$pattern" ]] && continue

        local regex
        regex="$(_glob_to_regex "$pattern")"

        # Match against both the original resolved path and the normalized path
        if [[ "$resolved" =~ $regex ]] || [[ "$normalized" =~ $regex ]]; then
            return 0
        fi
    done < <(_load_blocked_paths)

    return 1
}

# Validate a path and exit with error if blocked.
assert_path_allowed() {
    local target="$1"
    if is_path_blocked "$target"; then
        log_error "BLOCKED: Access to '${target}' is not permitted"
        log_error "This path matches a blocked pattern in conf/blocked_paths"
        exit 1
    fi
}

# Validate that a path exists and is a regular file (not a device, socket, etc.)
assert_regular_file() {
    local target="$1"
    if [[ ! -e "$target" ]]; then
        log_error "Path does not exist: ${target}"
        exit 1
    fi
    if [[ ! -f "$target" ]]; then
        log_error "Not a regular file: ${target} (type: $(file -b "$target"))"
        log_error "sread only reads regular files — not devices, sockets, or directories"
        exit 1
    fi
}

# Load allowed MIME type prefixes from config.
_load_allowed_mimetypes() {
    local allowed_file="${SREAD_CONF}/allowed_mimetypes"
    if [[ ! -f "$allowed_file" ]]; then
        log_warn "Allowed MIME types config not found: ${allowed_file}"
        return
    fi
    grep -v '^\s*#' "$allowed_file" | grep -v '^\s*$'
}

# Check if a file's MIME type is in the allowed list.
# Returns 0 (true) if allowed, 1 (false) if blocked.
is_mimetype_allowed() {
    local target="$1"

    if ! command -v file &>/dev/null; then
        log_warn "file(1) command not found — skipping MIME check"
        return 0
    fi

    local mime
    mime="$(file --mime-type -b "$target" 2>/dev/null)" || {
        log_warn "Could not determine MIME type for: ${target}"
        return 1
    }

    local allowed
    while IFS= read -r allowed; do
        [[ -z "$allowed" ]] && continue
        # Exact match or prefix match (e.g., "text/" matches "text/plain")
        if [[ "$mime" == "$allowed" ]]; then
            return 0
        fi
    done < <(_load_allowed_mimetypes)

    # Also allow anything starting with "text/" as a catch-all
    # in case a specific text subtype isn't listed
    if [[ "$mime" == text/* ]]; then
        return 0
    fi

    return 1
}

# Validate MIME type and exit with error if not allowed.
assert_mimetype_allowed() {
    local target="$1"
    if ! is_mimetype_allowed "$target"; then
        local mime
        mime="$(file --mime-type -b "$target" 2>/dev/null || echo 'unknown')"
        log_error "BLOCKED: MIME type '${mime}' is not allowed for reading"
        log_error "File: ${target}"
        log_error "sread only reads text and config files — not binaries, images, archives, or databases"
        log_error "Allowed types are listed in conf/allowed_mimetypes"
        exit 1
    fi
}
