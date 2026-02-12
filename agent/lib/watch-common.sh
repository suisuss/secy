#!/usr/bin/env bash
# agent/lib/watch-common.sh — Shared utilities for the watch daemon

source "${BASH_SOURCE[0]%/*}/secy-common.sh"

WATCH_STATE_DIR="${STATE_DIR}/watch"
WATCH_SEEN_DB="${WATCH_STATE_DIR}/seen.db"
WATCH_QUEUE_DIR="${WATCH_STATE_DIR}/queue"
WATCH_FINDINGS_DIR="${STATE_DIR}/findings"
WATCH_DIRECTIVES_FILE="${STATE_DIR}/directives/watch-config.conf"

# Extra directories to scan (set by C2 directive)
WATCH_EXTRA_DIRS=""

# Track mtime of last-loaded directives file
_WATCH_DIRECTIVE_MTIME=0

# ── State directory management ────────────────────────────────────

init_watch_state() {
    mkdir -p "$WATCH_STATE_DIR"
    mkdir -p "$WATCH_QUEUE_DIR"
    mkdir -p "$WATCH_FINDINGS_DIR"
    touch "$WATCH_SEEN_DB"
    secy_log "watch" "State initialized at ${WATCH_STATE_DIR}"
}

# ── Seen database ─────────────────────────────────────────────────
#
# Format: <sha256> <size_bytes> <filepath> <first_seen_timestamp>
# One entry per line, space-separated (filepath may contain spaces, so
# we use tab as delimiter).

is_file_seen() {
    local filepath="$1"
    local filesize="$2"
    # Check if this exact file+size combo is already in the DB
    # Use grep -F (fixed string) to avoid regex injection from filenames
    grep -F "	${filepath}	" "$WATCH_SEEN_DB" 2>/dev/null \
        | grep -q "^[0-9a-f]\{64\}	${filesize}	"
}

get_seen_hash() {
    local filepath="$1"
    # Return the stored hash for a filepath (ignoring size)
    # || true: grep returns 1 when no match; pipefail would propagate it
    grep -F "	${filepath}	" "$WATCH_SEEN_DB" 2>/dev/null | head -1 | cut -f1 || true
}

get_seen_size() {
    local filepath="$1"
    grep -F "	${filepath}	" "$WATCH_SEEN_DB" 2>/dev/null | head -1 | cut -f2 || true
}

mark_file_seen() {
    local hash="$1"
    local size="$2"
    local filepath="$3"
    local timestamp
    timestamp="$(date -Iseconds)"

    # Remove any existing entry for this filepath
    # Use grep -F (fixed string) to avoid regex injection from filenames
    if grep -qF "	${filepath}	" "$WATCH_SEEN_DB" 2>/dev/null; then
        local tmp
        tmp="$(mktemp)"
        grep -vF "	${filepath}	" "$WATCH_SEEN_DB" > "$tmp" 2>/dev/null || true
        mv "$tmp" "$WATCH_SEEN_DB"
    fi

    # Add new entry (tab-delimited)
    printf '%s\t%s\t%s\t%s\n' "$hash" "$size" "$filepath" "$timestamp" >> "$WATCH_SEEN_DB"
}

# ── File classification ───────────────────────────────────────────

classify_file() {
    local filepath="$1"

    local mime="unknown"
    if command -v file &>/dev/null; then
        mime="$(file --mime-type -b "$filepath" 2>/dev/null || echo 'unknown')"
    fi

    local size
    size="$(stat -c%s "$filepath" 2>/dev/null || echo 0)"

    # Skip tiny files (<32 bytes — likely empty/placeholder)
    if [[ "$size" -lt 32 ]]; then
        echo "SKIP_TINY"
        return
    fi

    # Skip files over max size
    if [[ "$size" -gt "$WATCH_MAX_FILE_SIZE" ]]; then
        echo "SKIP_LARGE"
        return
    fi

    # Media files — near-zero risk as direct malware on Linux
    # Hash check still catches them via known-malware DB
    case "$mime" in
        image/*|video/*|audio/*)
            echo "SKIP_MEDIA"
            return
            ;;
    esac

    # Analyzable file types
    case "$mime" in
        # Scripts and code
        text/x-shellscript|text/x-python|text/x-perl|text/x-ruby|text/x-php|\
        application/javascript|application/x-javascript|text/javascript|\
        text/x-c|text/x-c++|text/x-java|text/x-script.*)
            echo "ANALYZABLE"
            return
            ;;
        # Executables
        application/x-executable|application/x-pie-executable|\
        application/x-sharedlib|application/x-dosexec|\
        application/x-mach-binary)
            echo "ANALYZABLE"
            return
            ;;
        # Documents that can embed code
        application/pdf)
            echo "ANALYZABLE"
            return
            ;;
        # Office documents (macros)
        application/vnd.ms-*|application/vnd.openxmlformats-*|\
        application/msword|application/vnd.oasis.opendocument.*)
            echo "ANALYZABLE"
            return
            ;;
        # Archives
        application/zip|application/gzip|application/x-tar|\
        application/x-gzip|application/x-bzip2|application/x-xz|\
        application/x-rar*|application/x-7z*|application/java-archive)
            echo "ANALYZABLE"
            return
            ;;
        # Installers / disk images
        application/x-debian-package|application/x-rpm|\
        application/x-iso9660-image|application/x-apple-diskimage)
            echo "ANALYZABLE"
            return
            ;;
        # Generic text (could be scripts without proper shebang)
        text/plain)
            echo "ANALYZABLE"
            return
            ;;
        # Unknown/octet-stream — worth analyzing
        application/octet-stream)
            echo "ANALYZABLE"
            return
            ;;
    esac

    # Default: skip unrecognized types
    echo "SKIP_OTHER"
}

# ── Queue management ──────────────────────────────────────────────

enqueue_file() {
    local hash="$1"
    local filepath="$2"
    local mime="$3"
    # Write queue entry as a file named by hash
    printf '%s\t%s\n' "$filepath" "$mime" > "${WATCH_QUEUE_DIR}/${hash}"
}

dequeue_all() {
    # Output all queued entries and remove them
    local count=0
    for qfile in "${WATCH_QUEUE_DIR}"/*; do
        [[ -f "$qfile" ]] || continue
        local hash
        hash="$(basename "$qfile")"
        local content
        content="$(cat "$qfile")"
        local filepath mime
        filepath="$(echo "$content" | cut -f1)"
        mime="$(echo "$content" | cut -f2)"
        printf '%s\t%s\t%s\n' "$hash" "$filepath" "$mime"
        rm -f "$qfile"
        (( count++ )) || true
        if [[ "$count" -ge "$WATCH_BATCH_SIZE" ]]; then
            break
        fi
    done
}

queue_size() {
    local count=0
    for qfile in "${WATCH_QUEUE_DIR}"/*; do
        [[ -f "$qfile" ]] || continue
        (( count++ )) || true
    done
    echo "$count"
}

# ── Alert writing ─────────────────────────────────────────────────

write_alert() {
    local severity="$1"
    local hash="$2"
    local filepath="$3"
    local detail="$4"

    local timestamp
    timestamp="$(date +%Y-%m-%d-%H%M%S)"
    local alert_file="${WATCH_FINDINGS_DIR}/watch-${timestamp}-${severity,,}.md"

    cat > "$alert_file" <<EOF
# Watch Alert: ${severity}

- **Time**: $(date -Iseconds)
- **File**: ${filepath}
- **SHA256**: ${hash}
- **Detail**: ${detail}

---

*Generated by secy watch mode*
EOF

    secy_log "watch" "${severity}: ${filepath} — ${detail} (${alert_file})"
}

# ── Directive reload ─────────────────────────────────────────────
#
# Checks state/directives/watch-config.conf for changes.
# Reloads WATCH_SCAN_DEPTH and WATCH_EXTRA_DIRS if the file has been
# updated since last check.

check_watch_directives() {
    # Check persistent watch-config.conf
    _check_watch_config

    # Process one-shot directive files
    _process_watch_directive_files
}

_check_watch_config() {
    [[ -f "$WATCH_DIRECTIVES_FILE" ]] || return 0

    local current_mtime
    current_mtime="$(stat -c%Y "$WATCH_DIRECTIVES_FILE" 2>/dev/null || echo 0)"

    if [[ "$current_mtime" -le "$_WATCH_DIRECTIVE_MTIME" ]]; then
        return 0
    fi

    _WATCH_DIRECTIVE_MTIME="$current_mtime"
    secy_log "watch" "Reloading directives from ${WATCH_DIRECTIVES_FILE}"

    while IFS= read -r line; do
        # Skip comments and blank lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// /}" ]] && continue

        local key value
        key="$(echo "$line" | cut -d'=' -f1 | tr -d '[:space:]')"
        value="$(echo "$line" | cut -d'=' -f2-)"
        value="$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

        case "$key" in
            scan_depth)
                if [[ "$value" =~ ^[0-9]+$ ]]; then
                    WATCH_SCAN_DEPTH="$value"
                    secy_log "watch" "Directive: scan_depth=${value}"
                fi
                ;;
            extra_dirs)
                WATCH_EXTRA_DIRS="$value"
                secy_log "watch" "Directive: extra_dirs=${value}"
                ;;
        esac
    done < "$WATCH_DIRECTIVES_FILE"
}

_process_watch_directive_files() {
    local directives_dir="${STATE_DIR}/directives/active"
    local applied_dir="${STATE_DIR}/directives/applied"
    [[ -d "$directives_dir" ]] || return 0

    for dfile in "${directives_dir}"/*.watch-directive; do
        [[ -f "$dfile" ]] || continue

        local basename
        basename="$(basename "$dfile")"
        secy_log "watch" "Processing directive: ${basename}"

        local applied_changes=""
        local apply_errors=""

        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line// /}" ]] && continue

            local key value
            key="$(echo "$line" | cut -d'=' -f1 | tr -d '[:space:]')"
            value="$(echo "$line" | cut -d'=' -f2-)"
            value="$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

            case "$key" in
                scan_depth)
                    if [[ "$value" =~ ^[0-9]+$ ]]; then
                        local old_val="$WATCH_SCAN_DEPTH"
                        WATCH_SCAN_DEPTH="$value"
                        applied_changes+="  scan_depth: ${old_val} -> ${value}\n"
                        secy_log "watch" "Directive: scan_depth=${value}"
                    else
                        apply_errors+="  scan_depth: invalid value '${value}'\n"
                    fi
                    ;;
                extra_dirs)
                    local old_val="$WATCH_EXTRA_DIRS"
                    WATCH_EXTRA_DIRS="$value"
                    applied_changes+="  extra_dirs: '${old_val}' -> '${value}'\n"
                    secy_log "watch" "Directive: extra_dirs=${value}"
                    ;;
                *)
                    apply_errors+="  ${key}: unknown key\n"
                    ;;
            esac
        done < "$dfile"

        # Move to applied/
        mkdir -p "$applied_dir"
        mv "$dfile" "${applied_dir}/${basename}" 2>/dev/null || true

        # Write application report
        {
            echo "# Directive Application Report"
            echo ""
            echo "- **Directive**: ${basename}"
            echo "- **Service**: watch"
            echo "- **Timestamp**: $(date -Iseconds)"
            echo "- **Status**: $(if [[ -n "$apply_errors" ]]; then echo "partial"; else echo "applied"; fi)"
            echo ""
            if [[ -n "$applied_changes" ]]; then
                echo "## Changes Applied"
                echo ""
                printf "%b" "$applied_changes"
                echo ""
            fi
            if [[ -n "$apply_errors" ]]; then
                echo "## Errors"
                echo ""
                printf "%b" "$apply_errors"
                echo ""
            fi
            if [[ -z "$applied_changes" ]] && [[ -z "$apply_errors" ]]; then
                echo "## Result"
                echo ""
                echo "  No actionable entries found in directive."
                echo ""
            fi
        } > "${applied_dir}/${basename}.report"

        secy_log "watch" "Directive applied: ${basename} (report written)"
    done
}
