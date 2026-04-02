#!/usr/bin/env bash
# agent/watch.sh — Download monitoring daemon
#
# Continuously watches /host/home/*/Downloads/ for new files, checks
# hashes against a local malware database, and optionally triggers
# Claude AI analysis for unknown analyzable files.
#
# Usage:
#   watch.sh [--no-claude] [--poll-interval N]

set -euo pipefail

AGENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${AGENT_DIR}/lib/watch-common.sh"
source "${AGENT_DIR}/lib/inotify-watch.sh"

# ── Flag parsing ─────────────────────────────────────────────────

NO_CLAUDE=false
POLL_OVERRIDE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-claude)
            NO_CLAUDE=true
            shift
            ;;
        --poll-interval)
            if [[ $# -lt 2 ]]; then
                echo "ERROR: --poll-interval requires a value" >&2; exit 1
            fi
            if ! [[ "$2" =~ ^[0-9]+$ ]]; then
                echo "ERROR: --poll-interval requires a numeric value" >&2; exit 1
            fi
            POLL_OVERRIDE="$2"
            shift 2
            ;;
        --help|-h)
            echo "secy watch — Download monitoring daemon"
            echo ""
            echo "Usage: secy watch [--no-claude] [--poll-interval N]"
            echo ""
            echo "Options:"
            echo "  --no-claude        Hash-check only, skip AI analysis"
            echo "  --poll-interval N  Override poll interval (default: ${WATCH_POLL_INTERVAL}s)"
            echo ""
            echo "Watches /host/home/*/Downloads/ for new files."
            echo "Checks SHA256 against local malware DB (MalwareBazaar)."
            echo "Queues unknown analyzable files for Claude triage."
            exit 0
            ;;
        *)
            echo "ERROR: Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

if [[ -n "$POLL_OVERRIDE" ]]; then
    WATCH_POLL_INTERVAL="$POLL_OVERRIDE"
fi

# ── Preflight ────────────────────────────────────────────────────

preflight_watch() {
    preflight_core

    if ! command -v sha256sum &>/dev/null; then
        secy_log "watch" "ERROR: sha256sum not found"
        exit 1
    fi

    if ! command -v file &>/dev/null; then
        secy_log "watch" "WARNING: file(1) not found — classification will be limited"
    fi

    if [[ "$NO_CLAUDE" != "true" ]]; then
        if ! command -v claude &>/dev/null; then
            secy_log "watch" "WARNING: claude not found — falling back to --no-claude mode"
            NO_CLAUDE=true
        fi
    fi

    # Verify at least one Downloads directory exists
    local found=false
    for dl in /host/home/*/Downloads; do
        if [[ -d "$dl" ]]; then
            found=true
            break
        fi
    done
    if [[ "$found" != "true" ]]; then
        secy_log "watch" "WARNING: No Downloads directories found at /host/home/*/Downloads/"
    fi
}

# ── Scan cycle ───────────────────────────────────────────────────

scan_downloads() {
    local new_files=0
    local hash_matches=0
    local queued=0
    local skipped=0

    # Build list of directories to scan: standard Downloads + extra dirs from C2
    local scan_dirs=()
    for dl_dir in /host/home/*/Downloads; do
        [[ -d "$dl_dir" ]] && scan_dirs+=("$dl_dir")
    done
    if [[ -n "$WATCH_EXTRA_DIRS" ]]; then
        for extra_dir in $WATCH_EXTRA_DIRS; do
            [[ -d "$extra_dir" ]] && scan_dirs+=("$extra_dir")
        done
    fi

    for dl_dir in "${scan_dirs[@]}"; do

        # Find files (maxdepth 1 — don't recurse into subdirectories)
        while IFS= read -r -d '' filepath; do
            [[ -f "$filepath" ]] || continue

            local filesize
            filesize="$(stat -c%s "$filepath" 2>/dev/null || echo 0)"

            # Skip files still being written (modified <2s ago)
            local mtime now age
            mtime="$(stat -c%Y "$filepath" 2>/dev/null || echo 0)"
            now="$(date +%s)"
            age=$(( now - mtime ))
            if [[ "$age" -lt 2 ]]; then
                continue
            fi

            # Skip if already seen with same size
            if is_file_seen "$filepath" "$filesize"; then
                continue
            fi

            # Check if size changed since last seen (partial download completed)
            local prev_size
            prev_size="$(get_seen_size "$filepath")"
            if [[ -n "$prev_size" ]] && [[ "$prev_size" != "$filesize" ]]; then
                secy_log "watch" "Size changed: ${filepath} (${prev_size} -> ${filesize}), re-hashing"
            fi

            (( new_files++ )) || true

            # Compute SHA256
            local hash
            hash="$(sha256sum "$filepath" 2>/dev/null | awk '{print $1}')"
            if [[ -z "$hash" ]]; then
                secy_log "watch" "WARNING: Failed to hash ${filepath} (file may have been removed)"
                continue
            fi

            # Check against malware DB
            local lookup_result=""
            if command -v sread &>/dev/null; then
                lookup_result="$(sread hashlookup "$hash" 2>/dev/null)" || true
            fi

            if echo "$lookup_result" | grep -q '^\[MATCH\]'; then
                (( hash_matches++ )) || true
                write_alert "CRITICAL" "$hash" "$filepath" "SHA256 matches known malware in MalwareBazaar database"
                mark_file_seen "$hash" "$filesize" "$filepath"
                continue
            fi

            # Mark as seen
            mark_file_seen "$hash" "$filesize" "$filepath"

            # Re-check file exists before classification (file may have been
            # deleted/renamed between hashing and here)
            if [[ ! -f "$filepath" ]]; then
                secy_log "watch" "File disappeared after hash: ${filepath}"
                continue
            fi

            # Classify file for analysis
            local classification
            classification="$(classify_file "$filepath")"

            case "$classification" in
                ANALYZABLE)
                    if [[ "$NO_CLAUDE" != "true" ]]; then
                        local mime
                        mime="$(file --mime-type -b "$filepath" 2>/dev/null || echo 'unknown')"
                        enqueue_file "$hash" "$filepath" "$mime"
                        (( queued++ )) || true
                        secy_log "watch" "Queued for analysis: ${filepath} (${mime})"
                    else
                        secy_log "watch" "New file (no-claude): ${filepath} [${classification}]"
                    fi
                    ;;
                SKIP_MEDIA)
                    (( skipped++ )) || true
                    ;;
                SKIP_TINY|SKIP_LARGE|SKIP_OTHER)
                    (( skipped++ )) || true
                    secy_log "watch" "Skipped: ${filepath} [${classification}]"
                    ;;
            esac

        done < <(find "$dl_dir" -maxdepth "${WATCH_SCAN_DEPTH}" -not -path '*/secy-ignore/*' -type f -print0 2>/dev/null)
    done

    # Return counts via globals (bash can't return multiple values)
    _SCAN_NEW=$new_files
    _SCAN_MATCHES=$hash_matches
    _SCAN_QUEUED=$queued
    _SCAN_SKIPPED=$skipped
}

# ── Claude analysis batch ────────────────────────────────────────

analyze_batch() {
    local batch_data
    batch_data="$(dequeue_all)"

    if [[ -z "$batch_data" ]]; then
        return
    fi

    local file_count
    file_count="$(echo "$batch_data" | wc -l)"
    secy_log "watch" "Analyzing batch of ${file_count} file(s) with Claude"

    local timestamp
    timestamp="$(date +%Y-%m-%d-%H%M%S)"
    local findings_file="${WATCH_FINDINGS_DIR}/watch-triage-${timestamp}.md"

    # Gather file info for each queued file
    local file_table=""
    local file_details=""

    while IFS=$'\t' read -r hash filepath mime; do
        [[ -n "$hash" ]] || continue

        file_table+="| ${filepath##*/} | ${mime} | ${hash} |
"
        # Get detailed info via sread fileinfo
        local info=""
        if command -v sread &>/dev/null; then
            info="$(sread fileinfo "$filepath" 2>/dev/null)" || info="(fileinfo failed)"
        fi

        file_details+="
## File: ${filepath##*/}
- **Path**: ${filepath}
- **SHA256**: ${hash}
- **MIME**: ${mime}

\`\`\`
${info}
\`\`\`

"
    done <<< "$batch_data"

    # Assemble prompt
    local watch_prompt="${AGENT_DIR}/WATCH.md"
    if [[ ! -f "$watch_prompt" ]]; then
        secy_log "watch" "ERROR: Watch prompt not found at ${watch_prompt}"
        return
    fi

    local system_prompt
    system_prompt="$(cat "$watch_prompt")"

    local prompt="## Malware Triage Task

Analyze the following ${file_count} file(s) recently downloaded to the host system.

### File Summary

| Filename | MIME Type | SHA256 |
|----------|-----------|--------|
${file_table}

All files have been checked against the MalwareBazaar SHA256 database — none matched known malware. Your job is to assess whether they are CLEAN, SUSPICIOUS, or MALICIOUS based on their metadata and content.

### File Details

${file_details}

### Instructions

1. Assess each file based on the metadata above
2. If you need more information, use \`sread fileinfo <path>\` or \`sread hash <path>\`
3. Do NOT read raw file content — triage from metadata, structure, and indicators only
4. Write your triage report to: ${findings_file}
5. Output SECY_COMPLETE when done
"

    # Watch uses restricted tool set — no Read tool to prevent prompt injection
    # from untrusted file content. Claude triages from sread metadata only.
    local _saved_tools="$ALLOWED_TOOLS"
    ALLOWED_TOOLS="Bash,Write,Grep,Glob"
    invoke_claude "$system_prompt" "$prompt" "$MAX_BUDGET_USD" > /dev/null
    ALLOWED_TOOLS="$_saved_tools"

    if [[ -f "$findings_file" ]]; then
        secy_log "watch" "Triage report written: ${findings_file}"
    else
        secy_log "watch" "WARNING: Claude did not write findings to ${findings_file}"
    fi
}

# ── Event callback ───────────────────────────────────────────────
#
# Called by watch_directory_loop on each inotify event or poll tick.
# Runs the same scan+analyze logic, just triggered by callback.

_WATCH_LAST_DIRECTIVE_CHECK=0

on_watch_event() {
    local _event="$1"
    local _filename="$2"

    # Periodically check for C2 directives
    local now
    now="$(date +%s)"
    local elapsed=$(( now - _WATCH_LAST_DIRECTIVE_CHECK ))
    if [[ $elapsed -ge $DIRECTIVE_CHECK_INTERVAL ]]; then
        check_watch_directives
        _WATCH_LAST_DIRECTIVE_CHECK="$now"
    fi

    # Scan for new files
    _SCAN_NEW=0 _SCAN_MATCHES=0 _SCAN_QUEUED=0 _SCAN_SKIPPED=0
    scan_downloads

    if [[ $_SCAN_NEW -gt 0 ]]; then
        secy_log "watch" "Scan: ${_SCAN_NEW} new, ${_SCAN_MATCHES} malware match(es), ${_SCAN_QUEUED} queued, ${_SCAN_SKIPPED} skipped"
    fi

    # If there are queued files and Claude is enabled, analyze them
    if [[ "$NO_CLAUDE" != "true" ]]; then
        local qsize
        qsize="$(queue_size)"
        if [[ "$qsize" -gt 0 ]]; then
            analyze_batch
        fi
    fi
}

# ── Main daemon loop ─────────────────────────────────────────────

main() {
    preflight_watch
    init_watch_state
    daemon_init

    secy_log "watch" "Watch daemon starting"
    secy_log "watch" "  Poll interval: ${WATCH_POLL_INTERVAL}s"
    secy_log "watch" "  Max file size: ${WATCH_MAX_FILE_SIZE} bytes"
    secy_log "watch" "  Batch size:    ${WATCH_BATCH_SIZE}"
    secy_log "watch" "  Scan depth:    ${WATCH_SCAN_DEPTH}"
    secy_log "watch" "  Claude:        $(if [[ "$NO_CLAUDE" == "true" ]]; then echo "disabled"; else echo "enabled"; fi)"
    secy_log "watch" "  Scanning:      /host/home/*/Downloads/"

    # Find the first valid Downloads dir for inotify probe target
    local primary_watch_dir=""
    for dl in /host/home/*/Downloads; do
        if [[ -d "$dl" ]]; then
            primary_watch_dir="$dl"
            break
        fi
    done

    if [[ -z "$primary_watch_dir" ]]; then
        secy_log "watch" "No Downloads directories found — falling back to poll mode"
        primary_watch_dir="/host/home"
    fi

    # Collect extra watch dirs (remaining Downloads dirs beyond the primary)
    local extra_watch_dirs=()
    for dl in /host/home/*/Downloads; do
        [[ -d "$dl" ]] || continue
        [[ "$dl" == "$primary_watch_dir" ]] && continue
        extra_watch_dirs+=("$dl")
    done

    watch_directory_loop \
        "$primary_watch_dir" \
        "on_watch_event" \
        "$WATCH_POLL_INTERVAL" \
        "watch" \
        "${extra_watch_dirs[@]}"

    secy_log "watch" "Watch daemon stopped"
}

main
