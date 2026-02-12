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
    if [[ $EUID -ne 0 ]]; then
        watch_log "ERROR: watch must run as root (run inside Docker container)"
        exit 1
    fi

    if [[ ! -d "/host/etc" ]]; then
        watch_log "ERROR: Host filesystem not found at /host"
        exit 1
    fi

    if ! command -v sha256sum &>/dev/null; then
        watch_log "ERROR: sha256sum not found"
        exit 1
    fi

    if ! command -v file &>/dev/null; then
        watch_log "WARNING: file(1) not found — classification will be limited"
    fi

    if [[ "$NO_CLAUDE" != "true" ]]; then
        if ! command -v claude &>/dev/null; then
            watch_log "WARNING: claude not found — falling back to --no-claude mode"
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
        watch_log "WARNING: No Downloads directories found at /host/home/*/Downloads/"
    fi
}

# ── Scan cycle ───────────────────────────────────────────────────

scan_downloads() {
    local new_files=0
    local hash_matches=0
    local queued=0
    local skipped=0

    for dl_dir in /host/home/*/Downloads; do
        [[ -d "$dl_dir" ]] || continue

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
                watch_log "Size changed: ${filepath} (${prev_size} -> ${filesize}), re-hashing"
            fi

            (( new_files++ ))

            # Compute SHA256
            local hash
            hash="$(sha256sum "$filepath" 2>/dev/null | awk '{print $1}')" || {
                watch_log "WARNING: Failed to hash ${filepath}"
                continue
            }

            # Check against malware DB
            local lookup_result=""
            if command -v sread &>/dev/null; then
                lookup_result="$(sread hashlookup "$hash" 2>/dev/null)" || true
            fi

            if echo "$lookup_result" | grep -q '^\[MATCH\]'; then
                (( hash_matches++ ))
                write_alert "CRITICAL" "$hash" "$filepath" "SHA256 matches known malware in MalwareBazaar database"
                mark_file_seen "$hash" "$filesize" "$filepath"
                continue
            fi

            # Mark as seen
            mark_file_seen "$hash" "$filesize" "$filepath"

            # Classify file for analysis
            local classification
            classification="$(classify_file "$filepath")"

            case "$classification" in
                ANALYZABLE)
                    if [[ "$NO_CLAUDE" != "true" ]]; then
                        local mime
                        mime="$(file --mime-type -b "$filepath" 2>/dev/null || echo 'unknown')"
                        enqueue_file "$hash" "$filepath" "$mime"
                        (( queued++ ))
                        watch_log "Queued for analysis: ${filepath} (${mime})"
                    else
                        watch_log "New file (no-claude): ${filepath} [${classification}]"
                    fi
                    ;;
                SKIP_MEDIA)
                    (( skipped++ ))
                    ;;
                SKIP_TINY|SKIP_LARGE|SKIP_OTHER)
                    (( skipped++ ))
                    watch_log "Skipped: ${filepath} [${classification}]"
                    ;;
            esac

        done < <(find "$dl_dir" -maxdepth "${WATCH_SCAN_DEPTH}" -type f -print0 2>/dev/null)
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
    watch_log "Analyzing batch of ${file_count} file(s) with Claude"

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
        watch_log "ERROR: Watch prompt not found at ${watch_prompt}"
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

1. Read each file's metadata above carefully
2. If you need more information, use \`sread fileinfo <path>\` or \`sread hash <path>\`
3. For text-like files, you may use the Read tool to inspect content directly
4. Write your triage report to: ${findings_file}
5. Output SECY_COMPLETE when done
"

    # Build claude command
    local claude_cmd="claude"
    if command -v srt &>/dev/null; then
        if srt -- echo srt-ok >/dev/null 2>&1; then
            claude_cmd="srt claude"
        fi
    fi

    local stream_formatter="${AGENT_DIR}/lib/format-stream.sh"

    $claude_cmd \
        --dangerously-skip-permissions \
        --print \
        --verbose \
        --output-format stream-json \
        --model "$CLAUDE_MODEL" \
        --max-budget-usd "$MAX_BUDGET_USD" \
        --tools "$ALLOWED_TOOLS" \
        --system-prompt "$system_prompt" \
        -p "$prompt" \
        | bash "$stream_formatter" >&2 || true

    if [[ -f "$findings_file" ]]; then
        watch_log "Triage report written: ${findings_file}"
    else
        watch_log "WARNING: Claude did not write findings to ${findings_file}"
    fi
}

# ── Signal handling ──────────────────────────────────────────────

RUNNING=true

cleanup() {
    RUNNING=false
    watch_log "Shutting down (received signal)"
}

trap cleanup SIGTERM SIGINT SIGHUP

# ── Main daemon loop ─────────────────────────────────────────────

main() {
    preflight_watch
    init_watch_state

    watch_log "Watch daemon starting"
    watch_log "  Poll interval: ${WATCH_POLL_INTERVAL}s"
    watch_log "  Max file size: ${WATCH_MAX_FILE_SIZE} bytes"
    watch_log "  Batch size:    ${WATCH_BATCH_SIZE}"
    watch_log "  Scan depth:    ${WATCH_SCAN_DEPTH}"
    watch_log "  Claude:        $(if [[ "$NO_CLAUDE" == "true" ]]; then echo "disabled"; else echo "enabled"; fi)"
    watch_log "  Scanning:      /host/home/*/Downloads/"

    while [[ "$RUNNING" == "true" ]]; do
        # Scan for new files
        _SCAN_NEW=0 _SCAN_MATCHES=0 _SCAN_QUEUED=0 _SCAN_SKIPPED=0
        scan_downloads

        if [[ $_SCAN_NEW -gt 0 ]]; then
            watch_log "Scan: ${_SCAN_NEW} new, ${_SCAN_MATCHES} malware match(es), ${_SCAN_QUEUED} queued, ${_SCAN_SKIPPED} skipped"
        fi

        # If there are queued files and Claude is enabled, analyze them
        if [[ "$NO_CLAUDE" != "true" ]]; then
            local qsize
            qsize="$(queue_size)"
            if [[ "$qsize" -gt 0 ]]; then
                analyze_batch
            fi
        fi

        # Sleep with interruptible wait
        local i=0
        while [[ "$RUNNING" == "true" ]] && [[ $i -lt $WATCH_POLL_INTERVAL ]]; do
            sleep 1
            (( i++ ))
        done
    done

    watch_log "Watch daemon stopped"
}

main
