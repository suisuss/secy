#!/usr/bin/env bash
# agent/lib/inotify-watch.sh — Shared inotify + poll fallback utility
#
# Provides watch_directory_loop() used by both watch and C2 daemons.
# Probes inotify at startup; falls back to polling if it fails
# (common on Docker bind mounts across kernel versions).

# ── inotify probe ───────────────────────────────────────────────
# Creates a temp file in the target dir, runs inotifywait with a short
# timeout, checks if the create event was detected.
# Returns 0 (inotify works) or 1 (fall back to poll).

probe_inotify() {
    local dir="$1"
    local tag="${2:-inotify}"

    if ! command -v inotifywait &>/dev/null; then
        secy_log "$tag" "inotifywait not found — using poll fallback"
        return 1
    fi

    if [[ ! -d "$dir" ]]; then
        secy_log "$tag" "Probe dir ${dir} does not exist — using poll fallback"
        return 1
    fi

    # Start inotifywait in background watching for CREATE events
    local probe_out
    probe_out="$(mktemp)"
    inotifywait -t 3 -e create "$dir" > "$probe_out" 2>/dev/null &
    local inotify_pid=$!

    # Give inotifywait a moment to set up its watch
    sleep 0.5

    # Create a probe file to trigger the event
    local probe_file="${dir}/.inotify-probe-$$"
    touch "$probe_file" 2>/dev/null
    rm -f "$probe_file" 2>/dev/null

    # Wait for inotifywait to finish (it should exit on the event or timeout)
    wait "$inotify_pid" 2>/dev/null || true

    local result
    if grep -q "CREATE" "$probe_out" 2>/dev/null; then
        secy_log "$tag" "inotify probe succeeded — using event-driven mode"
        result=0
    else
        secy_log "$tag" "inotify probe failed — using poll fallback"
        result=1
    fi

    rm -f "$probe_out"
    return $result
}

# ── Directory watch loop ────────────────────────────────────────
# Watches a directory for file events, calling a callback on each.
# Falls back to polling if inotify is unavailable or broken.
#
# Usage: watch_directory_loop DIR CALLBACK POLL_INTERVAL TAG [EXTRA_DIRS...]
#   DIR            — primary directory to watch
#   CALLBACK       — function name: called as callback(event, filename)
#                    event is one of: CREATE, CLOSE_WRITE, MOVED_TO, POLL
#   POLL_INTERVAL  — seconds between polls (also inotifywait timeout)
#   TAG            — log tag (e.g. "watch", "c2")
#   EXTRA_DIRS     — additional directories to watch (optional)

watch_directory_loop() {
    local dir="$1"
    local callback="$2"
    local poll_interval="$3"
    local tag="$4"
    shift 4
    local extra_dirs=("$@")

    local use_inotify=false
    if probe_inotify "$dir" "$tag"; then
        use_inotify=true
    fi

    if [[ "$use_inotify" == "true" ]]; then
        _watch_inotify_loop "$dir" "$callback" "$poll_interval" "$tag" "${extra_dirs[@]}"
    else
        _watch_poll_loop "$dir" "$callback" "$poll_interval" "$tag"
    fi
}

# ── inotify-based loop (internal) ──────────────────────────────

_watch_inotify_loop() {
    local dir="$1"
    local callback="$2"
    local poll_interval="$3"
    local tag="$4"
    shift 4
    local extra_dirs=("$@")

    # Build the list of directories to watch
    local watch_dirs=("$dir")
    for d in "${extra_dirs[@]}"; do
        [[ -d "$d" ]] && watch_dirs+=("$d")
    done

    secy_log "$tag" "inotify watching: ${watch_dirs[*]}"

    while [[ "$SECY_DAEMON_RUNNING" == "true" ]]; do
        # inotifywait blocks until an event occurs or timeout expires.
        # -t timeout ensures we re-check SECY_DAEMON_RUNNING periodically.
        # -r for recursive, -q for quiet, --format for parseable output.
        local inotify_output=""
        inotify_output="$(inotifywait \
            -t "$poll_interval" \
            -r \
            -q \
            --format '%e %f' \
            -e close_write \
            -e create \
            -e moved_to \
            "${watch_dirs[@]}" 2>/dev/null)" || true

        [[ "$SECY_DAEMON_RUNNING" == "true" ]] || break

        if [[ -n "$inotify_output" ]]; then
            # Process each event line
            while IFS= read -r line; do
                [[ -n "$line" ]] || continue
                local event filename
                event="$(echo "$line" | cut -d' ' -f1)"
                filename="$(echo "$line" | cut -d' ' -f2-)"
                "$callback" "$event" "$filename"
            done <<< "$inotify_output"
        else
            # Timeout — fire a poll event so the callback can do periodic work
            "$callback" "POLL" ""
        fi
    done
}

# ── Poll-based loop (internal) ──────────────────────────────────

_watch_poll_loop() {
    local dir="$1"
    local callback="$2"
    local poll_interval="$3"
    local tag="$4"

    secy_log "$tag" "Poll mode: checking every ${poll_interval}s"

    while [[ "$SECY_DAEMON_RUNNING" == "true" ]]; do
        "$callback" "POLL" ""
        interruptible_sleep "$poll_interval"
    done
}
