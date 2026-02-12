# Plan: Unify agent/ under secy-common.sh

## Context

The agent/ directory has three independent codepaths (audit/baseline/monitor, watch, patrol) that each maintain their own bootstrap, logging, preflight, and Claude invocation code. As modes were added, shared logic was copy-pasted rather than extracted. This refactor creates a single foundation file that all modes inherit from, eliminating ~80 lines of duplication and ensuring consistent behavior (e.g., all modes get persistent file logging, not just daemons).

## What moves to secy-common.sh

| Function | Current location(s) | Notes |
|----------|---------------------|-------|
| Bootstrap (AGENT_DIR, SREAD_ROOT, source agent.conf) | agent-common.sh:1-13, watch-common.sh:1-12, patrol-common.sh:1-12 | Identical in all three |
| `secy_log(tag, msg)` | `log_agent()`, `watch_log()`, `patrol_log()` | Unify into one function with tag parameter. Always writes to file + stderr. Rotation at 1MB. |
| `preflight_core()` | `preflight_check()`, `preflight_watch()`, `preflight_patrol()` | Extract common: root check + /host check. Each mode adds own checks on top. |
| `invoke_claude(system_prompt, prompt, budget)` | secy.sh:99-127, watch.sh:278-298, patrol-common.sh:346-365 | Identical srt probe + claude invocation + stream formatter pipe. One function. |
| `daemon_init(tag)` | watch.sh:309-316, patrol.sh:104-111 | Sets RUNNING=true, trap cleanup SIGTERM/SIGINT/SIGHUP |
| `interruptible_sleep(seconds)` | watch.sh:351-355, patrol.sh:172-175 | 1s tick loop checking RUNNING |

## What stays mode-specific

- `agent-common.sh`: `assemble_prompt()`, `check_completion()`, `acquire_lock()`/`release_lock()`, `ensure_state_dirs()`
- `watch-common.sh`: seen.db ops, `classify_file()`, queue management, `write_alert()`
- `patrol-common.sh`: schedule parsing, `run_module()`, diff management, review gate logic

## Implementation

### 1. Create `agent/lib/secy-common.sh`

```bash
#!/usr/bin/env bash
# agent/lib/secy-common.sh — Foundation shared by all secy modes

set -euo pipefail

AGENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${SREAD_ROOT:-}" ]]; then
    SREAD_ROOT="$(cd "${AGENT_DIR}/../sread" && pwd)"
fi
export SREAD_ROOT

source "${AGENT_DIR}/conf/agent.conf"

# ── Logging ──────────────────────────────────────────────────────
# Usage: secy_log "tag" "message"
#   secy_log "watch" "Starting scan"  →  [secy:watch 2026-...] Starting scan
#   secy_log "" "Starting audit"      →  [secy 2026-...] Starting audit

SECY_LOG_DIR="${STATE_DIR}"
SECY_LOG_MAX_SIZE=1048576  # 1MB

secy_log() {
    local tag="$1"; shift
    local prefix
    if [[ -n "$tag" ]]; then
        prefix="[secy:${tag} $(date -Iseconds)]"
    else
        prefix="[secy $(date -Iseconds)]"
    fi
    local msg="${prefix} $*"
    echo "$msg" >&2

    # Persistent file logging (best-effort)
    local logfile="${SECY_LOG_DIR}/secy.log"
    if [[ -d "$SECY_LOG_DIR" ]]; then
        if [[ -f "$logfile" ]] && [[ "$(stat -c%s "$logfile" 2>/dev/null || echo 0)" -gt $SECY_LOG_MAX_SIZE ]]; then
            mv "$logfile" "${logfile}.1" 2>/dev/null || true
        fi
        echo "$msg" >> "$logfile" 2>/dev/null || true
    fi
}

# ── Preflight (common checks) ───────────────────────────────────

preflight_core() {
    if [[ $EUID -ne 0 ]]; then
        secy_log "" "ERROR: secy must run as root (run inside Docker container)"
        exit 1
    fi
    if [[ ! -d "/host/etc" ]]; then
        secy_log "" "ERROR: Host filesystem not found at /host"
        secy_log "" "       Run via: docker compose run secy <mode>"
        exit 1
    fi
}

# ── Claude invocation ────────────────────────────────────────────
# Usage: invoke_claude "$system_prompt" "$prompt" "$budget"
# Probes srt, invokes claude with stream-json, pipes through format-stream.sh.
# Returns the raw stream-json output on stdout.

invoke_claude() {
    local system_prompt="$1"
    local prompt="$2"
    local budget="$3"

    local claude_cmd="claude"
    if command -v srt &>/dev/null; then
        if srt -- echo srt-ok >/dev/null 2>&1; then
            claude_cmd="srt claude"
            secy_log "" "Using srt sandbox"
        else
            secy_log "" "srt available but sandbox failed (Docker is the sandbox boundary)"
        fi
    else
        secy_log "" "Running without srt (Docker is the sandbox boundary)"
    fi

    local stream_formatter="${AGENT_DIR}/lib/format-stream.sh"
    local raw_json
    raw_json="$(mktemp)"

    $claude_cmd \
        --dangerously-skip-permissions \
        --print \
        --verbose \
        --output-format stream-json \
        --model "$CLAUDE_MODEL" \
        --max-budget-usd "$budget" \
        --tools "$ALLOWED_TOOLS" \
        --system-prompt "$system_prompt" \
        -p "$prompt" \
        | tee "$raw_json" \
        | bash "$stream_formatter" >&2 || true

    cat "$raw_json"
    rm -f "$raw_json"
}

# ── Daemon utilities ─────────────────────────────────────────────
# Used by watch.sh and patrol.sh — not by the Ralph loop modes.

SECY_DAEMON_RUNNING=true

daemon_init() {
    SECY_DAEMON_RUNNING=true
    trap '_daemon_cleanup' SIGTERM SIGINT SIGHUP
}

_daemon_cleanup() {
    SECY_DAEMON_RUNNING=false
    secy_log "" "Shutting down (received signal)"
}

interruptible_sleep() {
    local seconds="$1"
    local i=0
    while [[ "$SECY_DAEMON_RUNNING" == "true" ]] && [[ $i -lt $seconds ]]; do
        sleep 1
        (( i++ ))
    done
}
```

### 2. Update `agent/lib/agent-common.sh`

- Remove bootstrap block (lines 1-13), replace with `source "${BASH_SOURCE[0]%/*}/secy-common.sh"`
- Remove `log_agent()`, replace all calls with `secy_log "" "msg"`
- Remove `preflight_check()`, replace with `preflight_core` + mode-specific checks (claude/srt/sread) inline
- Keep: `ensure_state_dirs()`, `acquire_lock()`/`release_lock()`, `assemble_prompt()`, `check_completion()`

### 3. Update `agent/lib/watch-common.sh`

- Remove bootstrap block (lines 1-12), replace with `source "${BASH_SOURCE[0]%/*}/secy-common.sh"`
- Remove `watch_log()`, replace all calls with `secy_log "watch" "msg"`
- Keep everything else (seen.db, classify, queue, alerts)
- Update `write_alert()` to use `secy_log` instead of `watch_log`

### 4. Update `agent/lib/patrol-common.sh`

- Remove bootstrap block (lines 1-12), replace with `source "${BASH_SOURCE[0]%/*}/secy-common.sh"`
- Remove `patrol_log()`, replace all calls with `secy_log "patrol" "msg"`
- Keep everything else (schedule, module exec, diffs, review gate)
- Update `run_claude_review()` to use `invoke_claude()` instead of inline claude invocation

### 5. Update `agent/secy.sh`

- Update `run_agent()` to use `invoke_claude()` instead of inline claude invocation (lines 99-131 replaced by ~3 lines)
- Replace `log_agent` calls with `secy_log ""`

### 6. Update `agent/watch.sh`

- Replace `watch_log` calls with `secy_log "watch"`
- Replace inline claude invocation in `analyze_batch()` with `invoke_claude()`
- Replace signal handling block with `daemon_init`
- Replace interruptible sleep loop with `interruptible_sleep $WATCH_POLL_INTERVAL`
- Replace `RUNNING` checks with `SECY_DAEMON_RUNNING`
- Remove `preflight_watch()`, replace with `preflight_core` + mode-specific checks inline

### 7. Update `agent/patrol.sh`

- Replace `patrol_log` calls with `secy_log "patrol"`
- Replace signal handling block with `daemon_init`
- Replace interruptible sleep loop with `interruptible_sleep $PATROL_TICK_INTERVAL`
- Replace `RUNNING` checks with `SECY_DAEMON_RUNNING`
- Remove `preflight_patrol()`, replace with `preflight_core` + mode-specific checks inline

## Files

| Action | Path |
|--------|------|
| Create | `agent/lib/secy-common.sh` |
| Modify | `agent/lib/agent-common.sh` |
| Modify | `agent/lib/watch-common.sh` |
| Modify | `agent/lib/patrol-common.sh` |
| Modify | `agent/secy.sh` |
| Modify | `agent/watch.sh` |
| Modify | `agent/patrol.sh` |

No changes to: agent.conf, Dockerfile, docker-compose.yml, entrypoint.sh, any .md prompts, sread/.

## Verification

1. **Syntax check**: `bash -n` on all 7 modified/created files
2. **Logging**: `source agent/lib/secy-common.sh && secy_log "test" "hello"` — verify stderr output and file write to state dir
3. **Existing modes preserved**: `secy.sh --help` still shows all modes
4. **Watch smoke test**: `docker compose run secy watch --no-claude --help` — verify it starts, logs with `[secy:watch]` prefix
5. **Patrol smoke test**: `docker compose run secy patrol --no-claude --help` — verify it starts, logs with `[secy:patrol]` prefix
6. **Docker build**: `docker compose build` succeeds (secy-common.sh gets copied with rest of agent/)
