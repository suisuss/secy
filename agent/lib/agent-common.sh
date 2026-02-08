#!/usr/bin/env bash
# secy-agent/lib/agent-common.sh — Shared functions for the agent loop

set -euo pipefail

AGENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# SECY_ROOT can be set externally (e.g. in Docker where agent and secy are separate)
if [[ -z "${SECY_ROOT:-}" ]]; then
    SECY_ROOT="$(cd "${AGENT_DIR}/.." && pwd)"
fi
export SECY_ROOT

source "${AGENT_DIR}/conf/agent.conf"

# ── Logging ───────────────────────────────────────────────────────

log_agent() {
    echo "[secy-agent $(date -Iseconds)] $*" >&2
}

# ── Preflight checks ─────────────────────────────────────────────

preflight_check() {
    local missing=false

    for cmd in claude srt secy; do
        if ! command -v "$cmd" &>/dev/null; then
            log_agent "ERROR: '${cmd}' not found in PATH"
            missing=true
        fi
    done

    if [[ "$missing" == "true" ]]; then
        exit 1
    fi

    if [[ $EUID -ne 0 ]]; then
        log_agent "ERROR: secy-agent must run as root (run inside Docker container)"
        exit 1
    fi

    # Verify host filesystem is mounted
    if [[ ! -d "/host/etc" ]]; then
        log_agent "ERROR: Host filesystem not found at /host"
        log_agent "       Run via: docker compose run secy-agent <mode>"
        exit 1
    fi
}

# ── State directory management ────────────────────────────────────

ensure_state_dirs() {
    mkdir -p "${STATE_DIR}/baseline"
    mkdir -p "${STATE_DIR}/current"
    mkdir -p "${STATE_DIR}/findings"
}

# ── Lock management ───────────────────────────────────────────────

acquire_lock() {
    local lockdir="${STATE_DIR}/agent.lock"
    # mkdir is atomic — if it succeeds, we own the lock
    if ! mkdir "$lockdir" 2>/dev/null; then
        local pidfile="${lockdir}/pid"
        if [[ -f "$pidfile" ]]; then
            local pid
            pid="$(cat "$pidfile")"
            if kill -0 "$pid" 2>/dev/null; then
                log_agent "ERROR: secy-agent already running (pid ${pid})"
                exit 1
            fi
            # Stale lock from crashed run
            log_agent "Removing stale lock (pid ${pid} not running)"
        fi
        rm -rf "$lockdir"
        mkdir "$lockdir" || { log_agent "ERROR: could not acquire lock"; exit 1; }
    fi
    echo $$ > "${lockdir}/pid"
}

release_lock() {
    rm -rf "${STATE_DIR}/agent.lock"
}

# ── Prompt assembly ───────────────────────────────────────────────

assemble_prompt() {
    local mode="$1"
    local iteration="$2"
    local max_iterations="$3"
    local timestamp="$4"

    local prompt=""

    # Mode-specific instructions
    case "$mode" in
        baseline)
            prompt+="## Current Task: Capture Baseline

Read the following host files and save snapshots. Do NOT analyze — just capture the current state.

For each item, read the source file and write its content to the baseline path:

| Baseline file | Host source |
|---|---|
| ${STATE_DIR}/baseline/tcp.txt | /host/proc/net/tcp and /host/proc/net/tcp6 |
| ${STATE_DIR}/baseline/udp.txt | /host/proc/net/udp and /host/proc/net/udp6 |
| ${STATE_DIR}/baseline/passwd.txt | /host/etc/passwd |
| ${STATE_DIR}/baseline/group.txt | /host/etc/group |
| ${STATE_DIR}/baseline/sudoers.txt | /host/etc/sudoers and /host/etc/sudoers.d/* |
| ${STATE_DIR}/baseline/sshd.txt | /host/etc/ssh/sshd_config |
| ${STATE_DIR}/baseline/cron.txt | /host/etc/crontab, /host/etc/cron.d/*, /host/var/spool/cron/crontabs/* |
| ${STATE_DIR}/baseline/sysctl.txt | Key files under /host/proc/sys/ (ip_forward, randomize_va_space, etc.) |
| ${STATE_DIR}/baseline/setuid.txt | Run: find /host -perm -4000 -type f 2>/dev/null |
| ${STATE_DIR}/baseline/world.txt | Run EXACTLY: find /host -perm -0002 -type f -not -path '/host/proc/*' -not -path '/host/sys/*' -not -path '/host/tmp/*' -not -path '/host/var/tmp/*' -not -path '/host/dev/*' -not -path '/host/run/*' 2>/dev/null — do NOT add extra exclusions, /home and /var/lib/docker MUST be scanned |
| ${STATE_DIR}/baseline/firewall.txt | /host/etc/nftables.conf and/or /host/etc/iptables/rules.v4 (if they exist) |
| ${STATE_DIR}/baseline/auth-log.txt | Last 100 lines of /host/var/log/auth.log |

Also write \`${STATE_DIR}/baseline/baseline.meta\` with the hostname (from /host/etc/hostname), date (${timestamp}), kernel (from /host/proc/version), and OS (from /host/etc/os-release).

When ALL files are saved, output SECY_AGENT_COMPLETE as the very last line.
"
            ;;
        audit)
            prompt+="## Current Task: Full Security Audit

Read host system files and analyze for security anomalies using the guidance in your system prompt. Produce a comprehensive findings report with explanations and recommended commands.

The host filesystem is mounted at /host (read-only).
"
            # If a baseline exists, tell the agent to also diff against it
            if [[ -f "${STATE_DIR}/baseline/baseline.meta" ]]; then
                prompt+="
### Baseline Available

A baseline snapshot exists at ${STATE_DIR}/baseline/. After analyzing the current state for security issues, also compare key files against the baseline to identify what has changed since it was captured. Use \`diff ${STATE_DIR}/baseline/<file> -\` or save current state to ${STATE_DIR}/current/ and diff against it. Include a 'Changes Since Baseline' section in your report noting any significant deviations.

Baseline metadata:
$(cat "${STATE_DIR}/baseline/baseline.meta")
"
            fi

            prompt+="
Write your findings report to: ${STATE_DIR}/findings/audit-${timestamp}.md
Update progress at: ${STATE_DIR}/progress.md

This is iteration ${iteration} of ${max_iterations}. If this is your last iteration, you MUST finalize and write the findings report with whatever you have.
"
            ;;
        monitor)
            prompt+="## Current Task: Security Monitoring (Delta Check)

A baseline exists at ${STATE_DIR}/baseline/. Read the same host files, save current state to ${STATE_DIR}/current/, and compare against baseline.

For each baseline file:
1. Read the corresponding host file(s) and save to ${STATE_DIR}/current/
2. Compare: run \`diff ${STATE_DIR}/baseline/<file> ${STATE_DIR}/current/<file>\`
3. Analyze the diff — determine if changes are benign or suspicious

The host filesystem is mounted at /host (read-only).

Write your findings report to: ${STATE_DIR}/findings/monitor-${timestamp}.md
Update progress at: ${STATE_DIR}/progress.md

This is iteration ${iteration} of ${max_iterations}. If this is your last iteration, you MUST finalize and write the findings report.
"
            ;;
    esac

    # Append progress from previous iterations (if any)
    if [[ -f "${STATE_DIR}/progress.md" ]] && [[ -s "${STATE_DIR}/progress.md" ]]; then
        prompt+="
## Progress From Previous Iterations

$(cat "${STATE_DIR}/progress.md")
"
    fi

    echo "$prompt"
}

# ── Completion check ──────────────────────────────────────────────

check_completion() {
    local output="$1"
    # Works for both plain text and stream-json output
    echo "$output" | grep -q "SECY_AGENT_COMPLETE"
}
