#!/usr/bin/env bash
# entrypoint.sh — Container entrypoint that sets up runtime state
# before handing off to secy-agent.sh.
#
# Handles:
#   - Copying OAuth credentials from staging mount into the Claude Code
#     tmpfs (the bind mount at /root/.claude/.credentials.json is shadowed
#     by the tmpfs at /root/.claude, so we stage via /mnt).

set -euo pipefail

# ── OAuth credential setup ─────────────────────────────────────────
# The credential file is bind-mounted to /mnt/claude-credentials.json
# (read-only) to avoid being shadowed by the /root/.claude tmpfs.
# Copy it into the tmpfs where Claude Code expects it.
if [[ -f /mnt/claude-credentials.json ]]; then
    mkdir -p /root/.claude
    cp /mnt/claude-credentials.json /root/.claude/.credentials.json
fi

# ── Hand off to secy-agent ─────────────────────────────────────────
exec /opt/secy-agent/secy-agent.sh "$@"
