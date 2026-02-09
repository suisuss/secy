#!/usr/bin/env bash
# entrypoint.sh — Container entrypoint that sets up runtime state
# before handing off to secy.sh.
#
# /root is a tmpfs (see docker-compose.yml), so files baked into
# the image at /root/* are shadowed. We stage them elsewhere and
# copy them in here.

set -euo pipefail

# ── Populate /root tmpfs ─────────────────────────────────────────

# srt settings — staged at build time to /opt/secy/conf/
cp /opt/secy/conf/srt-settings.json /root/.srt-settings.json

# OAuth credentials — bind-mounted to /mnt (read-only) to avoid
# being shadowed by the /root tmpfs.
if [[ -f /mnt/claude-credentials.json ]]; then
    mkdir -p /root/.claude
    cp /mnt/claude-credentials.json /root/.claude/.credentials.json
fi

# ── Hand off to secy ─────────────────────────────────────────────
exec /opt/secy/secy.sh "$@"
