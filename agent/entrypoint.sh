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

# ── Integrity check ──────────────────────────────────────────────
# Verify that security-critical files match the hashes baked at build time.
# If any file was modified (tampered prompts, weakened blocklists, etc.),
# refuse to start.

INTEGRITY_MANIFEST="/opt/secy/integrity.sha256"

if [[ -f "$INTEGRITY_MANIFEST" ]]; then
    if ! sha256sum --check --strict "$INTEGRITY_MANIFEST" > /dev/null 2>&1; then
        echo "INTEGRITY CHECK FAILED — security-critical files have been modified:" >&2
        sha256sum --check "$INTEGRITY_MANIFEST" 2>&1 | grep -v ': OK$' >&2
        echo "" >&2
        echo "This likely means the image was not rebuilt after changing prompts," >&2
        echo "configs, or blocklists. Rebuild with: docker compose build" >&2
        echo "" >&2
        echo "If this is unexpected, the image may have been tampered with." >&2
        exit 1
    fi
else
    echo "WARNING: integrity manifest not found — skipping verification" >&2
fi

# ── Hand off to secy ─────────────────────────────────────────────
exec /opt/secy/secy.sh "$@"
