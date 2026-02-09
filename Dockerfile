# ── Build stage ──────────────────────────────────────────────────────
FROM node:22-bookworm-slim AS build

# Install Claude Code CLI and sandbox-runtime (srt)
RUN npm install -g @anthropic-ai/claude-code @anthropic-ai/sandbox-runtime

# Prepare sread binary (patch root path for container layout)
COPY sread/bin/ /tmp/sread-src/bin/
RUN sed 's|^SREAD_ROOT=.*|SREAD_ROOT="/usr/local/lib/sread"|' \
    /tmp/sread-src/bin/sread > /tmp/sread-bin \
    && chmod 755 /tmp/sread-bin

# ── Run stage ────────────────────────────────────────────────────────
FROM debian:bookworm-slim

# Runtime system dependencies (bubblewrap + socat for Linux sandboxing)
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    coreutils \
    findutils \
    diffutils \
    file \
    curl \
    ca-certificates \
    bubblewrap \
    socat \
    ripgrep \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Node.js runtime + globally-installed CLI tools from build stage
COPY --from=build /usr/local/bin /usr/local/bin
COPY --from=build /usr/local/lib/node_modules /usr/local/lib/node_modules

# Install sread (used for redacted reads of config files with secrets)
COPY sread/bin/ /usr/local/lib/sread/bin/
COPY sread/lib/ /usr/local/lib/sread/lib/
COPY sread/conf/ /usr/local/lib/sread/conf/
COPY --from=build /tmp/sread-bin /usr/local/bin/sread

# Install agent
COPY agent/ /opt/secy/
RUN chmod +x /opt/secy/secy.sh /opt/secy/entrypoint.sh

# srt settings — staged outside /root (which is a tmpfs at runtime).
# entrypoint.sh copies this into place.
COPY agent/conf/srt-settings.json /opt/secy/conf/srt-settings.json

# State directory — mount a volume here for persistent findings
RUN mkdir -p /var/lib/secy/state

ENV SECY_STATE_DIR=/var/lib/secy/state

# Claude Code allows --dangerously-skip-permissions as root when IS_SANDBOX=1.
# This is the intended escape hatch — Docker is the real sandbox boundary.
ENV IS_SANDBOX=1

WORKDIR /opt/secy

ENTRYPOINT ["/opt/secy/entrypoint.sh"]
CMD ["audit"]
