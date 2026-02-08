FROM debian:bookworm-slim

# Core utilities + srt dependencies (bubblewrap, socat for Linux sandboxing)
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    coreutils \
    findutils \
    diffutils \
    file \
    curl \
    ca-certificates \
    gnupg \
    bubblewrap \
    socat \
    ripgrep \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js (required for Claude Code CLI and srt)
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# Install Claude Code CLI and sandbox-runtime (srt)
RUN npm install -g @anthropic-ai/claude-code @anthropic-ai/sandbox-runtime

# Install secy (used for redacted reads of config files with secrets)
COPY bin/ /usr/local/lib/secy/bin/
COPY lib/ /usr/local/lib/secy/lib/
COPY conf/ /usr/local/lib/secy/conf/

RUN sed 's|SECY_ROOT=.*|SECY_ROOT="/usr/local/lib/secy"|' \
    /usr/local/lib/secy/bin/secy > /usr/local/bin/secy \
    && chmod 755 /usr/local/bin/secy

# Install agent
COPY agent/ /opt/secy-agent/
RUN chmod +x /opt/secy-agent/secy-agent.sh

# srt settings — Anthropic sandbox-runtime configuration
COPY agent/conf/srt-settings.json /root/.srt-settings.json

# State directory — mount a volume here for persistent findings
RUN mkdir -p /var/lib/secy-agent/state

ENV SECY_STATE_DIR=/var/lib/secy-agent/state

# Claude Code allows --dangerously-skip-permissions as root when IS_SANDBOX=1.
# This is the intended escape hatch — Docker is the real sandbox boundary.
ENV IS_SANDBOX=1

WORKDIR /opt/secy-agent

ENTRYPOINT ["/opt/secy-agent/secy-agent.sh"]
CMD ["audit"]
