# ── Build stage ──────────────────────────────────────────────────────
FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

COPY threatlab/src/ /tmp/src/

# Compile memfd_exec (statically linked — no library deps at runtime)
RUN gcc -O2 -static -o /tmp/memfd_exec /tmp/src/memfd_exec.c

# Compile dummy keylog shared library
RUN gcc -shared -o /tmp/libkeylog_hook.so /tmp/src/keylog_hook.c

# Patch sread binary for container layout
COPY sread/bin/ /tmp/sread-src/bin/
RUN sed 's|^SREAD_ROOT=.*|SREAD_ROOT="/usr/local/lib/sread"|' \
    /tmp/sread-src/bin/sread > /tmp/sread-bin \
    && chmod 755 /tmp/sread-bin

# ── Run stage ────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    coreutils \
    findutils \
    procps \
    socat \
    file \
    && rm -rf /var/lib/apt/lists/*

# Install sread (same layout as main Dockerfile)
COPY sread/bin/ /usr/local/lib/sread/bin/
COPY sread/lib/ /usr/local/lib/sread/lib/
COPY sread/conf/ /usr/local/lib/sread/conf/
RUN mkdir -p /usr/local/lib/sread/data
COPY --from=build /tmp/sread-bin /usr/local/bin/sread

# Install compiled threat artifacts
COPY --from=build /tmp/memfd_exec /usr/local/bin/memfd_exec
COPY --from=build /tmp/libkeylog_hook.so /usr/local/lib/libkeylog_hook.so
RUN ldconfig

# Create test user
RUN useradd -m -s /bin/bash testuser

# Install seed script
COPY threatlab/seed.sh /opt/threatlab/seed.sh
RUN chmod +x /opt/threatlab/seed.sh

# Export volume mountpoint
RUN mkdir -p /export

ENTRYPOINT ["/opt/threatlab/seed.sh"]
