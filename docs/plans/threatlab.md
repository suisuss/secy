# Threat Lab Container — Implementation Plan

## Context

secy's sread modules detect 51 threat techniques, but there's no way to verify detections work end-to-end. This creates a Debian bookworm container pre-filled with simulated threat artifacts matching THREATS.md, scanned by secy's sread from the existing secy container via a shared volume. An automated test runner verifies expected detections.

## Architecture

Two containers, connected via shared volume + PID/network namespace sharing:

```
┌─────────────────────┐     ┌─────────────────────────┐
│     threatlab        │     │       secy-test          │
│                      │     │                          │
│  seed.sh populates   │     │  run-tests.sh invokes    │
│  /export/ volume     │────▸│  sread modules reading   │
│  with artifacts      │vol  │  /host/ (= /export/)     │
│                      │     │                          │
│  Background procs    │────▸│  /proc shows threatlab's │
│  (logkeys, x11vnc,  │PID  │  processes (PID sharing)  │
│   deleted binary...) │     │                          │
│                      │────▸│  /proc/net shows threat- │
│  socat listener      │NET  │  lab's network (net sharing)│
└─────────────────────┘     └─────────────────────────┘
```

**How sread auto-detection works in this setup:**
- `[[ -d "/host/etc" ]] && root="/host"` → reads filesystem from shared volume
- `[[ -d "/host/proc" ]] && proc="/host/proc"` → NO /host/proc in volume → falls back to `/proc` which shows threatlab's processes (PID namespace sharing)
- `netconn.sh` reads `/proc/net/tcp` → shows threatlab's network (network namespace sharing)

## File Structure

```
threatlab/
├── Dockerfile           # Multi-stage build: compile C artifacts → Debian bookworm + threat artifacts
├── seed.sh              # Entrypoint: populates /export/ volume, starts bg processes, idles
├── run-tests.sh         # Runs inside secy-test: invokes sread modules, checks expected output
└── src/
    ├── memfd_exec.c     # memfd_create execution (threat 2.6)
    └── keylog_hook.c    # Dummy suspicious .so for ld cache (threat 1.11)

docker-compose.test.yml  # Project root: orchestrates threatlab + secy-test
```

## Files to Create

### 1. `threatlab/src/keylog_hook.c`
One-line dummy shared library. Compiled to `libkeylog_hook.so`. Installed in threat lab's `/usr/local/lib/` and registered via ldconfig. Triggers preload module's suspicious ld cache pattern (`keylog`).

### 2. `threatlab/src/memfd_exec.c`
Small C program: `memfd_create("payload", 0)` → writes `#!/bin/sh\nsleep 86400\n` → `fexecve()`. Creates a process where `/proc/PID/exe` → `/memfd:payload`. Triggers spyproc module's memfd detection.

### 3. `threatlab/Dockerfile`

**Build stage** (debian:bookworm-slim + gcc):
- Compile memfd_exec and libkeylog_hook.so
- Patch sread binary SREAD_ROOT

**Run stage** (debian:bookworm-slim):
- Install: bash, coreutils, findutils, procps, socat, file
- Copy sread (lib/, conf/, patched bin) — same pattern as main `Dockerfile`
- Copy compiled C artifacts
- `ldconfig` to register libkeylog_hook.so
- `useradd -m -s /bin/bash testuser`
- Copy seed.sh
- `ENTRYPOINT ["/opt/threatlab/seed.sh"]`

### 4. `threatlab/seed.sh`

Entrypoint that:
1. Populates `/export/` volume with filesystem artifacts (see artifact table below)
2. Starts background "malicious" processes
3. Writes `/export/.ready` sentinel
4. Sleeps forever (container idles while secy-test scans)

**Filesystem artifacts seeded to /export/:**

| Threat ID | What | Path in /export/ |
|-----------|------|------------------|
| 1.1a | XDG autostart (system) | `etc/xdg/autostart/malicious-updater.desktop` — Exec=curl payload |
| 1.1b | XDG autostart (per-user) | `home/testuser/.config/autostart/keylogger.desktop` — Exec=logkeys |
| 1.2 | Systemd user service | `home/testuser/.config/systemd/user/backdoor.service` — ExecStart=/tmp/.beacon |
| 1.3 | Shell profile hook | `home/testuser/.bashrc` — PROMPT_COMMAND with curl exfil |
| 1.5 | Executable rc.local | `etc/rc.local` — reverse shell, chmod +x |
| 1.6 | Non-package init.d | `etc/init.d/syshealth` + empty `var/lib/dpkg/info/` (no matching .list) |
| 1.7 | Chrome extension | `home/testuser/.config/google-chrome/Default/Extensions/abc123/1.0/manifest.json` — "Keyboard Monitor Pro" |
| 1.8 | /etc/ld.so.preload | `etc/ld.so.preload` → /usr/local/lib/libkeylog_hook.so |
| 1.10 | PAM tampering | `etc/pam.d/common-auth` — pam_exec.so line |
| 3.1 | SUID binary | `usr/local/bin/suid-backdoor` — chmod u+s |
| 3.2 | SGID binary | `usr/local/bin/sgid-tool` — chmod g+s |
| 3.3 | World-writable files | `var/lib/evil-payload` (666), `opt/backdoor.conf` (666) |
| 3.4 | Backdated binary | `usr/bin/backdated-binary` — touch -t to backdate mtime, ctime stays current |
| 3.8a-d | /dev/shm artifacts | `dev/shm/payload` (+x), `dev/shm/data.bin` (ELF no +x), `dev/shm/helper.txt` (shebang no +x), `dev/shm/.config` (hidden) |
| 7.5 | Package tamper | `usr/bin/yes` (modified) + `var/lib/dpkg/info/coreutils.md5sums` (original hashes) |

**Background processes started at runtime:**

| Threat ID | Process | How |
|-----------|---------|-----|
| 1.9 | LD_PRELOAD per-process | `LD_PRELOAD=/usr/local/lib/libkeylog_hook.so sleep 86400 &` |
| 2.1 | Known spyware name | `cp /usr/bin/sleep /tmp/logkeys && /tmp/logkeys 86400 &` |
| 2.5 | Deleted binary | `cp /usr/bin/sleep /tmp/deleted-test && /tmp/deleted-test 86400 & rm /tmp/deleted-test` |
| 2.6 | memfd execution | `/usr/local/bin/memfd_exec &` |
| 2.7 | Process name spoofing | `ln -sf /usr/bin/sleep /tmp/innocent-svc && /tmp/innocent-svc 86400 &` (comm ≠ basename(exe)) |
| 5.1 | TCP listener | `socat TCP-LISTEN:31337,bind=0.0.0.0,fork /dev/null &` |
| RD | Remote desktop proc | `cp /usr/bin/sleep /tmp/x11vnc && /tmp/x11vnc 86400 &` |

### 5. `threatlab/run-tests.sh`

Runs inside the secy-test container. Structure:

```bash
#!/usr/bin/env bash
# Wait for threatlab to finish seeding
while [[ ! -f /host/.ready ]]; do sleep 0.5; done

PASS=0 FAIL=0 SKIP=0

assert() {
    local id="$1" desc="$2" module="$3" pattern="$4"
    shift 4
    output="$(sread "$module" "$@" 2>&1)" || true
    if echo "$output" | grep -qiE "$pattern"; then
        printf "  PASS  %-6s %s\n" "$id" "$desc"
    else
        printf "  FAIL  %-6s %s\n" "$id" "$desc"
    fi
}

# Autostart module tests
assert "1.1a" "XDG system autostart" autostart "malicious-updater.*curl"
assert "1.1b" "XDG user autostart"   autostart "keylogger.*logkeys"
# ... (all 27 test cases)

echo "Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
exit $FAIL
```

**Full test case list (27 active + 2 skip):**

| ID | Module + args | Expected pattern |
|----|---------------|-----------------|
| 1.1a | `autostart` | `malicious-updater.*curl` |
| 1.1b | `autostart` | `keylogger.*logkeys` |
| 1.2 | `autostart` | `backdoor.service` |
| 1.5 | `autostart` | `rc.local exists and is executable` |
| 1.6 | `autostart` | `syshealth.*not owned by any package` |
| 1.3 | `preload` | `PROMPT_COMMAND.*curl` |
| 1.8 | `preload` | `File EXISTS` |
| 1.9 | `preload` | `LD_PRELOAD=` |
| 1.10 | `preload` | `pam_exec` |
| 1.11 | `preload` | `keylog` (in ld cache section) |
| 2.1 | `spyproc` | `logkeys` |
| 2.5 | `spyproc` | `deleted binary` |
| 2.6 | `spyproc` | `memfd.*memory-only` |
| 2.7 | `spyproc` | `comm=.*exe=` |
| 3.1 | `setuid --path /host` | `suid-backdoor` |
| 3.2 | `setuid --path /host` | `sgid-tool` |
| 3.3a | `world --path /host` | `evil-payload` |
| 3.3b | `world --path /host` | `backdoor.conf` |
| 3.4 | `tamper` | `backdated-binary` |
| 3.8a | `world --path /host` | `executable.*payload` |
| 3.8b | `world --path /host` | `ELF binary.*data.bin` |
| 3.8c | `world --path /host` | `script.*helper.txt` |
| 3.8d | `world --path /host` | `hidden file.*\.config` |
| 1.7 | `desktop` | `Keyboard Monitor Pro` |
| RD | `desktop` | `x11vnc` |
| 7.5 | `pkgverify` | `MODIFIED.*yes` |
| 5.1 | `netconn` | `0.0.0.0:31337` |
| 4.x | `kmod` | SKIP — kernel-level, not testable in container |
| 1.4 | `cron` | SKIP — cron.sh uses hardcoded paths (no /host prefix), needs module fix |

### 6. `docker-compose.test.yml`

```yaml
services:
  threatlab:
    build:
      context: .
      dockerfile: threatlab/Dockerfile
    volumes:
      - threatlab-fs:/export
    healthcheck:
      test: ["CMD", "test", "-f", "/export/.ready"]
      interval: 1s
      retries: 30

  secy-test:
    build: .
    pid: "service:threatlab"
    network_mode: "service:threatlab"
    cap_add:
      - DAC_READ_SEARCH
      - SYS_PTRACE
      - SYS_ADMIN
    volumes:
      - threatlab-fs:/host:ro
      - ./state:/var/lib/secy/state
      - ./threatlab/run-tests.sh:/opt/threatlab/run-tests.sh:ro
    depends_on:
      threatlab:
        condition: service_healthy
    entrypoint: ["bash", "/opt/threatlab/run-tests.sh"]

volumes:
  threatlab-fs:
```

### 7. Fix `cron.sh` (optional, enables cron test)

Add `/host` prefix support to match all other modules:
```bash
local root=""
[[ -d "/host/etc" ]] && root="/host"
```
Then use `${root}/etc/crontab`, `${root}/etc/cron.d`, `${root}/var/spool/cron/crontabs`. If done, cron test moves from SKIP to active.

## Known Limitations

| Category | Reason |
|----------|--------|
| Kernel modules (4.1-4.8) | Container shares host kernel; can't load/fake modules |
| Ptrace (2.2) | Needs real ptrace between two processes — complexity vs value |
| /dev/input readers (2.3) | No /dev/input devices in containers |
| Raw/packet sockets (2.4) | Needs CAP_NET_RAW + real socket creation |
| Outbound connections (5.2-5.3) | Needs real network traffic to external hosts |
| Cron (1.4) | cron.sh doesn't use /host prefix (bug); skipped until fixed |

## Implementation Order

1. `threatlab/src/keylog_hook.c` + `threatlab/src/memfd_exec.c` (small C files)
2. `threatlab/Dockerfile` (multi-stage build)
3. `threatlab/seed.sh` (artifact seeding + process startup)
4. `threatlab/run-tests.sh` (test runner)
5. `docker-compose.test.yml` (orchestration)
6. Build + run, iterate on failures

## Verification

```bash
# Build and run all tests
docker compose -f docker-compose.test.yml run --rm secy-test

# Manual inspection mode
docker compose -f docker-compose.test.yml up -d threatlab
docker compose -f docker-compose.test.yml run --rm --entrypoint bash secy-test
# Then: sread spyproc, sread preload, sread autostart, etc.
```

Exit code 0 = all 27 tests pass. Non-zero = number of failures.
