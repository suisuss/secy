# secy — Autonomous Security Monitor for Linux

An autonomous AI security monitor that continuously watches your Linux system for threats. Four containerized services — watch, patrol, C2, and one-shot audit — read the host filesystem, detect anomalies, correlate findings across services, and report actionable issues to the user. Runs inside sandboxed Docker containers with read-only host access.

### Target system

secy is built for **developer workstations** running:

- **Debian 12 (bookworm)** on **x86_64/amd64**
- **GNOME desktop** (X11 or Wayland) — required for desktop notifications
- **systemd** — user services for the notification watcher
- **Docker Engine** with Compose v2

It is not designed for headless servers, non-Debian distributions, or ARM architectures. Patrol modules parse Debian-specific paths (`/var/lib/dpkg`, apt logs), sread uses Debian package verification (`debsums`), and the notification system depends on a graphical session with `notify-send` and D-Bus.

## How it works

```
  Host machine
  ┌─────────────────────────────────────────────────────────────┐
  │                                                             │
  │  ~/.local/share/secy/                                       │
  │  ├── issues/  ← user-visible output (bind mount)           │
  │  └── state/   ← patrol history, findings, baselines        │
  │                                                             │
  │  Docker   ┌────────────────────────────────────────────┐    │
  │           │  state/ bind mount → /var/lib/secy/state   │    │
  │           │  ├── findings/   ← all services write here │    │
  │           │  ├── directives/ ← C2 writes, others read  │    │
  │           │  ├── patrol/     ← module runs, diffs       │    │
  │           │  ├── watch/      ← seen DB, queue           │    │
  │           │  └── c2/         ← progress memory          │    │
  │           └────────────────────────────────────────────┘    │
  │                                                             │
  │   ┌──────────┐   ┌──────────┐   ┌──────────┐              │
  │   │  watch   │   │  patrol  │   │    C2    │              │
  │   │ (sensor) │   │ (sensor) │   │ (brain)  │              │
  │   │ inotify/ │   │scheduled │   │ event-   │              │
  │   │ poll     │   │ scans    │   │ driven   │              │
  │   └────┬─────┘   └────┬─────┘   └────┬─────┘              │
  │        │              │               │                     │
  │        └── findings/ ─┴───────────────┘                     │
  │                 ↑                │                           │
  │                 └─ directives/ ←─┘                           │
  │                                                             │
  │   /host:ro ─────────────────── host filesystem (read-only)  │
  │                                                             │
  │   Host-side (systemd user service)                          │
  │   ┌──────────────────────────────────────────────────┐      │
  │   │  notify.sh (inotifywait on issues/)              │      │
  │   │  → desktop notifications on new findings         │      │
  │   │  ← cron healthcheck (hourly, restarts if down)   │      │
  │   └──────────────────────────────────────────────────┘      │
  └─────────────────────────────────────────────────────────────┘
```

**Watch** monitors Downloads for new files — hash-checks against a malware database, then triages unknowns with Claude. **Patrol** runs scheduled security scans (41 modules covering ports, services, kernel modules, users, network threats, process trees, temp execution, mount hardening, etc.), diffs between runs, and reviews changes with Claude. **C2** correlates findings across both services, identifies compound threats (e.g., suspicious download + new listening port + process from /tmp), and creates issues for the user.

Issues are written to `~/.local/share/secy/issues/` — self-contained markdown files describing what was detected, the evidence, and what to investigate. A host-side notification watcher sends desktop alerts when new issues appear. All internal state lives on the host at `~/.local/share/secy/state/`.

No commands are executed on the host. The containers read the host filesystem at `/host` (read-only mount) and use `sread` — a restricted audit tool with blocklist enforcement and output redaction — for config files that may contain secrets.

## Setup

```bash
git clone https://github.com/suisuss/secy.git && cd secy
./setup.sh install
```

This checks prerequisites, builds the Docker image, starts all services, and installs desktop notifications.

### Prerequisites

- Docker and Docker Compose
- One of:
  - **Claude Code OAuth** (Pro/Max subscription) — `claude` CLI authenticated on the host
  - **Anthropic API key** (pay-per-use) — set in `.env`
- For desktop notifications: `inotify-tools`, `libnotify-bin`

Check prerequisites without installing:

```bash
./setup.sh doctor
```

### Authentication

**Option A: OAuth (Pro/Max subscription)**

If you've already authenticated with `claude` on the host, credentials are at `~/.claude/.credentials.json`. The container mounts this automatically — no extra config needed.

**Option B: API key**

```bash
cp .env.example .env
# Edit .env and set ANTHROPIC_API_KEY=sk-ant-...
```

## Usage

### Lifecycle commands

```bash
./setup.sh install     # Build image, start services, setup notifications
./setup.sh start       # Start all services
./setup.sh stop        # Stop all services
./setup.sh status      # Dashboard of all components
./setup.sh doctor      # Check prerequisites, diagnose issues
./setup.sh uninstall   # Stop everything, optionally remove data and images
```

### One-shot scans

```bash
docker compose run --rm secy audit       # Full security sweep
docker compose run --rm secy baseline    # Capture system baseline
docker compose run --rm secy monitor     # Compare against baseline
```

### Without AI (dry-run / debugging)

```bash
docker compose run --rm secy watch --no-claude
docker compose run --rm secy patrol --no-claude
docker compose run --rm secy c2 --no-claude
```

### What to expect

The agent streams its activity as it works:

```
[secy 2026-02-09T00:24:06+00:00] Starting audit (max 3 iterations)
[secy 2026-02-09T00:24:06+00:00] Iteration 1/3
  [init] model=claude-opus-4-6-20250901
  [read] /host/proc/net/tcp
  [read] /host/etc/passwd
  [bash] find /host -perm -4000 -type f 2>/dev/null
  [read] /host/etc/ssh/sshd_config
  [write] /var/lib/secy/state/findings/audit-2026-02-09-002406.md
  [done] 12 turns, 45230ms
```

When a finding warrants user attention, a desktop notification appears with the issue title and severity.

### Troubleshooting

**No output from Claude (exits immediately):**

```bash
docker compose run --entrypoint bash secy -c '
cp /opt/secy/conf/srt-settings.json /root/.srt-settings.json
if [ -f /mnt/claude-credentials.json ]; then
    mkdir -p /root/.claude
    cp /mnt/claude-credentials.json /root/.claude/.credentials.json
fi
claude --print -p "say hello" 2>&1
echo "exit: $?"
cat /root/.claude/debug/latest 2>/dev/null
'
```

**"Not logged in" error:** OAuth credentials aren't being found. Check that `~/.claude/.credentials.json` exists on the host.

**srt sandbox fails:** Expected in most Docker setups. The agent falls back to running without srt — Docker is the primary sandbox boundary.

## Services

| Service | Role | Model | Runs as |
|---------|------|-------|---------|
| `secy` | One-shot audit, baseline, monitor | Opus | `docker compose run` |
| `secy-watch` | Downloads malware detection | Opus | Daemon |
| `secy-patrol` | Scheduled security scans | Opus | Daemon |
| `secy-c2` | Cross-service correlation | Haiku | Daemon |

Watch and patrol use Opus for nuanced judgment on raw, unstructured inputs (unknown files, ambiguous system changes). C2 uses Haiku — its inputs are already triaged and structured, so the correlation task is simpler.

### Watch

Monitors `/home/*/Downloads/` for new files using inotify (with polling fallback). For each new file:

1. **Hash check** — SHA256 against MalwareBazaar database (~1.5M known malware hashes, baked in at build time). Known malware triggers an immediate CRITICAL alert.
2. **Classify** — MIME type check. Media files are skipped. Scripts, executables, PDFs, office docs, and archives are queued.
3. **AI triage** — Claude assesses each queued file as CLEAN, SUSPICIOUS, or MALICIOUS based on metadata, structure, and content indicators.

### Patrol

Runs 41 sread modules on configurable schedules, diffs output between runs, and invokes Claude to review meaningful changes.

Each module runs at its own interval (e.g., `netthreats` every 2 minutes, `pkgverify` every hour). When non-empty diffs accumulate — especially from high-priority modules — Claude is invoked to assess what changed.

Default patrol schedule (high-priority modules):

| Module | Interval | What it checks |
|--------|----------|---------------|
| `netthreats` | 120s | Non-standard port connections, beaconing, suspicious process connections, reverse DNS |
| `tmpexec` | 120s | Processes running from /tmp, staged payloads, hidden files, interpreter scripts in temp dirs |
| `ports` | 300s | Open ports, listening services |
| `spyproc` | 300s | Keyloggers, RATs, deleted binaries, memfd execution, process spoofing |
| `netconn` | 300s | Established connections with process attribution, unusual remote ports |
| `proctree` | 300s | Orphaned daemons, supply chain process chains, setsid detachment |
| `kmod` | 600s | Suspicious kernel modules |
| `preload` | 600s | LD_PRELOAD hijacking, shell hooks |
| `cron` | 600s | Suspicious cron jobs |

Module schedules are configurable via `state/patrol/schedule.conf`.

### C2 (correlation)

Monitors `state/findings/` for new reports from watch and patrol. When findings accumulate past a debounce interval (default 5 minutes), spawns Claude to:

1. **Correlate across services** — a suspicious download (watch) + a new listening port (patrol) + a process from /tmp (patrol) together indicate a supply chain attack was executed
2. **Assess compound threats** — staging, persistence, privilege escalation, lateral movement, exfiltration patterns
3. **Issue directives** — increase scan frequency for specific modules, expand watch directories
4. **Create issues** — self-contained reports written to `~/.local/share/secy/issues/` for the user

C2 adjusts what watch and patrol monitor, but never takes remediation actions. secy is strictly observe-only.

### One-shot modes

| Mode | What it does | Iterations |
|------|-------------|-----------|
| `baseline` | Captures current system state as the "normal" reference | 1 |
| `audit` | Full security sweep — reads system files, produces findings report | Up to 3 |
| `monitor` | Compares current state against baseline, flags deviations | Up to 2 |

## Desktop notifications

secy includes a host-side notification system with a three-way watchdog:

```
    secy patrol (Docker)
        | secyhealth module (every 30min):
        |   notify service installed?
        |   cron entry present?
        v
    notify service <-------- cron healthcheck (hourly)
        |                        |
        | inotifywait on         | checks:
        | issues/ dir            |   notify service alive?
        | -> desktop alerts      |   patrol container alive?
        |                        |   watch container alive?
        |                        |   c2 container alive?
        v                        v
      [you see it]           [you see it]
```

Any single failure is caught by at least one other component. Setup is handled by `./setup.sh install`. To manage independently:

```bash
./scripts/setup-notify.sh              # Install service + cron
./scripts/setup-notify.sh --uninstall  # Remove
systemctl --user status secy-notify    # Check status
```

### Severity levels and notification urgency

| Severity | Icon | Notification | Meaning |
|----------|------|-------------|---------|
| **critical** | Red | Persistent | Likely active threat requiring prompt attention |
| **warning** | Yellow | Normal | Suspicious activity worth investigating |
| **info** | Blue | Low | Notable change the user should be aware of |

## Issues

Issues are how secy communicates with the user. `~/.local/share/secy/issues/` is the only secy output visible on the host.

When C2 identifies something that warrants user attention, it creates a markdown file:

```
~/.local/share/secy/issues/
  0001-suspicious-binary-downloaded.md
  0002-axios-supply-chain-rat-credentials-at-risk.md
  0003-new-listening-port-4444.md
```

Each issue is self-contained — it includes all evidence, timestamps, detection details, and recommended investigation steps.

**Lifecycle**: an issue file exists = open. The user deletes it when resolved. If the same problem recurs with new evidence, C2 creates a new issue.

### Issue format

Every issue includes:
- **What was detected** — plain language description with specific files, ports, processes, timestamps
- **How it was detected** — which service(s) flagged it, what scan found the anomaly
- **Evidence** — inline data: hashes, diff snippets, port numbers, process names. Commands the user can run to verify
- **Why this matters** — security implication, attack stage, confidence level
- **Recommended action** — what to investigate, what to look for

## Directives

C2 adjusts monitoring by writing directive files. Watch and patrol poll for changes every 60 seconds.

| Directive | Target | Purpose |
|-----------|--------|---------|
| `state/directives/schedule-override.conf` | Patrol | Increase scan frequency for specific modules |
| `state/directives/watch-config.conf` | Watch | Expand watch coverage (extra directories, scan depth) |
| `state/directives/active/*.directive` | Patrol | One-shot overrides (moved to `applied/` after processing) |
| `state/directives/active/*.watch-directive` | Watch | One-shot overrides (moved to `applied/` after processing) |

Directives only adjust what secy monitors — they never take actions that change the host system.

## What it checks

### sread modules (41 modules)

| Module | What it checks |
|--------|---------------|
| `netthreats` | Outbound connections to non-standard ports, beaconing detection across runs, suspicious process connections from /tmp or hidden paths, detached interpreters with network, reverse DNS |
| `tmpexec` | Processes executing from /tmp, /dev/shm, /var/tmp; interpreters running temp scripts; staged executables; recently created scripts; hidden dot-prefixed files |
| `proctree` | Orphaned user processes (PPID=1), suspicious parent-child chains (npm->sh->python), session leaders without terminal (setsid/double-fork) |
| `mountsec` | noexec/nosuid/nodev on /tmp, /dev/shm, /var/tmp; /home mount options; remediation commands |
| `secyhealth` | secy-notify service installed and enabled, cron healthcheck present, issues directory accessible |
| `netconn` | Established TCP connections with process attribution, listeners on 0.0.0.0, connections to unusual remote ports |
| `ports` | TCP/UDP listeners |
| `spyproc` | Keyloggers, screen recorders, RATs, deleted binaries, memfd execution, process name spoofing, ptrace attachments, thread injection, /dev/input readers, PID namespace anomalies |
| `dnstun` | DNS tunneling tools, rogue DNS listeners, suspicious resolv.conf |
| `firewall` | ufw/nftables/iptables rules, default policies, coverage assessment |
| `kmod` | Suspicious kernel modules, unsigned/out-of-tree, tainted kernel |
| `preload` | LD_PRELOAD hijacking, /etc/ld.so.preload, shell profile hooks, PAM modules, ld cache |
| `autostart` | XDG autostart, systemd user services, rc.local, non-package init.d scripts |
| `userpersist` | Shell rc backdoors, SSH authorized_keys anomalies, systemd user timers, XDG autostart |
| `cron` | Suspicious cron jobs, writable scripts, remote execution patterns |
| `users` | UID 0 accounts, service accounts with login shells, sudo configuration |
| `services` | Systemd services, insecure configurations |
| `sysctl` | Kernel parameters: ASLR, IP forwarding, ptrace scope |
| `credexpose` | Credential files in world-readable locations |
| `credperms` | File permissions on sensitive credential stores |
| `privesc` | Privilege escalation vectors |
| `setuid` | SUID/SGID binaries outside standard locations |
| `world` | World-writable files, /dev/shm artifacts |
| `mounts` | Bind mount shadowing, overlapping mounts |
| `tamper` | Backdated binaries, package integrity |
| `pkgverify` | Package file hash verification |
| `packages` | Installed packages |
| `logs` | Auth logs, brute force detection |
| `desktop` | Remote desktop, browser extensions |
| `display` | Display server access, screen sharing |
| `surveil` | Surveillance indicators |
| `container` | Container escape vectors |
| `ebpf` | eBPF programs, security-relevant tracepoints |
| `firmware` | EFI/UEFI Secure Boot, boot entries |
| `xattr` | Suspicious extended attributes on binaries |
| `files` | File content reads (text only, MIME-checked) |
| `fileinfo` | File metadata and risk indicators |
| `hash` | SHA256/MD5 hashing |
| `hashlookup` | Hash lookup against malware database |
| `perms` | File permission analysis |
| `full` | Run all modules |

## Security model

Each container runs three nested isolation layers:

```
+------------------------------------------------------+
|  Docker Container                                     |
|  - /host:ro (read-only host mount)                    |
|  - read_only: true (immutable container filesystem)   |
|  - no-new-privileges, cap_drop: ALL                   |
|  - tmpfs: /tmp, /root (only writable dirs)            |
|                                                       |
|  +------------------------------------------------+  |
|  |  srt (Anthropic sandbox-runtime)               |  |
|  |  - Network: api.anthropic.com only             |  |
|  |  - Filesystem: deny /etc/shadow, SSH keys,     |  |
|  |    credential stores                            |  |
|  |                                                |  |
|  |  +------------------------------------------+  |  |
|  |  |  Claude Code + sread                     |  |  |
|  |  |  - sread: path blocklist, output         |  |  |
|  |  |    redaction, MIME whitelist              |  |  |
|  |  |  - Reads /host/proc, /host/etc, /host/var|  |  |
|  |  |  - Writes to state/ + issues/            |  |  |
|  |  +------------------------------------------+  |  |
|  +------------------------------------------------+  |
+------------------------------------------------------+
```

| Layer | Mechanism | Prevents |
|-------|-----------|----------|
| **Docker** | Read-only host mount, immutable container filesystem, `no-new-privileges`, all capabilities dropped except `DAC_READ_SEARCH`/`SYS_ADMIN`/`NET_ADMIN`, tmpfs-only writable dirs | Host modification, privilege escalation, command execution on host, tampering with agent code |
| **srt** | Anthropic sandbox-runtime — network allowlist (`api.anthropic.com` only), filesystem deny on credentials/keys | Data exfiltration, credential theft at OS level |
| **sread** | Path blocklist, output redaction, MIME type whitelist, argument validation | Credential file reads, password leakage in output, binary file reads |

### What is NOT defended

- Audit output and issues reveal system architecture (users, ports, services, configs). Treat `~/.local/share/secy/issues/` as sensitive.
- Prompt injection from host files (malicious log entries, poisoned configs) could influence agent reasoning. The three layers constrain what the agent can do in response.
- Audit data is sent to the Claude API. This is inherent to using a cloud LLM.
- secy is observe-only — it does not remediate threats. A compromised host could theoretically feed misleading data through `/host:ro`.

## Data

All secy data lives at `~/.local/share/secy/` (configurable via `SECY_DATA_DIR` env var):

```
~/.local/share/secy/
+-- issues/                        # User-visible output, desktop notifications watch this
+-- state/
    +-- findings/                  # Reports from watch, patrol, and C2
    +-- directives/
    |   +-- schedule-override.conf # Persistent patrol overrides
    |   +-- watch-config.conf      # Persistent watch overrides
    |   +-- active/                # One-shot directives (pending)
    |   +-- applied/               # Processed directives + .report files
    +-- patrol/
    |   +-- runs/<module>/latest   # Latest module output
    |   +-- diffs/                 # Diffs between runs
    |   +-- schedule.conf          # Module schedule
    +-- watch/
    |   +-- seen.db                # Processed file database
    |   +-- queue/                 # Files pending triage
    +-- c2/
    |   +-- processed.db           # Findings already correlated
    |   +-- progress.md            # Investigation continuity notes
    +-- baseline/                  # Baseline snapshots
```

## Testing

Tests run inside Docker using a threat lab container pre-filled with simulated threat artifacts:

```bash
docker compose --profile test run --rm secy-test
```

The test container shares PID and network namespaces with the threat lab to scan its processes and listeners. 34 tests covering autostart, preload, spyproc, setuid, world, tamper, desktop, pkgverify, netconn, tmpexec, proctree, mountsec, and netthreats modules.

## Configuration

### Agent settings (`agent/conf/agent.conf`)

```bash
# AI models (per-service)
CLAUDE_MODEL="opus"               # Used by watch + patrol (raw judgment calls)
CLAUDE_MODEL_C2="haiku"           # Used by C2 (structured correlation)

# One-shot modes
AUDIT_MAX_ITERATIONS=3
MONITOR_MAX_ITERATIONS=2
BASELINE_MAX_ITERATIONS=1
MAX_BUDGET_USD="1.00"             # Per-iteration cap (API key auth only)

# Watch
WATCH_POLL_INTERVAL=5
WATCH_BATCH_SIZE=10
WATCH_MAX_FILE_SIZE=52428800      # 50MB

# Patrol
PATROL_TICK_INTERVAL=10
PATROL_REVIEW_INTERVAL=1800       # 30 min
PATROL_REVIEW_BUDGET_USD="0.50"

# C2
C2_DEBOUNCE_INTERVAL=300          # 5 min
C2_REVIEW_BUDGET_USD="0.75"
C2_MAX_FINDINGS_PER_REVIEW=20
C2_CONTEXT_WINDOW=10
```

Budget settings (`MAX_BUDGET_USD`, `*_REVIEW_BUDGET_USD`) are per-invocation caps enforced by Claude Code CLI via `--max-budget-usd`. These only apply to API key auth (pay-per-use). On Pro/Max OAuth subscriptions, the constraint is the subscription rate limit, not dollars.

### Data directory

Default: `~/.local/share/secy`. Override via environment variable:

```bash
export SECY_DATA_DIR=/path/to/custom/location
./setup.sh install
```

## Status

Prototype. Not audited for production use. Redaction patterns and blocklists are not exhaustive.

## Docs

- [docs/THREATS.md](docs/THREATS.md) — Threat detection index
- [docs/THREATS-DEPTH.md](docs/THREATS-DEPTH.md) — Detailed threat explanations and remediation
- [docs/plans/sandboxing.md](docs/plans/sandboxing.md) — Security architecture and sandbox layers
- [docs/plans/sread.md](docs/plans/sread.md) — sread architecture and module inventory
- [docs/plans/watch-mode.md](docs/plans/watch-mode.md) — Watch mode design
- [docs/plans/patrol-mode.md](docs/plans/patrol-mode.md) — Patrol mode design
- [docs/plans/c2-inotify.md](docs/plans/c2-inotify.md) — C2 + inotify implementation plan
- [docs/plans/threatlab.md](docs/plans/threatlab.md) — Threat lab test container design
