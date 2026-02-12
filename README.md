# secy — Autonomous Security Monitor for Linux

An autonomous AI security monitor that continuously watches your Linux system for threats. Four containerized services — watch, patrol, C2, and one-shot audit — read the host filesystem, detect anomalies, correlate findings across services, and report actionable issues to the user. Runs inside sandboxed Docker containers with read-only host access.

## How it works

```
  Host machine
  ┌─────────────────────────────────────────────────────────────┐
  │  ./issues/  ← only host-visible output (bind mount)        │
  │                                                             │
  │  Docker   ┌────────────────────────────────────────────┐    │
  │           │  secy-state volume (internal, not on host) │    │
  │           │  ├── findings/   ← all services write here │    │
  │           │  ├── directives/ ← C2 writes, others read  │    │
  │           │  ├── patrol/     ← module runs, diffs       │    │
  │           │  ├── watch/      ← seen DB, queue           │    │
  │           │  ├── c2/         ← progress memory          │    │
  │           │  └── issues/     ← overlaid by bind mount   │    │
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
  └─────────────────────────────────────────────────────────────┘
```

**Watch** monitors Downloads for new files — hash-checks against a malware database, then triages unknowns with Claude. **Patrol** runs scheduled security scans (ports, services, kernel modules, users, etc.), diffs between runs, and reviews changes with Claude. **C2** correlates findings across both services, identifies compound threats (e.g., suspicious download + new listening port), and creates issues for the user.

The only output visible on the host is `./issues/` — self-contained markdown files describing what was detected, the evidence, and what to investigate. All internal state lives on a Docker named volume.

No commands are executed on the host. The containers read the host filesystem at `/host` (read-only mount) and use `sread` — a restricted audit tool with blocklist enforcement and output redaction — for config files that may contain secrets.

## Setup

### Prerequisites

- Docker and Docker Compose
- One of:
  - **Claude Code OAuth** (Pro/Max subscription) — `claude` CLI authenticated on the host
  - **Anthropic API key** (pay-per-use)

### Build

```bash
git clone https://github.com/suisuss/secy.git && cd secy
docker compose build
```

### Authentication

**Option A: OAuth (Pro/Max subscription)**

If you've already authenticated with `claude` on the host, credentials are at `~/.claude/.credentials.json`. The container mounts this automatically — no extra config needed.

**Option B: API key**

Uncomment the `ANTHROPIC_API_KEY` line in `docker-compose.yml` and set the key:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
docker compose run secy audit
```

Or pass it inline:

```bash
ANTHROPIC_API_KEY=sk-ant-... docker compose run secy audit
```

## Run

### Start all monitoring services

```bash
# Start watch + patrol + C2 (recommended — full autonomous monitoring)
docker compose up -d secy-watch secy-patrol secy-c2

# Check service status
docker compose ps

# View logs
docker compose logs -f secy-c2

# Stop all services
docker compose down
```

### Individual services

```bash
# Watch Downloads for malware (daemon)
docker compose up -d secy-watch

# Patrol — scheduled security scans (daemon)
docker compose up -d secy-patrol

# C2 — cross-service correlation (daemon)
docker compose up -d secy-c2

# One-shot: full security audit
docker compose run --rm secy audit

# One-shot: capture baseline
docker compose run --rm secy baseline

# One-shot: compare against baseline
docker compose run --rm secy monitor
```

### Without AI (dry-run / debugging)

```bash
# Watch: hash-check only, no Claude triage
docker compose run --rm secy watch --no-claude

# Patrol: module scans and diffs only, no Claude review
docker compose run --rm secy patrol --no-claude

# C2: detect new findings but don't invoke Claude for correlation
docker compose run --rm secy c2 --no-claude
```

Issues are written to `./issues/` on the host. Internal findings and state live on the `secy-state` Docker volume.

### What to expect

The agent streams its activity as it works:

```
[secy 2026-02-09T00:24:06+00:00] Starting audit (max 3 iterations)
[secy 2026-02-09T00:24:06+00:00] Iteration 1/3
  [init] model=claude-sonnet-4-5-20250929
  [read] /host/proc/net/tcp
  [read] /host/etc/passwd
  [bash] find /host -perm -4000 -type f 2>/dev/null
  [read] /host/etc/ssh/sshd_config
  [write] /var/lib/secy/state/findings/audit-2026-02-09-002406.md
  [done] 12 turns, 45230ms, $0.42
```

A baseline run takes ~2–4 minutes. An audit takes ~5–10 minutes across up to 3 iterations.

### Troubleshooting

**No output from Claude (exits immediately):**
Check `/root/.claude/debug/latest` inside the container for the actual error:

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

**"Not logged in" error:** OAuth credentials aren't being found. Check that `~/.claude/.credentials.json` exists on the host. If using `--entrypoint bash`, you must manually copy credentials (the entrypoint is bypassed).

**srt sandbox fails:** Expected in most Docker setups. The agent falls back to running without srt — Docker is the primary sandbox boundary.

## Services

| Service | Role | Runs as | AI? |
|---------|------|---------|-----|
| `secy` | One-shot audit, baseline, monitor | `docker compose run` | Yes |
| `secy-watch` | Downloads malware detection | Daemon | Yes (triage) |
| `secy-patrol` | Scheduled security scans | Daemon | Yes (diff review) |
| `secy-c2` | Cross-service correlation | Daemon | Yes (correlation) |

### Watch

Monitors `/home/*/Downloads/` for new files using inotify (with polling fallback for environments where inotify doesn't work on Docker bind mounts). For each new file:

1. **Hash check** — SHA256 against MalwareBazaar database (~1.5M known malware hashes, baked in at build time). Known malware triggers an immediate CRITICAL alert.
2. **Classify** — MIME type check. Media files are skipped. Scripts, executables, PDFs, office docs, and archives are queued.
3. **AI triage** — Claude assesses each queued file as CLEAN, SUSPICIOUS, or MALICIOUS based on metadata, structure, and content indicators.

Triage reports are written to `state/findings/watch-*.md`. The hash database is baked at build time — rebuild the image to refresh it.

### Patrol

Runs sread modules on configurable schedules, diffs output between runs, and invokes Claude to review meaningful changes.

Each module runs at its own interval (e.g., `ports` every 5 minutes, `pkgverify` every hour). When non-empty diffs accumulate — especially from high-priority modules — Claude is invoked to assess what changed.

Module schedules are configurable via `state/patrol/schedule.conf` (created on first run with defaults). Patrol also checks `state/directives/` for C2 overrides every 60 seconds.

### C2 (correlation)

Monitors `state/findings/` for new reports from watch and patrol. When findings accumulate past a debounce interval (default 5 minutes), spawns Claude to:

1. **Correlate across services** — a suspicious download (watch) + a new listening port (patrol) together indicate the download was executed
2. **Assess compound threats** — staging, persistence, privilege escalation, lateral movement, exfiltration patterns
3. **Issue directives** — increase scan frequency for specific modules, expand watch directories
4. **Create issues** — self-contained reports written to `./issues/` for the user

C2 can adjust what watch and patrol monitor, but never takes remediation actions. secy is strictly observe-only.

### One-shot modes

| Mode | What it does | Iterations |
|------|-------------|-----------|
| `baseline` | Captures current system state as the "normal" reference | 1 |
| `audit` | Full security sweep — reads system files, produces findings report | Up to 3 |
| `monitor` | Compares current state against baseline, flags deviations | Up to 2 |

## Issues

Issues are how secy communicates with the user. The `./issues/` directory is the **only** secy output visible on the host — all other state lives on an internal Docker volume.

When C2 identifies something that warrants user attention, it creates a markdown file in `./issues/`:

```
issues/
├── 0001-suspicious-binary-downloaded.md
├── 0003-new-listening-port-4444.md
└── 0005-suid-binary-outside-package.md
```

Each issue is self-contained — it includes all evidence, timestamps, detection details, and recommended investigation steps. The user does not need access to internal secy state to understand or act on an issue.

**Lifecycle**: an issue file exists = open. The user deletes it when resolved. If the same problem recurs with new evidence, C2 creates a new issue.

### Issue format

Every issue includes:
- **What was detected** — plain language description with specific files, ports, processes, timestamps
- **How it was detected** — which service(s) flagged it, what scan found the anomaly, timestamps
- **Evidence** — inline data: hashes, diff snippets, port numbers, process names. Commands the user can run on the host to verify (e.g., `ss -tlnp`, `stat`, `ls -la`)
- **Why this matters** — security implication, attack stage, confidence level
- **Recommended action** — what to investigate, what to look for. Never includes remediation commands — the user decides what to do

### Severity levels

- **critical** — likely active threat requiring prompt attention
- **warning** — suspicious activity worth investigating
- **info** — notable change the user should be aware of

## Directives

C2 adjusts monitoring by writing directive files. Watch and patrol poll for changes every 60 seconds.

| Directive | Target | Purpose |
|-----------|--------|---------|
| `state/directives/schedule-override.conf` | Patrol | Increase scan frequency for specific modules |
| `state/directives/watch-config.conf` | Watch | Expand watch coverage (extra directories, scan depth) |
| `state/directives/active/*.directive` | Patrol | One-shot overrides (moved to `applied/` after processing) |
| `state/directives/active/*.watch-directive` | Watch | One-shot overrides (moved to `applied/` after processing) |

When a service processes a directive, it moves it from `active/` to `applied/` and writes a `.report` file documenting what changed. C2 reads these reports to verify directives were applied correctly.

Directives only adjust what secy monitors — they never kill processes, delete files, modify firewall rules, or take any action that changes the host system.

## What it checks

The agent reads host files and analyzes:

| Area | Source files | What it looks for |
|------|-------------|-------------------|
| Network | `/proc/net/tcp`, `tcp6`, `udp`, `udp6` | Listeners on 0.0.0.0, databases on non-localhost, unexpected ports |
| Users | `/etc/passwd`, `/etc/group`, `/etc/sudoers` | Extra UID 0 accounts, service accounts with login shells, overly permissive sudo |
| SSH | `/etc/ssh/sshd_config` | Root login, password auth, empty passwords, X11 forwarding |
| Kernel | `/proc/sys/net/ipv4/*`, `kernel/*`, `fs/*` | IP forwarding, ASLR, ICMP redirects, ptrace restrictions |
| Firewall | `/etc/nftables.conf`, `/etc/iptables/rules.v4` | Default ACCEPT policies, missing IPv6 rules |
| Cron | `/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/*` | Root jobs in writable dirs, remote execution patterns |
| Auth logs | `/var/log/auth.log` | Brute force attempts, unexpected logins, sudo by wrong users |
| SUID | `find -perm -4000` | GTFOBins candidates, SUID outside standard locations |
| World-writable | `find -perm -0002` | Writable files in /etc, writable executables, writable root-owned files |
| Services | `/etc/systemd/system/*` | Insecure legacy services, missing hardening directives |
| Surveillance processes | `/proc/*/cmdline`, `/proc/*/status` | Keyloggers, screen recorders, RATs, ptrace attachments, `/dev/input` readers |
| Library injection | `/etc/ld.so.preload`, `/proc/*/environ` | LD_PRELOAD hijacking, suspicious shared libraries, shell profile hooks |
| Kernel modules | `/proc/modules`, `/sys/module/*/taint` | Suspicious module names, unsigned/out-of-tree modules |
| Autostart persistence | `/etc/xdg/autostart/*`, `~/.config/autostart/*` | Unexpected XDG autostart entries, systemd user services, rc.local, non-package init.d scripts |
| Network connections | `/proc/net/tcp` (established) | Suspicious outbound connections, process attribution, unusual remote ports |
| Desktop surveillance | GNOME extensions, browser extensions, dconf | Remote desktop, screen sharing, unknown browser extensions |

## Security model

Each container runs three nested isolation layers:

```
┌──────────────────────────────────────────────────────┐
│  Docker Container                                     │
│  - /host:ro (read-only host mount)                    │
│  - read_only: true (immutable container filesystem)   │
│  - no-new-privileges, cap_drop: ALL                   │
│  - tmpfs: /tmp, /root (only writable dirs)            │
│                                                       │
│  ┌────────────────────────────────────────────────┐  │
│  │  srt (Anthropic sandbox-runtime)               │  │
│  │  - Network: api.anthropic.com only             │  │
│  │  - Filesystem: deny /etc/shadow, SSH keys,     │  │
│  │    credential stores                            │  │
│  │                                                │  │
│  │  ┌──────────────────────────────────────────┐  │  │
│  │  │  Claude Code + sread                     │  │  │
│  │  │  - sread: path blocklist (~250 rules),   │  │  │
│  │  │    output redaction, MIME whitelist       │  │  │
│  │  │  - Reads /host/proc, /host/etc, /host/var│  │  │
│  │  │  - Writes to state volume + issues/      │  │  │
│  │  └──────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
```

| Layer | Mechanism | Prevents |
|-------|-----------|----------|
| **Docker** | Read-only host mount (`/host:ro`), immutable container filesystem (`read_only: true`), `no-new-privileges`, all capabilities dropped except `DAC_READ_SEARCH`/`SYS_ADMIN`/`NET_ADMIN`, tmpfs-only writable dirs (`/tmp`, `/root`) | Host modification, privilege escalation, command execution on host, tampering with agent code or config |
| **srt** | Anthropic sandbox-runtime — network allowlist (`api.anthropic.com` only), filesystem deny on credentials/keys. Falls back gracefully if bubblewrap doesn't work inside Docker. | Data exfiltration, credential theft at OS level |
| **sread** | Path blocklist (~250 rules), output redaction, MIME type whitelist, argument validation | Credential file reads, password leakage in output, binary file reads |

All four services (`secy-watch`, `secy-patrol`, `secy-c2`, `secy`) run the same image with identical security posture. The container filesystem is immutable — the agent cannot modify sread config, blocklists, or its own prompts. Writable storage is limited to the `secy-state` named volume (shared state) and tmpfs mounts.

The `./issues/` bind mount is the only path where container writes appear on the host filesystem. Internal state (findings, directives, patrol runs, watch queue) lives entirely on the Docker volume and is not directly accessible from the host.

See [docs/plans/sandboxing.md](docs/plans/sandboxing.md) for the full threat model.

### What is NOT defended

- Audit output and issues reveal system architecture (users, ports, services, configs). Treat `./issues/` as sensitive.
- Prompt injection from host files (malicious log entries, poisoned configs) could influence agent reasoning. The three layers constrain what the agent can do in response.
- Audit data is sent to the Claude API. This is inherent to using a cloud LLM.
- secy is observe-only — it does not remediate threats. A compromised host could theoretically feed misleading data through `/host:ro`.

## Project structure

```
secy/
├── agent/
│   ├── secy.sh                    # Entry point — mode dispatch
│   ├── watch.sh                   # Watch daemon — inotify/poll + Claude triage
│   ├── patrol.sh                  # Patrol daemon — scheduled scans + Claude review
│   ├── c2.sh                     # C2 daemon — correlation + directives + issues
│   ├── entrypoint.sh              # Docker entrypoint (tmpfs setup, credential copy)
│   ├── AGENT.md                   # System prompt — security audit
│   ├── WATCH.md                   # System prompt — malware triage
│   ├── PATROL.md                  # System prompt — diff review
│   ├── C2.md                     # System prompt — correlation analyst
│   ├── conf/
│   │   ├── agent.conf             # All mode settings (audit, watch, patrol, C2)
│   │   └── srt-settings.json     # Anthropic sandbox-runtime config
│   └── lib/
│       ├── secy-common.sh         # Shared: logging, daemon init, Claude invocation
│       ├── agent-common.sh        # Audit/baseline/monitor: lock, preflight, prompts
│       ├── watch-common.sh        # Watch: seen DB, queue, classify, directive reload
│       ├── patrol-common.sh       # Patrol: scheduling, module runs, diff, directive reload
│       ├── c2-common.sh           # C2: state, context assembly, issue management
│       ├── inotify-watch.sh       # Shared: inotify + poll fallback (used by watch + C2)
│       └── format-stream.sh       # Stream-JSON formatter for activity log
├── sread/                         # Restricted audit tool (25 modules)
│   ├── bin/sread                  # Main binary (dispatch, arg validation, audit log)
│   ├── lib/
│   │   ├── common.sh, redact.sh, blocklist.sh
│   │   └── modules/               # 25 audit modules
│   ├── data/                      # Baked-in data (malware hash DB at build time)
│   ├── conf/                      # blocked_paths, allowed_mimetypes, redact_patterns
│   └── tests/
├── issues/                        # User-facing output (bind-mounted from host, gitignored)
├── docs/plans/                    # Design documents
├── THREATS.md                     # Threat detection index (63 techniques)
├── THREATS-DEPTH.md               # Detailed threat explanations and remediation
├── Dockerfile
├── docker-compose.yml
└── .gitignore
```

### Runtime state (Docker volume, not on host)

```
secy-state volume → /var/lib/secy/state/
├── findings/          # Reports from watch, patrol, and C2
├── directives/
│   ├── schedule-override.conf    # Persistent patrol overrides
│   ├── watch-config.conf         # Persistent watch overrides
│   ├── active/                   # One-shot directives (pending)
│   └── applied/                  # Processed directives + .report files
├── patrol/
│   ├── runs/<module>/latest.out  # Latest module output
│   ├── diffs/                    # Diffs between runs
│   └── schedule.conf             # Module schedule
├── watch/
│   ├── seen.db                   # Processed file database
│   └── queue/                    # Files pending triage
├── c2/
│   ├── processed.db              # Findings already correlated
│   └── progress.md               # Investigation continuity notes
├── baseline/                     # Baseline snapshots
└── issues/                       # Overlaid by bind mount → ./issues/ on host
```

## Agent architecture

secy uses the [Ralph pattern](docs/plans/ai-agent-landscape.md#ralph): a bash loop that spawns fresh Claude Code instances with filesystem-based memory.

Each Claude invocation:
1. Assembles a prompt (system instructions + mode-specific task + context from previous runs)
2. Spawns `claude --dangerously-skip-permissions --print ...` (wrapped in `srt` if the sandbox is available)
3. Claude reads host files, analyzes them, writes findings
4. Checks for completion signal (`SECY_COMPLETE`)
5. If not complete, loops with fresh context (reads progress file for continuity)

This means:
- No context window degradation across long monitoring sessions
- Each invocation is stateless from the LLM's perspective
- Memory persists via files on disk (findings, progress, directives, issues)
- Services communicate exclusively through the shared filesystem

## Configuration

### Agent settings (`agent/conf/agent.conf`)

```bash
# One-shot modes
AUDIT_MAX_ITERATIONS=3      # Max iterations for audit mode
MONITOR_MAX_ITERATIONS=2    # Max iterations for monitor mode
BASELINE_MAX_ITERATIONS=1   # Max iterations for baseline capture
CLAUDE_MODEL="sonnet"       # Claude model to use
MAX_BUDGET_USD="1.00"       # Spend cap per iteration

# Watch
WATCH_POLL_INTERVAL=5       # Seconds between scan cycles (poll fallback)
WATCH_BATCH_SIZE=10         # Max files per Claude triage batch
WATCH_MAX_FILE_SIZE=52428800  # Skip files >50MB
WATCH_SCAN_DEPTH=1          # Don't recurse into subdirs

# Patrol
PATROL_TICK_INTERVAL=10          # Main loop tick (seconds)
PATROL_REVIEW_INTERVAL=1800     # Claude review interval (30 min)
PATROL_REVIEW_BUDGET_USD="0.50" # Budget per Claude review

# C2
C2_POLL_INTERVAL=30          # Fallback poll if inotify fails (seconds)
C2_DEBOUNCE_INTERVAL=300     # Min seconds between Claude invocations
C2_REVIEW_BUDGET_USD="0.75"  # Budget per C2 invocation
C2_MAX_FINDINGS_PER_REVIEW=20
C2_CONTEXT_WINDOW=10         # Historical findings for context

# Directives (all services)
DIRECTIVE_CHECK_INTERVAL=60  # How often services check for directives
```

### Sandbox settings (`agent/conf/srt-settings.json`)

Network and filesystem restrictions enforced by Anthropic's sandbox-runtime. See [docs/sandboxing.md](docs/sandboxing.md).

### sread settings (`sread/conf/`)

sread is a restricted read tool the agent can use for config files that may contain secrets. It enforces a path blocklist, redacts sensitive values in output, and rejects non-text files. Edit `sread/conf/blocked_paths`, `sread/conf/redact_patterns`, and `sread/conf/allowed_mimetypes` to tune its behavior. Run `sread --help` for available modules.

## Status

Prototype. Not audited for production use. Redaction patterns and blocklists are not exhaustive.

## Docs

- [docs/plans/c2-inotify.md](docs/plans/c2-inotify.md) — C2 + inotify implementation plan
- [docs/plans/sread.md](docs/plans/sread.md) — sread architecture, threat model, and module inventory
- [docs/plans/sandboxing.md](docs/plans/sandboxing.md) — Security architecture and sandbox layers
- [docs/plans/everything-is-a-file.md](docs/plans/everything-is-a-file.md) — Design decision: file reading vs command execution
- [docs/plans/watch-mode.md](docs/plans/watch-mode.md) — Watch mode design
- [docs/plans/patrol-mode.md](docs/plans/patrol-mode.md) — Patrol mode design
- [docs/plans/threatlab.md](docs/plans/threatlab.md) — Threat lab test container design
- [THREATS.md](THREATS.md) — Threat detection index (63 techniques, coverage map)
- [THREATS-DEPTH.md](THREATS-DEPTH.md) — Detailed threat explanations, detection sources, and remediation
