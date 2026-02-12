# secy — Security Audit Agent for Linux Systems

An autonomous AI agent that reads your system's files, identifies security anomalies, explains what it finds, and recommends specific fixes. Runs inside a sandboxed Docker container with read-only access to the host.

## How it works

```
┌──────────────────────────────────────────────────────┐
│  Docker Container (read-only host at /host)           │
│                                                       │
│  ┌────────────────────────────────────────────────┐  │
│  │  srt (Anthropic sandbox-runtime)               │  │
│  │  Network: api.anthropic.com only               │  │
│  │  Filesystem: deny credentials, keys            │  │
│  │                                                │  │
│  │  ┌──────────────────────────────────────────┐  │  │
│  │  │  Claude Code                             │  │  │
│  │  │  Reads /host/proc, /host/etc, /host/var  │  │  │
│  │  │  Uses sread for redacted config reads    │  │  │
│  │  │  Writes findings to state volume         │  │  │
│  │  └──────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
```

The agent reads host state directly from files — `/proc/net/tcp` for open ports, `/etc/passwd` for users, `/proc/sys/` for kernel parameters, `/var/log/auth.log` for login attempts. No commands are executed on the host. The container has no host namespace access.

For config files that may contain secrets, the agent uses `sread` — a restricted audit tool with blocklist enforcement and output redaction.

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

```bash
# Full security audit
docker compose run secy audit

# Capture a baseline first (for change detection later)
docker compose run secy baseline

# Compare current state against baseline
docker compose run secy monitor

# Watch Downloads for malware (runs as daemon)
docker compose up -d secy-watch

# Watch without AI analysis (hash-check only)
docker compose run secy watch --no-claude

# Persistent security monitoring — scheduled module scans + AI review
docker compose up -d secy-patrol

# Patrol without AI review (module scans and diffs only)
docker compose run secy patrol --no-claude

# Clean up orphan containers from previous runs
docker compose run --remove-orphans secy audit
```

Findings are written to `./state/findings/` on the host.

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

## Modes

| Mode | What it does | Iterations |
|------|-------------|-----------|
| `baseline` | Captures current system state as the "normal" reference | 1 |
| `audit` | Full security sweep — reads system files, analyzes for anomalies, produces findings report with explanations and recommendations | Up to 3 |
| `monitor` | Compares current state against baseline, flags deviations | Up to 2 |
| `watch` | Continuously monitors Downloads for new files — checks hashes against malware DB, triggers Claude triage for unknown analyzable files | Daemon (runs indefinitely) |
| `patrol` | Persistent security monitoring — runs sread modules on a schedule, diffs output between runs, invokes secy to review meaningful changes | Daemon (runs indefinitely) |

## Watch mode

Watch mode is a long-lived daemon that monitors `/home/*/Downloads/` for new files. For each new file:

1. **Hash check** — computes SHA256 and checks against MalwareBazaar database (~1.5M known malware hashes, baked in at build time). Known malware triggers an immediate CRITICAL alert.
2. **Classify** — determines file type via MIME. Media files (images/video/audio) are skipped (hash check still catches them). Scripts, executables, PDFs, office docs, and archives are queued for analysis.
3. **AI triage** — batches queued files and spawns a Claude instance to assess each as CLEAN, SUSPICIOUS, or MALICIOUS based on metadata, structure, and content indicators.

```bash
# Run as background daemon
docker compose up -d secy-watch

# Run interactively (hash-check only, no AI)
docker compose run secy watch --no-claude

# Custom poll interval
docker compose run secy watch --poll-interval 10

# Stop the daemon
docker compose down secy-watch
```

Alerts and triage reports are written to `./state/findings/`. The hash database is baked at Docker build time — rebuild the image to refresh it (recommend daily cron for production).

## Patrol mode

Patrol mode is a persistent daemon that continuously runs sread modules on configurable schedules, detects changes between runs, and periodically invokes secy to review meaningful diffs.

Each module runs at its own interval (e.g., `ports` every 5 minutes, `pkgverify` every hour). Output is diffed against the previous run. When non-empty diffs accumulate — especially from high-priority modules — Claude is invoked to assess what changed and whether it's benign or suspicious.

```bash
# Run as background daemon
docker compose up -d secy-patrol

# Run interactively (module scans only, no AI review)
docker compose run secy patrol --no-claude

# Custom intervals
docker compose run secy patrol --tick-interval 5 --review-interval 900

# Stop the daemon
docker compose down secy-patrol
```

Module schedules are configurable via `state/patrol/schedule.conf` (created on first run with defaults). State persists across restarts in `./state/patrol/`.

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

## Output

The agent produces a markdown findings report with three severity levels:

- **CRITICAL** — Active exploitation indicators, privilege escalation paths
- **WARNING** — Weak configuration, unnecessary exposure, missing hardening
- **INFO** — Deviations from best practice, notable observations

Every finding includes:
- The specific file and content that triggered it
- An explanation of why it matters
- A specific command the operator should run on the host to fix it

## Security model

Three independent layers, each enforced at a different level:

| Layer | Mechanism | Prevents |
|-------|-----------|----------|
| **Docker** | Read-only host mount, read-only container, `no-new-privileges`, minimal capabilities | Host modification, privilege escalation, command execution on host |
| **srt** | Network allowlist (`api.anthropic.com` only), filesystem deny on credentials | Data exfiltration, credential theft at OS level |
| **sread** | Path blocklist, output redaction, MIME type whitelist, argument validation | Credential file reads, password leakage in output, binary file reads |

See [docs/sandboxing.md](docs/sandboxing.md) for the full threat model.

### What is NOT defended

- Audit output reveals system architecture (users, ports, services, configs). Treat findings as sensitive.
- Prompt injection from host files (malicious log entries, poisoned configs) could influence agent reasoning. The three layers constrain what the agent can do in response.
- Audit data is sent to the Claude API. This is inherent to using a cloud LLM.

## Project structure

```
secy/
├── agent/
│   ├── secy.sh                    # Entry point — mode dispatch (Ralph loop + daemon exec)
│   ├── watch.sh                   # Watch daemon — Downloads monitoring loop
│   ├── patrol.sh                  # Patrol daemon — scheduled module scans + AI review
│   ├── entrypoint.sh              # Docker entrypoint (tmpfs setup, credential copy)
│   ├── AGENT.md                   # System prompt — security audit domain knowledge
│   ├── WATCH.md                   # System prompt — malware triage for watch mode
│   ├── PATROL.md                  # System prompt — diff review for patrol mode
│   ├── conf/
│   │   ├── agent.conf             # All mode settings (iterations, watch, patrol)
│   │   └── srt-settings.json     # Anthropic sandbox-runtime config
│   └── lib/
│       ├── agent-common.sh        # Lock, preflight, prompt assembly (audit/baseline/monitor)
│       ├── watch-common.sh        # Watch utilities (seen.db, queue, classify, alerts)
│       ├── patrol-common.sh       # Patrol utilities (scheduling, module runs, diff, review)
│       └── format-stream.sh       # Stream-JSON formatter for activity log
├── sread/                             # Restricted audit tool (25 modules)
│   ├── bin/
│   │   └── sread                      # Main binary (dispatch, arg validation, audit log)
│   ├── lib/
│   │   ├── common.sh                  # Shared utilities (logging, colors, require_root)
│   │   ├── redact.sh                  # Output redaction engine
│   │   ├── blocklist.sh              # Path blocking, MIME checking, symlink resolution
│   │   └── modules/                   # 25 audit modules
│   ├── data/                          # Baked-in data (malware hash DB at build time)
│   ├── conf/
│   │   ├── blocked_paths              # Credential file patterns (~250 rules)
│   │   ├── allowed_mimetypes          # MIME type whitelist
│   │   ├── redact_patterns            # Output redaction regexes
│   │   └── sread.sudoers              # sudoers drop-in (for non-Docker use)
│   ├── tests/                         # Unit + integration tests
│   └── install.sh                     # sread standalone install
├── docs/
│   └── plans/                     # Design documents
│       ├── sread.md               # sread architecture and threat model
│       ├── sandboxing.md          # Security architecture and sandbox layers
│       ├── watch-mode.md          # Watch mode design
│       ├── patrol-mode.md         # Patrol mode design
│       ├── threatlab.md           # Threat lab test container design
│       └── everything-is-a-file.md  # File-reading vs command-execution rationale
├── state/                         # Runtime (gitignored)
│   ├── baseline/                  # Baseline snapshots
│   ├── current/                   # Latest run outputs
│   ├── findings/                  # Timestamped reports and alerts
│   ├── watch/                     # Watch daemon state (seen.db, queue, log)
│   └── patrol/                    # Patrol daemon state (runs, diffs, schedule, log)
├── THREATS.md                     # Threat detection index (63 techniques, coverage map)
├── THREATS-DEPTH.md               # Detailed threat explanations, detection, remediation
├── Dockerfile
├── docker-compose.yml
├── .env.example                   # API key config template
└── .gitignore
```

## Agent architecture

secy uses the [Ralph pattern](docs/ai-agent-landscape.md#ralph): a bash loop that spawns fresh Claude Code instances with filesystem-based memory.

Each iteration:
1. Assembles a prompt (system instructions + mode-specific task + progress from previous iterations)
2. Spawns `claude --dangerously-skip-permissions --print ...` (wrapped in `srt` if the sandbox is available)
3. Claude reads host files, analyzes them, writes findings
4. Checks for completion signal (`SECY_COMPLETE`)
5. If not complete, loops with fresh context (reads progress file for continuity)

This means:
- No context window degradation across a full audit
- Each iteration is stateless from the LLM's perspective
- Memory persists via files on disk (progress.md, findings, baseline)
- The agent can iteratively investigate: find anomaly → follow up → finalize report

## Configuration

### Agent settings (`agent/conf/agent.conf`)

```bash
AUDIT_MAX_ITERATIONS=3      # Max iterations for audit mode
MONITOR_MAX_ITERATIONS=2    # Max iterations for monitor mode
BASELINE_MAX_ITERATIONS=1   # Max iterations for baseline capture
CLAUDE_MODEL="sonnet"       # Claude model to use
MAX_BUDGET_USD="1.00"       # Spend cap per iteration

# Watch mode
WATCH_POLL_INTERVAL=5       # Seconds between scan cycles
WATCH_BATCH_SIZE=10         # Max files per Claude triage batch
WATCH_MAX_FILE_SIZE=52428800  # Skip files >50MB
WATCH_SCAN_DEPTH=1          # Don't recurse into subdirs

# Patrol mode
PATROL_TICK_INTERVAL=10          # Main loop tick (seconds)
PATROL_REVIEW_INTERVAL=1800     # Claude review interval (seconds, 30 min)
PATROL_REVIEW_BUDGET_USD="0.50" # Budget per Claude review invocation
```

### Sandbox settings (`agent/conf/srt-settings.json`)

Network and filesystem restrictions enforced by Anthropic's sandbox-runtime. See [docs/sandboxing.md](docs/sandboxing.md).

### sread settings (`sread/conf/`)

sread is a restricted read tool the agent can use for config files that may contain secrets. It enforces a path blocklist, redacts sensitive values in output, and rejects non-text files. Edit `sread/conf/blocked_paths`, `sread/conf/redact_patterns`, and `sread/conf/allowed_mimetypes` to tune its behavior. Run `sread --help` for available modules.

## Status

Prototype. Not audited for production use. Redaction patterns and blocklists are not exhaustive.

## Docs

- [docs/plans/sread.md](docs/plans/sread.md) — sread architecture, threat model, and module inventory
- [docs/plans/sandboxing.md](docs/plans/sandboxing.md) — Security architecture and sandbox layers
- [docs/plans/everything-is-a-file.md](docs/plans/everything-is-a-file.md) — Design decision: file reading vs command execution
- [docs/plans/watch-mode.md](docs/plans/watch-mode.md) — Watch mode design
- [docs/plans/patrol-mode.md](docs/plans/patrol-mode.md) — Patrol mode design
- [docs/plans/threatlab.md](docs/plans/threatlab.md) — Threat lab test container design
- [THREATS.md](THREATS.md) — Threat detection index (63 techniques, coverage map)
- [THREATS-DEPTH.md](THREATS-DEPTH.md) — Detailed threat explanations, detection sources, and remediation
