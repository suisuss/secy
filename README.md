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
│   ├── secy.sh                    # Outer loop (Ralph pattern)
│   ├── AGENT.md                   # Agent prompt — security domain knowledge
│   ├── conf/
│   │   ├── agent.conf             # Iteration limits, model, settings
│   │   └── srt-settings.json     # Anthropic sandbox-runtime config
│   └── lib/
│       ├── agent-common.sh        # Lock, preflight, prompt assembly
│       └── format-stream.sh       # Stream-JSON formatter for activity log
├── sread/                             # Restricted read tool (blocklist + redaction)
│   ├── bin/
│   │   └── sread                      # Main binary
│   ├── lib/
│   │   ├── common.sh                  # Shared utilities
│   │   ├── redact.sh                  # Output redaction engine
│   │   ├── blocklist.sh              # Path blocking, MIME checking
│   │   └── modules/                   # Audit modules (files, ports, users, ...)
│   ├── conf/
│   │   ├── blocked_paths              # Credential file patterns
│   │   ├── allowed_mimetypes          # MIME type whitelist
│   │   ├── redact_patterns            # Output redaction regexes
│   │   └── sread.sudoers              # sudoers drop-in (for non-Docker use)
│   ├── tests/                         # Unit + integration tests
│   └── install.sh                     # sread standalone install
├── docs/
│   ├── DESIGN.md                  # sread threat model
│   ├── sandboxing.md              # Security architecture
│   ├── sandboxing-audit.md        # Sandboxing audit findings
│   ├── shift.md                   # Design decisions
│   └── ai-agent-landscape.md     # Analysis of Ralph, OpenClaw
├── state/                         # Runtime (gitignored)
│   ├── baseline/                  # Module output snapshots
│   ├── current/                   # Latest run outputs
│   └── findings/                  # Timestamped reports
├── Dockerfile
├── docker-compose.yml
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
```

### Sandbox settings (`agent/conf/srt-settings.json`)

Network and filesystem restrictions enforced by Anthropic's sandbox-runtime. See [docs/sandboxing.md](docs/sandboxing.md).

### sread settings (`sread/conf/`)

sread is a restricted read tool the agent can use for config files that may contain secrets. It enforces a path blocklist, redacts sensitive values in output, and rejects non-text files. Edit `sread/conf/blocked_paths`, `sread/conf/redact_patterns`, and `sread/conf/allowed_mimetypes` to tune its behavior. Run `sread --help` for available modules.

## Status

Prototype. Not audited for production use. Redaction patterns and blocklists are not exhaustive.

## Docs

- [docs/sandboxing.md](docs/sandboxing.md) — Security architecture and threat model
- [docs/shift.md](docs/shift.md) — Design decision: file reading vs command execution
- [docs/ai-agent-landscape.md](docs/ai-agent-landscape.md) — Analysis of Ralph, Ralph Playbook, OpenClaw
- [docs/sandboxing-audit.md](docs/sandboxing-audit.md) — Sandboxing audit findings
- [docs/DESIGN.md](docs/DESIGN.md) — sread threat model and trust assumptions
