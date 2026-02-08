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
│  │  │  Uses secy for redacted config reads     │  │  │
│  │  │  Writes findings to state volume         │  │  │
│  │  └──────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
```

The agent reads host state directly from files — `/proc/net/tcp` for open ports, `/etc/passwd` for users, `/proc/sys/` for kernel parameters, `/var/log/auth.log` for login attempts. No commands are executed on the host. The container has no host namespace access.

For config files that may contain secrets, the agent uses `secy` — a restricted audit tool with blocklist enforcement and output redaction.

## Quick start

```bash
# Clone
git clone https://github.com/suisuss/secy.git && cd secy

# Build the container
docker compose build

# Run a security audit
ANTHROPIC_API_KEY=sk-... docker compose run secy-agent audit

# Capture a baseline (for change detection)
ANTHROPIC_API_KEY=sk-... docker compose run secy-agent baseline

# Monitor for changes against baseline
ANTHROPIC_API_KEY=sk-... docker compose run secy-agent monitor
```

Findings are written to `./state/findings/` on the host.

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
| **secy** | Path blocklist, output redaction, MIME type whitelist, argument validation | Credential file reads, password leakage in output, binary file reads |

See [docs/sandboxing.md](docs/sandboxing.md) for the full threat model.

### What is NOT defended

- Audit output reveals system architecture (users, ports, services, configs). Treat findings as sensitive.
- Prompt injection from host files (malicious log entries, poisoned configs) could influence agent reasoning. The three layers constrain what the agent can do in response.
- Audit data is sent to the Claude API. This is inherent to using a cloud LLM.

## secy modules

secy is a restricted audit tool that the agent uses for reading config files that may contain secrets. It can also be used standalone.

| Module | What it does |
|--------|-------------|
| `files <path>` | Read config file with blocklist enforcement and output redaction |
| `perms <path>` | File permissions, ACLs, attributes (no content) |
| `ports` | Open ports and listeners (via `ss`) |
| `services` | Systemd unit state |
| `packages` | Installed packages |
| `users` | Users, groups, sudoers, logins |
| `firewall` | iptables/nftables/ufw rules |
| `logs <type>` | System logs with redaction |
| `sysctl` | Kernel parameters |
| `cron` | Cron jobs and systemd timers |
| `setuid` | SUID/SGID binaries |
| `world` | World-writable files/dirs |
| `full` | Run all modules |

## Project structure

```
secy/
├── agent/
│   ├── secy-agent.sh              # Outer loop (Ralph pattern)
│   ├── AGENT.md                   # Agent prompt — security domain knowledge
│   ├── conf/
│   │   ├── agent.conf             # Iteration limits, model, settings
│   │   └── srt-settings.json     # Anthropic sandbox-runtime config
│   └── lib/
│       └── agent-common.sh        # Lock, preflight, prompt assembly
├── bin/
│   └── secy                       # secy entrypoint
├── lib/
│   ├── common.sh                  # Shared utilities
│   ├── redact.sh                  # Output redaction engine
│   ├── blocklist.sh               # Path blocking, MIME checking
│   └── modules/                   # 12 audit modules + full.sh
├── conf/
│   ├── secy.sudoers               # sudoers drop-in (for non-Docker use)
│   ├── blocked_paths              # Credential file patterns
│   ├── allowed_mimetypes          # MIME type whitelist
│   └── redact_patterns            # Output redaction regexes
├── tests/                         # Unit + integration tests
├── docs/
│   ├── sandboxing.md              # Security architecture
│   ├── shift.md                   # Design decisions
│   └── ai-agent-landscape.md     # Analysis of Ralph, OpenClaw
├── state/                         # Runtime (gitignored)
│   ├── baseline/                  # Module output snapshots
│   ├── current/                   # Latest run outputs
│   └── findings/                  # Timestamped reports
├── Dockerfile
├── docker-compose.yml
├── install.sh                     # secy standalone install
├── DESIGN.md                      # secy threat model
└── .gitignore
```

## Agent architecture

secy-agent uses the [Ralph pattern](docs/ai-agent-landscape.md#ralph): a bash loop that spawns fresh Claude Code instances with filesystem-based memory.

Each iteration:
1. Assembles a prompt (system instructions + mode-specific task + progress from previous iterations)
2. Spawns `srt claude --dangerously-skip-permissions --print ...`
3. Claude reads host files, analyzes them, writes findings
4. Checks for completion signal (`SECY_AGENT_COMPLETE`)
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
MAX_BUDGET_USD="1.00"       # Spend cap per iteration (API key auth)
```

### Sandbox settings (`agent/conf/srt-settings.json`)

Network and filesystem restrictions enforced by Anthropic's sandbox-runtime. See [docs/sandboxing.md](docs/sandboxing.md).

### secy settings (`conf/`)

Blocklist patterns, redaction regexes, and MIME type whitelist. Edit these to tune what the agent can and cannot read through secy.

## Requirements

- Docker and Docker Compose
- An Anthropic API key (`ANTHROPIC_API_KEY`)

## Status

Prototype. Not audited for production use. Redaction patterns and blocklists are not exhaustive.

## Docs

- [docs/sandboxing.md](docs/sandboxing.md) — Security architecture and threat model
- [docs/shift.md](docs/shift.md) — Design decision: file reading vs command execution
- [docs/ai-agent-landscape.md](docs/ai-agent-landscape.md) — Analysis of Ralph, Ralph Playbook, OpenClaw
- [DESIGN.md](DESIGN.md) — secy threat model and trust assumptions
