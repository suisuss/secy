# sread — Design Document

## Motivation

Security auditing requires root-level read access: configs, logs, permissions, services, kernel parameters. AI agents like Claude Code operate via shell commands. Granting raw `sudo` — even "read-only" — is unacceptable because:

1. **`sudo cat` reads anything.** Including `/etc/shadow`, private keys, crypto wallets, database files. "Read-only" at root level still means full information disclosure.

2. **Shell escapes.** Commands like `less`, `vim`, `man` have shell escape features (e.g., `!bash` inside `less`). Granting `sudo less` is effectively granting `sudo bash`.

3. **Read can lead to write.** Reading `/proc/kcore` or device files can leak memory. Reading scripts reveals credentials. The read/write distinction is weaker than it appears at the OS level.

4. **Audit vs exploit is intent, not commands.** `sudo ss -tlnp` is auditing. `sudo cat /etc/shadow` followed by an offline crack is not. The commands are identical — only purpose differs.

## Architecture: Four-Layer Defense

### Layer 1: sudoers allowlist

Only the `sread` wrapper binary is permitted in sudoers. Not `cat`, not `less`, not `grep`. One binary, NOEXEC'd to prevent shell escapes, env_reset'd to prevent environment injection.

```sudoers
Cmnd_Alias SREAD_AUDIT = /usr/local/bin/sread
Defaults!SREAD_AUDIT noexec, env_reset
%sread-audit ALL=(root) NOPASSWD: SREAD_AUDIT
```

**Why this matters:** Sudoers can restrict commands but not arguments effectively. `sudo cat /etc/ssh/sshd_config` and `sudo cat /etc/shadow` are the same command to sudoers. The wrapper applies argument-level policy.

### Layer 2: Wrapper scripts with argument validation

The `sread` binary:
- Validates module names against a known set
- Blocks shell metacharacters in all arguments (`;`, `|`, `&`, `$`, `` ` ``, `\`)
- Blocks subshell syntax (`$(...)`, `<(...)`)
- Checks file paths against a blocklist before reading
- Only reads regular files (not devices, sockets, FIFOs)
- Resolves symlinks before checking blocklist (prevents traversal)

### Layer 3: Container isolation (Docker)

The primary deployment model runs sread inside a Docker container:

- Host filesystem bind-mounted read-only at `/host`
- Container filesystem is `read_only: true` — sread binary, config, and blocklists are immutable
- Network restricted to `api.anthropic.com` only (via srt sandbox)
- All capabilities dropped except `DAC_READ_SEARCH` (read host files), `SYS_ADMIN` + `NET_ADMIN` (for srt/bwrap)
- `no-new-privileges: true` prevents privilege escalation
- Writes only to the state volume (`/var/lib/secy/state`) and tmpfs (`/tmp`, `/root`)

This effectively provides the namespace isolation described in the original design — network isolation, filesystem immutability, restricted capabilities — via Docker rather than `unshare`.

For non-Docker deployments, the sudoers model (Layer 1) is the primary boundary. A future `unshare`-based namespace layer remains possible for standalone installs.

### Layer 4: Output redaction

Audit output passes through a redaction engine before being returned. Patterns include:
- Passwords in config files (`password=...`, `secret: ...`)
- Connection strings with embedded credentials (`postgres://user:pass@...`)
- Bearer tokens and Authorization headers
- AWS-style access keys
- JWT tokens (`eyJ...` header.payload.signature)
- GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`)
- Base64-encoded blobs that look like keys
- Hash values from shadow-like entries
- Private key content

**Why redaction instead of just blocking?** Config files often mix safe and sensitive values. An `sshd_config` is useful for auditing even with `HostKey` paths visible — but a database config with plaintext passwords needs those values stripped. Redaction preserves audit utility while reducing exposure.

## Trust Model

### Assumptions

- The `sread` binary is root-owned, not writable by the agent's user
- The sudoers entry permits only the `sread` binary
- The agent cannot modify `sread` source, config, or blocklists
- Output redaction is **best-effort** — audit output should still be treated as sensitive
- Human review of audit output is expected (this is defense-in-depth, not a sandbox)

### What this does NOT protect against

- A compromised agent binary that has already achieved code execution
- Prompt injection that causes the agent to misinterpret audit findings
- Information leakage through the conversation context itself (API logs, etc.)
- Social engineering — the agent could describe what it reads to a user who shouldn't see it

### Residual risks

Even with all four layers, the agent has elevated **read** access to the system. The audit output — even redacted — reveals:

- System architecture (what services run, what packages are installed)
- Network topology (open ports, firewall rules)
- User accounts and group memberships
- Kernel configuration
- Cron job schedules

This is inherently sensitive. The conversation transcript containing this data should be treated accordingly.

## Comparison: Agent-as-Executor vs Agent-as-Analyst

| Aspect | Agent runs audit (sread) | Agent analyzes report |
|--------|------------------------|----------------------|
| Interactive follow-up | Yes — "check that file" | No — static report |
| Attack surface | Elevated shell access | None (just text) |
| Output sensitivity | Real-time, in context | Pre-generated, reviewable |
| Credential exposure risk | Medium (redaction helps) | Low (report is pre-filtered) |
| Setup complexity | sudoers + wrappers + install | Run Lynis, paste output |

**Recommendation for production:** Use the agent-as-analyst model. Run Lynis/OpenSCAP/CIS-CAT yourself, feed the output to the agent. This gets 80% of the value with almost none of the risk.

**sread exists for:** The remaining 20% — interactive investigation, follow-up questions ("what are the permissions on that specific directory?"), and cases where the agent needs to autonomously explore system state.

## What an ideal Claude Code integration would need

Beyond what sread provides at the shell level:

| Requirement | Why |
|---|---|
| Explicit audit mode | User opts in, scoped to a session |
| Command classification | Tag each command as read/write/destructive before execution |
| Output redaction | Strip credentials from audit output before storing in context |
| Immutable audit log | Every elevated command logged independently of Claude's context |
| Time-boxed sessions | Sudo access expires automatically |
| No chaining | Prevent `sudo sh -c "..."` — only discrete commands |
| Structured tool integration | Lynis/OpenSCAP as first-class tools, not raw shell |

## Current Module Inventory

25 modules across four categories:

| Category | Modules |
|----------|---------|
| **System state** | `ports`, `users`, `services`, `packages`, `cron`, `firewall`, `sysctl`, `logs` |
| **File analysis** | `files` (redacted config reads), `perms`, `setuid`, `world`, `hash`, `fileinfo`, `hashlookup` |
| **Threat detection** | `spyproc`, `preload`, `kmod`, `autostart`, `netconn`, `desktop`, `surveil` (meta), `pkgverify`, `tamper` |
| **Aggregation** | `full` (runs all modules) |

The `hash`, `fileinfo`, and `hashlookup` modules support the watch daemon (Downloads malware triage). They intentionally skip the MIME whitelist — they must operate on binaries — but still respect the path blocklist.

A local malware hash database (MalwareBazaar SHA256 export, ~1.5M hashes) is baked into the Docker image at build time at `data/malware-sha256.txt`. The `hashlookup` module uses `look(1)` for O(log n) binary search.

## Status

Prototype. Not audited for production use. The redaction patterns are not comprehensive. The blocklist is not exhaustive. Use for learning, experimentation, and as a starting point for a more robust solution.
