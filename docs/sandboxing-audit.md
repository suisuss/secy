# Sandboxing Audit

**Date:** 2026-02-09
**Scope:** Three-layer defense model — Docker container, Anthropic sandbox-runtime (srt), sread application-level controls
**Method:** Static analysis of configuration files, shell scripts, and documentation against actual enforcement behavior

---

## Layer 1: Docker Container

### Claimed vs actual

| Control | Documented | Actual |
|---------|-----------|--------|
| Host filesystem | `/:/host:ro` | Correct — read-only mount |
| Container filesystem | `read_only: true` — immutable | Correct — immutable. tmpfs for `/tmp` and `/root`. |
| Capabilities | `cap_drop: ALL`, add `DAC_READ_SEARCH` + `SYS_ADMIN` | Correct, but `SYS_ADMIN` is overly broad |
| Seccomp | Not documented | `seccomp=unconfined` — all syscall filtering disabled |
| Privilege escalation | `no-new-privileges: true` | Correct |

### Findings

**[RESOLVED] `read_only: true` was missing from `docker-compose.yml`.**
Fixed in `a6c2591`. `docker-compose.yml` now sets `read_only: true`. Only tmpfs mounts (`/tmp`, `/root`) and the state volume are writable. The agent cannot modify sread config, blocklists, or its own prompt.

~~Impact: A prompt-injected agent can:~~
~~- Overwrite `/usr/local/lib/sread/conf/blocked_paths` to empty the blocklist~~
~~- Overwrite `/usr/local/lib/sread/conf/redact_patterns` to disable redaction~~
~~- Modify `/opt/secy/AGENT.md` to change its own system prompt~~
~~- Write arbitrary files to the container filesystem~~

**[HIGH] `SYS_ADMIN` + `seccomp=unconfined` is overly permissive.**
`SYS_ADMIN` enables `mount()`, `unshare()`, `setns()`, `pivot_root()`, and namespace manipulation. `seccomp=unconfined` removes the default Docker seccomp profile that blocks ~44 dangerous syscalls (`keyctl`, `mount`, `reboot`, `kexec_load`, etc.).

Combined, these allow:
- Remounting `/host` as read-write (if the underlying block device permits)
- Creating new namespaces
- Entering existing namespaces
- Manipulating cgroups

The comment says `SYS_ADMIN` is "Required by bubblewrap (srt sandbox on Linux)." However, `agent/secy.sh` already handles srt failure gracefully (falls back to running without srt). The tradeoff — weakening Layer 1 to enable an optional Layer 2 — is questionable.

**[MEDIUM] `NET_ADMIN` enables network stack manipulation.**
Can modify iptables rules within the container's network namespace, potentially interfering with srt's network filtering if srt uses iptables-based enforcement. Can also manipulate routing tables and network interfaces.

**[RESOLVED] OAuth credential bind mount was shadowed by tmpfs.**
Fixed in `a6c2591`, refined in `a4e6e16`. Credentials are staged at `/mnt/claude-credentials.json` (bind mount) and copied into the `/root` tmpfs by `entrypoint.sh`. srt settings are staged at `/opt/secy/conf/srt-settings.json` and also copied into `/root` by the entrypoint. Both OAuth and API key auth function.

~~The tmpfs at `/root/.claude` shadows the bind mount at `/root/.claude/.credentials.json`. OAuth authentication cannot work — the credential file is invisible inside the container. Only API key auth functions.~~

**[RESOLVED] Claude Code failed silently in read-only container.**
Fixed in `a4e6e16`. Claude Code writes `/root/.claude.json` (a config file) at startup. The previous per-directory tmpfs mounts (`/root/.claude`, `/root/.npm`, `/root/.config`) didn't cover this file since it lives at `/root/` level. Claude exited 0 with zero output — the error was only visible in `/root/.claude/debug/`. Fix: single tmpfs on `/root`, entrypoint stages all needed files from immutable paths.

### Layer 1 verdict

Two strong controls (`:ro` host mount, `read_only: true` container filesystem). `/root` is a single tmpfs — simpler and covers all files Claude Code needs to write (`.claude.json`, `.claude/`, `.npm/`, `.config/`). `SYS_ADMIN` + `seccomp=unconfined` remain overly broad — the tradeoff for enabling srt inside Docker is real. OAuth credential staging and `/root` tmpfs resolve the authentication and startup gaps.

---

## Layer 2: Anthropic sandbox-runtime (srt)

### Claimed vs actual

| Control | Documented | Actual |
|---------|-----------|--------|
| Network | `api.anthropic.com` only | Correct when active, but srt is best-effort |
| Filesystem deny | Credential files blocked at OS level | Partial — only covers root's credentials |
| Enforcement | bubblewrap on Linux | `enableWeakerNestedSandbox: true` — may not engage |

### Findings

**[HIGH] srt is best-effort, not guaranteed.**
`agent/secy.sh` lines 89-98 test whether srt works and silently falls back:

```bash
if srt -- echo srt-ok >/dev/null 2>&1; then
    claude_cmd="srt claude"
else
    log_agent "srt available but sandbox failed (Docker is the sandbox boundary)"
fi
```

bubblewrap inside Docker with the weaker sandbox mode may or may not work depending on the Docker runtime, kernel version, and security policies. There is no hard failure if srt doesn't engage. When srt is inactive:
- No network isolation — agent can reach any endpoint via Bash (`curl`, `wget`, etc.)
- No OS-level file blocking — all `/host` files readable via `DAC_READ_SEARCH` capability

**[MEDIUM] No verification that srt enforcement is active.**
The check (`srt -- echo srt-ok`) tests that srt can launch a process, not that network/filesystem restrictions are enforced. A misconfigured srt that launches processes without policy enforcement would pass this check.

**[MEDIUM] `denyRead` only covers root's credentials.**

Blocked:
- `/host/etc/shadow`, `/host/etc/gshadow` (password hashes)
- SSH host keys (ed25519, rsa, ecdsa only)
- `/host/root/.ssh`, `.gnupg`, `.aws/credentials`, `.kube/config`, `.env`, `.password-store`
- `/host/proc/kcore`, `/host/proc/kallsyms`, `/host/dev/mem`, `/host/dev/kmem`

Not blocked:
- `/host/home/*/.ssh/` — non-root user SSH private keys
- `/host/home/*/.aws/credentials`, `/host/home/*/.kube/config`, `/host/home/*/.gnupg/`
- `/host/etc/ssl/private/` — TLS private keys
- `/host/home/*/.env` files
- `/host/root/.docker/config.json` — registry auth tokens
- `/host/root/.bash_history`, `/host/home/*/.bash_history` — may contain typed passwords
- SSH host keys with non-standard algorithms (e.g., `ssh_host_dsa_key`)

This matters because srt is the OS-level enforcement. If the agent bypasses sread's application-level blocklist, srt is the last defense for file reads — and it only protects root's secrets.

**Network isolation is strong when active.**
`allowedDomains: ["api.anthropic.com"]` is clean and narrow. If srt is active, exfiltration is blocked.

### Layer 2 verdict

srt is the right tool deployed as best-effort. The `denyRead` list has a user-credentials blind spot. Network isolation is strong when active. The critical question is reliability — there's no mechanism to verify enforcement at runtime or fail hard when it doesn't engage.

---

## Layer 3: sread (application-level)

### Claimed vs actual

| Control | Documented | Actual |
|---------|-----------|--------|
| Path blocklist | 64 patterns | Correct, but only enforced via `sread files` |
| Output redaction | 11 regex rules | Correct, same caveat |
| MIME whitelist | ~25 text/config types | Correct, same caveat |
| Argument validation | Metachar blocking | Correct, covers `;|&$\`` and `$(...)`, `<(...)` |

### Findings

**[HIGH] The agent mostly doesn't use sread.**
`AGENT.md` tells the agent to use Claude Code's `Read` tool and `Bash` tool for direct file reads from `/host/`. `sread files` is only recommended "when reading config files that likely contain passwords."

The agent reads `/host/etc/passwd`, `/host/proc/net/tcp`, `/host/etc/ssh/sshd_config`, `/host/var/log/auth.log`, etc. directly. sread's blocklist and redaction never touch these reads. Layer 3 is opt-in, not enforced — it depends on the LLM choosing to use `sread files`. A prompt injection or a model that ignores the instruction bypasses sread entirely.

**[LOW] Newline not blocked in argument validation.**
`_validate_args` blocks `;|&$\`` and subshell syntax but not embedded newlines or null bytes. Theoretical injection vector through path arguments containing these characters.

**[LOW] Stale comment in `redact_patterns`.**
Header says "Delimiter is ~ (tilde)" but the code uses SOH (`\x01`). Cosmetic only — the code is correct.

### What's done well

- Blocklist symlink resolution (`readlink -f`) prevents traversal attacks
- MIME whitelist defaults to reject (correct fail mode)
- The `text/*` catch-all is reasonable for audit use
- Argument validation covers the standard shell injection vectors

### Layer 3 verdict

Well-implemented for standalone (non-Docker) use where sread is the only filesystem interface. In the Docker agent context, it's supplementary — the agent has direct file access that bypasses all sread controls.

---

## Cross-Layer Analysis

### Defense-in-depth gaps

The three layers are designed to compensate for each other's weaknesses. In practice:

| If this fails... | ...this should catch it | ...but |
|-------------------|------------------------|--------|
| sread blocklist bypassed | srt `denyRead` | srt may not be active |
| srt not active | Docker `:ro` mount prevents writes | Agent can still read everything |
| Agent reads sensitive file | sread redaction strips secrets | Agent used `Read` tool, not `sread files` |
| Agent tries to exfiltrate | srt network allowlist | srt may not be active |
| Agent modifies own config | Docker `read_only: true` | Blocked |

The gap pattern: Layer 2 (srt) is optional and Layer 3 (sread) is opt-in. Layer 1 (Docker) is now properly hardened with `read_only: true` and `:ro` host mount, but the remaining concern is that no mandatory layer covers application-level file read restrictions when srt is inactive.

### The exfiltration path

Even with all three layers active, audit data goes to `api.anthropic.com` as prompt content. Anyone with access to the Anthropic account's conversation history can see the audit findings — users, ports, configs, cron jobs, kernel params. Acknowledged in the docs. Inherent to using a cloud LLM.

### The state volume write channel

`./state:/var/lib/secy/state` is the only persistent writable volume. The agent writes findings, progress, and baseline snapshots here. This is bind-mounted back to the host. Intended for markdown reports, but the agent can write arbitrary files to `./state/` on the host filesystem.

### `--dangerously-skip-permissions` is load-bearing

The entire agent loop depends on `--dangerously-skip-permissions`. `IS_SANDBOX=1` allows this flag when running as root. Claude Code's own permission system is completely disabled — the agent can use any tool without restriction. This is Anthropic's intended mechanism for containerized use.

### `ALLOWED_TOOLS` as a soft constraint

`agent.conf` restricts tools to `Bash,Read,Write,Grep,Glob`, preventing `WebFetch` or `WebSearch`. However, `Bash` is unrestricted within the container — the agent can run `curl`, `wget`, or any network tool via Bash (subject to srt's network filtering if active, unrestricted if not).

---

## Summary

### Critical (all resolved)

| # | Finding | Status |
|---|---------|--------|
| 1 | ~~`read_only: true` missing~~ | Resolved in `a6c2591` |
| 2 | ~~OAuth credential bind mount shadowed by tmpfs~~ | Resolved in `a6c2591` |
| 13 | ~~Claude Code silent failure — `/root/.claude.json` blocked by read-only fs~~ | Resolved in `a4e6e16` |

### High

| # | Finding | File |
|---|---------|------|
| 3 | `SYS_ADMIN` + `seccomp=unconfined` overly broad | `docker-compose.yml:40-41,49` |
| 4 | srt is best-effort, silently degrades to nothing | `agent/secy.sh:89-98, agent/secy.sh:103-115` |
| 5 | sread is opt-in — agent reads files directly, bypassing blocklist/redaction | `agent/AGENT.md` |

### Medium

| # | Finding | File |
|---|---------|------|
| 6 | srt `denyRead` only covers root's credentials | `agent/conf/srt-settings.json` |
| 7 | No verification that srt enforcement is actually active | `agent/secy.sh:90` |
| 8 | `NET_ADMIN` capability enables network stack manipulation | `docker-compose.yml:44` |
| 9 | State volume is writable channel from container to host | `docker-compose.yml:14` |

### Low

| # | Finding | File |
|---|---------|------|
| 10 | Stale delimiter comment in `redact_patterns` | `sread/conf/redact_patterns:4` |
| 11 | Newline not blocked in sread argument validation | `sread/bin/sread:35` |
| 12 | Audit log falls back to tmpfs, lost on restart | `sread/bin/sread:115` |

### Operational notes

- **Debug output location:** Claude Code writes debug logs to `/root/.claude/debug/` (on the tmpfs). When Claude exits 0 with no output, check the `latest` symlink there for the actual error. This was how the `/root/.claude.json` EROFS failure was diagnosed.
- **Output pipeline:** The agent's output pipeline uses `tee file | formatter >&2` (simple pipeline) rather than process substitutions inside command substitutions, which are unreliable for real-time output in bash.

### What's done well

- Read-only host mount (`/:/host:ro`) is the strongest control and correctly configured
- "Everything is a file" design eliminates host namespace sharing — right architectural choice
- Sudoers configuration for standalone use is tight (`noexec`, `env_reset`, `secure_path`, single binary)
- Blocklist symlink resolution prevents traversal attacks
- MIME whitelist defaults to reject
- Documentation is honest about what isn't defended
- Defense-in-depth model is sound in concept
