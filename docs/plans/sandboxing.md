# Sandboxing Architecture

secy runs inside a Docker container with three independent security layers. Each layer is designed to fail-closed: if any single layer is bypassed, the remaining layers still prevent damage.

## Layer 1: Docker Container

The outer boundary. Provides hard isolation between the agent and the host.

| Control | Setting | Effect |
|---------|---------|--------|
| Host filesystem | `/:/host:ro` | Read-only. Agent cannot modify host. |
| Container filesystem | `read_only: true` | Immutable. Only tmpfs and state volume are writable. |
| Writable areas | `./state` volume, `/tmp`, `/root/.claude` tmpfs | Findings, baseline, progress — nothing else. |
| Capabilities | `cap_drop: ALL`, add only `DAC_READ_SEARCH` + `SYS_ADMIN` | Cannot modify network, mount filesystems, or signal host processes. `SYS_ADMIN` is required by bubblewrap for srt. |
| Privilege escalation | `no-new-privileges: true` | Cannot gain capabilities beyond what was granted at container start. |

**What Docker prevents:** Writing to the host, running host commands, modifying host network/firewall, accessing host devices, escalating privileges.

## Layer 2: Anthropic sandbox-runtime (srt)

Wraps the `claude` process inside the container. Provides OS-level enforcement via bubblewrap on Linux.

Configuration: `agent/conf/srt-settings.json`

### Network isolation

```json
{
  "network": {
    "allowedDomains": ["api.anthropic.com"]
  }
}
```

The agent can ONLY reach `api.anthropic.com` — the Claude API endpoint. All other network traffic is blocked at the OS level. This means:

- A compromised agent cannot exfiltrate data to an attacker's server
- Cannot download malicious scripts
- Cannot contact C2 infrastructure
- Cannot leak audit findings to unauthorized endpoints

### Filesystem isolation

```json
{
  "filesystem": {
    "denyRead": [
      "/host/etc/shadow", "/host/etc/gshadow",
      "/host/etc/ssh/ssh_host_*_key",
      "/host/root/.ssh", "/host/root/.gnupg",
      "/host/root/.aws/credentials",
      "/host/proc/kcore", "/host/dev/mem"
    ],
    "allowWrite": ["/var/lib/secy/state", "/tmp"]
  }
}
```

OS-level enforcement of credential file blocking. Even if Claude Code bypasses sread's application-level blocklist, srt denies the read at the kernel level.

### Nested sandbox mode

```json
{
  "enableWeakerNestedSandbox": true
}
```

Running srt inside Docker requires the weaker sandbox mode. This is acceptable because Docker provides the strong outer boundary. The defense-in-depth model means neither layer needs to be individually perfect.

Per [Anthropic's guidance](https://www.anthropic.com/engineering/claude-code-sandboxing): this mode "should only be used in cases where additional isolation is otherwise enforced" — which is exactly our case.

## Layer 3: sread

Application-level controls when reading config files through the `sread files` command.

| Mechanism | What it does |
|-----------|-------------|
| **Blocklist** (`conf/blocked_paths`) | 64 glob patterns blocking credential files, private keys, databases, cloud creds |
| **Redaction** (`conf/redact_patterns`) | 11 regex rules stripping passwords, API keys, bearer tokens, connection strings, JWT tokens, GitHub tokens, base64 secrets, hashes |
| **MIME check** (`conf/allowed_mimetypes`) | Whitelist of ~25 text/config MIME types — rejects binaries, images, archives |
| **Argument validation** | Blocks shell metacharacters (`;|&$`), subshell syntax (`$(...)`, `<(...)`) |

sread is the innermost defense. It's the only layer that understands file content — Docker and srt operate at the filesystem/network level.

## Combined threat model

| Attack vector | Layer 1 (Docker) | Layer 2 (srt) | Layer 3 (sread) |
|---------------|:-:|:-:|:-:|
| Write to host filesystem | Blocked (ro mount) | — | — |
| Exfiltrate data via network | — | Blocked (domain allowlist) | — |
| Read /etc/shadow | — | Blocked (denyRead) | Blocked (blocklist) |
| Read SSH private keys | — | Blocked (denyRead) | Blocked (blocklist) |
| Read binary/archive files | — | — | Blocked (MIME check) |
| Leak passwords in config output | — | — | Redacted |
| Shell injection via arguments | — | — | Blocked (metachar filter) |
| Privilege escalation | Blocked (no-new-privs) | — | — |
| Run host commands | Blocked (no namespace sharing) | — | — |

## What is NOT defended

- **Information disclosure of system architecture.** The agent can read `/host/etc/passwd`, `/host/proc/net/tcp`, service configs, cron jobs, kernel parameters. This is by design — it's an audit tool. The operator should treat audit findings as sensitive.
- **Prompt injection from host files.** A malicious file on the host (crafted log entry, poisoned config) could influence agent behavior. The three layers constrain what the agent can DO in response, but cannot prevent the agent from reasoning about injected content.
- **Conversation transcript exposure.** Claude Code logs sessions. These contain audit output. Treat `~/.claude/` as sensitive.
- **Anthropic API traffic.** srt allows `api.anthropic.com`. Audit data is sent to the Claude API as prompt content. This is inherent to using a cloud LLM for analysis.

## References

- [Anthropic: Claude Code Sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing)
- [Claude Code Docs: Sandboxing](https://code.claude.com/docs/en/sandboxing)
- [sandbox-runtime (GitHub)](https://github.com/anthropic-experimental/sandbox-runtime)
