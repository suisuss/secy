# Design Shift: Everything Is a File

This document captures the architectural decision to move from command execution to file reading as the primary audit mechanism.

## The original approach

sread modules wrap system commands: `ss` for ports, `systemctl` for services, `iptables` for firewall rules, `sysctl` for kernel parameters. The agent runs these commands via `sudo sread <module>` and analyzes the output.

This required:
- `sudo` access (via sudoers allowlist)
- Host namespace sharing (`--net=host`, `--pid=host`) for commands to see host state
- System command packages installed in the container (iproute2, iptables, nftables, procps, etc.)
- Elevated capabilities (`NET_ADMIN`, `NET_RAW`)

## The problem

Running commands inside a container that need to observe host state is fundamentally awkward. `ss` shows the container's network stack unless you share the host network namespace. `systemctl` talks to the container's init unless you share PID namespace and mount the systemd socket. Each command requires its own namespace workaround.

More importantly: this contradicts the security model. The agent is supposed to be constrained. Giving it host namespace access and capabilities for command execution widens the attack surface.

## The insight

In Unix, system state is exposed through files:

| You don't need to run... | When you can read... |
|---|---|
| `ss -tlnp` | `/proc/net/tcp`, `/proc/net/tcp6` |
| `sysctl -a` | `/proc/sys/net/ipv4/ip_forward`, etc. |
| `systemctl list-units` | `/etc/systemd/system/*`, `/usr/lib/systemd/system/*` |
| `iptables -L` | `/etc/iptables/rules.v4`, `/etc/nftables.conf` |
| `cat /etc/passwd` | `/etc/passwd` (it's already a file) |
| `crontab -l` | `/var/spool/cron/crontabs/*` |
| `last` | `/var/log/wtmp` |

An LLM can parse `/proc/net/tcp` (hex-encoded addresses and ports) just as well as it can parse `ss` output. It can read systemd unit files and understand what services are configured. It can read `/proc/sys/` files directly instead of running `sysctl`.

## The new approach

Mount the host filesystem read-only at `/host`. The agent reads files directly.

**What changed:**

| Before | After |
|---|---|
| `sudo sread ports` → runs `ss` | Read `/host/proc/net/tcp` |
| `sudo sread sysctl --security` → runs `sysctl -a` | Read `/host/proc/sys/...` files |
| `sudo sread users` → runs `getent`, parses passwd | Read `/host/etc/passwd`, `/host/etc/group` |
| `sudo sread firewall` → runs `iptables -L` | Read `/host/etc/nftables.conf` |
| `sudo sread services` → runs `systemctl` | Read `/host/etc/systemd/system/*` |
| `--net=host`, `--pid=host` | Not needed |
| `NET_ADMIN`, `NET_RAW` capabilities | Not needed |
| iproute2, iptables, nftables, procps packages | Not needed |

**What didn't change:**

- `sread files <path>` is still used for config files with sensitive content — its blocklist and redaction engine add value that direct reads don't provide
- `find` is still needed for SUID/world-writable scans (permissions aren't readable from a single file)
- `diff` is still needed for baseline comparison

## The output model

The agent no longer just reports findings. It:

1. **Reads** host files
2. **Explains** what the content means and why it matters
3. **Recommends** specific commands the operator should run on the host

The agent is advisory. It reads and analyzes. The human executes.

Example:

> **[WARN-003] SSH allows password authentication**
> - **File**: `/etc/ssh/sshd_config` line 58
> - **Found**: `PasswordAuthentication yes`
> - **Why it matters**: Password auth is vulnerable to brute force. Auth logs show 847 failed password attempts in the last 24 hours.
> - **Recommendation**:
>   ```bash
>   sudo sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
>   sudo systemctl restart sshd
>   ```

## Consequences

**Simplified container:** Fewer packages, no namespace sharing, minimal capabilities. The Dockerfile installs `findutils`, `file`, `diffutils`, `curl`, and `jq` — that's it beyond Node.js and Claude Code.

**Stronger security:** The container has no host network access, no host PID visibility, no ability to run host commands. The only interface to the host is a read-only filesystem mount.

**LLM does more work:** The agent must parse `/proc/net/tcp` hex notation, understand systemd unit file syntax, interpret firewall rule files. This is well within an LLM's capability but means the prompt (`AGENT.md`) needs to teach these formats.

**Some dynamic state is less accessible:** Saved firewall rules (`/etc/nftables.conf`) may differ from runtime rules (`nft list ruleset`). Systemd unit files show configuration, not runtime state. The agent should note this limitation in findings where relevant.
