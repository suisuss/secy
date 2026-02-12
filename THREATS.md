# Threat Detection Index

Techniques for finding sophisticatedly hidden malicious programs on a Linux system, mapped to where (if anywhere) secy addresses them. See [THREATS-DEPTH.md](THREATS-DEPTH.md) for detailed explanations, detection methods, and remediation for each technique.

## Coverage legend

| Symbol | Meaning |
|--------|---------|
| **Y** | Implemented — code exists in a sread module or agent prompt |
| **P** | Partial — some aspect is covered but gaps remain |
| **N** | Not covered |

---

## 1. Userland persistence

| # | Technique | Covered | Where | Notes |
|---|-----------|---------|-------|-------|
| 1.1 | XDG autostart entries (system + per-user) | **Y** | `sread autostart`, AGENT.md §Autostart persistence | Parses Name/Exec fields from .desktop files |
| 1.2 | Systemd user services | **Y** | `sread autostart` | Lists enabled/running via systemctl or file scan fallback |
| 1.3 | Shell profile hooks (.bashrc, .zshrc, PROMPT_COMMAND, trap DEBUG) | **Y** | `sread preload` | Greps for exfiltration patterns (curl/wget/nc in PROMPT_COMMAND, trap DEBUG) |
| 1.4 | Cron persistence (system + per-user) | **Y** | `sread cron`, AGENT.md §Cron | Agent also checks for curl\|bash patterns, writable script dirs |
| 1.5 | rc.local | **Y** | `sread autostart` | Checks existence and executable bit |
| 1.6 | Non-package init.d scripts | **Y** | `sread autostart` | Cross-references against dpkg .list files |
| 1.7 | Browser extensions | **Y** | `sread desktop` | Chromium-based + Firefox; parses manifest.json with locale resolution |
| 1.8 | LD_PRELOAD system-wide (/etc/ld.so.preload) | **Y** | `sread preload` | Flags existence (should not be present on normal system) |
| 1.9 | LD_PRELOAD per-process (environ) | **Y** | `sread preload` | Scans /proc/[pid]/environ for LD_PRELOAD= |
| 1.10 | PAM module tampering (pam_exec, pam_script) | **Y** | `sread preload` | Greps pam.d for suspicious modules |
| 1.11 | Suspicious shared libraries in ld cache | **Y** | `sread preload` | Searches ldconfig -p for spy/hook/inject patterns |

## 2. Process-level hiding

| # | Technique | Covered | Where | Notes |
|---|-----------|---------|-------|-------|
| 2.1 | Known spyware process name matching | **Y** | `sread spyproc` | Keyloggers, screen recorders, RATs, sniffers, tracers |
| 2.2 | Ptrace attachment detection (TracerPid) | **Y** | `sread spyproc` | Scans /proc/[pid]/status for non-zero TracerPid |
| 2.3 | /dev/input readers (keylogger detection) | **Y** | `sread spyproc` | Checks fd symlinks; allowlists Xorg, Xwayland, libinput, mutter, gnome-shell |
| 2.4 | Raw/packet socket detection | **Y** | `sread spyproc --deep` | Correlates fd inodes against /proc/net/raw and /proc/net/packet |
| 2.5 | Deleted binary detection (/proc/[pid]/exe → "(deleted)") | **Y** | `sread spyproc` | Flags processes whose exe symlink points to a deleted file |
| 2.6 | memfd_create execution (/proc/[pid]/exe → "/memfd:*") | **Y** | `sread spyproc` | Flags memory-only execution via memfd_create |
| 2.7 | Process name spoofing (comm vs exe vs cmdline mismatch) | **Y** | `sread spyproc` | Compares comm against basename(exe); skips interpreters; 15-char truncation aware |
| 2.8 | Thread injection (unexpected /proc/[pid]/task/ entries) | **P** | `sread spyproc` | Compares thread comm against main process comm; allowlists known multi-threaded apps and worker patterns |
| 2.9 | PID namespace hiding (/proc/[pid]/ns/pid differs from PID 1) | **P** | `sread spyproc` | Compares process PID namespace against PID 1; allowlists container runtimes by process and parent comm |
| 2.10 | Process tree / ancestry analysis | **N** | — | Detect anomalous parent→child chains (nginx→bash, cron→curl\|sh); data in /proc/[pid]/status PPid field |
| 2.11 | Process memory content scanning (/proc/[pid]/mem) | **N** | — | Scan process memory for injected code, IoC strings, shellcode; detects hollowing and reflective injection |
| 2.12 | Loaded library verification (/proc/[pid]/maps) | **N** | — | Hash .so files mapped into processes against known-good; detects library injection without LD_PRELOAD |

## 3. Filesystem-level hiding

| # | Technique | Covered | Where | Notes |
|---|-----------|---------|-------|-------|
| 3.1 | SUID binary scan | **Y** | `sread setuid`, AGENT.md §SUID | Finds -perm -4000; agent checks for GTFOBins candidates |
| 3.2 | SGID binary scan | **Y** | `sread setuid` | Finds -perm -2000 |
| 3.3 | World-writable file scan | **Y** | `sread world`, AGENT.md §World-writable | Excludes /tmp, /var/tmp, /dev/shm, /run, /proc, /sys |
| 3.4 | Timestamp manipulation detection (mtime vs ctime discrepancy) | **Y** | `sread tamper` | Flags system binaries where ctime >> mtime (backdated); also flags recent ctime |
| 3.5 | Extended attribute (xattr) payloads | **Y** | `sread xattr` | Scans system binaries and temp dirs for non-standard xattrs; flags user.* namespace on system binaries |
| 3.6 | Bind mount file hiding | **Y** | `sread mounts` | Parses mountinfo for bind mounts over sensitive paths; detects overlapping mount points on same device |
| 3.7 | Dotfile/unicode filename tricks | **N** | — | ". " (dot-space), ".." in non-root dirs, Cyrillic/lookalike characters |
| 3.8 | /dev/shm staging area | **Y** | `sread world` | Dedicated scan for executables, ELF binaries, scripts, and hidden files in /dev/shm |
| 3.9 | File ACL analysis | **P** | `sread perms` | perms.sh runs getfacl but doesn't flag anomalous ACLs |
| 3.10 | Extended file attributes (lsattr/chattr) | **P** | `sread perms` | perms.sh runs lsattr but doesn't flag suspicious attributes (e.g., immutable bit on unusual files) |
| 3.11 | Known rootkit artifact paths | **N** | — | Check for files/dirs installed by known rootkits (rkhunter-style): /dev/.hid, /usr/lib/libproc.a, SHV5/Adore/knark/Diamorphine artifacts |
| 3.12 | Full filesystem hash database (AIDE/Tripwire-style) | **N** | — | Persistent cryptographic hash DB of all critical files; detects modification of non-packaged files, configs, manually-placed scripts |

## 4. Kernel-level (rootkits)

| # | Technique | Covered | Where | Notes |
|---|-----------|---------|-------|-------|
| 4.1 | Suspicious kernel module name matching | **Y** | `sread kmod` | Pattern match: keylog, spy, hook, rootkit, hide, stealth, sniff, intercept, backdoor |
| 4.2 | Out-of-tree / unsigned module detection | **Y** | `sread kmod` | Checks /sys/module/[name]/taint for O (out-of-tree) and E (unsigned) flags |
| 4.3 | Input subsystem module enumeration | **Y** | `sread kmod` | Lists uinput, evdev, hid, keyboard modules |
| 4.4 | /proc/modules vs /sys/module/ cross-verification | **Y** | `sread kmod` | Checks both directions; filters built-in modules via refcnt |
| 4.5 | Syscall table integrity (kprobes list) | **P** | `sread kmod` | Enumerates active kprobes and kprobe events; flags hooks on sensitive functions; requires debugfs mount |
| 4.6 | eBPF program enumeration | **P** | `sread ebpf` | Pinned BPF objects, bpftool prog list, active tracepoints, BPF sysctl; needs bpftool/debugfs for full coverage |
| 4.7 | DKMS third-party module persistence | **Y** | `sread kmod` | Enumerates /var/lib/dkms/; allowlists known-legitimate drivers; flags unknown modules |
| 4.8 | Kernel taint bitmask decoding | **Y** | `sread kmod` | Per-module taint flags + system-wide /proc/sys/kernel/tainted with full bitmask decode |

## 5. Network-level indicators

| # | Technique | Covered | Where | Notes |
|---|-----------|---------|-------|-------|
| 5.1 | TCP listener enumeration | **Y** | `sread netconn`, `sread ports`, AGENT.md §Network | Parses /proc/net/tcp; flags 0.0.0.0 listeners |
| 5.2 | Established connection analysis with process attribution | **Y** | `sread netconn` | Correlates socket inodes to /proc/[pid]/fd for process names |
| 5.3 | Unusual outbound port detection | **Y** | `sread netconn` | Flags connections to non-standard remote ports outside LAN |
| 5.4 | UDP socket enumeration | **Y** | AGENT.md §Network | Agent reads /proc/net/udp and udp6 |
| 5.5 | Raw socket detection (/proc/net/raw) | **Y** | `sread spyproc --deep` | Almost nothing legitimate uses raw sockets besides ping |
| 5.6 | Packet socket detection (/proc/net/packet) | **Y** | `sread spyproc --deep` | Detects sniffers |
| 5.7 | DNS exfiltration / tunneling detection | **P** | `sread dnstun` | Detects tunneling tool processes/binaries, rogue UDP/53 listeners, suspicious resolv.conf; needs packet capture for full detection |
| 5.8 | Conntrack / NAT translation analysis | **N** | — | /proc/net/nf_conntrack reveals hidden destinations behind NAT |
| 5.9 | Socket inode → PID correlation | **Y** | `sread netconn` | _find_proc_by_inode helper; also recommended as host-side ss -tnp |
| 5.10 | C2 / malicious IP reputation matching | **N** | — | Cross-reference established connections against known-bad IP databases (Feodo Tracker, abuse.ch); bakeable at build time like hash DB |

## 6. Firmware / hardware

| # | Technique | Covered | Where | Notes |
|---|-----------|---------|-------|-------|
| 6.1 | EFI variable inspection (/sys/firmware/efi/efivars/) | **P** | `sread firmware` | Enumerates boot entries, flags large efivars (>4KB); limited to what sysfs exposes |
| 6.2 | UEFI Secure Boot state verification | **P** | `sread firmware` | Reads SecureBoot efivar and mokutil; flags if disabled; cannot verify boot chain integrity |
| 6.3 | BMC/IPMI presence detection | **P** | `sread firmware` | Checks /dev/ipmi0, IPMI modules, ipmitool, network interfaces; cannot audit BMC firmware |

## 7. Meta-techniques

| # | Technique | Covered | Where | Notes |
|---|-----------|---------|-------|-------|
| 7.1 | Baseline diffing (known-good state comparison) | **Y** | Agent monitor mode, `agent/secy.sh` | Captures baseline, diffs current state against it |
| 7.2 | Cross-source verification (multiple sources for same data) | **P** | — | netconn.sh uses /host/proc/1/net for host namespace awareness, but no systematic cross-verification (e.g., /proc/modules vs /sys/module/) |
| 7.3 | Behavioral analysis (what processes *do* vs what they're named) | **P** | `sread spyproc` | Checks fd targets and socket types, but relies heavily on name-based signature matching |
| 7.4 | Entropy analysis of suspicious binaries | **N** | — | Packed/encrypted binaries have abnormally high entropy |
| 7.5 | Package integrity verification (debsums -c / rpm -Va) | **Y** | `sread pkgverify` | Verifies md5sums for critical packages; --all for full scan |
| 7.6 | Offline / external analysis (boot from trusted media) | **N** | — | Out of scope for a running-system tool; noted for completeness |
| 7.7 | YARA / content-based signature scanning | **N** | — | Pattern match on file content (strings, hex, regex, structure); catches malware variants/families, not just exact hashes; community rulesets (Florian Roth signature-base, YARA-Rules) |
| 7.8 | Structured log parsing and correlation | **N** | — | Parse syslog, auth.log, dpkg.log, journal with field extraction; correlate events across sources into attack chains; currently agent reads auth.log tail ad-hoc |
| 7.9 | Dynamic analysis / sandboxed execution | **N** | — | Execute suspicious files in isolated environment, monitor syscalls/network/filesystem changes (Cuckoo/Cape); out of scope for read-only container |

## 8. Operational capabilities

Not detection techniques, but infrastructure that determines whether detections are actionable. Established antimalware solutions (ClamAV, Wazuh, CrowdStrike, rkhunter) include these; secy does not.

| # | Capability | Covered | Where | Notes |
|---|-----------|---------|-------|-------|
| 8.1 | Real-time event hooks (eBPF / auditd / fanotify) | **N** | — | Detect events at syscall time instead of polling; requires host-side component or kernel access; secy polls every 5s–30min |
| 8.2 | Alerting / notification | **N** | — | Webhook, email, desktop notification, syslog forwarding when findings are written; currently writes markdown to state/findings/ silently |
| 8.3 | Quarantine / automated response | **N** | — | Move malware to quarantine dir, kill processes, block IPs; requires write access to host; secy is read-only by design |
| 8.4 | Automatic signature/DB updates | **N** | — | Refresh hash DB without full image rebuild; ClamAV freshclam updates hourly; secy requires docker compose build |
| 8.5 | Compliance benchmarking (CIS/STIG scoring) | **P** | AGENT.md | Ad-hoc hardening checks exist (SSH, kernel params, firewall) but no formal benchmark scoring, hardening index, or profile mapping |
| 8.6 | Multi-host / centralized management | **N** | — | Fleet-wide visibility, cross-host correlation, central console; Wazuh/OSSEC manager-agent model |

---

## Gap summary

### Not covered (specialized)

Require capabilities beyond file reading, or have limited applicability:

| # | Threat | Why hard |
|---|--------|----------|
| 5.8 | Conntrack analysis | Requires /proc/net/nf_conntrack (host netns + conntrack loaded) |
| 7.6 | Offline analysis | Fundamentally cannot be done from a running system |
| 7.9 | Dynamic analysis / sandboxing | Requires execution environment; fundamentally incompatible with read-only container model |
| 8.1 | Real-time event hooks | Requires host-side kernel access (eBPF, auditd, fanotify); Docker container can only poll |
| 8.3 | Quarantine / response | Requires write access to host; secy is read-only by design |
| 8.6 | Multi-host management | Architectural change; requires server component, agent protocol, central datastore |

### Not covered (implementable)

Could be added within the current architecture (read-only container, build-time data baking):

| # | Threat | Implementation path |
|---|--------|---------------------|
| 2.10 | Process tree analysis | Read PPid from /proc/[pid]/status; reconstruct parent→child chains; flag anomalous spawning patterns |
| 2.11 | Process memory scanning | Read /proc/[pid]/mem (requires CAP_SYS_PTRACE); scan for IoC strings, shellcode patterns |
| 2.12 | Loaded library verification | Parse /proc/[pid]/maps; hash mapped .so files; compare against package md5sums |
| 3.11 | Known rootkit artifacts | Bake rkhunter-style artifact list at build time; check ~200 known paths/filenames |
| 3.12 | Full filesystem hash DB | Generate hash DB on baseline run; diff on subsequent runs; extends existing baseline mode |
| 5.10 | C2 IP reputation | Bake Feodo Tracker / abuse.ch IP blocklist at build time (same pattern as malware hash DB); check in netconn module |
| 7.7 | YARA scanning | Install YARA + community rulesets in Docker image; run as fast pre-filter before Claude triage in watch mode |
| 7.8 | Structured log parsing | Add sread modules for dpkg.log, apt history, syslog, journal; field extraction + correlation rules |
| 8.2 | Alerting / notification | Write hook in secy-common.sh; curl webhook or notify-send on CRITICAL findings; minimal implementation |
| 8.4 | Automatic DB updates | Download hash DB / YARA rules to state volume on startup or periodic refresh; avoids full rebuild |

### Partial coverage (improvement opportunities)

| # | Current state | Improvement |
|---|---------------|-------------|
| 2.8 | Thread comm mismatch heuristic | Deeper thread analysis (stack traces, memory regions) |
| 2.9 | PID namespace comparison with container allowlist | Track namespace creation events, correlate with network activity |
| 3.9 | perms.sh runs getfacl | Flag ACLs that grant unexpected users access to sensitive files |
| 3.10 | perms.sh runs lsattr | Flag immutable/append-only bits on non-standard files |
| 4.5 | Kprobe enumeration from debugfs | Requires debugfs mount; syscall table address comparison needs /proc/kallsyms |
| 4.6 | Pinned BPF + bpftool + tracepoints + sysctl | Requires bpftool for full program listing; container may lack bpffs |
| 5.7 | Tool/binary/listener/resolv.conf detection | Needs packet capture (tcpdump/tshark) to detect actual DNS tunneling traffic |
| 6.1–6.3 | EFI vars, Secure Boot, BMC/IPMI presence | Cannot verify boot chain integrity or audit BMC firmware from userspace |
| 7.2 | kmod cross-check implemented; netconn uses host netns | Further cross-source techniques (e.g., /proc/net/tcp vs ss output) |
| 7.3 | Name-based + behavioral + exe-based | fd analysis for all processes, not just known names |
| 8.5 | Ad-hoc hardening checks in AGENT.md | Map checks to CIS benchmark IDs; produce a hardening score; add STIG/PCI profiles |
