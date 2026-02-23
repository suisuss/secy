# Threat Detection Depth Reference

Companion to [THREATS.md](THREATS.md). For each technique: what the threat is, where to look, what to look for, and how to fix it.

---

## 1. Userland persistence

### 1.1 XDG autostart entries

**Threat**: `.desktop` files in XDG autostart directories run automatically when a user logs in to a graphical session. An attacker who drops a `.desktop` file here gets persistent code execution that survives reboot, triggered every time the user logs in.

**Where to look**:
- `/etc/xdg/autostart/*.desktop` — system-wide, affects all users
- `~/.config/autostart/*.desktop` — per-user

**What to look for**:
- `Exec=` lines containing `curl`, `wget`, `nc`, `bash -c`, `python -c`, `/tmp/`, `/dev/shm/`, or any path outside standard application directories
- `Hidden=true` combined with a suspicious Exec — hides the entry from desktop settings UI
- `.desktop` files with `Name=` values mimicking system services ("System Updater", "Desktop Service")
- Files not owned by a package — cross-reference against `dpkg -S <file>`
- Recently modified files — `stat -c '%Y %n' /etc/xdg/autostart/*.desktop | sort -n`

**Remediation**:
```bash
# Remove the malicious autostart entry
rm /etc/xdg/autostart/malicious-entry.desktop
# Or for per-user:
rm ~/.config/autostart/malicious-entry.desktop

# Verify no process is still running from it
pgrep -af <executable_from_Exec_line>
kill <pid>
```

---

### 1.2 Systemd user services

**Threat**: Systemd user services run in the user's session without root privileges. An attacker can create a service unit that starts automatically, restarts on failure, and survives logout if lingering is enabled. These are often missed because admins focus on system-level units.

**Where to look**:
- `~/.config/systemd/user/*.service` — user service unit files
- `~/.config/systemd/user/*.timer` — user timer units (cron equivalent)
- `~/.config/systemd/user/default.target.wants/` — enabled units

**What to look for**:
- `ExecStart=` pointing to `/tmp/`, `/dev/shm/`, or hidden directories
- `Restart=always` or `Restart=on-failure` — persistence through crashes
- Services with `Type=simple` running shell commands or interpreters
- Timer units triggering at high frequency (every minute, every 5 minutes)
- Units with `WantedBy=default.target` (auto-starts on login)
- Files not matching any installed package

**Remediation**:
```bash
# Stop and disable the service
systemctl --user stop malicious.service
systemctl --user disable malicious.service

# Remove the unit file
rm ~/.config/systemd/user/malicious.service

# Reload the user daemon
systemctl --user daemon-reload

# Check if lingering is enabled (allows user services to run without login)
loginctl show-user <username> | grep Linger
# Disable if not needed:
sudo loginctl disable-linger <username>
```

---

### 1.3 Shell profile hooks

**Threat**: Shell initialization files (`.bashrc`, `.zshrc`, `.profile`, `.bash_profile`) execute every time a shell starts. Malware can inject commands that exfiltrate data on every shell session — `PROMPT_COMMAND` runs before every prompt, `trap DEBUG` runs before every command. These are invisible to the user during normal operation.

**Where to look**:
- `~/.bashrc`, `~/.zshrc` — interactive shell init
- `~/.profile`, `~/.bash_profile` — login shell init
- `~/.bash_logout` — runs on logout (can exfiltrate session history)
- `/etc/profile`, `/etc/bash.bashrc` — system-wide (requires root to modify)
- `/etc/profile.d/*.sh` — system-wide drop-in scripts

**What to look for**:
- `PROMPT_COMMAND` containing `curl`, `wget`, `nc`, or any network command
- `trap '...' DEBUG` — runs a command before every user command; used for keystroke/command exfiltration
- `eval $(curl ...)` or `eval $(wget -qO- ...)` — downloads and executes code
- Base64-encoded payloads: `echo <base64> | base64 -d | bash`
- Obfuscated variable names or hex-encoded strings
- Lines added at the very end of the file (after legitimate content)
- `/dev/tcp/` or `/dev/udp/` bash network redirects

**Remediation**:
```bash
# Remove the malicious lines from the shell profile
# First, identify them:
grep -n 'PROMPT_COMMAND\|trap.*DEBUG\|eval.*curl\|base64.*bash' ~/.bashrc

# Edit the file and remove the offending lines
nano ~/.bashrc

# Check system-wide profiles too
grep -rn 'curl\|wget\|nc\|/dev/tcp' /etc/profile /etc/profile.d/ /etc/bash.bashrc

# Kill any background processes spawned by the hook
pgrep -af 'curl\|wget\|nc'
```

---

### 1.4 Cron persistence

**Threat**: Cron jobs execute commands on a schedule as the owning user (or root for system crontabs). An attacker with write access can install a cron job that re-establishes a backdoor, exfiltrates data, or downloads fresh payloads periodically. Cron jobs survive reboot.

**Where to look**:
- `/etc/crontab` — system crontab (specifies user field)
- `/etc/cron.d/*` — system cron drop-ins
- `/etc/cron.{hourly,daily,weekly,monthly}/` — periodic script directories
- `/var/spool/cron/crontabs/*` — per-user crontabs (one file per user)
- On Red Hat: `/var/spool/cron/*`

**What to look for**:
- `curl | bash`, `wget -O- | sh`, or any download-and-execute pattern
- Jobs running every minute (`* * * * *`) or at very high frequency
- Root cron jobs referencing scripts in user-writable directories (e.g., `/tmp/`, `/home/`)
- Jobs for users that no longer exist in `/etc/passwd`
- References to non-existent scripts (leftover from failed cleanup)
- Encoded or obfuscated commands
- Use of `@reboot` for boot persistence

**Remediation**:
```bash
# List all user crontabs
for user in $(cut -d: -f1 /etc/passwd); do
    crontab -l -u "$user" 2>/dev/null && echo "--- $user ---"
done

# Remove a specific user's crontab entry
crontab -e -u <username>
# Or remove their entire crontab:
crontab -r -u <username>

# Remove malicious system cron drop-in
rm /etc/cron.d/malicious-job

# Verify the referenced script/binary doesn't remain
rm /path/to/malicious/script.sh
```

---

### 1.5 rc.local

**Threat**: `/etc/rc.local` runs as root at the end of the boot process on systems that support it. On modern systemd systems it should not exist or should not be executable. If present and executable, it's a legacy persistence mechanism that runs arbitrary commands as root on every boot.

**Where to look**:
- `/etc/rc.local`
- Symlink target if it's a symlink

**What to look for**:
- File exists and has the executable bit set (`-rwxr-xr-x`)
- Content containing reverse shells, download-and-execute, or any command beyond simple system setup
- Recently modified (`stat /etc/rc.local`)
- On systemd systems: check if `rc-local.service` is enabled (`systemctl is-enabled rc-local`)

**Remediation**:
```bash
# Inspect the contents
cat /etc/rc.local

# Remove the malicious content (keep the file if needed, remove the executable bit)
chmod -x /etc/rc.local
# Or delete entirely if not needed:
rm /etc/rc.local

# Disable the rc-local service
sudo systemctl disable rc-local.service
sudo systemctl stop rc-local.service
```

---

### 1.6 Non-package init.d scripts

**Threat**: Scripts in `/etc/init.d/` that don't belong to any installed package are suspicious. On systems using systemd, init.d scripts are compatibility wrappers — legitimate ones come from packages. An attacker can drop a script here that gets invoked by systemd-sysv-generator, creating a service that starts at boot.

**Where to look**:
- `/etc/init.d/*`
- Cross-reference each script against `/var/lib/dpkg/info/*.list` (Debian/Ubuntu) or `rpm -qf` (RHEL/Fedora)

**What to look for**:
- Scripts not owned by any package: `dpkg -S /etc/init.d/<script>` returns "not found"
- Scripts with recent modification times
- Content containing reverse shells, miners, or network-facing daemons
- Scripts named to mimic system services ("syshealth", "system-updater", "networkd-helper")

**Remediation**:
```bash
# Identify the script and verify it's not from a package
dpkg -S /etc/init.d/suspicious-script
# If "not found":

# Stop the service
sudo systemctl stop suspicious-script
sudo systemctl disable suspicious-script

# Remove the script
sudo rm /etc/init.d/suspicious-script

# Reload systemd to clear the generated unit
sudo systemctl daemon-reload
```

---

### 1.7 Browser extensions

**Threat**: Browser extensions can read all web traffic, capture credentials, inject content into pages, access cookies, and exfiltrate browsing data. A malicious extension installed silently (or a legitimate one compromised via update) has near-total visibility into the user's web activity.

**Where to look**:
- Chromium-based (Chrome, Brave, Edge): `~/.config/google-chrome/Default/Extensions/<id>/<version>/manifest.json`
- Brave: `~/.config/BraveSoftware/Brave-Browser/Default/Extensions/`
- Firefox: `~/.mozilla/firefox/<profile>/extensions/` (`.xpi` files) and `extensions.json`
- GNOME Web/Epiphany: `~/.local/share/epiphany/extensions/`

**What to look for**:
- `manifest.json` permissions: `<all_urls>`, `tabs`, `webRequest`, `webRequestBlocking`, `cookies`, `history`, `downloads`, `nativeMessaging`
- Extensions with vague names ("Helper", "Optimizer", "Enhancer") and no web store listing
- Extensions not installed from the official web store — check `update_url` in manifest
- Extensions with `content_scripts` matching all URLs (`"matches": ["<all_urls>"]`)
- `background` scripts that make network requests to unknown domains
- Localized names (`__MSG_...`) — resolve via `_locales/en/messages.json`

**Remediation**:
```bash
# Identify suspicious extensions by reading their manifests
for dir in ~/.config/google-chrome/Default/Extensions/*/; do
    manifest="$(find "$dir" -name manifest.json -maxdepth 2 | head -1)"
    [ -n "$manifest" ] && echo "$dir: $(jq -r '.name' "$manifest" 2>/dev/null)"
done

# Remove from the browser UI (preferred — handles cleanup):
# Chrome: chrome://extensions → Remove
# Firefox: about:addons → Remove

# Manual removal (if browser is compromised):
rm -rf ~/.config/google-chrome/Default/Extensions/<extension-id>/

# Block enterprise-installed extensions:
# Remove policies from /etc/opt/chrome/policies/ or /etc/chromium/policies/
```

---

### 1.8 LD_PRELOAD system-wide

**Threat**: `/etc/ld.so.preload` lists shared libraries that the dynamic linker loads into **every** dynamically-linked process on the system. A malicious library here can intercept any libc function (open, read, write, connect) in every process — including login, SSH, sudo. This is the most powerful userland hooking mechanism on Linux.

**Where to look**:
- `/etc/ld.so.preload`

**What to look for**:
- The file should **not exist** on a normal system. Its mere existence is a finding.
- If it exists: every library path listed in it
- Verify each listed library: `file <path>`, `strings <path>`, `sha256sum <path>`
- Check if the library is from a known package: `dpkg -S <path>`
- On a compromised system, the library may hook `readdir()` to hide itself from `ls` and `find`

**Remediation**:
```bash
# Check if the file exists
cat /etc/ld.so.preload

# Remove it (or remove the malicious entry)
sudo rm /etc/ld.so.preload

# Remove the malicious shared library
sudo rm /path/to/malicious.so

# Rebuild the ld cache
sudo ldconfig

# CRITICAL: any process started while the preload was active may be compromised.
# Restart all services, or reboot.
sudo reboot
```

---

### 1.9 LD_PRELOAD per-process

**Threat**: The `LD_PRELOAD` environment variable, when set for a specific process, loads a shared library into that process before all others. Unlike `/etc/ld.so.preload`, this targets specific processes — an attacker can inject a hooking library into a single high-value target (SSH daemon, web server, database) without affecting the whole system.

**Where to look**:
- `/proc/[pid]/environ` — environment variables of each running process (NUL-delimited, requires root)

**What to look for**:
- Any process with `LD_PRELOAD=` in its environment
- The path of the preloaded library — is it from a package? Does it exist on disk? Is it in a temporary directory?
- Processes where LD_PRELOAD would not normally be set (sshd, nginx, postgres, etc.)
- Note: some legitimate uses exist (e.g., `LD_PRELOAD=libfakeroot.so` for fakeroot, jemalloc overrides)

**Remediation**:
```bash
# Find all processes with LD_PRELOAD
for pid in /proc/[0-9]*/; do
    env_file="${pid}environ"
    [ -r "$env_file" ] && tr '\0' '\n' < "$env_file" | grep -q '^LD_PRELOAD=' && \
        echo "PID $(basename $pid): $(cat ${pid}cmdline | tr '\0' ' ')"
done

# Kill the affected process
kill <pid>

# Remove the malicious library
rm /path/to/injected.so

# Find how LD_PRELOAD was set — check:
#   - The service unit file (Environment= or EnvironmentFile=)
#   - The shell profile that launched it
#   - /etc/environment
#   - The wrapper script that started it
grep -r LD_PRELOAD /etc/systemd/system/ /etc/environment /etc/profile.d/

# Restart the clean service
sudo systemctl restart <service>
```

---

### 1.10 PAM module tampering

**Threat**: PAM (Pluggable Authentication Modules) controls how authentication works on the system — login, SSH, sudo, su all go through PAM. An attacker who adds a malicious PAM module can backdoor authentication (always accept a magic password), log credentials (capture every password entered on the system), or bypass authentication entirely.

**Where to look**:
- `/etc/pam.d/*` — PAM configuration files (one per service)
- `/lib/x86_64-linux-gnu/security/` or `/lib/security/` — PAM module binaries

**What to look for**:
- `pam_exec.so` entries — executes an arbitrary script during auth. Check what script it runs.
- `pam_script.so` — similar, runs scripts from `/etc/pam-script.d/`
- `pam_permit.so` in an `auth` stack — always succeeds (backdoor)
- Modules with `sufficient` control that appear before normal auth modules — allows bypass
- Unknown `.so` files in the PAM module directory not owned by a package
- Recently modified PAM configs: `stat /etc/pam.d/*`
- Modified PAM module binaries: `debsums -c libpam-modules`

**Remediation**:
```bash
# Check for suspicious PAM entries
grep -rn 'pam_exec\|pam_script\|pam_permit' /etc/pam.d/

# Verify PAM module integrity
debsums -c libpam-modules libpam0g

# Remove the malicious PAM config line
# CAUTION: incorrect PAM editing can lock you out of the system.
# Keep a root shell open while editing.
sudo nano /etc/pam.d/common-auth

# Remove unauthorized PAM modules
sudo rm /lib/x86_64-linux-gnu/security/malicious_pam.so

# Reinstall PAM modules from packages to restore known-good state
sudo apt-get install --reinstall libpam-modules
```

---

### 1.11 Suspicious shared libraries in ld cache

**Threat**: The dynamic linker cache (`/etc/ld.so.cache`, populated by `ldconfig`) lists all shared libraries available for dynamic linking. A malicious `.so` installed in a library path and registered via `ldconfig` can be loaded by any program that links against a library it mimics — or can be loaded via `LD_PRELOAD` or `dlopen()`.

**Where to look**:
- `ldconfig -p` — print current cache
- `/etc/ld.so.conf` and `/etc/ld.so.conf.d/*.conf` — library search paths
- Library directories: `/usr/lib/`, `/usr/local/lib/`, `/lib/`

**What to look for**:
- Libraries with suspicious names in the cache: keywords like `spy`, `hook`, `inject`, `keylog`, `intercept`, `sniff`, `backdoor`
- Libraries in `/usr/local/lib/` or custom paths not owned by any package
- Recently installed libraries: `find /usr/local/lib -name '*.so*' -newer /var/lib/dpkg/info -type f`
- Library paths in `/etc/ld.so.conf.d/` that point to unusual directories

**Remediation**:
```bash
# List suspicious libraries
ldconfig -p | grep -iE 'spy|hook|inject|keylog|sniff|backdoor'

# Identify the library file
find /usr/lib /usr/local/lib /lib -name '*suspicious*'

# Check if it's from a package
dpkg -S /path/to/suspicious.so

# Remove the library
sudo rm /path/to/suspicious.so

# Remove any custom ldconfig conf that loaded it
ls /etc/ld.so.conf.d/
sudo rm /etc/ld.so.conf.d/suspicious.conf

# Rebuild the cache
sudo ldconfig
```

---

### 1.12 SSH authorized_keys persistence

**Threat**: An attacker who gains write access to `~/.ssh/authorized_keys` can add their own public key for persistent passwordless SSH access. This survives password changes, service restarts, and reboots. Forced commands can be used to execute payloads on every login, and non-standard `AuthorizedKeysFile` paths in sshd_config can hide keys from casual inspection.

**Where to look**:
- `~/.ssh/authorized_keys` and `~/.ssh/authorized_keys2` — per-user authorized keys
- `/etc/ssh/sshd_config` — `AuthorizedKeysFile` directive (may point to non-standard locations)
- `/etc/ssh/sshd_config.d/*.conf` — drop-in overrides
- `/root/.ssh/authorized_keys` — root account

**What to look for**:
- Keys added recently that the user doesn't recognize — compare key count against expected
- `command="..."` forced command prefixes — execute arbitrary code on every SSH login
- `no-pty,no-agent-forwarding` restrictions on legitimate keys being removed (widening access)
- `AuthorizedKeysFile` pointing to non-standard paths like `/tmp/`, `/dev/shm/`, or world-writable directories
- Keys with comments that don't match known team members or machines
- `authorized_keys` files with unexpected permissions (should be 600)

**Remediation**:
```bash
# List all authorized keys for all users
for home in /home/* /root; do
    [ -f "$home/.ssh/authorized_keys" ] && echo "=== $home ===" && cat "$home/.ssh/authorized_keys"
done

# Check for non-standard AuthorizedKeysFile
grep -ri AuthorizedKeysFile /etc/ssh/

# Remove unauthorized keys
# Edit ~/.ssh/authorized_keys and remove unknown entries

# Verify permissions
chmod 600 ~/.ssh/authorized_keys
chmod 700 ~/.ssh
```

---

### 1.13 Systemd drop-in overrides

**Threat**: Systemd drop-in files (`/etc/systemd/system/<unit>.d/override.conf`) can silently replace the `ExecStart` of any system service without modifying the original unit file. Generators in `/etc/systemd/system-generators/` or `/etc/systemd/user-generators/` dynamically create units at boot. Socket activation hijacking redirects traffic intended for one service to a malicious one.

**Where to look**:
- `/etc/systemd/system/*.d/override.conf` — system service overrides
- `~/.config/systemd/user/*.d/override.conf` — user service overrides
- `/etc/systemd/system-generators/` and `/etc/systemd/user-generators/` — dynamic unit generators
- `/etc/systemd/system/*.socket` — socket activation units

**What to look for**:
- `ExecStart=` in drop-in files that differs from the original unit (especially pointing to `/tmp/`, `/dev/shm/`, or hidden dirs)
- Drop-in files that clear `ExecStart=` (empty value) then set a new one — complete ExecStart replacement
- Generators that are not from installed packages: `dpkg -S /etc/systemd/system-generators/*`
- Socket units listening on the same port as a legitimate service but activating a different binary
- Recently created drop-in directories: `find /etc/systemd/system -name '*.d' -newer /var/lib/dpkg/info -type d`

**Remediation**:
```bash
# List all overrides
systemd-delta --type=overridden

# Check generators
ls -la /etc/systemd/system-generators/ /etc/systemd/user-generators/ 2>/dev/null

# Remove malicious override
rm /etc/systemd/system/<service>.d/override.conf
systemctl daemon-reload
systemctl restart <service>

# Remove malicious generator
rm /etc/systemd/system-generators/<generator>
systemctl daemon-reload
```

---

### 1.14 Git hook persistence

**Threat**: Git hooks (`.git/hooks/`) execute automatically on git operations (commit, push, checkout, merge). An attacker who modifies hooks in a frequently-used repository gets code execution whenever the developer runs git commands. Global `core.hooksPath` redirects all repos to attacker-controlled hooks. `url.*.insteadOf` can silently redirect git remotes to attacker-controlled servers.

**Where to look**:
- `.git/hooks/` in any repository — per-repo hooks
- `~/.gitconfig` or `~/.config/git/config` — global git configuration
- `/etc/gitconfig` — system-wide git configuration
- `git config --global --list` — check core.hooksPath and url.*.insteadOf

**What to look for**:
- Executable hooks in `.git/hooks/` that are not symlinks to a known hook manager (husky, pre-commit, lefthook)
- `core.hooksPath` pointing to an unexpected directory (especially outside the repo)
- `url.<base>.insteadOf` entries that redirect known hosts to unknown servers
- Hooks containing `curl`, `wget`, `nc`, `bash -c`, or any network exfiltration commands
- `post-checkout` or `post-merge` hooks — execute on common operations developers don't think twice about

**Remediation**:
```bash
# Check global hooks path
git config --global core.hooksPath

# Check URL rewriting rules
git config --global --get-regexp 'url\..*\.insteadof'

# Inspect hooks in a repository
ls -la .git/hooks/
cat .git/hooks/post-checkout

# Remove malicious global config
git config --global --unset core.hooksPath
git config --global --unset-all url.<malicious>.insteadOf

# Remove malicious per-repo hooks
rm .git/hooks/<malicious-hook>
```

---

### 1.15 D-Bus service hijacking

**Threat**: D-Bus is the inter-process communication system used by most Linux desktops. User-writable service files in `~/.local/share/dbus-1/services/` can intercept service activation requests — when an application asks D-Bus to start a service by name, the attacker's binary runs instead. Permissive system bus policies in `/etc/dbus-1/system.d/` can allow unprivileged users to call privileged methods.

**Where to look**:
- `~/.local/share/dbus-1/services/*.service` — user session bus services
- `/usr/share/dbus-1/services/*.service` — system-installed session bus services
- `/etc/dbus-1/system.d/*.conf` — system bus policies
- `/usr/share/dbus-1/system-services/*.service` — system bus services

**What to look for**:
- User session services in `~/.local/share/dbus-1/services/` that shadow system-installed services (same `Name=` but different `Exec=`)
- Service files with `Exec=` pointing to `/tmp/`, `/dev/shm/`, or hidden directories
- System bus policies with `<allow send_destination="..." />` for unexpected senders
- Policies granting `<allow own="..." />` to non-root users for privileged service names
- Recently modified service files: `find ~/.local/share/dbus-1/services/ -newer /var/lib/dpkg/info`

**Remediation**:
```bash
# List user D-Bus services
ls -la ~/.local/share/dbus-1/services/

# Compare against system-installed services
diff <(ls /usr/share/dbus-1/services/) <(ls ~/.local/share/dbus-1/services/ 2>/dev/null)

# Remove malicious user service
rm ~/.local/share/dbus-1/services/malicious.service

# Check system bus policies for overly permissive rules
grep -r 'allow.*send_destination' /etc/dbus-1/system.d/

# Restart D-Bus (caution: affects all D-Bus services)
sudo systemctl restart dbus
```

---

## 2. Process-level hiding

### 2.1 Known spyware process name matching

**Threat**: Many surveillance tools, keyloggers, screen recorders, and RATs run as named processes that can be identified by their binary name in `/proc`. While sophisticated malware renames itself, commodity tools often don't.

**Where to look**:
- `/proc/[pid]/cmdline` — full command line (NUL-delimited)
- `/proc/[pid]/comm` — kernel's 15-character process name
- `/proc/[pid]/exe` — symlink to the actual binary on disk

**What to look for**:
- **Keyloggers**: `logkeys`, `lkl`, `pykeylogger`, `xspy`, `xkeysnail`, `screenkey`
- **Screen recorders** (when unexpected): `recordmydesktop`, `simplescreenrecorder`, `vokoscreen`, `kazam`, `peek`, `ffmpeg` with `x11grab`
- **RATs / remote access**: `teamviewer`, `anydesk`, `rustdesk`, `x11vnc`, `tigervnc`, `xrdp`, `vino`, `chrome-remote-desktop`
- **Sniffers**: `tcpdump`, `wireshark`, `tshark`, `ettercap`, `bettercap`, `mitmproxy`
- **Tracers**: `strace` or `ltrace` attached to other processes

**Remediation**:
```bash
# Find and kill the suspicious process
pgrep -af <process_name>
kill <pid>

# Find its binary on disk
readlink /proc/<pid>/exe

# Remove the binary
rm /path/to/malicious/binary

# Check how it was started — look at its parent:
cat /proc/<pid>/status | grep PPid
# Then investigate the parent process

# Check persistence mechanisms (cron, autostart, systemd, rc.local)
```

---

### 2.2 Ptrace attachment detection

**Threat**: `ptrace()` allows one process to observe and control another — read its memory, intercept syscalls, modify registers. A debugger/tracer attached to a process can steal credentials, inject code, or exfiltrate data. While `strace` and `gdb` are legitimate tools, an unexpected `TracerPid` is a strong indicator of compromise.

**Where to look**:
- `/proc/[pid]/status` — the `TracerPid` field

**What to look for**:
- Any process with `TracerPid` != 0
- Identify the tracer: `readlink /proc/<TracerPid>/exe` and `cat /proc/<TracerPid>/cmdline`
- Legitimate tracers: `gdb`, `strace`, `ltrace` used by developers. Unexpected tracers on production systems are suspicious.
- Tracers attached to high-value targets: sshd, gpg-agent, ssh-agent, browser processes

**Remediation**:
```bash
# Find traced processes
grep -l 'TracerPid:\s*[1-9]' /proc/[0-9]*/status 2>/dev/null

# Kill the tracer
kill <tracer_pid>

# Harden against ptrace:
# Set kernel ptrace scope (1 = only parent can trace)
echo 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope

# Make persistent:
echo "kernel.yama.ptrace_scope = 1" | sudo tee /etc/sysctl.d/99-ptrace.conf
sudo sysctl -p /etc/sysctl.d/99-ptrace.conf
```

---

### 2.3 /dev/input readers (keylogger detection)

**Threat**: `/dev/input/event*` devices expose raw keyboard, mouse, and other input events. A process reading these devices directly can capture every keystroke on the system — passwords, messages, commands — without hooking any library or kernel function. This is the simplest hardware-level keylogging technique on Linux.

**Where to look**:
- `/proc/[pid]/fd/` — check symlink targets for each process's open file descriptors
- Look for `fd -> /dev/input/event*`

**What to look for**:
- Any process with an open fd to `/dev/input/event*`
- Legitimate readers: Xorg, Xwayland, libinput, mutter, gnome-shell, kwin, sway (display servers and compositors need input devices)
- Everything else reading `/dev/input/` is suspicious
- Check the process binary: `readlink /proc/<pid>/exe`

**Remediation**:
```bash
# Find processes reading input devices
for pid in /proc/[0-9]*/; do
    ls -la "${pid}fd/" 2>/dev/null | grep '/dev/input/' && echo "PID: $(basename $pid) CMD: $(cat ${pid}cmdline | tr '\0' ' ')"
done

# Kill the suspicious reader
kill <pid>

# Remove the binary
rm "$(readlink /proc/<pid>/exe)"

# Restrict input device permissions (most systems already do this):
# Ensure /dev/input/ is only readable by root and the 'input' group
ls -la /dev/input/
# Only the display server user should be in the 'input' group
grep input /etc/group
```

---

### 2.4 Raw/packet socket detection

**Threat**: Raw sockets (`AF_RAW`) and packet sockets (`AF_PACKET`) allow a process to send and receive network packets directly, bypassing the kernel's protocol stack. This enables packet sniffing (capture all traffic on the interface), packet injection, and network attacks. Almost nothing legitimate uses raw sockets besides `ping`.

**Where to look**:
- `/proc/net/raw` — raw socket table
- `/proc/net/packet` — packet socket table
- `/proc/[pid]/fd/` — correlate socket inodes against the above tables

**What to look for**:
- Any entry in `/proc/net/raw` or `/proc/net/packet`
- The inode column links to a process via `/proc/[pid]/fd/` symlinks: `socket:[<inode>]`
- Legitimate: `ping` (ICMP raw socket), `dhclient` (packet socket for DHCP), NetworkManager
- Suspicious: any unknown process holding a raw or packet socket

**Remediation**:
```bash
# Check for raw/packet sockets
cat /proc/net/raw
cat /proc/net/packet

# Identify the owning process (by inode)
inode=<from_above>
find /proc/[0-9]*/fd -lname "socket:\[$inode\]" 2>/dev/null

# Kill the sniffer
kill <pid>

# Remove CAP_NET_RAW from non-essential binaries:
# Check what has it:
getcap /usr/bin/ping
# If ping doesn't need it (modern kernels handle ICMP):
sudo setcap -r /usr/bin/ping
```

---

### 2.5 Deleted binary detection

**Threat**: When a process's binary is deleted from disk while the process is still running, `/proc/[pid]/exe` shows the path appended with ` (deleted)`. This is normal after package upgrades (old binary deleted, new one installed, process still running the old version). But it's also a classic malware technique: run the binary, then delete it from disk to avoid forensic analysis.

**Where to look**:
- `/proc/[pid]/exe` — symlink to the executable. Read with `readlink`.

**What to look for**:
- `readlink /proc/[pid]/exe` returning a path ending in ` (deleted)`
- Cross-reference with recent package upgrades: `grep -i 'upgrade\|remove' /var/log/dpkg.log | tail -50`
- If a package was recently upgraded and a service hasn't been restarted — that's expected (e.g., `libssl` upgrade, Apache still running old version). Restart the service.
- If there's no corresponding package upgrade — the binary was deliberately deleted. Investigate.

**Remediation**:
```bash
# Find all deleted-binary processes
ls -la /proc/[0-9]*/exe 2>/dev/null | grep '(deleted)'

# For legitimate post-upgrade cases:
sudo systemctl restart <service>
# Or if needrestart is installed:
sudo needrestart

# For malicious cases — recover the binary for analysis before killing:
cp /proc/<pid>/exe /tmp/recovered-binary
file /tmp/recovered-binary
strings /tmp/recovered-binary | head -50

# Then kill it
kill <pid>
```

---

### 2.6 memfd_create execution

**Threat**: `memfd_create()` creates an anonymous file in memory (backed by tmpfs) that has no path on any filesystem. An attacker can write an executable payload into a memfd, then execute it with `fexecve()`. The binary never touches disk — there is no file to find, hash, or scan. `/proc/[pid]/exe` shows `/memfd:<name>`. This is a primary fileless malware technique on Linux.

**Where to look**:
- `/proc/[pid]/exe` — check for symlinks to `/memfd:*`

**What to look for**:
- Any `exe` symlink containing `/memfd:` — this is almost never legitimate
- Rare legitimate uses: some JIT compilers and runtimes use memfd for code generation (e.g., some Java/V8 configurations). These should be identifiable by parent process and name.
- Check the process's memory map: `cat /proc/<pid>/maps` — the memfd will appear as a mapped region
- Check network connections: `ls -la /proc/<pid>/fd/ | grep socket` — fileless malware often maintains C2 connections

**Remediation**:
```bash
# Find memfd processes
for pid in /proc/[0-9]*/; do
    exe="$(readlink ${pid}exe 2>/dev/null)"
    [[ "$exe" == *"/memfd:"* ]] && echo "PID $(basename $pid): $exe — $(cat ${pid}cmdline | tr '\0' ' ')"
done

# Dump the binary from memory for analysis
cp /proc/<pid>/exe /tmp/memfd-dump
file /tmp/memfd-dump
sha256sum /tmp/memfd-dump

# Kill the process
kill -9 <pid>

# Investigate how it was launched — check parent process and any persistence mechanisms
cat /proc/<pid>/status | grep PPid

# Harden: restrict memfd_create via seccomp or audit rules
# Add auditd rule to log memfd_create calls:
sudo auditctl -a always,exit -F arch=b64 -S memfd_create -k memfd
```

---

### 2.7 Process name spoofing

**Threat**: A process can change its `comm` name (what shows in `ps`, `top`) via `prctl(PR_SET_NAME)` or by overwriting `argv[0]`. This makes malware appear as a legitimate process. The kernel's `comm` field is only 15 characters and can be set to anything.

**Where to look**:
- `/proc/[pid]/comm` — kernel process name (15 chars max)
- `/proc/[pid]/exe` — actual binary on disk
- `/proc/[pid]/cmdline` — command line arguments (can also be spoofed)

**What to look for**:
- Mismatch between `comm` and `basename(exe)` — accounting for 15-char truncation
- Exclude legitimate mismatches: interpreters (bash running a script shows script name), multi-call binaries (busybox), Java (java running a .jar)
- A binary named `sshd` whose exe points to `/tmp/payload` — clear spoofing
- Check if the exe path binary exists and is legitimate

**Remediation**:
```bash
# Find mismatches
for pid in /proc/[0-9]*/; do
    comm="$(cat ${pid}comm 2>/dev/null)"
    exe="$(readlink ${pid}exe 2>/dev/null)"
    exe_base="$(basename "$exe" 2>/dev/null)"
    if [ -n "$comm" ] && [ -n "$exe_base" ] && [ "$comm" != "${exe_base:0:15}" ]; then
        echo "PID $(basename $pid): comm=$comm exe=$exe"
    fi
done 2>/dev/null

# Kill spoofed processes after investigation
kill <pid>

# Remove the binary
rm "$(readlink /proc/<pid>/exe)"
```

---

### 2.8 Thread injection

**Threat**: An attacker can inject threads into a legitimate process, making malicious code run under the identity and permissions of a trusted process. The injected thread appears as a task under `/proc/[pid]/task/` but executes attacker-controlled code.

**Where to look**:
- `/proc/[pid]/task/` — list of all threads in a process
- `/proc/[pid]/task/[tid]/comm` — per-thread name
- `/proc/[pid]/task/[tid]/status` — per-thread state

**What to look for**:
- Thread count significantly higher than expected for the process type
- Threads with `comm` names that don't match the parent process's expected thread naming convention
- Threads with different memory maps or capability sets than expected
- Compare thread count against a known-good baseline for that service

**Remediation**:
```bash
# Count threads per process
for pid in /proc/[0-9]*/; do
    nthreads=$(ls -1 ${pid}task/ 2>/dev/null | wc -l)
    [ "$nthreads" -gt 20 ] && echo "PID $(basename $pid) ($nthreads threads): $(cat ${pid}cmdline | tr '\0' ' ')"
done

# Restart the affected service to clear injected threads
sudo systemctl restart <service>

# Harden against ptrace-based injection:
echo 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

---

### 2.9 PID namespace hiding

**Threat**: Linux PID namespaces isolate process ID spaces — a process in a non-default PID namespace is invisible to `ps` and other tools running in the default namespace (unless they specifically inspect all namespaces). An attacker can create a PID namespace to hide processes from standard monitoring.

**Where to look**:
- `/proc/[pid]/ns/pid` — PID namespace identifier (inode number)
- Compare against PID 1's namespace: `readlink /proc/1/ns/pid`

**What to look for**:
- Any process whose `/proc/[pid]/ns/pid` differs from PID 1's namespace (and is not a container)
- Cross-reference with known container runtimes (Docker, Podman, LXC) — those legitimately use PID namespaces
- Processes in non-default namespaces that are not part of any known container workload

**Remediation**:
```bash
# Find processes in non-default PID namespaces
default_ns=$(readlink /proc/1/ns/pid)
for pid in /proc/[0-9]*/; do
    ns=$(readlink ${pid}ns/pid 2>/dev/null)
    if [ -n "$ns" ] && [ "$ns" != "$default_ns" ]; then
        echo "PID $(basename $pid) in namespace $ns: $(cat ${pid}cmdline | tr '\0' ' ')"
    fi
done

# Enter the namespace to inspect
sudo nsenter -t <pid> -p -m ps aux

# Kill the namespace leader to tear down all processes in it
kill <namespace_leader_pid>
```

---

### 2.10 Process tree / ancestry analysis

**Threat**: Malware often manifests as anomalous parent-child process relationships. A web server spawning a shell, cron spawning curl piped to bash, or systemd directly spawning a binary from `/tmp` — these patterns indicate exploitation or persistence. Individual process inspection may miss what the tree makes obvious.

**Where to look**:
- `/proc/[pid]/status` — `PPid` field gives the parent PID
- `/proc/[pid]/stat` — field 4 is the PPID
- Reconstruct the full tree by walking PPid chains up to PID 1

**What to look for**:
- Web server (apache, nginx, php-fpm) → shell (bash, sh, dash) — web shell or RCE
- Cron → shell → network command (curl, wget, nc) — download-and-execute persistence
- Systemd → binary in /tmp, /dev/shm, or /var/tmp — suspicious service
- sshd → shell → unusual commands for the user — account compromise
- init/systemd → orphaned process with no service unit — re-parented after parent death
- Database (mysql, postgres) → shell — SQL injection to OS command execution

**Remediation**:
```bash
# Build a process tree focused on suspicious processes
pstree -apls <pid>

# Or manually walk the chain
pid=<suspicious_pid>
while [ "$pid" -gt 1 ]; do
    echo "PID $pid: $(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')"
    pid=$(grep PPid /proc/$pid/status 2>/dev/null | awk '{print $2}')
done

# Kill the entire process tree
kill -- -<process_group_id>
# Or kill the root of the malicious tree and let children be re-parented and die

# Fix the vulnerability that allowed the anomalous chain
# (patch the web app, fix the cron job, rotate compromised credentials)
```

---

### 2.11 Process memory content scanning

**Threat**: Malware running in memory may not have any on-disk signature. Injected code in a legitimate process, shellcode in a heap buffer, or decrypted payloads in memory can only be found by scanning the process's address space directly.

**Where to look**:
- `/proc/[pid]/mem` — process memory (requires `CAP_SYS_PTRACE` or same UID)
- `/proc/[pid]/maps` — memory map showing what's loaded where

**What to look for**:
- Shellcode patterns: `\x90\x90` NOP sleds, `\x31\xc0` (xor eax,eax), `/bin/sh` strings in heap/stack regions
- Known IoC strings in memory (C2 domain names, campaign identifiers, unique malware strings)
- Executable regions (`rwxp` permissions in maps) in unexpected locations — heap or stack marked executable
- Regions with no backing file (anonymous mappings) containing executable code
- PE headers (`MZ`) in memory of Linux processes — cross-platform malware

**Remediation**:
```bash
# Dump process memory for offline analysis
cat /proc/<pid>/maps   # Understand the layout
# Use gdb or gcore to dump:
gcore -o /tmp/memdump <pid>

# Scan for known IoC strings
strings /tmp/memdump.<pid> | grep -iE 'c2-domain|known-malware-string'

# Kill the compromised process
kill -9 <pid>

# Restart the service from clean binaries
sudo systemctl restart <service>

# Investigate the infection vector — how did code get injected?
```

---

### 2.12 Loaded library verification

**Threat**: Even without `LD_PRELOAD`, a compromised process can load malicious shared libraries via `dlopen()`, or an attacker can replace a legitimate `.so` file on disk. The `/proc/[pid]/maps` file shows every shared library mapped into a process's address space. Comparing these against known-good hashes detects tampering.

**Where to look**:
- `/proc/[pid]/maps` — memory-mapped files including shared libraries
- Extract `.so` file paths from the maps file

**What to look for**:
- Libraries loaded from unusual paths (`/tmp/`, `/dev/shm/`, `/var/tmp/`, home directories)
- Libraries whose hash doesn't match the version installed by the package manager
- Libraries not owned by any package: `dpkg -S /path/to/lib.so`
- Multiple versions of the same library loaded (legitimate one + injected one)
- Anonymous mappings with `r-xp` permissions interleaved between library mappings — may indicate manual `mmap()` of code

**Remediation**:
```bash
# List all unique libraries loaded by a process
grep '\.so' /proc/<pid>/maps | awk '{print $6}' | sort -u

# Verify each against package manager
for lib in $(grep '\.so' /proc/<pid>/maps | awk '{print $6}' | sort -u); do
    dpkg -S "$lib" 2>/dev/null || echo "UNPACKAGED: $lib"
done

# Hash-check against package md5sums
md5sum /path/to/suspicious.so
grep "$(basename /path/to/suspicious.so)" /var/lib/dpkg/info/*.md5sums

# If tampered: reinstall the owning package
sudo apt-get install --reinstall <package>

# Restart the affected process
sudo systemctl restart <service>
```

---

## 3. Filesystem-level hiding

### 3.1 SUID binary scan

**Threat**: A binary with the SUID bit set runs with the privileges of the file's owner (usually root) regardless of who executes it. A SUID-root binary is a direct privilege escalation path — if it can be abused to run arbitrary commands (GTFOBins), an unprivileged user becomes root.

**Where to look**:
- `find / -perm -4000 -type f 2>/dev/null`

**What to look for**:
- SUID binaries outside standard locations (`/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/usr/lib`, `/usr/libexec`)
- GTFOBins candidates: `find`, `vim`, `python`, `perl`, `ruby`, `bash`, `dash`, `env`, `nmap`, `less`, `more`, `man`, `awk`, `sed`, `tar`, `zip`, `git`, `docker`, `strace`, `gdb`, `node`
- SUID binaries not owned by root
- SUID binaries not belonging to any package
- Recently created SUID binaries: `find / -perm -4000 -newer /var/log/dpkg.log -type f`

**Remediation**:
```bash
# Remove SUID from unnecessary binaries
sudo chmod u-s /path/to/unnecessary-suid-binary

# For GTFOBins candidates that need SUID for legitimate function,
# use capabilities instead:
sudo chmod u-s /usr/bin/ping
sudo setcap cap_net_raw+ep /usr/bin/ping

# Remove entirely if not legitimate
sudo rm /path/to/malicious-suid-binary
```

---

### 3.2 SGID binary scan

**Threat**: Similar to SUID, the SGID bit makes a binary run with the group privileges of the file's group. Less dangerous than SUID-root, but SGID binaries in groups like `shadow`, `disk`, `docker`, or `sudo` can still lead to escalation.

**Where to look**:
- `find / -perm -2000 -type f 2>/dev/null`

**What to look for**:
- SGID binaries in sensitive groups (`shadow`, `disk`, `docker`, `lxd`, `adm`)
- SGID binaries outside standard locations
- SGID binaries not owned by any package

**Remediation**:
```bash
# Remove SGID from unnecessary binaries
sudo chmod g-s /path/to/binary

# Use capabilities where possible
```

---

### 3.3 World-writable file scan

**Threat**: Files writable by any user can be modified by any attacker who gets any level of code execution on the system. World-writable scripts in cron, PATH directories, or service configurations are direct privilege escalation vectors — modify the script, wait for root/service to run it.

**Where to look**:
- `find / -perm -0002 -type f` excluding `/proc`, `/sys`, `/tmp`, `/var/tmp`, `/dev`, `/run`
- `find / -perm -0002 -type d` — world-writable directories (enable file creation/deletion by anyone)

**What to look for**:
- World-writable executables anywhere — immediate escalation vector
- World-writable files in `/etc/` — config tampering
- World-writable files in PATH directories — binary replacement
- World-writable files owned by root — if root runs them, escalation
- World-writable directories outside temp locations — allow dropping malicious files

**Remediation**:
```bash
# Fix permissions on specific files
sudo chmod o-w /path/to/writable-file

# For directories, set the sticky bit to prevent file deletion by non-owners
sudo chmod +t /path/to/writable-directory

# Audit bulk:
find / -perm -0002 -not -path '/proc/*' -not -path '/sys/*' \
  -not -path '/tmp/*' -not -path '/dev/*' -not -path '/run/*' \
  -type f -exec chmod o-w {} \;
```

---

### 3.4 Timestamp manipulation detection

**Threat**: `touch -t` can reset a file's `mtime` (modification time) to any date, making a backdoored binary appear to have been installed months ago. However, `ctime` (inode change time) updates automatically whenever any metadata changes and **cannot be reset** without raw disk access. A large discrepancy between `ctime` and `mtime` — where `ctime` is much newer — indicates the file was modified then backdated.

**Where to look**:
- System binary directories: `/usr/bin/`, `/usr/sbin/`, `/bin/`, `/sbin/`, `/usr/lib/`, `/lib/`
- `stat <file>` shows both Access, Modify, and Change times

**What to look for**:
- `ctime` significantly newer than `mtime` (threshold: 48+ hours) on system binaries
- System binaries with `ctime` within the last 24 hours (outside of a known package upgrade window)
- Cross-reference with `/var/log/dpkg.log` — a legitimate upgrade explains ctime changes

**Remediation**:
```bash
# Check for backdated binaries
find /usr/bin /usr/sbin /bin /sbin -type f -exec stat -c '%n mtime=%Y ctime=%Z' {} \; \
  | awk '{split($2,m,"="); split($3,c,"="); if(c[2]-m[2] > 172800) print}'

# Verify the specific binary against its package
dpkg -S /usr/bin/suspicious-binary
debsums -c <package>

# If modified, reinstall from package
sudo apt-get install --reinstall <package>
```

---

### 3.5 Extended attribute (xattr) payloads

**Threat**: Extended attributes are arbitrary name-value pairs attached to files. Malware can store configuration, encryption keys, C2 addresses, or even small payloads in xattrs. Most tools don't display them, most backup tools don't preserve them, and most admins don't check them. They persist through file copies on the same filesystem.

**Where to look**:
- `getfattr -d -m '' <file>` — dump all extended attributes
- `getfattr -R -d -m '' /etc/ /usr/ /var/` — recursive scan

**What to look for**:
- Any `user.*` xattrs on system binaries or config files — these are user-defined and unusual
- Large xattr values (> 100 bytes) — may contain encoded payloads
- Xattrs on files that don't normally have them
- `security.capability` xattrs that grant capabilities (alternative to SUID): `getcap <file>`

**Remediation**:
```bash
# List xattrs on a file
getfattr -d -m '' /path/to/suspicious-file

# Remove a specific xattr
setfattr -x user.malicious_key /path/to/file

# Scan broadly
find /usr /etc -exec getfattr -d -m '' {} \; 2>/dev/null | grep -v '^$'

# Remove file capabilities if inappropriate
sudo setcap -r /path/to/file
```

---

### 3.6 Bind mount file hiding

**Threat**: `mount --bind` mounts one directory on top of another, completely hiding the original contents. An attacker can hide a backdoor directory by bind-mounting an empty (or innocent-looking) directory over it. `ls` and `find` see the mount, not what's underneath.

**Where to look**:
- `/proc/mounts` or `mount` output — look for bind mounts (identified by same device, different mount points, or `bind` option)
- `/proc/self/mountinfo` — more detailed mount information

**What to look for**:
- Two mount entries with the same source device and filesystem type but different mount points
- Bind mounts on top of `/etc/`, `/usr/`, `/var/`, or other system directories
- Bind mounts where the source is a tmpfs or a directory in `/tmp/`, `/dev/shm/`
- Unusual mount count — compare number of mounts against a known-good baseline

**Remediation**:
```bash
# List all bind mounts
findmnt -t none -o TARGET,SOURCE,OPTIONS | grep bind
# Or parse /proc/self/mountinfo for duplicate device numbers

# Unmount the hiding mount to reveal what's underneath
sudo umount /path/to/suspicious/mount

# Investigate what was hidden
ls -la /path/to/now-revealed/directory

# Make persistent: check /etc/fstab for bind mount entries
grep bind /etc/fstab
```

---

### 3.7 Dotfile/unicode filename tricks

**Threat**: Filenames can be crafted to be invisible or misleading: `. ` (dot-space) looks like the current directory, `..` in a subdirectory is hidden by default, filenames with Cyrillic or other Unicode lookalike characters can impersonate legitimate files, and names starting with a dot are hidden from default `ls` output.

**Where to look**:
- `ls -la` in sensitive directories
- `find / -name '.. *' -o -name '. *'` — files starting with dot-space
- `find / -name '.*' -type f` in non-home directories

**What to look for**:
- Files named `. ` (dot-space), `.. ` (dot-dot-space), or `...` in system directories
- Hidden files (dotfiles) in system directories where they don't belong (`/etc/.hidden`, `/usr/bin/.payload`)
- Filenames with non-ASCII characters that visually mimic legitimate names
- Files in `/dev/`, `/dev/shm/`, or system directories starting with `.`

**Remediation**:
```bash
# Find hidden files in system directories
find /usr /etc /var /opt -name '.*' -type f 2>/dev/null

# Find dot-space files
find / -name '. *' -o -name '.. *' -o -name '...*' 2>/dev/null

# Remove the malicious file
rm '/path/to/. '  # Note the quotes to handle special names
# Or use inode number:
ls -lai /path/to/directory/
find /path/to/directory -inum <inode_number> -delete
```

---

### 3.8 /dev/shm staging area

**Threat**: `/dev/shm` is a world-writable tmpfs (RAM-backed filesystem) that leaves no disk forensics trace. Fileless malware frequently stages payloads here — write executable, run it, delete it. The file only ever exists in RAM. It's also writable by any user and rarely monitored.

**Where to look**:
- `/dev/shm/` — list all contents including hidden files

**What to look for**:
- Executable files (any file with `+x` permission)
- ELF binaries (check for `\x7fELF` magic header) even without `+x`
- Scripts with shebang lines (`#!/bin/sh`, `#!/usr/bin/python`) even without `+x`
- Hidden dotfiles
- Any file owned by root that wasn't created by the system

**Remediation**:
```bash
# Inspect /dev/shm
ls -la /dev/shm/
file /dev/shm/*

# Remove malicious files
rm /dev/shm/payload /dev/shm/.hidden

# Mount /dev/shm with noexec to prevent execution:
sudo mount -o remount,noexec /dev/shm

# Make persistent in /etc/fstab:
# tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0
```

---

### 3.9 File ACL analysis

**Threat**: POSIX ACLs (Access Control Lists) extend standard Unix permissions, allowing fine-grained per-user and per-group access that `ls -l` doesn't show. An attacker can grant themselves read/write access to sensitive files via ACLs while the standard permission display looks normal. A `+` at the end of the permission string (e.g., `drwxr-xr-x+`) indicates ACLs are present.

**Where to look**:
- `getfacl <file>` — display ACLs
- `find / -exec getfacl {} \; 2>/dev/null | grep -B5 'user:[^:]*:rwx'` — find files with non-owner user ACLs

**What to look for**:
- ACLs granting unexpected users access to `/etc/shadow`, `/etc/sudoers`, SSH key directories, cron files
- ACLs on system binaries granting write access to non-root users
- `default:` ACLs on directories (inherited by new files) that are overly permissive
- Any ACL on files that normally have none — `ls -l` shows `+` indicator

**Remediation**:
```bash
# Check for ACLs on sensitive files
getfacl /etc/shadow /etc/sudoers /etc/ssh/sshd_config

# Remove all ACLs from a file (restore to base permissions)
setfacl -b /path/to/file

# Remove a specific user's ACL
setfacl -x u:malicious_user /path/to/file
```

---

### 3.10 Extended file attributes (lsattr/chattr)

**Threat**: `chattr` sets filesystem attributes on ext2/3/4 filesystems. The immutable attribute (`+i`) prevents any modification or deletion — even by root — without first removing the attribute. Malware uses this to protect its files from removal. The append-only attribute (`+a`) prevents truncation, which can protect malicious log entries.

**Where to look**:
- `lsattr <file>` — display attributes
- `lsattr -R /etc/ /usr/ /var/` — recursive scan

**What to look for**:
- Immutable bit (`i`) on non-standard files — malware protecting its persistence
- Append-only bit (`a`) on files that shouldn't have it
- Any attribute on files in `/tmp/`, `/dev/shm/`, `/var/tmp/` — these shouldn't have special attributes
- Immutable bit on cron files, shell profiles, or autostart entries — prevents cleanup

**Remediation**:
```bash
# Check attributes
lsattr /path/to/suspicious-file

# Remove immutable bit (requires root)
sudo chattr -i /path/to/file

# Then delete or modify as needed
sudo rm /path/to/file

# Scan for immutable files system-wide
lsattr -R / 2>/dev/null | grep -- '----i'
```

---

### 3.11 Known rootkit artifact paths

**Threat**: Known rootkits install specific files and directories at predictable locations. While sophisticated rootkits customize their installation, commodity rootkits (SHV, Adore, knark, Diamorphine, Reptile, Jynx) use default paths that have been catalogued.

**Where to look**:
- A curated list of ~200 known paths. Key examples:
  - `/dev/.hid`, `/dev/.blkp`, `/dev/ptyxx` — SHV rootkit
  - `/usr/lib/libproc.a` — process-hiding library
  - `/usr/share/.hid`, `/usr/share/locale/en_XX/` — Adore-ng
  - `/lib/modules/<kernel>/kernel/drivers/.hide/` — kernel module hiding
  - `/etc/ld.so.hash` — fake linker cache
  - `/dev/shm/.x` — generic staging

**What to look for**:
- Exact path matches from a known-rootkit database (rkhunter uses ~400 path checks)
- Files in `/dev/` that are regular files (not device nodes) — `/dev/` should only contain device nodes, not regular files
- Hidden directories under `/usr/share/`, `/usr/lib/`, `/lib/modules/`
- Files in kernel module directories that don't match any installed kernel module package

**Remediation**:
```bash
# Check for known rootkit artifacts
for path in /dev/.hid /dev/.blkp /usr/lib/libproc.a /usr/share/.hid; do
    [ -e "$path" ] && echo "FOUND: $path"
done

# If a rootkit is confirmed:
# 1. DO NOT trust any command on the compromised system — the rootkit may hook them
# 2. Boot from trusted media (live USB) for forensic analysis
# 3. Reinstall the operating system from known-good media
# 4. Restore data from pre-compromise backups
# 5. Investigate the initial access vector before reconnecting to network

# For preliminary investigation from the running system (unreliable if rootkit is active):
rkhunter --check
chkrootkit
```

---

### 3.12 Full filesystem hash database (AIDE/Tripwire-style)

**Threat**: Package integrity tools (`debsums`) only cover files installed by packages. Configuration files, manually-placed scripts, cron jobs, SSH authorized_keys, and other non-packaged files are invisible to package verification. A comprehensive hash database covers everything.

**Where to look**:
- Critical directories: `/etc/`, `/usr/bin/`, `/usr/sbin/`, `/bin/`, `/sbin/`, `/usr/lib/`, `/lib/`, `/boot/`
- Home directory sensitive files: `~/.ssh/authorized_keys`, `~/.bashrc`
- Cron directories: `/etc/cron.d/`, `/var/spool/cron/`

**What to look for**:
- Any file whose hash differs from the stored baseline
- New files that didn't exist in the baseline
- Deleted files that should still exist
- Permission or ownership changes

**Remediation**:
```bash
# Initialize a database (using AIDE as example)
sudo aide --init
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Check against baseline
sudo aide --check

# After legitimate changes (package upgrades, config edits):
sudo aide --update
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# For manual approach without AIDE:
# Generate baseline:
find /etc /usr/bin /usr/sbin -type f -exec sha256sum {} \; > /root/baseline.sha256
# Check later:
sha256sum -c /root/baseline.sha256 2>/dev/null | grep FAILED
```

---

### 3.13 Credential file permission exposure

**Threat**: Credential files (.env, private keys, config files with embedded passwords) that are world-readable or group-readable by unintended groups allow any local user — or any compromised process — to harvest credentials without privilege escalation. This is one of the most common misconfigurations and a frequent finding in penetration tests.

**Where to look**:
- `~/.env`, project directories containing `.env` files
- `~/.ssh/id_*`, `~/.ssh/*.pem` — SSH private keys
- `~/.aws/credentials`, `~/.config/gcloud/credentials.db` — cloud provider credentials
- `/etc/shadow` (should be 640 root:shadow), `/etc/gshadow`
- Application config files: `wp-config.php`, `settings.py`, `database.yml`, `*.secret.*`
- `/etc/ssl/private/` — TLS private keys

**What to look for**:
- Files with permissions more open than 600 (owner-only) containing secrets
- Private keys readable by group or others: `find / -name '*.pem' -o -name '*.key' -o -name 'id_*' | xargs stat -c '%a %U %G %n' | grep -v '^600'`
- `.env` files with world-readable permissions
- `/etc/shadow` with permissions other than 640
- Credential files owned by unexpected users or groups
- Key files without restrictive permissions that SSH/TLS would normally reject (SSH enforces 600, but leaked copies may not)

**Remediation**:
```bash
# Find credential files with overly permissive access
find /home /root /etc -type f \( -name '.env' -o -name '*.pem' -o -name '*.key' -o -name 'id_*' -o -name 'credentials*' \) -perm /o+r 2>/dev/null

# Fix permissions on private keys
chmod 600 ~/.ssh/id_*
chmod 600 ~/.aws/credentials

# Fix .env files
find /home -name '.env' -exec chmod 600 {} \;

# Verify /etc/shadow permissions
chmod 640 /etc/shadow
chown root:shadow /etc/shadow
```

---

## 4. Kernel-level (rootkits)

### 4.1 Suspicious kernel module name matching

**Threat**: Kernel modules run with full kernel privileges — they can hide processes, files, network connections, and intercept any syscall. Modules with names suggesting surveillance or rootkit functionality indicate compromise at the deepest level.

**Where to look**:
- `/proc/modules` — currently loaded modules
- `/sys/module/*/` — sysfs module entries

**What to look for**:
- Module names containing: `keylog`, `spy`, `hook`, `rootkit`, `hide`, `stealth`, `sniff`, `intercept`, `backdoor`
- Modules you don't recognize — compare against a known-good list for your kernel and hardware
- Modules loaded recently that don't correspond to hardware changes or package installs

**Remediation**:
```bash
# List loaded modules
lsmod

# Get info about a suspicious module
modinfo <module_name>

# Unload the module
sudo rmmod <module_name>

# Blacklist to prevent re-loading
echo "blacklist <module_name>" | sudo tee /etc/modprobe.d/blacklist-suspicious.conf
echo "install <module_name> /bin/false" | sudo tee -a /etc/modprobe.d/blacklist-suspicious.conf

# WARNING: a rootkit module may hook rmmod to prevent its own unloading.
# If rmmod fails, you need to boot from trusted media.
```

---

### 4.2 Out-of-tree / unsigned module detection

**Threat**: Legitimate kernel modules are built with the kernel and signed by the distribution's key. Out-of-tree modules (compiled separately) and unsigned modules are either third-party drivers or potentially malicious. Secure Boot with module signing enforcement blocks unsigned modules, but many systems don't enforce this.

**Where to look**:
- `/sys/module/<name>/taint` — per-module taint flags
  - `O` = out-of-tree
  - `E` = unsigned

**What to look for**:
- Modules with `O` (out-of-tree) flag — not part of the kernel source tree
- Modules with `E` (unsigned) flag — no valid signature
- Expected out-of-tree modules: NVIDIA drivers, VirtualBox guest additions, ZFS, DKMS-built modules. Anything else is suspicious.
- Cross-reference with `dkms status` to identify known third-party modules

**Remediation**:
```bash
# Check module taint flags
for mod in /sys/module/*/; do
    taint="$(cat ${mod}taint 2>/dev/null)"
    [ -n "$taint" ] && echo "$(basename $mod): taint=$taint"
done

# Unload and blacklist unauthorized modules
sudo rmmod <module>
echo "blacklist <module>" | sudo tee /etc/modprobe.d/blacklist-unsigned.conf

# Enable Secure Boot module signing enforcement
# Check current state:
mokutil --sb-state
```

---

### 4.3 Input subsystem module enumeration

**Threat**: Kernel modules in the input subsystem (`uinput`, `evdev`, `hid`) have legitimate roles in handling keyboards, mice, and other input devices. However, a malicious module registered as an input handler can intercept keystrokes before they reach userspace — a kernel-level keylogger.

**Where to look**:
- `/proc/modules` — filter for `uinput`, `evdev`, `hid*`, `keyboard`, `input`
- `/sys/class/input/` — registered input devices

**What to look for**:
- `uinput` module loaded when no application should need virtual input devices
- Unknown HID modules
- Input devices in `/sys/class/input/` with unfamiliar names
- More input event devices than physical input devices would explain

**Remediation**:
```bash
# List input-related modules
lsmod | grep -iE 'input|hid|evdev|uinput|keyboard'

# List registered input devices
cat /proc/bus/input/devices

# Unload uinput if not needed
sudo rmmod uinput
echo "blacklist uinput" | sudo tee /etc/modprobe.d/blacklist-uinput.conf
```

---

### 4.4 /proc/modules vs /sys/module/ cross-verification

**Threat**: A rootkit that hooks procfs can hide its module from `/proc/modules` (what `lsmod` reads). A rootkit that hooks sysfs can hide from `/sys/module/`. But hooking **both** independently is harder and less common. Comparing the two lists reveals modules that are hiding from one source but visible in the other.

**Where to look**:
- `/proc/modules` — procfs module list
- `/sys/module/*/` — sysfs module directories

**What to look for**:
- Modules in `/sys/module/` that don't appear in `/proc/modules` (excluding built-in modules which have no `refcnt` file)
- Modules in `/proc/modules` that have no corresponding `/sys/module/` directory
- Either discrepancy is a strong rootkit indicator

**Remediation**:
```bash
# Cross-check (exclude built-in modules — they have no refcnt in sysfs)
for mod in /sys/module/*/; do
    name=$(basename "$mod")
    if [ -f "${mod}refcnt" ] && ! grep -q "^${name} " /proc/modules; then
        echo "HIDDEN from /proc/modules: $name"
    fi
done

# If discrepancy found: this system is likely rootkitted.
# Boot from trusted media for forensic analysis.
# Reinstall the operating system.
```

---

### 4.5 Syscall table integrity

**Threat**: Rootkits can hook syscalls by modifying the syscall table, using kprobes, or inserting function trampolines. Hooked syscalls allow the rootkit to filter any data before userspace sees it — hiding processes from `getdents()`, hiding files from `stat()`, hiding connections from `recvmsg()`.

**Where to look**:
- `/sys/kernel/debug/kprobes/list` — active kprobes (requires debugfs mounted)
- `/sys/kernel/debug/tracing/kprobe_events` — kprobe tracepoints

**What to look for**:
- Kprobes on sensitive functions: `sys_getdents`, `sys_read`, `sys_write`, `tcp4_seq_show`, `vfs_read`
- Any kprobe that wasn't registered by a known legitimate module (systemtap, perf, BCC tools)
- Unexpected number of active kprobes

**Remediation**:
```bash
# Check if debugfs is mounted
mount | grep debugfs
# Mount if needed:
sudo mount -t debugfs none /sys/kernel/debug

# List active kprobes
cat /sys/kernel/debug/kprobes/list

# If suspicious hooks found:
# The hooking module must be identified and removed
# Check which module registered the kprobe:
# This is difficult from a compromised system — boot from trusted media
```

---

### 4.6 eBPF program enumeration

**Threat**: eBPF (extended Berkeley Packet Filter) programs run in the kernel with nearly full visibility into system operations. A malicious eBPF program attached to a syscall tracepoint can intercept and modify data, hide network connections, capture keystrokes, or exfiltrate data. eBPF programs are verified by the kernel but can still be used maliciously.

**Where to look**:
- `/sys/fs/bpf/` — pinned BPF objects
- `bpftool prog list` — loaded BPF programs (if bpftool available)
- `/sys/kernel/debug/tracing/events/` — active tracepoints

**What to look for**:
- BPF programs attached to syscall tracepoints (`sys_enter_*`, `sys_exit_*`)
- Programs of type `kprobe`, `tracepoint`, or `raw_tracepoint` on sensitive functions
- Pinned BPF programs in `/sys/fs/bpf/` that aren't from known tools
- BPF programs loaded by processes that aren't known BPF toolkits (bcc, bpftrace, cilium, falco)

**Remediation**:
```bash
# List BPF programs (requires bpftool)
sudo bpftool prog list

# Show details of a specific program
sudo bpftool prog show id <id>

# Identify the process that loaded it
sudo bpftool prog show id <id> | grep pids

# Remove a pinned BPF object
sudo rm /sys/fs/bpf/malicious_prog

# Restrict unprivileged BPF:
echo 1 | sudo tee /proc/sys/kernel/unprivileged_bpf_disabled
# Make persistent:
echo "kernel.unprivileged_bpf_disabled = 1" | sudo tee /etc/sysctl.d/99-bpf.conf
```

---

### 4.7 DKMS third-party module persistence

**Threat**: DKMS (Dynamic Kernel Module Support) automatically rebuilds kernel modules when the kernel is upgraded. A malicious module registered with DKMS persists across kernel updates — it gets rebuilt and re-installed automatically with every new kernel version.

**Where to look**:
- `/var/lib/dkms/` — DKMS module source trees
- `dkms status` — installed DKMS modules

**What to look for**:
- Modules in `/var/lib/dkms/` that aren't from known-legitimate packages (NVIDIA, VirtualBox, ZFS, WireGuard, broadcom-sta)
- Recently added DKMS modules: `ls -lt /var/lib/dkms/`
- Module source code in the DKMS tree — inspect `dkms.conf` and the source files

**Remediation**:
```bash
# List DKMS modules
dkms status

# Inspect a suspicious module's source
cat /var/lib/dkms/<module>/<version>/source/dkms.conf
ls /var/lib/dkms/<module>/<version>/source/

# Remove a DKMS module
sudo dkms remove <module>/<version> --all
sudo rm -rf /var/lib/dkms/<module>/

# Unload the currently running module
sudo rmmod <module>
```

---

### 4.8 Kernel taint bitmask decoding

**Threat**: The kernel taint state (`/proc/sys/kernel/tainted`) is a bitmask that records events compromising kernel integrity. Non-zero taint means something unusual has happened — proprietary module loaded, module force-loaded, unsigned module loaded, machine check exception, etc. While a tainted kernel isn't necessarily compromised, it indicates the kernel's integrity guarantees have been weakened.

**Where to look**:
- `/proc/sys/kernel/tainted` — system-wide taint bitmask
- `/sys/module/<name>/taint` — per-module taint

**What to look for**:
- Value `0` = clean kernel (ideal)
- Key bits: `0` = proprietary module, `12` = unsigned module, `13` = out-of-tree module, `15` = live-patched
- Unexpected bits set — especially on systems that should only run signed, in-tree modules
- Taint appearing at a time that doesn't correlate with legitimate module loads

**Remediation**:
```bash
# Decode the taint value
taint=$(cat /proc/sys/kernel/tainted)
echo "Taint value: $taint"
# Decode bits:
# 0=proprietary, 1=force-loaded, 2=unsafe SMP, 4=force-unloaded
# 12=unsigned, 13=out-of-tree, 15=live-patched

# Identify which modules caused the taint
for mod in /sys/module/*/; do
    t=$(cat ${mod}taint 2>/dev/null)
    [ -n "$t" ] && echo "$(basename $mod): $t"
done

# Taint cannot be cleared without reboot (by design).
# Address the source: remove/blacklist the offending modules, then reboot.
```

---

## 5. Network-level indicators

### 5.1 TCP listener enumeration

**Threat**: Every listening TCP port is an attack surface. Services bound to `0.0.0.0` (all interfaces) are exposed to the network. Databases, debug ports, admin panels, and backdoors listening on unexpected ports are common findings.

**Where to look**:
- `/proc/net/tcp` and `/proc/net/tcp6` — TCP socket table (hex-encoded)

**What to look for**:
- State `0A` (LISTEN) with local address `00000000` (0.0.0.0) — exposed to all interfaces
- Known-dangerous ports on 0.0.0.0: 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis), 27017 (MongoDB), 9200 (Elasticsearch)
- Unexpected listening ports — correlate UID field with `/etc/passwd`
- Ports in the high range (>10000) with unknown UIDs — possible backdoor listeners

**Remediation**:
```bash
# On the host, identify listeners with process info:
ss -tlnp

# Bind services to localhost instead of 0.0.0.0:
# MySQL: bind-address = 127.0.0.1 in /etc/mysql/my.cnf
# PostgreSQL: listen_addresses = 'localhost' in postgresql.conf
# Redis: bind 127.0.0.1 in redis.conf

# Or use firewall rules:
sudo nft add rule inet filter input tcp dport 3306 drop
```

---

### 5.2 Established connection analysis with process attribution

**Threat**: Established TCP connections reveal active communication — C2 channels, data exfiltration, lateral movement. Attributing connections to specific processes identifies which software is communicating and whether that communication is expected.

**Where to look**:
- `/proc/net/tcp` — entries with state `01` (ESTABLISHED)
- Socket inode (column 10) → correlate against `/proc/[pid]/fd/` symlinks to identify the owning process

**What to look for**:
- Connections to unusual remote IPs or ports
- Connections from unexpected processes (a web server connecting to IRC ports, a database connecting outbound)
- Connections to known C2 infrastructure IPs (requires threat intelligence feed)
- Multiple established connections from the same process to different external hosts — scan or exfiltration behavior

**Remediation**:
```bash
# On the host:
ss -tnp | grep ESTAB

# Identify suspicious connections and the owning process
# Kill the process if malicious
kill <pid>

# Block the remote IP
sudo nft add rule inet filter output ip daddr <malicious_ip> drop

# Investigate the process — how was it started, what files does it have open
ls -la /proc/<pid>/fd/
cat /proc/<pid>/cmdline | tr '\0' ' '
```

---

### 5.3 Unusual outbound port detection

**Threat**: Legitimate services communicate on well-known ports (80, 443, 53, 22). Connections to unusual ports (IRC: 6667, C2: 4444/5555/8888, high ephemeral ports as destinations) suggest malware communicating with command-and-control infrastructure.

**Where to look**:
- `/proc/net/tcp` — ESTABLISHED connections, check remote port (second hex value in `rem_address`)

**What to look for**:
- Remote ports: 4444, 5555, 6666, 6667 (IRC), 8888, 31337, 1234 — common C2/backdoor ports
- Any connection to a remote port outside the standard set (80, 443, 53, 22, 25, 587, 993, 995) that isn't from a known application
- Connections to remote ports in the 1024-10000 range from unexpected processes

**Remediation**:
```bash
# Identify outbound connections to unusual ports
ss -tnp state established '( not dport = :80 and not dport = :443 and not dport = :53 and not dport = :22 )'

# Kill the process making the suspicious connection
kill <pid>

# Block the remote endpoint
sudo nft add rule inet filter output ip daddr <ip> tcp dport <port> drop

# Implement egress filtering:
# Default-deny outbound, allow only necessary ports
```

---

### 5.4 UDP socket enumeration

**Threat**: UDP sockets are often overlooked in security audits because they don't show up in TCP-focused tools. DNS (53), SNMP (161/162), syslog (514), and NTP (123) use UDP. Malware can use UDP for covert channels, DNS tunneling, or as a lightweight C2 protocol.

**Where to look**:
- `/proc/net/udp` and `/proc/net/udp6`

**What to look for**:
- UDP listeners on `0.0.0.0` that shouldn't be exposed
- SNMP (161) listeners — SNMP v1/v2 with default community strings is a severe vulnerability
- Unexpected UDP sockets from unknown UIDs
- High-port UDP listeners not attributable to known services

**Remediation**:
```bash
# On the host:
ss -ulnp

# Disable unnecessary UDP services
sudo systemctl stop snmpd
sudo systemctl disable snmpd

# Firewall UDP:
sudo nft add rule inet filter input udp dport 161 drop
```

---

### 5.5 Raw socket detection

**Threat**: Raw sockets (`AF_INET` with `SOCK_RAW`) allow direct packet construction and reception, bypassing the kernel's TCP/UDP stack. Almost nothing legitimate needs raw sockets beyond `ping` (ICMP). A raw socket usually means packet sniffing, packet injection, or network-level attacks.

**Where to look**:
- `/proc/net/raw` — raw socket table

**What to look for**:
- Any entry in `/proc/net/raw` — should normally be empty or contain only ICMP sockets from `ping`
- Protocol 6 (TCP) or 17 (UDP) raw sockets — likely a sniffer or injector
- Correlate the socket inode to a process via `/proc/[pid]/fd/`

**Remediation**:
```bash
# Check for raw sockets
cat /proc/net/raw

# Remove CAP_NET_RAW from all non-essential binaries
# Find binaries with this capability:
find / -exec getcap {} \; 2>/dev/null | grep net_raw

# Restrict at the kernel level (disallow non-root raw sockets):
# Most systems already require CAP_NET_RAW
```

---

### 5.6 Packet socket detection

**Threat**: Packet sockets (`AF_PACKET`) operate at layer 2 (Ethernet frame level), providing access to all traffic on the interface including traffic not destined for this host. This is what `tcpdump` and Wireshark use. On a production system, an unexpected packet socket is a sniffer.

**Where to look**:
- `/proc/net/packet` — packet socket table

**What to look for**:
- Any entry — should be empty on systems not actively running diagnostic tools
- Correlate to process: the inode maps to a PID via `/proc/[pid]/fd/`
- Legitimate uses: temporarily running tcpdump for diagnosis, dhclient for DHCP
- Persistent packet sockets from unknown processes — sniffer/exfiltration

**Remediation**:
```bash
# Check for packet sockets
cat /proc/net/packet

# Find the owning process
for pid in /proc/[0-9]*/; do
    ls -la ${pid}fd/ 2>/dev/null | grep "socket:\[$(awk '{print $9}' /proc/net/packet)\]" && echo "PID: $(basename $pid)"
done

# Kill the sniffer
kill <pid>
```

---

### 5.7 DNS exfiltration / tunneling detection

**Threat**: DNS tunneling encodes data in DNS queries (as subdomain labels) and responses (as TXT or other records). Since DNS traffic is almost always allowed through firewalls, it's a reliable covert channel. Data exfiltration, C2 communication, and even full TCP-over-DNS tunnels (iodine, dns2tcp) use this technique.

**Where to look**:
- DNS query logs (if logging is enabled on the local resolver)
- `/var/log/syslog` for dnsmasq/systemd-resolved logs
- Packet capture on port 53

**What to look for**:
- Queries with unusually long subdomain labels (>30 characters) — data encoded as subdomains
- High query volume to a single domain (hundreds of queries/minute to one domain)
- TXT record queries at high frequency — common for DNS tunneling
- Queries for domains with high entropy names (random-looking subdomains)
- DNS traffic to non-standard resolvers (not the configured DNS server)

**Remediation**:
```bash
# Enable DNS query logging (systemd-resolved)
sudo resolvectl log-level debug
journalctl -u systemd-resolved -f

# Check for common DNS tunneling tools
pgrep -af 'iodine|dns2tcp|dnscat|dnscrypt'

# Block DNS to non-authorized resolvers:
sudo nft add rule inet filter output udp dport 53 ip daddr != <your_dns_server> drop
sudo nft add rule inet filter output tcp dport 53 ip daddr != <your_dns_server> drop
```

---

### 5.8 Conntrack / NAT translation analysis

**Threat**: Conntrack (connection tracking) maintains state for NAT'd connections. `/proc/net/nf_conntrack` reveals the true destination of connections going through DNAT/SNAT — a local service might be silently forwarding traffic to an external attacker host via iptables NAT rules. The regular `/proc/net/tcp` shows the translated address, not the real one.

**Where to look**:
- `/proc/net/nf_conntrack` — requires conntrack module loaded and host network namespace access

**What to look for**:
- DNAT entries where the original destination differs from the reply source — traffic is being redirected
- NAT rules forwarding traffic to unexpected external hosts
- Connections that appear local in `/proc/net/tcp` but are actually being NAT'd to remote hosts

**Remediation**:
```bash
# View conntrack table
cat /proc/net/nf_conntrack
# Or use:
sudo conntrack -L

# Check NAT rules
sudo nft list table nat
# Or:
sudo iptables -t nat -L -v -n

# Remove malicious NAT rules
sudo nft delete rule nat <chain> handle <handle>
```

---

### 5.9 Socket inode to PID correlation

**Threat**: This is a detection technique rather than a threat itself. It allows attributing network connections to specific processes when tools like `ss -p` aren't available. Essential for identifying which process owns a suspicious connection.

**Where to look**:
- `/proc/net/tcp` — inode column (column 10)
- `/proc/[pid]/fd/` — symlinks showing `socket:[<inode>]`

**What to look for**:
- Match the inode from the network socket table to a process's file descriptors
- If no process claims the inode, the socket may be from a kernel thread or a process in a different namespace

**Remediation**: N/A — this is a detection technique. On the host:
```bash
# The easy way:
ss -tnp
# Shows process names directly associated with sockets
```

---

### 5.10 C2 / malicious IP reputation matching

**Threat**: Known command-and-control infrastructure uses specific IP addresses that are catalogued by threat intelligence services. Checking established connections against these lists provides an immediate indicator of compromise without needing to understand the malware itself.

**Where to look**:
- `/proc/net/tcp` — remote addresses of ESTABLISHED connections
- Cross-reference against threat intelligence IP lists:
  - Feodo Tracker (abuse.ch) — banking trojan C2 IPs
  - abuse.ch SSL Blacklist — malicious SSL certificate IPs
  - Tor exit node lists — not malicious per se but worth noting
  - Emerging Threats blocklists

**What to look for**:
- Any established connection to an IP on a threat intelligence blocklist
- Connections to IPs in unusual geolocations for the organization's operations
- Connections to IPs with no reverse DNS or with recently registered domains
- Multiple connections to the same suspicious IP from different processes

**Remediation**:
```bash
# Block the C2 IP immediately
sudo nft add rule inet filter output ip daddr <c2_ip> drop

# Kill the connecting process
ss -tnp | grep <c2_ip>
kill <pid>

# Investigate the process:
# - How was it started?
# - What files does it have?
# - What other connections has it made?
# - What data might have been exfiltrated?

# Add the IP to permanent blocklist
echo "<c2_ip>" >> /etc/nftables-blocklist.conf
```

---

### 5.11 Container/Docker escape vectors

**Threat**: A container with access to the Docker socket, running in privileged mode, or with a user in the docker group has an equivalent-to-root escape path to the host. The docker group grants unrestricted daemon access (mount host filesystem, run privileged containers). Cgroup escape techniques allow breaking out of the container namespace entirely.

**Where to look**:
- `/var/run/docker.sock` — Docker socket permissions
- `/etc/group` — docker group membership
- `/proc/1/cgroup` — detect if running inside a container
- `docker inspect` output — privileged flag, capabilities, mounts
- `/proc/self/status` — `CapEff` bitmask showing granted capabilities

**What to look for**:
- Docker socket (`/var/run/docker.sock`) readable/writable by non-root users or groups
- Users in the docker group who shouldn't have unrestricted host access
- Containers running with `--privileged` flag (all capabilities + device access)
- Containers with sensitive host mounts: `/`, `/etc/`, `/var/run/docker.sock`
- Containers with `SYS_ADMIN`, `SYS_PTRACE`, or `DAC_READ_SEARCH` capabilities
- Writable cgroup paths from within containers (`/sys/fs/cgroup/*/release_agent`)

**Remediation**:
```bash
# Check docker socket permissions
ls -la /var/run/docker.sock

# List docker group members
grep docker /etc/group

# Remove unnecessary users from docker group
sudo gpasswd -d <user> docker

# List privileged containers
docker ps -q | xargs docker inspect --format '{{.Name}} privileged={{.HostConfig.Privileged}}'

# List containers with sensitive mounts
docker ps -q | xargs docker inspect --format '{{.Name}} {{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}'

# Use rootless Docker or Podman instead
# https://docs.docker.com/engine/security/rootless/
```

---

## 6. Firmware / hardware

### 6.1 EFI variable inspection

**Threat**: UEFI firmware bootkits persist in EFI System Partition (ESP) boot entries and EFI variables. They execute before the operating system loads, can subvert Secure Boot, and survive OS reinstallation. They are effectively invisible to any tool running from the OS.

**Where to look**:
- `/sys/firmware/efi/efivars/` — EFI variable store
- EFI System Partition (usually `/boot/efi/EFI/`)
- `efibootmgr -v` — boot entries

**What to look for**:
- Boot entries pointing to unexpected binaries in the ESP
- EFI variables with unknown GUIDs
- Modified boot loaders (compare hashes against known-good)
- Files in the ESP that aren't from the OS installer, GRUB, or systemd-boot

**Remediation**:
```bash
# List boot entries
efibootmgr -v

# Check ESP contents
ls -laR /boot/efi/EFI/

# Verify bootloader integrity
sha256sum /boot/efi/EFI/debian/shimx64.efi
# Compare against known-good hash from package

# If compromised: reflash firmware from known-good source, reinstall bootloader
# This requires physical access and manufacturer firmware tools
```

---

### 6.2 UEFI Secure Boot state verification

**Threat**: Secure Boot prevents loading of unsigned boot components. If Secure Boot is unexpectedly disabled, it may indicate an attacker disabling it to load an unsigned bootkit or rootkit kernel module.

**Where to look**:
- `mokutil --sb-state` — Secure Boot status
- `/sys/firmware/efi/efivars/SecureBoot-*` — EFI variable

**What to look for**:
- Secure Boot disabled on a system where it should be enabled
- Enrolled MOK (Machine Owner Keys) that aren't recognized — attacker-enrolled keys allow loading attacker-signed code
- `mokutil --list-enrolled` shows unexpected certificates

**Remediation**:
```bash
# Check Secure Boot state
mokutil --sb-state

# List enrolled keys
mokutil --list-enrolled

# Re-enable Secure Boot (requires BIOS/UEFI access)
# Remove unauthorized MOK keys:
mokutil --delete /path/to/suspicious.der

# Enable kernel module signing enforcement:
# Ensure CONFIG_MODULE_SIG_FORCE=y in kernel config
```

---

### 6.3 BMC/IPMI presence detection

**Threat**: The Baseboard Management Controller (BMC) is a separate computer on the motherboard with its own network interface, operating system, and full access to the host via IPMI. A compromised BMC can read all memory, control power, access the console, and persist through OS reinstallation. BMC firmware is rarely updated and often has vulnerabilities.

**Where to look**:
- `ipmitool lan print` — BMC network configuration
- `ipmitool user list` — BMC user accounts
- `dmidecode -t 38` — IPMI device information

**What to look for**:
- BMC exposed to the general network (should be on a dedicated management VLAN)
- Default credentials still in place
- BMC firmware version with known vulnerabilities
- Unknown user accounts in the BMC
- BMC configured with DHCP on the production network

**Remediation**:
```bash
# Check if IPMI is present and accessible
ipmitool lan print 2>/dev/null

# Change default credentials
ipmitool user set password 2 <new_strong_password>

# Restrict BMC to management network only (requires BIOS/BMC console access)
# Update BMC firmware to latest version from manufacturer

# If BMC compromise suspected:
# Re-flash BMC firmware from known-good source (manufacturer download)
# Reset all BMC credentials
# Verify BMC network isolation
```

---

## 7. Meta-techniques

### 7.1 Baseline diffing

**Threat**: Without a known-good reference point, it's impossible to know what has changed. Baseline diffing captures system state when known-clean, then compares future state against it to detect additions, modifications, and deletions.

**Where to look**:
- All system state sources: network listeners, users, packages, kernel params, cron jobs, SUID binaries, services, firewall rules, auth logs

**What to look for**:
- New listening ports, new users, new cron jobs, new SUID binaries — anything that appeared since baseline
- Changed configurations — weakened security settings, modified service files
- Missing items — deleted security controls, removed firewall rules

**Remediation**: The baseline itself is the tool. Keep it fresh — rebaseline after legitimate changes (package upgrades, configuration changes). Investigate all unexplained deltas.

---

### 7.2 Cross-source verification

**Threat**: Rootkits and sophisticated malware hide from specific data sources. A rootkit hooking `getdents()` hides from `ls` but might be visible in `/proc`. Cross-checking the same data from multiple sources reveals inconsistencies that indicate tampering.

**Where to look**:
- Compare `/proc/modules` against `/sys/module/`
- Compare `/proc/net/tcp` against `ss` output
- Compare `ps` against `/proc/[pid]/` directory listing
- Compare package file list against actual filesystem

**What to look for**:
- Any discrepancy between two sources that should show the same data
- Processes visible in `/proc/` but not in `ps` (or vice versa)
- Modules in sysfs but not procfs
- Files on disk that the package manager doesn't know about (in package directories)

**Remediation**: Discrepancies indicate active tampering. Do not trust the compromised system. Boot from trusted media for forensic analysis.

---

### 7.3 Behavioral analysis

**Threat**: Name-based detection is easily evaded by renaming binaries. Behavioral analysis looks at what a process **does** — what files it opens, what sockets it holds, what devices it reads, what syscalls it makes — rather than what it's called.

**Where to look**:
- `/proc/[pid]/fd/` — open file descriptors (files, sockets, devices)
- `/proc/[pid]/maps` — loaded libraries and memory regions
- `/proc/[pid]/net/` — per-process network namespace view
- `/proc/[pid]/status` — capabilities, UID, TracerPid
- `strace -p <pid>` — live syscall tracing (intrusive)

**What to look for**:
- Processes with open sockets that shouldn't have network access
- Processes reading `/dev/input/` that aren't display servers
- Processes with raw/packet sockets that aren't network tools
- Processes reading sensitive files (shadow, SSH keys, browser credential stores)
- Processes with capabilities they shouldn't have

**Remediation**: Kill the process, remove its binary, investigate how it was started, close the vulnerability that allowed it.

---

### 7.4 Entropy analysis of suspicious binaries

**Threat**: Packed, encrypted, or compressed executables have abnormally high entropy (close to 8.0 bits/byte = maximum randomness). Legitimate binaries have mixed entropy (code sections ~6.0, data sections vary). High overall entropy is a packing indicator — packers like UPX are used to evade signature-based detection.

**Where to look**:
- Any executable binary, especially those flagged by other checks (unknown, in unusual locations, recently appeared)

**What to look for**:
- Overall file entropy >7.0 bits/byte — likely packed or encrypted
- Specific section entropy: `.text` section >7.0 is very suspicious
- UPX magic bytes (`UPX!`) — common packer
- Very small `.text` section relative to file size — packer stub
- Few meaningful strings in a large binary — encrypted payload

**Remediation**:
```bash
# Calculate entropy (using ent or custom script)
ent /path/to/suspicious-binary

# Check for UPX packing
strings /path/to/binary | grep UPX
# Unpack:
upx -d /path/to/binary -o /tmp/unpacked

# Submit hash to VirusTotal or other scanning service
sha256sum /path/to/suspicious-binary

# Remove the binary
rm /path/to/suspicious-binary
```

---

### 7.5 Package integrity verification

**Threat**: The most impactful persistence technique is replacing a system binary with a trojanized version. It runs as root, survives reboots, and hides in plain sight. Package managers store checksums of installed files — comparing current files against these checksums detects tampering.

**Where to look**:
- `/var/lib/dpkg/info/*.md5sums` — Debian/Ubuntu stored checksums
- `rpm -Va` — Red Hat/Fedora verification

**What to look for**:
- Files whose current hash differs from the stored hash — the binary on disk isn't what was installed
- Missing binaries or libraries — files that should exist but don't
- Focus on security-critical packages: coreutils, bash, sudo, openssh, pam, openssl, systemd, apt, dpkg

**Remediation**:
```bash
# Debian/Ubuntu:
debsums -c                    # Check all packages, show only changed files
debsums -c <package>          # Check specific package

# If files are modified:
sudo apt-get install --reinstall <package>

# Red Hat:
rpm -Va                       # Verify all packages
sudo yum reinstall <package>

# IMPORTANT: if system binaries are trojanized, apt/dpkg themselves may be compromised.
# Verify from trusted media or compare hashes against a known-good system.
```

---

### 7.6 Offline / external analysis

**Threat**: Any tool running on a compromised system can be subverted by the compromise itself — the rootkit can hook the tool's syscalls, modify its output, or hide from it. The only way to fully trust analysis is to run it from a known-clean environment on the same disk.

**Where to look**:
- Boot from a live USB/CD of a trusted Linux distribution
- Mount the target disk read-only
- Run analysis tools from the live environment

**What to look for**:
- Everything you'd normally check, but from outside the potentially compromised OS
- Files that were hidden by rootkit hooks now become visible
- Binary integrity checks against known-good package repositories

**Remediation**: If offline analysis reveals rootkit presence, reinstall the operating system from trusted media. Do not attempt to "clean" a rootkitted system.

---

### 7.7 YARA / content-based signature scanning

**Threat**: Hash-based detection (SHA256 exact match) only catches known-exact samples. A single byte change — recompilation, different configuration, different encryption key — produces a different hash. YARA rules match on file content patterns (strings, byte sequences, structure), catching entire malware families and variants.

**Where to look**:
- Any file on the system, with focus on: executables, scripts, documents, archives in user directories
- Process memory (YARA can scan `/proc/[pid]/mem`)

**What to look for**:
- Rule matches from community rulesets: Florian Roth's signature-base, YARA-Rules project, Elastic YARA rules
- Patterns specific to known malware families (unique strings, code sequences, configuration structures)
- Generic suspicious patterns: shellcode, packer signatures, obfuscation techniques

**Remediation**:
```bash
# Scan a file
yara /path/to/rules.yar /path/to/suspicious-file

# Scan a directory recursively
yara -r /path/to/rules.yar /path/to/scan/

# Scan process memory
yara /path/to/rules.yar /proc/<pid>/mem

# Remove matched malware
rm /path/to/matched-file

# Keep YARA rules updated:
# Clone community rulesets and update regularly
git pull https://github.com/Yara-Rules/rules
```

---

### 7.8 Structured log parsing and correlation

**Threat**: Individual log entries tell partial stories. Correlation across multiple log sources reveals attack chains: a failed SSH brute-force followed by a successful login, then a new cron job, then an outbound connection to a C2 server. Without structured parsing and correlation, these events appear unrelated.

**Where to look**:
- `/var/log/auth.log` — authentication events
- `/var/log/syslog` — general system events
- `/var/log/kern.log` — kernel messages (module loads, network events)
- `/var/log/dpkg.log` — package operations
- `/var/log/apt/history.log` — apt operations
- `journalctl` — systemd journal (structured)
- Application-specific logs: `/var/log/apache2/`, `/var/log/nginx/`, etc.

**What to look for**:
- **Brute force → success**: Multiple `Failed password` followed by `Accepted password/publickey` from same IP
- **Privilege escalation chain**: Normal user login → `sudo` to root → service modification
- **Persistence installation**: Package install or file modification → new service enabled → new listener
- **Lateral movement**: Inbound SSH → outbound SSH to other internal hosts
- **Data staging**: Large file operations followed by outbound network connections

**Remediation**: Correlation findings indicate compound attacks. Address each stage:
```bash
# Block the attack source
sudo nft add rule inet filter input ip saddr <attacker_ip> drop

# Revoke compromised credentials
sudo passwd -l <compromised_user>
# Remove their SSH keys:
rm ~<user>/.ssh/authorized_keys

# Remove persistence installed by the attacker
# (cron jobs, services, autostart entries — use the relevant technique-specific remediation)

# Review all changes made during the attack window
```

---

### 7.9 Dynamic analysis / sandboxed execution

**Threat**: Static analysis (reading file content, metadata, strings) cannot reveal what a program **does** when executed. Encrypted payloads, time-delayed detonation, environment-aware malware (only activates on specific systems), and multi-stage droppers all evade static analysis. Dynamic analysis executes the file in a controlled environment and monitors its behavior.

**Where to look**:
- Execute the suspicious file in an isolated VM or container
- Monitor: syscalls (strace), network connections, filesystem modifications, process creation, registry/config changes

**What to look for**:
- Network connections to unknown hosts — C2 communication
- File creation in persistence locations (cron, autostart, systemd, shell profiles)
- Privilege escalation attempts
- Data collection (reading browser stores, SSH keys, /etc/shadow)
- Anti-analysis behavior: VM detection, debugger detection, sleep timers

**Remediation**: Dynamic analysis is a detection technique, not a direct remediation. If the file is confirmed malicious:
```bash
# Remove the file
rm /path/to/malicious-file

# Check if it was already executed on production:
# Look for IoCs identified during dynamic analysis
# (C2 IPs, dropped files, created services, modified configs)
```

---

## 8. Operational capabilities

### 8.1 Real-time event hooks (eBPF / auditd / fanotify)

**Threat**: Polling-based detection has a blind spot between polls. An attacker who can act and clean up within the poll interval (5 seconds to 30 minutes) evades detection entirely. Real-time hooks trigger on the event itself — process execution, file modification, network connection — with no window of opportunity.

**Where to look**:
- `auditd` — kernel audit framework, logs syscalls
- `fanotify` — filesystem notification API (used by real-time FIM)
- eBPF — programmable kernel hooks

**What to look for** (when implementing):
- `execve` syscalls — every process execution
- File modifications in sensitive directories
- Network `connect()` calls to external hosts
- `init_module` / `finit_module` — kernel module loads
- `ptrace` calls — process tracing/injection

**Remediation**: This is an infrastructure capability. Implementation:
```bash
# Enable auditd with rules for critical events
sudo apt-get install auditd

# Example audit rules:
sudo auditctl -a always,exit -F arch=b64 -S execve -k exec_log
sudo auditctl -w /etc/passwd -p wa -k passwd_changes
sudo auditctl -w /etc/shadow -p wa -k shadow_changes
sudo auditctl -a always,exit -F arch=b64 -S init_module -k module_load

# Save rules permanently
sudo auditctl -l > /etc/audit/rules.d/secy.rules
```

---

### 8.2 Alerting / notification

**Threat**: Findings written to files are useless if nobody reads them. The latency between detection and human awareness determines how much damage an attacker can do before response begins.

**Where to look**: N/A — this is about sending notifications when findings are generated.

**What to look for** (when implementing):
- CRITICAL findings should trigger immediate notification
- WARNING findings should be batched and sent periodically
- INFO findings should be available in reports but not alert

**Remediation** (implementation approaches):
```bash
# Webhook notification (Slack, Discord, generic)
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"CRITICAL: Known malware detected in Downloads"}' \
  https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Desktop notification (if running on desktop)
notify-send -u critical "secy" "Malware detected in Downloads"

# Email
echo "CRITICAL finding detected" | mail -s "secy alert" admin@example.com

# Syslog forwarding (to SIEM)
logger -p auth.crit "secy: known malware hash match in /home/user/Downloads/payload.bin"
```

---

### 8.3 Quarantine / automated response

**Threat**: Detection without response is observation without action. The time between detecting malware and removing it is time the malware is active — exfiltrating data, spreading, or escalating privileges.

**Where to look**: N/A — this is about taking action on findings.

**What to look for** (response actions by severity):
- **CRITICAL (known malware hash match)**: Move to quarantine directory, notify immediately
- **CRITICAL (active C2 connection)**: Block the IP, kill the process, notify
- **WARNING (suspicious file)**: Flag for human review, do not auto-delete
- **WARNING (weak configuration)**: Generate remediation script for human approval

**Remediation** (implementation concepts):
```bash
# Quarantine a file (move, remove execute permission, record metadata)
mkdir -p /var/quarantine
mv /path/to/malware /var/quarantine/$(date +%s)-$(basename /path/to/malware)
chmod 000 /var/quarantine/*

# Kill a malicious process
kill -9 <pid>

# Block a C2 IP
nft add rule inet filter output ip daddr <ip> drop

# NOTE: automated response requires write access to the host.
# secy's read-only design prevents this intentionally.
# A host-side agent component would be needed.
```

---

### 8.4 Automatic signature/DB updates

**Threat**: Threat databases age rapidly. New malware samples appear daily. A hash database frozen at build time becomes less effective every day. Automatic updates keep detection current without manual intervention.

**Where to look**: N/A — this is about keeping detection data fresh.

**What to look for** (update sources):
- MalwareBazaar SHA256 full export (daily refresh)
- YARA rule repositories (weekly refresh)
- C2 IP blocklists (daily refresh)
- Known rootkit artifact lists (monthly refresh)

**Remediation** (implementation approaches):
```bash
# Download fresh hash DB to state volume (avoids image rebuild)
curl -sSL https://bazaar.abuse.ch/export/txt/sha256/full/ \
  | grep -E '^[0-9a-f]{64}$' \
  | sort > /var/lib/secy/state/malware-sha256.txt

# Update YARA rules
cd /var/lib/secy/state/yara-rules && git pull

# Schedule via cron or systemd timer on the host
# 0 4 * * * docker compose run --rm secy update-db
```

---

### 8.5 Compliance benchmarking (CIS/STIG scoring)

**Threat**: Without a formal benchmark, there's no objective measure of security posture and no way to track improvement over time. Compliance frameworks provide structured, numbered controls that map to specific audit checks.

**Where to look**:
- CIS Benchmark for Debian/Ubuntu/RHEL — hundreds of specific checks
- DISA STIG — Department of Defense hardening standard
- PCI-DSS — payment card industry requirements

**What to look for** (key CIS checks for Linux):
- Filesystem configuration (separate partitions, mount options, sticky bits)
- Software updates (automatic security updates enabled)
- Secure Boot, ASLR, ptrace scope, core dumps restricted
- Service hardening (unnecessary services disabled, NTP configured)
- Network configuration (IP forwarding, ICMP redirects, TCP wrappers)
- Logging and auditing (auditd configured, log permissions correct)
- Authentication (password policy, account lockout, SSH hardening)
- File permissions (critical file ownership, SUID audit)

**Remediation**: Use a scanning tool that maps to the benchmark:
```bash
# Lynis — open-source CIS-style auditing
sudo lynis audit system
# Produces a hardening index (0-100) and numbered findings

# OpenSCAP — formal SCAP scanning
oscap xccdf eval --profile cis --report report.html /path/to/benchmark.xml

# Track score over time — run monthly, graph the hardening index
```

---

### 8.6 Multi-host / centralized management

**Threat**: Attackers move laterally. Compromising one host is often a stepping stone to others. Without fleet-wide visibility, compromise of one system doesn't trigger investigation of others. Cross-host correlation (same malware hash on multiple hosts, same C2 IP contacted from different systems) is invisible.

**Where to look**: N/A — this is an architectural capability.

**What to look for** (when implementing):
- Shared indicators: same malware hash detected on multiple hosts
- Lateral movement: SSH connections between internal hosts followed by similar compromise indicators
- Common vulnerability: multiple hosts with the same weak configuration
- Timeline correlation: events on different hosts at similar times suggesting coordinated attack

**Remediation** (architecture options):
- **Wazuh model**: Server collects agent data, applies correlation rules, sends alerts
- **osquery + FleetDM model**: SQL-based queries pushed to fleet, results aggregated centrally
- **SIEM model**: Forward logs/findings to Elasticsearch/Splunk, build dashboards and correlation rules
- **Minimal model**: Each host pushes findings to a shared location (S3, NFS), a central script scans for cross-host patterns

---

## 9. Credential and secret exposure

### 9.1 Credentials in process environment

**Threat**: Environment variables are a common way to pass secrets to applications (12-factor app pattern). Every process's environment is readable via `/proc/[pid]/environ` by the same UID (or root). A compromised low-privilege process can harvest API keys, database passwords, and cloud tokens from other processes running as the same user.

**Where to look**:
- `/proc/[pid]/environ` — NUL-delimited environment variables for each process
- `/proc/[pid]/status` — UID to determine which user owns the process

**What to look for**:
- Variables matching credential patterns: `*_KEY=`, `*_SECRET=`, `*_PASSWORD=`, `*_TOKEN=`, `*_CREDENTIAL=`
- Specific high-value variables: `AWS_SECRET_ACCESS_KEY`, `DATABASE_URL` (with embedded password), `GITHUB_TOKEN`, `STRIPE_SECRET_KEY`, `OPENAI_API_KEY`
- Variables with base64-encoded values (may be encoded credentials)
- Long-running processes (daemons, web servers) with credentials in their environment — these are exposed for the lifetime of the process

**Remediation**:
```bash
# Audit what credentials are exposed in process environments
for pid in /proc/[0-9]*/environ; do
    strings "$pid" 2>/dev/null | grep -iE 'password|secret|token|key|credential' && echo "^^^ PID: $(echo $pid | cut -d/ -f3)"
done

# Use secret management instead of environment variables:
# - HashiCorp Vault, AWS Secrets Manager, systemd LoadCredential=
# - Pass secrets via files with restrictive permissions (600)
# - Use systemd's EnvironmentFile= with restricted permissions

# If you must use env vars, clear them after reading:
# In application code: os.environ.pop('SECRET_KEY') after startup
```

---

### 9.2 Credentials in process command line

**Threat**: Passwords and tokens passed as command-line arguments are visible to every user on the system via `ps aux` or `/proc/[pid]/cmdline`. Unlike environment variables (readable only by same UID), command lines are world-readable. This is a well-known anti-pattern but remains common.

**Where to look**:
- `/proc/[pid]/cmdline` — NUL-delimited command line for each process
- `ps auxww` — full command lines of all processes

**What to look for**:
- Arguments matching: `-p <password>`, `--password=`, `--token=`, `--secret=`, `--api-key=`
- MySQL/PostgreSQL connection strings with embedded passwords: `mysql -u root -p<password>`
- curl commands with authentication: `curl -u user:password`, `curl -H 'Authorization: Bearer <token>'`
- SSH/SCP with password arguments (sshpass)
- Base64-encoded strings in arguments that decode to credentials

**Remediation**:
```bash
# Find processes with credential-like arguments
ps auxww | grep -iE 'password|passwd|secret|token|apikey|api-key' | grep -v grep

# Use configuration files or environment variables instead:
# MySQL: use ~/.my.cnf with [client] section
# curl: use .netrc or --netrc-file
# General: use credential files with 600 permissions

# For MySQL specifically:
# Instead of: mysql -u root -pMyPassword
# Use: mysql --defaults-file=/root/.my.cnf
```

---

### 9.3 Swap/core dump credential leakage

**Threat**: Process memory containing credentials can be written to disk via swap or core dumps. Swap is typically unencrypted, meaning any secret held in memory (decrypted passwords, session tokens, private keys) can be recovered from the swap partition. Core dumps capture full process memory and may be stored in world-readable locations.

**Where to look**:
- `/proc/sys/fs/suid_dumpable` — controls whether setuid processes dump core (0=disabled, 2=suidsafe)
- `/proc/sys/kernel/core_pattern` — where core dumps are written (may include `|` for pipe to collector)
- `/etc/security/limits.conf` — core file size limits
- `swapon --show` or `/proc/swaps` — active swap devices
- `/etc/fstab` — swap partition configuration (check if encrypted)
- `/var/crash/`, `/var/lib/systemd/coredump/` — stored core dumps

**What to look for**:
- `suid_dumpable` set to 1 (full dumps of privileged processes) — should be 0 or 2
- `core_pattern` writing to world-readable directories
- Existing core dumps containing sensitive data: `strings /var/crash/*.crash | grep -i password`
- Unencrypted swap partitions (no dm-crypt/LUKS layer)
- No `mlock()` usage by security-sensitive applications (allows secrets to be swapped out)

**Remediation**:
```bash
# Disable core dumps for setuid binaries
echo 0 > /proc/sys/fs/suid_dumpable
echo 'fs.suid_dumpable = 0' >> /etc/sysctl.d/99-security.conf

# Restrict core dumps
echo '* hard core 0' >> /etc/security/limits.conf

# Clean up existing core dumps
rm -f /var/crash/*.crash
rm -f /var/lib/systemd/coredump/core.*

# Encrypt swap (if not already)
# Use LUKS-encrypted swap or zram (compressed in-memory swap)
```

---

## 10. Privilege escalation misconfigurations

### 10.1 Sudo NOPASSWD with GTFOBins

**Threat**: Sudo rules with `NOPASSWD` allow command execution as root without authentication. When the allowed command is a GTFOBins candidate (vim, find, python, less, awk, etc.), the user can trivially escape to a root shell. This is one of the most common privilege escalation paths in CTFs and real-world compromises.

**Where to look**:
- `/etc/sudoers` — main sudoers file
- `/etc/sudoers.d/*` — drop-in sudoers files
- `sudo -l` — effective rules for the current user

**What to look for**:
- `NOPASSWD` entries for interactive programs: `vim`, `vi`, `nano`, `less`, `more`, `man`
- `NOPASSWD` entries for interpreters: `python`, `python3`, `perl`, `ruby`, `node`, `lua`
- `NOPASSWD` entries for file utilities with exec: `find` (with -exec), `awk`, `nmap` (interactive mode)
- `NOPASSWD` entries for package managers: `apt`, `pip`, `gem` (can run arbitrary code during install)
- `NOPASSWD: ALL` — unrestricted root access without password
- Wildcards in command paths: `/usr/bin/*` or `(ALL) NOPASSWD: /bin/bash *`

**Remediation**:
```bash
# Audit NOPASSWD entries
grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/

# Remove or restrict dangerous entries
sudo visudo
# Replace: user ALL=(ALL) NOPASSWD: /usr/bin/vim
# With specific, non-escapable commands only

# If the program is needed, restrict arguments:
# user ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart myservice
# (specific service, not arbitrary systemctl)

# Cross-reference against GTFOBins:
# https://gtfobins.github.io/#+sudo
```

---

### 10.2 Sudo env_keep preserving injection vars

**Threat**: The `env_keep` directive in sudoers preserves specified environment variables across sudo invocation. If variables like `LD_PRELOAD`, `PYTHONPATH`, or `LD_LIBRARY_PATH` are kept, a user can inject a malicious shared library or Python module that executes with root privileges when the sudo command runs.

**Where to look**:
- `/etc/sudoers` — `Defaults env_keep` lines
- `/etc/sudoers.d/*` — drop-in overrides
- `sudo -V` — shows compiled-in defaults including env_keep

**What to look for**:
- `env_keep` containing `LD_PRELOAD` — load arbitrary shared library as root
- `env_keep` containing `LD_LIBRARY_PATH` — redirect library loading to attacker-controlled directory
- `env_keep` containing `PYTHONPATH` — inject Python modules executed by root Python processes
- `env_keep` containing `PERL5LIB`, `RUBYLIB`, `NODE_PATH` — same pattern for other interpreters
- `env_keep` containing `PATH` — redirect command resolution (though sudo usually resets PATH via secure_path)

**Remediation**:
```bash
# Check env_keep settings
sudo grep -r env_keep /etc/sudoers /etc/sudoers.d/

# Check effective env settings
sudo sudo -V 2>/dev/null | grep -A 20 'Environment variables to preserve'

# Remove dangerous variables from env_keep
sudo visudo
# Remove LD_PRELOAD, LD_LIBRARY_PATH, PYTHONPATH from env_keep

# Ensure env_reset is enabled (default)
# Defaults    env_reset
```

---

### 10.3 File capabilities on binaries

**Threat**: Linux file capabilities grant specific privileges to binaries without requiring full SUID-root. A binary with `cap_setuid` can change its UID to root. `cap_dac_override` bypasses all file permission checks. `cap_net_raw` enables packet sniffing. Unlike SUID, capabilities are less visible and often missed in audits.

**Where to look**:
- `getcap -r /usr/bin /usr/sbin /usr/local/bin /opt 2>/dev/null` — scan for binaries with capabilities
- `/usr/bin/`, `/usr/sbin/`, `/usr/local/bin/` — standard binary directories
- Any custom application directories

**What to look for**:
- `cap_setuid` on interpreters or general-purpose tools — instant root via UID change
- `cap_dac_override` — bypass all file permission checks (read /etc/shadow, write /etc/passwd)
- `cap_dac_read_search` — read any file on the system
- `cap_sys_admin` — broad privilege (mount, BPF, many kernel interfaces)
- `cap_net_raw` on unexpected binaries (only ping should normally have this)
- `cap_sys_ptrace` — attach to and modify any process
- Capabilities on binaries not installed by the package manager

**Remediation**:
```bash
# List all binaries with capabilities
getcap -r / 2>/dev/null

# Verify capabilities match expected packages
# Typical legitimate capabilities:
# /usr/bin/ping = cap_net_raw+ep
# /usr/bin/mtr-packet = cap_net_raw+ep

# Remove unexpected capabilities
sudo setcap -r /path/to/suspicious/binary

# Verify package integrity for binaries with capabilities
dpkg -S /path/to/binary
debsums <package>
```

---

### 10.4 Polkit rule manipulation

**Threat**: Polkit (PolicyKit) mediates privilege escalation for desktop and system actions. Rules in `/etc/polkit-1/rules.d/` are JavaScript files that can grant any user passwordless access to privileged operations (mounting disks, managing services, installing packages). A malicious rule file provides persistent, nearly invisible privilege escalation.

**Where to look**:
- `/etc/polkit-1/rules.d/*.rules` — local rules (highest priority)
- `/usr/share/polkit-1/rules.d/*.rules` — vendor rules
- `/etc/polkit-1/localauthority/` — legacy .pkla files (older systems)

**What to look for**:
- Rules that return `polkit.Result.YES` for all subjects or broad groups
- Rules granting `org.freedesktop.systemd1.manage-units` — start/stop any service
- Rules granting `org.freedesktop.policykit.exec` — execute programs as another user
- Rules granting `org.freedesktop.packagekit.system-update` — install arbitrary packages
- Rule files not owned by a package: `dpkg -S /etc/polkit-1/rules.d/*`
- Recently modified rules: `ls -lt /etc/polkit-1/rules.d/`

**Remediation**:
```bash
# List all local polkit rules
ls -la /etc/polkit-1/rules.d/

# Check for overly permissive rules
grep -r 'Result.YES' /etc/polkit-1/rules.d/

# Verify rules are from packages
for f in /etc/polkit-1/rules.d/*; do
    dpkg -S "$f" 2>/dev/null || echo "UNPACKAGED: $f"
done

# Remove malicious rules
sudo rm /etc/polkit-1/rules.d/malicious.rules
sudo systemctl restart polkit
```
