#!/usr/bin/env bash
# run-tests.sh — Verify sread modules detect threatlab artifacts.
# Runs inside secy-test container with PID/network namespace sharing.
set -uo pipefail

# ── Wait for threatlab to finish seeding ──────────────────────────────
echo "Waiting for threatlab to seed artifacts..."
tries=0
while [[ ! -f /host/.ready ]]; do
    sleep 0.5
    tries=$((tries + 1))
    if [[ $tries -ge 60 ]]; then
        echo "FATAL: threatlab did not become ready after 30s"
        exit 1
    fi
done
echo "Threatlab ready. Running tests..."
echo ""

# ── Setup: install keylog library for ld cache test (1.11) ───────────
if [[ -f /host/usr/local/lib/libkeylog_hook.so ]]; then
    cp /host/usr/local/lib/libkeylog_hook.so /usr/local/lib/ 2>/dev/null || true
    ldconfig 2>/dev/null || true
fi

# ── Test framework ────────────────────────────────────────────────────
PASS=0 FAIL=0 SKIP=0

assert() {
    local id="$1" desc="$2" module="$3" pattern="$4"
    shift 4
    local output
    output="$(sread "$module" "$@" 2>&1)" || true
    if echo "$output" | grep -qiE "$pattern"; then
        printf "  \033[32mPASS\033[0m  %-6s %s\n" "$id" "$desc"
        PASS=$((PASS + 1))
    else
        printf "  \033[31mFAIL\033[0m  %-6s %s\n" "$id" "$desc"
        FAIL=$((FAIL + 1))
        # Show last 20 lines of module output for debugging
        echo "        --- module output (last 20 lines) ---"
        echo "$output" | tail -20 | sed 's/^/        /'
        echo "        --- expected pattern: $pattern ---"
    fi
}

skip() {
    local id="$1" desc="$2" reason="$3"
    printf "  \033[33mSKIP\033[0m  %-6s %s (%s)\n" "$id" "$desc" "$reason"
    SKIP=$((SKIP + 1))
}

# ══════════════════════════════════════════════════════════════════════
# AUTOSTART MODULE
# ══════════════════════════════════════════════════════════════════════
echo "── autostart ──────────────────────────────────────────────────"
assert "1.1a" "XDG system autostart"         autostart "malicious-updater.*curl"
assert "1.1b" "XDG user autostart"           autostart "keylogger.*logkeys"
assert "1.2"  "Systemd user service"         autostart "backdoor.service"
assert "1.5"  "Executable rc.local"          autostart "rc\.local exists and is executable"
assert "1.6"  "Non-package init.d script"    autostart "syshealth.*not owned by any package"
echo ""

# ══════════════════════════════════════════════════════════════════════
# PRELOAD MODULE
# ══════════════════════════════════════════════════════════════════════
echo "── preload ───────────────────────────────────────────────────"
assert "1.3"  "Shell profile PROMPT_COMMAND"  preload "PROMPT_COMMAND.*curl"
assert "1.8"  "/etc/ld.so.preload exists"     preload "File EXISTS"
assert "1.9"  "LD_PRELOAD in process env"     preload "LD_PRELOAD="
assert "1.10" "PAM exec module"               preload "pam_exec"
assert "1.11" "Suspicious ld cache entry"     preload "keylog"
echo ""

# ══════════════════════════════════════════════════════════════════════
# SPYPROC MODULE
# ══════════════════════════════════════════════════════════════════════
echo "── spyproc ───────────────────────────────────────────────────"
assert "2.1"  "Known spyware name (logkeys)"  spyproc "logkeys"
assert "2.5"  "Deleted binary"                spyproc "deleted binary"
assert "2.6"  "memfd execution"               spyproc "memfd.*memory-only"
assert "2.7"  "Process name spoofing"         spyproc "comm=.*exe="
echo ""

# ══════════════════════════════════════════════════════════════════════
# SETUID MODULE
# ══════════════════════════════════════════════════════════════════════
echo "── setuid ────────────────────────────────────────────────────"
assert "3.1"  "SUID binary"                   setuid "suid-backdoor" --path /host
assert "3.2"  "SGID binary"                   setuid "sgid-tool" --path /host
echo ""

# ══════════════════════════════════════════════════════════════════════
# WORLD MODULE
# ══════════════════════════════════════════════════════════════════════
echo "── world ─────────────────────────────────────────────────────"
assert "3.3a" "World-writable file (var)"     world "evil-payload" --path /host
assert "3.3b" "World-writable file (opt)"     world "backdoor.conf" --path /host
assert "3.8a" "/dev/shm executable"           world "executable.*payload" --path /host
assert "3.8b" "/dev/shm ELF binary"           world "ELF binary.*data\.bin" --path /host
assert "3.8c" "/dev/shm script"               world "script.*helper\.txt" --path /host
assert "3.8d" "/dev/shm hidden file"          world "hidden file.*\.config" --path /host
echo ""

# ══════════════════════════════════════════════════════════════════════
# TAMPER MODULE
# ══════════════════════════════════════════════════════════════════════
echo "── tamper ────────────────────────────────────────────────────"
assert "3.4"  "Backdated binary"              tamper "backdated-binary"
echo ""

# ══════════════════════════════════════════════════════════════════════
# DESKTOP MODULE
# ══════════════════════════════════════════════════════════════════════
echo "── desktop ───────────────────────────────────────────────────"
assert "1.7"  "Chrome extension"              desktop "Keyboard Monitor Pro"
assert "RD"   "Remote desktop process"        desktop "x11vnc"
echo ""

# ══════════════════════════════════════════════════════════════════════
# PKGVERIFY MODULE
# ══════════════════════════════════════════════════════════════════════
echo "── pkgverify ─────────────────────────────────────────────────"
assert "7.5"  "Package tamper (yes)"          pkgverify "MODIFIED.*yes" --all
echo ""

# ══════════════════════════════════════════════════════════════════════
# NETCONN MODULE
# ══════════════════════════════════════════════════════════════════════
echo "── netconn ───────────────────────────────────────────────────"
assert "5.1"  "TCP listener on :31337"        netconn "0\.0\.0\.0:31337"
echo ""

# ══════════════════════════════════════════════════════════════════════
# TMPEXEC MODULE
# ══════════════════════════════════════════════════════════════════════
echo "── tmpexec ───────────────────────────────────────────────────"
assert "TX-1" "Process running from /tmp"     tmpexec "exe=.*/tmp/"
assert "TX-2" "Script file in /tmp (ld.py)"   tmpexec "ld\.py"
assert "TX-3" "Hidden file in /tmp"           tmpexec "\.a1b2c3|\.beacon"
assert "TX-4" "Executable in /tmp"            tmpexec "\.a1b2c3.*bytes|\.beacon.*bytes"
echo ""

# ══════════════════════════════════════════════════════════════════════
# PROCTREE MODULE
# ══════════════════════════════════════════════════════════════════════
echo "── proctree ──────────────────────────────────────────────────"
assert "PT-1" "Orphaned process (PPID=1)"     proctree "PPID=1"
assert "PT-2" "Session leader no terminal"    proctree "session leader, no terminal"
echo ""

# ══════════════════════════════════════════════════════════════════════
# USERS MODULE
# ══════════════════════════════════════════════════════════════════════
echo "── users ──────────────────────────────────────────────────────"
assert "RS-1" "Active root shell (UID 0 + TTY)" users "root.*(interactive shell|process).*pts/"
skip  "RS-2" "/dev/uinput reader detection"     "requires /dev/uinput device node"
echo ""

# ══════════════════════════════════════════════════════════════════════
# DEBSECAN MODULE
# ══════════════════════════════════════════════════════════════════════
echo "── debsecan ──────────────────────────────────────────────────"
# debsecan needs to fetch the CVE list from security-tracker.debian.org.
# The test container has network access; if the fetch fails (offline CI)
# the module still emits the section header and a debsecan warning, which
# we tolerate by asserting only on the headers it always prints.
assert "DS-1" "Module runs and emits section header"  debsecan "DEBSECAN CVE ANALYSIS"
assert "DS-2" "Module reports source line"            debsecan "status file:.*dpkg/status"
# Summary appears only when debsecan ran successfully against the dpkg
# status file. If the invocation flags are wrong, this fails — catching
# the kind of regression where the module silently degrades to "no CVEs".
assert "DS-3" "debsecan invocation succeeds (Summary block)"  debsecan "Summary ---"
assert "DS-4" "Reports a non-zero CVE total"          debsecan "total:[[:space:]]+[1-9]"
echo ""

# ══════════════════════════════════════════════════════════════════════
# MOUNTSEC MODULE
# ══════════════════════════════════════════════════════════════════════
echo "── mountsec ──────────────────────────────────────────────────"
assert "MS-1" "Temp dir mount check"          mountsec "/tmp"
echo ""

# ══════════════════════════════════════════════════════════════════════
# NETTHREATS MODULE
# ══════════════════════════════════════════════════════════════════════
echo "── netthreats ────────────────────────────────────────────────"
skip  "NT-1" "Non-allowed port connection"    "requires outbound to external IP"
skip  "NT-2" "Beacon detection"               "requires multiple runs with --state-dir"
echo ""

# ══════════════════════════════════════════════════════════════════════
# SKIPPED (not testable in container)
# ══════════════════════════════════════════════════════════════════════
echo "── skipped ───────────────────────────────────────────────────"
skip  "4.x"  "Kernel modules"                "kernel-level, not testable in container"
skip  "1.4"  "Cron jobs"                     "cron.sh uses hardcoded paths, no /host prefix"
echo ""

# ══════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════
echo "════════════════════════════════════════════════════════════════"
printf "Results: \033[32m%d passed\033[0m, \033[31m%d failed\033[0m, \033[33m%d skipped\033[0m\n" \
    "$PASS" "$FAIL" "$SKIP"
echo "════════════════════════════════════════════════════════════════"

exit "$FAIL"
