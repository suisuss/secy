# Analyze loaded kernel modules for suspicious or surveillance-related entries
# Usage: sread kmod

run() {
    require_root

    local proc="/proc"
    [[ -d "/host/proc" ]] && proc="/host/proc"
    local sys="/sys"
    [[ -d "/host/sys" ]] && sys="/host/sys"

    section_header "KERNEL MODULE ANALYSIS"

    local modules_file="${proc}/modules"
    if [[ ! -f "$modules_file" ]]; then
        log_error "Cannot read ${modules_file}"
        exit 1
    fi

    # ── Known suspicious module patterns ─────────────────────────────
    local spy_patterns="keylog|logger|spy|monitor|hook|rootkit|hide|stealth|sniff|intercept|backdoor"

    echo "--- Suspicious module name scan ---"
    local suspicious
    suspicious="$(grep -iE "$spy_patterns" "$modules_file" 2>/dev/null || true)"
    if [[ -n "$suspicious" ]]; then
        echo "$suspicious" | while read -r line; do
            local mod_name
            mod_name="$(echo "$line" | awk '{print $1}')"
            echo "  [!] ${mod_name}: ${line}"
        done
    else
        echo "  (none detected)"
    fi
    echo ""

    # ── Input subsystem modules ──────────────────────────────────────
    echo "--- Input subsystem modules (normal but worth auditing) ---"
    local input_modules
    input_modules="$(grep -iE '^(uinput|evdev|hid|keyboard|input)' "$modules_file" 2>/dev/null || true)"
    if [[ -n "$input_modules" ]]; then
        echo "$input_modules" | while read -r line; do
            local mod_name mod_size mod_used
            mod_name="$(echo "$line" | awk '{print $1}')"
            mod_size="$(echo "$line" | awk '{print $2}')"
            mod_used="$(echo "$line" | awk '{print $3}')"
            echo "  ${mod_name} (size: ${mod_size}, used_by: ${mod_used})"
        done
    else
        echo "  (none loaded)"
    fi
    echo ""

    # ── Unsigned / out-of-tree modules ───────────────────────────────
    echo "--- Out-of-tree / unsigned modules ---"
    local oot_found=0
    local sys_modules="${proc}/sys/module"
    [[ -d "/host/sys/module" ]] && sys_modules="/host/sys/module"
    if [[ -d "$sys_modules" ]]; then
        while read -r line; do
            local mod_name
            mod_name="$(echo "$line" | awk '{print $1}')"
            local taint_file="${sys_modules}/${mod_name}/taint"
            if [[ -f "$taint_file" ]]; then
                local taint
                taint="$(cat "$taint_file" 2>/dev/null || echo "")"
                # O = out-of-tree, E = unsigned
                if [[ "$taint" == *O* ]] || [[ "$taint" == *E* ]]; then
                    echo "  [!] ${mod_name} (taint: ${taint})"
                    oot_found=$((oot_found + 1))
                fi
            fi
        done < "$modules_file"
    fi
    [[ $oot_found -eq 0 ]] && echo "  (none detected — all modules appear in-tree and signed)"
    echo ""

    # ── /proc/modules vs /sys/module cross-verification ───────────────
    # A rootkit that hooks procfs to hide from /proc/modules may forget
    # to also hide from /sys/module (or vice versa). Discrepancies
    # between these two sources are a strong rootkit indicator.
    echo "--- /proc/modules vs /sys/module cross-check ---"
    local hidden_from_sysfs=0
    local hidden_from_proc=0
    if [[ -d "$sys_modules" ]]; then
        # Check: modules in /proc/modules but missing from /sys/module
        while read -r line; do
            local mod_name
            mod_name="$(echo "$line" | awk '{print $1}')"
            if [[ ! -d "${sys_modules}/${mod_name}" ]]; then
                echo "  [!] ${mod_name} in /proc/modules but MISSING from /sys/module"
                hidden_from_sysfs=$((hidden_from_sysfs + 1))
            fi
        done < "$modules_file"

        # Check: loadable modules in /sys/module but missing from /proc/modules
        # Built-in modules appear in /sys/module without a refcnt file;
        # only flag entries that have refcnt (loadable) but aren't in /proc/modules
        local proc_mod_names
        proc_mod_names="$(awk '{print $1}' "$modules_file")"
        for mod_dir in "${sys_modules}"/*/; do
            [[ -d "$mod_dir" ]] || continue
            # Only check loadable modules (have refcnt), skip built-ins
            [[ -f "${mod_dir}/refcnt" ]] || continue
            local mod_name
            mod_name="$(basename "$mod_dir")"
            if ! echo "$proc_mod_names" | grep -qx "$mod_name"; then
                echo "  [!] ${mod_name} in /sys/module (loadable) but MISSING from /proc/modules"
                hidden_from_proc=$((hidden_from_proc + 1))
            fi
        done
    else
        echo "  (skipped — /sys/module not accessible)"
    fi
    [[ $((hidden_from_sysfs + hidden_from_proc)) -eq 0 ]] && echo "  (consistent — no discrepancies)"
    echo ""

    # ── System-wide kernel taint bitmask ──────────────────────────────
    # /proc/sys/kernel/tainted is a bitmask summarizing whether the
    # kernel has been tainted by any out-of-tree, unsigned, or forced
    # module loads. Non-zero values warrant investigation.
    echo "--- System-wide kernel taint flags ---"
    local taint_file="${proc}/sys/kernel/tainted"
    if [[ -f "$taint_file" ]]; then
        local taint_val
        taint_val="$(cat "$taint_file" 2>/dev/null || echo "?")"
        if [[ "$taint_val" == "0" ]]; then
            echo "  Taint value: 0 (clean)"
        else
            echo "  [!] Taint value: ${taint_val}"
            # Decode known bits (from kernel Documentation/admin-guide/tainted-kernels.rst)
            local -a taint_bits=(
                "proprietary module loaded"
                "module force-loaded"
                "kernel running on out-of-spec system"
                "module force-unloaded"
                "processor reported MCE"
                "bad page found (hardware memory error)"
                "user requested taint"
                "kernel died recently (OOPS or BUG)"
                "ACPI table overridden by user"
                "kernel issued warning"
                "staging driver loaded"
                "workaround for platform firmware bug applied"
                "unsigned module loaded"
                "soft lockup occurred"
                "kernel live-patched"
                "auxiliary taint (platform-specific)"
                "struct randomization plugin in use"
                "in-kernel test run"
            )
            local i
            for i in "${!taint_bits[@]}"; do
                if (( taint_val & (1 << i) )); then
                    echo "      bit ${i}: ${taint_bits[$i]}"
                fi
            done
        fi
    else
        echo "  (cannot read ${taint_file})"
    fi
    echo ""

    # ── Active kprobes ─────────────────────────────────────────────
    # Kprobes allow dynamic hooking of kernel functions. A rootkit can
    # use them to intercept syscalls or sensitive operations. Hooks on
    # security-critical functions are especially suspicious.
    echo "--- Active kprobes ---"
    local kprobe_list="${sys}/kernel/debug/kprobes/list"
    local kprobe_count=0
    local sensitive_kprobes=0
    local sensitive_funcs="sys_execve|sys_open|sys_openat|sys_connect|sys_accept|sys_ptrace|vfs_read|vfs_write|tcp_sendmsg|security_"
    if [[ -f "$kprobe_list" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            kprobe_count=$((kprobe_count + 1))
            if echo "$line" | grep -qE "$sensitive_funcs"; then
                echo "  [!] ${line}"
                sensitive_kprobes=$((sensitive_kprobes + 1))
            else
                echo "  ${line}"
            fi
        done < "$kprobe_list"
        [[ $kprobe_count -eq 0 ]] && echo "  (none active)"
    else
        echo "  (debugfs kprobes not accessible — requires debugfs mount)"
    fi
    echo ""

    # ── Kprobe tracing events ──────────────────────────────────────
    echo "--- Kprobe tracing events ---"
    local kprobe_events="${sys}/kernel/debug/tracing/kprobe_events"
    local kprobe_event_count=0
    if [[ -f "$kprobe_events" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            echo "  [!] ${line}"
            kprobe_event_count=$((kprobe_event_count + 1))
        done < "$kprobe_events"
        [[ $kprobe_event_count -eq 0 ]] && echo "  (none configured)"
    else
        echo "  (debugfs tracing not accessible)"
    fi
    echo ""

    # ── DKMS registered modules ───────────────────────────────────
    # DKMS modules auto-rebuild on kernel updates, providing persistence
    # across kernel upgrades. Legitimate uses include GPU drivers and
    # VPN modules, but malicious modules can also use DKMS.
    echo "--- DKMS registered modules ---"
    local root=""
    [[ -d "/host/var" ]] && root="/host"
    local dkms_dir="${root}/var/lib/dkms"
    local dkms_count=0
    local dkms_suspicious=0
    local dkms_allowlist="^(virtualbox|vboxguest|vboxdrv|nvidia|broadcom-sta|bcmwl|rtl[0-9]|zfs|wireguard|v4l2loopback|bbswitch|tp_smapi|acpi_call|evdi|dahdi|xtables-addons|drbd)$"
    if [[ -d "$dkms_dir" ]]; then
        for mod_dir in "${dkms_dir}"/*/; do
            [[ -d "$mod_dir" ]] || continue
            local mod_name
            mod_name="$(basename "$mod_dir")"
            [[ "$mod_name" == "kernel"* ]] && continue
            dkms_count=$((dkms_count + 1))
            if echo "$mod_name" | grep -qiE "$dkms_allowlist"; then
                echo "  ${mod_name}"
            else
                echo "  [!] ${mod_name} (not in known-legitimate allowlist)"
                dkms_suspicious=$((dkms_suspicious + 1))
            fi
        done
        [[ $dkms_count -eq 0 ]] && echo "  (none registered)"
    else
        echo "  (DKMS not installed or ${dkms_dir} not accessible)"
    fi
    echo ""

    # ── Module count summary ─────────────────────────────────────────
    local total
    total="$(wc -l < "$modules_file" | tr -d ' ')"
    echo "--- Summary ---"
    echo "  Total loaded modules: ${total}"
    echo "  Out-of-tree/unsigned: ${oot_found}"
    echo "  Hidden from sysfs: ${hidden_from_sysfs}"
    echo "  Hidden from procfs: ${hidden_from_proc}"
    echo "  Active kprobes: ${kprobe_count}"
    echo "  Sensitive function hooks: ${sensitive_kprobes}"
    echo "  DKMS modules: ${dkms_count}"
    echo "  DKMS suspicious: ${dkms_suspicious}"

    echo ""
    log_ok "Kernel module scan complete (kprobes: ${kprobe_count}, sensitive: ${sensitive_kprobes})"
}
