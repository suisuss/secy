# Enumerate eBPF programs and security-relevant BPF configuration
# Usage: sread ebpf

run() {
    require_root

    local proc="/proc"
    [[ -d "/host/proc" ]] && proc="/host/proc"
    local sys="/sys"
    [[ -d "/host/sys" ]] && sys="/host/sys"

    section_header "eBPF PROGRAM ANALYSIS"

    echo "NOTE: Full eBPF enumeration requires bpftool and debugfs."
    echo "      Results may be partial without these."
    echo ""

    # ── Pinned BPF programs ────────────────────────────────────────
    echo "--- Pinned BPF programs (/sys/fs/bpf) ---"
    local bpf_fs="${sys}/fs/bpf"
    local pinned=0
    if [[ -d "$bpf_fs" ]]; then
        while IFS= read -r -d '' f; do
            echo "  [!] ${f}"
            pinned=$((pinned + 1))
        done < <(find "$bpf_fs" -type f -print0 2>/dev/null)
        [[ $pinned -eq 0 ]] && echo "  (none found)"
    else
        echo "  (bpffs not mounted at ${bpf_fs})"
    fi
    echo ""

    # ── bpftool prog list ──────────────────────────────────────────
    echo "--- Loaded BPF programs (bpftool) ---"
    local security_types="tracepoint|kprobe|raw_tracepoint|lsm|tracing"
    local bpf_total=0
    local bpf_security=0
    if command -v bpftool &>/dev/null; then
        local bpf_output
        bpf_output="$(bpftool prog list 2>/dev/null || true)"
        if [[ -n "$bpf_output" ]]; then
            while IFS= read -r line; do
                # Lines starting with a number are program entries
                if [[ "$line" =~ ^[0-9]+: ]]; then
                    bpf_total=$((bpf_total + 1))
                    if echo "$line" | grep -qiE "$security_types"; then
                        echo "  [!] ${line}"
                        bpf_security=$((bpf_security + 1))
                    else
                        echo "  ${line}"
                    fi
                fi
            done <<< "$bpf_output"
            [[ $bpf_total -eq 0 ]] && echo "  (no programs loaded)"
        else
            echo "  (bpftool returned no output)"
        fi
    else
        echo "  (bpftool not available — install bpftool for full enumeration)"
    fi
    echo ""

    # ── Active security tracepoints ────────────────────────────────
    echo "--- Active security tracepoints ---"
    local tracing_base="${sys}/kernel/debug/tracing/events"
    local active_tp=0
    if [[ -d "$tracing_base" ]]; then
        # Check syscall enter tracepoints
        for enable_file in "${tracing_base}"/syscalls/sys_enter_*/enable; do
            [[ -f "$enable_file" ]] || continue
            local val
            val="$(cat "$enable_file" 2>/dev/null || echo "0")"
            if [[ "$val" == "1" ]]; then
                local tp_name
                tp_name="$(basename "$(dirname "$enable_file")")"
                echo "  [!] ${tp_name} = ENABLED"
                active_tp=$((active_tp + 1))
            fi
        done
        # Check security subsystem tracepoints
        if [[ -d "${tracing_base}/security" ]]; then
            for enable_file in "${tracing_base}"/security/*/enable; do
                [[ -f "$enable_file" ]] || continue
                local val
                val="$(cat "$enable_file" 2>/dev/null || echo "0")"
                if [[ "$val" == "1" ]]; then
                    local tp_name
                    tp_name="$(basename "$(dirname "$enable_file")")"
                    echo "  [!] security/${tp_name} = ENABLED"
                    active_tp=$((active_tp + 1))
                fi
            done
        fi
        [[ $active_tp -eq 0 ]] && echo "  (none active)"
    else
        echo "  (debugfs tracing not accessible — mount debugfs for full analysis)"
    fi
    echo ""

    # ── BPF sysctl indicators ──────────────────────────────────────
    echo "--- BPF sysctl configuration ---"
    local sysctl_base="${proc}/sys/net/core"

    local jit_file="${sysctl_base}/bpf_jit_enable"
    if [[ -f "$jit_file" ]]; then
        local jit_val
        jit_val="$(cat "$jit_file" 2>/dev/null || echo "?")"
        echo "  bpf_jit_enable = ${jit_val}"
        [[ "$jit_val" == "2" ]] && echo "    Note: JIT debugging mode (generates /tmp BPF images)"
    else
        echo "  bpf_jit_enable: (not available)"
    fi

    local unpriv_file="${proc}/sys/kernel/unprivileged_bpf_disabled"
    if [[ -f "$unpriv_file" ]]; then
        local unpriv_val
        unpriv_val="$(cat "$unpriv_file" 2>/dev/null || echo "?")"
        if [[ "$unpriv_val" == "0" ]]; then
            echo "  [!] unprivileged_bpf_disabled = 0 (unprivileged users CAN load BPF programs)"
        elif [[ "$unpriv_val" == "1" ]]; then
            echo "  unprivileged_bpf_disabled = 1 (disabled until reboot)"
        elif [[ "$unpriv_val" == "2" ]]; then
            echo "  unprivileged_bpf_disabled = 2 (permanently disabled)"
        else
            echo "  unprivileged_bpf_disabled = ${unpriv_val}"
        fi
    else
        echo "  unprivileged_bpf_disabled: (not available)"
    fi
    echo ""

    # ── Summary ────────────────────────────────────────────────────
    echo "--- Summary ---"
    echo "  Pinned BPF objects: ${pinned}"
    echo "  Loaded programs (bpftool): ${bpf_total}"
    echo "  Security-sensitive programs: ${bpf_security}"
    echo "  Active tracepoints: ${active_tp}"

    echo ""
    log_ok "eBPF scan complete (pinned: ${pinned}, programs: ${bpf_total}, security: ${bpf_security}, tracepoints: ${active_tp})"
}
