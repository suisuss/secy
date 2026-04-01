# Check security mount options on temp directories and sensitive paths
# Usage: sread mountsec

run() {
    require_root

    local proc="/proc"
    [[ -d "/host/proc" ]] && proc="/host/proc"

    section_header "MOUNT SECURITY HARDENING"

    local mountinfo="${proc}/1/mountinfo"
    if [[ ! -f "$mountinfo" ]]; then
        mountinfo="${proc}/self/mountinfo"
    fi

    if [[ ! -f "$mountinfo" ]]; then
        log_error "Cannot read mountinfo"
        exit 1
    fi

    # ── 1. Temp directories: noexec, nosuid, nodev ─────────────────
    # /tmp, /dev/shm, and /var/tmp should be mounted with noexec to
    # prevent execution of dropped payloads (e.g., /tmp/ld.py).
    # nosuid prevents setuid escalation, nodev prevents device nodes.
    echo "--- Temp directory mount hardening ---"
    local temp_mounts="/tmp /dev/shm /var/tmp"
    local required_opts="noexec nosuid nodev"
    local temp_issues=0

    for target in $temp_mounts; do
        # Find the mount entry for this path. Match against host-prefixed
        # path or bare path depending on context.
        local found=false
        local mount_opts=""

        while IFS= read -r line; do
            local fields
            read -ra fields <<< "$line"
            [[ ${#fields[@]} -lt 6 ]] && continue

            local mpoint="${fields[4]}"
            # Strip /host prefix for comparison
            local clean_mpoint="${mpoint#/host}"

            if [[ "$clean_mpoint" == "$target" ]]; then
                mount_opts="${fields[5]}"
                # Also grab super_options after the "-" separator
                local k sep_idx=0
                for (( k=6; k<${#fields[@]}; k++ )); do
                    [[ "${fields[$k]}" == "-" ]] && { sep_idx=$k; break; }
                done
                if [[ $sep_idx -gt 0 ]] && [[ $((sep_idx + 3)) -le ${#fields[@]} ]]; then
                    mount_opts="${mount_opts},${fields[$((sep_idx + 3))]}"
                fi
                found=true
                break
            fi
        done < "$mountinfo"

        if ! $found; then
            echo "  [!] ${target} — NOT a separate mount (inherits root fs permissions)"
            echo "      recommendation: mount as separate tmpfs with noexec,nosuid,nodev"
            temp_issues=$((temp_issues + 1))
            continue
        fi

        local missing=""
        for opt in $required_opts; do
            if ! echo "$mount_opts" | grep -q "$opt"; then
                missing="${missing} ${opt}"
            fi
        done

        if [[ -n "$missing" ]]; then
            echo "  [!] ${target} — mounted but MISSING:${missing}"
            echo "      current options: ${mount_opts}"
            temp_issues=$((temp_issues + 1))
        else
            echo "  ${target} — OK (noexec,nosuid,nodev present)"
        fi
    done
    echo ""

    # ── 2. /home nodev check ───────────────────────────────────────
    echo "--- /home mount options ---"
    local home_issues=0
    local home_found=false
    while IFS= read -r line; do
        local fields
        read -ra fields <<< "$line"
        [[ ${#fields[@]} -lt 6 ]] && continue
        local mpoint="${fields[4]}"
        local clean_mpoint="${mpoint#/host}"
        if [[ "$clean_mpoint" == "/home" ]]; then
            local opts="${fields[5]}"
            home_found=true
            if ! echo "$opts" | grep -q "nodev"; then
                echo "  [!] /home — missing nodev"
                home_issues=$((home_issues + 1))
            else
                echo "  /home — OK (nodev present)"
            fi
            break
        fi
    done < "$mountinfo"
    if ! $home_found; then
        echo "  /home — not a separate mount (inherits root fs options)"
    fi
    echo ""

    # ── 3. Writable + executable /proc, /sys checks ────────────────
    echo "--- Sensitive pseudo-filesystem checks ---"
    local pseudo_issues=0
    local pseudofs_targets="/proc /sys"
    for target in $pseudofs_targets; do
        local found=false
        while IFS= read -r line; do
            local fields
            read -ra fields <<< "$line"
            [[ ${#fields[@]} -lt 6 ]] && continue
            local mpoint="${fields[4]}"
            local clean_mpoint="${mpoint#/host}"
            if [[ "$clean_mpoint" == "$target" ]]; then
                local opts="${fields[5]}"
                found=true
                if echo "$opts" | grep -q "rw"; then
                    echo "  ${target} — read-write (normal for host)"
                else
                    echo "  ${target} — read-only (hardened)"
                fi
                break
            fi
        done < "$mountinfo"
        if ! $found; then
            echo "  ${target} — not found in mountinfo"
        fi
    done
    echo ""

    # ── 4. Remediation commands ────────────────────────────────────
    if [[ $temp_issues -gt 0 ]]; then
        echo "--- Remediation ---"
        echo "  Add to /etc/fstab:"
        echo "    tmpfs  /tmp      tmpfs  defaults,noexec,nosuid,nodev,size=2G  0 0"
        echo "    tmpfs  /var/tmp  tmpfs  defaults,noexec,nosuid,nodev,size=1G  0 0"
        echo ""
        echo "  /dev/shm — add to /etc/fstab or remount:"
        echo "    tmpfs  /dev/shm  tmpfs  defaults,noexec,nosuid,nodev  0 0"
        echo ""
        echo "  Apply immediately (non-persistent):"
        echo "    mount -o remount,noexec,nosuid,nodev /tmp"
        echo "    mount -o remount,noexec,nosuid,nodev /dev/shm"
        echo "    mount -o remount,noexec,nosuid,nodev /var/tmp"
        echo ""
    fi

    # ── Summary ─────────────────────────────────────────────────────
    echo "--- Summary ---"
    echo "  Temp directory issues: ${temp_issues}"
    echo "  Home directory issues: ${home_issues}"
    echo "  Pseudo-filesystem issues: ${pseudo_issues}"

    echo ""
    log_ok "Mount security check complete (temp_issues: ${temp_issues}, home_issues: ${home_issues}, pseudo_issues: ${pseudo_issues})"
}
