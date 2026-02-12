# Detect bind mounts hiding files and suspicious mount overlaps
# Usage: sread mounts

run() {
    require_root

    local proc="/proc"
    [[ -d "/host/proc" ]] && proc="/host/proc"

    section_header "MOUNT ANALYSIS"

    # Use PID 1's mountinfo for host-level view (not container self)
    local mountinfo="${proc}/1/mountinfo"
    if [[ ! -f "$mountinfo" ]]; then
        mountinfo="${proc}/self/mountinfo"
    fi

    if [[ ! -f "$mountinfo" ]]; then
        log_error "Cannot read mountinfo"
        exit 1
    fi

    # ── Bind mount detection ───────────────────────────────────────
    # In mountinfo, field 4 is the root of the mount within the filesystem.
    # For normal mounts this is "/". For bind mounts it's the subdirectory
    # being mounted, so root != "/" indicates a bind mount.
    echo "--- Bind mount detection ---"
    local sensitive_paths="^/(usr/bin|usr/sbin|etc|lib|lib64|boot|sbin|bin)"
    local bind_total=0
    local bind_suspicious=0
    while IFS= read -r line; do
        # mountinfo format:
        # id parent_id major:minor root mount_point options ... - fstype source super_options
        local fields
        read -ra fields <<< "$line"
        [[ ${#fields[@]} -lt 6 ]] && continue

        local mount_root="${fields[3]}"
        local mount_point="${fields[4]}"

        # Bind mount indicator: root is not "/"
        [[ "$mount_root" == "/" ]] && continue

        bind_total=$((bind_total + 1))

        # Strip /host prefix for comparison
        local clean_mount="${mount_point#/host}"
        if echo "$clean_mount" | grep -qE "$sensitive_paths"; then
            echo "  [!] BIND ${mount_root} -> ${mount_point} (sensitive system path)"
            bind_suspicious=$((bind_suspicious + 1))
        else
            echo "  ${mount_root} -> ${mount_point}"
        fi
    done < "$mountinfo"
    [[ $bind_total -eq 0 ]] && echo "  (no bind mounts detected)"
    echo ""

    # ── Overlapping mount points ───────────────────────────────────
    # Mounting over an existing path can shadow (hide) its contents.
    # Look for parent-child mount point pairs on the same device.
    echo "--- Overlapping mount points (potential shadowing) ---"
    local -a mount_points=()
    local -a mount_devs=()
    local overlap_count=0
    while IFS= read -r line; do
        local fields
        read -ra fields <<< "$line"
        [[ ${#fields[@]} -lt 6 ]] && continue
        mount_devs+=("${fields[2]}")
        mount_points+=("${fields[4]}")
    done < "$mountinfo"

    local i j
    for (( i=0; i<${#mount_points[@]}; i++ )); do
        for (( j=i+1; j<${#mount_points[@]}; j++ )); do
            # Check if one is a parent of the other on the same device
            if [[ "${mount_devs[$i]}" == "${mount_devs[$j]}" ]]; then
                if [[ "${mount_points[$j]}" == "${mount_points[$i]}"/* ]]; then
                    echo "  [!] ${mount_points[$i]} shadowed by child mount ${mount_points[$j]} (same device ${mount_devs[$i]})"
                    overlap_count=$((overlap_count + 1))
                elif [[ "${mount_points[$i]}" == "${mount_points[$j]}"/* ]]; then
                    echo "  [!] ${mount_points[$j]} shadowed by child mount ${mount_points[$i]} (same device ${mount_devs[$j]})"
                    overlap_count=$((overlap_count + 1))
                fi
            fi
        done
    done
    [[ $overlap_count -eq 0 ]] && echo "  (no overlapping mounts on same device)"
    echo ""

    # ── System directory filesystem types ──────────────────────────
    echo "--- System directory mount types ---"
    local sys_mount_dirs="^/host/(usr|etc|bin|sbin|lib|var|boot|opt)$"
    while IFS= read -r line; do
        local fields
        read -ra fields <<< "$line"
        [[ ${#fields[@]} -lt 6 ]] && continue

        local mount_point="${fields[4]}"

        # Find the separator "-" and extract fstype
        local sep_idx=0
        local k
        for (( k=6; k<${#fields[@]}; k++ )); do
            if [[ "${fields[$k]}" == "-" ]]; then
                sep_idx=$k
                break
            fi
        done
        [[ $sep_idx -eq 0 ]] && continue
        local fstype="${fields[$((sep_idx + 1))]}"
        local source="${fields[$((sep_idx + 2))]}"

        if echo "$mount_point" | grep -qE "$sys_mount_dirs"; then
            echo "  ${mount_point}: ${fstype} (${source})"
        fi
    done < "$mountinfo"
    echo ""

    # ── Summary ────────────────────────────────────────────────────
    echo "--- Summary ---"
    echo "  Total bind mounts: ${bind_total}"
    echo "  Bind mounts on sensitive paths: ${bind_suspicious}"
    echo "  Overlapping mount pairs: ${overlap_count}"

    echo ""
    log_ok "Mount analysis complete (bind: ${bind_total}, suspicious: ${bind_suspicious}, overlaps: ${overlap_count})"
}
