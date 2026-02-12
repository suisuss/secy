# Detect timestamp manipulation on system binaries
# Usage: sread tamper [--threshold HOURS]

run() {
    require_root

    local root=""
    [[ -d "/host/etc" ]] && root="/host"

    # Default: flag binaries where ctime is >48h newer than mtime
    # This indicates someone modified the file then backdated mtime
    local threshold_secs=172800
    if [[ "${1:-}" == "--threshold" ]] && [[ -n "${2:-}" ]]; then
        threshold_secs=$(( ${2} * 3600 ))
    fi

    section_header "TIMESTAMP MANIPULATION DETECTION"

    echo "--- Backdated system binaries (ctime >> mtime) ---"
    echo "  Threshold: ctime more than $((threshold_secs / 3600))h newer than mtime"
    echo "  ctime cannot be faked without raw disk access; mtime can be set"
    echo "  with touch. A large gap means someone modified the file then"
    echo "  reset mtime to hide the change."
    echo ""

    local dirs=(
        "${root}/usr/bin"
        "${root}/usr/sbin"
        "${root}/bin"
        "${root}/sbin"
        "${root}/usr/lib"
        "${root}/lib"
    )

    local backdated=0
    local scanned=0

    for dir in "${dirs[@]}"; do
        [[ -d "$dir" ]] || continue

        while IFS= read -r filepath; do
            [[ -f "$filepath" ]] || continue
            # Skip symlinks — their timestamps are irrelevant
            [[ -L "$filepath" ]] && continue

            scanned=$((scanned + 1))

            local mtime ctime
            mtime="$(stat -c '%Y' "$filepath" 2>/dev/null)" || continue
            ctime="$(stat -c '%Z' "$filepath" 2>/dev/null)" || continue

            local diff=$((ctime - mtime))
            if [[ $diff -gt $threshold_secs ]]; then
                local display_path="${filepath#"$root"}"
                local mtime_human ctime_human
                mtime_human="$(date -d "@${mtime}" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "$mtime")"
                ctime_human="$(date -d "@${ctime}" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "$ctime")"
                echo "  [!] ${display_path}"
                echo "      mtime: ${mtime_human}  ctime: ${ctime_human}  (gap: $((diff / 3600))h)"
                backdated=$((backdated + 1))
            fi
        done < <(find "$dir" -maxdepth 1 -type f 2>/dev/null)
    done

    if [[ $backdated -eq 0 ]]; then
        echo "  (none detected)"
    fi
    echo ""

    # ── Recently changed system binaries ──────────────────────────────
    # Binaries with very recent ctime in system dirs are worth noting
    # regardless of mtime, since system dirs change infrequently
    # outside of package upgrades.
    echo "--- System binaries with ctime in last 24h ---"
    local now
    now="$(date +%s)"
    local recent_threshold=$((now - 86400))
    local recent=0

    for dir in "${dirs[@]}"; do
        [[ -d "$dir" ]] || continue

        while IFS= read -r filepath; do
            [[ -f "$filepath" ]] || continue
            [[ -L "$filepath" ]] && continue

            local ctime
            ctime="$(stat -c '%Z' "$filepath" 2>/dev/null)" || continue

            if [[ $ctime -gt $recent_threshold ]]; then
                local display_path="${filepath#"$root"}"
                local ctime_human
                ctime_human="$(date -d "@${ctime}" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "$ctime")"
                echo "  [!] ${display_path} (ctime: ${ctime_human})"
                recent=$((recent + 1))
            fi
        done < <(find "$dir" -maxdepth 1 -type f 2>/dev/null)
    done

    if [[ $recent -eq 0 ]]; then
        echo "  (none — no recent changes to system binaries)"
    fi
    echo ""

    echo "--- Summary ---"
    echo "  Binaries scanned: ${scanned}"
    echo "  Backdated (ctime >> mtime): ${backdated}"
    echo "  Recently changed (ctime <24h): ${recent}"

    echo ""
    log_ok "Timestamp analysis complete"
}
