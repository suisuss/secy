# Detect suspicious extended attributes (xattrs) on system binaries and temp directories
# Usage: sread xattr

run() {
    require_root

    local root=""
    [[ -d "/host/etc" ]] && root="/host"

    section_header "EXTENDED ATTRIBUTE (XATTR) ANALYSIS"

    if ! command -v getfattr &>/dev/null; then
        log_warn "getfattr not available — install attr package for xattr scanning"
        echo "  (skipping xattr analysis — getfattr not found)"
        echo ""
        log_ok "Xattr scan skipped (getfattr not available)"
        return
    fi

    # ── Non-standard xattrs on system binaries ─────────────────────
    # System binaries should only have security framework xattrs
    # (SELinux, capabilities, IMA, AppArmor, POSIX ACLs). Anything
    # else may be malware storing configuration or payloads.
    echo "--- Non-standard xattrs on system binaries ---"
    local sys_dirs=("${root}/usr/bin" "${root}/usr/sbin" "${root}/bin" "${root}/sbin")
    local allowed_xattrs="^(security\\.selinux|security\\.capability|security\\.ima|security\\.evm|security\\.apparmor|system\\.posix_acl_access|system\\.posix_acl_default)$"
    local nonstandard=0
    for dir in "${sys_dirs[@]}"; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r -d '' f; do
            local attrs
            attrs="$(getfattr -d -m '.' --absolute-names "$f" 2>/dev/null)" || continue
            [[ -z "$attrs" ]] && continue
            # Parse xattr names (lines matching name=value pattern)
            while IFS= read -r line; do
                # Skip comment/filename lines
                [[ "$line" == \#* ]] && continue
                [[ -z "$line" ]] && continue
                local attr_name="${line%%=*}"
                [[ -z "$attr_name" ]] && continue
                if ! echo "$attr_name" | grep -qE "$allowed_xattrs"; then
                    echo "  [!] ${f}: ${line}"
                    nonstandard=$((nonstandard + 1))
                fi
            done <<< "$attrs"
        done < <(find "$dir" -maxdepth 1 -type f -print0 2>/dev/null)
    done
    [[ $nonstandard -eq 0 ]] && echo "  (none detected — all xattrs are standard security attributes)"
    echo ""

    # ── user.* namespace xattrs on system binaries ─────────────────
    # The user.* xattr namespace is writable by file owners without
    # special privileges. System binaries should never have user.* xattrs.
    echo "--- user.* xattrs on system binaries ---"
    local user_xattrs=0
    for dir in "${sys_dirs[@]}"; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r -d '' f; do
            local attrs
            attrs="$(getfattr -d -m 'user\\.' --absolute-names "$f" 2>/dev/null)" || continue
            [[ -z "$attrs" ]] && continue
            # Filter out comment and empty lines
            local real_attrs
            real_attrs="$(echo "$attrs" | grep -v '^#' | grep -v '^$' || true)"
            if [[ -n "$real_attrs" ]]; then
                echo "  [!] ${f}:"
                echo "$real_attrs" | sed 's/^/      /'
                user_xattrs=$((user_xattrs + 1))
            fi
        done < <(find "$dir" -maxdepth 1 -type f -print0 2>/dev/null)
    done
    [[ $user_xattrs -eq 0 ]] && echo "  (none detected — normal)"
    echo ""

    # ── Temp directory xattrs ──────────────────────────────────────
    # Files in /tmp, /dev/shm, /var/tmp should rarely have non-selinux xattrs.
    echo "--- Xattrs in temp directories ---"
    local temp_dirs=("${root}/tmp" "${root}/dev/shm" "${root}/var/tmp")
    local temp_xattrs=0
    local temp_allowed="^(security\\.selinux|system\\.posix_acl_access|system\\.posix_acl_default)$"
    for dir in "${temp_dirs[@]}"; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r -d '' f; do
            local attrs
            attrs="$(getfattr -d -m '.' --absolute-names "$f" 2>/dev/null)" || continue
            [[ -z "$attrs" ]] && continue
            while IFS= read -r line; do
                [[ "$line" == \#* ]] && continue
                [[ -z "$line" ]] && continue
                local attr_name="${line%%=*}"
                [[ -z "$attr_name" ]] && continue
                if ! echo "$attr_name" | grep -qE "$temp_allowed"; then
                    echo "  [!] ${f}: ${line}"
                    temp_xattrs=$((temp_xattrs + 1))
                fi
            done <<< "$attrs"
        done < <(find "$dir" -maxdepth 2 -type f -print0 2>/dev/null)
    done
    [[ $temp_xattrs -eq 0 ]] && echo "  (none detected)"
    echo ""

    # ── Summary ────────────────────────────────────────────────────
    echo "--- Summary ---"
    echo "  Non-standard system binary xattrs: ${nonstandard}"
    echo "  user.* xattrs on system binaries: ${user_xattrs}"
    echo "  Temp directory non-standard xattrs: ${temp_xattrs}"

    echo ""
    log_ok "Xattr scan complete (nonstandard: ${nonstandard}, user: ${user_xattrs}, temp: ${temp_xattrs})"
}
