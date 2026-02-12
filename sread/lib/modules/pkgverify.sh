# Verify installed package file integrity against stored checksums
# Usage: sread pkgverify [--all]

run() {
    require_root

    local root=""
    [[ -d "/host/etc" ]] && root="/host"

    local scan_all=false
    [[ "${1:-}" == "--all" ]] && scan_all=true

    section_header "PACKAGE INTEGRITY VERIFICATION"

    local dpkg_info="${root}/var/lib/dpkg/info"
    if [[ ! -d "$dpkg_info" ]]; then
        log_warn "dpkg info directory not found — package verification requires a Debian-based system"
        return 0
    fi

    if ! command -v md5sum &>/dev/null; then
        log_error "md5sum not available"
        return 1
    fi

    # Security-critical packages: trojanizing these gives an attacker
    # persistent root access or credential capture
    local critical_pkgs=(
        base-files coreutils login passwd sudo
        openssh-server openssh-client
        openssl libssl3 libssl1.1
        bash dash
        libc6 libpam0g libpam-modules
        systemd
        apt dpkg
        ca-certificates
        util-linux mount
        adduser
        grep findutils sed gawk
    )

    local md5sums_files=()
    if $scan_all; then
        echo "--- Full package integrity scan ---"
        while IFS= read -r f; do
            md5sums_files+=("$f")
        done < <(find "$dpkg_info" -name '*.md5sums' 2>/dev/null)
    else
        echo "--- Critical package integrity scan ---"
        echo "  (use --all for full scan)"
        for pkg in "${critical_pkgs[@]}"; do
            # Check exact match and multiarch variants (e.g., libc6:amd64)
            for f in "${dpkg_info}/${pkg}.md5sums" "${dpkg_info}/${pkg}:"*.md5sums; do
                [[ -f "$f" ]] && md5sums_files+=("$f")
            done
        done
    fi

    echo "  Packages to verify: ${#md5sums_files[@]}"
    echo ""

    if [[ ${#md5sums_files[@]} -eq 0 ]]; then
        echo "  (no matching md5sums files found)"
        echo ""
        log_ok "Package integrity scan complete (nothing to check)"
        return 0
    fi

    local total_files=0
    local modified=0
    local missing=0
    local errors=0

    for md5file in "${md5sums_files[@]}"; do
        local pkg_name
        pkg_name="$(basename "$md5file" .md5sums)"

        while IFS= read -r line; do
            [[ -z "$line" ]] && continue

            # Format: <32-char md5 hash>  <relative path>
            local expected_hash="${line:0:32}"
            local filepath="${line:34}"

            [[ -z "$filepath" ]] && continue
            total_files=$((total_files + 1))

            local full_path="${root}/${filepath}"

            if [[ ! -f "$full_path" ]]; then
                # Config files are often legitimately missing (dpkg-divert, etc.)
                # Only flag binaries and libraries
                case "$filepath" in
                    usr/bin/*|usr/sbin/*|bin/*|sbin/*|usr/lib/*|lib/*)
                        echo "  [!] MISSING: /${filepath} (${pkg_name})"
                        missing=$((missing + 1))
                        ;;
                esac
                continue
            fi

            local actual_hash
            actual_hash="$(md5sum "$full_path" 2>/dev/null | awk '{print $1}')" || {
                errors=$((errors + 1))
                continue
            }

            if [[ "$actual_hash" != "$expected_hash" ]]; then
                echo "  [!] MODIFIED: /${filepath} (${pkg_name})"
                echo "      expected: ${expected_hash}"
                echo "      actual:   ${actual_hash}"
                modified=$((modified + 1))
            fi
        done < "$md5file"
    done

    echo ""
    echo "--- Summary ---"
    echo "  Files checked: ${total_files}"
    echo "  Modified: ${modified}"
    echo "  Missing: ${missing}"
    echo "  Errors: ${errors}"

    echo ""
    log_ok "Package integrity scan complete"
}
