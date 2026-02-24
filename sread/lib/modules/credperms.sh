# Audit credential file permissions for exposure risk (threat 3.13)
# Usage: sread credperms

run() {
    require_root

    local root=""
    [[ -d "/host/etc" ]] && root="/host"

    local findings=0

    section_header "CREDENTIAL FILE PERMISSIONS"

    # ── SSH private keys ───────────────────────────────────────────
    echo "--- SSH private keys (expect 600) ---"
    local ssh_found=0
    for base_dir in "${root}/home" "${root}/root"; do
        [[ -d "$base_dir" ]] || continue
        if [[ "$base_dir" == "${root}/root" ]]; then
            local ssh_dirs=("${base_dir}/.ssh")
        else
            local ssh_dirs=()
            for d in "${base_dir}"/*/.ssh; do
                [[ -d "$d" ]] && ssh_dirs+=("$d")
            done
        fi
        for ssh_dir in "${ssh_dirs[@]}"; do
            [[ -d "$ssh_dir" ]] || continue
            while IFS= read -r keyfile; do
                [[ -f "$keyfile" ]] || continue
                # Skip public keys and known_hosts
                [[ "$keyfile" == *.pub ]] && continue
                [[ "$(basename "$keyfile")" == "known_hosts" ]] && continue
                [[ "$(basename "$keyfile")" == "known_hosts.old" ]] && continue
                [[ "$(basename "$keyfile")" == "authorized_keys" ]] && continue
                [[ "$(basename "$keyfile")" == "config" ]] && continue
                local perms
                perms="$(stat -c '%a' "$keyfile" 2>/dev/null)" || continue
                if [[ "$perms" != "600" && "$perms" != "400" ]]; then
                    echo "  [!] ${keyfile} has permissions ${perms} (should be 600)"
                    ls -la "$keyfile" 2>/dev/null | sed 's/^/      /'
                    findings=$((findings + 1))
                fi
                ssh_found=$((ssh_found + 1))
            done < <(find "$ssh_dir" -maxdepth 1 -type f \( -name 'id_*' -o -name '*.pem' -o -name '*.key' \) 2>/dev/null)
        done
    done
    [[ $ssh_found -eq 0 ]] && echo "  (no SSH private keys found)"
    echo ""

    # ── Environment and credential files ───────────────────────────
    echo "--- Environment/credential files (.env, credentials, secrets) ---"
    local env_found=0
    for base_dir in "${root}/home" "${root}/root"; do
        [[ -d "$base_dir" ]] || continue
        while IFS= read -r f; do
            [[ -f "$f" ]] || continue
            local perms
            perms="$(stat -c '%a' "$f" 2>/dev/null)" || continue
            # Flag if group-readable (>=040) or world-readable (>=004)
            local group_bit=$(( (8#$perms / 8) % 8 ))
            local other_bit=$(( 8#$perms % 8 ))
            if [[ $other_bit -ge 4 ]]; then
                echo "  [!] world-readable: ${f} (${perms})"
                ls -la "$f" 2>/dev/null | sed 's/^/      /'
                findings=$((findings + 1))
            elif [[ $group_bit -ge 4 ]]; then
                echo "  [!] group-readable: ${f} (${perms})"
                ls -la "$f" 2>/dev/null | sed 's/^/      /'
                findings=$((findings + 1))
            fi
            env_found=$((env_found + 1))
        done < <(find "$base_dir" -maxdepth 3 -type f \( -name '.env' -o -name '.env.*' -o -name 'credentials.json' -o -name '*.secret.*' \) 2>/dev/null)
    done
    [[ $env_found -eq 0 ]] && echo "  (no .env/credential files found)"
    echo ""

    # ── /etc/shadow permissions ────────────────────────────────────
    echo "--- /etc/shadow (expect 640 root:shadow) ---"
    local shadow="${root}/etc/shadow"
    if [[ -f "$shadow" ]]; then
        local perms owner group
        perms="$(stat -c '%a' "$shadow" 2>/dev/null)" || true
        owner="$(stat -c '%U' "$shadow" 2>/dev/null)" || true
        group="$(stat -c '%G' "$shadow" 2>/dev/null)" || true
        if [[ "$perms" != "640" && "$perms" != "600" && "$perms" != "000" ]]; then
            echo "  [!] /etc/shadow has permissions ${perms} (expected 640 or stricter)"
            ls -la "$shadow" 2>/dev/null | sed 's/^/      /'
            findings=$((findings + 1))
        elif [[ "$owner" != "root" ]]; then
            echo "  [!] /etc/shadow owned by ${owner} (expected root)"
            ls -la "$shadow" 2>/dev/null | sed 's/^/      /'
            findings=$((findings + 1))
        else
            echo "  ${perms} ${owner}:${group} -- ok"
        fi
    else
        echo "  (not present)"
    fi
    echo ""

    # ── Cloud credential files ─────────────────────────────────────
    echo "--- Cloud credentials (AWS, GCP, Kubernetes) ---"
    local cloud_found=0
    local cloud_paths=()
    for base_dir in "${root}/home" "${root}/root"; do
        [[ -d "$base_dir" ]] || continue
        if [[ "$base_dir" == "${root}/root" ]]; then
            local homes=("$base_dir")
        else
            local homes=()
            for d in "${base_dir}"/*/; do
                [[ -d "$d" ]] && homes+=("${d%/}")
            done
        fi
        for home in "${homes[@]}"; do
            cloud_paths+=(
                "${home}/.aws/credentials"
                "${home}/.aws/config"
                "${home}/.config/gcloud/application_default_credentials.json"
                "${home}/.kube/config"
            )
        done
    done
    for cred in "${cloud_paths[@]}"; do
        [[ -f "$cred" ]] || continue
        local perms
        perms="$(stat -c '%a' "$cred" 2>/dev/null)" || continue
        local other_bit=$(( 8#$perms % 8 ))
        local group_bit=$(( (8#$perms / 8) % 8 ))
        if [[ $other_bit -ge 4 ]]; then
            echo "  [!] world-readable: ${cred} (${perms})"
            ls -la "$cred" 2>/dev/null | sed 's/^/      /'
            findings=$((findings + 1))
        elif [[ $group_bit -ge 4 ]]; then
            echo "  [!] group-readable: ${cred} (${perms})"
            ls -la "$cred" 2>/dev/null | sed 's/^/      /'
            findings=$((findings + 1))
        fi
        cloud_found=$((cloud_found + 1))
    done
    [[ $cloud_found -eq 0 ]] && echo "  (no cloud credential files found)"
    echo ""

    # ── TLS private keys ──────────────────────────────────────────
    echo "--- TLS private keys (/etc/ssl/private/) ---"
    local ssl_dir="${root}/etc/ssl/private"
    if [[ -d "$ssl_dir" ]]; then
        # Check directory permissions (expect 700)
        local dir_perms
        dir_perms="$(stat -c '%a' "$ssl_dir" 2>/dev/null)" || true
        if [[ "$dir_perms" != "700" ]]; then
            echo "  [!] ${ssl_dir}/ has permissions ${dir_perms} (expected 700)"
            ls -ld "$ssl_dir" 2>/dev/null | sed 's/^/      /'
            findings=$((findings + 1))
        fi
        # Check individual key files (expect 600 or 640)
        local tls_found=0
        while IFS= read -r keyfile; do
            [[ -f "$keyfile" ]] || continue
            local perms
            perms="$(stat -c '%a' "$keyfile" 2>/dev/null)" || continue
            if [[ "$perms" != "600" && "$perms" != "640" && "$perms" != "400" ]]; then
                echo "  [!] ${keyfile} has permissions ${perms} (expected 600)"
                ls -la "$keyfile" 2>/dev/null | sed 's/^/      /'
                findings=$((findings + 1))
            fi
            tls_found=$((tls_found + 1))
        done < <(find "$ssl_dir" -maxdepth 1 -type f 2>/dev/null)
        [[ $tls_found -eq 0 && "$dir_perms" == "700" ]] && echo "  (directory empty, permissions ok)"
    else
        echo "  (directory not present)"
    fi

    echo ""
    log_ok "Credential permission scan complete (${findings} finding(s))"
}
