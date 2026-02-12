# Find world-writable files and directories
# Usage: sread world [--path /search/root]

run() {
    require_root

    local search_root="/"
    if [[ "${1:-}" == "--path" ]] && [[ -n "${2:-}" ]]; then
        search_root="$2"
    fi

    section_header "WORLD-WRITABLE FILES/DIRS"

    echo "--- World-writable directories (excluding /tmp, /var/tmp, /dev/shm, /run) ---"
    find "$search_root" -type d -perm -0002 \
        -not -path "/tmp/*" -not -path "/var/tmp/*" -not -path "/dev/shm/*" \
        -not -path "/proc/*" -not -path "/sys/*" -not -path "/run/*" \
        2>/dev/null | while read -r f; do
        ls -ld "$f" 2>/dev/null | sed 's/^/  /'
    done
    echo ""

    echo "--- World-writable files (excluding /tmp, /var/tmp, /dev/shm, /run) ---"
    find "$search_root" -type f -perm -0002 \
        -not -path "/tmp/*" -not -path "/var/tmp/*" -not -path "/dev/shm/*" \
        -not -path "/proc/*" -not -path "/sys/*" -not -path "/run/*" \
        2>/dev/null | while read -r f; do
        ls -la "$f" 2>/dev/null | sed 's/^/  /'
    done
    echo ""

    # ── /dev/shm staging scan ─────────────────────────────────────────
    # /dev/shm is a world-writable tmpfs that doesn't survive reboot.
    # Fileless malware frequently stages payloads here because:
    #   - it's writable by any user
    #   - it's in RAM (no disk forensics trace)
    #   - it's rarely monitored
    # The general world-writable scan above excludes /dev/shm to reduce
    # noise. This dedicated scan looks for genuinely suspicious content.
    local shm_root="${search_root%/}/dev/shm"
    echo "--- /dev/shm payload scan ---"
    if [[ ! -d "$shm_root" ]]; then
        echo "  (not present)"
    else
        local shm_found=0

        # Executable files (any file with +x)
        while IFS= read -r f; do
            echo "  [!] executable: ${f}"
            ls -la "$f" 2>/dev/null | sed 's/^/      /'
            shm_found=$((shm_found + 1))
        done < <(find "$shm_root" -type f -executable 2>/dev/null)

        # ELF binaries (even without +x, an ELF in /dev/shm is suspicious)
        while IFS= read -r f; do
            # Skip if already flagged as executable
            [[ -x "$f" ]] && continue
            local magic
            magic="$(head -c 4 "$f" 2>/dev/null | od -A n -t x1 2>/dev/null | tr -d ' ')" || continue
            if [[ "$magic" == "7f454c46" ]]; then
                echo "  [!] ELF binary (non-executable): ${f}"
                ls -la "$f" 2>/dev/null | sed 's/^/      /'
                shm_found=$((shm_found + 1))
            fi
        done < <(find "$shm_root" -type f ! -executable 2>/dev/null)

        # Script files (shebang without +x)
        while IFS= read -r f; do
            [[ -x "$f" ]] && continue
            local first_bytes
            first_bytes="$(head -c 2 "$f" 2>/dev/null)" || continue
            if [[ "$first_bytes" == "#!" ]]; then
                echo "  [!] script (non-executable): ${f}"
                head -1 "$f" 2>/dev/null | sed 's/^/      /'
                shm_found=$((shm_found + 1))
            fi
        done < <(find "$shm_root" -type f ! -executable 2>/dev/null)

        # Hidden files (dotfiles)
        while IFS= read -r f; do
            local base
            base="$(basename "$f")"
            if [[ "$base" == .* ]] && [[ "$base" != "." ]] && [[ "$base" != ".." ]]; then
                echo "  [!] hidden file: ${f}"
                ls -la "$f" 2>/dev/null | sed 's/^/      /'
                shm_found=$((shm_found + 1))
            fi
        done < <(find "$shm_root" -maxdepth 2 -type f 2>/dev/null)

        [[ $shm_found -eq 0 ]] && echo "  (clean — no executables, ELF binaries, scripts, or hidden files)"
    fi
}
