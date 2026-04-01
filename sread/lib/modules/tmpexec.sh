# Detect processes executing from temp directories and staged payloads in /tmp
# Usage: sread tmpexec

run() {
    require_root

    local proc="/proc"
    [[ -d "/host/proc" ]] && proc="/host/proc"
    local root=""
    [[ -d "/host/tmp" ]] && root="/host"

    section_header "TEMP DIRECTORY EXECUTION DETECTION"

    local tmp_dirs="/tmp /dev/shm /var/tmp"
    local suspicious_dirs="^(/tmp/|/dev/shm/|/var/tmp/)"

    # ── 1. Running processes with exe in temp directories ──────────
    # Any process whose binary lives in /tmp, /dev/shm, or /var/tmp
    # is suspicious. Legitimate software does not run from these paths.
    # The axios ld.py executed from /tmp/ld.py.
    echo "--- Processes executing from temp directories ---"
    local running_count=0
    for pid_dir in "${proc}"/[0-9]*; do
        # Skip kernel threads
        [[ -f "${pid_dir}/cmdline" ]] || continue
        local cmdline_check
        cmdline_check="$(cat "${pid_dir}/cmdline" 2>/dev/null)" || continue
        [[ -z "$cmdline_check" ]] && continue

        local exe
        exe="$(readlink "${pid_dir}/exe" 2>/dev/null)" || continue

        local exe_clean="${exe% (deleted)}"

        # Check against host-relative paths too
        local check_path="$exe_clean"
        [[ "$check_path" == /host/* ]] && check_path="${check_path#/host}"

        if [[ "$check_path" =~ $suspicious_dirs ]]; then
            local pid comm cmdline ppid parent_comm uid_line
            pid="$(basename "$pid_dir")"
            comm="$(cat "${pid_dir}/comm" 2>/dev/null || echo "?")"
            cmdline="$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null || echo "?")"
            ppid="$(grep '^PPid:' "${pid_dir}/status" 2>/dev/null | awk '{print $2}')" || ppid="?"
            parent_comm="$(cat "${proc}/${ppid}/comm" 2>/dev/null || echo "?")"
            uid_line="$(grep '^Uid:' "${pid_dir}/status" 2>/dev/null | awk '{print $2}')" || uid_line="?"

            local deleted_tag=""
            [[ "$exe" == *"(deleted)"* ]] && deleted_tag=" [DELETED from disk]"

            echo "  [!] PID ${pid} (${comm}) exe=${check_path}${deleted_tag}"
            echo "      cmdline: ${cmdline}"
            echo "      parent: PID ${ppid} (${parent_comm}), uid: ${uid_line}"
            running_count=$((running_count + 1))
        fi
    done
    [[ $running_count -eq 0 ]] && echo "  (none — no processes running from temp directories)"
    echo ""

    # ── 2. Interpreter processes with temp directory arguments ─────
    # Catches: python3 /tmp/ld.py, bash /dev/shm/dropper.sh, etc.
    # Even if the interpreter binary itself is in /usr/bin, the script
    # it's running may be in /tmp.
    echo "--- Interpreters running scripts from temp directories ---"
    local interp_count=0
    local interpreters="^(python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|node|bash|sh|dash|zsh|lua[0-9.]*)$"

    for pid_dir in "${proc}"/[0-9]*; do
        [[ -f "${pid_dir}/cmdline" ]] || continue
        local comm
        comm="$(cat "${pid_dir}/comm" 2>/dev/null)" || continue

        if ! [[ "$comm" =~ $interpreters ]]; then
            continue
        fi

        local cmdline
        cmdline="$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null)" || continue

        # Check if any argument references a temp directory
        if echo "$cmdline" | grep -qE "(^| )(/tmp/|/dev/shm/|/var/tmp/)"; then
            local pid ppid parent_comm
            pid="$(basename "$pid_dir")"
            ppid="$(grep '^PPid:' "${pid_dir}/status" 2>/dev/null | awk '{print $2}')" || ppid="?"
            parent_comm="$(cat "${proc}/${ppid}/comm" 2>/dev/null || echo "?")"

            echo "  [!] PID ${pid} (${comm}): ${cmdline}"
            echo "      parent: PID ${ppid} (${parent_comm})"
            interp_count=$((interp_count + 1))
        fi
    done
    [[ $interp_count -eq 0 ]] && echo "  (none — no interpreters running temp scripts)"
    echo ""

    # ── 3. Staged payloads: executable files in temp directories ───
    # Files that are executable but not yet running. Could be waiting
    # for a trigger or were dropped and haven't been cleaned up.
    echo "--- Executable files in temp directories (staged payloads) ---"
    local staged_count=0
    for dir in $tmp_dirs; do
        local scan_dir="${root}${dir}"
        [[ -d "$scan_dir" ]] || continue

        # Find executable regular files (not directories, not sockets)
        # Limit depth to avoid traversing deep npm caches etc.
        while IFS= read -r -d '' file; do
            [[ -f "$file" ]] || continue
            [[ -x "$file" ]] || continue

            local file_display="${file#"${root}"}"
            local file_size file_mtime file_owner
            file_size="$(stat -c%s "$file" 2>/dev/null || echo "?")"
            file_mtime="$(stat -c%Y "$file" 2>/dev/null || echo "0")"
            file_owner="$(stat -c%U "$file" 2>/dev/null || echo "?")"

            local now
            now="$(date +%s)"
            local age_hours="?"
            if [[ "$file_mtime" != "0" ]]; then
                age_hours=$(( (now - file_mtime) / 3600 ))
            fi

            echo "  [!] ${file_display} (${file_size} bytes, owner: ${file_owner}, age: ${age_hours}h)"
            staged_count=$((staged_count + 1))
        done < <(find "$scan_dir" -maxdepth 3 -type f -executable -print0 2>/dev/null)
    done
    [[ $staged_count -eq 0 ]] && echo "  (none — no executable files found in temp directories)"
    echo ""

    # ── 4. Recently created script files in temp directories ───────
    # Scripts don't need the execute bit — interpreters can run them
    # directly (python3 /tmp/script.py). Look for recently written
    # script files by extension.
    echo "--- Recently created scripts in temp directories (last 24h) ---"
    local script_count=0
    local script_exts="py|sh|pl|rb|js|lua|php|ps1|bat|cmd|vbs"

    for dir in $tmp_dirs; do
        local scan_dir="${root}${dir}"
        [[ -d "$scan_dir" ]] || continue

        while IFS= read -r -d '' file; do
            local file_display="${file#"${root}"}"
            local file_size file_owner
            file_size="$(stat -c%s "$file" 2>/dev/null || echo "?")"
            file_owner="$(stat -c%U "$file" 2>/dev/null || echo "?")"

            echo "  [!] ${file_display} (${file_size} bytes, owner: ${file_owner})"
            script_count=$((script_count + 1))
        done < <(find "$scan_dir" -maxdepth 3 -type f -mmin -1440 \
            -regextype posix-extended -regex ".*\.(${script_exts})" \
            -print0 2>/dev/null)
    done
    [[ $script_count -eq 0 ]] && echo "  (none — no recent script files in temp directories)"
    echo ""

    # ── 5. Hidden files in temp directories ────────────────────────
    # The axios peinject command wrote to /tmp/.<random> — dot-prefixed
    # to hide from casual ls.
    echo "--- Hidden files in temp directories ---"
    local hidden_count=0
    for dir in $tmp_dirs; do
        local scan_dir="${root}${dir}"
        [[ -d "$scan_dir" ]] || continue

        while IFS= read -r -d '' file; do
            # Skip standard hidden dirs like .X11-unix, .ICE-unix, .font-unix
            local basename_f
            basename_f="$(basename "$file")"
            case "$basename_f" in
                .X11-unix|.ICE-unix|.font-unix|.XIM-unix|.X0-lock|.X1-lock) continue ;;
                .snap*|.docker*|.Test-*) continue ;;
            esac

            local file_display="${file#"${root}"}"
            local file_size file_perms
            file_size="$(stat -c%s "$file" 2>/dev/null || echo "?")"
            file_perms="$(stat -c%a "$file" 2>/dev/null || echo "?")"

            echo "  [!] ${file_display} (${file_size} bytes, mode: ${file_perms})"
            hidden_count=$((hidden_count + 1))
        done < <(find "$scan_dir" -maxdepth 2 -name '.*' -type f -print0 2>/dev/null)
    done
    [[ $hidden_count -eq 0 ]] && echo "  (none)"
    echo ""

    # ── Summary ─────────────────────────────────────────────────────
    echo "--- Summary ---"
    echo "  Processes from temp dirs: ${running_count}"
    echo "  Interpreters running temp scripts: ${interp_count}"
    echo "  Staged executables: ${staged_count}"
    echo "  Recent script files: ${script_count}"
    echo "  Hidden files: ${hidden_count}"

    echo ""
    log_ok "Temp execution scan complete (running: ${running_count}, interp: ${interp_count}, staged: ${staged_count}, scripts: ${script_count}, hidden: ${hidden_count})"
}
