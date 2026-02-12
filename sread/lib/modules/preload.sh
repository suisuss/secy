# Detect LD_PRELOAD hijacking, library injection, and shell hook tampering
# Usage: sread preload

source "${SREAD_ROOT}/lib/redact.sh"

run() {
    require_root

    local root=""
    [[ -d "/host/etc" ]] && root="/host"
    local proc="/proc"
    [[ -d "/host/proc" ]] && proc="/host/proc"

    section_header "LIBRARY INJECTION & SHELL HOOKS"

    # ── /etc/ld.so.preload ───────────────────────────────────────────
    echo "--- /etc/ld.so.preload ---"
    local preload_file="${root}/etc/ld.so.preload"
    if [[ -f "$preload_file" ]]; then
        echo "  [!] File EXISTS — libraries listed here are injected into every process:"
        sed 's/^/      /' "$preload_file" 2>/dev/null
    else
        echo "  (not present — normal)"
    fi
    echo ""

    # ── LD_PRELOAD in running process environments ───────────────────
    echo "--- LD_PRELOAD in process environments ---"
    local preload_found=0
    for pid_dir in "${proc}"/[0-9]*; do
        [[ -f "${pid_dir}/environ" ]] || continue
        local pid
        pid="$(basename "$pid_dir")"
        local preload_val
        preload_val="$({ tr '\0' '\n' < "${pid_dir}/environ" | grep '^LD_PRELOAD='; } 2>/dev/null || true)"
        if [[ -n "$preload_val" ]]; then
            local comm
            comm="$(cat "${pid_dir}/comm" 2>/dev/null || echo "?")"
            echo "  [!] PID ${pid} (${comm}): ${preload_val}"
            preload_found=$((preload_found + 1))
        fi
    done
    [[ $preload_found -eq 0 ]] && echo "  (none detected — normal)"
    echo ""

    # ── Suspicious shared libraries ──────────────────────────────────
    echo "--- Suspicious entries in ld cache ---"
    if command -v ldconfig &>/dev/null; then
        local suspicious
        suspicious="$(ldconfig -p 2>/dev/null | grep -iE 'keylog|spy|hook|inject|monitor|intercept|sniff' || true)"
        if [[ -n "$suspicious" ]]; then
            echo "$suspicious" | sed 's/^/  [!] /'
        else
            echo "  (none detected)"
        fi
    else
        echo "  (ldconfig not available)"
    fi
    echo ""

    # ── Shell profile hooks ──────────────────────────────────────────
    echo "--- Shell profile surveillance hooks ---"
    local profiles=()
    # System-wide
    for f in "${root}/etc/profile" "${root}/etc/bash.bashrc" "${root}/etc/zsh/zshrc"; do
        [[ -f "$f" ]] && profiles+=("$f")
    done
    # Per-user
    if [[ -d "${root}/home" ]]; then
        for home in "${root}"/home/*; do
            [[ -d "$home" ]] || continue
            for f in ".bashrc" ".zshrc" ".profile" ".bash_profile" ".bash_login"; do
                [[ -f "${home}/${f}" ]] && profiles+=("${home}/${f}")
            done
        done
    fi
    # Root
    for f in "${root}/root/.bashrc" "${root}/root/.zshrc" "${root}/root/.profile"; do
        [[ -f "$f" ]] && profiles+=("$f")
    done

    local hook_patterns='keylog|spy|monitor|capture|record|PROMPT_COMMAND.*curl|PROMPT_COMMAND.*wget|PROMPT_COMMAND.*nc[[:space:]]|trap.*DEBUG.*curl|trap.*DEBUG.*wget'
    local hooks_found=0
    for profile in "${profiles[@]}"; do
        local matches
        matches="$(grep -inE "$hook_patterns" "$profile" 2>/dev/null || true)"
        if [[ -n "$matches" ]]; then
            echo "  [!] ${profile}:"
            echo "$matches" | redact_output | sed 's/^/      /'
            hooks_found=$((hooks_found + 1))
        fi
    done
    [[ $hooks_found -eq 0 ]] && echo "  (none detected)"
    echo ""

    # ── PAM modules ──────────────────────────────────────────────────
    echo "--- Suspicious PAM modules ---"
    local pam_dir="${root}/etc/pam.d"
    if [[ -d "$pam_dir" ]]; then
        local pam_suspicious
        pam_suspicious="$(grep -rlE 'pam_exec.*log|keylog|pam_script' "$pam_dir" 2>/dev/null || true)"
        if [[ -n "$pam_suspicious" ]]; then
            echo "$pam_suspicious" | while read -r f; do
                echo "  [!] ${f}:"
                grep -nE 'pam_exec.*log|keylog|pam_script' "$f" 2>/dev/null | sed 's/^/      /'
            done
        else
            echo "  (none detected)"
        fi
    else
        echo "  (pam.d not found)"
    fi

    echo ""
    log_ok "Injection scan complete (preload_envs: ${preload_found}, profile_hooks: ${hooks_found})"
}
