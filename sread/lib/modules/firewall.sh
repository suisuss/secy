# Detect active firewall, assess coverage, and dump rules
# Usage: sread firewall

run() {
    require_root
    warn_if_container

    local root=""
    [[ -d "/host/etc" ]] && root="/host"

    section_header "FIREWALL ASSESSMENT"

    local firewall_active=false
    local findings=0

    # ── ufw (highest-level — if active, it manages iptables) ────────
    echo "--- ufw ---"
    local ufw_bin=""
    if command -v ufw &>/dev/null; then
        ufw_bin="ufw"
    elif [[ -x "${root}/usr/sbin/ufw" ]]; then
        ufw_bin="${root}/usr/sbin/ufw"
    fi

    if [[ -n "$ufw_bin" ]]; then
        local ufw_status
        ufw_status="$($ufw_bin status 2>/dev/null || true)"
        if echo "$ufw_status" | grep -qi "^Status: active"; then
            echo "  ufw is ACTIVE"
            firewall_active=true

            local ufw_verbose
            ufw_verbose="$($ufw_bin status verbose 2>/dev/null || true)"
            local default_in
            default_in="$(echo "$ufw_verbose" | grep -i 'Default:' | head -1 || true)"
            if [[ -n "$default_in" ]]; then
                echo "  ${default_in}"
                if echo "$default_in" | grep -qi 'deny\|reject'; then
                    echo "  Default incoming policy: deny (good)"
                elif echo "$default_in" | grep -qi 'allow'; then
                    echo "  [!] Default incoming policy: ALLOW (permissive)"
                    findings=$((findings + 1))
                fi
            fi

            echo ""
            echo "  Rules:"
            $ufw_bin status numbered 2>/dev/null | sed 's/^/    /' || true
        else
            echo "  ufw is installed but INACTIVE (in this context)"
        fi
    else
        echo "  (not installed in this context)"
    fi

    # In a container, check the host's ufw config via /host
    if ! $firewall_active && [[ -n "$root" && -f "${root}/etc/ufw/ufw.conf" ]]; then
        local ufw_enabled
        ufw_enabled="$(grep '^ENABLED=' "${root}/etc/ufw/ufw.conf" 2>/dev/null | cut -d= -f2 || true)"
        if [[ "$ufw_enabled" == "yes" ]]; then
            echo "  ufw ENABLED on host (detected via /etc/ufw/ufw.conf)"
            firewall_active=true

            local user_rules="${root}/etc/ufw/user.rules"
            if [[ -f "$user_rules" ]]; then
                local rule_count
                rule_count="$(grep -cE '^\-A ufw' "$user_rules" 2>/dev/null || echo 0)"
                echo "  Host ufw rules: ${rule_count}"

                local default_policy
                default_policy="$(grep '^DEFAULT_INPUT_POLICY=' "${root}/etc/default/ufw" 2>/dev/null | cut -d= -f2 | tr -d '"' || true)"
                if [[ -n "$default_policy" ]]; then
                    echo "  Default input policy: ${default_policy}"
                    if [[ "$default_policy" == "ACCEPT" ]]; then
                        echo "  [!] Default input policy is ACCEPT (permissive)"
                        findings=$((findings + 1))
                    fi
                fi

                echo ""
                echo "  User rules summary:"
                grep -E '^\-A ufw.*(ACCEPT|DROP|REJECT)' "$user_rules" 2>/dev/null | head -20 | sed 's/^/    /' || true
            fi
        else
            echo "  ufw installed on host but DISABLED"
        fi
    fi
    echo ""

    # ── nftables ────────────────────────────────────────────────────
    echo "--- nftables ---"
    if command -v nft &>/dev/null; then
        local nft_rules
        nft_rules="$(nft list ruleset 2>/dev/null || true)"
        if [[ -z "$nft_rules" ]]; then
            echo "  (no nft ruleset loaded)"
        else
            local nft_rule_count
            nft_rule_count="$(echo "$nft_rules" | grep -cE '^\s+(accept|drop|reject|counter|ct state)' || echo 0)"
            local nft_chain_count
            nft_chain_count="$(echo "$nft_rules" | grep -cE '^\s+chain ' || echo 0)"
            echo "  Chains: ${nft_chain_count}  Rules: ${nft_rule_count}"

            if [[ "$nft_rule_count" -gt 0 ]]; then
                firewall_active=true
            else
                echo "  [!] nftables loaded but contains NO rules (empty chains)"
                if ! $firewall_active; then
                    findings=$((findings + 1))
                fi
            fi

            local drop_policies
            drop_policies="$(echo "$nft_rules" | grep -c 'policy drop\|policy reject' || echo 0)"
            if [[ "$drop_policies" -gt 0 ]]; then
                echo "  Default-deny policies: ${drop_policies}"
            elif [[ "$nft_rule_count" -gt 0 ]]; then
                echo "  [!] No default-deny policy (chains default to accept)"
                findings=$((findings + 1))
            fi

            echo ""
            echo "$nft_rules" | sed 's/^/    /'
        fi
    else
        echo "  (nft not available)"

        # Check host nftables config from container
        local nft_conf="${root}/etc/nftables.conf"
        if [[ -f "$nft_conf" ]]; then
            local conf_rules
            conf_rules="$(grep -cE '(accept|drop|reject|ct state|policy)' "$nft_conf" 2>/dev/null)" || conf_rules=0
            echo "  Host nftables.conf exists (${conf_rules} rule-like lines)"
            if [[ "$conf_rules" -eq 0 ]]; then
                echo "  [!] nftables.conf has no active rules"
                if ! $firewall_active; then
                    findings=$((findings + 1))
                fi
            fi
        fi
    fi
    echo ""

    # ── iptables ────────────────────────────────────────────────────
    echo "--- iptables ---"
    if command -v iptables &>/dev/null; then
        local ipt_rules
        ipt_rules="$(iptables -S 2>/dev/null || true)"
        if [[ -n "$ipt_rules" ]]; then
            local custom_rules
            custom_rules="$(echo "$ipt_rules" | grep -cvE '^-P (INPUT|FORWARD|OUTPUT) ACCEPT$' || echo 0)"
            local total_rules
            total_rules="$(echo "$ipt_rules" | wc -l | tr -d ' ')"
            echo "  Total rules: ${total_rules}  Custom rules: ${custom_rules}"

            if [[ "$custom_rules" -gt 0 ]]; then
                firewall_active=true
            fi

            local input_policy
            input_policy="$(echo "$ipt_rules" | grep '^-P INPUT' | awk '{print $3}' || true)"
            if [[ "$input_policy" == "DROP" || "$input_policy" == "REJECT" ]]; then
                echo "  INPUT policy: ${input_policy} (good)"
            elif [[ "$input_policy" == "ACCEPT" && "$custom_rules" -eq 0 ]]; then
                echo "  [!] INPUT policy: ACCEPT with no filtering rules"
                if ! $firewall_active; then
                    findings=$((findings + 1))
                fi
            else
                echo "  INPUT policy: ${input_policy:-unknown}"
            fi

            if [[ "$custom_rules" -gt 0 && "$custom_rules" -le 50 ]]; then
                echo ""
                echo "  Filter rules:"
                echo "$ipt_rules" | grep -v '^-P' | head -30 | sed 's/^/    /'
                [[ "$custom_rules" -gt 30 ]] && echo "    ... (${custom_rules} total, showing first 30)"
            fi
        else
            echo "  (no iptables rules)"
        fi
    else
        echo "  (iptables not available)"
    fi
    echo ""

    # ── Overall assessment ──────────────────────────────────────────
    echo "--- Assessment ---"
    if $firewall_active; then
        echo "  Firewall: ACTIVE"
    else
        echo "  [!] Firewall: NO ACTIVE FIREWALL DETECTED"
        echo "      No ufw, nftables rules, or iptables filtering found."
        echo "      All network services are exposed without filtering."
        findings=$((findings + 1))
    fi

    echo ""
    log_ok "Firewall assessment complete (active: ${firewall_active}, findings: ${findings})"
}
