# Detect EFI/firmware implants and BMC/IPMI presence from userspace
# Usage: sread firmware

run() {
    require_root

    local proc="/proc"
    [[ -d "/host/proc" ]] && proc="/host/proc"
    local sys="/sys"
    [[ -d "/host/sys" ]] && sys="/host/sys"

    section_header "FIRMWARE / EFI ANALYSIS"

    echo "NOTE: Firmware analysis from userspace is inherently limited."
    echo "      Full verification requires offline analysis with trusted media."
    echo ""

    # ── UEFI Secure Boot state ─────────────────────────────────────
    echo "--- UEFI Secure Boot state ---"
    local efi_dir="${sys}/firmware/efi"
    if [[ -d "$efi_dir" ]]; then
        echo "  Boot mode: UEFI"

        # Try reading SecureBoot EFI variable
        local sb_found=false
        for sb_file in "${efi_dir}"/efivars/SecureBoot-*; do
            [[ -f "$sb_file" ]] || continue
            sb_found=true
            # EFI var format: 4-byte attributes + payload
            # SecureBoot payload is 1 byte: 0x01 = enabled, 0x00 = disabled
            local sb_val
            sb_val="$(od -An -tx1 -j4 -N1 "$sb_file" 2>/dev/null | tr -d ' ')"
            if [[ "$sb_val" == "01" ]]; then
                echo "  Secure Boot: ENABLED"
            elif [[ "$sb_val" == "00" ]]; then
                echo "  [!] Secure Boot: DISABLED"
            else
                echo "  Secure Boot: unknown value (${sb_val:-?})"
            fi
            break
        done

        # Fallback: try mokutil
        if ! $sb_found; then
            if command -v mokutil &>/dev/null; then
                local mok_state
                mok_state="$(mokutil --sb-state 2>/dev/null || true)"
                if [[ -n "$mok_state" ]]; then
                    echo "  ${mok_state}"
                    if echo "$mok_state" | grep -qi "disabled"; then
                        echo "  [!] Secure Boot appears disabled"
                    fi
                else
                    echo "  (mokutil returned no output)"
                fi
            else
                echo "  (cannot determine Secure Boot state — no efivars or mokutil)"
            fi
        fi
    else
        echo "  Boot mode: Legacy BIOS (no EFI detected)"
        echo "  Secure Boot: N/A"
    fi
    echo ""

    # ── EFI boot entries ───────────────────────────────────────────
    echo "--- EFI boot entries ---"
    local efivars_dir="${efi_dir}/efivars"
    local boot_entries=0
    local large_vars=0
    if [[ -d "$efivars_dir" ]]; then
        # Read BootOrder
        for bo_file in "${efivars_dir}"/BootOrder-*; do
            [[ -f "$bo_file" ]] || continue
            local bo_hex
            bo_hex="$(od -An -tx2 -j4 "$bo_file" 2>/dev/null | tr -d ' \n')"
            if [[ -n "$bo_hex" ]]; then
                echo "  Boot order: ${bo_hex}"
            fi
            break
        done

        # List Boot0* entries
        for boot_file in "${efivars_dir}"/Boot0*; do
            [[ -f "$boot_file" ]] || continue
            local boot_name
            boot_name="$(basename "$boot_file")"
            boot_name="${boot_name%%-*}"
            local boot_desc
            boot_desc="$(strings "$boot_file" 2>/dev/null | head -3 | tr '\n' ' ')"
            local boot_size
            boot_size="$(stat -c%s "$boot_file" 2>/dev/null || echo 0)"

            boot_entries=$((boot_entries + 1))
            if [[ "$boot_size" -gt 4096 ]]; then
                echo "  [!] ${boot_name}: ${boot_desc}(${boot_size} bytes — unusually large)"
                large_vars=$((large_vars + 1))
            else
                echo "  ${boot_name}: ${boot_desc}(${boot_size} bytes)"
            fi
        done
        [[ $boot_entries -eq 0 ]] && echo "  (no boot entries found)"
    else
        echo "  (EFI variables not accessible)"
    fi
    echo ""

    # ── EFI variable overview ──────────────────────────────────────
    echo "--- EFI variable overview ---"
    if [[ -d "$efivars_dir" ]]; then
        local total_vars=0
        local large_total=0
        for var_file in "${efivars_dir}"/*; do
            [[ -f "$var_file" ]] || continue
            total_vars=$((total_vars + 1))
            local var_size
            var_size="$(stat -c%s "$var_file" 2>/dev/null || echo 0)"
            if [[ "$var_size" -gt 4096 ]]; then
                local var_name
                var_name="$(basename "$var_file")"
                echo "  [!] Large efivar: ${var_name} (${var_size} bytes)"
                large_total=$((large_total + 1))
            fi
        done
        echo "  Total EFI variables: ${total_vars}"
        echo "  Variables > 4KB: ${large_total}"
    else
        echo "  (EFI variables not accessible)"
    fi
    echo ""

    # ── BMC / IPMI presence ────────────────────────────────────────
    echo "--- BMC / IPMI presence ---"
    local ipmi_found=0

    # Check /dev/ipmi0
    if [[ -c "${sys%/sys}/dev/ipmi0" ]] || [[ -c "/dev/ipmi0" ]]; then
        echo "  [!] /dev/ipmi0 exists (IPMI device present)"
        ipmi_found=$((ipmi_found + 1))
    fi

    # Check IPMI kernel modules
    local modules_file="${proc}/modules"
    if [[ -f "$modules_file" ]]; then
        local ipmi_mods
        ipmi_mods="$(grep -iE '^ipmi_' "$modules_file" 2>/dev/null || true)"
        if [[ -n "$ipmi_mods" ]]; then
            echo "  IPMI kernel modules loaded:"
            echo "$ipmi_mods" | while IFS= read -r line; do
                echo "    $(echo "$line" | awk '{print $1}')"
            done
            ipmi_found=$((ipmi_found + 1))
        fi
    fi

    # Try ipmitool if available
    if command -v ipmitool &>/dev/null; then
        local bmc_info
        bmc_info="$(ipmitool bmc info 2>/dev/null | head -5 || true)"
        if [[ -n "$bmc_info" ]]; then
            echo "  BMC info (ipmitool):"
            echo "$bmc_info" | sed 's/^/    /'
            ipmi_found=$((ipmi_found + 1))
        fi
    fi

    # Check for IPMI network interfaces
    local ipmi_net
    ipmi_net="$(ip link show 2>/dev/null | grep -i 'ipmi\|bmc' || true)"
    if [[ -n "$ipmi_net" ]]; then
        echo "  IPMI network interfaces:"
        echo "$ipmi_net" | sed 's/^/    /'
        ipmi_found=$((ipmi_found + 1))
    fi

    [[ $ipmi_found -eq 0 ]] && echo "  (no BMC/IPMI detected)"
    echo ""

    # ── Summary ────────────────────────────────────────────────────
    echo "--- Summary ---"
    echo "  Boot mode: $(if [[ -d "$efi_dir" ]]; then echo "UEFI"; else echo "Legacy BIOS"; fi)"
    echo "  EFI boot entries: ${boot_entries}"
    echo "  Large EFI variables (>4KB): ${large_vars}"
    echo "  BMC/IPMI indicators: ${ipmi_found}"

    echo ""
    log_ok "Firmware scan complete (boot_entries: ${boot_entries}, large_vars: ${large_vars}, ipmi: ${ipmi_found})"
}
