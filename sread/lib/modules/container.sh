# Detect container/Docker escape vectors and misconfigurations
# Usage: sread container

run() {
    require_root

    local root=""
    [[ -d "/host/etc" ]] && root="/host"
    local proc="/proc"
    [[ -d "/host/proc" ]] && proc="/host/proc"
    local sys="/sys"
    [[ -d "/host/sys" ]] && sys="/host/sys"

    section_header "CONTAINER / DOCKER ESCAPE VECTORS"

    local findings=0

    # ── Docker socket permissions ─────────────────────────────────
    echo "--- Docker socket permissions ---"
    local docker_sock="${root}/var/run/docker.sock"
    if [[ -e "$docker_sock" ]]; then
        local sock_perms sock_owner sock_group
        sock_perms="$(stat -c '%a' "$docker_sock" 2>/dev/null || true)"
        sock_owner="$(stat -c '%U' "$docker_sock" 2>/dev/null || true)"
        sock_group="$(stat -c '%G' "$docker_sock" 2>/dev/null || true)"
        echo "  ${docker_sock}: mode=${sock_perms} owner=${sock_owner} group=${sock_group}"

        # Flag if world-readable or world-writable
        if [[ -n "$sock_perms" ]]; then
            local other_bits="${sock_perms: -1}"
            if [[ "$other_bits" -ge 4 ]]; then
                echo "  [!] Docker socket is world-readable (mode ${sock_perms})"
                findings=$((findings + 1))
            fi
            if [[ "$other_bits" -ge 2 ]]; then
                echo "  [!] Docker socket is world-writable (mode ${sock_perms})"
                findings=$((findings + 1))
            fi
        fi

        # Flag if group is not docker or root
        if [[ -n "$sock_group" && "$sock_group" != "docker" && "$sock_group" != "root" ]]; then
            echo "  [!] Docker socket group is '${sock_group}' (expected 'docker' or 'root')"
            findings=$((findings + 1))
        fi
    else
        echo "  (docker socket not found at /var/run/docker.sock)"
    fi
    echo ""

    # ── Docker group membership ───────────────────────────────────
    echo "--- Docker group membership ---"
    local group_file="${root}/etc/group"
    local docker_users=0
    if [[ -f "$group_file" ]]; then
        local docker_line
        docker_line="$(grep '^docker:' "$group_file" 2>/dev/null || true)"
        if [[ -n "$docker_line" ]]; then
            local members
            members="$(echo "$docker_line" | cut -d: -f4)"
            if [[ -n "$members" ]]; then
                IFS=',' read -ra member_arr <<< "$members"
                for user in "${member_arr[@]}"; do
                    [[ -z "$user" ]] && continue
                    if [[ "$user" != "root" ]]; then
                        echo "  [!] Non-root user '${user}' in docker group (root-equivalent access)"
                        findings=$((findings + 1))
                        docker_users=$((docker_users + 1))
                    else
                        echo "  ${user} (expected)"
                    fi
                done
                [[ $docker_users -eq 0 && ${#member_arr[@]} -eq 0 ]] && echo "  (no members)"
            else
                echo "  (docker group exists but has no members)"
            fi
        else
            echo "  (no docker group found)"
        fi
    else
        echo "  (cannot read ${group_file})"
    fi
    echo ""

    # ── Privileged containers ─────────────────────────────────────
    echo "--- Running containers (privileged / dangerous caps) ---"
    local priv_containers=0
    if command -v docker &>/dev/null; then
        local container_ids
        container_ids="$(docker ps -q 2>/dev/null || true)"
        if [[ -n "$container_ids" ]]; then
            while IFS= read -r cid; do
                [[ -z "$cid" ]] && continue
                local cname cimage cprivileged ccaps
                cname="$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's|^/||' || true)"
                cimage="$(docker inspect --format '{{.Config.Image}}' "$cid" 2>/dev/null || true)"
                cprivileged="$(docker inspect --format '{{.HostConfig.Privileged}}' "$cid" 2>/dev/null || true)"
                ccaps="$(docker inspect --format '{{.HostConfig.CapAdd}}' "$cid" 2>/dev/null || true)"

                if [[ "$cprivileged" == "true" ]]; then
                    echo "  [!] ${cname} (${cimage}): --privileged"
                    findings=$((findings + 1))
                    priv_containers=$((priv_containers + 1))
                elif [[ -n "$ccaps" && "$ccaps" != "[]" && "$ccaps" != "<no value>" ]]; then
                    local dangerous_caps="SYS_ADMIN|SYS_PTRACE|SYS_RAWIO|DAC_READ_SEARCH|NET_ADMIN"
                    if echo "$ccaps" | grep -qE "$dangerous_caps"; then
                        echo "  [!] ${cname} (${cimage}): caps=${ccaps}"
                        findings=$((findings + 1))
                        priv_containers=$((priv_containers + 1))
                    else
                        echo "  ${cname} (${cimage}): caps=${ccaps}"
                    fi
                else
                    echo "  ${cname} (${cimage}): unprivileged"
                fi
            done <<< "$container_ids"
        else
            echo "  (no running containers)"
        fi
    else
        echo "  (docker CLI not available)"
    fi
    echo ""

    # ── Sensitive host mounts ─────────────────────────────────────
    echo "--- Sensitive host mounts in containers ---"
    local mount_findings=0
    if command -v docker &>/dev/null; then
        local container_ids
        container_ids="$(docker ps -q 2>/dev/null || true)"
        if [[ -n "$container_ids" ]]; then
            while IFS= read -r cid; do
                [[ -z "$cid" ]] && continue
                local cname
                cname="$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's|^/||' || true)"
                local mounts_json
                mounts_json="$(docker inspect --format '{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' "$cid" 2>/dev/null || true)"
                [[ -z "$mounts_json" ]] && continue

                for mount_pair in $mounts_json; do
                    local src
                    src="$(echo "$mount_pair" | cut -d: -f1)"
                    case "$src" in
                        /|/etc|/etc/*)
                            echo "  [!] ${cname}: host ${mount_pair}"
                            findings=$((findings + 1))
                            mount_findings=$((mount_findings + 1))
                            ;;
                        /var/run/docker.sock)
                            echo "  [!] ${cname}: docker socket mounted (${mount_pair})"
                            findings=$((findings + 1))
                            mount_findings=$((mount_findings + 1))
                            ;;
                        /proc|/sys|/dev)
                            echo "  [!] ${cname}: host ${mount_pair}"
                            findings=$((findings + 1))
                            mount_findings=$((mount_findings + 1))
                            ;;
                        *)
                            ;;
                    esac
                done
            done <<< "$container_ids"
            [[ $mount_findings -eq 0 ]] && echo "  (no sensitive host mounts detected)"
        else
            echo "  (no running containers)"
        fi
    else
        echo "  (docker CLI not available)"
    fi
    echo ""

    # ── Container escape indicators (from inside a container) ─────
    echo "--- Container environment detection ---"
    local inside_container="no"

    # Check /proc/1/cgroup for container indicators
    local cgroup_file="${proc}/1/cgroup"
    if [[ -f "$cgroup_file" ]]; then
        if grep -qE 'docker|containerd|kubepods|lxc' "$cgroup_file" 2>/dev/null; then
            echo "  [!] Running INSIDE a container (detected via /proc/1/cgroup)"
            inside_container="yes"
            findings=$((findings + 1))
        else
            echo "  Not running inside a container (per /proc/1/cgroup)"
        fi
    fi

    # Check for .dockerenv
    if [[ -f "${root}/.dockerenv" ]]; then
        echo "  [!] /.dockerenv exists (container indicator)"
        inside_container="yes"
        findings=$((findings + 1))
    fi
    echo ""

    # ── Dangerous capabilities (escape potential) ─────────────────
    echo "--- Effective capabilities (escape potential) ---"
    local capeff_file="${proc}/self/status"
    if [[ -f "$capeff_file" ]]; then
        local capeff
        capeff="$(grep '^CapEff:' "$capeff_file" 2>/dev/null | awk '{print $2}' || true)"
        if [[ -n "$capeff" ]]; then
            echo "  CapEff: 0x${capeff}"

            # Decode known dangerous capabilities
            # CapEff is a hex bitmask. Key bits:
            #   CAP_SYS_ADMIN  = bit 21 (0x200000)
            #   CAP_SYS_PTRACE = bit 19 (0x80000)
            #   CAP_SYS_RAWIO  = bit 17 (0x20000)
            #   CAP_NET_ADMIN  = bit 12 (0x1000)
            #   CAP_DAC_READ_SEARCH = bit 2 (0x4)
            local capeff_dec
            capeff_dec=$((16#${capeff}))

            if (( capeff_dec & 0x200000 )); then
                echo "  [!] CAP_SYS_ADMIN is set (container escape via cgroup/mount)"
                findings=$((findings + 1))
            fi
            if (( capeff_dec & 0x80000 )); then
                echo "  [!] CAP_SYS_PTRACE is set (process injection possible)"
                findings=$((findings + 1))
            fi
            if (( capeff_dec & 0x20000 )); then
                echo "  [!] CAP_SYS_RAWIO is set (raw I/O access)"
                findings=$((findings + 1))
            fi
            if (( capeff_dec & 0x1000 )); then
                echo "  [!] CAP_NET_ADMIN is set (network namespace manipulation)"
                findings=$((findings + 1))
            fi
            if (( capeff_dec & 0x4 )); then
                echo "  [!] CAP_DAC_READ_SEARCH is set (bypass file read permissions)"
                findings=$((findings + 1))
            fi

            # Full capabilities = likely privileged container
            if [[ "$capeff" == "0000003fffffffff" || "$capeff" == "000001ffffffffff" ]]; then
                echo "  [!] Full capability set detected (privileged container or host root)"
                findings=$((findings + 1))
            fi
        else
            echo "  (could not read CapEff)"
        fi
    else
        echo "  (cannot read ${capeff_file})"
    fi
    echo ""

    # ── Cgroup release_agent escape ───────────────────────────────
    echo "--- Cgroup release_agent (escape vector) ---"
    local release_found=0
    local cgroup_base="${sys}/fs/cgroup"
    if [[ -d "$cgroup_base" ]]; then
        while IFS= read -r agent_file; do
            if [[ -w "$agent_file" ]]; then
                echo "  [!] Writable release_agent: ${agent_file}"
                findings=$((findings + 1))
                release_found=$((release_found + 1))
            fi
        done < <(find "$cgroup_base" -name "release_agent" -type f 2>/dev/null || true)
        [[ $release_found -eq 0 ]] && echo "  (no writable release_agent files)"
    else
        echo "  (cgroup filesystem not found at ${cgroup_base})"
    fi
    echo ""

    # ── Summary ───────────────────────────────────────────────────
    echo "--- Summary ---"
    echo "  Inside container: ${inside_container}"
    echo "  Docker group non-root users: ${docker_users}"
    echo "  Privileged/dangerous containers: ${priv_containers}"
    echo "  Sensitive host mounts: ${mount_findings}"
    echo "  Writable release_agents: ${release_found}"
    echo "  Total findings: ${findings}"

    echo ""
    log_ok "Container escape scan complete (findings: ${findings}, inside_container: ${inside_container})"
}
