# Detect known CVEs in installed Debian packages via debsecan
# Usage: sread debsecan [--all] [--suite <codename>]
#
# By default, reports only CVEs with severity high/medium that have a fix
# available. --all shows every CVE returned by debsecan.
#
# Reads the host dpkg status file at /host/var/lib/dpkg/status when running
# inside the secy container, otherwise falls back to /var/lib/dpkg/status.
#
# Output is sorted and deduped so that patrol diffs remain stable across
# runs and only show genuine additions/removals (new CVE published, package
# upgraded out of vulnerability).

run() {
    section_header "DEBSECAN CVE ANALYSIS"

    local show_all=0
    local suite="bookworm"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --all)   show_all=1; shift ;;
            --suite) suite="${2:-bookworm}"; shift 2 ;;
            *) shift ;;
        esac
    done

    if ! command -v debsecan &>/dev/null; then
        log_warn "debsecan not installed in this environment"
        echo "  (install: apt-get install debsecan)"
        return 0
    fi

    local status_file="/var/lib/dpkg/status"
    [[ -f "/host/var/lib/dpkg/status" ]] && status_file="/host/var/lib/dpkg/status"

    echo "--- Source ---"
    echo "  suite:       ${suite}"
    echo "  status file: ${status_file}"
    echo "  filter:      $([[ $show_all -eq 1 ]] && echo "all CVEs" || echo "fix available, urgency not low/unimportant")"
    echo ""

    # debsecan --format detail emits blocks like:
    #   CVE-2024-1234
    #     package1 (remote, high urgency, fix available <version>)
    # We capture stderr separately so transient network issues are visible
    # but don't poison the diff.
    local raw err
    err="$(mktemp)"
    raw="$(debsecan \
            --suite "$suite" \
            --status "$status_file" \
            --format detail 2>"$err")" || true

    if [[ -s "$err" ]]; then
        echo "--- debsecan warnings ---"
        sed 's/^/  /' "$err"
        echo ""
    fi
    rm -f "$err"

    if [[ -z "$raw" ]]; then
        echo "--- Result ---"
        echo "  No CVEs reported (or debsecan failed to fetch CVE data)."
        return 0
    fi

    # Parse debsecan --format detail output into one stable line per
    # (cve, package). Real format:
    #
    #   CVE-2024-1234 (low urgency)
    #     <description text>
    #     installed: <binpkg> <version>
    #                (built from <srcpkg> <version>)
    #     fixed in unstable: <pkg> <version> (source package)
    #
    # Urgency is on the CVE line (absent = unknown). Package name comes
    # from the "installed:" line. A "fixed ..." line means a fix exists.
    # Records are flushed on blank line or next CVE header.
    local parsed
    parsed="$(awk '
        function flush() {
            if (cve != "" && pkg != "") {
                if (fix == "") fix = "none"
                printf "%-11s  %-16s  %-30s  fix=%s\n", urgency, cve, pkg, fix
            }
            cve = ""; pkg = ""; urgency = "unknown"; fix = ""
        }
        /^(CVE-|TEMP-)/ {
            flush()
            cve = $1
            if (match($0, /\((low|medium|high|unimportant) urgency\)/)) {
                urgency = substr($0, RSTART+1, RLENGTH-2)
                sub(/ urgency/, "", urgency)
            }
            next
        }
        /^[[:space:]]+installed:/ {
            # "  installed: <pkg> <version>"
            line = $0
            sub(/^[[:space:]]+installed:[[:space:]]*/, "", line)
            pkg = line
            sub(/[[:space:]].*$/, "", pkg)
            next
        }
        /^[[:space:]]+fixed (in|on)/ {
            line = $0
            sub(/^[[:space:]]+fixed (in|on)[^:]*:[[:space:]]*/, "", line)
            # Take "<pkg> <version>" up to the parens
            sub(/[[:space:]]*\(.*$/, "", line)
            fix = line
            next
        }
        /^[[:space:]]*$/ { flush() }
        END { flush() }
    ' <<< "$raw" | sort -u)"

    if [[ -z "$parsed" ]]; then
        echo "--- Result ---"
        echo "  debsecan returned data but no CVE entries were parsed."
        echo "  Raw output (first 20 lines):"
        echo "$raw" | head -20 | sed 's/^/    /'
        return 0
    fi

    # Severity buckets — counted on full set, listed per filter.
    # Most Debian CVEs carry no urgency tag at all (security team only
    # tags exceptional cases), so "unknown" is the dominant bucket and
    # should NOT be filtered out by default.
    local total high medium low unimportant unknown
    total=$(       echo "$parsed" | wc -l)
    high=$(        echo "$parsed" | grep -c '^high'        || true)
    medium=$(      echo "$parsed" | grep -c '^medium'      || true)
    low=$(         echo "$parsed" | grep -c '^low'         || true)
    unimportant=$( echo "$parsed" | grep -c '^unimportant' || true)
    unknown=$(     echo "$parsed" | grep -c '^unknown'     || true)

    echo "--- Summary ---"
    printf "  total:        %d\n" "$total"
    printf "  high:         %d\n" "$high"
    printf "  medium:       %d\n" "$medium"
    printf "  low:          %d\n" "$low"
    printf "  unimportant:  %d\n" "$unimportant"
    printf "  unknown:      %d\n" "$unknown"
    echo ""

    local filtered
    if [[ $show_all -eq 1 ]]; then
        filtered="$parsed"
        echo "--- All CVEs ---"
    else
        # Actionable: fix exists AND urgency isn't explicitly downgraded.
        # Keeps "unknown" (untriaged) entries, which is the bulk of real
        # findings on Debian.
        filtered="$(echo "$parsed" \
            | awk '$1 != "low" && $1 != "unimportant"' \
            | grep -v 'fix=none' \
            | grep -v 'undetermined' || true)"
        echo "--- Actionable CVEs (fix available, urgency not low/unimportant) ---"
    fi

    if [[ -z "$filtered" ]]; then
        echo "  (none)"
    else
        echo "$filtered" | sed 's/^/  /'
    fi
}
