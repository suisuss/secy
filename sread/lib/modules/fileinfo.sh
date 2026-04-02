# Extract file metadata without reading full content
# Usage: sread fileinfo <path> [path...]

source "${SREAD_ROOT}/lib/blocklist.sh"

_entropy_estimate() {
    # Count unique byte values in first 8KB — rough entropy indicator
    # High unique count (>240) suggests encrypted/compressed/random data
    local target="$1"
    local unique
    unique="$(head -c 8192 "$target" 2>/dev/null | od -A n -t x1 | tr -s ' ' '\n' | sort -u | grep -c .)" 2>/dev/null || unique="unknown"
    echo "$unique"
}

_elf_info() {
    local target="$1"
    if command -v readelf &>/dev/null; then
        echo "--- ELF header ---"
        readelf -h "$target" 2>/dev/null | grep -E '(Class|Type|Machine|Entry point)' | sed 's/^/  /'
    else
        echo "  (readelf not available)"
    fi
}

_pdf_info() {
    local target="$1"
    if command -v pdfinfo &>/dev/null; then
        echo "--- PDF metadata ---"
        pdfinfo "$target" 2>/dev/null | head -20 | sed 's/^/  /'
    else
        echo "  (pdfinfo not available — install poppler-utils)"
    fi

    # Check for suspicious PDF keywords
    echo "--- PDF risk indicators ---"
    local suspicious=0
    for keyword in "/JavaScript" "/OpenAction" "/Launch" "/EmbeddedFile" "/RichMedia" "/XFA" "/AA"; do
        if grep -c "$keyword" "$target" 2>/dev/null | grep -qv '^0$'; then
            local count
            count="$(grep -c "$keyword" "$target" 2>/dev/null || echo 0)"
            echo "  ${keyword}: ${count} occurrence(s)"
            suspicious=1
        fi
    done
    if [[ $suspicious -eq 0 ]]; then
        echo "  (none found)"
    fi
}

_archive_info() {
    local target="$1"
    local mime="$2"

    echo "--- Archive contents (first 50 entries) ---"
    case "$mime" in
        application/zip|application/java-archive|application/vnd.openxmlformats*)
            if command -v zipinfo &>/dev/null; then
                zipinfo -1 "$target" 2>/dev/null | head -50 | sed 's/^/  /'
            else
                echo "  (zipinfo not available)"
            fi
            ;;
        application/gzip|application/x-tar|application/x-gzip)
            tar tf "$target" 2>/dev/null | head -50 | sed 's/^/  /'
            ;;
        application/x-rar*)
            echo "  (rar listing not supported)"
            ;;
        application/x-7z*)
            echo "  (7z listing not supported)"
            ;;
        *)
            echo "  (unknown archive format)"
            ;;
    esac
}

_strings_preview() {
    local target="$1"
    if command -v strings &>/dev/null; then
        echo "--- Strings preview (first 20 lines) ---"
        strings "$target" 2>/dev/null | head -20 | sed 's/^/  /'
    fi
}

run() {
    if [[ $# -eq 0 ]]; then
        echo "Usage: sread fileinfo <path> [path...]"
        echo ""
        echo "Extract metadata and risk indicators from files."
        echo "Does not read full content — safe for binaries."
        exit 1
    fi

    for target in "$@"; do
        # Respect path blocklist
        assert_path_allowed "$target"

        # Must be a regular file
        assert_regular_file "$target"

        # NOTE: Intentionally skips MIME whitelist — must inspect binaries

        section_header "FILEINFO: ${target}"

        # Basic metadata
        echo "--- stat ---"
        stat --format="  name:     %n
  size:     %s bytes
  owner:    %U:%G
  mode:     %a
  modified: %y
  changed:  %z
  accessed: %x" "$target" 2>/dev/null || echo "  (stat failed)"

        echo ""

        # MIME type and file magic
        local mime="unknown"
        local magic="unknown"
        if command -v file &>/dev/null; then
            mime="$(file --mime-type -b "$target" 2>/dev/null || echo 'unknown')"
            magic="$(file -b "$target" 2>/dev/null || echo 'unknown')"
        fi
        echo "--- type ---"
        echo "  mime:  ${mime}"
        echo "  magic: ${magic}"
        echo ""

        # SHA256 hash
        echo "--- hash ---"
        local hash
        hash="$(sha256sum "$target" 2>/dev/null | awk '{print $1}')" || hash="(failed)"
        echo "  sha256: ${hash}"
        echo ""

        # Entropy estimate
        echo "--- entropy ---"
        local unique_bytes
        unique_bytes="$(_entropy_estimate "$target")"
        echo "  unique byte values in first 8KB: ${unique_bytes}/256"
        echo ""

        # Type-specific analysis
        case "$mime" in
            application/x-executable|application/x-pie-executable|application/x-sharedlib)
                _elf_info "$target"
                echo ""
                _strings_preview "$target"
                ;;
            application/pdf)
                _pdf_info "$target"
                ;;
            application/zip|application/java-archive|application/gzip|application/x-tar|application/x-gzip|application/x-rar*|application/x-7z*|application/vnd.openxmlformats*)
                _archive_info "$target" "$mime"
                ;;
            application/vnd.ms-*)
                # Office documents (legacy format) — check for VBA macros indicator
                echo "--- office metadata ---"
                if strings "$target" 2>/dev/null | grep -q "vbaProject"; then
                    echo "  [!] VBA macro project detected"
                else
                    echo "  no VBA macros detected"
                fi
                ;;
            text/*|application/json|application/xml|application/javascript)
                # Text-like: line count and shebang only (no content — prompt injection risk)
                echo "--- text metadata ---"
                local line_count
                line_count="$(wc -l < "$target" 2>/dev/null || echo "?")"
                echo "  lines: ${line_count}"
                local first_line
                first_line="$(head -1 "$target" 2>/dev/null)" || first_line=""
                if [[ "$first_line" =~ ^#![[:space:]]*(/[a-zA-Z0-9/_.-]+) ]]; then
                    echo "  shebang: ${BASH_REMATCH[1]}"
                fi
                # File size categories for text
                local size
                size="$(stat -c%s "$target" 2>/dev/null || echo 0)"
                if [[ "$size" -gt 1048576 ]]; then
                    echo "  note: large text file (>1MB) — unusual for scripts"
                fi
                ;;
            *)
                # Unknown type — report magic only, no content extraction
                echo "  (no type-specific analysis available)"
                ;;
        esac

        echo ""
    done
}
