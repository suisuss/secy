#!/usr/bin/env bash
# Tests for MIME type checking

set -euo pipefail

SREAD_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export SREAD_ROOT
source "${SREAD_ROOT}/lib/blocklist.sh"

PASS=0
FAIL=0
inc_pass() { PASS=$((PASS + 1)); }
inc_fail() { FAIL=$((FAIL + 1)); }

TMPDIR="$(mktemp -d /tmp/sread-mime-test.XXXXXX)"
trap "rm -rf '$TMPDIR'" EXIT

# Create test files with known content
create_text_file()   { echo "PermitRootLogin no" > "${TMPDIR}/sshd_config"; }
create_json_file()   { echo '{"key": "value"}' > "${TMPDIR}/config.json"; }
create_xml_file()    { echo '<?xml version="1.0"?><root/>' > "${TMPDIR}/config.xml"; }
create_shell_file()  { echo '#!/bin/bash' > "${TMPDIR}/script.sh"; }
create_empty_file()  { touch "${TMPDIR}/empty"; }
create_binary_file() { printf '\x7fELF\x02\x01\x01' > "${TMPDIR}/binary.elf"; }
create_image_file()  { printf '\x89PNG\r\n\x1a\n' > "${TMPDIR}/image.png"; }
create_gzip_file()   { printf '\x1f\x8b\x08' > "${TMPDIR}/archive.gz"; }
create_sqlite_file() { printf 'SQLite format 3\x00' > "${TMPDIR}/data.sqlite"; }
create_pdf_file()    { printf '%%PDF-1.4' > "${TMPDIR}/document.pdf"; }

assert_mime_allowed() {
    local file="$1"
    local desc="$2"
    if is_mimetype_allowed "$file"; then
        echo "  PASS: allowed ${desc} ($(file --mime-type -b "$file"))"
        inc_pass
    else
        echo "  FAIL: expected '${desc}' to be allowed ($(file --mime-type -b "$file"))"
        inc_fail
    fi
}

assert_mime_blocked() {
    local file="$1"
    local desc="$2"
    if is_mimetype_allowed "$file"; then
        echo "  FAIL: expected '${desc}' to be blocked ($(file --mime-type -b "$file"))"
        inc_fail
    else
        echo "  PASS: blocked ${desc} ($(file --mime-type -b "$file"))"
        inc_pass
    fi
}

echo "=== MIME Type Tests ==="
echo ""

# Create all test files
create_text_file
create_json_file
create_xml_file
create_shell_file
create_empty_file
create_binary_file
create_image_file
create_gzip_file
create_sqlite_file
create_pdf_file

echo "-- Should be ALLOWED (text/config files) --"
assert_mime_allowed "${TMPDIR}/sshd_config" "text config file"
assert_mime_allowed "${TMPDIR}/config.json" "JSON file"
assert_mime_allowed "${TMPDIR}/config.xml" "XML file"
assert_mime_allowed "${TMPDIR}/script.sh" "shell script"
assert_mime_allowed "${TMPDIR}/empty" "empty file"

echo ""
echo "-- Should be BLOCKED (binary/non-text files) --"
assert_mime_blocked "${TMPDIR}/binary.elf" "ELF binary"
assert_mime_blocked "${TMPDIR}/image.png" "PNG image"
assert_mime_blocked "${TMPDIR}/archive.gz" "gzip archive"
assert_mime_blocked "${TMPDIR}/data.sqlite" "SQLite database"
assert_mime_blocked "${TMPDIR}/document.pdf" "PDF document"

echo ""
echo "-- System files (if readable) --"
if [[ -r /etc/passwd ]]; then
    assert_mime_allowed "/etc/passwd" "/etc/passwd"
fi
if [[ -r /etc/hosts ]]; then
    assert_mime_allowed "/etc/hosts" "/etc/hosts"
fi
if [[ -r /usr/bin/env ]]; then
    assert_mime_blocked "/usr/bin/env" "/usr/bin/env (binary)"
fi

echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
