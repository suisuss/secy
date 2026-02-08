#!/usr/bin/env bash
# secy/lib/common.sh — Shared utilities for secy modules

set -euo pipefail

SECY_ROOT="${SECY_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SECY_CONF="${SECY_ROOT}/conf"
SECY_LIB="${SECY_ROOT}/lib"

# Colors (disabled if not a terminal)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' BOLD='' RESET=''
fi

log_info()  { echo -e "${BLUE}[secy]${RESET} $*"; }
log_warn()  { echo -e "${YELLOW}[secy:warn]${RESET} $*" >&2; }
log_error() { echo -e "${RED}[secy:error]${RESET} $*" >&2; }
log_ok()    { echo -e "${GREEN}[secy:ok]${RESET} $*"; }

# Section headers for report output
section_header() {
    local title="$1"
    echo ""
    echo "================================================================"
    echo "  ${title}"
    echo "================================================================"
    echo ""
}

# Check if running as root (via sudo)
require_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This module requires root privileges. Run via: sudo secy $*"
        exit 1
    fi
}

# Check if a command exists
require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" &>/dev/null; then
        log_error "Required command not found: ${cmd}"
        exit 1
    fi
}
