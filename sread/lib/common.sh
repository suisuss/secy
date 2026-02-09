#!/usr/bin/env bash
# sread/lib/common.sh — Shared utilities for sread modules

set -euo pipefail

SREAD_ROOT="${SREAD_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SREAD_CONF="${SREAD_ROOT}/conf"
SREAD_LIB="${SREAD_ROOT}/lib"

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

log_info()  { echo -e "${BLUE}[sread]${RESET} $*"; }
log_warn()  { echo -e "${YELLOW}[sread:warn]${RESET} $*" >&2; }
log_error() { echo -e "${RED}[sread:error]${RESET} $*" >&2; }
log_ok()    { echo -e "${GREEN}[sread:ok]${RESET} $*"; }

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
        log_error "This module requires root privileges. Run via: sudo sread $*"
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

# Warn if running inside the Docker agent container where host commands
# show container state, not host state.  Modules that rely on commands
# like ss, systemctl, iptables, or sysctl should call this.
warn_if_container() {
    if [[ -d "/host/etc" ]]; then
        log_warn "Running inside container — this module shows CONTAINER state, not host."
        log_warn "For host state, read files under /host/ directly (see AGENT.md)."
    fi
}
