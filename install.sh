#!/usr/bin/env bash
# secy installer — sets up sudoers rule and binary permissions
#
# Usage: sudo ./install.sh [--uninstall]

set -euo pipefail

SECY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_BIN="/usr/local/bin/secy"
INSTALL_LIB="/usr/local/lib/secy"
SUDOERS_FILE="/etc/sudoers.d/secy"
AUDIT_GROUP="secy-audit"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RESET='\033[0m'

log_info()  { echo -e "${GREEN}[install]${RESET} $*"; }
log_warn()  { echo -e "${YELLOW}[install]${RESET} $*"; }
log_error() { echo -e "${RED}[install]${RESET} $*" >&2; }

if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root: sudo ./install.sh"
    exit 1
fi

uninstall() {
    log_info "Uninstalling secy..."
    rm -f "$INSTALL_BIN"
    rm -rf "$INSTALL_LIB"
    rm -f "$SUDOERS_FILE"
    log_info "Removed ${INSTALL_BIN}, ${INSTALL_LIB}, ${SUDOERS_FILE}"
    log_warn "The '${AUDIT_GROUP}' group was not removed. Remove manually if desired:"
    log_warn "  groupdel ${AUDIT_GROUP}"
}

install() {
    log_info "Installing secy..."

    # Create the audit group if it doesn't exist
    if ! getent group "$AUDIT_GROUP" &>/dev/null; then
        groupadd "$AUDIT_GROUP"
        log_info "Created group: ${AUDIT_GROUP}"
    else
        log_info "Group already exists: ${AUDIT_GROUP}"
    fi

    # Copy library files
    mkdir -p "$INSTALL_LIB"
    cp -r "${SECY_ROOT}/lib/"* "$INSTALL_LIB/"
    cp -r "${SECY_ROOT}/conf" "$INSTALL_LIB/"

    # Set ownership and permissions on library
    chown -R root:root "$INSTALL_LIB"
    chmod -R 755 "$INSTALL_LIB"
    # Config files should not be writable by anyone but root
    chmod 644 "$INSTALL_LIB"/conf/*

    # Install the binary — rewrite SECY_ROOT to point to installed location
    sed "s|^SECY_ROOT=.*|SECY_ROOT=\"${INSTALL_LIB}\"|" "${SECY_ROOT}/bin/secy" > "$INSTALL_BIN"
    chown root:root "$INSTALL_BIN"
    chmod 755 "$INSTALL_BIN"

    log_info "Installed binary: ${INSTALL_BIN}"
    log_info "Installed library: ${INSTALL_LIB}"

    # Install sudoers rule
    cp "${SECY_ROOT}/conf/secy.sudoers" "$SUDOERS_FILE"
    chmod 0440 "$SUDOERS_FILE"
    chown root:root "$SUDOERS_FILE"

    # Validate sudoers syntax
    if visudo -cf "$SUDOERS_FILE" &>/dev/null; then
        log_info "Sudoers rule installed and validated: ${SUDOERS_FILE}"
    else
        log_error "Sudoers syntax error! Removing invalid file."
        rm -f "$SUDOERS_FILE"
        exit 1
    fi

    # Create audit log file
    touch /var/log/secy-audit.log
    chmod 640 /var/log/secy-audit.log
    chown root:root /var/log/secy-audit.log

    echo ""
    log_info "Installation complete."
    echo ""
    echo "Next steps:"
    echo "  1. Add users to the '${AUDIT_GROUP}' group:"
    echo "     sudo usermod -aG ${AUDIT_GROUP} <username>"
    echo ""
    echo "  2. Log out and back in (or run: newgrp ${AUDIT_GROUP})"
    echo ""
    echo "  3. Test: sudo secy --capabilities"
}

case "${1:-}" in
    --uninstall) uninstall ;;
    *)           install ;;
esac
