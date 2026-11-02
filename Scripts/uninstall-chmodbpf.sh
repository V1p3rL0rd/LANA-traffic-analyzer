#!/usr/bin/env bash
# Removes the LANA ChmodBPF daemon and restores default /dev/bpf* permissions.
# The access_bpf group is kept when Wireshark still uses it (pass --remove-group to force).
set -euo pipefail

readonly LABEL="app.lana.ChmodBPF"
readonly GROUP="access_bpf"
readonly PLIST="/Library/LaunchDaemons/${LABEL}.plist"
readonly SUPPORT_DIR="/Library/Application Support/LANA"

log() { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }
trap 'die "aborted at line ${LINENO}"' ERR

REMOVE_GROUP=0
[[ "${1:-}" == "--remove-group" ]] && REMOVE_GROUP=1
[[ "$(uname -s)" == "Darwin" ]] || die "macOS only"
[[ "${EUID}" -eq 0 ]] || die "run with sudo"

launchctl bootout "system/${LABEL}" 2>/dev/null || true
rm -f "${PLIST}"
rm -rf "${SUPPORT_DIR}"
log "daemon removed"

if [[ ! -f /Library/LaunchDaemons/org.wireshark.ChmodBPF.plist ]]; then
    chgrp wheel /dev/bpf* && chmod g-rw /dev/bpf*
    log "/dev/bpf* permissions restored"
    if [[ ${REMOVE_GROUP} -eq 1 ]] && dseditgroup -q -o read "${GROUP}" >/dev/null 2>&1; then
        dseditgroup -q -o delete "${GROUP}"
        log "group ${GROUP} deleted"
    fi
else
    log "Wireshark ChmodBPF still installed — leaving /dev/bpf* permissions and group intact"
fi
