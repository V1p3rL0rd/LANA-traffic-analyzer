#!/usr/bin/env bash
# Grants members of the `access_bpf` group read/write access to /dev/bpf* at every boot,
# so LANA captures without running as root (same model as Wireshark's ChmodBPF).
# Idempotent: re-running only re-applies state. Requires root.
set -euo pipefail

readonly LABEL="app.lana.ChmodBPF"
readonly GROUP="access_bpf"
readonly SUPPORT_DIR="/Library/Application Support/LANA/ChmodBPF"
readonly HELPER="${SUPPORT_DIR}/ChmodBPF"
readonly PLIST="/Library/LaunchDaemons/${LABEL}.plist"
readonly WIRESHARK_PLIST="/Library/LaunchDaemons/org.wireshark.ChmodBPF.plist"

log()  { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
die()  { printf '[ERROR] %s\n' "$*" >&2; exit 1; }
trap 'die "aborted at line ${LINENO}"' ERR
trap 'die "interrupted"' INT TERM

usage() {
    cat <<EOF
Usage: sudo $0 [--user <name>]
  --user  account to add to the '${GROUP}' group (default: \$SUDO_USER)
EOF
}

TARGET_USER="${SUDO_USER:-}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --user) TARGET_USER="${2:-}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage; die "unknown argument: $1" ;;
    esac
done

[[ "$(uname -s)" == "Darwin" ]] || die "macOS only"
[[ "${EUID}" -eq 0 ]] || die "run with sudo"
[[ -n "${TARGET_USER}" && "${TARGET_USER}" != "root" ]] || die "cannot determine target user; pass --user <name>"
id "${TARGET_USER}" >/dev/null 2>&1 || die "user '${TARGET_USER}' does not exist"

# 1. Group
if dseditgroup -q -o read "${GROUP}" >/dev/null 2>&1; then
    log "group ${GROUP} exists"
else
    log "creating group ${GROUP}"
    dseditgroup -q -o create -r "BPF device access (packet capture)" "${GROUP}"
fi

if dseditgroup -o checkmember -m "${TARGET_USER}" "${GROUP}" >/dev/null 2>&1; then
    log "user ${TARGET_USER} already in ${GROUP}"
else
    log "adding ${TARGET_USER} to ${GROUP}"
    dseditgroup -q -o edit -a "${TARGET_USER}" -t user "${GROUP}"
fi

# 2. Boot-time helper. Wireshark's daemon does the same job — don't install a second one.
if [[ -f "${WIRESHARK_PLIST}" ]]; then
    log "Wireshark ChmodBPF detected (${WIRESHARK_PLIST}) — reusing it, skipping daemon install"
else
    install -d -m 0755 -o root -g wheel "${SUPPORT_DIR}"
    cat > "${HELPER}.tmp" <<'HELPER_EOF'
#!/bin/bash
# Pre-create BPF clones (macOS creates /dev/bpfN lazily) and open them to the access_bpf group.
set -u
MAX=256
SYSCTL_MAX=$(sysctl -n debug.bpf_maxdevices 2>/dev/null || echo 256)
[ "$MAX" -gt "$SYSCTL_MAX" ] && MAX=$SYSCTL_MAX
i=0
while [ "$i" -lt "$MAX" ]; do
    read -r -n 0 2>/dev/null < "/dev/bpf$i" > /dev/null
    i=$((i + 1))
done
chgrp access_bpf /dev/bpf*
chmod g+rw /dev/bpf*
logger -t ChmodBPF "permissions set on /dev/bpf0-$((MAX - 1))"
HELPER_EOF
    install -m 0755 -o root -g wheel "${HELPER}.tmp" "${HELPER}"
    rm -f "${HELPER}.tmp"

    cat > "${PLIST}.tmp" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array><string>${HELPER}</string></array>
    <key>RunAtLoad</key><true/>
</dict>
</plist>
PLIST_EOF
    plutil -lint "${PLIST}.tmp" >/dev/null
    install -m 0644 -o root -g wheel "${PLIST}.tmp" "${PLIST}"
    rm -f "${PLIST}.tmp"

    log "loading launch daemon ${LABEL}"
    launchctl bootout "system/${LABEL}" 2>/dev/null || true
    launchctl bootstrap system "${PLIST}"
fi

# 3. Apply now (no reboot needed)
if [[ -x "${HELPER}" ]]; then "${HELPER}"; else chgrp "${GROUP}" /dev/bpf* && chmod g+rw /dev/bpf*; fi

log "done. Log out and back in (or reboot) so '${TARGET_USER}' picks up the new group membership."
log "verify: ls -l /dev/bpf0   → crw-rw----  root  ${GROUP}"
