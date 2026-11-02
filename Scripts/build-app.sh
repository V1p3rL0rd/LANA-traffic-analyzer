#!/usr/bin/env bash
# Builds "LANA Traffic Analyzer.app" from the Swift package, signs it and (optionally) installs it.
#
#   Scripts/build-app.sh                 # release build for the host arch -> "build/LANA Traffic Analyzer.app"
#   Scripts/build-app.sh --install       # also install to /Applications (or $INSTALL_DIR) -> Launchpad, Spotlight, Dock
#   Scripts/build-app.sh --universal     # arm64 + x86_64 (requires full Xcode, not just CLT)
#
#   SIGN_IDENTITY="Developer ID Application: …" Scripts/build-app.sh   # default: ad-hoc
#
# Idempotent: every run rebuilds the bundle in a temp dir and atomically replaces the old one.
set -euo pipefail

readonly APP_NAME="LANA Traffic Analyzer"   # bundle / display name
readonly EXEC_NAME="LANA"                   # SwiftPM product (binary inside the bundle)
readonly LEGACY_APP_NAMES=("LANA")          # earlier bundle names, removed on --install
readonly SIGN_IDENTITY="${SIGN_IDENTITY:--}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT
readonly OUT_DIR="${ROOT}/build"
readonly APP="${OUT_DIR}/${APP_NAME}.app"

UNIVERSAL="${UNIVERSAL:-0}"
INSTALL=0
STAGE=""

log()  { printf '\033[1;34m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
warn() { printf '\033[1;33m[%s] WARN:\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die()  { printf '\033[1;31m[%s] ERROR:\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; exit 1; }

cleanup() {
    if [[ -n "${STAGE}" && -d "${STAGE}" ]]; then rm -rf "${STAGE}"; fi
}
trap cleanup EXIT
trap 'die "interrupted"' INT TERM
trap 'die "failed at line ${LINENO}: ${BASH_COMMAND}"' ERR

usage() { sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install)   INSTALL=1 ;;
        --universal) UNIVERSAL=1 ;;
        -h|--help)   usage 0 ;;
        *)           warn "unknown option: $1"; usage 2 ;;
    esac
    shift
done

[[ "$(uname -s)" == "Darwin" ]] || die "this script must run on macOS"
[[ "${EUID}" -ne 0 ]] || die "do not build as root: .build/ and build/ would become root-owned (use your own user)"
command -v swift >/dev/null    || die "swift not found — install Command Line Tools: xcode-select --install"
command -v codesign >/dev/null || die "codesign not found"

cd "${ROOT}"

ARCH_ARGS=()
if [[ "${UNIVERSAL}" == "1" ]]; then
    ARCH_ARGS=(--arch arm64 --arch x86_64)
    log "building universal binary (arm64 + x86_64)"
else
    log "building for $(uname -m)"
fi

swift build -c release ${ARCH_ARGS[@]+"${ARCH_ARGS[@]}"}
# Multi-arch builds go through xcbuild and land in .build/apple; --show-bin-path is unreliable there.
if [[ ${#ARCH_ARGS[@]} -gt 0 ]]; then
    BIN_DIR="${ROOT}/.build/apple/Products/Release"
else
    BIN_DIR="$(swift build -c release --show-bin-path)"
fi
[[ -x "${BIN_DIR}/${EXEC_NAME}" ]] || die "binary not found in ${BIN_DIR}"

mkdir -p "${OUT_DIR}"
STAGE="$(mktemp -d "${OUT_DIR}/.stage.XXXXXX")"
BUNDLE="${STAGE}/${APP_NAME}.app"
mkdir -p "${BUNDLE}/Contents/MacOS" "${BUNDLE}/Contents/Resources"
cp "${BIN_DIR}/${EXEC_NAME}" "${BUNDLE}/Contents/MacOS/${EXEC_NAME}"
cp "${ROOT}/Resources/Info.plist" "${BUNDLE}/Contents/Info.plist"
plutil -lint "${BUNDLE}/Contents/Info.plist" >/dev/null

# App icon (source: Assets/AppIcon.svg, same visual language as LANA Scanner).
if [[ -f "${ROOT}/Assets/AppIcon.icns" ]]; then
    cp "${ROOT}/Assets/AppIcon.icns" "${BUNDLE}/Contents/Resources/AppIcon.icns"
else
    warn "Assets/AppIcon.icns not found — building without an icon"
fi

log "codesign (${SIGN_IDENTITY})"
codesign --force --options runtime --timestamp=none \
    --entitlements "${ROOT}/Resources/LANA.entitlements" \
    --sign "${SIGN_IDENTITY}" "${BUNDLE}"
codesign --verify --strict "${BUNDLE}"

rm -rf "${APP}" "${OUT_DIR}/LANA.app"
mv "${BUNDLE}" "${APP}"
log "built ${APP} ($(lipo -archs "${APP}/Contents/MacOS/${EXEC_NAME}" 2>/dev/null || echo "?"))"

if [[ ${INSTALL} -eq 1 ]]; then
    DEST="${INSTALL_DIR:-/Applications}"
    mkdir -p "${DEST}"
    [[ -w "${DEST}" ]] || die "${DEST} is not writable — run as an admin user or set INSTALL_DIR=~/Applications"
    for legacy in "${LEGACY_APP_NAMES[@]}"; do
        if [[ -d "${DEST}/${legacy}.app" ]]; then
            rm -rf "${DEST:?}/${legacy}.app"
            log "removed old ${DEST}/${legacy}.app"
        fi
    done
    rm -rf "${DEST:?}/${APP_NAME}.app"
    ditto "${APP}" "${DEST}/${APP_NAME}.app"
    # Make Finder/Dock/Launchpad pick up the icon instead of a cached generic one.
    touch "${DEST}/${APP_NAME}.app"
    LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
    if [[ -x "${LSREGISTER}" ]]; then "${LSREGISTER}" -f "${DEST}/${APP_NAME}.app" || true; fi
    log "installed to ${DEST}/${APP_NAME}.app"
fi

if [[ ${INSTALL} -eq 1 ]]; then
    log "run: open \"${DEST}/${APP_NAME}.app\" (or find it in Launchpad / Spotlight)"
else
    log "run: open \"${APP}\"   — add --install to put it into /Applications"
fi
