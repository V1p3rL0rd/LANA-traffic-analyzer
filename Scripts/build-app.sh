#!/usr/bin/env bash
# Builds LANA.app (release) for the host arch. UNIVERSAL=1 adds x86_64 (deprecated on macOS 26+).
#   SIGN_IDENTITY="Developer ID Application: …" ./Scripts/build-app.sh   # default: ad-hoc
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT
readonly APP="${ROOT}/build/LANA.app"
readonly SIGN_IDENTITY="${SIGN_IDENTITY:--}"
readonly UNIVERSAL="${UNIVERSAL:-0}"

log() { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }
trap 'die "build failed at line ${LINENO}"' ERR
trap 'die "interrupted"' INT TERM

[[ "$(uname -s)" == "Darwin" ]] || die "macOS only"
command -v swift >/dev/null || die "swift not found (install Xcode 15+ or Command Line Tools)"

cd "${ROOT}"
ARCH_FLAGS=()
[[ "${UNIVERSAL}" == "1" ]] && ARCH_FLAGS=(--arch arm64 --arch x86_64)

log "swift build -c release ${ARCH_FLAGS[*]:-}"
swift build -c release ${ARCH_FLAGS[@]+"${ARCH_FLAGS[@]}"}
# Multi-arch builds go through xcbuild and land in .build/apple; --show-bin-path is unreliable there.
if [[ ${#ARCH_FLAGS[@]} -gt 0 ]]; then
    BIN_DIR="${ROOT}/.build/apple/Products/Release"
else
    BIN_DIR="$(swift build -c release --show-bin-path)"
fi
[[ -x "${BIN_DIR}/LANA" ]] || die "binary not found in ${BIN_DIR}"

log "assembling ${APP}"
rm -rf "${APP}"
install -d "${APP}/Contents/MacOS" "${APP}/Contents/Resources"
install -m 0755 "${BIN_DIR}/LANA" "${APP}/Contents/MacOS/LANA"
install -m 0644 "${ROOT}/Resources/Info.plist" "${APP}/Contents/Info.plist"
# App icon (source: Assets/AppIcon.svg, same visual language as LANA Scanner).
if [[ -f "${ROOT}/Assets/AppIcon.icns" ]]; then
    install -m 0644 "${ROOT}/Assets/AppIcon.icns" "${APP}/Contents/Resources/AppIcon.icns"
else
    log "WARN: Assets/AppIcon.icns not found — building without an icon"
fi
plutil -lint "${APP}/Contents/Info.plist" >/dev/null

log "codesign (${SIGN_IDENTITY})"
codesign --force --options runtime --timestamp=none \
    --entitlements "${ROOT}/Resources/LANA.entitlements" \
    --sign "${SIGN_IDENTITY}" "${APP}"
codesign --verify --strict "${APP}"

log "built: ${APP}"
lipo -info "${APP}/Contents/MacOS/LANA" || true
