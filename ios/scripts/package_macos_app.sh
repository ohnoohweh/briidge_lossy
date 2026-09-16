#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IOS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_VARIANT="${OBSTACLEBRIDGE_MACOS_BUILD_VARIANT:-normal}"
if [[ "${BUILD_VARIANT}" == "normal" ]]; then
  BUILD_DIR="${IOS_DIR}/build/macos"
else
  BUILD_DIR="${IOS_DIR}/build/macos-${BUILD_VARIANT}"
fi
APP_BUNDLE="${OBSTACLEBRIDGE_MACOS_APP_BUNDLE:-${BUILD_DIR}/ObstacleBridge.app}"
OUTPUT_DIR="${OBSTACLEBRIDGE_MACOS_PACKAGE_OUTPUT_DIR:-${BUILD_DIR}/release}"
ARCHIVE_NAME="${OBSTACLEBRIDGE_MACOS_PACKAGE_NAME:-ObstacleBridge-macos-preview.zip}"
ARCHIVE_PATH="${OUTPUT_DIR}/${ARCHIVE_NAME}"
CHECKSUM_PATH="${ARCHIVE_PATH}.sha256"
MANIFEST_PATH="${OUTPUT_DIR}/ObstacleBridge-macos-preview-build-info.json"

usage() {
  cat <<'EOF'
Usage: ios/scripts/package_macos_app.sh

Packages an already-built ObstacleBridge.app for CI evidence or a GitHub Release.
The script never builds, signs, or mutates the bundle: callers must invoke
ios/scripts/build_macos_app.sh first and retain its signing contract.

Environment:
  OBSTACLEBRIDGE_MACOS_APP_BUNDLE          bundle to package
  OBSTACLEBRIDGE_MACOS_PACKAGE_OUTPUT_DIR  output directory
  OBSTACLEBRIDGE_MACOS_PACKAGE_NAME        ZIP filename
EOF
}

if [[ "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

for required_path in \
  "${APP_BUNDLE}/Contents/MacOS/ObstacleBridge" \
  "${APP_BUNDLE}/Contents/MacOS/ObstacleBridgeHostRunner" \
  "${APP_BUNDLE}/Contents/MacOS/ObstacleBridgeTunHelper" \
  "${APP_BUNDLE}/Contents/Resources/ObstacleBridge.build-info.json" \
  "${APP_BUNDLE}/Contents/Library/LaunchDaemons/com.obstaclebridge.macos.ObstacleBridge.TunHelper.plist"; do
  if [[ ! -e "${required_path}" ]]; then
    echo "[package_macos_app] required bundle path is missing: ${required_path}" >&2
    exit 1
  fi
done

for executable in \
  "${APP_BUNDLE}/Contents/MacOS/ObstacleBridge" \
  "${APP_BUNDLE}/Contents/MacOS/ObstacleBridgeHostRunner" \
  "${APP_BUNDLE}/Contents/MacOS/ObstacleBridgeTunHelper"; do
  if [[ ! -x "${executable}" ]]; then
    echo "[package_macos_app] expected executable is not executable: ${executable}" >&2
    exit 1
  fi
  codesign --verify --strict "${executable}"
done
codesign --verify --strict "${APP_BUNDLE}"
plutil -lint "${APP_BUNDLE}/Contents/Info.plist"
plutil -lint "${APP_BUNDLE}/Contents/Library/LaunchDaemons/com.obstaclebridge.macos.ObstacleBridge.TunHelper.plist"

mkdir -p "${OUTPUT_DIR}"
rm -f "${ARCHIVE_PATH}" "${CHECKSUM_PATH}" "${MANIFEST_PATH}"

echo "[package_macos_app] creating ${ARCHIVE_PATH}"
ditto -c -k --keepParent "${APP_BUNDLE}" "${ARCHIVE_PATH}"
(cd "${OUTPUT_DIR}" && shasum -a 256 "${ARCHIVE_NAME}" > "$(basename "${CHECKSUM_PATH}")")
cp "${APP_BUNDLE}/Contents/Resources/ObstacleBridge.build-info.json" "${MANIFEST_PATH}"

echo "[package_macos_app] archive: ${ARCHIVE_PATH}"
echo "[package_macos_app] checksum: ${CHECKSUM_PATH}"
echo "[package_macos_app] build info: ${MANIFEST_PATH}"
