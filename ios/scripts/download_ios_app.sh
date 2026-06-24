#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IOS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${IOS_DIR}/.." && pwd)"

if [ -f "${IOS_DIR}/.local-device-env" ]; then
  # shellcheck disable=SC1091
  . "${IOS_DIR}/.local-device-env"
fi

DERIVED_DATA_PATH="${DERIVED_DATA_PATH:-/tmp/obstaclebridge-ios-build}"
APP_BUNDLE="${APP_BUNDLE:-${DERIVED_DATA_PATH}/Build/Products/Debug-iphoneos/ObstacleBridge.app}"

if [ -z "${OB_IOS_DEVICE_ID:-}" ]; then
  echo "[download_ios_app] OB_IOS_DEVICE_ID is required" >&2
  exit 1
fi

if [ ! -d "${APP_BUNDLE}" ]; then
  echo "[download_ios_app] app bundle not found at ${APP_BUNDLE}" >&2
  echo "[download_ios_app] build first with ./ios/scripts/build_ios_app.sh" >&2
  exit 1
fi

echo "[download_ios_app] installing existing app bundle to device ${OB_IOS_DEVICE_ID}"
echo "[download_ios_app] app bundle: ${APP_BUNDLE}"

xcrun devicectl device install app \
  --device "${OB_IOS_DEVICE_ID}" \
  "${APP_BUNDLE}"

