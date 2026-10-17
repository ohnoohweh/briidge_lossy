#!/usr/bin/env bash
# Request a one-shot cleanup of only ObstacleBridge Documents/logs on a paired iPhone.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IOS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
if [ -f "${IOS_DIR}/.local-device-env" ]; then
  # shellcheck disable=SC1091
  . "${IOS_DIR}/.local-device-env"
fi

if [ -z "${OB_IOS_DEVICE_ID:-}" ]; then
  echo "[clear_ios_logs] OB_IOS_DEVICE_ID is required" >&2
  exit 2
fi

BUNDLE_ID="${OB_IOS_BUNDLE_ID:-com.obstaclebridge.obstacle-bridge-ios}"
MARKER_DIR="$(mktemp -d)"
MARKER_FILE="${MARKER_DIR}/.obstaclebridge-clear-logs-v1"
trap 'rm -rf "${MARKER_DIR}"' EXIT
printf 'clear Documents/logs only\n' > "${MARKER_FILE}"

echo "[clear_ios_logs] staging one-shot log-cleanup request"
xcrun devicectl device copy to \
  --device "${OB_IOS_DEVICE_ID}" \
  --domain-type appDataContainer \
  --domain-identifier "${BUNDLE_ID}" \
  --source "${MARKER_FILE}" \
  --destination "Documents/.obstaclebridge-clear-logs-v1"

echo "[clear_ios_logs] launching ObstacleBridge to consume the request"
xcrun devicectl device process launch \
  --device "${OB_IOS_DEVICE_ID}" \
  "${BUNDLE_ID}" >/dev/null
sleep 2

VERIFY_DIR="$(mktemp -d)"
trap 'rm -rf "${MARKER_DIR}" "${VERIFY_DIR}"' EXIT
if xcrun devicectl device copy from \
  --device "${OB_IOS_DEVICE_ID}" \
  --domain-type appDataContainer \
  --domain-identifier "${BUNDLE_ID}" \
  --source "Documents/logs" \
  --destination "${VERIFY_DIR}/logs" >/dev/null 2>&1; then
  if find "${VERIFY_DIR}/logs" -type f -print -quit | grep -q .; then
    echo "[clear_ios_logs] cleanup request was not consumed; install the current app build and retry" >&2
    exit 1
  fi
fi
echo "[clear_ios_logs] Documents/logs cleared; configuration and telemetry staging were preserved"
