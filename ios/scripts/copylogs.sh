#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "${SCRIPT_DIR}/.local-device-env" ]; then
  # shellcheck disable=SC1091
  . "${SCRIPT_DIR}/.local-device-env"
fi

export LOG_DIR="${SCRIPT_DIR}/../.logs/obstaclebridge-logs"

rm -Rf "${LOG_DIR}"
mkdir -p "${LOG_DIR}"
xcrun devicectl device copy from \
  --device "${OB_IOS_DEVICE_ID}" \
  --domain-type appDataContainer \
  --domain-identifier com.obstaclebridge.obstacle-bridge-ios \
  --source Documents/logs \
  --destination "${LOG_DIR}"
