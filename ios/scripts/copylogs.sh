#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "${SCRIPT_DIR}/.local-device-env" ]; then
  # shellcheck disable=SC1091
  . "${SCRIPT_DIR}/.local-device-env"
fi

cleanup_macos_metadata() {
  local ios_dir log_dir
  ios_dir="$(cd "${SCRIPT_DIR}/.." && pwd)"
  log_dir="${ios_dir}/.logs/fedora"
  rm -f "${ios_dir}/.DS_Store"
  find "${log_dir}" -name '.DS_Store' -delete 2>/dev/null || true
}

trap cleanup_macos_metadata EXIT

export LOG_DIR="${SCRIPT_DIR}/../.logs/fedora"

rm -Rf "${LOG_DIR}"
mkdir -p "${LOG_DIR}"
xcrun devicectl device copy from \
  --device "${OB_IOS_DEVICE_ID}" \
  --domain-type appDataContainer \
  --domain-identifier com.obstaclebridge.obstacle-bridge-ios \
  --source Documents/logs \
  --destination "${LOG_DIR}"
