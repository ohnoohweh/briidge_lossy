#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IOS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [ -f "${IOS_DIR}/.local-device-env" ]; then
  # shellcheck disable=SC1091
  . "${IOS_DIR}/.local-device-env"
fi

if [ -z "${OB_IOS_DEVICE_ID:-}" ]; then
  echo "[download_ios_config] OB_IOS_DEVICE_ID is required" >&2
  exit 1
fi

DEST_PATH="${1:-${IOS_DIR}/.device-config/ObstacleBridge.cfg}"
DEST_DIR="$(dirname "${DEST_PATH}")"
mkdir -p "${DEST_DIR}"

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

echo "[download_ios_config] downloading Documents/config/ObstacleBridge.cfg from device ${OB_IOS_DEVICE_ID}"
xcrun devicectl device copy from \
  --device "${OB_IOS_DEVICE_ID}" \
  --domain-type appDataContainer \
  --domain-identifier com.obstaclebridge.obstacle-bridge-ios \
  --source Documents/config/ObstacleBridge.cfg \
  --destination "${TMP_DIR}/ObstacleBridge.cfg"

SOURCE_FILE=""
for candidate in \
  "${TMP_DIR}/ObstacleBridge.cfg" \
  "${TMP_DIR}/Documents/config/ObstacleBridge.cfg" \
  "${TMP_DIR}/config/ObstacleBridge.cfg"
do
  if [ -f "${candidate}" ]; then
    SOURCE_FILE="${candidate}"
    break
  fi
done

if [ -z "${SOURCE_FILE}" ]; then
  echo "[download_ios_config] could not find downloaded ObstacleBridge.cfg in ${TMP_DIR}" >&2
  exit 1
fi

cp "${SOURCE_FILE}" "${DEST_PATH}"
echo "[download_ios_config] wrote ${DEST_PATH}"
stat -f '[download_ios_config] local size=%z mtime=%Sm' -t '%Y-%m-%d %H:%M:%S %z' "${DEST_PATH}"
