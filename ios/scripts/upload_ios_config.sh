#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IOS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [ -f "${IOS_DIR}/.local-device-env" ]; then
  # shellcheck disable=SC1091
  . "${IOS_DIR}/.local-device-env"
fi

if [ -z "${OB_IOS_DEVICE_ID:-}" ]; then
  echo "[upload_ios_config] OB_IOS_DEVICE_ID is required" >&2
  exit 1
fi

LOCAL_CFG="${1:-${IOS_DIR}/.device-config/ObstacleBridge.cfg}"
if [ ! -f "${LOCAL_CFG}" ]; then
  echo "[upload_ios_config] local config not found: ${LOCAL_CFG}" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

PREV_DIR="${TMP_DIR}/previous"
VERIFY_DIR="${TMP_DIR}/verify"
mkdir -p "${PREV_DIR}" "${VERIFY_DIR}"

echo "[upload_ios_config] downloading current device config for reference"
xcrun devicectl device copy from \
  --device "${OB_IOS_DEVICE_ID}" \
  --domain-type appDataContainer \
  --domain-identifier com.obstaclebridge.obstacle-bridge-ios \
  --source Documents/config/ObstacleBridge.cfg \
  --destination "${PREV_DIR}/ObstacleBridge.cfg" >/dev/null

PREV_FILE=""
for candidate in \
  "${PREV_DIR}/ObstacleBridge.cfg" \
  "${PREV_DIR}/Documents/config/ObstacleBridge.cfg" \
  "${PREV_DIR}/config/ObstacleBridge.cfg"
do
  if [ -f "${candidate}" ]; then
    PREV_FILE="${candidate}"
    break
  fi
done

if [ -n "${PREV_FILE}" ]; then
  echo "[upload_ios_config] current device file:"
  stat -f '  size=%z mtime=%Sm' -t '%Y-%m-%d %H:%M:%S %z' "${PREV_FILE}"
fi

# Make the uploaded source unmistakably newer than the previous file.
sleep 1
touch "${LOCAL_CFG}"

echo "[upload_ios_config] uploading ${LOCAL_CFG}"
xcrun devicectl device copy to \
  --device "${OB_IOS_DEVICE_ID}" \
  --domain-type appDataContainer \
  --domain-identifier com.obstaclebridge.obstacle-bridge-ios \
  --source "${LOCAL_CFG}" \
  --destination Documents/config/ObstacleBridge.cfg

echo "[upload_ios_config] reading file back for verification"
xcrun devicectl device copy from \
  --device "${OB_IOS_DEVICE_ID}" \
  --domain-type appDataContainer \
  --domain-identifier com.obstaclebridge.obstacle-bridge-ios \
  --source Documents/config/ObstacleBridge.cfg \
  --destination "${VERIFY_DIR}/ObstacleBridge.cfg" >/dev/null

VERIFY_FILE=""
for candidate in \
  "${VERIFY_DIR}/ObstacleBridge.cfg" \
  "${VERIFY_DIR}/Documents/config/ObstacleBridge.cfg" \
  "${VERIFY_DIR}/config/ObstacleBridge.cfg"
do
  if [ -f "${candidate}" ]; then
    VERIFY_FILE="${candidate}"
    break
  fi
done

if [ -z "${VERIFY_FILE}" ]; then
  echo "[upload_ios_config] could not read back ObstacleBridge.cfg after upload" >&2
  exit 1
fi

if ! cmp -s "${LOCAL_CFG}" "${VERIFY_FILE}"; then
  echo "[upload_ios_config] readback verification failed: uploaded file differs from device copy" >&2
  exit 1
fi

echo "[upload_ios_config] upload verified"
stat -f '[upload_ios_config] verified size=%z mtime=%Sm' -t '%Y-%m-%d %H:%M:%S %z' "${VERIFY_FILE}"
