#!/usr/bin/env bash
# Stage an encrypted telemetry identity in the connected ObstacleBridge app's
# Documents container. The app must import it into Keychain and delete it;
# Packet Tunnel code never reads a private key directly from Documents.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IOS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [ -f "${IOS_DIR}/.local-device-env" ]; then
  # shellcheck disable=SC1091
  . "${IOS_DIR}/.local-device-env"
fi

usage() {
  cat <<'EOF'
Usage:
  bash ios/scripts/upload_ios_telemetry_identity.sh /secure/path/identity.p12 [collector-ca.cer]

The encrypted .p12 is copied to the ObstacleBridge app Documents container and
verified by a device readback. An optional public collector CA is staged beside
it. This is temporary enrolment staging only: the app must import the identity
into Keychain and remove the .p12 before the Packet Tunnel can use telemetry.
EOF
}

case "${1:-}" in
  -h|--help|"") usage; [ "${1:-}" = "" ] && exit 2 || exit 0 ;;
esac

if [ -z "${OB_IOS_DEVICE_ID:-}" ]; then
  echo "[upload_ios_telemetry_identity] OB_IOS_DEVICE_ID is required" >&2
  exit 2
fi

LOCAL_P12="$1"
LOCAL_CA="${2:-}"
BUNDLE_ID="${OB_IOS_BUNDLE_ID:-com.obstaclebridge.obstacle-bridge-ios}"
REMOTE_P12="Documents/ObstacleBridge-telemetry-identity.p12"
REMOTE_CA="Documents/ObstacleBridge-telemetry-collector-ca.cer"

if [ ! -f "${LOCAL_P12}" ]; then
  echo "[upload_ios_telemetry_identity] PKCS#12 file not found: ${LOCAL_P12}" >&2
  exit 2
fi
case "${LOCAL_P12}" in
  *.p12|*.P12) ;;
  *) echo "[upload_ios_telemetry_identity] expected a .p12 file: ${LOCAL_P12}" >&2; exit 2 ;;
esac
if [ -n "${LOCAL_CA}" ] && [ ! -f "${LOCAL_CA}" ]; then
  echo "[upload_ios_telemetry_identity] collector CA file not found: ${LOCAL_CA}" >&2
  exit 2
fi

TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "${TMP_DIR}"; }
trap cleanup EXIT

read -r -s -p "PKCS#12 password: " P12_PASSWORD
echo
if [ -z "${P12_PASSWORD}" ]; then
  echo "[upload_ios_telemetry_identity] PKCS#12 password is required" >&2
  exit 2
fi
PASSWORD_FILE="${TMP_DIR}/ObstacleBridge-telemetry-identity.password"
umask 077
printf '%s\n' "${P12_PASSWORD}" > "${PASSWORD_FILE}"
unset P12_PASSWORD

copy_and_verify() {
  local source="$1"
  local remote_path="$2"
  local verify_path="${TMP_DIR}/$(basename "${remote_path}")"
  echo "[upload_ios_telemetry_identity] uploading $(basename "${source}")"
  xcrun devicectl device copy to \
    --device "${OB_IOS_DEVICE_ID}" \
    --domain-type appDataContainer \
    --domain-identifier "${BUNDLE_ID}" \
    --source "${source}" \
    --destination "${remote_path}"
  xcrun devicectl device copy from \
    --device "${OB_IOS_DEVICE_ID}" \
    --domain-type appDataContainer \
    --domain-identifier "${BUNDLE_ID}" \
    --source "${remote_path}" \
    --destination "${verify_path}" >/dev/null
  local copied=""
  for candidate in "${verify_path}" "${TMP_DIR}/Documents/$(basename "${remote_path}")"; do
    if [ -f "${candidate}" ]; then copied="${candidate}"; break; fi
  done
  if [ -z "${copied}" ] || ! cmp -s "${source}" "${copied}"; then
    echo "[upload_ios_telemetry_identity] readback verification failed for ${remote_path}" >&2
    exit 1
  fi
}

copy_and_verify "${LOCAL_P12}" "${REMOTE_P12}"
copy_and_verify "${PASSWORD_FILE}" "Documents/ObstacleBridge-telemetry-identity.password"
if [ -n "${LOCAL_CA}" ]; then
  copy_and_verify "${LOCAL_CA}" "${REMOTE_CA}"
fi

echo "[upload_ios_telemetry_identity] staged encrypted identity in ${REMOTE_P12}"
echo "[upload_ios_telemetry_identity] it is not yet a Keychain identity; import then delete the staged .p12 before enabling telemetry"
