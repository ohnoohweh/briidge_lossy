#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IOS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [ -f "${IOS_DIR}/.local-device-env" ]; then
  # shellcheck disable=SC1091
  . "${IOS_DIR}/.local-device-env"
fi

if [ -z "${OB_SERVER:-}" ]; then
  echo "[copy_peer_listener_logs] OB_SERVER is required (set in ios/.local-device-env)" >&2
  exit 1
fi

if [ -z "${OB_SERVER_USER:-}" ]; then
  echo "[copy_peer_listener_logs] OB_SERVER_USER is required (set in ios/.local-device-env)" >&2
  exit 1
fi

if ! command -v rsync >/dev/null 2>&1; then
  echo "[copy_peer_listener_logs] rsync is required but was not found" >&2
  exit 1
fi

REMOTE_PEER_LOG_PATH="${OB_REMOTE_PEER_LOG_PATH:-/tmp/ObstacleBridge.*}"
LOCAL_LOG_DIR="${IOS_DIR}/.logs/peer_listener"
REMOTE_HOST="${OB_SERVER_USER}@${OB_SERVER}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"

mkdir -p "${LOCAL_LOG_DIR}"

echo "[copy_peer_listener_logs] pulling logs from ${REMOTE_HOST}:${REMOTE_PEER_LOG_PATH}"

if ssh "${REMOTE_HOST}" "test -d '${REMOTE_PEER_LOG_PATH}'"; then
  rsync -az --progress "${REMOTE_HOST}:${REMOTE_PEER_LOG_PATH}/" "${LOCAL_LOG_DIR}/"
else
  BASENAME="$(basename "${REMOTE_PEER_LOG_PATH}")"
  TARGET_FILE="${LOCAL_LOG_DIR}/${TIMESTAMP}-${BASENAME}"
  rsync -az --progress "${REMOTE_HOST}:${REMOTE_PEER_LOG_PATH}" "${TARGET_FILE}"
fi

echo "[copy_peer_listener_logs] logs available at ${LOCAL_LOG_DIR}"
