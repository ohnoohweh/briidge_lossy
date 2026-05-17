#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IOS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${IOS_DIR}/.." && pwd)"

if [ -f "${IOS_DIR}/.local-device-env" ]; then
  # shellcheck disable=SC1091
  . "${IOS_DIR}/.local-device-env"
fi

if [ -z "${OB_SERVER:-}" ]; then
  echo "[sync_peer_listener_server] OB_SERVER is required (set in ios/.local-device-env)" >&2
  exit 1
fi

if [ -z "${OB_SERVER_USER:-}" ]; then
  echo "[sync_peer_listener_server] OB_SERVER_USER is required (set in ios/.local-device-env)" >&2
  exit 1
fi

if ! command -v rsync >/dev/null 2>&1; then
  echo "[sync_peer_listener_server] rsync is required but was not found" >&2
  exit 1
fi

REMOTE_BASE="${OB_REMOTE_BASE:-~/quicbr}"
REMOTE_HOST="${OB_SERVER_USER}@${OB_SERVER}"

RSYNC_DELETE_FLAG=""
RSYNC_DRY_RUN_FLAG=""

for arg in "$@"; do
  case "$arg" in
    --delete)
      RSYNC_DELETE_FLAG="--delete"
      ;;
    --dry-run)
      RSYNC_DRY_RUN_FLAG="--dry-run"
      ;;
    *)
      echo "[sync_peer_listener_server] unknown argument: ${arg}" >&2
      echo "usage: $0 [--dry-run] [--delete]" >&2
      exit 1
      ;;
  esac
done

echo "[sync_peer_listener_server] syncing ${REPO_ROOT} -> ${REMOTE_HOST}:${REMOTE_BASE}"

rsync -az --progress \
  ${RSYNC_DRY_RUN_FLAG} \
  ${RSYNC_DELETE_FLAG} \
  --exclude '/ObstacleBridge.cfg' \
  --exclude '.git/' \
  --exclude '.venv/' \
  --exclude '.pytest_cache/' \
  --exclude '__pycache__/' \
  --exclude '.mypy_cache/' \
  --exclude '.ruff_cache/' \
  --exclude 'ios/build/' \
  --exclude 'ios/.logs/' \
  --exclude 'logs/' \
  --exclude '*.pyc' \
  --exclude '*.pyo' \
  --exclude '*.swp' \
  "${REPO_ROOT}/" "${REMOTE_HOST}:${REMOTE_BASE}/"

echo "[sync_peer_listener_server] done"
