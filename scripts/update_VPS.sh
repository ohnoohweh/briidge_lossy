#!/usr/bin/env bash

set -euo pipefail

PORT="${PORT:-18022}"
USER_NAME="${USER_NAME:-root}"
HOST="${HOST:-127.0.0.1}"
DEST_DIR="${DEST_DIR:-~/quicbr}"
SOURCE_DIR="${SOURCE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

RSYNC_SSH=(ssh -p "${PORT}")
RSYNC_EXCLUDES=(
  --exclude='*.pyc'
  --exclude='__pycache__/'
)

copy_path() {
  local rel_path="$1"
  echo "Syncing ${SOURCE_DIR}/${rel_path} -> ${USER_NAME}@${HOST}:${DEST_DIR}/"
  rsync -avz --delete "${RSYNC_EXCLUDES[@]}" -e "${RSYNC_SSH[*]}" \
    "${SOURCE_DIR}/${rel_path}" "${USER_NAME}@${HOST}:${DEST_DIR}/"
}

copy_path "ObstacleBridge.py"
copy_path "obstacle_bridge"
copy_path "scripts"
copy_path "src"
copy_path "admin_web"
