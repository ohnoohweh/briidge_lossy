#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PY="$ROOT_DIR/.venv/bin/python"

if [[ -x "$VENV_PY" ]]; then
  PYTHON_BIN="$VENV_PY"
else
  PYTHON_BIN="python3"
fi

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  exec sudo env \
    OBSTACLEBRIDGE_RUN_MACOS_ELEVATED=1 \
    OBSTACLEBRIDGE_GITHUB_ACTIONS="${GITHUB_ACTIONS:-}" \
    "$0" "$@"
fi

export OBSTACLEBRIDGE_RUN_MACOS_ELEVATED=1
export GITHUB_ACTIONS="${GITHUB_ACTIONS:-${OBSTACLEBRIDGE_GITHUB_ACTIONS:-}}"

restore_artifact_ownership() {
  if [[ -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
    chown -R "${SUDO_UID}:${SUDO_GID}" \
      "$ROOT_DIR/ios/build/macos" \
      "$ROOT_DIR/ios/build/generated" \
      "$ROOT_DIR/src/obstacle_bridge/_generated" \
      2>/dev/null || true
  fi
}

trap restore_artifact_ownership EXIT

cd "$ROOT_DIR"
"$PYTHON_BIN" -m pytest -q -rs tests/integration/test_macos_swift_elevated.py -m macos_elevated --run-macos-elevated "$@"
