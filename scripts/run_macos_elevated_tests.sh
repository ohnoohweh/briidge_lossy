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

cd "$ROOT_DIR"
exec "$PYTHON_BIN" -m pytest -q -rs tests/integration/test_macos_elevated.py -m macos_elevated --run-macos-elevated "$@"
