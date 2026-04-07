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
  exec sudo env OBSTACLEBRIDGE_RUN_LINUX_ELEVATED=1 "$0" "$@"
fi

export OBSTACLEBRIDGE_RUN_LINUX_ELEVATED=1

cd "$ROOT_DIR"
exec "$PYTHON_BIN" -m pytest -q tests/integration/test_linux_elevated.py -m linux_elevated --run-linux-elevated "$@"