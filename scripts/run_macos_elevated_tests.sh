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
export OBSTACLEBRIDGE_ELEVATED_TEST_PROGRESS=1
export PYTHONUNBUFFERED=1
export TERM="${TERM:-dumb}"

diagnose_exit() {
  status=$?
  echo "[macos-elevated] pytest exited with status=${status}; collecting final host diagnostics"
  echo "[macos-elevated] routes"
  netstat -rn -f inet 2>&1 || true
  echo "[macos-elevated] interfaces"
  ifconfig -l 2>&1 || true
  echo "[macos-elevated] process summary"
  ps -axo pid,ppid,%cpu,%mem,etime,command 2>&1 | head -n 80 || true
  exit "$status"
}

trap diagnose_exit EXIT

cd "$ROOT_DIR"
"$PYTHON_BIN" -m pytest -vv -s -rs --durations=20 \
  tests/integration/test_macos_elevated.py -m macos_elevated --run-macos-elevated "$@"
