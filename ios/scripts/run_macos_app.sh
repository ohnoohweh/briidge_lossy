#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IOS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${IOS_DIR}/.." && pwd)"
BINARY_PATH="${IOS_DIR}/build/macos/ObstacleBridgeMacHostRunner"
DEFAULT_RUNTIME_CONFIG="${IOS_DIR}/examples/macos_runtime.json"
TMP_BASE="${TMPDIR:-/tmp}"
KEEP_TEMP_HOME="${KEEP_TEMP_HOME:-0}"
GENERATED_TEMP_HOME="0"

if [ ! -x "${BINARY_PATH}" ]; then
  "${SCRIPT_DIR}/build_macos_app.sh"
fi

if [ -n "${OBSTACLEBRIDGE_TMP_HOME:-}" ]; then
  TEMP_HOME="${OBSTACLEBRIDGE_TMP_HOME}"
else
  TEMP_HOME="$(mktemp -d "${TMP_BASE%/}/obstaclebridge-macos-home.XXXXXX")"
  GENERATED_TEMP_HOME="1"
fi

cleanup() {
  if [ "${KEEP_TEMP_HOME}" = "1" ]; then
    echo "[run_macos_app] keeping temp home: ${TEMP_HOME}"
    return
  fi
  if [ -d "${TEMP_HOME}" ]; then
    rm -rf "${TEMP_HOME}"
    echo "[run_macos_app] removed temp home: ${TEMP_HOME}"
  fi
}

trap cleanup EXIT INT TERM

mkdir -p "${TEMP_HOME}/Documents/ObstacleBridge"

export HOME="${TEMP_HOME}"
export OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT="${OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT:-${TEMP_HOME}/Documents/ObstacleBridge}"

ARGS=("$@")
if [ ${#ARGS[@]} -eq 0 ]; then
  ARGS=(
    --runtime-config "${DEFAULT_RUNTIME_CONFIG}"
    --bind-host 127.0.0.1
    --status-port 18080
  )
fi

echo "[run_macos_app] temp home: ${TEMP_HOME}"
echo "[run_macos_app] documents root: ${OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT}"
if [ "${GENERATED_TEMP_HOME}" = "1" ]; then
  echo "[run_macos_app] using mktemp under ${TMP_BASE}"
fi

cd "${REPO_ROOT}"
"${BINARY_PATH}" "${ARGS[@]}"