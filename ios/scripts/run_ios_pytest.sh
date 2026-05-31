#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IOS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${IOS_DIR}/.." && pwd)"
TMP_BASE="${TMPDIR:-/tmp}"
KEEP_TEMP_DOCS_ROOT="${KEEP_TEMP_DOCS_ROOT:-0}"
GENERATED_TEMP_DOCS_ROOT="0"

if [ -x "${REPO_ROOT}/.venv/bin/pytest" ]; then
  PYTEST_CMD="${REPO_ROOT}/.venv/bin/pytest"
else
  PYTEST_CMD="pytest"
fi

if [ -n "${OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT:-}" ]; then
  TEMP_DOCS_ROOT="${OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT}"
else
  TEMP_DOCS_ROOT="$(mktemp -d "${TMP_BASE%/}/obstaclebridge-ios-docs.XXXXXX")"
  GENERATED_TEMP_DOCS_ROOT="1"
fi

cleanup() {
  if [ "${KEEP_TEMP_DOCS_ROOT}" = "1" ]; then
    echo "[run_ios_pytest] keeping temp documents root: ${TEMP_DOCS_ROOT}"
    return
  fi
  if [ -d "${TEMP_DOCS_ROOT}" ]; then
    rm -rf "${TEMP_DOCS_ROOT}"
    echo "[run_ios_pytest] removed temp documents root: ${TEMP_DOCS_ROOT}"
  fi
}

trap cleanup EXIT INT TERM

mkdir -p "${TEMP_DOCS_ROOT}"
export OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT="${TEMP_DOCS_ROOT}"

echo "[run_ios_pytest] documents root: ${OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT}"
if [ "${GENERATED_TEMP_DOCS_ROOT}" = "1" ]; then
  echo "[run_ios_pytest] using mktemp under ${TMP_BASE}"
fi

cd "${REPO_ROOT}"
exec "${PYTEST_CMD}" "$@"