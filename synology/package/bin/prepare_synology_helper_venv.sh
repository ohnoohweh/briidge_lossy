#!/bin/sh
set -eu

PKG_DIR="${1:-}"
VAR_DIR="${2:-}"
PY_BIN="${3:-}"

if [ -z "${PKG_DIR}" ] || [ -z "${VAR_DIR}" ] || [ -z "${PY_BIN}" ]; then
    echo "usage: $0 <pkg_dir> <var_dir> <python_bin>" >&2
    exit 2
fi

HELPER_VENV="${VAR_DIR}/helper-venv"
HELPER_PY="${HELPER_VENV}/bin/python3"

mkdir -p "${VAR_DIR}"

if [ ! -x "${HELPER_PY}" ]; then
    "${PY_BIN}" -m venv --system-site-packages --copies "${HELPER_VENV}"
fi

if [ ! -x "${HELPER_PY}" ]; then
    echo "failed to prepare helper python at ${HELPER_PY}" >&2
    exit 1
fi

if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_admin+ep "${HELPER_PY}"
fi

echo "${HELPER_PY}"
