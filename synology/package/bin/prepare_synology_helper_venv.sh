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
PY_PACKAGES_DIR="${VAR_DIR}/python-packages"

mkdir -p "${VAR_DIR}"

"${PY_BIN}" - "${PKG_DIR}" "${PY_PACKAGES_DIR}" <<'PY'
import pathlib
import subprocess
import sys
import tomllib

pkg_dir = pathlib.Path(sys.argv[1])
target_dir = pathlib.Path(sys.argv[2])
pyproject_path = pkg_dir / "pyproject.toml"
data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
dependencies = list(data.get("project", {}).get("dependencies", []))
if not dependencies:
    raise SystemExit("no project.dependencies found in pyproject.toml")
target_dir.mkdir(parents=True, exist_ok=True)
subprocess.check_call(
    [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--upgrade",
        "--target",
        str(target_dir),
        *dependencies,
    ]
)
PY

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
