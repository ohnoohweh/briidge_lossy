#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONFIGURATION="${OBSTACLEBRIDGE_LINUX_BUILD_CONFIGURATION:-release}"
OUTPUT_DIR="${OBSTACLEBRIDGE_LINUX_OUTPUT_DIR:-${REPO_ROOT}/build/linux}"
SCRATCH_DIR="${OBSTACLEBRIDGE_LINUX_SCRATCH_DIR:-${OUTPUT_DIR}/.swift-build}"

usage() {
  cat <<'EOF'
Usage: ./scripts/build_linux_app.sh [--debug] [--output-dir <directory>]

Builds the Linux Swift executable using the locally installed Swift toolchain.

Environment:
  OBSTACLEBRIDGE_LINUX_BUILD_CONFIGURATION  release (default) or debug
  OBSTACLEBRIDGE_LINUX_OUTPUT_DIR           artifact directory (default: build/linux)
  OBSTACLEBRIDGE_LINUX_SCRATCH_DIR          SwiftPM scratch directory
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --debug)
      CONFIGURATION="debug"
      ;;
    --output-dir)
      [ "$#" -ge 2 ] || { echo "[build_linux_app] --output-dir requires a directory" >&2; exit 2; }
      OUTPUT_DIR="$2"
      SCRATCH_DIR="${OUTPUT_DIR}/.swift-build"
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "[build_linux_app] unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

case "${CONFIGURATION}" in
  release|debug) ;;
  *)
    echo "[build_linux_app] configuration must be release or debug, got ${CONFIGURATION}" >&2
    exit 2
    ;;
esac

if ! command -v swift >/dev/null 2>&1; then
  echo "[build_linux_app] swift is required; install Swift and make it available on PATH" >&2
  exit 1
fi
if ! command -v swiftc >/dev/null 2>&1; then
  echo "[build_linux_app] swiftc is required; install a complete Swift toolchain" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}" "${SCRATCH_DIR}"

echo "[build_linux_app] compiling ${CONFIGURATION} Linux Swift artifact"
swift build \
  --package-path "${REPO_ROOT}" \
  --scratch-path "${SCRATCH_DIR}" \
  --configuration "${CONFIGURATION}" \
  --product ObstacleBridgeLinux

BINARY_SOURCE="${SCRATCH_DIR}/${CONFIGURATION}/ObstacleBridgeLinux"
if [ ! -x "${BINARY_SOURCE}" ]; then
  echo "[build_linux_app] expected SwiftPM artifact is missing: ${BINARY_SOURCE}" >&2
  exit 1
fi

BINARY_PATH="${OUTPUT_DIR}/ObstacleBridgeLinux"
BUILD_INFO_PATH="${OUTPUT_DIR}/ObstacleBridgeLinux.build-info.json"
cp "${BINARY_SOURCE}" "${BINARY_PATH}"

COMMIT="$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD 2>/dev/null || printf 'unknown')"
if git -C "${REPO_ROOT}" status --porcelain | grep -q .; then
  DIRTY=true
else
  DIRTY=false
fi
DIFF_SHA="$(git -C "${REPO_ROOT}" diff --binary HEAD 2>/dev/null | sha256sum | awk '{print substr($1, 1, 12)}')"
if [ "${DIFF_SHA}" = "e3b0c44298fc" ]; then
  DIFF_SHA=""
fi
BUILD_TIMESTAMP_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cat > "${BUILD_INFO_PATH}" <<EOF
{"artifact":"ObstacleBridgeLinux","build_configuration":"${CONFIGURATION}","build_timestamp_utc":"${BUILD_TIMESTAMP_UTC}","commit":"${COMMIT}","diff_sha":"${DIFF_SHA}","dirty":${DIRTY},"source":"swift-package"}
EOF

echo "[build_linux_app] wrote ${BINARY_PATH}"
echo "[build_linux_app] wrote ${BUILD_INFO_PATH}"
