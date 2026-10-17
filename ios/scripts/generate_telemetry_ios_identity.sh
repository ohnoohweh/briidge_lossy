#!/usr/bin/env bash
# Issue and package one iPhone telemetry identity using the standard local CA.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IOS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${IOS_DIR}/.." && pwd)"
PYTHON_CMD="${REPO_ROOT}/.venv/bin/python"
CA_KEY="${TELEMETRY_CA_KEY:-/var/lib/obstaclebridge/telemetry-ca/ca.key.pem}"
CA_CERT="${TELEMETRY_CA_CERT:-/var/lib/obstaclebridge/telemetry-ca/ca.cert.pem}"
OUTPUT_DIR="${TELEMETRY_IOS_OUTPUT_DIRECTORY:-${HOME}/obstaclebridge-iphone-telemetry}"
DAYS="${TELEMETRY_IDENTITY_DAYS:-30}"
INSTALLATION_ID="${TELEMETRY_INSTALLATION_ID:-}"

usage() {
  cat <<'EOF'
Usage:
  TELEMETRY_INSTALLATION_ID=iphone-primary bash ios/scripts/generate_telemetry_ios_identity.sh

Optional environment variables:
  TELEMETRY_CA_KEY              CA key PEM (default: /var/lib/obstaclebridge/telemetry-ca/ca.key.pem)
  TELEMETRY_CA_CERT             CA certificate PEM (default: /var/lib/obstaclebridge/telemetry-ca/ca.cert.pem)
  TELEMETRY_IOS_OUTPUT_DIRECTORY output directory (default: $HOME/obstaclebridge-iphone-telemetry)
  TELEMETRY_IDENTITY_DAYS       certificate lifetime (default: 30)
EOF
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  "") ;;
  *) echo "[generate_telemetry_ios_identity] unexpected argument: $1" >&2; usage >&2; exit 2 ;;
esac

if [ ! -x "${PYTHON_CMD}" ]; then
  echo "[generate_telemetry_ios_identity] missing project virtual-environment Python: ${PYTHON_CMD}" >&2
  exit 2
fi
if [ -z "${INSTALLATION_ID}" ]; then
  read -r -p "iPhone telemetry installation ID (certificate CN): " INSTALLATION_ID
fi
if [ -z "${INSTALLATION_ID}" ]; then
  echo "[generate_telemetry_ios_identity] installation ID is required" >&2
  exit 2
fi

echo "[generate_telemetry_ios_identity] issuing ${INSTALLATION_ID}; sudo may ask for your password to read the CA key"
sudo "${PYTHON_CMD}" "${REPO_ROOT}/scripts/generate_telemetry_ios_identity.py" \
  --ca-key "${CA_KEY}" \
  --ca-cert "${CA_CERT}" \
  --installation-id "${INSTALLATION_ID}" \
  --out-dir "${OUTPUT_DIR}" \
  --days "${DAYS}"

# The generator runs as root solely to read the CA key. Return the new output
# to the invoking operator so the password-protected identity can be moved to
# the device without leaving a root-owned copy in the home directory.
sudo chown -R "$(id -un):$(id -gn)" "${OUTPUT_DIR}"
echo "[generate_telemetry_ios_identity] created ${OUTPUT_DIR}"
