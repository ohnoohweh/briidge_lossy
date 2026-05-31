#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IOS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${IOS_DIR}/.." && pwd)"
BUILD_DIR="${IOS_DIR}/build/macos"
BINARY_PATH="${BUILD_DIR}/ObstacleBridgeMacHostRunner"
BUILD_INFO_JSON="${BUILD_DIR}/ObstacleBridgeMacHostRunner.build-info.json"

if command -v swiftc >/dev/null 2>&1; then
  SWIFTC_CMD="$(command -v swiftc)"
elif command -v xcrun >/dev/null 2>&1; then
  SWIFTC_CMD="$(xcrun --find swiftc)"
else
  SWIFTC_CMD=""
fi

if [ -z "${SWIFTC_CMD}" ]; then
  echo "[build_macos_app] swiftc is required" >&2
  exit 1
fi

if [ -x "${REPO_ROOT}/.venv/bin/python" ]; then
  PYTHON_CMD="${REPO_ROOT}/.venv/bin/python"
else
  PYTHON_CMD="python3"
fi

mkdir -p "${BUILD_DIR}"

echo "[build_macos_app] refreshing embedded build metadata"
"${PYTHON_CMD}" "${REPO_ROOT}/scripts/write_build_info.py"

echo "[build_macos_app] compiling macOS Swift host runner"
"${SWIFTC_CMD}" \
  -o "${BINARY_PATH}" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeAdminAPI.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeChannelMuxCodec.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeSecureLinkPskCodec.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeSecureLinkPskRuntime.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeSecureLinkPskTransportAdapter.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeOverlayLayerTransportAdapter.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeRuntimeConfig.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeWebAdminServer.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeChannelMuxUdpRuntime.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeChannelMuxTcpRuntime.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeChannelMuxTCPTransportOwner.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeUdpOverlayCodec.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeUdpOverlaySessionCodec.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeUdpOverlayPeerRuntime.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeUdpOverlayTransportOwner.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeCompressLayerRuntime.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeOverlayStackPlanner.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeWebSocketPayloadCodec.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeWebSocketOverlayRuntime.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeTcpOverlayRuntime.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeTcpOverlayTransportOwner.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeMacRunner/ObstacleBridgeMacHostRunner.swift"

echo "[build_macos_app] writing build identification sidecar"
OBSTACLEBRIDGE_REPO_ROOT="${REPO_ROOT}" "${PYTHON_CMD}" - <<'PY' > "${BUILD_INFO_JSON}"
from __future__ import annotations

import json
import os
from pathlib import Path

repo_root = Path(os.environ["OBSTACLEBRIDGE_REPO_ROOT"])
namespace: dict[str, object] = {}
build_info_path = repo_root / "src" / "obstacle_bridge" / "build_info.py"
exec(build_info_path.read_text(encoding="utf-8"), namespace)
payload = {
  "commit": namespace.get("BUILD_COMMIT", "unknown"),
  "source": namespace.get("BUILD_SOURCE", "embedded"),
  "repo_root": "",
  "tainted": bool(namespace.get("BUILD_DIRTY", False)),
  "tracked_changes": 0,
  "untracked_changes": 0,
  "available": True,
  "diff_sha": namespace.get("BUILD_DIFF_SHA", ""),
    "build_timestamp_utc": namespace.get("BUILD_TIMESTAMP_UTC", ""),
}
print(json.dumps(payload, sort_keys=True))
PY

echo "[build_macos_app] build completed"
echo "[build_macos_app] binary: ${BINARY_PATH}"
echo "[build_macos_app] build info: ${BUILD_INFO_JSON}"
