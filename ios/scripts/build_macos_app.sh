#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IOS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${IOS_DIR}/.." && pwd)"
BUILD_VARIANT="${OBSTACLEBRIDGE_MACOS_BUILD_VARIANT:-normal}"
if [ "${BUILD_VARIANT}" = "normal" ]; then
  BUILD_DIR="${IOS_DIR}/build/macos"
else
  BUILD_DIR="${IOS_DIR}/build/macos-${BUILD_VARIANT}"
fi
GENERATED_SWIFT_DIR="${IOS_DIR}/build/generated"
GENERATED_BUILD_STAMP_SWIFT="${GENERATED_SWIFT_DIR}/ObstacleBridgeGeneratedBuildStamp.swift"
BINARY_PATH="${BUILD_DIR}/ObstacleBridgeHostRunner"
BUILD_INFO_JSON="${BUILD_DIR}/ObstacleBridgeHostRunner.build-info.json"
APP_BUNDLE="${BUILD_DIR}/ObstacleBridge.app"
APP_CONTENTS_DIR="${APP_BUNDLE}/Contents"
APP_MACOS_DIR="${APP_CONTENTS_DIR}/MacOS"
APP_RESOURCES_DIR="${APP_CONTENTS_DIR}/Resources"
APP_EXECUTABLE="${APP_MACOS_DIR}/ObstacleBridge"
APP_INFO_PLIST="${APP_CONTENTS_DIR}/Info.plist"
APP_BUNDLE_ID="${OBSTACLEBRIDGE_MACOS_BUNDLE_ID:-com.obstaclebridge.macos.ObstacleBridge}"
APP_CODESIGN_IDENTITY="${OBSTACLEBRIDGE_CODESIGN_IDENTITY:--}"
APP_ENTITLEMENTS="${OBSTACLEBRIDGE_CODESIGN_ENTITLEMENTS:-}"
APP_ICONSET_DIR="${BUILD_DIR}/ObstacleBridge.iconset"
APP_ICON_ICNS="${APP_RESOURCES_DIR}/ObstacleBridge.icns"
APP_ICON_MASTER_PNG="${IOS_DIR}/resources/obstaclebridge-icon-master.png"
APP_ICON_FALLBACK_PNG="${IOS_DIR}/resources/obstaclebridge-icon-1024.png"

cleanup_macos_metadata() {
  local path=""
  for path in "${REPO_ROOT}/.DS_Store" "${IOS_DIR}/.DS_Store"; do
    if [ -f "${path}" ]; then
      rm -f "${path}"
    fi
  done
  find "${BUILD_DIR}" -name '.DS_Store' -delete 2>/dev/null || true
}

build_macos_app_icon() {
  local icon_source=""

  if [ -f "${APP_ICON_MASTER_PNG}" ]; then
    icon_source="${APP_ICON_MASTER_PNG}"
  elif [ -f "${APP_ICON_FALLBACK_PNG}" ]; then
    icon_source="${APP_ICON_FALLBACK_PNG}"
  fi

  if [ -z "${icon_source}" ]; then
    echo "[build_macos_app] no app icon source found under ios/resources; skipping macOS icon generation"
    return 0
  fi

  if ! command -v sips >/dev/null 2>&1; then
    echo "[build_macos_app] sips is required to generate the macOS app icon" >&2
    return 1
  fi

  if ! command -v iconutil >/dev/null 2>&1; then
    echo "[build_macos_app] iconutil is required to generate the macOS app icon" >&2
    return 1
  fi

  rm -rf "${APP_ICONSET_DIR}"
  mkdir -p "${APP_ICONSET_DIR}"

  local base_size retina_size
  for base_size in 16 32 128 256 512; do
    retina_size=$((base_size * 2))
    sips -z "${base_size}" "${base_size}" "${icon_source}" --out "${APP_ICONSET_DIR}/icon_${base_size}x${base_size}.png" >/dev/null
    sips -z "${retina_size}" "${retina_size}" "${icon_source}" --out "${APP_ICONSET_DIR}/icon_${base_size}x${base_size}@2x.png" >/dev/null
  done

  iconutil -c icns "${APP_ICONSET_DIR}" -o "${APP_ICON_ICNS}"
  rm -rf "${APP_ICONSET_DIR}"
}

trap cleanup_macos_metadata EXIT

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

SWIFT_EXTRA_FLAGS=()
if [ "${OBSTACLEBRIDGE_SWIFT_FAILURE_INJECTION:-0}" = "1" ]; then
  SWIFT_EXTRA_FLAGS+=("-DOBSTACLEBRIDGE_FAILURE_INJECTION")
fi
SWIFT_EXTRA_FLAGS_EXPANDED=("${SWIFT_EXTRA_FLAGS[@]-}")

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
  "${SWIFT_EXTRA_FLAGS_EXPANDED[@]}" \
  -o "${BINARY_PATH}" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeAdminAPI.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeAdminAuth.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeAdminConfigChallenge.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeAdminConfigSupport.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeConfigSecretCodec.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeAdminSnapshotSupport.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeAdminWebSupport.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeNativeCrypto.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeChannelMuxCodec.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeSecureLinkPskCodec.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeSecureLinkPskRuntime.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeSecureLinkPskTransportAdapter.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeOverlayLayerTransportAdapter.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeMacOSTunAdapter.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeNativeServiceSpec.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeNativeProxyConnections.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeOverlayConnectionSupport.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgePeerAddressResolver.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeRuntimeConfig.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeOnboarding.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeWebAdminServer.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeChannelMuxUdpRuntime.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeChannelMuxTunRuntime.swift" \
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
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeWebSocketOverlayTransportOwner.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeTcpOverlayRuntime.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeTcpOverlayTransportOwner.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeQuicOverlayRuntime.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeQuicOverlayTransportOwner.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeApp/ObstacleBridgeHostRunner.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeApp/ObstacleBridgeHostRunnerMain.swift"

echo "[build_macos_app] preparing macOS app bundle"
rm -rf "${APP_BUNDLE}"
mkdir -p "${APP_MACOS_DIR}" "${APP_RESOURCES_DIR}"

echo "[build_macos_app] generating macOS app icon"
build_macos_app_icon

echo "[build_macos_app] compiling macOS app executable"
"${SWIFTC_CMD}" \
  "${SWIFT_EXTRA_FLAGS_EXPANDED[@]}" \
  -o "${APP_EXECUTABLE}" \
  "${GENERATED_BUILD_STAMP_SWIFT}" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeAdminAPI.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeAdminAuth.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeAdminConfigChallenge.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeAdminConfigSupport.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeConfigSecretCodec.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeAdminSnapshotSupport.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeAdminWebSupport.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeNativeCrypto.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeChannelMuxCodec.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeSecureLinkPskCodec.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeSecureLinkPskRuntime.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeSecureLinkPskTransportAdapter.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeOverlayLayerTransportAdapter.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeMacOSTunAdapter.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeNativeServiceSpec.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeNativeProxyConnections.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeOverlayConnectionSupport.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgePeerAddressResolver.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeRuntimeConfig.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeOnboarding.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeWebAdminServer.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeChannelMuxUdpRuntime.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeChannelMuxTunRuntime.swift" \
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
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeWebSocketOverlayTransportOwner.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeTcpOverlayRuntime.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeTcpOverlayTransportOwner.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeQuicOverlayRuntime.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeShared/ObstacleBridgeQuicOverlayTransportOwner.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeApp/ObstacleBridgeHostRunner.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeApp/ObstacleBridgeTunnelControl.swift" \
  "${REPO_ROOT}/ios/native/ObstacleBridgeApp/ObstacleBridgeMacAppMain.swift"

cat > "${APP_INFO_PLIST}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>ObstacleBridge</string>
  <key>CFBundleIdentifier</key>
  <string>${APP_BUNDLE_ID}</string>
  <key>CFBundleIconFile</key>
  <string>ObstacleBridge</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>ObstacleBridge</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>1.0</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
</dict>
</plist>
EOF

cp -R "${REPO_ROOT}/admin_web" "${APP_RESOURCES_DIR}/admin_web"
cp -R "${REPO_ROOT}/web" "${APP_RESOURCES_DIR}/web"

echo "[build_macos_app] writing build identification sidecar"
cp "${REPO_ROOT}/ios/build/generated/obstaclebridge-build-info.json" "${BUILD_INFO_JSON}"

cp "${BUILD_INFO_JSON}" "${APP_RESOURCES_DIR}/ObstacleBridge.build-info.json"

if [ "${APP_CODESIGN_IDENTITY}" != "off" ]; then
  echo "[build_macos_app] codesigning app bundle"
  CODESIGN_ARGS=(
    --force
    --deep
    --sign "${APP_CODESIGN_IDENTITY}"
    --timestamp=none
  )
  if [ -n "${APP_ENTITLEMENTS}" ]; then
    echo "[build_macos_app] using custom entitlements: ${APP_ENTITLEMENTS}"
    CODESIGN_ARGS+=(--entitlements "${APP_ENTITLEMENTS}")
  else
    echo "[build_macos_app] signing without extra entitlements so the standalone app remains launchable"
  fi
  codesign "${CODESIGN_ARGS[@]}" "${APP_BUNDLE}"
fi

echo "[build_macos_app] build completed"
echo "[build_macos_app] binary: ${BINARY_PATH}"
echo "[build_macos_app] build info: ${BUILD_INFO_JSON}"
echo "[build_macos_app] app bundle: ${APP_BUNDLE}"
