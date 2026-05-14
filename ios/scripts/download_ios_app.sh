#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "${SCRIPT_DIR}/.local-device-env" ]; then
  # shellcheck disable=SC1091
  . "${SCRIPT_DIR}/.local-device-env"
fi

xcodebuild \
  -project build/obstacle_bridge_ios/ios/xcode/ObstacleBridge.xcodeproj \
  -scheme ObstacleBridge \
  -configuration Debug \
  -destination "id=${OB_IOS_DEVICE_ID}" \
  -allowProvisioningUpdates \
  DEVELOPMENT_TEAM="${OB_APPLE_TEAM_ID}" \
  CODE_SIGN_STYLE=Automatic \
  -derivedDataPath /tmp/obstaclebridge-ios-device \
  build

xcrun devicectl device install app \
  --device "${OB_IOS_DEVICE_ID}" \
  /tmp/obstaclebridge-ios-device/Build/Products/Debug-iphoneos/ObstacleBridge.app
  
  

  