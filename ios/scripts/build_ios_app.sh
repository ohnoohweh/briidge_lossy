#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IOS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${IOS_DIR}/.." && pwd)"

if [ -f "${IOS_DIR}/.local-device-env" ]; then
  # shellcheck disable=SC1091
  . "${IOS_DIR}/.local-device-env"
fi

if [ -n "${BRIEFCASE:-}" ]; then
  BRIEFCASE_CMD="${BRIEFCASE}"
elif [ -x "${REPO_ROOT}/.venv/bin/briefcase" ]; then
  BRIEFCASE_CMD="${REPO_ROOT}/.venv/bin/briefcase"
else
  BRIEFCASE_CMD="briefcase"
fi

if [ -x "${REPO_ROOT}/.venv/bin/python" ]; then
  PYTHON_CMD="${REPO_ROOT}/.venv/bin/python"
else
  PYTHON_CMD="python3"
fi

PROJECT_PBXPROJ="${IOS_DIR}/build/obstacle_bridge_ios/ios/xcode/ObstacleBridge.xcodeproj/project.pbxproj"
PROJECT_FILE="${IOS_DIR}/build/obstacle_bridge_ios/ios/xcode/ObstacleBridge.xcodeproj"
DERIVED_DATA_PATH="${DERIVED_DATA_PATH:-/tmp/obstaclebridge-ios-build}"
SIM_APP_PACKAGES_DIR="${IOS_DIR}/build/obstacle_bridge_ios/ios/xcode/ObstacleBridge/app_packages.iphonesimulator"

echo "[build_ios_app] refreshing embedded build metadata and VPN profile timestamp"
"${PYTHON_CMD}" "${REPO_ROOT}/scripts/write_build_info.py"

if [ ! -f "${PROJECT_PBXPROJ}" ]; then
  echo "[build_ios_app] Xcode project missing, creating it first"
  "${IOS_DIR}/scripts/create_ios_xcode_project.sh" --no-input
else
  echo "[build_ios_app] updating Briefcase iOS bundle so changed Python sources are included"
  (
    cd "${IOS_DIR}"
    "${BRIEFCASE_CMD}" update iOS --no-input -a obstacle_bridge_ios
  )
  echo "[build_ios_app] reapplying repo-owned Xcode project patches"
  "${PYTHON_CMD}" "${IOS_DIR}/scripts/patch_briefcase_xcode_project.py" "${PROJECT_PBXPROJ}"
fi

if [ -d "${SIM_APP_PACKAGES_DIR}" ]; then
  echo "[build_ios_app] removing simulator app payload staging (${SIM_APP_PACKAGES_DIR})"
  rm -rf "${SIM_APP_PACKAGES_DIR}"
fi

RESOLVED_APPLE_TEAM_ID="${OB_APPLE_TEAM_ID:-}"
if [ -z "${RESOLVED_APPLE_TEAM_ID}" ] && [ -f "${PROJECT_PBXPROJ}" ]; then
  RESOLVED_APPLE_TEAM_ID="$({
    grep -E '^[[:space:]]*DEVELOPMENT_TEAM = [A-Z0-9]+;' "${PROJECT_PBXPROJ}" || true
  } | head -n 1 | sed -E 's/.*DEVELOPMENT_TEAM = ([A-Z0-9]+);/\1/')"
fi

if [ -z "${RESOLVED_APPLE_TEAM_ID}" ]; then
  echo "[build_ios_app] OB_APPLE_TEAM_ID is required for xcodebuild signing" >&2
  exit 1
fi

if [ -z "${OB_APPLE_TEAM_ID:-}" ]; then
  echo "[build_ios_app] using DEVELOPMENT_TEAM=${RESOLVED_APPLE_TEAM_ID} from project settings"
fi

if [ -n "${OB_IOS_DEVICE_ID:-}" ]; then
  DESTINATION=("id=${OB_IOS_DEVICE_ID}")
  PROVISIONING_ARGS=(-allowProvisioningUpdates)
  echo "[build_ios_app] building for connected device ${OB_IOS_DEVICE_ID}"
else
  DESTINATION=("generic/platform=iOS")
  PROVISIONING_ARGS=()
  echo "[build_ios_app] building for generic iOS device target"
fi

XCODEBUILD_ARGS=(
  -project "${PROJECT_FILE}"
  -scheme ObstacleBridge
  -configuration Debug
  -destination "${DESTINATION[0]}"
  DEVELOPMENT_TEAM="${RESOLVED_APPLE_TEAM_ID}"
  CODE_SIGN_STYLE=Automatic
  -derivedDataPath "${DERIVED_DATA_PATH}"
  build
)

if [ "${#PROVISIONING_ARGS[@]}" -gt 0 ]; then
  XCODEBUILD_ARGS=("${XCODEBUILD_ARGS[@]:0:8}" "${PROVISIONING_ARGS[@]}" "${XCODEBUILD_ARGS[@]:8}")
fi

xcodebuild "${XCODEBUILD_ARGS[@]}"

echo "[build_ios_app] build completed"
echo "[build_ios_app] app bundle: ${DERIVED_DATA_PATH}/Build/Products/Debug-iphoneos/ObstacleBridge.app"
