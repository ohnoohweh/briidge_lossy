#!/usr/bin/env bash
# Build, archive, export, and upload the signed ObstacleBridge iOS container
# app to TestFlight. IPServer is an embedded packet-tunnel extension and is
# signed and archived as part of the ObstacleBridge scheme.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IOS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${IOS_DIR}/.." && pwd)"
PROJECT_FILE="${IOS_DIR}/build/obstacle_bridge_ios/ios/xcode/ObstacleBridge.xcodeproj"

load_release_environment() {
  local env_file="$1"
  local assignment
  local name
  local value

  [ -f "${env_file}" ] || return 0
  # The shared local environment can contain unrelated credentials. Evaluate
  # it only in a subshell and import the release allowlist, so those values do
  # not become part of xcodebuild or upload subprocess environments.
  while IFS= read -r assignment; do
    name="${assignment%%=*}"
    value="${assignment#*=}"
    case "${name}" in
      OB_APPLE_TEAM_ID|OB_APPSTORE_API_KEY_ID|OB_APPSTORE_API_ISSUER_ID|OB_APPSTORE_API_KEY_PATH|OB_APPSTORE_PROVIDER_PUBLIC_ID|OB_IOS_DISTRIBUTION_CERTIFICATE_PATH|OB_IOS_DISTRIBUTION_PRIVATE_KEY_PATH|OB_IOS_MARKETING_VERSION|OB_IOS_BUILD_NUMBER|OB_TESTFLIGHT_OUTPUT_DIR|OB_TESTFLIGHT_DERIVED_DATA_PATH|OB_TESTFLIGHT_GROUP_NAME|OB_APPSTORE_BUNDLE_ID)
        printf -v "${name}" '%s' "${value}"
        export "${name}"
        ;;
    esac
  done < <(
    (
      # shellcheck disable=SC1090
      . "${env_file}"
      for name in \
        OB_APPLE_TEAM_ID \
        OB_APPSTORE_API_KEY_ID \
        OB_APPSTORE_API_ISSUER_ID \
        OB_APPSTORE_API_KEY_PATH \
        OB_APPSTORE_PROVIDER_PUBLIC_ID \
        OB_IOS_DISTRIBUTION_CERTIFICATE_PATH \
        OB_IOS_DISTRIBUTION_PRIVATE_KEY_PATH \
        OB_IOS_MARKETING_VERSION \
        OB_IOS_BUILD_NUMBER \
        OB_TESTFLIGHT_OUTPUT_DIR \
        OB_TESTFLIGHT_DERIVED_DATA_PATH \
        OB_TESTFLIGHT_GROUP_NAME \
        OB_APPSTORE_BUNDLE_ID; do
        if [ -n "${!name:-}" ]; then
          printf '%s=%s\n' "${name}" "${!name}"
        fi
      done
    )
  )
}

# The user-wide file is the primary local release configuration. Repo-local
# files remain optional machine-specific overrides and are intentionally
# untracked.
load_release_environment "${HOME}/.local-device-env"
load_release_environment "${IOS_DIR}/.local-device-env"
load_release_environment "${IOS_DIR}/.local-testflight-env"

require_value() {
  local name="$1"
  local value="${!name:-}"
  if [ -z "${value}" ]; then
    echo "[release_ios_testflight] ${name} is required" >&2
    exit 2
  fi
}

for command in xcodebuild xcrun security; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "[release_ios_testflight] ${command} is required" >&2
    exit 2
  }
done

require_value OB_APPLE_TEAM_ID
require_value OB_APPSTORE_API_KEY_ID
require_value OB_APPSTORE_API_ISSUER_ID
require_value OB_APPSTORE_API_KEY_PATH

if [ ! -f "${OB_APPSTORE_API_KEY_PATH}" ]; then
  echo "[release_ios_testflight] OB_APPSTORE_API_KEY_PATH does not name a readable API key file" >&2
  exit 2
fi

has_distribution_identity() {
  security find-identity -v -p codesigning 2>/dev/null | grep -Eq '(Apple|iPhone) Distribution:'
}

if ! has_distribution_identity; then
  require_value OB_IOS_DISTRIBUTION_CERTIFICATE_PATH
  require_value OB_IOS_DISTRIBUTION_PRIVATE_KEY_PATH
  if [ ! -f "${OB_IOS_DISTRIBUTION_CERTIFICATE_PATH}" ] || [ ! -f "${OB_IOS_DISTRIBUTION_PRIVATE_KEY_PATH}" ]; then
    echo "[release_ios_testflight] distribution certificate and private-key paths must name readable files" >&2
    exit 2
  fi
  echo "[release_ios_testflight] importing configured distribution identity into the login keychain"
  security import "${OB_IOS_DISTRIBUTION_PRIVATE_KEY_PATH}" -k "${HOME}/Library/Keychains/login.keychain-db" -T /usr/bin/codesign
  security import "${OB_IOS_DISTRIBUTION_CERTIFICATE_PATH}" -k "${HOME}/Library/Keychains/login.keychain-db" -T /usr/bin/codesign
fi
if ! has_distribution_identity; then
  echo "[release_ios_testflight] no usable Apple or iPhone Distribution signing identity is installed after import" >&2
  exit 2
fi

IOS_MARKETING_VERSION="${OB_IOS_MARKETING_VERSION:-$(date -u +%Y.%m.%d)}"
# TestFlight requires every upload to use a new numeric build number. The UTC
# timestamp avoids a duplicate when the same commit is rebuilt; callers may
# set OB_IOS_BUILD_NUMBER to use their release-system sequence instead.
IOS_BUILD_NUMBER="${OB_IOS_BUILD_NUMBER:-$(date -u +%Y%m%d%H%M%S)}"
case "${IOS_BUILD_NUMBER}" in
  *[!0-9]*|"")
    echo "[release_ios_testflight] OB_IOS_BUILD_NUMBER must contain only digits" >&2
    exit 2
    ;;
esac

OUTPUT_DIR="${OB_TESTFLIGHT_OUTPUT_DIR:-${IOS_DIR}/build/testflight}"
ARCHIVE_PATH="${OUTPUT_DIR}/ObstacleBridge-${IOS_MARKETING_VERSION}-${IOS_BUILD_NUMBER}.xcarchive"
EXPORT_DIR="${OUTPUT_DIR}/export-${IOS_MARKETING_VERSION}-${IOS_BUILD_NUMBER}"
DERIVED_DATA_PATH="${OB_TESTFLIGHT_DERIVED_DATA_PATH:-${OUTPUT_DIR}/derived-${IOS_BUILD_NUMBER}}"
TESTFLIGHT_GROUP_NAME="${OB_TESTFLIGHT_GROUP_NAME:-ObstacleBridgeTesters}"
APPSTORE_BUNDLE_ID="${OB_APPSTORE_BUNDLE_ID:-com.obstaclebridge.obstacle-bridge-ios}"
EXPORT_OPTIONS_PATH="$(mktemp "${TMPDIR:-/tmp}/obstaclebridge-testflight-export.XXXXXX.plist")"

cleanup() {
  rm -f "${EXPORT_OPTIONS_PATH}"
}
trap cleanup EXIT

mkdir -p "${OUTPUT_DIR}"

# mktemp creates a zero-length file.  PlistBuddy only edits an existing plist,
# so initialize the temporary path before adding the App Store export settings.
/usr/bin/plutil -create xml1 "${EXPORT_OPTIONS_PATH}"
/usr/libexec/PlistBuddy -c 'Add :method string app-store-connect' "${EXPORT_OPTIONS_PATH}"
/usr/libexec/PlistBuddy -c 'Add :signingStyle string automatic' "${EXPORT_OPTIONS_PATH}"
/usr/libexec/PlistBuddy -c "Add :teamID string ${OB_APPLE_TEAM_ID}" "${EXPORT_OPTIONS_PATH}"
/usr/bin/plutil -lint "${EXPORT_OPTIONS_PATH}" >/dev/null

export OB_IOS_MARKETING_VERSION="${IOS_MARKETING_VERSION}"
export OB_IOS_BUILD_NUMBER="${IOS_BUILD_NUMBER}"
export OB_IOS_ALLOW_PROVISIONING_UPDATES=1
export OB_IOS_PREPARE_ONLY=1
export DERIVED_DATA_PATH

echo "[release_ios_testflight] refreshing generated app project and packaged sources"
"${IOS_DIR}/scripts/build_ios_app.sh"

if [ ! -d "${PROJECT_FILE}" ]; then
  echo "[release_ios_testflight] generated Xcode project is missing after refresh" >&2
  exit 1
fi

echo "[release_ios_testflight] archiving ObstacleBridge version=${IOS_MARKETING_VERSION} build=${IOS_BUILD_NUMBER}"
xcodebuild \
  -project "${PROJECT_FILE}" \
  -scheme ObstacleBridge \
  -configuration Release \
  -destination 'generic/platform=iOS' \
  -archivePath "${ARCHIVE_PATH}" \
  -allowProvisioningUpdates \
  DEVELOPMENT_TEAM="${OB_APPLE_TEAM_ID}" \
  MARKETING_VERSION="${IOS_MARKETING_VERSION}" \
  CURRENT_PROJECT_VERSION="${IOS_BUILD_NUMBER}" \
  CODE_SIGN_STYLE=Automatic \
  archive

echo "[release_ios_testflight] exporting App Store IPA"
xcodebuild -exportArchive \
  -archivePath "${ARCHIVE_PATH}" \
  -exportPath "${EXPORT_DIR}" \
  -exportOptionsPlist "${EXPORT_OPTIONS_PATH}" \
  -allowProvisioningUpdates

validate_bundle_version() {
  local bundle_path="$1"
  local short_version
  local build_version

  short_version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "${bundle_path}/Info.plist")"
  build_version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "${bundle_path}/Info.plist")"
  if ! [[ "${short_version}" =~ ^[0-9]+(\.[0-9]+){0,2}$ ]]; then
    echo "[release_ios_testflight] invalid CFBundleShortVersionString in ${bundle_path}" >&2
    exit 1
  fi
  if ! [[ "${build_version}" =~ ^[0-9]+(\.[0-9]+){0,2}$ ]]; then
    echo "[release_ios_testflight] invalid CFBundleVersion in ${bundle_path}" >&2
    exit 1
  fi
  printf '%s|%s\n' "${short_version}" "${build_version}"
}

APP_BUNDLE_PATH="${ARCHIVE_PATH}/Products/Applications/ObstacleBridge.app"
EXTENSION_BUNDLE_PATH="${APP_BUNDLE_PATH}/PlugIns/IPServer.appex"
APP_VERSION="$(validate_bundle_version "${APP_BUNDLE_PATH}")"
EXTENSION_VERSION="$(validate_bundle_version "${EXTENSION_BUNDLE_PATH}")"
if [ "${APP_VERSION}" != "${EXTENSION_VERSION}" ]; then
  echo "[release_ios_testflight] container and IPServer bundle versions differ" >&2
  exit 1
fi
echo "[release_ios_testflight] validated bundle version ${APP_VERSION%%|*} (${APP_VERSION#*|})"

IPA_PATH="${EXPORT_DIR}/ObstacleBridge.ipa"
if [ ! -f "${IPA_PATH}" ]; then
  IPA_PATH="$(find "${EXPORT_DIR}" -maxdepth 1 -type f -name '*.ipa' -print -quit)"
fi
if [ -z "${IPA_PATH:-}" ] || [ ! -f "${IPA_PATH}" ]; then
  echo "[release_ios_testflight] no IPA was exported" >&2
  exit 1
fi

UPLOAD_ARGS=(
  --upload-package "${IPA_PATH}"
  --api-key "${OB_APPSTORE_API_KEY_ID}"
  --api-issuer "${OB_APPSTORE_API_ISSUER_ID}"
  --p8-file-path "${OB_APPSTORE_API_KEY_PATH}"
  --wait
)
if [ -n "${OB_APPSTORE_PROVIDER_PUBLIC_ID:-}" ]; then
  UPLOAD_ARGS+=(--provider-public-id "${OB_APPSTORE_PROVIDER_PUBLIC_ID}")
fi

echo "[release_ios_testflight] uploading IPA to App Store Connect and waiting for processing"
xcrun altool "${UPLOAD_ARGS[@]}"

echo "[release_ios_testflight] waiting for App Store Connect processing and assigning ${TESTFLIGHT_GROUP_NAME}"
"${IOS_DIR}/scripts/assign_testflight_group.py" \
  --key-id "${OB_APPSTORE_API_KEY_ID}" \
  --issuer-id "${OB_APPSTORE_API_ISSUER_ID}" \
  --private-key "${OB_APPSTORE_API_KEY_PATH}" \
  --bundle-id "${APPSTORE_BUNDLE_ID}" \
  --build-number "${IOS_BUILD_NUMBER}" \
  --group-name "${TESTFLIGHT_GROUP_NAME}"

echo "[release_ios_testflight] upload completed"
echo "[release_ios_testflight] archive=${ARCHIVE_PATH}"
echo "[release_ios_testflight] ipa=${IPA_PATH}"
