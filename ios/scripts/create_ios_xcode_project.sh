#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
IOS_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$IOS_DIR/.." && pwd)"
APP_NAME="obstacle_bridge_ios"
PROJECT_PBXPROJ="$IOS_DIR/build/$APP_NAME/ios/xcode/ObstacleBridge.xcodeproj/project.pbxproj"
XCODE_ROOT="$IOS_DIR/build/$APP_NAME/ios/xcode"
PYTHON_SUPPORT_XCFRAMEWORK="$XCODE_ROOT/Support/Python.xcframework"

if [ -n "${BRIEFCASE:-}" ]; then
  BRIEFCASE_CMD="$BRIEFCASE"
elif [ -x "$REPO_ROOT/.venv/bin/briefcase" ]; then
  BRIEFCASE_CMD="$REPO_ROOT/.venv/bin/briefcase"
else
  BRIEFCASE_CMD="briefcase"
fi

cd "$IOS_DIR"
"$REPO_ROOT/.venv/bin/python" "$REPO_ROOT/scripts/write_build_info.py"
if [ -f "$PROJECT_PBXPROJ" ] && [ -d "$PYTHON_SUPPORT_XCFRAMEWORK" ]; then
  echo "[create_ios_xcode_project] existing iOS project detected, refreshing app bundle"
  "$BRIEFCASE_CMD" update iOS --no-input -a "$APP_NAME"
else
  if [ -d "$IOS_DIR/build/$APP_NAME" ]; then
    echo "[create_ios_xcode_project] removing incomplete generated iOS environment"
    rm -rf "$IOS_DIR/build/$APP_NAME"
  fi
  echo "[create_ios_xcode_project] project support missing, creating iOS environment"
  "$BRIEFCASE_CMD" create iOS "$@"
fi
"$REPO_ROOT/.venv/bin/python" "$IOS_DIR/scripts/patch_ios_xcode_project.py"
