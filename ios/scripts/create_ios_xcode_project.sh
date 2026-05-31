#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
IOS_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$IOS_DIR/.." && pwd)"
APP_NAME="obstacle_bridge_ios"
PROJECT_PBXPROJ="$IOS_DIR/build/$APP_NAME/ios/xcode/ObstacleBridge.xcodeproj/project.pbxproj"

if [ -n "${BRIEFCASE:-}" ]; then
  BRIEFCASE_CMD="$BRIEFCASE"
elif [ -x "$REPO_ROOT/.venv/bin/briefcase" ]; then
  BRIEFCASE_CMD="$REPO_ROOT/.venv/bin/briefcase"
else
  BRIEFCASE_CMD="briefcase"
fi

cd "$IOS_DIR"
"$REPO_ROOT/.venv/bin/python" "$REPO_ROOT/scripts/write_build_info.py"
if [ -f "$PROJECT_PBXPROJ" ]; then
  echo "[create_ios_xcode_project] existing iOS project detected, refreshing app bundle"
  "$BRIEFCASE_CMD" update iOS --no-input -a "$APP_NAME"
else
  echo "[create_ios_xcode_project] creating iOS project"
  "$BRIEFCASE_CMD" create iOS "$@"
fi
"$REPO_ROOT/.venv/bin/python" "$IOS_DIR/scripts/patch_ios_xcode_project.py"
