#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PY="$ROOT_DIR/.venv/bin/python"

if [[ -x "$VENV_PY" ]]; then
  PYTHON_BIN="$VENV_PY"
else
  PYTHON_BIN="python3"
fi

INTERACTIVE_ELEVATION=0
if [[ "${1:-}" == "--interactive-elevation" ]]; then
  # Local functional qualification may use the operator's normal Terminal
  # password prompt. Keep unattended automation on the scoped NOPASSWD path.
  INTERACTIVE_ELEVATION=1
  shift
fi

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  # Re-exec the whitelisted wrapper itself. Prefixing it with `env` changes
  # the sudo command path, so a narrowly scoped NOPASSWD rule cannot match.
  if [[ "$INTERACTIVE_ELEVATION" -eq 1 ]]; then
    exec sudo "$0" "$@"
  fi
  exec sudo -n "$0" "$@"
fi

export OBSTACLEBRIDGE_RUN_MACOS_ELEVATED=1
export GITHUB_ACTIONS="${GITHUB_ACTIONS:-${OBSTACLEBRIDGE_GITHUB_ACTIONS:-}}"

restore_artifact_ownership() {
  if [[ -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
    chown -R "${SUDO_UID}:${SUDO_GID}" \
      "$ROOT_DIR/.build" \
      "$ROOT_DIR/ios/build/macos" \
      "$ROOT_DIR/ios/build/generated" \
      "$ROOT_DIR/src/obstacle_bridge/_generated" \
      2>/dev/null || true
  fi
}

trap restore_artifact_ownership EXIT

cd "$ROOT_DIR"
if [[ "${1:-}" == "--diagnose-macos-tun-helper" ]]; then
  helper_label="com.obstaclebridge.macos.ObstacleBridge.TunHelper"
  launchctl print "system/${helper_label}" 2>&1 || true
  log show --style compact --last 15m \
    --predicate "process == \"ObstacleBridgeTunHelper\" OR eventMessage CONTAINS \"${helper_label}\"" \
    2>&1 || true
  exit 0
fi

REUSE_EXISTING_BUILD=0
APP_BUNDLE_OVERRIDE=""
RUN_PACKAGED_XPC_QUALIFICATION=0
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --codesign-identity)
      if [[ "$#" -lt 2 || -z "${2:-}" ]]; then
        echo "[run_macos_swift_elevated_tests] --codesign-identity requires an identity" >&2
        exit 2
      fi
      export OBSTACLEBRIDGE_CODESIGN_IDENTITY="$2"
      # A signing identity changes the packaged artifact even if Swift sources
      # are unchanged; bypass source-only freshness checks for this request.
      export OBSTACLEBRIDGE_FORCE_MACOS_BUILD=1
      shift 2
      ;;
    --reuse-macos-build)
      REUSE_EXISTING_BUILD=1
      shift
      ;;
    --app-bundle)
      if [[ "$#" -lt 2 || -z "${2:-}" ]]; then
        echo "[run_macos_swift_elevated_tests] --app-bundle requires an absolute app-bundle path" >&2
        exit 2
      fi
      APP_BUNDLE_OVERRIDE="$2"
      shift 2
      ;;
    --run-packaged-xpc-qualification)
      # These tests intentionally remain opt-in while the macOS BTM/XPC
      # qualification blocker is unresolved. The normal product path proves
      # the in-process fallback through the routine elevated matrix.
      RUN_PACKAGED_XPC_QUALIFICATION=1
      shift
      ;;
    --)
      shift
      break
      ;;
    *)
      break
      ;;
  esac
done

if [[ -n "$APP_BUNDLE_OVERRIDE" && -n "${OBSTACLEBRIDGE_CODESIGN_IDENTITY:-}" ]]; then
  echo "[run_macos_swift_elevated_tests] --app-bundle cannot be combined with --codesign-identity" >&2
  exit 2
fi

if [[ -n "$APP_BUNDLE_OVERRIDE" ]]; then
  if [[ "$APP_BUNDLE_OVERRIDE" != /* ]]; then
    echo "[run_macos_swift_elevated_tests] --app-bundle must be absolute" >&2
    exit 2
  fi
  export OBSTACLEBRIDGE_MACOS_APP_BUNDLE="$APP_BUNDLE_OVERRIDE"
  REUSE_EXISTING_BUILD=1
elif [[ "$REUSE_EXISTING_BUILD" -eq 1 ]]; then
  for required_artifact in \
    "$ROOT_DIR/ios/build/macos/ObstacleBridgeHostRunner" \
    "$ROOT_DIR/ios/build/macos/ObstacleBridge.app/Contents/MacOS/ObstacleBridgeHostRunner" \
    "$ROOT_DIR/ios/build/macos/ObstacleBridge.app/Contents/MacOS/ObstacleBridgeTunHelper"; do
    if [[ ! -x "$required_artifact" ]]; then
      echo "[run_macos_swift_elevated_tests] --reuse-macos-build requires $required_artifact" >&2
      exit 2
    fi
  done
else
  # Build the complete app bundle exactly once.  The test helper reuses that
  # declared shared artifact for every selected elevated case.
  "$PYTHON_BIN" -c 'from ios.tests.swift_test_support import build_macos_swift_artifact; build_macos_swift_artifact()'
fi
export OBSTACLEBRIDGE_REUSE_MACOS_BUILD=1
# A cold Swift build is allowed 180 seconds by swift_test_support.  Keep the
# outer pytest deadline above that build allowance plus the live-test budget;
# otherwise pytest interrupts a valid build at 120 seconds and retries it for
# every test case.
TEST_TARGETS=(tests/integration/test_macos_swift_elevated.py)
if [[ "$#" -gt 0 ]]; then
  # A node id replaces the default file target.  Passing both makes pytest run
  # the whole file and the selected node, which repeats every elevated case.
  TEST_TARGETS=("$@")
fi
MARK_EXPRESSION="macos_elevated and not macos_xpc_qualification"
if [[ "$RUN_PACKAGED_XPC_QUALIFICATION" -eq 1 ]]; then
  MARK_EXPRESSION="macos_elevated"
fi
"$PYTHON_BIN" -m pytest -vv --timeout=300 -rs -m "$MARK_EXPRESSION" --run-macos-elevated "${TEST_TARGETS[@]}"
