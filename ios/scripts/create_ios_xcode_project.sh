#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
IOS_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$IOS_DIR/.." && pwd)"

if [ -n "${BRIEFCASE:-}" ]; then
  BRIEFCASE_CMD="$BRIEFCASE"
elif [ -x "$REPO_ROOT/.venv/bin/briefcase" ]; then
  BRIEFCASE_CMD="$REPO_ROOT/.venv/bin/briefcase"
else
  BRIEFCASE_CMD="briefcase"
fi

cd "$IOS_DIR"
"$BRIEFCASE_CMD" create iOS "$@"
"$REPO_ROOT/.venv/bin/python" "$IOS_DIR/scripts/patch_briefcase_xcode_project.py"
