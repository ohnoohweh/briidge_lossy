#!/usr/bin/env python3
"""Guard: verify the current branch PR body follows the repository PR template.

This script uses the GitHub CLI `gh` to fetch the current branch's PR body
and checks for required template headings. Exit code 0 on success, 2 on
validation failure, 1 on other errors.

Usage:
  python scripts/check_pr_template_guard.py [--pr PR_NUMBER]

Requires: `gh` installed and authenticated, and run from the repo root.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys


REQUIRED_HEADINGS = ["## Summary", "## Problem", "## Changes", "## Validation"]


def run(cmd: list[str]) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return p.returncode, p.stdout.strip()
    except FileNotFoundError:
        return 1, ""


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--pr", type=str, help="PR number or URL (optional)")
    args = p.parse_args()

    gh_cmd = ["gh", "pr", "view"]
    if args.pr:
        gh_cmd.append(args.pr)
    gh_cmd.extend(["--json", "body"])

    rc, out = run(gh_cmd)
    if rc != 0:
        print("ERROR: failed to run 'gh pr view'. Is gh installed and authenticated?", file=sys.stderr)
        return 1

    try:
        body = json.loads(out).get("body", "")
    except json.JSONDecodeError:
        body = out

    missing = [h for h in REQUIRED_HEADINGS if h not in body]
    if missing:
        print("PR template check failed. Missing headings:", ", ".join(missing), file=sys.stderr)
        return 2

    print("PR template check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
