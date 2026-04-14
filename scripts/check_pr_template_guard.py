#!/usr/bin/env python3
"""Guard: verify the current branch PR body follows the repository PR template.

This script uses the GitHub CLI `gh` to fetch the current branch's PR body
and checks for required template headings. Exit code 0 on success, 2 on
validation failure, 1 on other errors.

Usage:
  python scripts/check_pr_template_guard.py [--pr PR_NUMBER]
  python scripts/check_pr_template_guard.py --body-file /path/to/pr-body.md

Requires: `gh` installed and authenticated, and run from the repo root.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import json
import subprocess
import sys


TEMPLATE_PATH = Path(".github/PULL_REQUEST_TEMPLATE.md")

REQUIRED_HEADINGS = [
    "## Summary",
    "## Problem",
    "## Changes",
    "## Why This Matters",
    "## Validation",
    "## Reviewer Notes",
    "Checklist before merging:",
]

PLACEHOLDER_FRAGMENTS = [
    "(One-paragraph summary",
    "(Concrete, observable problem",
    "(What changed in code",
    "(Short description of the risk/benefit",
    "Results: (e.g.",
    "Focus review on: (list",
    "Suggested reviewers: (@handle)",
]


def run(cmd: list[str]) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return p.returncode, p.stdout.strip()
    except FileNotFoundError:
        return 1, ""


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--pr", type=str, help="PR number or URL (optional)")
    p.add_argument("--body-file", type=str, help="Read PR body from a local file instead of gh")
    args = p.parse_args()

    if args.body_file:
        try:
            body = Path(args.body_file).read_text(encoding="utf-8")
        except OSError as exc:
            print(f"ERROR: failed to read PR body file {args.body_file!r}: {exc}", file=sys.stderr)
            return 1
    else:
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
    placeholders = [fragment for fragment in PLACEHOLDER_FRAGMENTS if fragment in body]
    if missing:
        print("PR template check failed.", file=sys.stderr)
        print(f"Template: {TEMPLATE_PATH}", file=sys.stderr)
        print("Missing required headings:", ", ".join(missing), file=sys.stderr)
        print("Please apply the repository PR template and fill in the missing section(s).", file=sys.stderr)
        return 2
    if placeholders:
        print("PR template check failed.", file=sys.stderr)
        print(f"Template: {TEMPLATE_PATH}", file=sys.stderr)
        print("Found unfilled template placeholder text:", file=sys.stderr)
        for fragment in placeholders:
            print(f"- {fragment}", file=sys.stderr)
        print("Please replace placeholder instructions with PR-specific content.", file=sys.stderr)
        return 2

    print("PR template check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
