#!/usr/bin/env python3
"""Require explicit synchronization evidence for changed unchecked Swift owners."""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SWIFT_SOURCE = "swift/Sources/"
UNCHECKED = "@unchecked Sendable"
MUTABLE_COLLECTION = re.compile(r"\bvar\s+\w+.*(?:\[|Set<|Dictionary<)|\.\s*(?:append|remove|insert|updateValue)\s*\(|\w+\s*\[[^]]+\]\s*=")
EVIDENCE = "OBSTACLEBRIDGE-CONCURRENCY:"
# This guard cannot retroactively require markers for PR edits that predate
# its introduction. New collection mutations after this commit are gated.
POLICY_BASELINE = "2aba4ed4"

def effective_base(base_ref: str) -> str:
    if subprocess.run(["git", "merge-base", "--is-ancestor", base_ref, POLICY_BASELINE], cwd=ROOT).returncode == 0:
        return POLICY_BASELINE
    return base_ref

def changed_lines(args: list[str]) -> dict[str, list[str]]:
    proc = subprocess.run(["git", "diff", "--unified=0", *args], cwd=ROOT, check=True, capture_output=True, text=True)
    path = ""; result: dict[str, list[str]] = {}
    for line in proc.stdout.splitlines():
        if line.startswith("+++ b/"):
            path = line[6:]
        elif path and line.startswith("+") and not line.startswith("+++"):
            result.setdefault(path, []).append(line[1:])
    return result

def validate(changes: dict[str, list[str]]) -> list[str]:
    errors = []
    for path, added in changes.items():
        if not path.startswith(SWIFT_SOURCE) or not path.endswith(".swift"):
            continue
        source = (ROOT / path).read_text(encoding="utf-8")
        if UNCHECKED not in source or not any(MUTABLE_COLLECTION.search(line) for line in added):
            continue
        evidence = "\n".join(added)
        if EVIDENCE not in evidence:
            errors.append(f"{path}: changed mutable collection in an @unchecked Sendable owner requires a changed-line {EVIDENCE} lock|actor|serial; test=<concurrency test> marker.")
    return errors

def main() -> int:
    parser = argparse.ArgumentParser()
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--base-ref"); scope.add_argument("--staged", action="store_true")
    args = parser.parse_args()
    try:
        errors = validate(changed_lines(["--cached"] if args.staged else [f"{effective_base(args.base_ref)}...HEAD"]))
    except (OSError, subprocess.CalledProcessError) as exc:
        sys.stderr.write(str(exc)); return 2
    if errors:
        sys.stderr.write("\n".join(errors) + "\n"); return 1
    print("Swift concurrency guard passed.")
    return 0

if __name__ == "__main__": raise SystemExit(main())
