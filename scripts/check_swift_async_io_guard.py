#!/usr/bin/env python3
"""Reject newly introduced blocking Swift receive operations in runtime code."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_PREFIX = "swift/Sources/"
RECEIVE_CALL = re.compile(r"\b(?:read|recv|recvfrom)\s*\(")
NONBLOCKING = re.compile(r"\b(?:MSG_DONTWAIT|O_NONBLOCK)\b")
EXCEPTION = "OBSTACLEBRIDGE-ASYNC-IO-EXCEPTION:"


def changed_lines(diff_args: list[str]) -> list[tuple[str, int, str]]:
    proc = subprocess.run(
        ["git", "diff", "--unified=0", *diff_args], cwd=ROOT, check=True,
        capture_output=True, text=True,
    )
    path: str | None = None
    line_number = 0
    result: list[tuple[str, int, str]] = []
    for line in proc.stdout.splitlines():
        if line.startswith("+++ b/"):
            path = line[6:]
        elif line.startswith("@@ "):
            match = re.search(r"\+(\d+)(?:,\d+)?", line)
            line_number = int(match.group(1)) if match else 0
        elif path and line.startswith("+") and not line.startswith("+++"):
            result.append((path, line_number, line[1:]))
            line_number += 1
        elif path and not line.startswith("-"):
            line_number += 1
    return result


def validate(diff_args: list[str]) -> list[str]:
    errors: list[str] = []
    for path, line_number, line in changed_lines(diff_args):
        if not path.startswith(SOURCE_PREFIX) or not path.endswith(".swift"):
            continue
        if RECEIVE_CALL.search(line) and not NONBLOCKING.search(line) and EXCEPTION not in line:
            errors.append(
                f"{path}:{line_number}: new blocking receive call is forbidden. "
                "Use a readiness/framework callback and MSG_DONTWAIT, or document the bounded "
                f"bootstrap exception on this line with {EXCEPTION} <reason>."
            )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--base-ref")
    scope.add_argument("--staged", action="store_true")
    args = parser.parse_args()
    diff_args = ["--cached"] if args.staged else [f"{args.base_ref}...HEAD"]
    try:
        errors = validate(diff_args)
    except subprocess.CalledProcessError as exc:
        sys.stderr.write(exc.stderr or str(exc))
        return 2
    if errors:
        sys.stderr.write("\n".join(errors) + "\n")
        return 1
    print("Swift async I/O guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
