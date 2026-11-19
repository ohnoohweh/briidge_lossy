#!/usr/bin/env python3
"""Report risky Swift ownership patterns and block proven new memory hazards.

This is deliberately a conservative diff gate.  It does not claim to prove
the absence of leaks; it blocks only two construction patterns whose ownership
is syntactically explicit and reports the remaining patterns for review.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PREFIX = "swift/Sources/"
ALLOW_MARKER = "OBSTACLEBRIDGE-MEMORY-ALLOW:"
NETWORK_SEND_MARKER = "OBSTACLEBRIDGE-NETWORK-SEND-BOUNDS:"
NULL_GIT_SHA = "0" * 40

PERSISTENT_DATA_RETENTION = re.compile(
    r"\b(?:private|fileprivate|internal)\s+(?:var|let)\s+"
    r"(?:[A-Za-z_]\w+\s*:\s*\[[^\n=]*\bData\b[^\n=]*\]"
    r"|[A-Za-z_]\w*(?:pending|queue|buffer|fifo|payload|frame|wire|packet|record|message)[A-Za-z_\d]*\s*(?::[^=\n]*\bData\b|=\s*Data\s*\())",
    re.IGNORECASE,
)
NETWORK_SEND = re.compile(r"\b(?:\w+\.)?send\s*\(")
STRONG_STORED_CLOSURE = re.compile(
    r"self\.(?P<property>[A-Za-z_]\w*)\s*=\s*\{(?P<capture>\s*\[[^\]]*\])?(?P<body>.*?)\n\s*\}",
    re.DOTALL,
)
WARNING_RULES = (
    ("MEM003", re.compile(r"\b(?:private\s+)?(?:var|let)\s+delegate\s*:"), "strong delegate property; use weak for a back-reference"),
    ("MEM004", re.compile(r"addObserver\s*\([^\n]*using\s*:"), "block observer registration needs explicit token cleanup"),
    ("MEM005", re.compile(r"Timer\.scheduledTimer\s*\([^\n]*repeats\s*:\s*true"), "repeating timer needs lifecycle cancellation and weak capture review"),
    ("MEM006", re.compile(r"\.sink\s*(?:\([^)]*\))?\s*\{[^\n]*self\b"), "long-lived Combine sink captures self"),
    ("MEM007", re.compile(r"\bTask\s*\{[^\n]*self\b"), "task captures self; verify cancellation/lifetime"),
    ("MEM008", re.compile(r"\[\s*unowned\s+self\s*\]"), "unowned self capture needs a proven lifetime guarantee"),
)


def effective_base(base_ref: str) -> str:
    if base_ref == NULL_GIT_SHA:
        result = subprocess.run(["git", "merge-base", "HEAD", "origin/main"], cwd=ROOT, capture_output=True, text=True)
        return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else "HEAD^"
    return base_ref


def changed_lines(diff_args: list[str]) -> list[tuple[str, int, str]]:
    proc = subprocess.run(["git", "diff", "--unified=0", *diff_args], cwd=ROOT, check=True, capture_output=True, text=True)
    path = ""; line_number = 0; result: list[tuple[str, int, str]] = []
    for line in proc.stdout.splitlines():
        if line.startswith("+++ b/"):
            path = line[6:]
        elif line.startswith("@@ "):
            match = re.search(r"\+(\d+)(?:,\d+)?", line)
            line_number = int(match.group(1)) if match else 0
        elif path and line.startswith("+") and not line.startswith("+++"):
            result.append((path, line_number, line[1:])); line_number += 1
        elif path and not line.startswith("-"):
            line_number += 1
    return result


def _line_for_offset(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def validate(changes: list[tuple[str, int, str]]) -> tuple[list[str], list[str]]:
    errors: list[str] = []; warnings: list[str] = []
    by_path: dict[str, list[tuple[int, str]]] = {}
    for path, line, text in changes:
        if path.startswith(SOURCE_PREFIX) and path.endswith(".swift"):
            by_path.setdefault(path, []).append((line, text))
    for path, additions in by_path.items():
        changed_numbers = {line for line, _ in additions}
        added_text = "\n".join(text for _, text in additions)
        for line, text in additions:
            if PERSISTENT_DATA_RETENTION.search(text) and ALLOW_MARKER not in added_text:
                errors.append(
                    f"{path}:{line}: MEM009 persistent Data retention must use "
                    "ObstacleBridgeBoundedDataFIFO/ObstacleBridgeBoundedFIFO. "
                    f"An exceptional raw owner requires {ALLOW_MARKER} reason=<text>; bounds=<text>; test=<name>."
                )
            if NETWORK_SEND.search(text) and NETWORK_SEND_MARKER not in added_text:
                errors.append(
                    f"{path}:{line}: MEM010 Network.framework/WebSocket send requires "
                    f"{NETWORK_SEND_MARKER} inflight=<n>; queue=<bounded-owner>; test=<name>."
                )
            for rule, pattern, message in WARNING_RULES:
                if pattern.search(text):
                    warnings.append(f"{path}:{line}: {rule} review: {message}.")
        source_path = ROOT / path
        if not source_path.exists():
            continue
        source = source_path.read_text(encoding="utf-8")
        for match in STRONG_STORED_CLOSURE.finditer(source):
            start_line = _line_for_offset(source, match.start())
            end_line = _line_for_offset(source, match.end())
            capture = match.group("capture") or ""
            if not (changed_numbers & set(range(start_line, end_line + 1))):
                continue
            if "weak self" not in capture and "unowned self" not in capture and re.search(r"\bself\b", match.group("body")):
                errors.append(f"{path}:{start_line}: MEM002 self.{match.group('property')} stores a closure that strongly captures self; use [weak self] or restructure ownership.")
    return errors, warnings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--base-ref"); scope.add_argument("--staged", action="store_true")
    args = parser.parse_args()
    try:
        changes = changed_lines(["--cached"] if args.staged else [f"{effective_base(args.base_ref)}...HEAD"])
    except subprocess.CalledProcessError as exc:
        sys.stderr.write(exc.stderr or str(exc)); return 2
    errors, warnings = validate(changes)
    if warnings:
        sys.stderr.write("\n".join(warnings) + "\n")
    if errors:
        sys.stderr.write("\n".join(errors) + "\n"); return 1
    print("Swift memory safety guard passed." + (f" ({len(warnings)} review warning(s))" if warnings else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
