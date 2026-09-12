#!/usr/bin/env python3
"""Reject ChannelMux service wire serializers below the Linux Core boundary."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADAPTER_FILES = (
    "swift/Sources/ObstacleBridgeLinuxAdapters/ObstacleBridgeLinuxServiceCatalog.swift",
    "swift/Sources/ObstacleBridgeLinuxAdapters/ObstacleBridgeLinuxServiceDataPlane.swift",
)
FORBIDDEN_FRAGMENTS = (
    'Data("O5"',
    'Data("O4"',
    'Data("RS3"',
    'Data("RS2"',
    "JSONSerialization",
    "readUInt16",
    "readUInt32",
    "readUInt64",
    "appendUInt16",
    "appendUInt32",
    "appendUInt64",
)


def validate() -> list[str]:
    errors: list[str] = []
    for relative_path in ADAPTER_FILES:
        text = (ROOT / relative_path).read_text(encoding="utf-8")
        for fragment in FORBIDDEN_FRAGMENTS:
            if fragment in text:
                errors.append(f"{relative_path} retains core wire serializer fragment {fragment!r}")
    return errors


def main() -> int:
    errors = validate()
    if errors:
        sys.stderr.write("\n".join(errors) + "\n")
        return 1
    print("ObstacleBridgeCore wire-ownership guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
