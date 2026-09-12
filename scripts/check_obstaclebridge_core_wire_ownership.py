#!/usr/bin/env python3
"""Reject Core-owned wire serializers below the Linux adapter boundary."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADAPTER_FILES = (
    "swift/Sources/ObstacleBridgeLinuxAdapters/ObstacleBridgeLinuxServiceCatalog.swift",
    "swift/Sources/ObstacleBridgeLinuxAdapters/ObstacleBridgeLinuxServiceDataPlane.swift",
)
OVERLAY_ADAPTER_FILE = "swift/Sources/ObstacleBridgeLinuxAdapters/ObstacleBridgeLinuxOverlayTransport.swift"
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
OVERLAY_FORBIDDEN_FRAGMENTS = (
    "UInt32(payload.count + 1).bigEndian",
    "var pongLength = UInt32(9).bigEndian",
    "var pong = Data([2])",
    "Data([0]) + payload",
)


def validate() -> list[str]:
    errors: list[str] = []
    for relative_path in ADAPTER_FILES:
        text = (ROOT / relative_path).read_text(encoding="utf-8")
        for fragment in FORBIDDEN_FRAGMENTS:
            if fragment in text:
                errors.append(f"{relative_path} retains core wire serializer fragment {fragment!r}")
    overlay_text = (ROOT / OVERLAY_ADAPTER_FILE).read_text(encoding="utf-8")
    for fragment in OVERLAY_FORBIDDEN_FRAGMENTS:
        if fragment in overlay_text:
            errors.append(f"{OVERLAY_ADAPTER_FILE} retains Core overlay serializer fragment {fragment!r}")
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
