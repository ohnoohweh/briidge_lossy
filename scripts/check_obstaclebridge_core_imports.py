#!/usr/bin/env python3
"""Keep ObstacleBridgeCore independent of operating-system frameworks."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORE_ROOT = ROOT / "swift/Sources/ObstacleBridgeCore"
FORBIDDEN_IMPORTS = {
    "Darwin",
    "Glibc",
    "WinSDK",
    "Network",
    "NetworkExtension",
    "Security",
    "ServiceManagement",
    "CryptoKit",
    "CommonCrypto",
    "zlib",
    "SwiftUI",
    "UIKit",
    "AppKit",
}
IMPORT_RE = re.compile(r"^\s*import\s+([A-Za-z_][A-Za-z0-9_]*)\b", re.MULTILINE)


def validate() -> list[str]:
    errors: list[str] = []
    for path in sorted(CORE_ROOT.glob("*.swift")):
        imports = IMPORT_RE.findall(path.read_text(encoding="utf-8"))
        for module in imports:
            if module in FORBIDDEN_IMPORTS:
                errors.append(f"{path.relative_to(ROOT)} imports forbidden core module {module}")
    return errors


def main() -> int:
    errors = validate()
    if errors:
        sys.stderr.write("\n".join(errors) + "\n")
        return 1
    print("ObstacleBridgeCore import guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
