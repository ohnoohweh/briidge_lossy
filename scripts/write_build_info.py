#!/usr/bin/env python3
"""Write source metadata into the package so mobile builds can log their origin."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "src" / "obstacle_bridge" / "build_info.py"


def _git(args: list[str]) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return str(proc.stdout or "").strip() if proc.returncode == 0 else ""


def main() -> int:
    commit = _git(["rev-parse", "--short=12", "HEAD"]) or "unknown"
    status = _git(["status", "--porcelain"])
    diff = _git(["diff", "--binary", "HEAD"])
    diff_sha = hashlib.sha256(diff.encode("utf-8")).hexdigest()[:12] if diff else ""
    TARGET.write_text(
        "\n".join(
            [
                '"""Build metadata embedded into packaged ObstacleBridge applications."""',
                "",
                f'BUILD_COMMIT = "{commit}"',
                'BUILD_SOURCE = "embedded-build-info"',
                f"BUILD_DIRTY = {bool(status)!r}",
                f'BUILD_DIFF_SHA = "{diff_sha}"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    print(f"wrote {TARGET} commit={commit} dirty={bool(status)} diff_sha={diff_sha or '-'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
