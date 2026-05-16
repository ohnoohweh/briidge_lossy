#!/usr/bin/env python3
"""Write source metadata into the package so mobile builds can log their origin."""

from __future__ import annotations

import hashlib
import subprocess
from datetime import datetime, timezone
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "src" / "obstacle_bridge" / "build_info.py"
IOS_TUNNEL_CONTROL = ROOT / "ios" / "native" / "ObstacleBridgeApp" / "ObstacleBridgeTunnelControl.swift"


def _git(args: list[str]) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return str(proc.stdout or "").strip() if proc.returncode == 0 else ""


def _replace_once(pattern: str, replacement: str, text: str, *, path: Path) -> str:
    updated, count = re.subn(pattern, replacement, text, count=1)
    if count != 1:
        raise RuntimeError(f"expected to replace exactly once in {path}: {pattern}")
    return updated


def _write_ios_tunnel_build_stamp(build_timestamp_utc: str) -> None:
    original = IOS_TUNNEL_CONTROL.read_text(encoding="utf-8")
    updated = _replace_once(
        r'private static let providerBuildTimestampUTC = "[^"]+"',
        f'private static let providerBuildTimestampUTC = "{build_timestamp_utc}"',
        original,
        path=IOS_TUNNEL_CONTROL,
    )
    if updated != original:
        IOS_TUNNEL_CONTROL.write_text(updated, encoding="utf-8")


def main() -> int:
    commit = _git(["rev-parse", "--short=12", "HEAD"]) or "unknown"
    status = _git(["status", "--porcelain"])
    diff = _git(["diff", "--binary", "HEAD"])
    diff_sha = hashlib.sha256(diff.encode("utf-8")).hexdigest()[:12] if diff else ""
    build_timestamp_utc = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    TARGET.write_text(
        "\n".join(
            [
                '"""Build metadata embedded into packaged ObstacleBridge applications."""',
                "",
                f'BUILD_COMMIT = "{commit}"',
                'BUILD_SOURCE = "embedded-build-info"',
                f"BUILD_DIRTY = {bool(status)!r}",
                f'BUILD_DIFF_SHA = "{diff_sha}"',
                f'BUILD_TIMESTAMP_UTC = "{build_timestamp_utc}"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    _write_ios_tunnel_build_stamp(build_timestamp_utc)
    print(
        f"wrote {TARGET} commit={commit} dirty={bool(status)} diff_sha={diff_sha or '-'} "
        f"build_timestamp_utc={build_timestamp_utc}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
