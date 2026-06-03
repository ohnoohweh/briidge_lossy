#!/usr/bin/env python3
"""Write source metadata into the package so mobile builds can log their origin."""

from __future__ import annotations

import hashlib
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PY_GENERATED_TARGET = ROOT / "src" / "obstacle_bridge" / "_generated" / "build_info_generated.py"
JSON_GENERATED_TARGET = ROOT / "ios" / "build" / "generated" / "obstaclebridge-build-info.json"
IOS_GENERATED_BUILD_STAMP = ROOT / "ios" / "build" / "generated" / "ObstacleBridgeGeneratedBuildStamp.swift"


def _git(args: list[str]) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return str(proc.stdout or "").strip() if proc.returncode == 0 else ""


def _write_ios_generated_build_stamp(build_timestamp_utc: str) -> None:
    IOS_GENERATED_BUILD_STAMP.parent.mkdir(parents=True, exist_ok=True)
    IOS_GENERATED_BUILD_STAMP.write_text(
        "\n".join(
            [
                "import Foundation",
                "",
                "enum ObstacleBridgeGeneratedBuildStamp {",
                f'    static let providerBuildTimestampUTC = "{build_timestamp_utc}"',
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )


def _write_python_generated_build_info(
    *,
    commit: str,
    dirty: bool,
    diff_sha: str,
    build_timestamp_utc: str,
) -> None:
    PY_GENERATED_TARGET.parent.mkdir(parents=True, exist_ok=True)
    PY_GENERATED_TARGET.write_text(
        "\n".join(
            [
                '"""Generated build metadata for packaged ObstacleBridge applications."""',
                "",
                f'BUILD_COMMIT = "{commit}"',
                'BUILD_SOURCE = "embedded-build-info"',
                f"BUILD_DIRTY = {dirty!r}",
                f'BUILD_DIFF_SHA = "{diff_sha}"',
                f'BUILD_TIMESTAMP_UTC = "{build_timestamp_utc}"',
                "",
            ]
        ),
        encoding="utf-8",
    )


def _write_generated_json(
    *,
    commit: str,
    dirty: bool,
    diff_sha: str,
    build_timestamp_utc: str,
) -> None:
    import json

    JSON_GENERATED_TARGET.parent.mkdir(parents=True, exist_ok=True)
    JSON_GENERATED_TARGET.write_text(
        json.dumps(
            {
                "commit": commit,
                "source": "embedded-build-info",
                "repo_root": "",
                "tainted": dirty,
                "tracked_changes": 0,
                "untracked_changes": 0,
                "available": True,
                "diff_sha": diff_sha,
                "build_timestamp_utc": build_timestamp_utc,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def main() -> int:
    commit = _git(["rev-parse", "--short=12", "HEAD"]) or "unknown"
    status = _git(["status", "--porcelain"])
    diff = _git(["diff", "--binary", "HEAD"])
    diff_sha = hashlib.sha256(diff.encode("utf-8")).hexdigest()[:12] if diff else ""
    build_timestamp_utc = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    dirty = bool(status)
    _write_python_generated_build_info(
        commit=commit,
        dirty=dirty,
        diff_sha=diff_sha,
        build_timestamp_utc=build_timestamp_utc,
    )
    _write_generated_json(
        commit=commit,
        dirty=dirty,
        diff_sha=diff_sha,
        build_timestamp_utc=build_timestamp_utc,
    )
    _write_ios_generated_build_stamp(build_timestamp_utc)
    print(
        f"wrote {PY_GENERATED_TARGET} commit={commit} dirty={dirty} diff_sha={diff_sha or '-'} "
        f"build_timestamp_utc={build_timestamp_utc}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
