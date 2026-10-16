"""Build and verify the Swift TUN helper selected by Python helper mode."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
from typing import Any


_LINUX_SWIFT_BACKENDS = {"linux-swift", "linux_swift", "swift-linux", "swift_native"}


def is_linux_swift_backend(name: str) -> bool:
    return str(name or "").strip().lower() in _LINUX_SWIFT_BACKENDS


def _repository_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[2]


def _git(root: pathlib.Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def expected_build_identity(root: pathlib.Path | None = None) -> dict[str, Any]:
    root = root or _repository_root()
    try:
        commit = _git(root, "rev-parse", "--short=12", "HEAD")
        dirty = bool(_git(root, "status", "--porcelain"))
        diff_sha = _git(root, "diff", "--binary", "HEAD")
    except (OSError, subprocess.CalledProcessError) as error:
        raise RuntimeError("Swift TUN helper requires a readable Git checkout to verify its build identity") from error
    digest = ""
    if diff_sha:
        import hashlib
        digest = hashlib.sha256(diff_sha.encode("utf-8")).hexdigest()[:12]
    return {"commit": commit, "dirty": dirty, "diff_sha": digest}


def _artifact_path(root: pathlib.Path) -> pathlib.Path:
    return root / "build" / "linux" / "ObstacleBridgeLinux"


def _embedded_build_identity(artifact: pathlib.Path) -> dict[str, Any] | None:
    if not artifact.is_file() or not os.access(artifact, os.X_OK):
        return None
    try:
        completed = subprocess.run(
            [str(artifact), "--helper-build-info"],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
        value = json.loads(completed.stdout)
    except (OSError, ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    return value if isinstance(value, dict) else None


def _identity_matches(actual: dict[str, Any] | None, expected: dict[str, Any]) -> bool:
    if actual is None:
        return False
    return all(actual.get(key) == value for key, value in expected.items())


def ensure_linux_swift_tun_helper() -> str:
    """Return a current Linux helper, rebuilding absent, stale, or dirty worktrees.

    A dirty checkout is deliberately never reused.  It preserves the operator's
    request that startup recompiles a helper after any uncommitted source state.
    """
    if not sys.platform.startswith("linux"):
        raise RuntimeError("linux-swift helper backend is only available on Linux")
    root = _repository_root()
    expected = expected_build_identity(root)
    artifact = _artifact_path(root)
    if expected["dirty"] or not _identity_matches(_embedded_build_identity(artifact), expected):
        script = root / "scripts" / "build_linux_app.sh"
        try:
            subprocess.run([str(script)], cwd=root, check=True, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.CalledProcessError) as error:
            raise RuntimeError("failed to build the Linux Swift TUN helper") from error
        # A dirty checkout remains dirty by design, but still must produce a
        # binary whose embedded identity precisely describes this checkout.
        if not _identity_matches(_embedded_build_identity(artifact), expected):
            raise RuntimeError("built Linux Swift TUN helper has an unexpected embedded build identity")
    return str(artifact)
