"""Build and verify the Swift TUN helper selected by Python helper mode."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
from typing import Any


_LINUX_SWIFT_BACKENDS = {"linux-swift", "linux_swift", "swift-linux", "swift_native"}
_DARWIN_SWIFT_BACKENDS = {"darwin-swift", "darwin_swift", "macos-swift", "macos_swift", "swift-darwin"}


def is_linux_swift_backend(name: str) -> bool:
    return str(name or "").strip().lower() in _LINUX_SWIFT_BACKENDS


def is_darwin_swift_backend(name: str) -> bool:
    return str(name or "").strip().lower() in _DARWIN_SWIFT_BACKENDS


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
    return completed.stdout


def expected_build_identity(root: pathlib.Path | None = None) -> dict[str, Any]:
    root = root or _repository_root()
    try:
        commit = _git(root, "rev-parse", "--short=8", "HEAD").strip()
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
    """Return a Linux helper whose embedded identity matches this checkout.

    The diff digest is part of the identity, so a matching dirty artifact is
    safe to reuse.  This matters when both peers start at once: rebuilding an
    already matching dirty artifact serializes on SwiftPM's lock and can make
    either peer miss its startup deadline.
    """
    if not sys.platform.startswith("linux"):
        raise RuntimeError("linux-swift helper backend is only available on Linux")
    root = _repository_root()
    expected = expected_build_identity(root)
    artifact = _artifact_path(root)
    if not _identity_matches(_embedded_build_identity(artifact), expected):
        script = root / "scripts" / "build_linux_app.sh"
        try:
            subprocess.run([str(script)], cwd=root, check=True, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.CalledProcessError) as error:
            raise RuntimeError("failed to build the Linux Swift TUN helper") from error
        if not _identity_matches(_embedded_build_identity(artifact), expected):
            raise RuntimeError("built Linux Swift TUN helper has an unexpected embedded build identity")
    return str(artifact)


def ensure_darwin_swift_tun_helper() -> str:
    """Return the current packaged macOS protocol-v1 helper."""
    if not sys.platform.startswith("darwin"):
        raise RuntimeError("darwin-swift helper backend is only available on macOS")
    root = _repository_root()
    expected = expected_build_identity(root)
    artifact = root / "ios" / "build" / "macos" / "ObstacleBridge.app" / "Contents" / "MacOS" / "ObstacleBridgeTunHelper"
    if expected["dirty"] or not _identity_matches(_embedded_build_identity(artifact), expected):
        try:
            subprocess.run([str(root / "ios" / "scripts" / "build_macos_app.sh")], cwd=root, check=True, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.CalledProcessError) as error:
            raise RuntimeError("failed to build the macOS Swift TUN helper") from error
        if not _identity_matches(_embedded_build_identity(artifact), expected):
            raise RuntimeError("built macOS Swift TUN helper has an unexpected embedded build identity")
    return str(artifact)
