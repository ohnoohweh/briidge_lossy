from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import pytest


def require_swift_module(*, module_name: str, missing_swiftc_reason: str, missing_module_reason: str) -> str:
    return require_swift_modules(
        module_name,
        missing_swiftc_reason=missing_swiftc_reason,
        missing_module_reason=missing_module_reason,
    )


def require_swift_modules(*module_names: str, missing_swiftc_reason: str, missing_module_reason: str) -> str:
    swiftc = shutil.which("swiftc")
    if not swiftc:
        pytest.skip(missing_swiftc_reason)
    missing_modules = [module_name for module_name in module_names if not _swift_module_available(swiftc, module_name)]
    if missing_modules:
        joined = ", ".join(sorted(missing_modules))
        pytest.skip(f"{missing_module_reason}: missing Swift modules {joined}")
    return swiftc


@lru_cache(maxsize=None)
def _swift_module_available(swiftc: str, module_name: str) -> bool:
    with tempfile.TemporaryDirectory(prefix="swift-module-probe-") as tmpdir:
        source_path = Path(tmpdir) / "probe.swift"
        source_path.write_text(f"import {module_name}\n", encoding="utf-8")
        completed = subprocess.run(
            [swiftc, "-typecheck", str(source_path)],
            capture_output=True,
            text=True,
            check=False,
        )
    return completed.returncode == 0


ROOT = Path(__file__).resolve().parents[2]
IOS_DIR = ROOT / "ios"
BUILD_MACOS_APP_SCRIPT = IOS_DIR / "scripts" / "build_macos_app.sh"


@dataclass(frozen=True)
class MacOSSwiftArtifact:
    variant: str
    build_dir: Path
    binary_path: Path
    app_bundle: Path
    build_info_path: Path


@lru_cache(maxsize=None)
def build_macos_swift_artifact(*, failure_injection: bool = False) -> MacOSSwiftArtifact:
    if sys.platform != "darwin":
        pytest.skip("macOS Swift artifacts can only be built on macOS")
    require_swift_modules(
        "CryptoKit",
        "zlib",
        missing_swiftc_reason="swiftc is required for macOS Swift-backed tests",
        missing_module_reason="macOS Swift-backed tests require a Swift toolchain with CryptoKit and zlib support",
    )
    variant = "failure-injection" if failure_injection else "normal"
    env = dict(os.environ)
    env["OBSTACLEBRIDGE_MACOS_BUILD_VARIANT"] = variant
    if failure_injection:
        env["OBSTACLEBRIDGE_SWIFT_FAILURE_INJECTION"] = "1"
    completed = subprocess.run(
        [str(BUILD_MACOS_APP_SCRIPT)],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            "build_macos_app.sh failed with exit code "
            f"{completed.returncode}:\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    build_dir = IOS_DIR / "build" / ("macos" if variant == "normal" else f"macos-{variant}")
    return MacOSSwiftArtifact(
        variant=variant,
        build_dir=build_dir,
        binary_path=build_dir / "ObstacleBridgeHostRunner",
        app_bundle=build_dir / "ObstacleBridge.app",
        build_info_path=build_dir / "ObstacleBridgeHostRunner.build-info.json",
    )
