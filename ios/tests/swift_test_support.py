from __future__ import annotations

import contextlib
import os
import signal
import shutil
import subprocess
import sys
import tempfile
import time
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
def swift_core_crypto_compile_flags() -> tuple[str, ...]:
    """Expose the pinned SwiftPM Crypto product to raw-source macOS probes."""
    if sys.platform != "darwin":
        return ()
    module_dirs = sorted(ROOT.glob(".build/*/debug/Modules"))
    if not module_dirs:
        completed = subprocess.run(
            ["swift", "build", "--target", "ObstacleBridgeCore"],
            cwd=str(ROOT), capture_output=True, text=True, check=False,
        )
        if completed.returncode != 0:
            raise AssertionError(
                f"swift build --target ObstacleBridgeCore failed:\n{completed.stdout}\n{completed.stderr}"
            )
        module_dirs = sorted(ROOT.glob(".build/*/debug/Modules"))
    if not module_dirs:
        raise AssertionError("pinned Swift Crypto module directory was not produced")
    module_dir = module_dirs[0]
    # On Apple platforms swift-crypto's `Crypto` module forwards to CryptoKit.
    # SwiftPM emits the module but no standalone libCrypto artifact, so raw
    # source probes must import the module without inventing a linker input.
    return ("-I", str(module_dir))


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
MACOS_BUILD_IDLE_TIMEOUT_S = 120.0
MACOS_BUILD_ACTIVITY_POLL_S = 2.0
MACOS_BUILD_MIN_CPU_PERCENT = 0.1


@dataclass(frozen=True)
class MacOSSwiftArtifact:
    variant: str
    build_dir: Path
    binary_path: Path
    app_bundle: Path
    build_info_path: Path


def _process_tree_cpu_percent(pid: int) -> float:
    """Return aggregate CPU use for a process and descendants."""
    try:
        listing = subprocess.run(
            ["ps", "-axo", "pid=,ppid=,%cpu="],
            capture_output=True, text=True, check=False, timeout=2.0,
        )
    except (OSError, subprocess.SubprocessError):
        return 0.0
    children: dict[int, list[tuple[int, float]]] = {}
    for line in str(listing.stdout or "").splitlines():
        fields = line.split()
        if len(fields) != 3:
            continue
        try:
            child_pid, parent_pid, cpu = int(fields[0]), int(fields[1]), float(fields[2])
        except ValueError:
            continue
        children.setdefault(parent_pid, []).append((child_pid, cpu))
    total = 0.0
    pending = [int(pid)]
    seen: set[int] = set()
    while pending:
        parent = pending.pop()
        if parent in seen:
            continue
        seen.add(parent)
        for child_pid, cpu in children.get(parent, []):
            total += max(0.0, cpu)
            pending.append(child_pid)
    return total


def _build_macos_app_with_activity_monitor(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Permit slow compiles; fail only after sustained process-tree inactivity."""
    process = subprocess.Popen(
        [str(BUILD_MACOS_APP_SCRIPT)], cwd=str(ROOT), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        start_new_session=True,
    )
    last_active = time.monotonic()
    while True:
        try:
            stdout, stderr = process.communicate(timeout=MACOS_BUILD_ACTIVITY_POLL_S)
            return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
        except subprocess.TimeoutExpired:
            if _process_tree_cpu_percent(process.pid) >= MACOS_BUILD_MIN_CPU_PERCENT:
                last_active = time.monotonic()
            if time.monotonic() - last_active < MACOS_BUILD_IDLE_TIMEOUT_S:
                continue
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            stdout, stderr = process.communicate()
            raise AssertionError(
                "build_macos_app.sh had no compiler/process-tree CPU activity for "
                f"{MACOS_BUILD_IDLE_TIMEOUT_S:.0f}s and was terminated.\n"
                f"STDOUT:\n{stdout or ''}\nSTDERR:\n{stderr or ''}"
            )


def _macos_artifact_is_fresh(build_dir: Path) -> bool:
    """Reuse a complete shared artifact only when its declared inputs are older."""
    required = (
        build_dir / "ObstacleBridgeHostRunner",
        build_dir / "ObstacleBridgeTunHelper",
        build_dir / "ObstacleBridgeHostRunner.build-info.json",
        build_dir / "ObstacleBridge.app" / "Contents" / "MacOS" / "ObstacleBridge",
        build_dir / "ObstacleBridge.app" / "Contents" / "MacOS" / "ObstacleBridgeHostRunner",
    )
    try:
        oldest_artifact = min(path.stat().st_mtime for path in required)
    except OSError:
        return False
    for root in (
        IOS_DIR / "native",
        BUILD_MACOS_APP_SCRIPT,
        ROOT / "scripts" / "client-tun-hook-macos.sh",
        ROOT / "scripts" / "server-tun-hook-macos.sh",
        ROOT / "swift" / "Sources",
        ROOT / "Package.swift",
    ):
        paths = root.rglob("*") if root.is_dir() else (root,)
        for path in paths:
            if path.is_file() and path.stat().st_mtime > oldest_artifact:
                return False
    return True


def _macos_artifact_exists(build_dir: Path) -> bool:
    return all(path.is_file() for path in (
        build_dir / "ObstacleBridgeHostRunner",
        build_dir / "ObstacleBridgeTunHelper",
        build_dir / "ObstacleBridgeHostRunner.build-info.json",
        build_dir / "ObstacleBridge.app" / "Contents" / "MacOS" / "ObstacleBridge",
        build_dir / "ObstacleBridge.app" / "Contents" / "MacOS" / "ObstacleBridgeHostRunner",
    ))


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
    build_dir = IOS_DIR / "build" / ("macos" if variant == "normal" else f"macos-{variant}")
    reuse_prebuilt = str(env.get("OBSTACLEBRIDGE_REUSE_MACOS_BUILD") or "").strip() == "1"
    force_rebuild = str(env.get("OBSTACLEBRIDGE_FORCE_MACOS_BUILD") or "").strip() == "1"
    if reuse_prebuilt and not _macos_artifact_exists(build_dir):
        raise AssertionError(f"requested shared macOS artifact is incomplete: {build_dir}")
    if not reuse_prebuilt and (force_rebuild or not _macos_artifact_is_fresh(build_dir)):
        completed = _build_macos_app_with_activity_monitor(env)
        if completed.returncode != 0:
            raise AssertionError(
                "build_macos_app.sh failed with exit code "
                f"{completed.returncode}:\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
            )
    return MacOSSwiftArtifact(
        variant=variant,
        build_dir=build_dir,
        binary_path=build_dir / "ObstacleBridgeHostRunner",
        app_bundle=build_dir / "ObstacleBridge.app",
        build_info_path=build_dir / "ObstacleBridgeHostRunner.build-info.json",
    )
