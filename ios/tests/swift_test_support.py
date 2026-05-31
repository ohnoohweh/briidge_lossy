from __future__ import annotations

import shutil
import subprocess
import tempfile
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