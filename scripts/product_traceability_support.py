#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path

from check_requirements_guard import ROOT


PRODUCTS = ("python", "macos", "ios")
TRACEABILITY_TEST_KEYS = ("tests", "integration_tests", "unit_tests")

IOS_UNIT_PRODUCT_FILES = {
    "tests/unit/test_bridge_tun_ios.py",
    "tests/unit/test_check_ios_fedora_log_fit.py",
    "tests/unit/test_replay_ios_udp_connector_trace.py",
    "tests/unit/test_runner_ios_status_callbacks.py",
}

IOS_INTEGRATION_FILES = {
    "tests/integration/test_ios_e2e.py",
    "tests/integration/test_ios_simulator_e2e.py",
}
TEST_CASE_RE = re.compile(r"^\s*(?:async\s+)?def\s+(test_[A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)


def normalize_rel_path(path: str | Path) -> str:
    path_str = str(path).replace("\\", "/")
    try:
        resolved = Path(path_str)
        if resolved.is_absolute():
            return resolved.relative_to(ROOT).as_posix()
    except Exception:
        pass
    return path_str


def classify_test_file(path: str | Path) -> str | None:
    rel_path = normalize_rel_path(path)
    if rel_path in IOS_INTEGRATION_FILES:
        return "ios"
    if rel_path.startswith("ios/tests/test_macos_"):
        return "macos"
    if rel_path.startswith("ios/tests/"):
        return "ios"
    if rel_path in IOS_UNIT_PRODUCT_FILES:
        return "ios"
    if rel_path.startswith("tests/"):
        name = Path(rel_path).name
        if "_ios" in name:
            return "ios"
        return "python"
    return None


def classify_test_ref(test_ref: str) -> str | None:
    rel_path, _, test_name = test_ref.partition("::")
    rel_path = normalize_rel_path(rel_path)
    if rel_path == "ios/tests/test_m3_native_sources.py":
        lowered = test_name.lower()
        if "macos" in lowered or "host_runner" in lowered:
            return "macos"
        return "ios"
    return classify_test_file(rel_path)


def iter_test_files() -> list[Path]:
    seen: set[str] = set()
    out: list[Path] = []
    for base in (ROOT / "tests", ROOT / "ios/tests"):
        if not base.exists():
            continue
        for path in sorted(base.rglob("test_*.py")):
            rel = path.relative_to(ROOT).as_posix()
            if rel in seen:
                continue
            seen.add(rel)
            out.append(path)
    return out


def count_test_defs(path: Path) -> int:
    text = path.read_text(encoding="utf-8")
    return len(TEST_CASE_RE.findall(text))
