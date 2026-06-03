#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path

from check_requirements_guard import ROOT


TEST_CASE_RE = re.compile(r"^\s*(?:async\s+)?def\s+(test_[A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)


DRIFT_EVIDENCE = [
    {
        "key": "direct_unit_parity",
        "label": "Direct unit parity",
        "kind": "direct",
        "description": "Python and Swift produce the same bytes or state transitions for the same inputs.",
        "unit_files": [
            ("tests/unit/test_channel_mux_swift_parity.py", None),
        ],
        "integration_files": [],
    },
    {
        "key": "mixed_runtime_integration",
        "label": "Mixed-runtime integration",
        "kind": "interop",
        "description": "Python and Swift runtimes talk to each other successfully over live overlay paths.",
        "unit_files": [],
        "integration_files": [
            ("tests/integration/test_overlay_e2e.py", "mixed_runtime"),
        ],
    },
    {
        "key": "swift_backed_integration",
        "label": "Swift-backed integration",
        "kind": "interop",
        "description": "Swift host-runner behavior is exercised against Python-backed expectations and peers.",
        "unit_files": [],
        "integration_files": [
            ("ios/tests/test_macos_swift_host_runner.py", None),
        ],
    },
    {
        "key": "swift_contract_unit",
        "label": "Swift contract probes",
        "kind": "contract",
        "description": "Swift-only contract tests that guard expected behavior but do not directly compare against Python output.",
        "unit_files": [
            ("ios/tests/test_ios_overlay_layer_transport_adapter.py", None),
            ("ios/tests/test_ios_secure_link_transport_adapter.py", None),
            ("ios/tests/test_ios_secure_link_runtime.py", None),
            ("ios/tests/test_ios_packet_tunnel_provider_probe.py", None),
        ],
        "integration_files": [],
    },
]


def _count_tests(rel_path: str, name_filter: str | None) -> int:
    text = (ROOT / rel_path).read_text(encoding="utf-8")
    names = TEST_CASE_RE.findall(text)
    if name_filter:
        names = [name for name in names if name_filter in name]
    return len(names)


def _lane_counts(lane: dict[str, object]) -> tuple[int, int]:
    unit = sum(_count_tests(rel, name_filter) for rel, name_filter in lane["unit_files"])
    integration = sum(_count_tests(rel, name_filter) for rel, name_filter in lane["integration_files"])
    return unit, integration


def main() -> int:
    print("Python/Swift drift evidence snapshot")
    print("===================================")
    print("This report is intentionally narrower than product coverage. It counts only tests that provide direct parity,")
    print("mixed-runtime interoperability, or Swift-side contract evidence relevant to Python/Swift functional drift.")
    print()
    total_unit = 0
    total_integration = 0
    for lane in DRIFT_EVIDENCE:
        unit, integration = _lane_counts(lane)
        total_unit += unit
        total_integration += integration
        any_count = unit + integration
        print(f"{lane['label']}:")
        print(f"  class: {lane['kind']}")
        print(f"  unit evidence: {unit}")
        print(f"  integration evidence: {integration}")
        print(f"  any evidence: {any_count}")
        print(f"  scope: {lane['description']}")
        print()
    print("Total parity-oriented evidence:")
    print(f"  unit evidence: {total_unit}")
    print(f"  integration evidence: {total_integration}")
    print(f"  any evidence: {total_unit + total_integration}")
    print()
    print("Important caveat:")
    print("  This is evidence of parity and drift resistance, not a proof of full equivalence.")
    print("  Physical-device iOS behavior and all future feature slices still need explicit coverage.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
