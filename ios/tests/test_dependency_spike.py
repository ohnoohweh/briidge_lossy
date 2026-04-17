from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ios" / "src"))

from obstacle_bridge_ios.dependency_spike import (
    run_m2_dependency_spike,
    run_m2_dependency_spike_sync,
    write_m2_dependency_spike_report,
)


def test_m2_dependency_spike_reports_all_checks() -> None:
    report = asyncio.run(run_m2_dependency_spike())

    assert report["milestone"] == "M2"
    checks = {item["name"]: item for item in report["checks"]}
    assert set(checks.keys()) == {
        "websockets_device_smoke",
        "cryptography_device_or_fallback",
        "aioquic_result_documented",
        "asyncio_tcp_loopback",
        "asyncio_udp_loopback",
    }
    assert all(bool(item["ok"]) for item in checks.values())


def test_m2_dependency_spike_sync_and_report_persistence(tmp_path: Path) -> None:
    report = run_m2_dependency_spike_sync()
    report_path = write_m2_dependency_spike_report(report, base_dir=tmp_path)

    assert report_path.exists()
    loaded = json.loads(report_path.read_text(encoding="utf-8"))
    assert loaded["milestone"] == "M2"
    assert isinstance(loaded["checks"], list)
