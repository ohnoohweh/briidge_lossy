from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "capture_runtime_qualification", ROOT / "scripts" / "capture_runtime_qualification.py"
)
assert SPEC and SPEC.loader
capture_tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture_tool)


def _status(*, authenticated: bool = True) -> dict[str, object]:
    return {
        "runtime_health_record_count": 4,
        "swift_udp_bridge_state": {
            "packets_from_system": 10,
            "packets_to_system": 20,
            "myudp_runtime": {
                "connection_layers": [{
                    "layer": "secure_link",
                    "state": "authenticated" if authenticated else "handshaking",
                    "app_ready": authenticated,
                }]
            },
        },
    }


def test_preflight_requires_health_counters_and_ready_secure_link() -> None:
    assert capture_tool.preflight(_status(), require_authenticated=True) == {"from_owner": 10, "to_owner": 20}
    with pytest.raises(ValueError, match="authenticated"):
        capture_tool.preflight(_status(authenticated=False), require_authenticated=True)
    with pytest.raises(ValueError, match="runtime-health"):
        capture_tool.preflight({"swift_udp_bridge_state": {}}, require_authenticated=False)


def test_capture_writes_redacted_admin_snapshots_and_delta(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    counter = {"value": 0}

    def fetcher(url: str, _headers: dict[str, str]) -> dict[str, object]:
        if url.endswith("/api/status"):
            counter["value"] += 1
            status = _status()
            bridge = status["swift_udp_bridge_state"]
            assert isinstance(bridge, dict)
            bridge["packets_from_system"] = counter["value"]
            bridge["packets_to_system"] = counter["value"] * 2
            return status
        return {"endpoint": url}

    monkeypatch.setattr(capture_tool, "current_revision", lambda: "test-revision")
    manifest = capture_tool.capture(
        base_url="http://admin.example:18090/",
        output_dir=tmp_path / "bundle",
        build_identifier="ObstacleBridge 1.2.3 (42)",
        traffic_source="qualification traffic generator run 42",
        termination_report_location="device diagnostics/export-42",
        samples=2,
        interval_seconds=0.01,
        headers={"Authorization": "Bearer redacted"},
        require_authenticated=True,
        fetcher=fetcher,
    )

    assert manifest["repository_revision"] == "test-revision"
    assert manifest["build_identifier"] == "ObstacleBridge 1.2.3 (42)"
    assert manifest["traffic_source"] == "qualification traffic generator run 42"
    assert manifest["termination_report_location"] == "device diagnostics/export-42"
    assert manifest["admin_authentication"] == "bearer"
    assert manifest["packet_counter_delta"] == {"from_owner": 1, "to_owner": 2}
    assert json.loads((tmp_path / "bundle" / "snapshots.json").read_text())[1]["packet_counters"] == {"from_owner": 2, "to_owner": 4}
