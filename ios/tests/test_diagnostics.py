from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ios" / "src"))

from obstacle_bridge_ios import diagnostics


def test_update_component_state_and_snapshot_paths(tmp_path) -> None:
    diagnostics.update_component_state(tmp_path, "python-runtime", state="running", heartbeat_count=3)
    diagnostics.log_event(tmp_path, "sample_event", detail="ok")

    state_path = diagnostics.component_state_path(tmp_path, "python-runtime")
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    snapshot = diagnostics.snapshot(tmp_path)

    assert payload["component"] == "python-runtime"
    assert payload["state"] == "running"
    assert payload["heartbeat_count"] == 3
    assert snapshot["component_state_files"]["python_runtime"] == str(state_path)
    assert snapshot["component_state_files"]["native_provider"].endswith("ipserver-native-provider-state.json")
    assert snapshot["component_state_files"]["udp_connector"].endswith("ipserver-udp-connector-state.json")


def test_build_diagnostics_use_package_metadata_without_server_runtime() -> None:
    source = (ROOT / "ios" / "src" / "obstacle_bridge_ios" / "diagnostics.py").read_text(encoding="utf-8")

    assert "from obstacle_bridge.bridge import _detect_build_info" not in source
    build = diagnostics._detect_build_info()
    assert build["repo_root"] == ""
    assert "commit" in build


def test_diagnostic_jsonl_rotates_and_snapshot_uses_a_bounded_tail(tmp_path) -> None:
    path = diagnostics.event_log_path(tmp_path)
    original_maximum = diagnostics.DIAGNOSTIC_LOG_MAX_BYTES
    try:
        diagnostics.DIAGNOSTIC_LOG_MAX_BYTES = 64
        diagnostics.append_jsonl(path, {"event": "first", "payload": "x" * 40})
        diagnostics.append_jsonl(path, {"event": "second", "payload": "x" * 40})
    finally:
        diagnostics.DIAGNOSTIC_LOG_MAX_BYTES = original_maximum

    assert path.with_suffix(".jsonl.1").exists()
    assert [json.loads(line)["event"] for line in diagnostics.read_jsonl_tail(path, 10)] == ["second"]
