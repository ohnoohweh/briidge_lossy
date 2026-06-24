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
