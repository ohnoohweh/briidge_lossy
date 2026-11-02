from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_foreground_restart_request_is_actor_owned_before_shutdown_signal() -> None:
    source = (ROOT / "swift" / "Sources" / "ObstacleBridgeLinux" / "main.swift").read_text(encoding="utf-8")

    assert "private actor ForegroundRestartState" in source
    assert "requested = true\n            ObstacleBridgeLinuxMain.requestForegroundShutdown()" in source
    assert "Task { await foregroundRestartState.request() }" in source
    assert "if await foregroundRestartState.consume() { restartForegroundProcess() }" in source
    assert "ForegroundRestartState: @unchecked Sendable" not in source
