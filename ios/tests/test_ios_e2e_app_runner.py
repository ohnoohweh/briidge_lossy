from __future__ import annotations

import asyncio
import json
import socket
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
E2E_SRC = ROOT / "ios" / "e2e_app" / "src"
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
if str(E2E_SRC) not in sys.path:
    sys.path.insert(0, str(E2E_SRC))

from obstacle_bridge_ios_e2e.__main__ import main
from obstacle_bridge_ios_e2e.runner import (
    run_host_websocket_probe,
    run_ws_udp_echo_probe,
    write_report,
)


def _unused_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def _with_websocket_echo() -> tuple[str, list[dict[str, Any]], Any]:
    import websockets

    messages: list[dict[str, Any]] = []

    async def handle(websocket: Any) -> None:
        raw = await websocket.recv()
        message = json.loads(raw)
        messages.append(message)
        await websocket.send(json.dumps(message, sort_keys=True))

    server = await websockets.serve(handle, "127.0.0.1", 0)
    port = int(server.sockets[0].getsockname()[1])
    return f"ws://127.0.0.1:{port}/obstaclebridge-ios-e2e", messages, server


def test_e2e_runner_websocket_probe_reports_success() -> None:
    async def scenario() -> None:
        url, messages, server = await _with_websocket_echo()
        try:
            report = await run_host_websocket_probe(url)
        finally:
            server.close()
            await server.wait_closed()

        assert report["ok"] is True
        assert report["app"] == "obstacle_bridge_ios_e2e"
        assert report["probe"] == "host-websocket"
        assert report["url"] == url
        assert report["received"]["message"] == "obstaclebridge-ios-e2e-probe"
        assert messages == [report["sent"]]

    asyncio.run(scenario())


def test_e2e_runner_writes_report_to_dedicated_app_directory(tmp_path: Path) -> None:
    report_path = write_report({"ok": True}, root=tmp_path)

    assert report_path == tmp_path / "host-websocket-latest.json"
    assert json.loads(report_path.read_text(encoding="utf-8")) == {"ok": True}


def test_e2e_runner_writes_ws_udp_echo_report_to_dedicated_app_directory(tmp_path: Path) -> None:
    report_path = write_report({"ok": True, "probe": "ws-udp-echo"}, root=tmp_path)

    assert report_path == tmp_path / "ws-udp-echo-latest.json"
    assert json.loads(report_path.read_text(encoding="utf-8")) == {"ok": True, "probe": "ws-udp-echo"}


def test_e2e_main_requires_probe_url(capsys) -> None:
    exit_code = main(["--host-websocket-probe"])

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert exit_code == 2
    assert report["app"] == "obstacle_bridge_ios_e2e"
    assert report["error"] == "--host-websocket-probe requires a ws:// URL"


def test_e2e_main_validates_ws_udp_echo_arguments(capsys) -> None:
    exit_code = main(["--ws-udp-echo-probe", "ws://127.0.0.1:8080"])

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert exit_code == 2
    assert report["app"] == "obstacle_bridge_ios_e2e"
    assert report["probe"] == "ws-udp-echo"
    assert "--local-udp-port is required" in report["error"]


def test_e2e_runner_ws_udp_echo_reports_startup_failure_on_missing_peer() -> None:
    async def scenario() -> None:
        report = await run_ws_udp_echo_probe(
            ws_url="ws://127.0.0.1:9/obstaclebridge",
            local_udp_port=_unused_udp_port(),
            target_udp_host="127.0.0.1",
            target_udp_port=_unused_udp_port(),
            payload=b"\x01ios-udp",
            expected=b"\x02ios-udp",
            timeout_sec=0.5,
        )

        assert report["ok"] is False
        assert report["app"] == "obstacle_bridge_ios_e2e"
        assert report["probe"] == "ws-udp-echo"
        assert report["payload_hex"] == b"\x01ios-udp".hex()
        assert report["expected_hex"] == b"\x02ios-udp".hex()

    asyncio.run(scenario())
