from __future__ import annotations

import asyncio
import json
import socket
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
E2E_SRC = ROOT / "ios" / "e2e_app" / "src"
IOS_SRC = ROOT / "ios" / "src"
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
if str(IOS_SRC) not in sys.path:
    sys.path.insert(0, str(IOS_SRC))
if str(E2E_SRC) not in sys.path:
    sys.path.insert(0, str(E2E_SRC))

from obstacle_bridge_ios_e2e.__main__ import main
from obstacle_bridge_ios_e2e.runner import (
    run_runtime_config,
    run_webadmin_http_probe,
    run_host_websocket_probe,
    run_ws_secure_link_probe,
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


def test_e2e_runner_writes_ws_secure_link_report_to_dedicated_app_directory(tmp_path: Path) -> None:
    report_path = write_report({"ok": True, "probe": "ws-secure-link"}, root=tmp_path)

    assert report_path == tmp_path / "ws-secure-link-latest.json"
    assert json.loads(report_path.read_text(encoding="utf-8")) == {"ok": True, "probe": "ws-secure-link"}


def test_e2e_runner_writes_runtime_config_report_to_dedicated_app_directory(tmp_path: Path) -> None:
    report_path = write_report({"ok": True, "probe": "runtime-config"}, root=tmp_path)

    assert report_path == tmp_path / "runtime-config-latest.json"
    assert json.loads(report_path.read_text(encoding="utf-8")) == {"ok": True, "probe": "runtime-config"}


def test_e2e_runner_writes_embedded_webadmin_report_to_dedicated_app_directory(tmp_path: Path) -> None:
    report_path = write_report({"ok": True, "probe": "embedded-webadmin"}, root=tmp_path)

    assert report_path == tmp_path / "embedded-webadmin-latest.json"
    assert json.loads(report_path.read_text(encoding="utf-8")) == {"ok": True, "probe": "embedded-webadmin"}


def test_e2e_runner_writes_webadmin_http_report_to_dedicated_app_directory(tmp_path: Path) -> None:
    report_path = write_report({"ok": True, "probe": "webadmin-http"}, root=tmp_path)

    assert report_path == tmp_path / "webadmin-http-latest.json"
    assert json.loads(report_path.read_text(encoding="utf-8")) == {"ok": True, "probe": "webadmin-http"}


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


def test_e2e_main_validates_ws_secure_link_arguments(capsys) -> None:
    exit_code = main(["--ws-secure-link-probe", "ws://127.0.0.1:8080"])

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert exit_code == 2
    assert report["app"] == "obstacle_bridge_ios_e2e"
    assert report["probe"] == "ws-secure-link"
    assert "--secure-link-psk is required" in report["error"]


def test_e2e_main_validates_runtime_config_arguments(capsys) -> None:
    exit_code = main(["--runtime-config", "/definitely/missing.json"])

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert exit_code == 2
    assert report["app"] == "obstacle_bridge_ios_e2e"
    assert report["probe"] == "runtime-config"
    assert "No such file or directory" in report["error"]


def test_e2e_main_accepts_embedded_webadmin_probe(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "obstacle_bridge_ios_e2e.__main__.run_embedded_webadmin_probe_sync",
        lambda **kwargs: {"ok": True, "app": "obstacle_bridge_ios_e2e", "probe": "embedded-webadmin", **kwargs},
    )

    exit_code = main(["--embedded-webadmin-probe", "--timeout-sec", "5", "--restart-timeout-sec", "3"])

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert exit_code == 0
    assert report["probe"] == "embedded-webadmin"
    assert report["timeout_sec"] == 5.0
    assert report["restart_timeout_sec"] == 3.0


def test_e2e_main_accepts_webadmin_http_probe(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "obstacle_bridge_ios_e2e.__main__.run_webadmin_http_probe_sync",
        lambda **kwargs: {"ok": True, "app": "obstacle_bridge_ios_e2e", "probe": "webadmin-http", **kwargs},
    )

    exit_code = main(
        [
            "--webadmin-http-probe",
            "--timeout-sec",
            "5",
            "--attempts",
            "4",
            "--delay-sec",
            "0.25",
            "--probe-url",
            "http://10.77.0.2:18080/",
            "--probe-url",
            "http://127.0.0.1:18080/",
        ]
    )

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert exit_code == 0
    assert report["probe"] == "webadmin-http"
    assert report["timeout_sec"] == 5.0
    assert report["attempts"] == 4
    assert report["delay_sec"] == 0.25
    assert report["urls"] == ["http://10.77.0.2:18080/", "http://127.0.0.1:18080/"]


def test_e2e_main_validates_webadmin_http_probe_arguments(capsys) -> None:
    exit_code = main(["--webadmin-http-probe", "--attempts", "bad"])

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert exit_code == 2
    assert report["app"] == "obstacle_bridge_ios_e2e"
    assert report["probe"] == "webadmin-http"
    assert "invalid --webadmin-http-probe arguments" in report["error"]


def test_e2e_main_validates_embedded_webadmin_probe_arguments(capsys) -> None:
    exit_code = main(["--embedded-webadmin-probe", "--timeout-sec", "bad"])

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert exit_code == 2
    assert report["app"] == "obstacle_bridge_ios_e2e"
    assert report["probe"] == "embedded-webadmin"
    assert "invalid --embedded-webadmin-probe arguments" in report["error"]


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


def test_e2e_runner_ws_secure_link_reports_startup_failure_on_missing_peer() -> None:
    async def scenario() -> None:
        report = await run_ws_secure_link_probe(
            ws_url="ws://127.0.0.1:9/obstaclebridge",
            secure_link_psk="ios-sim-psk",
            timeout_sec=0.5,
            hold_after_success_sec=0.0,
        )

        assert report["ok"] is False
        assert report["app"] == "obstacle_bridge_ios_e2e"
        assert report["probe"] == "ws-secure-link"
        assert report["secure_link_mode"] == "psk"

    asyncio.run(scenario())


def test_e2e_runner_runtime_config_reports_webadmin_url_and_started_state() -> None:
    async def scenario() -> None:
        report = await run_runtime_config(
            config={
                "overlay_transport": "ws",
                "ws_peer": "127.0.0.1",
                "ws_peer_port": 9,
                "admin_web": True,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": 18080,
                "status": False,
            },
            hold_sec=0.0,
        )

        assert report["ok"] is True
        assert report["probe"] == "runtime-config"
        assert report["started"] is True
        assert report["webadmin_url"] == "http://127.0.0.1:18080/"

    asyncio.run(scenario())


def test_e2e_runner_webadmin_http_probe_reports_connection_failures() -> None:
    async def scenario() -> None:
        report = await run_webadmin_http_probe(
            urls=["http://127.0.0.1:9/"],
            timeout_sec=0.25,
            attempts=1,
            delay_sec=0.0,
        )

        assert report["ok"] is False
        assert report["app"] == "obstacle_bridge_ios_e2e"
        assert report["probe"] == "webadmin-http"
        assert report["probe_urls"] == ["http://127.0.0.1:9/"]
        assert "shared_logs_after" in report
        assert report["probes"][0]["ok"] is False
        assert report["probes"][0]["attempts"][0]["meta"]["error_type"] in {"URLError", "ConnectionRefusedError"}

    asyncio.run(scenario())
