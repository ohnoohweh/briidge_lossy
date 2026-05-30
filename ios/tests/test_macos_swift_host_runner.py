from __future__ import annotations

import json
import shutil
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SHARED_NATIVE_DIR = ROOT / "ios" / "native" / "ObstacleBridgeShared"
MAC_RUNNER_SOURCE = ROOT / "ios" / "native" / "ObstacleBridgeMacRunner" / "ObstacleBridgeMacHostRunner.swift"


def _unused_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _compile_mac_host_runner(binary_path: Path) -> None:
    swiftc = shutil.which("swiftc")
    if not swiftc:
        pytest.skip("swiftc is required for macOS Swift host runner tests")
    command = [
        swiftc,
        "-o",
        str(binary_path),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeCompressLayerRuntime.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeOverlayStackPlanner.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeWebSocketPayloadCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeWebSocketOverlayRuntime.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeTcpOverlayRuntime.swift"),
        str(MAC_RUNNER_SOURCE),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise AssertionError(f"swiftc failed with exit code {completed.returncode}:\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}")


def _http_json(url: str, *, timeout_sec: float = 2.0) -> dict:
    with urllib.request.urlopen(url, timeout=timeout_sec) as response:
        return json.loads(response.read().decode("utf-8"))


def _wait_http_json(url: str, *, timeout_sec: float = 10.0) -> dict:
    deadline = time.time() + timeout_sec
    last_error = "unknown"
    while time.time() < deadline:
        try:
            return _http_json(url, timeout_sec=1.0)
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            time.sleep(0.1)
    raise AssertionError(f"timed out waiting for {url}: {last_error}")


def test_macos_swift_host_runner_bootstraps_ws_stack_and_serves_status(tmp_path: Path) -> None:
    binary_path = tmp_path / "obstaclebridge-mac-host-runner"
    _compile_mac_host_runner(binary_path)

    status_port = _unused_tcp_port()
    runtime_config_path = tmp_path / "runtime.json"
    runtime_config_path.write_text(
        json.dumps(
            {
                "overlay_transport": "ws",
                "ws_peer": "bridge.example.net",
                "ws_peer_port": 8443,
                "ws_payload_mode": "base64",
                "ws_send_timeout": 7.5,
                "secure_link": True,
                "secure_link_mode": "psk",
                "secure_link_psk": "mac-host-runner-psk",
                "compress_layer": True,
                "compress_layer_algo": "zlib",
                "compress_layer_level": 5,
                "compress_layer_min_bytes": 96,
                "compress_layer_types": "data,data_ack",
                "admin_web": True,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": status_port,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--status-port",
            str(status_port),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        status = _wait_http_json(f"http://127.0.0.1:{status_port}/api/status")
        with urllib.request.urlopen(f"http://127.0.0.1:{status_port}/", timeout=1.0) as response:
            html = response.read().decode("utf-8")

        assert status["ok"] is True
        assert status["mode"] == "swift_host_runner"
        assert status["admin_port"] == status_port
        assert status["admin_url"] == f"http://127.0.0.1:{status_port}/"
        bootstrap = status["bootstrap_state"]
        assert bootstrap["status"] == "prepared"
        assert bootstrap["transport"] == "ws"
        assert bootstrap["secure_link_mode"] == "psk"
        assert bootstrap["compress_runtime"] == "ready"
        assert bootstrap["websocket_runtime"] == "ready"
        assert bootstrap["compress_layer_types"] == "data,data_ack"
        assert bootstrap["ws_payload_mode"] == "base64"
        assert "ObstacleBridge macOS Swift Host Runner" in html
        assert "/api/status" in html
    finally:
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )