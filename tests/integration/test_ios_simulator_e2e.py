from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from obstacle_bridge.core import ObstacleBridgeClient


ROOT = Path(__file__).resolve().parents[2]
IOS_DIR = ROOT / "ios"
IOS_E2E_APP_NAME = "obstacle_bridge_ios_e2e"
IOS_E2E_BUNDLE_ID = "com.obstaclebridge.obstacle-bridge-ios-e2e"
IOS_WS_UDP_REQUEST = b"\x01ios-simulator-ws-udp"
IOS_WS_UDP_RESPONSE = b"\x02ios-simulator-ws-udp"
IOS_SECURE_LINK_PSK = "ios-simulator-secure-link-psk"


def _unused_port(kind: int) -> int:
    with socket.socket(socket.AF_INET, kind) as sock:
        if kind == socket.SOCK_STREAM:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class HostWebSocketEcho:
    def __init__(self) -> None:
        self.port = 0
        self.messages: list[dict[str, Any]] = []
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._thread_main, daemon=True)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server: Any = None
        self._error: BaseException | None = None

    def __enter__(self) -> "HostWebSocketEcho":
        self._thread.start()
        if not self._ready.wait(timeout=10.0):
            raise RuntimeError("host WebSocket echo server did not start")
        if self._error is not None:
            raise RuntimeError("host WebSocket echo server failed to start") from self._error
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._loop is not None and self._server is not None:
            self._loop.call_soon_threadsafe(self._server.close)
        self._thread.join(timeout=10.0)

    def _thread_main(self) -> None:
        try:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(self._run())
        except BaseException as exc:
            self._error = exc
            self._ready.set()

    async def _run(self) -> None:
        try:
            import websockets
        except Exception as exc:
            self._error = exc
            self._ready.set()
            return

        async def handle(websocket: Any) -> None:
            raw = await websocket.recv()
            message = json.loads(raw)
            self.messages.append(message)
            await websocket.send(json.dumps(message, sort_keys=True))

        self._server = await websockets.serve(handle, "127.0.0.1", 0)
        self.port = int(self._server.sockets[0].getsockname()[1])
        self._ready.set()
        await self._server.wait_closed()


class _UDPBounceProtocol(asyncio.DatagramProtocol):
    def __init__(self, messages: list[bytes]) -> None:
        self.messages = messages
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: Any) -> None:
        payload = bytes(data)
        self.messages.append(payload)
        if self.transport is not None:
            response = bytes([0x02]) + payload[1:] if payload else b""
            self.transport.sendto(response, addr)


class HostWsUdpBridgePeer:
    def __init__(self) -> None:
        self.ws_port = _unused_port(socket.SOCK_STREAM)
        self.udp_port = _unused_port(socket.SOCK_DGRAM)
        self.messages: list[bytes] = []
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._thread_main, daemon=True)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop_event: asyncio.Event | None = None
        self._error: BaseException | None = None

    def __enter__(self) -> "HostWsUdpBridgePeer":
        self._thread.start()
        if not self._ready.wait(timeout=10.0):
            raise RuntimeError("host WS/UDP bridge peer did not start")
        if self._error is not None:
            raise RuntimeError("host WS/UDP bridge peer failed to start") from self._error
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._loop is not None and self._stop_event is not None:
            self._loop.call_soon_threadsafe(self._stop_event.set)
        self._thread.join(timeout=10.0)

    def _thread_main(self) -> None:
        try:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(self._run())
        except BaseException as exc:
            self._error = exc
            self._ready.set()

    async def _run(self) -> None:
        loop = asyncio.get_running_loop()
        self._stop_event = asyncio.Event()
        udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: _UDPBounceProtocol(self.messages),
            local_addr=("127.0.0.1", self.udp_port),
        )
        bridge = ObstacleBridgeClient(
            {
                "overlay_transport": "ws",
                "ws_bind": "127.0.0.1",
                "ws_own_port": self.ws_port,
                "secure_link_mode": "off",
                "admin_web": False,
                "status": False,
            }
        )
        try:
            await bridge.start()
            self._ready.set()
            await self._stop_event.wait()
        finally:
            await bridge.stop()
            udp_transport.close()


class HostWsSecureLinkPeer:
    def __init__(self) -> None:
        self.ws_port = _unused_port(socket.SOCK_STREAM)
        self.admin_port = _unused_port(socket.SOCK_STREAM)
        self.log_path = Path(tempfile.mkstemp(prefix="obstaclebridge-host-securelink-", suffix=".log")[1])
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._thread_main, daemon=True)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop_event: asyncio.Event | None = None
        self._error: BaseException | None = None

    def __enter__(self) -> "HostWsSecureLinkPeer":
        self._thread.start()
        if not self._ready.wait(timeout=10.0):
            raise RuntimeError("host WS secure-link peer did not start")
        if self._error is not None:
            raise RuntimeError("host WS secure-link peer failed to start") from self._error
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._loop is not None and self._stop_event is not None:
            self._loop.call_soon_threadsafe(self._stop_event.set)
        self._thread.join(timeout=10.0)
        with contextlib.suppress(FileNotFoundError):
            self.log_path.unlink()

    def _thread_main(self) -> None:
        try:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(self._run())
        except BaseException as exc:
            self._error = exc
            self._ready.set()

    async def _run(self) -> None:
        self._stop_event = asyncio.Event()
        bridge = ObstacleBridgeClient(
            {
                "overlay_transport": "ws",
                "ws_bind": "127.0.0.1",
                "ws_own_port": self.ws_port,
                "secure_link": True,
                "secure_link_mode": "psk",
                "secure_link_psk": IOS_SECURE_LINK_PSK,
                "admin_web": True,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": self.admin_port,
                "admin_web_auth_disable": True,
                "status": False,
                "log": "DEBUG",
                "console_level": "DEBUG",
                "file_level": "DEBUG",
                "log_file": str(self.log_path),
                "log_secure_link": "DEBUG",
                "log_ws_session": "DEBUG",
                "log_runner": "DEBUG",
                "log_admin_web": "DEBUG",
            }
        )
        try:
            await bridge.start()
            self._ready.set()
            await self._stop_event.wait()
        finally:
            await bridge.stop()


def _read_text_if_exists(path: str | Path | None) -> str:
    if not path:
        return ""
    target = Path(path)
    if not target.exists():
        return ""
    return target.read_text(encoding="utf-8", errors="replace")


def _extract_json_object(output: str, *, probe: str) -> dict[str, Any]:
    decoder = json.JSONDecoder()
    for index, char in enumerate(output):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(output[index:])
        except json.JSONDecodeError:
            continue
        if (
            isinstance(value, dict)
            and value.get("app") == IOS_E2E_APP_NAME
            and value.get("probe") == probe
        ):
            return value
    raise AssertionError(f"no {probe} JSON report found in output:\n{output}")


def _read_e2e_app_probe_report(*, probe: str) -> dict[str, Any]:
    completed = subprocess.run(
        ["xcrun", "simctl", "get_app_container", "booted", IOS_E2E_BUNDLE_ID, "data"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30.0,
    )
    if completed.returncode != 0:
        raise AssertionError(f"could not locate simulator app data container:\n{completed.stderr}")
    data_container = Path(completed.stdout.strip())
    if probe == "ws-udp-echo":
        report_name = "ws-udp-echo-latest.json"
    elif probe == "ws-secure-link":
        report_name = "ws-secure-link-latest.json"
    else:
        report_name = "host-websocket-latest.json"
    candidates = [
        data_container / ".obstaclebridge-ios-e2e" / report_name,
        data_container / "Documents" / ".obstaclebridge-ios-e2e" / report_name,
    ]
    for path in candidates:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    raise AssertionError(f"no simulator probe report found under {data_container}")


def _read_e2e_app_runtime_log(*, report: dict[str, Any]) -> str:
    log_file = report.get("runtime_log_file")
    if not log_file:
        return ""
    return _read_text_if_exists(Path(str(log_file)))


def _briefcase_command(app_args: list[str]) -> list[str]:
    briefcase = (
        os.environ.get("BRIEFCASE")
        or shutil.which("briefcase")
        or str(ROOT / ".venv" / "bin" / "briefcase")
    )
    if not Path(briefcase).exists() and shutil.which(briefcase) is None:
        briefcase = None
    if briefcase is None:
        pytest.skip("briefcase executable is required for iOS simulator integration tests")
    device = os.environ.get("OBSTACLEBRIDGE_IOS_SIMULATOR_DEVICE", "iPhone 17 Pro")
    return [
        briefcase,
        "run",
        "iOS",
        "-a",
        IOS_E2E_APP_NAME,
        "-u",
        "-r",
        "--no-input",
        "-d",
        device,
        "--",
        *app_args,
    ]


def _fetch_json(url: str, *, timeout: float = 2.0) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _wait_for_host_secure_link_authenticated(
    *,
    admin_port: int,
    transport: str,
    timeout_sec: float = 20.0,
) -> dict[str, Any]:
    deadline = time.time() + float(timeout_sec)
    last_doc: dict[str, Any] | None = None
    transport_norm = str(transport or "").strip().lower()
    while time.time() < deadline:
        try:
            doc = _fetch_json(f"http://127.0.0.1:{admin_port}/api/peers", timeout=1.5)
        except Exception:
            time.sleep(0.25)
            continue
        last_doc = doc
        for row in list(doc.get("peers") or []):
            if transport_norm and str(row.get("transport") or "").strip().lower() != transport_norm:
                continue
            if str(row.get("state") or "").strip().lower() == "listening":
                continue
            secure_link = row.get("secure_link") or {}
            if bool(secure_link.get("authenticated")) and str(secure_link.get("state") or "").strip().lower() == "authenticated":
                return doc
        time.sleep(0.25)
    raise AssertionError(
        f"host /api/peers did not expose authenticated secure_link state on port {admin_port}; last={last_doc!r}"
    )


def _poll_host_secure_link_authenticated(
    *,
    admin_port: int,
    transport: str,
) -> dict[str, Any] | None:
    try:
        doc = _fetch_json(f"http://127.0.0.1:{admin_port}/api/peers", timeout=1.5)
    except Exception:
        return None
    transport_norm = str(transport or "").strip().lower()
    for row in list(doc.get("peers") or []):
        if transport_norm and str(row.get("transport") or "").strip().lower() != transport_norm:
            continue
        if str(row.get("state") or "").strip().lower() == "listening":
            continue
        secure_link = row.get("secure_link") or {}
        if bool(secure_link.get("authenticated")) and str(secure_link.get("state") or "").strip().lower() == "authenticated":
            return doc
    return None


@pytest.mark.integration
@pytest.mark.ios
@pytest.mark.ios_simulator
@pytest.mark.slow
def test_ios_simulator_app_connects_to_macos_host_websocket_echo() -> None:
    if shutil.which("xcrun") is None:
        pytest.skip("xcrun is required for iOS simulator integration tests")

    with HostWebSocketEcho() as host:
        probe_url = f"ws://127.0.0.1:{host.port}/obstaclebridge-ios-e2e"
        try:
            completed = subprocess.run(
                _briefcase_command(["--host-websocket-probe", probe_url]),
                cwd=IOS_DIR,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=float(os.environ.get("OBSTACLEBRIDGE_IOS_SIMULATOR_TIMEOUT", "600")),
            )
        except subprocess.TimeoutExpired as exc:
            output = exc.output.decode("utf-8", errors="replace") if isinstance(exc.output, bytes) else str(exc.output or "")
            pytest.fail(f"iOS simulator Briefcase run timed out after {exc.timeout}s:\n{output}")

    try:
        report = _extract_json_object(completed.stdout, probe="host-websocket")
    except AssertionError:
        report = _read_e2e_app_probe_report(probe="host-websocket")
    if completed.returncode != 0 and not bool(report.get("ok")):
        raise AssertionError(completed.stdout)
    assert report["ok"] is True
    assert report["url"] == probe_url
    assert report["app"] == IOS_E2E_APP_NAME
    assert report["received"]["message"] == "obstaclebridge-ios-e2e-probe"
    assert host.messages == [report["sent"]]


@pytest.mark.integration
@pytest.mark.ios
@pytest.mark.ios_simulator
@pytest.mark.slow
def test_ios_simulator_e2e_app_ws_overlay_udp_service_reaches_macos_peer_udp_echo() -> None:
    if shutil.which("xcrun") is None:
        pytest.skip("xcrun is required for iOS simulator integration tests")

    local_udp_port = int(os.environ.get("OBSTACLEBRIDGE_IOS_E2E_LOCAL_UDP_PORT", "18081"))
    with HostWsUdpBridgePeer() as host:
        ws_url = f"ws://127.0.0.1:{host.ws_port}/obstaclebridge-ios-e2e"
        try:
            completed = subprocess.run(
                _briefcase_command(
                    [
                        "--ws-udp-echo-probe",
                        ws_url,
                        "--local-udp-port",
                        str(local_udp_port),
                        "--target-udp-host",
                        "127.0.0.1",
                        "--target-udp-port",
                        str(host.udp_port),
                        "--payload-hex",
                        IOS_WS_UDP_REQUEST.hex(),
                        "--expected-hex",
                        IOS_WS_UDP_RESPONSE.hex(),
                    ]
                ),
                cwd=IOS_DIR,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=float(os.environ.get("OBSTACLEBRIDGE_IOS_SIMULATOR_TIMEOUT", "600")),
            )
        except subprocess.TimeoutExpired as exc:
            output = exc.output.decode("utf-8", errors="replace") if isinstance(exc.output, bytes) else str(exc.output or "")
            pytest.fail(f"iOS simulator Briefcase run timed out after {exc.timeout}s:\n{output}")

    try:
        report = _extract_json_object(completed.stdout, probe="ws-udp-echo")
    except AssertionError:
        report = _read_e2e_app_probe_report(probe="ws-udp-echo")
    if completed.returncode != 0 and not bool(report.get("ok")):
        raise AssertionError(completed.stdout)
    assert report["ok"] is True
    assert report["ws_url"] == ws_url
    assert report["local_udp"] == {"host": "127.0.0.1", "port": local_udp_port}
    assert report["target_udp"] == {"host": "127.0.0.1", "port": host.udp_port}
    assert report["payload_hex"] == IOS_WS_UDP_REQUEST.hex()
    assert report["response_hex"] == IOS_WS_UDP_RESPONSE.hex()
    assert host.messages == [IOS_WS_UDP_REQUEST]


@pytest.mark.integration
@pytest.mark.ios
@pytest.mark.ios_simulator
@pytest.mark.slow
def test_ios_simulator_e2e_app_ws_secure_link_client_authenticates_and_is_visible_via_host_webadmin_api() -> None:
    if shutil.which("xcrun") is None:
        pytest.skip("xcrun is required for iOS simulator integration tests")

    with HostWsSecureLinkPeer() as host:
        ws_url = f"ws://127.0.0.1:{host.ws_port}/obstaclebridge-ios-e2e"
        cmd = _briefcase_command(
            [
                "--ws-secure-link-probe",
                ws_url,
                "--secure-link-psk",
                IOS_SECURE_LINK_PSK,
                "--hold-after-success-sec",
                "4",
                "--timeout-sec",
                "20",
            ]
        )
        proc = subprocess.Popen(
            cmd,
            cwd=IOS_DIR,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        output = ""
        peers_doc: dict[str, Any] | None = None
        simulator_timeout = float(os.environ.get("OBSTACLEBRIDGE_IOS_SIMULATOR_TIMEOUT", "600"))
        deadline = time.time() + simulator_timeout
        try:
            while time.time() < deadline:
                peers_doc = _poll_host_secure_link_authenticated(
                    admin_port=host.admin_port,
                    transport="ws",
                )
                if peers_doc is not None:
                    output, _ = proc.communicate(timeout=max(1.0, deadline - time.time()))
                    break
                if proc.poll() is not None:
                    output, _ = proc.communicate(timeout=30.0)
                    break
                time.sleep(0.5)
            else:
                proc.terminate()
                output, _ = proc.communicate(timeout=30.0)
                pytest.fail(f"iOS simulator Briefcase run timed out before secure-link authentication:\n{output}")
        except subprocess.TimeoutExpired:
            proc.kill()
            output, _ = proc.communicate(timeout=30.0)
            pytest.fail(f"iOS simulator Briefcase run timed out:\n{output}")
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.communicate(timeout=30.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate(timeout=30.0)
        host_log = _read_text_if_exists(host.log_path)

    try:
        report = _extract_json_object(output, probe="ws-secure-link")
    except AssertionError:
        report = _read_e2e_app_probe_report(probe="ws-secure-link")
    ios_log = _read_e2e_app_runtime_log(report=report)
    if proc.returncode != 0 and not bool(report.get("ok")):
        raise AssertionError(
            "iOS simulator secure-link probe failed\n"
            f"briefcase_output:\n{output}\n\n"
            f"ios_report:\n{json.dumps(report, indent=2, sort_keys=True)}\n\n"
            f"ios_runtime_log:\n{ios_log}\n\n"
            f"host_runtime_log:\n{host_log}"
        )
    if peers_doc is None:
        raise AssertionError(
            "host WebAdmin never exposed an authenticated secure-link peer\n"
            f"briefcase_output:\n{output}\n\n"
            f"ios_report:\n{json.dumps(report, indent=2, sort_keys=True)}\n\n"
            f"ios_runtime_log:\n{ios_log}\n\n"
            f"host_runtime_log:\n{host_log}"
        )
    assert report["ok"] is True
    assert report["probe"] == "ws-secure-link"
    assert report["ws_url"] == ws_url
    assert report["secure_link_mode"] == "psk"
    assert report["secure_link_authenticated"] is True

    matching_rows = [
        row
        for row in list(peers_doc.get("peers") or [])
        if str(row.get("transport") or "").strip().lower() == "ws"
        and str(row.get("state") or "").strip().lower() != "listening"
    ]
    assert matching_rows, peers_doc
    secure_link = matching_rows[0].get("secure_link") or {}
    assert bool(secure_link.get("authenticated")) is True
    assert str(secure_link.get("state") or "").strip().lower() == "authenticated"
