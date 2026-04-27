"""Headless probes executed by the standalone iOS E2E application."""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import time
import urllib.request
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from obstacle_bridge.core import ObstacleBridgeClient
from obstacle_bridge.crypto_extract import available_crypto_extract


REPORT_DIRNAME = ".obstaclebridge-ios-e2e"
HOST_WEBSOCKET_REPORT_NAME = "host-websocket-latest.json"
WS_UDP_ECHO_REPORT_NAME = "ws-udp-echo-latest.json"
WS_SECURE_LINK_REPORT_NAME = "ws-secure-link-latest.json"
RUNTIME_CONFIG_REPORT_NAME = "runtime-config-latest.json"
CONFIG_PERSISTENCE_REPORT_NAME = "config-persistence-latest.json"


def _report_root(root: Path | None = None) -> Path:
    base = root or Path.home() / REPORT_DIRNAME
    base.mkdir(parents=True, exist_ok=True)
    return base


def _probe_logging_config(*, root: Path | None, name: str) -> dict[str, Any]:
    log_path = _report_root(root) / f"{name}.log"
    return {
        "log": "DEBUG",
        "console_level": "DEBUG",
        "file_level": "DEBUG",
        "log_file": str(log_path),
        "debug_stderr": True,
        "log_secure_link": "DEBUG",
        "log_ws_session": "DEBUG",
        "log_runner": "DEBUG",
        "log_admin_web": "DEBUG",
    }


def _webadmin_url_from_config(config: Mapping[str, Any]) -> str | None:
    if not isinstance(config, Mapping) or not bool(config.get("admin_web")):
        return None
    bind = str(config.get("admin_web_bind") or "127.0.0.1").strip() or "127.0.0.1"
    port = int(config.get("admin_web_port") or 18080)
    path = str(config.get("admin_web_path") or "/").strip() or "/"
    if not path.startswith("/"):
        path = "/" + path
    host = "127.0.0.1" if bind in {"0.0.0.0", "::", "*", "localhost"} else bind
    return f"http://{host}:{port}{path}"


def _unused_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _fetch_admin_json(
    url: str,
    *,
    method: str = "GET",
    payload: Mapping[str, Any] | None = None,
    timeout: float = 3.0,
) -> dict[str, Any]:
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


async def _wait_for_admin_config(base_url: str, *, timeout_sec: float) -> dict[str, Any]:
    deadline = time.perf_counter() + float(timeout_sec)
    last_detail = ""
    while time.perf_counter() < deadline:
        try:
            return await asyncio.to_thread(_fetch_admin_json, f"{base_url}/api/config")
        except Exception as exc:
            last_detail = f"{type(exc).__name__}: {exc}"
            await asyncio.sleep(0.1)
    raise TimeoutError(f"WebAdmin /api/config did not become ready: {last_detail}")


async def run_host_websocket_probe(url: str, timeout_sec: float = 5.0) -> dict[str, Any]:
    """Connect from the iOS E2E app process to a host WebSocket echo endpoint."""

    started = time.perf_counter()
    try:
        import websockets
    except Exception as exc:
        return {
            "ok": False,
            "app": "obstacle_bridge_ios_e2e",
            "probe": "host-websocket",
            "url": url,
            "detail": f"websockets import failed: {type(exc).__name__}: {exc}",
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }

    payload = {
        "app": "obstacle_bridge_ios_e2e",
        "probe": "host-websocket",
        "message": "obstaclebridge-ios-e2e-probe",
    }
    try:
        async with websockets.connect(url, open_timeout=timeout_sec, close_timeout=timeout_sec) as ws:
            await asyncio.wait_for(ws.send(json.dumps(payload, sort_keys=True)), timeout=timeout_sec)
            reply_text = await asyncio.wait_for(ws.recv(), timeout=timeout_sec)
        reply = json.loads(reply_text)
        ok = reply.get("message") == payload["message"] and reply.get("probe") == payload["probe"]
        return {
            "ok": bool(ok),
            "app": "obstacle_bridge_ios_e2e",
            "probe": "host-websocket",
            "url": url,
            "sent": payload,
            "received": reply,
            "detail": "host WebSocket echo succeeded" if ok else "host WebSocket echo payload mismatch",
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }
    except Exception as exc:
        return {
            "ok": False,
            "app": "obstacle_bridge_ios_e2e",
            "probe": "host-websocket",
            "url": url,
            "detail": f"host WebSocket probe failed: {type(exc).__name__}: {exc}",
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }


def run_host_websocket_probe_sync(url: str, timeout_sec: float = 5.0) -> dict[str, Any]:
    return asyncio.run(run_host_websocket_probe(url, timeout_sec=timeout_sec))


class _UDPProbeProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.response: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    def datagram_received(self, data: bytes, addr: Any) -> None:
        if not self.response.done():
            self.response.set_result(bytes(data))

    def error_received(self, exc: Exception) -> None:
        if not self.response.done():
            self.response.set_exception(exc)


async def _send_udp_and_wait(
    host: str,
    port: int,
    payload: bytes,
    *,
    timeout_sec: float,
) -> bytes:
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        _UDPProbeProtocol,
        remote_addr=(str(host), int(port)),
    )
    try:
        transport.sendto(payload)
        return await asyncio.wait_for(protocol.response, timeout=timeout_sec)
    finally:
        transport.close()


def _ws_peer_from_url(ws_url: str) -> tuple[str, int]:
    parsed = urlparse(ws_url)
    if parsed.scheme not in {"ws", "wss"}:
        raise ValueError(f"ws_url must use ws:// or wss://: {ws_url}")
    if not parsed.hostname:
        raise ValueError(f"ws_url must include a host: {ws_url}")
    if parsed.port is None:
        return parsed.hostname, 443 if parsed.scheme == "wss" else 80
    return parsed.hostname, int(parsed.port)


def _ios_ws_udp_bridge_config(
    *,
    ws_url: str,
    local_udp_port: int,
    target_udp_host: str,
    target_udp_port: int,
    report_root: Path | None = None,
) -> dict[str, Any]:
    peer_host, peer_port = _ws_peer_from_url(ws_url)
    return {
        "overlay_transport": "ws",
        "ws_peer": peer_host,
        "ws_peer_port": int(peer_port),
        "ws_bind": "127.0.0.1",
        "ws_own_port": 0,
        "secure_link_mode": "off",
        "admin_web": False,
        "status": False,
        "own_servers": [
            {
                "name": "ios-e2e-local-udp",
                "listen": {"protocol": "udp", "bind": "127.0.0.1", "port": int(local_udp_port)},
                "target": {
                    "protocol": "udp",
                    "host": str(target_udp_host),
                    "port": int(target_udp_port),
                },
            }
        ],
        **_probe_logging_config(root=report_root, name="ws-udp-echo-runtime"),
    }


def _ios_ws_secure_link_config(
    *,
    ws_url: str,
    secure_link_psk: str,
    report_root: Path | None = None,
) -> dict[str, Any]:
    peer_host, peer_port = _ws_peer_from_url(ws_url)
    return {
        "overlay_transport": "ws",
        "ws_peer": peer_host,
        "ws_peer_port": int(peer_port),
        "ws_bind": "127.0.0.1",
        "ws_own_port": 0,
        "secure_link": True,
        "secure_link_mode": "psk",
        "secure_link_psk": str(secure_link_psk),
        "admin_web": False,
        "status": False,
        **_probe_logging_config(root=report_root, name="ws-secure-link-runtime"),
    }


def _extract_secure_link_peer_doc(client: ObstacleBridgeClient) -> dict[str, Any] | None:
    runner = getattr(client, "runner", None)
    getter = getattr(runner, "get_peer_connections_snapshot", None) if runner is not None else None
    if not callable(getter):
        return None
    try:
        doc = dict(getter() or {})
    except Exception:
        return None
    peers = list(doc.get("peers") or [])
    for row in peers:
        if str(row.get("state") or "").strip().lower() == "listening":
            continue
        secure_link = row.get("secure_link") or {}
        if bool(secure_link.get("authenticated")):
            return {
                "peer": dict(row),
                "count": int(doc.get("count") or len(peers)),
            }
    return None


async def run_ws_udp_echo_probe(
    *,
    ws_url: str,
    local_udp_port: int,
    target_udp_host: str,
    target_udp_port: int,
    payload: bytes,
    expected: bytes | None = None,
    timeout_sec: float = 12.0,
) -> dict[str, Any]:
    """Run an iOS-side UDP service over a WS ObstacleBridge peer and validate the reply."""

    started = time.perf_counter()
    report_root = _report_root()
    expected_payload = payload if expected is None else expected
    config = _ios_ws_udp_bridge_config(
        ws_url=ws_url,
        local_udp_port=local_udp_port,
        target_udp_host=target_udp_host,
        target_udp_port=target_udp_port,
        report_root=report_root,
    )
    client = ObstacleBridgeClient(config, apply_logging=True)
    last_detail = ""
    try:
        await client.start()
        deadline = time.perf_counter() + float(timeout_sec)
        while time.perf_counter() < deadline:
            try:
                response = await _send_udp_and_wait(
                    "127.0.0.1",
                    int(local_udp_port),
                    payload,
                    timeout_sec=min(2.0, max(0.5, deadline - time.perf_counter())),
                )
                ok = response == expected_payload
                return {
                    "ok": bool(ok),
                    "app": "obstacle_bridge_ios_e2e",
                    "probe": "ws-udp-echo",
                    "ws_url": ws_url,
                    "local_udp": {"host": "127.0.0.1", "port": int(local_udp_port)},
                    "target_udp": {"host": str(target_udp_host), "port": int(target_udp_port)},
                    "payload_hex": payload.hex(),
                    "expected_hex": expected_payload.hex(),
                    "response_hex": response.hex(),
                    "detail": "UDP response matched" if ok else "UDP response did not match expected payload",
                    "latency_ms": int((time.perf_counter() - started) * 1000),
                }
            except Exception as exc:
                last_detail = f"{type(exc).__name__}: {exc}"
                await asyncio.sleep(0.25)
        return {
            "ok": False,
            "app": "obstacle_bridge_ios_e2e",
            "probe": "ws-udp-echo",
            "ws_url": ws_url,
            "local_udp": {"host": "127.0.0.1", "port": int(local_udp_port)},
            "target_udp": {"host": str(target_udp_host), "port": int(target_udp_port)},
            "payload_hex": payload.hex(),
            "expected_hex": expected_payload.hex(),
            "response_hex": "",
            "detail": f"UDP probe timed out: {last_detail}",
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }
    except Exception as exc:
        return {
            "ok": False,
            "app": "obstacle_bridge_ios_e2e",
            "probe": "ws-udp-echo",
            "ws_url": ws_url,
            "local_udp": {"host": "127.0.0.1", "port": int(local_udp_port)},
            "target_udp": {"host": str(target_udp_host), "port": int(target_udp_port)},
            "payload_hex": payload.hex(),
            "expected_hex": expected_payload.hex(),
            "response_hex": "",
            "detail": f"bridge startup/probe failed: {type(exc).__name__}: {exc}",
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }
    finally:
        await client.stop()


def run_ws_udp_echo_probe_sync(**kwargs: Any) -> dict[str, Any]:
    return asyncio.run(run_ws_udp_echo_probe(**kwargs))


async def run_ws_secure_link_probe(
    *,
    ws_url: str,
    secure_link_psk: str,
    timeout_sec: float = 12.0,
    hold_after_success_sec: float = 3.0,
) -> dict[str, Any]:
    """Connect from the iOS E2E app process to a WS peer using SecureLink PSK."""

    started = time.perf_counter()
    report_root = _report_root()
    config = _ios_ws_secure_link_config(ws_url=ws_url, secure_link_psk=secure_link_psk, report_root=report_root)
    client = ObstacleBridgeClient(config, apply_logging=True)
    last_doc: dict[str, Any] | None = None
    crypto_status = available_crypto_extract()
    log_file = str(report_root / "ws-secure-link-runtime.log")
    try:
        await client.start()
        deadline = time.perf_counter() + float(timeout_sec)
        while time.perf_counter() < deadline:
            match = _extract_secure_link_peer_doc(client)
            if match is not None:
                peer_row = dict(match.get("peer") or {})
                secure_link = dict(peer_row.get("secure_link") or {})
                if hold_after_success_sec > 0:
                    await asyncio.sleep(float(hold_after_success_sec))
                return {
                    "ok": True,
                    "app": "obstacle_bridge_ios_e2e",
                    "probe": "ws-secure-link",
                    "ws_url": ws_url,
                    "crypto_extract": crypto_status,
                    "runtime_log_file": log_file,
                    "secure_link_mode": "psk",
                    "peer_count": int(match.get("count") or 0),
                    "peer_transport": str(peer_row.get("transport") or ""),
                    "peer_state": str(peer_row.get("state") or ""),
                    "secure_link_state": str(secure_link.get("state") or ""),
                    "secure_link_authenticated": bool(secure_link.get("authenticated")),
                    "detail": "SecureLink authenticated over WebSocket",
                    "latency_ms": int((time.perf_counter() - started) * 1000),
                }
            runner = getattr(client, "runner", None)
            getter = getattr(runner, "get_peer_connections_snapshot", None) if runner is not None else None
            if callable(getter):
                with contextlib.suppress(Exception):
                    last_doc = dict(getter() or {})
            await asyncio.sleep(0.25)
        return {
            "ok": False,
            "app": "obstacle_bridge_ios_e2e",
            "probe": "ws-secure-link",
            "ws_url": ws_url,
            "crypto_extract": crypto_status,
            "runtime_log_file": log_file,
            "secure_link_mode": "psk",
            "detail": "SecureLink did not authenticate before timeout",
            "last_peer_doc": last_doc,
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }
    except Exception as exc:
        return {
            "ok": False,
            "app": "obstacle_bridge_ios_e2e",
            "probe": "ws-secure-link",
            "ws_url": ws_url,
            "crypto_extract": crypto_status,
            "runtime_log_file": log_file,
            "secure_link_mode": "psk",
            "detail": f"SecureLink probe failed: {type(exc).__name__}: {exc}",
            "last_peer_doc": last_doc,
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }
    finally:
        await client.stop()


def run_ws_secure_link_probe_sync(**kwargs: Any) -> dict[str, Any]:
    return asyncio.run(run_ws_secure_link_probe(**kwargs))


async def run_runtime_config(
    *,
    config: Mapping[str, Any],
    hold_sec: float = 600.0,
) -> dict[str, Any]:
    """Start an ObstacleBridge runtime from config and keep it alive for inspection."""

    started = time.perf_counter()
    report_root = _report_root()
    runtime_config = dict(config)
    if not any(key in runtime_config for key in ("log", "console_level", "log_file")):
        runtime_config.update(_probe_logging_config(root=report_root, name="runtime-config"))
    client = ObstacleBridgeClient(runtime_config, apply_logging=True)
    runtime_log_file = str(runtime_config.get("log_file") or "")
    try:
        await client.start()
        snapshot = dict(client.snapshot() or {})
        await asyncio.sleep(max(0.0, float(hold_sec)))
        final_snapshot = dict(client.snapshot() or {})
        return {
            "ok": True,
            "app": "obstacle_bridge_ios_e2e",
            "probe": "runtime-config",
            "hold_sec": float(hold_sec),
            "crypto_extract": available_crypto_extract(),
            "runtime_log_file": runtime_log_file,
            "started": bool(final_snapshot.get("started")),
            "webadmin_url": _webadmin_url_from_config(runtime_config),
            "config": runtime_config,
            "initial_snapshot": snapshot,
            "final_snapshot": final_snapshot,
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }
    except Exception as exc:
        return {
            "ok": False,
            "app": "obstacle_bridge_ios_e2e",
            "probe": "runtime-config",
            "hold_sec": float(hold_sec),
            "crypto_extract": available_crypto_extract(),
            "runtime_log_file": runtime_log_file,
            "webadmin_url": _webadmin_url_from_config(runtime_config),
            "config": runtime_config,
            "detail": f"runtime-config failed: {type(exc).__name__}: {exc}",
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }
    finally:
        await client.stop()


def run_runtime_config_sync(**kwargs: Any) -> dict[str, Any]:
    return asyncio.run(run_runtime_config(**kwargs))


async def run_config_persistence_probe(*, timeout_sec: float = 12.0) -> dict[str, Any]:
    """Persist a WebAdmin config change, restart, and confirm reload from disk."""

    started = time.perf_counter()
    report_root = _report_root()
    config_path = report_root / "ObstacleBridge.cfg"
    admin_port = _unused_tcp_port()
    base_url = f"http://127.0.0.1:{admin_port}"
    updated_name = f"ios-e2e-config-{int(started * 1000)}"
    initial_config = {
        "overlay_transport": "ws",
        "ws_bind": "127.0.0.1",
        "ws_own_port": 0,
        "secure_link_mode": "off",
        "admin_web": True,
        "admin_web_bind": "127.0.0.1",
        "admin_web_port": admin_port,
        "admin_web_auth_disable": True,
        "admin_web_name": "ios-e2e-initial",
        "status": False,
        **_probe_logging_config(root=report_root, name="config-persistence-runtime"),
    }
    runtime_log_file = str(initial_config.get("log_file") or "")
    client = ObstacleBridgeClient(initial_config, config_path=str(config_path), apply_logging=True)
    restart_response: dict[str, Any] | None = None
    saved_response: dict[str, Any] | None = None
    initial_response: dict[str, Any] | None = None
    reloaded_response: dict[str, Any] | None = None
    try:
        await client.start()
        initial_response = await _wait_for_admin_config(base_url, timeout_sec=timeout_sec)
        saved_response = await asyncio.to_thread(
            _fetch_admin_json,
            f"{base_url}/api/config",
            method="POST",
            payload={"updates": {"admin_web_name": updated_name}, "restart_after_save": False},
        )
        restart_response = await asyncio.to_thread(
            _fetch_admin_json,
            f"{base_url}/api/restart",
            method="POST",
            payload={},
        )
        restart_flag_seen = bool(getattr(getattr(client, "runner", None), "_restart_requested_flag", False))
        await client.stop()

        reloaded_client = ObstacleBridgeClient(config_path=str(config_path), apply_logging=True)
        try:
            await reloaded_client.start()
            reloaded_response = await _wait_for_admin_config(base_url, timeout_sec=timeout_sec)
        finally:
            await reloaded_client.stop()

        reloaded_config = dict((reloaded_response or {}).get("config") or {})
        ok = (
            bool(saved_response and saved_response.get("ok"))
            and bool(restart_response and restart_response.get("ok"))
            and restart_flag_seen
            and reloaded_config.get("admin_web_name") == updated_name
            and reloaded_config.get("admin_web_port") == admin_port
        )
        return {
            "ok": bool(ok),
            "app": "obstacle_bridge_ios_e2e",
            "probe": "config-persistence",
            "config_path": str(config_path),
            "runtime_log_file": runtime_log_file,
            "webadmin_url": base_url,
            "updated": {"admin_web_name": updated_name},
            "restart_requested_flag": restart_flag_seen,
            "initial_config": dict((initial_response or {}).get("config") or {}),
            "save_response": saved_response,
            "restart_response": restart_response,
            "reloaded_config": reloaded_config,
            "detail": "configuration persisted and reloaded after API restart"
            if ok
            else "configuration persistence/reload check failed",
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }
    except Exception as exc:
        return {
            "ok": False,
            "app": "obstacle_bridge_ios_e2e",
            "probe": "config-persistence",
            "config_path": str(config_path),
            "runtime_log_file": runtime_log_file,
            "webadmin_url": base_url,
            "detail": f"config-persistence failed: {type(exc).__name__}: {exc}",
            "initial_config": dict((initial_response or {}).get("config") or {}) if initial_response else None,
            "save_response": saved_response,
            "restart_response": restart_response,
            "reloaded_config": dict((reloaded_response or {}).get("config") or {}) if reloaded_response else None,
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }
    finally:
        await client.stop()


def run_config_persistence_probe_sync(**kwargs: Any) -> dict[str, Any]:
    return asyncio.run(run_config_persistence_probe(**kwargs))


def write_report(report: dict[str, Any], root: Path | None = None) -> Path:
    base = _report_root(root)
    if report.get("probe") == "ws-udp-echo":
        report_name = WS_UDP_ECHO_REPORT_NAME
    elif report.get("probe") == "ws-secure-link":
        report_name = WS_SECURE_LINK_REPORT_NAME
    elif report.get("probe") == "runtime-config":
        report_name = RUNTIME_CONFIG_REPORT_NAME
    elif report.get("probe") == "config-persistence":
        report_name = CONFIG_PERSISTENCE_REPORT_NAME
    else:
        report_name = HOST_WEBSOCKET_REPORT_NAME
    target = base / report_name
    target.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return target
