"""Headless probes executed by the standalone iOS E2E application."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from obstacle_bridge.core import ObstacleBridgeClient


REPORT_DIRNAME = ".obstaclebridge-ios-e2e"
HOST_WEBSOCKET_REPORT_NAME = "host-websocket-latest.json"
WS_UDP_ECHO_REPORT_NAME = "ws-udp-echo-latest.json"


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
    }


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
    expected_payload = payload if expected is None else expected
    config = _ios_ws_udp_bridge_config(
        ws_url=ws_url,
        local_udp_port=local_udp_port,
        target_udp_host=target_udp_host,
        target_udp_port=target_udp_port,
    )
    client = ObstacleBridgeClient(config)
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


def write_report(report: dict[str, Any], root: Path | None = None) -> Path:
    base = root or Path.home() / REPORT_DIRNAME
    base.mkdir(parents=True, exist_ok=True)
    report_name = WS_UDP_ECHO_REPORT_NAME if report.get("probe") == "ws-udp-echo" else HOST_WEBSOCKET_REPORT_NAME
    target = base / report_name
    target.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return target
