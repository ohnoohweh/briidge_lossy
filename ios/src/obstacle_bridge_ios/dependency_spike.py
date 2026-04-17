"""M2 dependency and asyncio smoke checks for iOS packaging spikes."""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any, Awaitable, Callable


def _make_result(name: str, ok: bool, detail: str, duration_ms: int) -> dict[str, Any]:
    return {
        "name": name,
        "ok": bool(ok),
        "detail": str(detail),
        "duration_ms": int(duration_ms),
    }


async def _timed(name: str, fn: Callable[[], Awaitable[str]]) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        detail = await fn()
        ok = True
    except Exception as exc:  # pragma: no cover - defensive; exercised in failure paths.
        ok = False
        detail = f"{type(exc).__name__}: {exc}"
    duration_ms = int((time.perf_counter() - started) * 1000)
    return _make_result(name, ok, detail, duration_ms)


async def _check_websockets_loopback() -> str:
    import websockets

    received: list[str] = []

    async def echo_handler(ws) -> None:
        async for message in ws:
            received.append(str(message))
            await ws.send(message)

    server = await websockets.serve(echo_handler, "127.0.0.1", 0)
    try:
        port = int(server.sockets[0].getsockname()[1])
        uri = f"ws://127.0.0.1:{port}"
        async with websockets.connect(uri) as client:
            await client.send("m2-websockets-ping")
            echoed = await asyncio.wait_for(client.recv(), timeout=2.0)
        if echoed != "m2-websockets-ping":
            raise RuntimeError(f"unexpected websocket echo payload: {echoed!r}")
        if received != ["m2-websockets-ping"]:
            raise RuntimeError(f"unexpected websocket server payloads: {received!r}")
        version = getattr(websockets, "__version__", "unknown")
        return f"import+loopback echo passed (websockets {version})"
    finally:
        server.close()
        await server.wait_closed()


async def _check_cryptography_roundtrip() -> str:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ModuleNotFoundError:
        return "cryptography unavailable in iOS package; fallback selected (defer secure-link crypto to native path for M2)"

    key = AESGCM.generate_key(bit_length=128)
    aead = AESGCM(key)
    nonce = os.urandom(12)
    aad = b"obstaclebridge-m2"
    plaintext = b"cryptography-smoke"
    ciphertext = aead.encrypt(nonce, plaintext, aad)
    recovered = aead.decrypt(nonce, ciphertext, aad)
    if recovered != plaintext:
        raise RuntimeError("cryptography decrypt mismatch")
    return "AESGCM roundtrip passed"


async def _check_aioquic_import() -> str:
    try:
        import aioquic
        from aioquic.quic.configuration import QuicConfiguration
    except ModuleNotFoundError:
        return "aioquic unavailable in iOS package; result documented for M2 transport-risk tracking"

    cfg = QuicConfiguration(is_client=True, alpn_protocols=["obstaclebridge-m2"])
    if not cfg.is_client:
        raise RuntimeError("aioquic config initialization failed")
    version = getattr(aioquic, "__version__", "unknown")
    return f"import+QuicConfiguration passed (aioquic {version})"


async def _check_asyncio_tcp_loopback() -> str:
    request_payload = b"m2-tcp-request"
    response_payload = request_payload[::-1]

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.readexactly(len(request_payload))
        writer.write(data[::-1])
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    try:
        port = int(server.sockets[0].getsockname()[1])
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(request_payload)
        await writer.drain()
        response = await asyncio.wait_for(reader.readexactly(len(response_payload)), timeout=2.0)
        writer.close()
        await writer.wait_closed()
        if response != response_payload:
            raise RuntimeError(f"unexpected tcp response payload: {response!r}")
        return "asyncio TCP loopback passed"
    finally:
        server.close()
        await server.wait_closed()


async def _check_asyncio_udp_loopback() -> str:
    request_payload = b"m2-udp-request"
    expected_response = request_payload[::-1]
    loop = asyncio.get_running_loop()
    received_future: asyncio.Future[bytes] = loop.create_future()

    class EchoServer(asyncio.DatagramProtocol):
        def connection_made(self, transport) -> None:
            self.transport = transport

        def datagram_received(self, data: bytes, addr) -> None:
            self.transport.sendto(data[::-1], addr)

    class Client(asyncio.DatagramProtocol):
        def connection_made(self, transport) -> None:
            self.transport = transport
            self.transport.sendto(request_payload)

        def datagram_received(self, data: bytes, addr) -> None:
            if not received_future.done():
                received_future.set_result(data)
            self.transport.close()

    server_transport, _ = await loop.create_datagram_endpoint(EchoServer, local_addr=("127.0.0.1", 0))
    client_transport = None
    try:
        port = int(server_transport.get_extra_info("sockname")[1])
        client_transport, _ = await loop.create_datagram_endpoint(Client, remote_addr=("127.0.0.1", port))
        response = await asyncio.wait_for(received_future, timeout=2.0)
        if response != expected_response:
            raise RuntimeError(f"unexpected udp response payload: {response!r}")
        return "asyncio UDP loopback passed"
    finally:
        if client_transport is not None:
            client_transport.close()
        server_transport.close()


async def run_m2_dependency_spike() -> dict[str, Any]:
    checks = [
        await _timed("websockets_device_smoke", _check_websockets_loopback),
        await _timed("cryptography_device_or_fallback", _check_cryptography_roundtrip),
        await _timed("aioquic_result_documented", _check_aioquic_import),
        await _timed("asyncio_tcp_loopback", _check_asyncio_tcp_loopback),
        await _timed("asyncio_udp_loopback", _check_asyncio_udp_loopback),
    ]
    ok = all(bool(item.get("ok")) for item in checks)
    return {
        "milestone": "M2",
        "ok": ok,
        "generated_unix_ts": int(time.time()),
        "checks": checks,
        "notes": [
            "Run this inside simulator and physical iOS device containers.",
            "If cryptography fails on device, document fallback strategy before M3.",
        ],
    }


def run_m2_dependency_spike_sync() -> dict[str, Any]:
    return asyncio.run(run_m2_dependency_spike())


def write_m2_dependency_spike_report(report: dict[str, Any], base_dir: Path | None = None) -> Path:
    root = Path(base_dir) if base_dir is not None else (Path.home() / ".obstaclebridge-ios")
    root.mkdir(parents=True, exist_ok=True)
    target = root / "m2-dependency-spike-latest.json"
    target.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return target
