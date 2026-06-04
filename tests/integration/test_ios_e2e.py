from __future__ import annotations

import asyncio
import base64
import contextlib
import importlib
import json
import os
import socket
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Awaitable, Callable

import pytest

ROOT = Path(__file__).resolve().parents[2]
IOS_SRC = ROOT / "ios" / "src"
E2E_SRC = ROOT / "ios" / "e2e_app" / "src"
if str(IOS_SRC) not in sys.path:
    sys.path.insert(0, str(IOS_SRC))
if str(E2E_SRC) not in sys.path:
    sys.path.insert(0, str(E2E_SRC))

from obstacle_bridge.core import ObstacleBridgeClient
from obstacle_bridge_ios.m25_ui import M25Config, profile_from_m25_config
from obstacle_bridge_ios.m3_tunnel import (
    M3NetworkSettings,
    M3TunnelConfig,
    m3_vpn_profile_from_profile,
    provider_configuration_from_m3_config,
)
from tests.fixtures.localhost_tls import materialize_localhost_tls_fixture_set


IOS_REQUEST_PACKET = bytes.fromhex("4500002400004000401100000a4d00020a4d00010035003500100000") + b"ios?"
IOS_RESPONSE_PACKET = bytes.fromhex("4500002500004000401100000a4d00010a4d00020035003500110000") + b"ios!"
IOS_WS_UDP_REQUEST = b"\x01ios-ws-udp"
IOS_WS_UDP_RESPONSE = b"\x02ios-ws-udp"


async def _read_exact(reader: asyncio.StreamReader, count: int) -> bytes:
    return await asyncio.wait_for(reader.readexactly(count), timeout=2.0)


async def _read_packet_frame(reader: asyncio.StreamReader) -> bytes:
    header = await _read_exact(reader, 4)
    length = int.from_bytes(header, "big")
    if not 0 < length <= 65535:
        raise AssertionError(f"invalid packet frame length: {length}")
    return await _read_exact(reader, length)


async def _write_packet_frame(writer: asyncio.StreamWriter, packet: bytes) -> None:
    writer.write(len(packet).to_bytes(4, "big") + packet)
    await asyncio.wait_for(writer.drain(), timeout=2.0)


IOS_E2E_TCP_PORT_BASE = 52000
IOS_E2E_UDP_PORT_BASE = 56000
IOS_E2E_PORT_WINDOW = 2000


def _xdist_worker_index() -> int:
    worker_id = str(os.environ.get("PYTEST_XDIST_WORKER", "gw0") or "gw0")
    digits = "".join(ch for ch in worker_id if ch.isdigit())
    return int(digits or 0)


def _xdist_worker_count() -> int:
    raw = str(os.environ.get("PYTEST_XDIST_WORKER_COUNT", "1") or "1")
    try:
        return max(1, int(raw))
    except Exception:
        return 1


def _alloc_local_port(kind: int, *, case_index: int, base: int) -> int:
    worker_index = _xdist_worker_index()
    worker_count = _xdist_worker_count()
    upper_bound = min(65535, int(base) + IOS_E2E_PORT_WINDOW)
    available = upper_bound - int(base)
    if available <= worker_count:
        raise RuntimeError(f"iOS E2E port allocation window too small: base={base} workers={worker_count}")
    per_worker_budget = max(16, available // worker_count)
    start = int(base) + (worker_index * per_worker_budget)
    stop = min(upper_bound, start + per_worker_budget)
    span = max(1, stop - start)
    first = start + (int(case_index) % span)
    candidates = list(range(first, stop)) + list(range(start, first))
    for port in candidates:
        with socket.socket(socket.AF_INET, kind) as sock:
            if kind == socket.SOCK_STREAM:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", int(port)))
            except OSError:
                continue
        return int(port)
    raise RuntimeError(f"failed to allocate local test port kind={kind} case_index={case_index} base={base}")


class _UDPBounceProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.received: list[bytes] = []
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr) -> None:
        self.received.append(bytes(data))
        if self.transport is not None:
            response = bytes([0x02]) + bytes(data)[1:] if data else b""
            self.transport.sendto(response, addr)


class SimulatedIOSPacketFlow:
    """Small Python stand-in for the NEPacketTunnelFlow behavior M3 needs."""

    def __init__(self, incoming_packets: list[bytes]) -> None:
        self._incoming = asyncio.Queue()
        for packet in incoming_packets:
            self._incoming.put_nowait(bytes(packet))
        self.outgoing_packets: list[bytes] = []

    async def read_packets(self) -> list[bytes]:
        return [await asyncio.wait_for(self._incoming.get(), timeout=2.0)]

    async def write_packets(self, packets: list[bytes]) -> None:
        self.outgoing_packets.extend(bytes(packet) for packet in packets)


async def _run_m3_packet_flow_once(provider_configuration: dict, flow: SimulatedIOSPacketFlow) -> None:
    peer = provider_configuration["peer"]
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(str(peer["host"]), int(peer["port"])),
        timeout=2.0,
    )
    try:
        packets = await flow.read_packets()
        for packet in packets:
            await _write_packet_frame(writer, packet)
        response = await _read_packet_frame(reader)
        await flow.write_packets([response])
    finally:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=2.0)


async def _with_packet_frame_peer(
    response_packet: bytes,
    body: Callable[[int, list[bytes]], Awaitable[None]],
) -> list[bytes]:
    received_packets: list[bytes] = []

    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            packet = await _read_packet_frame(reader)
            received_packets.append(packet)
            await _write_packet_frame(writer, response_packet)
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    try:
        socket = server.sockets[0]
        port = int(socket.getsockname()[1])
        await body(port, received_packets)
    finally:
        server.close()
        await server.wait_closed()
    return received_packets


def _m3_provider_configuration(peer_port: int) -> dict:
    profile = profile_from_m25_config(
        M25Config(
            profile_id="ios-m3-e2e",
            display_name="iOS M3 E2E",
            transport="tcp",
            peer_host="127.0.0.1",
            peer_port=peer_port,
            local_tcp_port=18080,
            local_udp_port=18081,
            target_host="127.0.0.1",
            target_tcp_port=8080,
            target_udp_port=8081,
        )
    )
    vpn_profile = m3_vpn_profile_from_profile(
        profile,
        provider_bundle_identifier="com.obstaclebridge.ObstacleBridge.PacketTunnel",
        network=M3NetworkSettings(
            tunnel_address="192.168.105.1",
            tunnel_prefix=30,
            included_routes=["192.168.105.0/30"],
            dns_servers=["1.1.1.1"],
            mtu=1280,
        ),
    )
    return json.loads(json.dumps(vpn_profile["provider_configuration"]))


async def _start_udp_bounce_server(host: str, port: int) -> tuple[asyncio.DatagramTransport, _UDPBounceProtocol]:
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        _UDPBounceProtocol,
        local_addr=(host, int(port)),
    )
    return transport, protocol


async def _probe_udp_roundtrip(host: str, port: int, payload: bytes, *, attempts: int = 40) -> bytes:
    last_error: BaseException | None = None
    loop = asyncio.get_running_loop()
    for _ in range(attempts):
        response_future: asyncio.Future[bytes] = loop.create_future()

        class _ProbeProtocol(asyncio.DatagramProtocol):
            def connection_made(self, transport: asyncio.BaseTransport) -> None:
                cast_transport = transport  # type: ignore[assignment]
                cast_transport.sendto(payload, (host, int(port)))

            def datagram_received(self, data: bytes, _addr) -> None:
                if not response_future.done():
                    response_future.set_result(bytes(data))

            def error_received(self, exc: Exception | None) -> None:
                if not response_future.done():
                    response_future.set_exception(exc or OSError("udp probe error"))

        transport: asyncio.DatagramTransport | None = None
        try:
            transport, _protocol = await loop.create_datagram_endpoint(_ProbeProtocol, local_addr=("127.0.0.1", 0))
            return await asyncio.wait_for(response_future, timeout=1.0)
        except (OSError, asyncio.TimeoutError, ConnectionError) as exc:
            last_error = exc
            await asyncio.sleep(0.1)
        finally:
            if transport is not None:
                transport.close()
        if not response_future.done():
            response_future.cancel()
    raise AssertionError(f"failed to round-trip UDP probe to {host}:{port}: {last_error}")


async def _start_tcp_line_bounce_server(host: str, port: int) -> tuple[asyncio.AbstractServer, list[bytes]]:
    received: list[bytes] = []

    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            payload = await asyncio.wait_for(reader.readline(), timeout=2.0)
            received.append(payload)
            response = bytes([0x02]) + payload[1:] if payload else b""
            writer.write(response)
            await asyncio.wait_for(writer.drain(), timeout=2.0)
        finally:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)

    server = await asyncio.start_server(handle_client, host, int(port))
    return server, received


async def _probe_tcp_line_roundtrip(host: str, port: int, payload: bytes, *, attempts: int = 40) -> bytes:
    last_error: BaseException | None = None
    for _ in range(attempts):
        reader: asyncio.StreamReader | None = None
        writer: asyncio.StreamWriter | None = None
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, int(port)), timeout=0.5)
            writer.write(payload)
            await asyncio.wait_for(writer.drain(), timeout=2.0)
            return await asyncio.wait_for(reader.readline(), timeout=2.0)
        except (OSError, asyncio.TimeoutError, ConnectionError) as exc:
            last_error = exc
            await asyncio.sleep(0.1)
        finally:
            if writer is not None:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
    raise AssertionError(f"failed to round-trip TCP probe to {host}:{port}: {last_error}")


async def _probe_http_get(host: str, port: int, path: str, *, attempts: int = 40) -> tuple[int, str]:
    last_error: BaseException | None = None
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{int(port)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("utf-8")
    for _ in range(attempts):
        reader: asyncio.StreamReader | None = None
        writer: asyncio.StreamWriter | None = None
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, int(port)), timeout=0.5)
            writer.write(request)
            await asyncio.wait_for(writer.drain(), timeout=2.0)
            raw = await asyncio.wait_for(reader.read(), timeout=4.0)
            head, _, body = raw.partition(b"\r\n\r\n")
            status_line = head.splitlines()[0].decode("iso-8859-1", errors="replace")
            parts = status_line.split(" ", 2)
            if len(parts) < 2:
                raise AssertionError(f"invalid HTTP status line: {status_line!r}")
            return int(parts[1]), body.decode("utf-8", errors="replace")
        except (OSError, asyncio.TimeoutError, ConnectionError, AssertionError) as exc:
            last_error = exc
            await asyncio.sleep(0.1)
        finally:
            if writer is not None:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
    raise AssertionError(f"failed to fetch HTTP GET {path} from {host}:{port}: {last_error}")


async def _wait_tcp_listener_ready(host: str, port: int, *, attempts: int = 120) -> None:
    last_error: BaseException | None = None
    for _ in range(attempts):
        writer: asyncio.StreamWriter | None = None
        try:
            _reader, writer = await asyncio.wait_for(asyncio.open_connection(host, int(port)), timeout=0.5)
            return
        except (OSError, asyncio.TimeoutError, ConnectionError) as exc:
            last_error = exc
            await asyncio.sleep(0.1)
        finally:
            if writer is not None:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
    raise AssertionError(f"TCP listener did not become ready on {host}:{port}: {last_error}")


def _fetch_json(url: str, timeout: float = 1.5) -> tuple[int, dict]:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
        return int(getattr(response, "status", 200) or 200), payload if isinstance(payload, dict) else {}


def _fetch_text(url: str, timeout: float = 2.0) -> tuple[int, str]:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        payload = response.read().decode("utf-8", errors="replace")
        return int(getattr(response, "status", 200) or 200), payload


def _http_request_json(
    url: str,
    *,
    method: str = "GET",
    payload: dict | None = None,
    timeout: float = 2.0,
) -> dict:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"} if data is not None else {}
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        doc = json.loads(response.read().decode("utf-8"))
        return doc if isinstance(doc, dict) else {}


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise AssertionError(f"socket closed while waiting for {size} bytes")
        data.extend(chunk)
    return bytes(data)


def _websocket_connect(
    host: str,
    port: int,
    path: str = "/api/live",
    *,
    headers: dict[str, str] | None = None,
) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=2.0)
    sock.settimeout(2.0)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request_lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}:{port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    for header_key, header_value in (headers or {}).items():
        request_lines.append(f"{header_key}: {header_value}")
    request = "\r\n".join(request_lines) + "\r\n\r\n"
    sock.sendall(request.encode("utf-8"))
    response = bytearray()
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError("websocket handshake response closed early")
        response.extend(chunk)
    header_text = response.decode("utf-8", errors="replace")
    if "101 Switching Protocols" not in header_text:
        raise AssertionError(f"unexpected websocket handshake response: {header_text}")
    return sock


def _recv_ws_json(sock: socket.socket) -> dict:
    while True:
        header = _recv_exact(sock, 2)
        b1, b2 = header[0], header[1]
        opcode = b1 & 0x0F
        masked = bool(b2 & 0x80)
        length = b2 & 0x7F
        if length == 126:
            length = int.from_bytes(_recv_exact(sock, 2), "big")
        elif length == 127:
            length = int.from_bytes(_recv_exact(sock, 8), "big")
        mask = _recv_exact(sock, 4) if masked else b""
        payload = bytearray(_recv_exact(sock, length))
        if masked:
            for index in range(len(payload)):
                payload[index] ^= mask[index % 4]
        if opcode == 0xA:
            continue
        if opcode == 0x8:
            raise AssertionError("websocket closed before expected message")
        if opcode != 0x1:
            raise AssertionError(f"unexpected websocket opcode: {opcode}")
        doc = json.loads(payload.decode("utf-8"))
        if not isinstance(doc, dict):
            raise AssertionError(f"unexpected websocket payload: {doc!r}")
        return doc


def _send_ws_json(sock: socket.socket, payload: dict) -> None:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    mask = os.urandom(4)
    frame = bytearray([0x81])
    if len(raw) < 126:
        frame.append(0x80 | len(raw))
    elif len(raw) <= 0xFFFF:
        frame.append(0x80 | 126)
        frame.extend(len(raw).to_bytes(2, "big"))
    else:
        frame.append(0x80 | 127)
        frame.extend(len(raw).to_bytes(8, "big"))
    frame.extend(mask)
    for index, byte in enumerate(raw):
        frame.append(byte ^ mask[index % 4])
    sock.sendall(frame)


def _wait_ws_message(sock: socket.socket, predicate, *, timeout: float = 5.0) -> dict:
    deadline = time.time() + timeout
    last_message = None
    while time.time() < deadline:
        last_message = _recv_ws_json(sock)
        if predicate(last_message):
            return last_message
    raise AssertionError(f"timed out waiting for websocket message: {last_message!r}")


def _recv_initial_live_ws_message(sock: socket.socket) -> dict:
    message = _recv_ws_json(sock)
    if str(message.get("type") or "") in {"hello", "status", "connections", "peers", "meta"}:
        return message
    raise AssertionError(f"unexpected initial websocket message: {message!r}")


def _wait_admin_peer_secure_link_state(
    admin_port: int,
    *,
    transport: str,
    expected_state: str,
    authenticated: bool,
    timeout: float = 12.0,
) -> dict:
    end = time.time() + timeout
    last_doc: dict | None = None
    while time.time() < end:
        try:
            _code, doc = _fetch_json(f"http://127.0.0.1:{admin_port}/api/peers")
        except Exception:
            time.sleep(0.25)
            continue
        last_doc = doc
        for row in list(doc.get("peers") or []):
            if str(row.get("transport") or "").strip().lower() != str(transport).strip().lower():
                continue
            if str(row.get("state") or "").strip().lower() == "listening":
                continue
            secure_link = row.get("secure_link") or {}
            if str(secure_link.get("state") or "").strip().lower() != str(expected_state).strip().lower():
                continue
            if bool(secure_link.get("authenticated")) != bool(authenticated):
                continue
            return doc
        time.sleep(0.25)
    raise AssertionError(
        f"/api/peers did not expose secure_link state={expected_state} transport={transport} on port {admin_port}; last={last_doc!r}"
    )


def _wait_admin_compress_layer_stats(
    admin_port: int,
    *,
    transport: str,
    minimum_applied_total: int = 1,
    timeout: float = 12.0,
) -> dict:
    end = time.time() + timeout
    last_doc: dict | None = None
    last_status_doc: dict | None = None
    while time.time() < end:
        try:
            _code, doc = _fetch_json(f"http://127.0.0.1:{admin_port}/api/peers")
            last_doc = doc
            for row in list(doc.get("peers") or []):
                if str(row.get("transport") or "").strip().lower() != str(transport).strip().lower():
                    continue
                if str(row.get("state") or "").strip().lower() == "listening":
                    continue
                comp = row.get("compress_layer") or {}
                if bool(comp.get("enabled")) and int(comp.get("compress_applied_total") or 0) >= int(minimum_applied_total):
                    return doc
        except Exception:
            pass
        try:
            _status_code, status_doc = _fetch_json(f"http://127.0.0.1:{admin_port}/api/status")
            last_status_doc = status_doc
            comp = status_doc.get("compress_layer") or {}
            if str(comp.get("transport") or "").strip().lower() in ("", str(transport).strip().lower()):
                if bool(comp.get("enabled")) and int(comp.get("compress_applied_total") or 0) >= int(minimum_applied_total):
                    return status_doc
        except Exception:
            pass
        time.sleep(0.25)
    raise AssertionError(
        f"admin surfaces did not expose compress_layer transport={transport} on port {admin_port}; last_peers={last_doc!r} last_status={last_status_doc!r}"
    )


def _wait_admin_tcp_listener_count(
    admin_port: int,
    *,
    minimum_count: int = 1,
    timeout: float = 12.0,
) -> dict:
    end = time.time() + timeout
    last_doc: dict | None = None
    while time.time() < end:
        try:
            _code, doc = _fetch_json(f"http://127.0.0.1:{admin_port}/api/connections")
        except Exception:
            time.sleep(0.25)
            continue
        last_doc = doc
        counts = doc.get("counts") or {}
        if int(counts.get("tcp_listening") or 0) >= int(minimum_count):
            return doc
        time.sleep(0.25)
    raise AssertionError(
        f"/api/connections did not expose tcp_listening>={minimum_count} on port {admin_port}; last={last_doc!r}"
    )


def _wait_client_tcp_listener_count(
    client: ObstacleBridgeClient,
    *,
    minimum_count: int = 1,
    timeout: float = 12.0,
) -> dict:
    end = time.time() + timeout
    last_snapshot: dict | None = None
    while time.time() < end:
        snapshot = client.snapshot()
        last_snapshot = snapshot
        counts = ((snapshot.get("connections") or {}).get("counts") or {}) if isinstance(snapshot, dict) else {}
        if int(counts.get("tcp_listening") or 0) >= int(minimum_count):
            return snapshot
        time.sleep(0.25)
    raise AssertionError(
        f"client snapshot did not expose tcp_listening>={minimum_count}; last={last_snapshot!r}"
    )


async def _wait_client_peer_secure_link_state(
    client: ObstacleBridgeClient,
    *,
    transport: str,
    expected_state: str,
    authenticated: bool,
    timeout: float = 12.0,
) -> dict:
    end = time.time() + timeout
    last_doc: dict | None = None
    while time.time() < end:
        runner = client.runner
        doc = runner.get_peer_connections_snapshot() if runner is not None else {}
        last_doc = doc if isinstance(doc, dict) else {}
        for row in list((last_doc.get("peers") or [])):
            if str(row.get("transport") or "").strip().lower() != str(transport).strip().lower():
                continue
            if str(row.get("state") or "").strip().lower() == "listening":
                continue
            secure_link = row.get("secure_link") or {}
            if str(secure_link.get("state") or "").strip().lower() != str(expected_state).strip().lower():
                continue
            if bool(secure_link.get("authenticated")) != bool(authenticated):
                continue
            return last_doc
        await asyncio.sleep(0.25)
    raise AssertionError(
        f"client peer snapshot did not expose secure_link state={expected_state} transport={transport}; last={last_doc!r}"
    )


async def _wait_client_compress_layer_stats(
    client: ObstacleBridgeClient,
    *,
    minimum_applied_total: int = 1,
    timeout: float = 12.0,
) -> dict:
    end = time.time() + timeout
    last_snapshot: dict | None = None
    while time.time() < end:
        snapshot = client.snapshot()
        last_snapshot = snapshot
        status = (snapshot.get("status") or {}) if isinstance(snapshot, dict) else {}
        comp = (status.get("compress_layer") or {}) if isinstance(status, dict) else {}
        if bool(comp.get("enabled")) and int(comp.get("compress_applied_total") or 0) >= int(minimum_applied_total):
            return snapshot
        await asyncio.sleep(0.25)
    raise AssertionError(
        f"client snapshot did not expose compress_layer stats applied>={minimum_applied_total}; last={last_snapshot!r}"
    )


async def _wait_extension_tcp_listener_count(
    snapshot_getter: Callable[[], dict[str, object]],
    *,
    minimum_count: int = 1,
    timeout: float = 12.0,
) -> dict[str, object]:
    end = time.time() + timeout
    last_snapshot: dict[str, object] | None = None
    while time.time() < end:
        snapshot = snapshot_getter()
        last_snapshot = snapshot
        counts = ((snapshot.get("connections") or {}).get("counts") or {}) if isinstance(snapshot, dict) else {}
        if int(counts.get("tcp_listening") or 0) >= int(minimum_count):
            return snapshot
        await asyncio.sleep(0.25)
    raise AssertionError(
        f"extension snapshot did not expose tcp_listening>={minimum_count}; last={last_snapshot!r}"
    )


async def _wait_extension_listener_count(
    snapshot_getter: Callable[[], dict[str, object]],
    *,
    protocol: str,
    minimum_count: int = 1,
    timeout: float = 12.0,
) -> dict[str, object]:
    end = time.time() + timeout
    key = f"{str(protocol).strip().lower()}_listening"
    last_snapshot: dict[str, object] | None = None
    while time.time() < end:
        snapshot = snapshot_getter()
        last_snapshot = snapshot
        counts = ((snapshot.get("connections") or {}).get("counts") or {}) if isinstance(snapshot, dict) else {}
        if int(counts.get(key) or 0) >= int(minimum_count):
            return snapshot
        await asyncio.sleep(0.25)
    raise AssertionError(
        f"extension snapshot did not expose {key}>={minimum_count}; last={last_snapshot!r}"
    )


def _ws_bridge_server_config(ws_port: int) -> dict:
    return {
        "overlay_transport": "ws",
        "ws_bind": "127.0.0.1",
        "ws_own_port": int(ws_port),
        "secure_link_mode": "off",
        "admin_web": False,
        "status": False,
    }


def _ws_secure_link_server_config(ws_port: int, *, case_index: int) -> dict:
    return {
        "overlay_transport": "ws",
        "ws_bind": "127.0.0.1",
        "ws_own_port": int(ws_port),
        "secure_link": True,
        "secure_link_mode": "psk",
        "secure_link_psk": "ios-e2e-secure-link-psk",
        "admin_web": True,
        "admin_web_bind": "127.0.0.1",
        "admin_web_port": _alloc_local_port(
            socket.SOCK_STREAM,
            case_index=case_index,
            base=IOS_E2E_TCP_PORT_BASE + 1000,
        ),
        "admin_web_auth_disable": True,
        "status": False,
    }


def _quic_secure_link_server_config(quic_port: int, *, case_index: int, cert_dir: Path) -> dict:
    return {
        "overlay_transport": "quic",
        "quic_bind": "127.0.0.1",
        "quic_own_port": int(quic_port),
        "quic_cert": str(cert_dir / "cert.pem"),
        "quic_key": str(cert_dir / "key.pem"),
        "secure_link": True,
        "secure_link_mode": "psk",
        "secure_link_psk": "ios-e2e-secure-link-psk",
        "admin_web": True,
        "admin_web_bind": "127.0.0.1",
        "admin_web_port": _alloc_local_port(
            socket.SOCK_STREAM,
            case_index=case_index,
            base=IOS_E2E_TCP_PORT_BASE + 1000,
        ),
        "admin_web_auth_disable": True,
        "status": False,
    }


def _quic_bridge_server_config(quic_port: int, *, cert_dir: Path) -> dict:
    return {
        "overlay_transport": "quic",
        "quic_bind": "127.0.0.1",
        "quic_own_port": int(quic_port),
        "quic_cert": str(cert_dir / "cert.pem"),
        "quic_key": str(cert_dir / "key.pem"),
        "admin_web": False,
        "status": False,
    }


def _myudp_secure_link_compress_server_config(udp_port: int, *, admin_port: int) -> dict:
    return {
        "overlay_transport": "myudp",
        "udp_bind": "0.0.0.0",
        "udp_own_port": int(udp_port),
        "secure_link": True,
        "secure_link_mode": "psk",
        "secure_link_psk": "ios-extension-myudp-psk",
        "compress_layer": True,
        "compress_layer_algo": "zlib",
        "compress_layer_level": 3,
        "compress_layer_min_bytes": 64,
        "compress_layer_types": "data,data_frag",
        "admin_web": True,
        "admin_web_bind": "127.0.0.1",
        "admin_web_port": int(admin_port),
        "admin_web_auth_disable": True,
        "status": False,
    }


def _reload_extension_modules(documents_root: Path, home_root: Path) -> tuple[Any, Any, Any]:
    os.environ["OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT"] = str(documents_root)
    os.environ["HOME"] = str(home_root)

    from obstacle_bridge_ios import app as ios_app
    from obstacle_bridge_ios import ipserver_extension
    from obstacle_bridge_ios import ipserver_runtime

    importlib.reload(ios_app)
    importlib.reload(ipserver_runtime)
    importlib.reload(ipserver_extension)
    return ios_app, ipserver_extension, ipserver_runtime


def _build_myudp_extension_provider_configuration(
    *,
    myudp_port: int,
    swift_bind_port: int,
    swift_peer_port: int,
    own_servers: list[dict[str, Any]],
    remote_servers: list[dict[str, Any]] | None = None,
    admin_web: bool = False,
    admin_web_bind: str = "127.0.0.1",
    admin_web_port: int = 0,
    admin_web_auth_disable: bool = True,
    tunnel_address: str,
    included_routes: list[str],
    profile_id: str,
    display_name: str,
) -> dict[str, Any]:
    remote_specs = list(remote_servers or [])
    return provider_configuration_from_m3_config(
        M3TunnelConfig(
            profile_id=profile_id,
            display_name=display_name,
            provider_bundle_identifier="com.obstaclebridge.ObstacleBridge.PacketTunnel",
            transport="myudp",
            peer_host="127.0.0.1",
            peer_port=myudp_port,
            server_address=f"127.0.0.1:{myudp_port}",
            runtime_config={
                "overlay_transport": "myudp",
                "udp_peer": "127.0.0.1",
                "udp_peer_port": myudp_port,
                "udp_bind": "0.0.0.0",
                "udp_own_port": 0,
                "secure_link": True,
                "secure_link_mode": "psk",
                "secure_link_psk": "ios-extension-myudp-psk",
                "compress_layer": True,
                "compress_layer_algo": "zlib",
                "compress_layer_level": 3,
                "compress_layer_min_bytes": 64,
                "compress_layer_types": "data,data_frag",
                "remote_servers": remote_specs,
                "channel_mux": {
                    "own_servers": list(own_servers),
                    "remote_servers": remote_specs,
                },
                "iOS_TUN_connector": {
                    "packetflow_connector": "swift_udp",
                    "bind_host": "127.0.0.1",
                    "bind_port": swift_bind_port,
                    "peer_host": "127.0.0.1",
                    "peer_port": swift_peer_port,
                    "ifname": "ios-utun",
                    "mtu": 1400,
                },
                "admin_web": admin_web,
                "admin_web_bind": admin_web_bind,
                "admin_web_port": int(admin_web_port),
                "admin_web_auth_disable": admin_web_auth_disable,
                "status": False,
            },
            network=M3NetworkSettings(
                tunnel_address=tunnel_address,
                tunnel_prefix=30,
                included_routes=list(included_routes),
                excluded_routes=[],
                dns_servers=["1.1.1.1"],
                mtu=1400,
            ),
        )
    )


def _build_empty_onboarding_extension_provider_configuration(
    *,
    admin_web_port: int,
    profile_id: str,
    display_name: str,
) -> dict[str, Any]:
    return provider_configuration_from_m3_config(
        M3TunnelConfig(
            profile_id=profile_id,
            display_name=display_name,
            provider_bundle_identifier="com.obstaclebridge.ObstacleBridge.PacketTunnel",
            transport="myudp",
            peer_host="bootstrap.invalid",
            peer_port=4433,
            server_address="bootstrap.invalid:4433",
            runtime_config={
                "overlay_transport": "myudp",
                "channel_mux": {
                    "own_servers": [],
                    "remote_servers": [],
                },
                "iOS_TUN_connector": {
                    "packetflow_connector": "swift_udp",
                    "bind_host": "127.0.0.1",
                    "bind_port": 5555,
                    "peer_host": "",
                    "peer_port": 0,
                    "ifname": "ios-utun",
                    "mtu": 1400,
                },
                "admin_web": True,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": int(admin_web_port),
                "admin_web_auth_disable": True,
                "status": False,
            },
            network=M3NetworkSettings(
                tunnel_address="192.168.106.40",
                tunnel_prefix=30,
                included_routes=[],
                excluded_routes=[],
                tunnel_address6="fd20:106::40",
                tunnel_prefix6=126,
                included_routes6=[],
                excluded_routes6=[],
                dns_servers=["1.1.1.1"],
                mtu=1400,
            ),
        )
    )


def _load_ios_e2e_runner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    documents_root = tmp_path / "ios-documents"
    home_root = tmp_path / "home"
    documents_root.mkdir(parents=True, exist_ok=True)
    home_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", str(documents_root))
    monkeypatch.setenv("HOME", str(home_root))

    from obstacle_bridge_ios import app as ios_app
    from obstacle_bridge_ios_e2e import runner as ios_runner

    importlib.reload(ios_app)
    return importlib.reload(ios_runner)


@pytest.mark.integration
@pytest.mark.ios
def test_ios_m3_packet_tunnel_poc_provider_config_round_trips_packets() -> None:
    async def scenario() -> None:
        async def run_client(peer_port: int, peer_packets: list[bytes]) -> None:
            provider_configuration = _m3_provider_configuration(peer_port)
            flow = SimulatedIOSPacketFlow([IOS_REQUEST_PACKET])

            await _run_m3_packet_flow_once(provider_configuration, flow)

            assert peer_packets == [IOS_REQUEST_PACKET]
            assert flow.outgoing_packets == [IOS_RESPONSE_PACKET]
            assert provider_configuration["schema"] == "obstaclebridge.ios.packet-tunnel.v1"
            assert provider_configuration["poc"]["packet_flow"] == "NEPacketTunnelFlow"
            assert provider_configuration["poc"]["transport_bridge"] == "tcp-length-prefixed-packets"

        await _with_packet_frame_peer(IOS_RESPONSE_PACKET, run_client)

    asyncio.run(scenario())


@pytest.mark.integration
@pytest.mark.ios
def test_ios_m3_vpn_profile_descriptor_survives_app_to_extension_serialization() -> None:
    provider_configuration = _m3_provider_configuration(peer_port=4433)
    restored = json.loads(json.dumps(provider_configuration))

    assert restored["milestone"] == "M3"
    assert restored["peer"] == {"host": "127.0.0.1", "port": 4433}
    assert restored["network_settings"]["tunnel_address"] == "192.168.105.1"
    assert restored["network_settings"]["tunnel_prefix"] == 30
    assert restored["network_settings"]["included_routes"] == ["192.168.105.0/30"]
    assert restored["poc"]["secure_link"] == "deferred-to-M4"


@pytest.mark.integration
@pytest.mark.ios
def test_ios_e2e_app_ws_overlay_udp_service_reaches_linux_peer_udp_echo(tmp_path: Path, monkeypatch) -> None:
    ios_runner = _load_ios_e2e_runner(tmp_path, monkeypatch)

    async def scenario() -> None:
        ws_port = _alloc_local_port(socket.SOCK_STREAM, case_index=0, base=IOS_E2E_TCP_PORT_BASE)
        local_udp_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=0, base=IOS_E2E_UDP_PORT_BASE)
        target_udp_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=1, base=IOS_E2E_UDP_PORT_BASE)

        udp_transport, udp_bounce = await _start_udp_bounce_server("127.0.0.1", target_udp_port)
        bridge_server = ObstacleBridgeClient(_ws_bridge_server_config(ws_port))
        try:
            await bridge_server.start()
            report = await ios_runner.run_ws_udp_echo_probe(
                ws_url=f"ws://127.0.0.1:{ws_port}/obstaclebridge-ios-e2e",
                local_udp_port=local_udp_port,
                target_udp_host="127.0.0.1",
                target_udp_port=target_udp_port,
                payload=IOS_WS_UDP_REQUEST,
                expected=IOS_WS_UDP_RESPONSE,
                timeout_sec=8.0,
            )
        finally:
            await bridge_server.stop()
            udp_transport.close()

        assert report["ok"] is True, report
        assert report["probe"] == "ws-udp-echo"
        assert report["payload_hex"] == IOS_WS_UDP_REQUEST.hex()
        assert report["response_hex"] == IOS_WS_UDP_RESPONSE.hex()
        assert udp_bounce.received == [IOS_WS_UDP_REQUEST]

    asyncio.run(scenario())


@pytest.mark.integration
@pytest.mark.ios
def test_ios_extension_shim_empty_config_serves_admin_web_onboarding_without_peer(tmp_path: Path, monkeypatch) -> None:
    async def scenario() -> None:
        documents_root = tmp_path / "ios-documents"
        home_root = tmp_path / "home"
        documents_root.mkdir(parents=True, exist_ok=True)
        home_root.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", str(documents_root))
        monkeypatch.setenv("HOME", str(home_root))

        _ios_app, ipserver_extension, _ipserver_runtime = _reload_extension_modules(documents_root, home_root)
        extension_admin_port = _alloc_local_port(socket.SOCK_STREAM, case_index=76, base=IOS_E2E_TCP_PORT_BASE + 1000)
        provider_configuration = _build_empty_onboarding_extension_provider_configuration(
            admin_web_port=extension_admin_port,
            profile_id="ios-empty-onboarding",
            display_name="iOS Empty Onboarding",
        )

        start_doc = ipserver_extension.handle_message(
            {
                "command": "start_embedded_webadmin",
                "provider_configuration": provider_configuration,
            }
        )
        try:
            assert start_doc["ok"] is True
            status = _http_request_json(f"http://127.0.0.1:{extension_admin_port}/api/status")
            profiles = _http_request_json(f"http://127.0.0.1:{extension_admin_port}/api/onboarding/connection-profiles")
            blueprints = _http_request_json(f"http://127.0.0.1:{extension_admin_port}/api/onboarding/blueprints")
            _html_code, html = _fetch_text(f"http://127.0.0.1:{extension_admin_port}/")

            assert provider_configuration["network_settings"]["included_routes"] == []
            assert provider_configuration["network_settings"]["included_routes6"] == []
            assert status.get("peer_state") == "DISCONNECTED"
            assert isinstance(status.get("admin_ui"), dict)
            assert status["admin_ui"]["home_tab_enabled"] is True
            assert status["admin_ui"]["first_start_detected"] is True
            assert status["admin_ui"]["config_file_state"] == "empty"
            assert profiles["ok"] is True
            assert isinstance(profiles["profiles"], list)
            assert blueprints["ok"] is True
            assert isinstance(blueprints["blueprints"], list)
            assert "Open Setup Assistant" in html or "Connection Profiles" in html
        finally:
            stop_doc = ipserver_extension.handle_message({"command": "disconnect_profile"})
            assert stop_doc["ok"] is True

    asyncio.run(scenario())


@pytest.mark.integration
@pytest.mark.ios
def test_ios_e2e_app_ws_secure_link_probe_authenticates_against_host_peer(tmp_path: Path, monkeypatch) -> None:
    ios_runner = _load_ios_e2e_runner(tmp_path, monkeypatch)

    async def scenario() -> None:
        ws_port = _alloc_local_port(socket.SOCK_STREAM, case_index=1, base=IOS_E2E_TCP_PORT_BASE)
        bridge_server = ObstacleBridgeClient(_ws_secure_link_server_config(ws_port, case_index=2))
        try:
            await bridge_server.start()
            report = await ios_runner.run_ws_secure_link_probe(
                ws_url=f"ws://127.0.0.1:{ws_port}/obstaclebridge-ios-e2e",
                secure_link_psk="ios-e2e-secure-link-psk",
                timeout_sec=8.0,
                hold_after_success_sec=0.0,
            )
        finally:
            await bridge_server.stop()

        assert report["ok"] is True, report
        assert report["probe"] == "ws-secure-link"
        assert report["secure_link_mode"] == "psk"
        assert report["secure_link_authenticated"] is True
        assert report["peer_transport"] == "ws"
        assert report["secure_link_state"] == "authenticated"

    asyncio.run(scenario())


@pytest.mark.integration
@pytest.mark.ios
@pytest.mark.parametrize("transport", ["ws", "quic"])
def test_ios_extension_shim_swift_udp_tcp_service_reaches_python_peer_for_ws_and_quic(
    tmp_path: Path,
    monkeypatch,
    transport: str,
) -> None:
    documents_root = tmp_path / "ios-documents"
    home_root = tmp_path / "home"
    documents_root.mkdir(parents=True, exist_ok=True)
    home_root.mkdir(parents=True, exist_ok=True)

    with monkeypatch.context() as local_mp:
        local_mp.setenv("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", str(documents_root))
        local_mp.setenv("HOME", str(home_root))

        from obstacle_bridge_ios import app as ios_app
        from obstacle_bridge_ios import ipserver_extension
        from obstacle_bridge_ios import ipserver_runtime

        importlib.reload(ios_app)
        importlib.reload(ipserver_runtime)
        importlib.reload(ipserver_extension)

        async def scenario() -> None:
            overlay_port = _alloc_local_port(
                socket.SOCK_STREAM if transport == "ws" else socket.SOCK_DGRAM,
                case_index=3 if transport == "ws" else 4,
                base=IOS_E2E_TCP_PORT_BASE if transport == "ws" else IOS_E2E_UDP_PORT_BASE,
            )
            local_tcp_port = _alloc_local_port(socket.SOCK_STREAM, case_index=4, base=IOS_E2E_TCP_PORT_BASE)
            target_tcp_port = _alloc_local_port(socket.SOCK_STREAM, case_index=5, base=IOS_E2E_TCP_PORT_BASE)
            swift_bind_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=6, base=IOS_E2E_UDP_PORT_BASE)
            swift_peer_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=7, base=IOS_E2E_UDP_PORT_BASE)
            probe_payloads = [
                b"\x01ios-extension-tcp-client1\n",
                b"\x01ios-extension-tcp-client2-xxxxxxxxxxxxxxxx\n",
                b"\x01ios-extension-tcp-client3-yyyyyyyyyyyyyyyyyyyyyyyy\n",
            ]
            expected_responses = [
                b"\x02ios-extension-tcp-client1\n",
                b"\x02ios-extension-tcp-client2-xxxxxxxxxxxxxxxx\n",
                b"\x02ios-extension-tcp-client3-yyyyyyyyyyyyyyyyyyyyyyyy\n",
            ]
            cert_dir = (
                materialize_localhost_tls_fixture_set(tmp_path / f"{transport}-ios-tcp-localhost-fixtures")
                if transport == "quic"
                else None
            )

            tcp_server, tcp_received = await _start_tcp_line_bounce_server("127.0.0.1", target_tcp_port)
            if transport == "ws":
                bridge_server = ObstacleBridgeClient(_ws_bridge_server_config(overlay_port))
                runtime_transport_config: dict[str, Any] = {
                    "overlay_transport": "ws",
                    "ws_peer": "127.0.0.1",
                    "ws_peer_port": overlay_port,
                    "ws_bind": "127.0.0.1",
                    "ws_own_port": 0,
                }
            else:
                assert cert_dir is not None
                bridge_server = ObstacleBridgeClient(_quic_bridge_server_config(overlay_port, cert_dir=cert_dir))
                runtime_transport_config = {
                    "overlay_transport": "quic",
                    "quic_peer": "127.0.0.1",
                    "quic_peer_port": overlay_port,
                    "quic_bind": "127.0.0.1",
                    "quic_own_port": 0,
                    "quic_alpn": "hq-29",
                    "quic_insecure": True,
                }
            provider_configuration = provider_configuration_from_m3_config(
                M3TunnelConfig(
                    profile_id=f"ios-extension-shim-{transport}-e2e",
                    display_name=f"iOS Extension Shim {transport.upper()} E2E",
                    provider_bundle_identifier="com.obstaclebridge.ObstacleBridge.PacketTunnel",
                    transport=transport,
                    peer_host="127.0.0.1",
                    peer_port=overlay_port,
                    server_address=f"127.0.0.1:{overlay_port}",
                    runtime_config={
                        **runtime_transport_config,
                        "channel_mux": {
                            "own_servers": [
                                {
                                    "name": "tcp-echo",
                                    "listen": {"bind": "127.0.0.1", "port": local_tcp_port, "protocol": "tcp"},
                                    "target": {"host": "127.0.0.1", "port": target_tcp_port, "protocol": "tcp"},
                                },
                                {
                                    "name": "tun",
                                    "listen": {"ifname": "ios-utun", "mtu": 1400, "protocol": "tun"},
                                    "target": {"ifname": "obtun2", "mtu": 1400, "protocol": "tun"},
                                },
                            ]
                        },
                        "iOS_TUN_connector": {
                            "packetflow_connector": "swift_udp",
                            "bind_host": "127.0.0.1",
                            "bind_port": swift_bind_port,
                            "peer_host": "127.0.0.1",
                            "peer_port": swift_peer_port,
                            "ifname": "ios-utun",
                            "mtu": 1400,
                        },
                        "admin_web": False,
                        "status": False,
                    },
                    network=M3NetworkSettings(
                        tunnel_address="192.168.106.2",
                        tunnel_prefix=30,
                        included_routes=["192.168.106.0/30"],
                        excluded_routes=[],
                        dns_servers=["1.1.1.1"],
                        mtu=1400,
                    ),
                )
            )
            start_result: dict[str, object] | None = None
            stop_result: dict[str, object] | None = None
            try:
                await bridge_server.start()
                start_result = ipserver_extension.handle_message(
                    {
                        "command": "start_embedded_webadmin",
                        "provider_configuration": provider_configuration,
                    }
                )
                assert start_result["ok"] is True, start_result
                snapshot = start_result["result"]
                assert isinstance(snapshot, dict)
                config = snapshot["config"]
                assert config["overlay_transport"] == transport
                assert os.environ.get("OBSTACLEBRIDGE_IOS_PACKETFLOW_CONNECTOR") == "swift_udp"

                responses = await asyncio.gather(
                    *[
                        _probe_tcp_line_roundtrip("127.0.0.1", local_tcp_port, payload)
                        for payload in probe_payloads
                    ]
                )
                assert responses == expected_responses
                assert sorted(tcp_received) == sorted(probe_payloads)

                snapshot_result = ipserver_extension.handle_message({"command": "snapshot"})
                assert snapshot_result["ok"] is True, snapshot_result
                runtime_snapshot = snapshot_result["result"]
                assert isinstance(runtime_snapshot, dict)
                assert runtime_snapshot["started"] is True
            finally:
                if ipserver_extension._CONTROLLER is not None:
                    stop_result = ipserver_extension.handle_message({"command": "disconnect_profile"})
                    ipserver_extension._CONTROLLER = None
                    with contextlib.suppress(asyncio.CancelledError):
                        await bridge_server.stop()
                tcp_server.close()
                await tcp_server.wait_closed()

            assert stop_result is not None
            assert stop_result["ok"] is True, stop_result

        asyncio.run(scenario())

    monkeypatch.setenv("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", str(documents_root))
    monkeypatch.setenv("HOME", str(home_root))
    importlib.reload(ios_app)
    importlib.reload(ipserver_runtime)
    importlib.reload(ipserver_extension)


@pytest.mark.integration
@pytest.mark.ios
def test_ios_extension_shim_swift_udp_myudp_secure_link_mixed_service_matrix_stays_authenticated(
    tmp_path: Path,
    monkeypatch,
) -> None:
    documents_root = tmp_path / "ios-documents-myudp-mixed-matrix"
    home_root = tmp_path / "home-myudp-mixed-matrix"
    documents_root.mkdir(parents=True, exist_ok=True)
    home_root.mkdir(parents=True, exist_ok=True)

    with monkeypatch.context() as local_mp:
        local_mp.setenv("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", str(documents_root))
        local_mp.setenv("HOME", str(home_root))

        ios_app, ipserver_extension, ipserver_runtime = _reload_extension_modules(documents_root, home_root)

        async def scenario() -> None:
            myudp_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=40, base=IOS_E2E_UDP_PORT_BASE)
            swift_bind_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=41, base=IOS_E2E_UDP_PORT_BASE)
            swift_peer_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=42, base=IOS_E2E_UDP_PORT_BASE)
            server_admin_port = _alloc_local_port(socket.SOCK_STREAM, case_index=43, base=IOS_E2E_TCP_PORT_BASE + 1000)
            extension_admin_port = _alloc_local_port(socket.SOCK_STREAM, case_index=44, base=IOS_E2E_TCP_PORT_BASE + 1200)
            local_http_port = _alloc_local_port(socket.SOCK_STREAM, case_index=45, base=IOS_E2E_TCP_PORT_BASE)
            local_tcp_port = _alloc_local_port(socket.SOCK_STREAM, case_index=46, base=IOS_E2E_TCP_PORT_BASE)
            target_tcp_port = _alloc_local_port(socket.SOCK_STREAM, case_index=47, base=IOS_E2E_TCP_PORT_BASE)
            local_udp_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=48, base=IOS_E2E_UDP_PORT_BASE)
            target_udp_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=49, base=IOS_E2E_UDP_PORT_BASE)
            remote_tcp_port = _alloc_local_port(socket.SOCK_STREAM, case_index=50, base=IOS_E2E_TCP_PORT_BASE + 200)

            own_servers = [
                {
                    "name": "udp-echo",
                    "listen": {"bind": "127.0.0.1", "port": local_udp_port, "protocol": "udp"},
                    "target": {"host": "127.0.0.1", "port": target_udp_port, "protocol": "udp"},
                },
                {
                    "name": "tcp-echo",
                    "listen": {"bind": "127.0.0.1", "port": local_tcp_port, "protocol": "tcp"},
                    "target": {"host": "127.0.0.1", "port": target_tcp_port, "protocol": "tcp"},
                },
                {
                    "name": "WebAdmin remote",
                    "listen": {"bind": "127.0.0.1", "port": local_http_port, "protocol": "tcp"},
                    "target": {"host": "127.0.0.1", "port": 18090, "protocol": "tcp"},
                },
                {
                    "name": "tun",
                    "listen": {"ifname": "ios-utun", "mtu": 1400, "protocol": "tun"},
                    "target": {"ifname": "obtun2", "mtu": 1400, "protocol": "tun"},
                },
            ]
            remote_servers = [
                {
                    "name": "WebAdmin Mac",
                    "listen": {"bind": "127.0.0.1", "port": remote_tcp_port, "protocol": "tcp"},
                    "target": {"host": "127.0.0.1", "port": 18090, "protocol": "tcp"},
                }
            ]
            udp_payloads = [
                b"\x01alpha-mixed-udp",
                b"\x01bravo-mixed-udp" * 6,
                b"\x01charlie-mixed-udp" * 12,
            ]
            tcp_payloads = [
                b"\x01alpha-mixed-tcp\n",
                b"\x01bravo-mixed-tcp" * 8 + b"\n",
                b"\x01charlie-mixed-tcp" * 16 + b"\n",
            ]

            udp_transport, udp_bounce = await _start_udp_bounce_server("127.0.0.1", target_udp_port)
            tcp_server, tcp_received = await _start_tcp_line_bounce_server("127.0.0.1", target_tcp_port)
            bridge_server = ObstacleBridgeClient(
                _myudp_secure_link_compress_server_config(myudp_port, admin_port=server_admin_port)
            )
            provider_configuration = _build_myudp_extension_provider_configuration(
                myudp_port=myudp_port,
                swift_bind_port=swift_bind_port,
                swift_peer_port=swift_peer_port,
                own_servers=own_servers,
                remote_servers=remote_servers,
                admin_web=True,
                admin_web_bind="127.0.0.1",
                admin_web_port=extension_admin_port,
                admin_web_auth_disable=True,
                tunnel_address="192.168.106.22",
                included_routes=["192.168.106.20/30"],
                profile_id="ios-extension-shim-myudp-mixed-service-matrix",
                display_name="iOS Extension Shim myUDP Mixed Service Matrix",
            )
            start_result: dict[str, object] | None = None
            stop_result: dict[str, object] | None = None
            try:
                await bridge_server.start()
                start_result = ipserver_extension.handle_message(
                    {
                        "command": "start_embedded_webadmin",
                        "provider_configuration": provider_configuration,
                    }
                )
                assert start_result["ok"] is True, start_result

                await _wait_client_peer_secure_link_state(
                    bridge_server,
                    transport="myudp",
                    expected_state="authenticated",
                    authenticated=True,
                    timeout=12.0,
                )
                await _wait_extension_listener_count(
                    lambda: ipserver_extension.handle_message({"command": "snapshot"})["result"],
                    protocol="tcp",
                    minimum_count=2,
                    timeout=12.0,
                )
                await _wait_extension_listener_count(
                    lambda: ipserver_extension.handle_message({"command": "snapshot"})["result"],
                    protocol="udp",
                    minimum_count=1,
                    timeout=12.0,
                )
                await _wait_tcp_listener_ready("127.0.0.1", local_http_port)
                await _wait_tcp_listener_ready("127.0.0.1", local_tcp_port)
                await _wait_tcp_listener_ready("127.0.0.1", remote_tcp_port)

                status_code, status_text = await _probe_http_get("127.0.0.1", local_http_port, "/api/status")
                assert status_code == 200
                status_doc = json.loads(status_text)
                assert "admin_ui" in status_doc or "build" in status_doc, status_doc

                remote_status_code, remote_status_text = await _probe_http_get("127.0.0.1", remote_tcp_port, "/api/status")
                assert remote_status_code == 200
                remote_status_doc = json.loads(remote_status_text)
                assert "admin_ui" in remote_status_doc or "build" in remote_status_doc, remote_status_doc

                tcp_roundtrips = await asyncio.gather(
                    *[
                        _probe_tcp_line_roundtrip("127.0.0.1", local_tcp_port, payload, attempts=80)
                        for payload in tcp_payloads
                    ]
                )
                for index, payload in enumerate(tcp_payloads):
                    assert tcp_roundtrips[index] == bytes([0x02]) + payload[1:]
                assert tcp_received == tcp_payloads

                udp_responses = []
                for payload in udp_payloads:
                    udp_responses.append(await _probe_udp_roundtrip("127.0.0.1", local_udp_port, payload, attempts=80))
                for index, payload in enumerate(udp_payloads):
                    assert udp_responses[index] == bytes([0x02]) + payload[1:]
                assert udp_bounce.received == udp_payloads

                burst_results = await asyncio.gather(
                    _probe_http_get("127.0.0.1", remote_tcp_port, "/api/status"),
                    _probe_http_get("127.0.0.1", remote_tcp_port, "/api/meta"),
                    _probe_http_get("127.0.0.1", remote_tcp_port, "/api/connections"),
                    _probe_http_get("127.0.0.1", remote_tcp_port, "/api/peers"),
                    _probe_http_get("127.0.0.1", remote_tcp_port, "/"),
                )
                for path, (code, text) in zip(
                    ["/api/status", "/api/meta", "/api/connections", "/api/peers", "/"],
                    burst_results,
                    strict=False,
                ):
                    assert code == 200, (path, code, text)

                await _wait_client_peer_secure_link_state(
                    bridge_server,
                    transport="myudp",
                    expected_state="authenticated",
                    authenticated=True,
                    timeout=6.0,
                )
            finally:
                if ipserver_extension._CONTROLLER is not None:
                    stop_result = ipserver_extension.handle_message({"command": "disconnect_profile"})
                    ipserver_extension._CONTROLLER = None
                tcp_server.close()
                await tcp_server.wait_closed()
                udp_transport.close()
                with contextlib.suppress(asyncio.CancelledError):
                    await bridge_server.stop()

            assert stop_result is not None
            assert stop_result["ok"] is True, stop_result

        asyncio.run(scenario())

    monkeypatch.setenv("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", str(documents_root))
    monkeypatch.setenv("HOME", str(home_root))
    importlib.reload(ios_app)
    importlib.reload(ipserver_runtime)
    importlib.reload(ipserver_extension)


@pytest.mark.integration
@pytest.mark.ios
def test_ios_extension_shim_swift_udp_ws_secure_link_remote_tcp_server_reaches_extension_admin_web(
    tmp_path: Path,
    monkeypatch,
) -> None:
    documents_root = tmp_path / "ios-documents-ws-remote-tcp"
    home_root = tmp_path / "home-ws-remote-tcp"
    documents_root.mkdir(parents=True, exist_ok=True)
    home_root.mkdir(parents=True, exist_ok=True)

    with monkeypatch.context() as local_mp:
        local_mp.setenv("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", str(documents_root))
        local_mp.setenv("HOME", str(home_root))

        ios_app, ipserver_extension, ipserver_runtime = _reload_extension_modules(documents_root, home_root)

        async def scenario() -> None:
            ws_port = _alloc_local_port(socket.SOCK_STREAM, case_index=36, base=IOS_E2E_TCP_PORT_BASE)
            swift_bind_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=37, base=IOS_E2E_UDP_PORT_BASE)
            swift_peer_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=38, base=IOS_E2E_UDP_PORT_BASE)
            server_admin_port = _alloc_local_port(socket.SOCK_STREAM, case_index=39, base=IOS_E2E_TCP_PORT_BASE + 1000)
            extension_admin_port = _alloc_local_port(socket.SOCK_STREAM, case_index=40, base=IOS_E2E_TCP_PORT_BASE + 1200)
            remote_tcp_port = _alloc_local_port(socket.SOCK_STREAM, case_index=41, base=IOS_E2E_TCP_PORT_BASE + 200)
            remote_servers = [
                {
                    "name": "ws-remote-admin-http",
                    "listen": {"bind": "127.0.0.1", "port": remote_tcp_port, "protocol": "tcp"},
                    "target": {"host": "127.0.0.1", "port": extension_admin_port, "protocol": "tcp"},
                }
            ]

            bridge_server_config = _ws_secure_link_server_config(ws_port, case_index=42)
            bridge_server_config["admin_web_port"] = server_admin_port
            bridge_server = ObstacleBridgeClient(bridge_server_config)
            provider_configuration = provider_configuration_from_m3_config(
                M3TunnelConfig(
                    profile_id="ios-extension-shim-ws-remote-tcp-e2e",
                    display_name="iOS Extension Shim WS Remote TCP E2E",
                    provider_bundle_identifier="com.obstaclebridge.ObstacleBridge.PacketTunnel",
                    transport="ws",
                    peer_host="127.0.0.1",
                    peer_port=ws_port,
                    server_address=f"127.0.0.1:{ws_port}",
                    runtime_config={
                        "overlay_transport": "ws",
                        "ws_peer": "127.0.0.1",
                        "ws_peer_port": ws_port,
                        "ws_bind": "127.0.0.1",
                        "ws_own_port": 0,
                        "secure_link": True,
                        "secure_link_mode": "psk",
                        "secure_link_psk": "ios-e2e-secure-link-psk",
                        "compress_layer": True,
                        "compress_layer_algo": "zlib",
                        "compress_layer_level": 3,
                        "compress_layer_min_bytes": 64,
                        "compress_layer_types": "data,data_frag",
                        "remote_servers": remote_servers,
                        "channel_mux": {
                            "own_servers": [],
                            "remote_servers": remote_servers,
                        },
                        "iOS_TUN_connector": {
                            "packetflow_connector": "swift_udp",
                            "bind_host": "127.0.0.1",
                            "bind_port": swift_bind_port,
                            "peer_host": "127.0.0.1",
                            "peer_port": swift_peer_port,
                            "ifname": "ios-utun",
                            "mtu": 1400,
                        },
                        "admin_web": True,
                        "admin_web_bind": "127.0.0.1",
                        "admin_web_port": extension_admin_port,
                        "admin_web_auth_disable": True,
                        "status": False,
                    },
                    network=M3NetworkSettings(
                        tunnel_address="192.168.106.22",
                        tunnel_prefix=30,
                        included_routes=["192.168.106.20/30"],
                        excluded_routes=[],
                        dns_servers=["1.1.1.1"],
                        mtu=1400,
                    ),
                )
            )
            start_result: dict[str, object] | None = None
            stop_result: dict[str, object] | None = None
            try:
                await bridge_server.start()
                start_result = ipserver_extension.handle_message(
                    {
                        "command": "start_embedded_webadmin",
                        "provider_configuration": provider_configuration,
                    }
                )
                assert start_result["ok"] is True, start_result

                await _wait_client_peer_secure_link_state(
                    bridge_server,
                    transport="ws",
                    expected_state="authenticated",
                    authenticated=True,
                    timeout=12.0,
                )
                await _wait_tcp_listener_ready("127.0.0.1", remote_tcp_port)

                status_code, status_text = await _probe_http_get("127.0.0.1", remote_tcp_port, "/api/status")
                assert status_code == 200
                status_doc = json.loads(status_text)
                assert "admin_ui" in status_doc or "build" in status_doc, status_doc

                root_code, root_html = await _probe_http_get("127.0.0.1", remote_tcp_port, "/")
                assert root_code == 200
                assert "ObstacleBridge" in root_html or "Admin Web" in root_html

                app_js_code, app_js_text = await _probe_http_get("127.0.0.1", remote_tcp_port, "/app.js")
                assert app_js_code == 200
                assert "async function loadStatus()" in app_js_text

                style_code, style_text = await _probe_http_get("127.0.0.1", remote_tcp_port, "/style.css")
                assert style_code == 200
                assert "--bg:" in style_text

                burst_results = await asyncio.gather(
                    _probe_http_get("127.0.0.1", remote_tcp_port, "/api/status"),
                    _probe_http_get("127.0.0.1", remote_tcp_port, "/api/meta"),
                    _probe_http_get("127.0.0.1", remote_tcp_port, "/api/connections"),
                    _probe_http_get("127.0.0.1", remote_tcp_port, "/api/peers"),
                    _probe_http_get("127.0.0.1", remote_tcp_port, "/"),
                    _probe_http_get("127.0.0.1", remote_tcp_port, "/app.js"),
                    _probe_http_get("127.0.0.1", remote_tcp_port, "/style.css"),
                    _probe_http_get("127.0.0.1", remote_tcp_port, "/api/status"),
                )
                for path, (code, text) in zip(
                    ["/api/status", "/api/meta", "/api/connections", "/api/peers", "/", "/app.js", "/style.css", "/api/status"],
                    burst_results,
                    strict=False,
                ):
                    assert code == 200, (path, code, text)
                burst_status = json.loads(burst_results[0][1])
                burst_meta = json.loads(burst_results[1][1])
                burst_connections = json.loads(burst_results[2][1])
                burst_peers = json.loads(burst_results[3][1])
                burst_root = burst_results[4][1]
                burst_app_js = burst_results[5][1]
                burst_style = burst_results[6][1]
                assert "admin_ui" in burst_status or "build" in burst_status, burst_status
                assert "build" in burst_meta or "admin_web_name" in burst_meta, burst_meta
                assert "counts" in burst_connections, burst_connections
                assert "peers" in burst_peers, burst_peers
                peer_row = burst_peers["peers"][0]
                if peer_row["transport"] == "myudp":
                    assert float(peer_row["rtt_est_ms"] or 0) > 0
                    assert float(peer_row["transmit_delay_est_ms"] or 0) > 0
                    assert peer_row["last_incoming_age_seconds"] is not None
                    assert int(peer_row["myudp"]["confirmed_total"]) >= 1
                assert "ObstacleBridge" in burst_root or "Admin Web" in burst_root
                assert "async function loadStatus()" in burst_app_js
                assert "--bg:" in burst_style
            finally:
                if ipserver_extension._CONTROLLER is not None:
                    stop_result = ipserver_extension.handle_message({"command": "disconnect_profile"})
                    ipserver_extension._CONTROLLER = None
                with contextlib.suppress(asyncio.CancelledError):
                    await bridge_server.stop()

            assert stop_result is not None
            assert stop_result["ok"] is True, stop_result

        asyncio.run(scenario())

    monkeypatch.setenv("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", str(documents_root))
    monkeypatch.setenv("HOME", str(home_root))
    importlib.reload(ios_app)
    importlib.reload(ipserver_runtime)
    importlib.reload(ipserver_extension)


@pytest.mark.integration
@pytest.mark.ios
def test_ios_extension_shim_swift_udp_myudp_secure_link_admin_web_live_ws_and_restart_contract(
    tmp_path: Path,
    monkeypatch,
) -> None:
    documents_root = tmp_path / "ios-documents-myudp-admin-live"
    home_root = tmp_path / "home-myudp-admin-live"
    documents_root.mkdir(parents=True, exist_ok=True)
    home_root.mkdir(parents=True, exist_ok=True)

    with monkeypatch.context() as local_mp:
        local_mp.setenv("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", str(documents_root))
        local_mp.setenv("HOME", str(home_root))

        ios_app, ipserver_extension, ipserver_runtime = _reload_extension_modules(documents_root, home_root)

        async def scenario() -> None:
            myudp_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=60, base=IOS_E2E_UDP_PORT_BASE)
            swift_bind_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=61, base=IOS_E2E_UDP_PORT_BASE)
            swift_peer_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=62, base=IOS_E2E_UDP_PORT_BASE)
            server_admin_port = _alloc_local_port(socket.SOCK_STREAM, case_index=63, base=IOS_E2E_TCP_PORT_BASE + 1000)
            extension_admin_port = _alloc_local_port(socket.SOCK_STREAM, case_index=64, base=IOS_E2E_TCP_PORT_BASE + 1200)

            bridge_server = ObstacleBridgeClient(
                _myudp_secure_link_compress_server_config(myudp_port, admin_port=server_admin_port)
            )
            provider_configuration = _build_myudp_extension_provider_configuration(
                myudp_port=myudp_port,
                swift_bind_port=swift_bind_port,
                swift_peer_port=swift_peer_port,
                own_servers=[],
                remote_servers=[],
                admin_web=True,
                admin_web_bind="127.0.0.1",
                admin_web_port=extension_admin_port,
                admin_web_auth_disable=True,
                tunnel_address="192.168.106.26",
                included_routes=["192.168.106.24/30"],
                profile_id="ios-extension-shim-myudp-admin-live",
                display_name="iOS Extension Shim myUDP Admin Live",
            )
            start_result: dict[str, object] | None = None
            stop_result: dict[str, object] | None = None
            live_socket: socket.socket | None = None
            try:
                await bridge_server.start()
                start_result = ipserver_extension.handle_message(
                    {"command": "start_embedded_webadmin", "provider_configuration": provider_configuration}
                )
                assert start_result["ok"] is True, start_result

                await _wait_client_peer_secure_link_state(
                    bridge_server,
                    transport="myudp",
                    expected_state="authenticated",
                    authenticated=True,
                    timeout=12.0,
                )
                await _wait_tcp_listener_ready("127.0.0.1", extension_admin_port)

                status = _http_request_json(f"http://127.0.0.1:{extension_admin_port}/api/status")
                meta = _http_request_json(f"http://127.0.0.1:{extension_admin_port}/api/meta")
                config = _http_request_json(f"http://127.0.0.1:{extension_admin_port}/api/config")
                auth_state = _http_request_json(f"http://127.0.0.1:{extension_admin_port}/api/auth/state")
                root_code, root_html = _fetch_text(f"http://127.0.0.1:{extension_admin_port}/")

                assert "admin_ui" in status
                assert "build" in status
                assert "uptime_sec" in status
                assert meta["overlay_transport"] == "myudp"
                assert config["ok"] is True
                assert auth_state["ok"] is True
                assert auth_state["auth_required"] is False
                assert root_code == 200
                assert "ObstacleBridge" in root_html or "Admin Web" in root_html
                _wait_admin_peer_secure_link_state(
                    extension_admin_port,
                    transport="myudp",
                    expected_state="authenticated",
                    authenticated=True,
                    timeout=12.0,
                )
                uptime_before = int(status.get("uptime_sec") or 0)
                if uptime_before < 1:
                    await asyncio.sleep(1.2)
                    status = _http_request_json(f"http://127.0.0.1:{extension_admin_port}/api/status")
                    uptime_before = int(status.get("uptime_sec") or 0)

                live_socket = _websocket_connect("127.0.0.1", extension_admin_port)
                first_live = _recv_initial_live_ws_message(live_socket)
                assert first_live["type"] in {"hello", "status", "connections", "peers", "meta"}
                _send_ws_json(live_socket, {"request": ["status", "connections", "peers"]})
                live_status = _wait_ws_message(live_socket, lambda message: message.get("type") == "status")
                live_connections = _wait_ws_message(live_socket, lambda message: message.get("type") == "connections")
                live_peers = _wait_ws_message(live_socket, lambda message: message.get("type") == "peers")
                assert "admin_ui" in live_status["data"]
                assert "counts" in live_connections["data"]
                assert "peers" in live_peers["data"]

                restart = _http_request_json(
                    f"http://127.0.0.1:{extension_admin_port}/api/restart",
                    method="POST",
                    payload={},
                )
                assert restart["ok"] is True
                assert restart["restarting"] is True
                assert restart["restart_mode"] in {"immediate", "delayed"}

                status_after = _http_request_json(f"http://127.0.0.1:{extension_admin_port}/api/status")
                assert "admin_ui" in status_after

                live_socket.close()
                live_socket = None
                stop_result = ipserver_extension.handle_message({"command": "disconnect_profile"})
                assert stop_result["ok"] is True, stop_result
                ipserver_extension._CONTROLLER = None

                restart_start_result = ipserver_extension.handle_message(
                    {"command": "start_embedded_webadmin", "provider_configuration": provider_configuration}
                )
                assert restart_start_result["ok"] is True, restart_start_result
                await _wait_client_peer_secure_link_state(
                    bridge_server,
                    transport="myudp",
                    expected_state="authenticated",
                    authenticated=True,
                    timeout=12.0,
                )
                await _wait_tcp_listener_ready("127.0.0.1", extension_admin_port)
                restarted_status = _http_request_json(f"http://127.0.0.1:{extension_admin_port}/api/status")
                assert "admin_ui" in restarted_status
                assert int(restarted_status.get("uptime_sec") or 0) <= uptime_before
            finally:
                if live_socket is not None:
                    live_socket.close()
                if ipserver_extension._CONTROLLER is not None:
                    stop_result = ipserver_extension.handle_message({"command": "disconnect_profile"})
                    ipserver_extension._CONTROLLER = None
                with contextlib.suppress(asyncio.CancelledError):
                    await bridge_server.stop()

            assert stop_result is not None
            assert stop_result["ok"] is True, stop_result

        asyncio.run(scenario())

    monkeypatch.setenv("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", str(documents_root))
    monkeypatch.setenv("HOME", str(home_root))
    importlib.reload(ios_app)
    importlib.reload(ipserver_runtime)
    importlib.reload(ipserver_extension)


@pytest.mark.integration
@pytest.mark.ios
def test_ios_extension_shim_swift_udp_ws_secure_link_admin_web_live_ws(
    tmp_path: Path,
    monkeypatch,
) -> None:
    documents_root = tmp_path / "ios-documents-ws-admin-live"
    home_root = tmp_path / "home-ws-admin-live"
    documents_root.mkdir(parents=True, exist_ok=True)
    home_root.mkdir(parents=True, exist_ok=True)

    with monkeypatch.context() as local_mp:
        local_mp.setenv("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", str(documents_root))
        local_mp.setenv("HOME", str(home_root))

        ios_app, ipserver_extension, ipserver_runtime = _reload_extension_modules(documents_root, home_root)

        async def scenario() -> None:
            ws_port = _alloc_local_port(socket.SOCK_STREAM, case_index=70, base=IOS_E2E_TCP_PORT_BASE)
            extension_admin_port = _alloc_local_port(socket.SOCK_STREAM, case_index=71, base=IOS_E2E_TCP_PORT_BASE + 1200)
            swift_bind_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=72, base=IOS_E2E_UDP_PORT_BASE)
            swift_peer_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=73, base=IOS_E2E_UDP_PORT_BASE)
            bridge_server_config = _ws_secure_link_server_config(ws_port, case_index=74)
            bridge_server_config["admin_web_port"] = _alloc_local_port(socket.SOCK_STREAM, case_index=75, base=IOS_E2E_TCP_PORT_BASE + 1000)

            bridge_server = ObstacleBridgeClient(bridge_server_config)
            provider_configuration = provider_configuration_from_m3_config(
                M3TunnelConfig(
                    profile_id="ios-extension-shim-ws-admin-live",
                    display_name="iOS Extension Shim WS Admin Live",
                    provider_bundle_identifier="com.obstaclebridge.ObstacleBridge.PacketTunnel",
                    transport="ws",
                    peer_host="127.0.0.1",
                    peer_port=ws_port,
                    server_address=f"127.0.0.1:{ws_port}",
                    runtime_config={
                        "overlay_transport": "ws",
                        "ws_peer": "127.0.0.1",
                        "ws_peer_port": ws_port,
                        "ws_bind": "127.0.0.1",
                        "ws_own_port": 0,
                        "secure_link": True,
                        "secure_link_mode": "psk",
                            "secure_link_psk": "ios-e2e-secure-link-psk",
                        "channel_mux": {"own_servers": [], "remote_servers": []},
                        "iOS_TUN_connector": {
                            "packetflow_connector": "swift_udp",
                            "bind_host": "127.0.0.1",
                            "bind_port": swift_bind_port,
                            "peer_host": "127.0.0.1",
                            "peer_port": swift_peer_port,
                            "ifname": "ios-utun",
                            "mtu": 1400,
                        },
                        "admin_web": True,
                        "admin_web_bind": "127.0.0.1",
                        "admin_web_port": extension_admin_port,
                        "admin_web_auth_disable": True,
                    },
                    network=M3NetworkSettings(
                        tunnel_address="192.168.106.30",
                        tunnel_prefix=30,
                        included_routes=["192.168.106.28/30"],
                        excluded_routes=[],
                        dns_servers=["1.1.1.1"],
                        mtu=1400,
                    ),
                )
            )
            start_result: dict[str, object] | None = None
            stop_result: dict[str, object] | None = None
            live_socket: socket.socket | None = None
            try:
                await bridge_server.start()
                start_result = ipserver_extension.handle_message(
                    {"command": "start_embedded_webadmin", "provider_configuration": provider_configuration}
                )
                assert start_result["ok"] is True, start_result

                await _wait_client_peer_secure_link_state(
                    bridge_server,
                    transport="ws",
                    expected_state="authenticated",
                    authenticated=True,
                    timeout=12.0,
                )
                await _wait_tcp_listener_ready("127.0.0.1", extension_admin_port)

                status = _http_request_json(f"http://127.0.0.1:{extension_admin_port}/api/status")
                meta = _http_request_json(f"http://127.0.0.1:{extension_admin_port}/api/meta")
                assert "admin_ui" in status
                assert meta["overlay_transport"] == "ws"
                _wait_admin_peer_secure_link_state(
                    extension_admin_port,
                    transport="ws",
                    expected_state="authenticated",
                    authenticated=True,
                    timeout=12.0,
                )

                live_socket = _websocket_connect("127.0.0.1", extension_admin_port)
                first_live = _recv_initial_live_ws_message(live_socket)
                assert first_live["type"] in {"hello", "status", "connections", "peers", "meta"}
                _send_ws_json(live_socket, {"request": ["status", "peers"]})
                live_status = _wait_ws_message(live_socket, lambda message: message.get("type") == "status")
                live_peers = _wait_ws_message(live_socket, lambda message: message.get("type") == "peers")
                assert "admin_ui" in live_status["data"]
                assert "peers" in live_peers["data"]
            finally:
                if live_socket is not None:
                    live_socket.close()
                if ipserver_extension._CONTROLLER is not None:
                    stop_result = ipserver_extension.handle_message({"command": "disconnect_profile"})
                    ipserver_extension._CONTROLLER = None
                with contextlib.suppress(asyncio.CancelledError):
                    await bridge_server.stop()

            assert stop_result is not None
            assert stop_result["ok"] is True, stop_result

        asyncio.run(scenario())

    monkeypatch.setenv("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", str(documents_root))
    monkeypatch.setenv("HOME", str(home_root))
    importlib.reload(ios_app)
    importlib.reload(ipserver_runtime)
    importlib.reload(ipserver_extension)


@pytest.mark.integration
@pytest.mark.ios
def test_ios_extension_shim_swift_udp_quic_secure_link_remote_tcp_server_reaches_extension_admin_web(
    tmp_path: Path,
    monkeypatch,
) -> None:
    documents_root = tmp_path / "ios-documents-quic-remote-tcp"
    home_root = tmp_path / "home-quic-remote-tcp"
    documents_root.mkdir(parents=True, exist_ok=True)
    home_root.mkdir(parents=True, exist_ok=True)
    cert_dir = materialize_localhost_tls_fixture_set(tmp_path / "quic-localhost-fixtures")

    with monkeypatch.context() as local_mp:
        local_mp.setenv("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", str(documents_root))
        local_mp.setenv("HOME", str(home_root))

        ios_app, ipserver_extension, ipserver_runtime = _reload_extension_modules(documents_root, home_root)

        async def scenario() -> None:
            quic_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=90, base=IOS_E2E_UDP_PORT_BASE)
            swift_bind_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=91, base=IOS_E2E_UDP_PORT_BASE)
            swift_peer_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=92, base=IOS_E2E_UDP_PORT_BASE)
            server_admin_port = _alloc_local_port(socket.SOCK_STREAM, case_index=93, base=IOS_E2E_TCP_PORT_BASE + 1000)
            extension_admin_port = _alloc_local_port(socket.SOCK_STREAM, case_index=94, base=IOS_E2E_TCP_PORT_BASE + 1200)
            remote_tcp_port = _alloc_local_port(socket.SOCK_STREAM, case_index=95, base=IOS_E2E_TCP_PORT_BASE + 200)
            remote_servers = [
                {
                    "name": "quic-remote-admin-http",
                    "listen": {"bind": "127.0.0.1", "port": remote_tcp_port, "protocol": "tcp"},
                    "target": {"host": "127.0.0.1", "port": extension_admin_port, "protocol": "tcp"},
                }
            ]

            bridge_server_config = _quic_secure_link_server_config(quic_port, case_index=96, cert_dir=cert_dir)
            bridge_server_config["admin_web_port"] = server_admin_port
            bridge_server = ObstacleBridgeClient(bridge_server_config)
            provider_configuration = provider_configuration_from_m3_config(
                M3TunnelConfig(
                    profile_id="ios-extension-shim-quic-remote-tcp-e2e",
                    display_name="iOS Extension Shim QUIC Remote TCP E2E",
                    provider_bundle_identifier="com.obstaclebridge.ObstacleBridge.PacketTunnel",
                    transport="quic",
                    peer_host="127.0.0.1",
                    peer_port=quic_port,
                    server_address=f"127.0.0.1:{quic_port}",
                    runtime_config={
                        "overlay_transport": "quic",
                        "quic_peer": "127.0.0.1",
                        "quic_peer_port": quic_port,
                        "quic_bind": "127.0.0.1",
                        "quic_own_port": 0,
                        "quic_insecure": True,
                        "quic_alpn": "hq-29",
                        "secure_link": True,
                        "secure_link_mode": "psk",
                        "secure_link_psk": "ios-e2e-secure-link-psk",
                        "compress_layer": True,
                        "compress_layer_algo": "zlib",
                        "compress_layer_level": 3,
                        "compress_layer_min_bytes": 64,
                        "compress_layer_types": "data,data_frag",
                        "remote_servers": remote_servers,
                        "channel_mux": {
                            "own_servers": [],
                            "remote_servers": remote_servers,
                        },
                        "iOS_TUN_connector": {
                            "packetflow_connector": "swift_udp",
                            "bind_host": "127.0.0.1",
                            "bind_port": swift_bind_port,
                            "peer_host": "127.0.0.1",
                            "peer_port": swift_peer_port,
                            "ifname": "ios-utun",
                            "mtu": 1400,
                        },
                        "admin_web": True,
                        "admin_web_bind": "127.0.0.1",
                        "admin_web_port": extension_admin_port,
                        "admin_web_auth_disable": True,
                        "status": False,
                    },
                    network=M3NetworkSettings(
                        tunnel_address="192.168.106.34",
                        tunnel_prefix=30,
                        included_routes=["192.168.106.32/30"],
                        excluded_routes=[],
                        dns_servers=["1.1.1.1"],
                        mtu=1400,
                    ),
                )
            )
            start_result: dict[str, object] | None = None
            stop_result: dict[str, object] | None = None
            try:
                await bridge_server.start()
                start_result = ipserver_extension.handle_message(
                    {
                        "command": "start_embedded_webadmin",
                        "provider_configuration": provider_configuration,
                    }
                )
                assert start_result["ok"] is True, start_result

                await _wait_client_peer_secure_link_state(
                    bridge_server,
                    transport="quic",
                    expected_state="authenticated",
                    authenticated=True,
                    timeout=16.0,
                )
                await _wait_tcp_listener_ready("127.0.0.1", remote_tcp_port)

                status_code, status_text = await _probe_http_get("127.0.0.1", remote_tcp_port, "/api/status")
                assert status_code == 200
                status_doc = json.loads(status_text)
                assert "admin_ui" in status_doc or "build" in status_doc, status_doc

                root_code, root_html = await _probe_http_get("127.0.0.1", remote_tcp_port, "/")
                assert root_code == 200
                assert "ObstacleBridge" in root_html or "Admin Web" in root_html

                burst_results = await asyncio.gather(
                    _probe_http_get("127.0.0.1", remote_tcp_port, "/api/status"),
                    _probe_http_get("127.0.0.1", remote_tcp_port, "/api/meta"),
                    _probe_http_get("127.0.0.1", remote_tcp_port, "/api/connections"),
                    _probe_http_get("127.0.0.1", remote_tcp_port, "/api/peers"),
                    _probe_http_get("127.0.0.1", remote_tcp_port, "/"),
                )
                for path, (code, text) in zip(
                    ["/api/status", "/api/meta", "/api/connections", "/api/peers", "/"],
                    burst_results,
                    strict=False,
                ):
                    assert code == 200, (path, code, text)
            finally:
                if ipserver_extension._CONTROLLER is not None:
                    stop_result = ipserver_extension.handle_message({"command": "disconnect_profile"})
                    ipserver_extension._CONTROLLER = None
                with contextlib.suppress(asyncio.CancelledError):
                    await bridge_server.stop()

            assert stop_result is not None
            assert stop_result["ok"] is True, stop_result

        asyncio.run(scenario())

    monkeypatch.setenv("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", str(documents_root))
    monkeypatch.setenv("HOME", str(home_root))
    importlib.reload(ios_app)
    importlib.reload(ipserver_runtime)
    importlib.reload(ipserver_extension)


@pytest.mark.integration
@pytest.mark.ios
def test_ios_extension_shim_swift_udp_quic_secure_link_admin_web_live_ws(
    tmp_path: Path,
    monkeypatch,
) -> None:
    documents_root = tmp_path / "ios-documents-quic-admin-live"
    home_root = tmp_path / "home-quic-admin-live"
    documents_root.mkdir(parents=True, exist_ok=True)
    home_root.mkdir(parents=True, exist_ok=True)
    cert_dir = materialize_localhost_tls_fixture_set(tmp_path / "quic-live-localhost-fixtures")

    with monkeypatch.context() as local_mp:
        local_mp.setenv("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", str(documents_root))
        local_mp.setenv("HOME", str(home_root))

        ios_app, ipserver_extension, ipserver_runtime = _reload_extension_modules(documents_root, home_root)

        async def scenario() -> None:
            quic_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=100, base=IOS_E2E_UDP_PORT_BASE)
            extension_admin_port = _alloc_local_port(socket.SOCK_STREAM, case_index=101, base=IOS_E2E_TCP_PORT_BASE + 1200)
            swift_bind_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=102, base=IOS_E2E_UDP_PORT_BASE)
            swift_peer_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=103, base=IOS_E2E_UDP_PORT_BASE)
            bridge_server_config = _quic_secure_link_server_config(quic_port, case_index=104, cert_dir=cert_dir)
            bridge_server_config["admin_web_port"] = _alloc_local_port(socket.SOCK_STREAM, case_index=105, base=IOS_E2E_TCP_PORT_BASE + 1000)

            bridge_server = ObstacleBridgeClient(bridge_server_config)
            provider_configuration = provider_configuration_from_m3_config(
                M3TunnelConfig(
                    profile_id="ios-extension-shim-quic-admin-live",
                    display_name="iOS Extension Shim QUIC Admin Live",
                    provider_bundle_identifier="com.obstaclebridge.ObstacleBridge.PacketTunnel",
                    transport="quic",
                    peer_host="127.0.0.1",
                    peer_port=quic_port,
                    server_address=f"127.0.0.1:{quic_port}",
                    runtime_config={
                        "overlay_transport": "quic",
                        "quic_peer": "127.0.0.1",
                        "quic_peer_port": quic_port,
                        "quic_bind": "127.0.0.1",
                        "quic_own_port": 0,
                        "quic_insecure": True,
                        "quic_alpn": "hq-29",
                        "secure_link": True,
                        "secure_link_mode": "psk",
                        "secure_link_psk": "ios-e2e-secure-link-psk",
                        "channel_mux": {"own_servers": [], "remote_servers": []},
                        "iOS_TUN_connector": {
                            "packetflow_connector": "swift_udp",
                            "bind_host": "127.0.0.1",
                            "bind_port": swift_bind_port,
                            "peer_host": "127.0.0.1",
                            "peer_port": swift_peer_port,
                            "ifname": "ios-utun",
                            "mtu": 1400,
                        },
                        "admin_web": True,
                        "admin_web_bind": "127.0.0.1",
                        "admin_web_port": extension_admin_port,
                        "admin_web_auth_disable": True,
                    },
                    network=M3NetworkSettings(
                        tunnel_address="192.168.106.38",
                        tunnel_prefix=30,
                        included_routes=["192.168.106.36/30"],
                        excluded_routes=[],
                        dns_servers=["1.1.1.1"],
                        mtu=1400,
                    ),
                )
            )
            start_result: dict[str, object] | None = None
            stop_result: dict[str, object] | None = None
            live_socket: socket.socket | None = None
            try:
                await bridge_server.start()
                start_result = ipserver_extension.handle_message(
                    {"command": "start_embedded_webadmin", "provider_configuration": provider_configuration}
                )
                assert start_result["ok"] is True, start_result

                await _wait_client_peer_secure_link_state(
                    bridge_server,
                    transport="quic",
                    expected_state="authenticated",
                    authenticated=True,
                    timeout=16.0,
                )
                await _wait_tcp_listener_ready("127.0.0.1", extension_admin_port)

                status = _http_request_json(f"http://127.0.0.1:{extension_admin_port}/api/status")
                meta = _http_request_json(f"http://127.0.0.1:{extension_admin_port}/api/meta")
                assert "admin_ui" in status
                assert meta["overlay_transport"] == "quic"
                _wait_admin_peer_secure_link_state(
                    extension_admin_port,
                    transport="quic",
                    expected_state="authenticated",
                    authenticated=True,
                    timeout=16.0,
                )

                live_socket = _websocket_connect("127.0.0.1", extension_admin_port)
                first_live = _recv_initial_live_ws_message(live_socket)
                assert first_live["type"] in {"hello", "status", "connections", "peers", "meta"}
                _send_ws_json(live_socket, {"request": ["status", "peers"]})
                live_status = _wait_ws_message(live_socket, lambda message: message.get("type") == "status")
                live_peers = _wait_ws_message(live_socket, lambda message: message.get("type") == "peers")
                assert "admin_ui" in live_status["data"]
                assert "peers" in live_peers["data"]
            finally:
                if live_socket is not None:
                    live_socket.close()
                if ipserver_extension._CONTROLLER is not None:
                    stop_result = ipserver_extension.handle_message({"command": "disconnect_profile"})
                    ipserver_extension._CONTROLLER = None
                with contextlib.suppress(asyncio.CancelledError):
                    await bridge_server.stop()

            assert stop_result is not None
            assert stop_result["ok"] is True, stop_result

        asyncio.run(scenario())

    monkeypatch.setenv("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", str(documents_root))
    monkeypatch.setenv("HOME", str(home_root))
    importlib.reload(ios_app)
    importlib.reload(ipserver_runtime)
    importlib.reload(ipserver_extension)


@pytest.mark.integration
@pytest.mark.ios
def test_ios_extension_shim_swift_udp_myudp_secure_link_compress_concurrent_tcp_reaches_python_peer(
    tmp_path: Path,
    monkeypatch,
) -> None:
    documents_root = tmp_path / "ios-documents-myudp"
    home_root = tmp_path / "home-myudp"
    documents_root.mkdir(parents=True, exist_ok=True)
    home_root.mkdir(parents=True, exist_ok=True)

    with monkeypatch.context() as local_mp:
        local_mp.setenv("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", str(documents_root))
        local_mp.setenv("HOME", str(home_root))

        ios_app, ipserver_extension, ipserver_runtime = _reload_extension_modules(documents_root, home_root)

        async def scenario() -> None:
            myudp_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=8, base=IOS_E2E_UDP_PORT_BASE)
            swift_bind_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=9, base=IOS_E2E_UDP_PORT_BASE)
            swift_peer_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=10, base=IOS_E2E_UDP_PORT_BASE)
            admin_port = _alloc_local_port(socket.SOCK_STREAM, case_index=11, base=IOS_E2E_TCP_PORT_BASE + 1000)
            local_tcp_port = _alloc_local_port(socket.SOCK_STREAM, case_index=12, base=IOS_E2E_TCP_PORT_BASE)
            target_tcp_port = _alloc_local_port(socket.SOCK_STREAM, case_index=13, base=IOS_E2E_TCP_PORT_BASE)
            own_servers = [
                {
                    "name": "tcp-echo",
                    "listen": {"bind": "127.0.0.1", "port": local_tcp_port, "protocol": "tcp"},
                    "target": {"host": "127.0.0.1", "port": target_tcp_port, "protocol": "tcp"},
                },
                {
                    "name": "tun",
                    "listen": {"ifname": "ios-utun", "mtu": 1400, "protocol": "tun"},
                    "target": {"ifname": "obtun2", "mtu": 1400, "protocol": "tun"},
                },
            ]
            payloads = [
                b"\x01alpha-ios-ext\n",
                b"\x01bravo-ios-ext" * 8 + b"\n",
                b"\x01charlie-ios-ext" * 16 + b"\n",
                b"\x01delta-ios-ext" * 24 + b"\n",
                b"\x01echo-ios-ext" * 32 + b"\n",
            ]

            tcp_server, tcp_received = await _start_tcp_line_bounce_server("127.0.0.1", target_tcp_port)
            bridge_server = ObstacleBridgeClient(
                _myudp_secure_link_compress_server_config(myudp_port, admin_port=admin_port)
            )
            provider_configuration = _build_myudp_extension_provider_configuration(
                myudp_port=myudp_port,
                swift_bind_port=swift_bind_port,
                swift_peer_port=swift_peer_port,
                own_servers=own_servers,
                tunnel_address="192.168.106.6",
                included_routes=["192.168.106.4/30"],
                profile_id="ios-extension-shim-myudp-e2e",
                display_name="iOS Extension Shim myUDP E2E",
            )
            start_result: dict[str, object] | None = None
            stop_result: dict[str, object] | None = None
            results: list[bytes | None] = [None] * len(payloads)
            try:
                await bridge_server.start()
                start_result = ipserver_extension.handle_message(
                    {
                        "command": "start_embedded_webadmin",
                        "provider_configuration": provider_configuration,
                    }
                )
                assert start_result["ok"] is True, start_result
                snapshot = start_result["result"]
                assert isinstance(snapshot, dict)
                assert snapshot["config"]["overlay_transport"] == "myudp"
                assert snapshot["config"]["secure_link"] is True
                assert snapshot["config"]["compress_layer"] is True
                assert os.environ.get("OBSTACLEBRIDGE_IOS_PACKETFLOW_CONNECTOR") == "swift_udp"
                await _wait_extension_listener_count(
                    lambda: ipserver_extension.handle_message({"command": "snapshot"})["result"],
                    protocol="tcp",
                    minimum_count=1,
                    timeout=12.0,
                )
                await _wait_tcp_listener_ready("127.0.0.1", local_tcp_port)

                async def _probe_one(index: int, payload: bytes) -> bytes:
                    await asyncio.sleep(0.05 * index)
                    return await _probe_tcp_line_roundtrip("127.0.0.1", local_tcp_port, payload, attempts=80)

                gathered = await asyncio.gather(
                    *[_probe_one(index, payload) for index, payload in enumerate(payloads)],
                    return_exceptions=True,
                )
                errors = [
                    (index, result)
                    for index, result in enumerate(gathered)
                    if isinstance(result, BaseException)
                ]
                assert not errors, errors
                for index, result in enumerate(gathered):
                    if not isinstance(result, BaseException):
                        results[index] = result

                assert tcp_received == payloads
                for index, payload in enumerate(payloads):
                    assert results[index] == bytes([0x02]) + payload[1:]

                await _wait_client_peer_secure_link_state(
                    bridge_server,
                    transport="myudp",
                    expected_state="authenticated",
                    authenticated=True,
                    timeout=12.0,
                )
                await _wait_client_compress_layer_stats(
                    bridge_server,
                    minimum_applied_total=1,
                    timeout=12.0,
                )
                snapshot_result = ipserver_extension.handle_message({"command": "snapshot"})
                assert snapshot_result["ok"] is True, snapshot_result
                runtime_snapshot = snapshot_result["result"]
                assert isinstance(runtime_snapshot, dict)
                assert runtime_snapshot["started"] is True
            finally:
                if ipserver_extension._CONTROLLER is not None:
                    stop_result = ipserver_extension.handle_message({"command": "disconnect_profile"})
                    ipserver_extension._CONTROLLER = None
                with contextlib.suppress(asyncio.CancelledError):
                    await bridge_server.stop()
                tcp_server.close()
                await tcp_server.wait_closed()

            assert stop_result is not None
            assert stop_result["ok"] is True, stop_result

        asyncio.run(scenario())

    monkeypatch.setenv("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", str(documents_root))
    monkeypatch.setenv("HOME", str(home_root))
    importlib.reload(ios_app)
    importlib.reload(ipserver_runtime)
    importlib.reload(ipserver_extension)


@pytest.mark.integration
@pytest.mark.ios
def test_ios_extension_shim_swift_udp_myudp_secure_link_tcp_own_server_reaches_python_admin_web(
    tmp_path: Path,
    monkeypatch,
) -> None:
    documents_root = tmp_path / "ios-documents-myudp-admin"
    home_root = tmp_path / "home-myudp-admin"
    documents_root.mkdir(parents=True, exist_ok=True)
    home_root.mkdir(parents=True, exist_ok=True)

    with monkeypatch.context() as local_mp:
        local_mp.setenv("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", str(documents_root))
        local_mp.setenv("HOME", str(home_root))

        ios_app, ipserver_extension, ipserver_runtime = _reload_extension_modules(documents_root, home_root)

        async def scenario() -> None:
            myudp_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=20, base=IOS_E2E_UDP_PORT_BASE)
            swift_bind_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=21, base=IOS_E2E_UDP_PORT_BASE)
            swift_peer_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=22, base=IOS_E2E_UDP_PORT_BASE)
            admin_port = _alloc_local_port(socket.SOCK_STREAM, case_index=23, base=IOS_E2E_TCP_PORT_BASE + 1000)
            local_http_port = _alloc_local_port(socket.SOCK_STREAM, case_index=24, base=IOS_E2E_TCP_PORT_BASE)
            own_servers = [
                {
                    "name": "remote-admin-http",
                    "listen": {"bind": "127.0.0.1", "port": local_http_port, "protocol": "tcp"},
                    "target": {"host": "127.0.0.1", "port": admin_port, "protocol": "tcp"},
                },
                {
                    "name": "tun",
                    "listen": {"ifname": "ios-utun", "mtu": 1400, "protocol": "tun"},
                    "target": {"ifname": "obtun2", "mtu": 1400, "protocol": "tun"},
                },
            ]

            bridge_server = ObstacleBridgeClient(
                _myudp_secure_link_compress_server_config(myudp_port, admin_port=admin_port)
            )
            provider_configuration = _build_myudp_extension_provider_configuration(
                myudp_port=myudp_port,
                swift_bind_port=swift_bind_port,
                swift_peer_port=swift_peer_port,
                own_servers=own_servers,
                tunnel_address="192.168.106.14",
                included_routes=["192.168.106.12/30"],
                profile_id="ios-extension-shim-myudp-admin-e2e",
                display_name="iOS Extension Shim myUDP Admin E2E",
            )
            start_result: dict[str, object] | None = None
            stop_result: dict[str, object] | None = None
            try:
                await bridge_server.start()
                start_result = ipserver_extension.handle_message(
                    {
                        "command": "start_embedded_webadmin",
                        "provider_configuration": provider_configuration,
                    }
                )
                assert start_result["ok"] is True, start_result
                await _wait_extension_listener_count(
                    lambda: ipserver_extension.handle_message({"command": "snapshot"})["result"],
                    protocol="tcp",
                    minimum_count=1,
                    timeout=12.0,
                )
                await _wait_tcp_listener_ready("127.0.0.1", local_http_port)

                await _wait_client_peer_secure_link_state(
                    bridge_server,
                    transport="myudp",
                    expected_state="authenticated",
                    authenticated=True,
                    timeout=12.0,
                )

                status_code, status_text = await _probe_http_get("127.0.0.1", local_http_port, "/api/status")
                assert status_code == 200
                status_doc = json.loads(status_text)
                assert "admin_ui" in status_doc or "build" in status_doc, status_doc

                root_code, root_html = await _probe_http_get("127.0.0.1", local_http_port, "/")
                assert root_code == 200
                assert "ObstacleBridge" in root_html or "Admin Web" in root_html

                await _wait_client_peer_secure_link_state(
                    bridge_server,
                    transport="myudp",
                    expected_state="authenticated",
                    authenticated=True,
                    timeout=6.0,
                )
            finally:
                if ipserver_extension._CONTROLLER is not None:
                    stop_result = ipserver_extension.handle_message({"command": "disconnect_profile"})
                    ipserver_extension._CONTROLLER = None
                with contextlib.suppress(asyncio.CancelledError):
                    await bridge_server.stop()

            assert stop_result is not None
            assert stop_result["ok"] is True, stop_result

        asyncio.run(scenario())

    monkeypatch.setenv("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", str(documents_root))
    monkeypatch.setenv("HOME", str(home_root))
    importlib.reload(ios_app)
    importlib.reload(ipserver_runtime)
    importlib.reload(ipserver_extension)


@pytest.mark.integration
@pytest.mark.ios
def test_ios_extension_shim_swift_udp_myudp_secure_link_compress_udp_own_server_reaches_python_peer(
    tmp_path: Path,
    monkeypatch,
) -> None:
    documents_root = tmp_path / "ios-documents-myudp-udp"
    home_root = tmp_path / "home-myudp-udp"
    documents_root.mkdir(parents=True, exist_ok=True)
    home_root.mkdir(parents=True, exist_ok=True)

    with monkeypatch.context() as local_mp:
        local_mp.setenv("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", str(documents_root))
        local_mp.setenv("HOME", str(home_root))

        ios_app, ipserver_extension, ipserver_runtime = _reload_extension_modules(documents_root, home_root)

        async def scenario() -> None:
            myudp_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=14, base=IOS_E2E_UDP_PORT_BASE)
            swift_bind_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=15, base=IOS_E2E_UDP_PORT_BASE)
            swift_peer_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=16, base=IOS_E2E_UDP_PORT_BASE)
            admin_port = _alloc_local_port(socket.SOCK_STREAM, case_index=17, base=IOS_E2E_TCP_PORT_BASE + 1000)
            local_udp_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=18, base=IOS_E2E_UDP_PORT_BASE)
            target_udp_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=19, base=IOS_E2E_UDP_PORT_BASE)
            own_servers = [
                {
                    "name": "udp-echo",
                    "listen": {"bind": "127.0.0.1", "port": local_udp_port, "protocol": "udp"},
                    "target": {"host": "127.0.0.1", "port": target_udp_port, "protocol": "udp"},
                },
                {
                    "name": "tun",
                    "listen": {"ifname": "ios-utun", "mtu": 1400, "protocol": "tun"},
                    "target": {"ifname": "obtun2", "mtu": 1400, "protocol": "tun"},
                },
            ]
            payloads = [
                b"\x01alpha-ios-ext-udp",
                b"\x01bravo-ios-ext-udp" * 8,
                b"\x01charlie-ios-ext-udp" * 16,
            ]

            udp_transport, udp_bounce = await _start_udp_bounce_server("127.0.0.1", target_udp_port)
            bridge_server = ObstacleBridgeClient(
                _myudp_secure_link_compress_server_config(myudp_port, admin_port=admin_port)
            )
            provider_configuration = _build_myudp_extension_provider_configuration(
                myudp_port=myudp_port,
                swift_bind_port=swift_bind_port,
                swift_peer_port=swift_peer_port,
                own_servers=own_servers,
                tunnel_address="192.168.106.10",
                included_routes=["192.168.106.8/30"],
                profile_id="ios-extension-shim-myudp-udp-e2e",
                display_name="iOS Extension Shim myUDP UDP E2E",
            )
            start_result: dict[str, object] | None = None
            stop_result: dict[str, object] | None = None
            try:
                await bridge_server.start()
                start_result = ipserver_extension.handle_message(
                    {
                        "command": "start_embedded_webadmin",
                        "provider_configuration": provider_configuration,
                    }
                )
                assert start_result["ok"] is True, start_result
                snapshot = start_result["result"]
                assert isinstance(snapshot, dict)
                assert snapshot["config"]["overlay_transport"] == "myudp"
                assert snapshot["config"]["secure_link"] is True
                assert snapshot["config"]["compress_layer"] is True
                assert os.environ.get("OBSTACLEBRIDGE_IOS_PACKETFLOW_CONNECTOR") == "swift_udp"
                await _wait_extension_listener_count(
                    lambda: ipserver_extension.handle_message({"command": "snapshot"})["result"],
                    protocol="udp",
                    minimum_count=1,
                    timeout=12.0,
                )

                responses = []
                for index, payload in enumerate(payloads):
                    await asyncio.sleep(0.05 * index)
                    responses.append(await _probe_udp_roundtrip("127.0.0.1", local_udp_port, payload, attempts=80))

                assert udp_bounce.received == payloads
                for index, payload in enumerate(payloads):
                    assert responses[index] == bytes([0x02]) + payload[1:]

                await _wait_client_peer_secure_link_state(
                    bridge_server,
                    transport="myudp",
                    expected_state="authenticated",
                    authenticated=True,
                    timeout=12.0,
                )
                await _wait_client_compress_layer_stats(
                    bridge_server,
                    minimum_applied_total=1,
                    timeout=12.0,
                )
                snapshot_result = ipserver_extension.handle_message({"command": "snapshot"})
                assert snapshot_result["ok"] is True, snapshot_result
                runtime_snapshot = snapshot_result["result"]
                assert isinstance(runtime_snapshot, dict)
                assert runtime_snapshot["started"] is True
            finally:
                if ipserver_extension._CONTROLLER is not None:
                    stop_result = ipserver_extension.handle_message({"command": "disconnect_profile"})
                    ipserver_extension._CONTROLLER = None
                with contextlib.suppress(asyncio.CancelledError):
                    await bridge_server.stop()
                udp_transport.close()

            assert stop_result is not None
            assert stop_result["ok"] is True, stop_result

        asyncio.run(scenario())

    monkeypatch.setenv("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", str(documents_root))
    monkeypatch.setenv("HOME", str(home_root))
    importlib.reload(ios_app)
    importlib.reload(ipserver_runtime)
    importlib.reload(ipserver_extension)


@pytest.mark.integration
@pytest.mark.ios
def test_ios_extension_shim_swift_udp_myudp_secure_link_remote_tcp_server_reaches_extension_admin_web(
    tmp_path: Path,
    monkeypatch,
) -> None:
    documents_root = tmp_path / "ios-documents-myudp-remote-tcp"
    home_root = tmp_path / "home-myudp-remote-tcp"
    documents_root.mkdir(parents=True, exist_ok=True)
    home_root.mkdir(parents=True, exist_ok=True)

    with monkeypatch.context() as local_mp:
        local_mp.setenv("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", str(documents_root))
        local_mp.setenv("HOME", str(home_root))

        ios_app, ipserver_extension, ipserver_runtime = _reload_extension_modules(documents_root, home_root)

        async def scenario() -> None:
            myudp_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=30, base=IOS_E2E_UDP_PORT_BASE)
            swift_bind_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=31, base=IOS_E2E_UDP_PORT_BASE)
            swift_peer_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=32, base=IOS_E2E_UDP_PORT_BASE)
            server_admin_port = _alloc_local_port(socket.SOCK_STREAM, case_index=33, base=IOS_E2E_TCP_PORT_BASE + 1000)
            extension_admin_port = _alloc_local_port(socket.SOCK_STREAM, case_index=34, base=IOS_E2E_TCP_PORT_BASE + 1200)
            remote_tcp_port = _alloc_local_port(socket.SOCK_STREAM, case_index=35, base=IOS_E2E_TCP_PORT_BASE + 200)
            remote_servers = [
                {
                    "name": "remote-admin-http",
                    "listen": {"bind": "127.0.0.1", "port": remote_tcp_port, "protocol": "tcp"},
                    "target": {"host": "127.0.0.1", "port": extension_admin_port, "protocol": "tcp"},
                }
            ]

            bridge_server = ObstacleBridgeClient(
                _myudp_secure_link_compress_server_config(myudp_port, admin_port=server_admin_port)
            )
            provider_configuration = _build_myudp_extension_provider_configuration(
                myudp_port=myudp_port,
                swift_bind_port=swift_bind_port,
                swift_peer_port=swift_peer_port,
                own_servers=[],
                remote_servers=remote_servers,
                admin_web=True,
                admin_web_bind="127.0.0.1",
                admin_web_port=extension_admin_port,
                admin_web_auth_disable=True,
                tunnel_address="192.168.106.18",
                included_routes=["192.168.106.16/30"],
                profile_id="ios-extension-shim-myudp-remote-tcp-e2e",
                display_name="iOS Extension Shim myUDP Remote TCP E2E",
            )
            start_result: dict[str, object] | None = None
            stop_result: dict[str, object] | None = None
            try:
                await bridge_server.start()
                start_result = ipserver_extension.handle_message(
                    {
                        "command": "start_embedded_webadmin",
                        "provider_configuration": provider_configuration,
                    }
                )
                assert start_result["ok"] is True, start_result

                await _wait_client_peer_secure_link_state(
                    bridge_server,
                    transport="myudp",
                    expected_state="authenticated",
                    authenticated=True,
                    timeout=12.0,
                )
                await _wait_tcp_listener_ready("127.0.0.1", remote_tcp_port)

                status_code, status_text = await _probe_http_get("127.0.0.1", remote_tcp_port, "/api/status")
                assert status_code == 200
                status_doc = json.loads(status_text)
                assert "admin_ui" in status_doc or "build" in status_doc, status_doc

                root_code, root_html = await _probe_http_get("127.0.0.1", remote_tcp_port, "/")
                assert root_code == 200
                assert "ObstacleBridge" in root_html or "Admin Web" in root_html

                burst_results = await asyncio.gather(
                    _probe_http_get("127.0.0.1", remote_tcp_port, "/api/status"),
                    _probe_http_get("127.0.0.1", remote_tcp_port, "/api/meta"),
                    _probe_http_get("127.0.0.1", remote_tcp_port, "/api/connections"),
                    _probe_http_get("127.0.0.1", remote_tcp_port, "/api/peers"),
                    _probe_http_get("127.0.0.1", remote_tcp_port, "/"),
                    _probe_http_get("127.0.0.1", remote_tcp_port, "/api/status"),
                )
                for path, (code, text) in zip(
                    ["/api/status", "/api/meta", "/api/connections", "/api/peers", "/", "/api/status"],
                    burst_results,
                    strict=False,
                ):
                    assert code == 200, (path, code, text)
                burst_status = json.loads(burst_results[0][1])
                burst_meta = json.loads(burst_results[1][1])
                burst_connections = json.loads(burst_results[2][1])
                burst_peers = json.loads(burst_results[3][1])
                burst_root = burst_results[4][1]
                assert "admin_ui" in burst_status or "build" in burst_status, burst_status
                assert "build" in burst_meta or "admin_web_name" in burst_meta, burst_meta
                assert "counts" in burst_connections, burst_connections
                assert "peers" in burst_peers, burst_peers
                assert "ObstacleBridge" in burst_root or "Admin Web" in burst_root

                await _wait_client_peer_secure_link_state(
                    bridge_server,
                    transport="myudp",
                    expected_state="authenticated",
                    authenticated=True,
                    timeout=6.0,
                )
            finally:
                if ipserver_extension._CONTROLLER is not None:
                    stop_result = ipserver_extension.handle_message({"command": "disconnect_profile"})
                    ipserver_extension._CONTROLLER = None
                with contextlib.suppress(asyncio.CancelledError):
                    await bridge_server.stop()

            assert stop_result is not None
            assert stop_result["ok"] is True, stop_result

        asyncio.run(scenario())

    monkeypatch.setenv("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", str(documents_root))
    monkeypatch.setenv("HOME", str(home_root))
    importlib.reload(ios_app)
    importlib.reload(ipserver_runtime)
    importlib.reload(ipserver_extension)
