from __future__ import annotations

import asyncio
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
    tunnel_address: str,
    included_routes: list[str],
    profile_id: str,
    display_name: str,
) -> dict[str, Any]:
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
                "channel_mux": {
                    "own_servers": list(own_servers),
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
                tunnel_address=tunnel_address,
                tunnel_prefix=30,
                included_routes=list(included_routes),
                excluded_routes=[],
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
def test_ios_extension_shim_swift_udp_ws_tcp_service_reaches_host_peer_on_macos(tmp_path: Path, monkeypatch) -> None:
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
            ws_port = _alloc_local_port(socket.SOCK_STREAM, case_index=3, base=IOS_E2E_TCP_PORT_BASE)
            local_tcp_port = _alloc_local_port(socket.SOCK_STREAM, case_index=4, base=IOS_E2E_TCP_PORT_BASE)
            target_tcp_port = _alloc_local_port(socket.SOCK_STREAM, case_index=5, base=IOS_E2E_TCP_PORT_BASE)
            swift_bind_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=6, base=IOS_E2E_UDP_PORT_BASE)
            swift_peer_port = _alloc_local_port(socket.SOCK_DGRAM, case_index=7, base=IOS_E2E_UDP_PORT_BASE)
            probe_payload = b"\x01ios-extension-tcp\n"
            expected_response = b"\x02ios-extension-tcp\n"

            tcp_server, tcp_received = await _start_tcp_line_bounce_server("127.0.0.1", target_tcp_port)
            bridge_server = ObstacleBridgeClient(_ws_bridge_server_config(ws_port))
            provider_configuration = provider_configuration_from_m3_config(
                M3TunnelConfig(
                    profile_id="ios-extension-shim-e2e",
                    display_name="iOS Extension Shim E2E",
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
                assert config["overlay_transport"] == "ws"
                assert os.environ.get("OBSTACLEBRIDGE_IOS_PACKETFLOW_CONNECTOR") == "swift_udp"

                response = await _probe_tcp_line_roundtrip("127.0.0.1", local_tcp_port, probe_payload)
                assert response == expected_response
                assert tcp_received == [probe_payload]

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
