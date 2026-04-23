from __future__ import annotations

import asyncio
import json
import socket
import sys
from pathlib import Path
from typing import Awaitable, Callable

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
from obstacle_bridge_ios.m3_tunnel import M3NetworkSettings, m3_vpn_profile_from_profile
from obstacle_bridge_ios_e2e.runner import run_ws_udp_echo_probe
from obstacle_bridge_ios_e2e.runner import run_ws_secure_link_probe


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


def _unused_port(kind: int) -> int:
    with socket.socket(socket.AF_INET, kind) as sock:
        if kind == socket.SOCK_STREAM:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


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
            tunnel_address="10.77.0.2",
            included_routes=["10.77.0.0/24"],
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


def _ws_bridge_server_config(ws_port: int) -> dict:
    return {
        "overlay_transport": "ws",
        "ws_bind": "127.0.0.1",
        "ws_own_port": int(ws_port),
        "secure_link_mode": "off",
        "admin_web": False,
        "status": False,
    }


def _ws_secure_link_server_config(ws_port: int) -> dict:
    return {
        "overlay_transport": "ws",
        "ws_bind": "127.0.0.1",
        "ws_own_port": int(ws_port),
        "secure_link": True,
        "secure_link_mode": "psk",
        "secure_link_psk": "ios-e2e-secure-link-psk",
        "admin_web": True,
        "admin_web_bind": "127.0.0.1",
        "admin_web_port": _unused_port(socket.SOCK_STREAM),
        "admin_web_auth_disable": True,
        "status": False,
    }


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
    assert restored["network_settings"]["tunnel_address"] == "10.77.0.2"
    assert restored["network_settings"]["included_routes"] == ["10.77.0.0/24"]
    assert restored["poc"]["secure_link"] == "deferred-to-M4"


@pytest.mark.integration
@pytest.mark.ios
def test_ios_e2e_app_ws_overlay_udp_service_reaches_linux_peer_udp_echo() -> None:
    async def scenario() -> None:
        ws_port = _unused_port(socket.SOCK_STREAM)
        local_udp_port = _unused_port(socket.SOCK_DGRAM)
        target_udp_port = _unused_port(socket.SOCK_DGRAM)

        udp_transport, udp_bounce = await _start_udp_bounce_server("127.0.0.1", target_udp_port)
        bridge_server = ObstacleBridgeClient(_ws_bridge_server_config(ws_port))
        try:
            await bridge_server.start()
            report = await run_ws_udp_echo_probe(
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
def test_ios_e2e_app_ws_secure_link_probe_authenticates_against_host_peer() -> None:
    async def scenario() -> None:
        ws_port = _unused_port(socket.SOCK_STREAM)
        bridge_server = ObstacleBridgeClient(_ws_secure_link_server_config(ws_port))
        try:
            await bridge_server.start()
            report = await run_ws_secure_link_probe(
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
