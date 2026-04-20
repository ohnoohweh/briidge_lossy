from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
NATIVE_DIR = ROOT / "ios" / "native" / "ObstacleBridgeTunnel"


def test_m3_native_packet_tunnel_provider_source_exists() -> None:
    provider = (NATIVE_DIR / "PacketTunnelProvider.swift").read_text(encoding="utf-8")

    assert "NEPacketTunnelProvider" in provider
    assert "NETunnelProviderProtocol" in provider
    assert "setTunnelNetworkSettings" in provider
    assert "handleAppMessage" in provider
    assert "obstaclebridge.ios.packet-tunnel.v1" in provider


def test_m3_native_packet_flow_bridge_reads_and_writes_packet_flow() -> None:
    bridge = (NATIVE_DIR / "PacketFlowBridge.swift").read_text(encoding="utf-8")

    assert "NEPacketTunnelFlow" in bridge
    assert "readPackets" in bridge
    assert "writePackets" in bridge
    assert "NWConnection" in bridge
    assert "UInt32(packet.count).bigEndian" in bridge
