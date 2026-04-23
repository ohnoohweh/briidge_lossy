from __future__ import annotations

from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[2]
NATIVE_DIR = ROOT / "ios" / "native" / "ObstacleBridgeTunnel"
SHARED_NATIVE_DIR = ROOT / "ios" / "native" / "ObstacleBridgeShared"


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


def test_native_crypto_bridge_source_exists() -> None:
    bridge = (SHARED_NATIVE_DIR / "ObstacleBridgeNativeCrypto.swift").read_text(encoding="utf-8")

    assert "CryptoKit" in bridge
    assert "CommonCrypto" in bridge
    assert "@objc(ObstacleBridgeNativeCrypto)" in bridge
    assert "aesGCMEncryptKey" in bridge
    assert "chaCha20Poly1305EncryptKey" in bridge
    assert "generateEd25519PrivateKey" in bridge
    assert "generateX25519PrivateKey" in bridge
    assert "sealed.ciphertext + sealed.tag" in bridge


def test_ios_e2e_briefcase_config_includes_rubicon_for_native_crypto_bridge() -> None:
    pyproject = tomllib.loads((ROOT / "ios" / "pyproject.toml").read_text(encoding="utf-8"))

    requires = pyproject["tool"]["briefcase"]["app"]["obstacle_bridge_ios_e2e"]["requires"]

    assert "websockets" in requires
    assert "rubicon-objc>=0.5.3" in requires
