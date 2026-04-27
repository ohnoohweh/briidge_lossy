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
    assert "ObstacleBridgeExtensionRuntime" in provider
    assert "obstacleBridgeConfig" in provider
    assert "obstaclebridge.ios.packet-tunnel.v1" in provider


def test_m3_native_extension_runtime_source_owns_obstaclebridge_layers() -> None:
    runtime = (NATIVE_DIR / "ObstacleBridgeExtensionRuntime.swift").read_text(encoding="utf-8")

    assert "final class ObstacleBridgeExtensionRuntime" in runtime
    assert "NEPacketTunnelFlow" in runtime
    assert "PacketFlowBridge" in runtime
    assert "ObstacleBridgePythonRuntime" in runtime
    assert "LocalWebAdminServer" in runtime
    assert "runtimeLayers" in runtime


def test_m3_native_extension_python_runtime_host_exists() -> None:
    header = (NATIVE_DIR / "ObstacleBridgePythonRuntime.h").read_text(encoding="utf-8")
    runtime = (NATIVE_DIR / "ObstacleBridgePythonRuntime.m").read_text(encoding="utf-8")
    bridge = (NATIVE_DIR / "ObstacleBridgeTunnel-Bridging-Header.h").read_text(encoding="utf-8")

    assert "ObstacleBridgePythonRuntime" in header
    assert "startWithProviderConfigurationJSON" in header
    assert "#include <Python/Python.h>" in runtime
    assert 'PyImport_ImportModule("obstacle_bridge_ios.extension_runtime")' in runtime
    assert "Py_InitializeFromConfig" in runtime
    assert 'ObstacleBridgePythonRuntime.h' in bridge


def test_m3_python_extension_runtime_starts_obstaclebridge_client() -> None:
    runtime = (ROOT / "ios" / "src" / "obstacle_bridge_ios" / "extension_runtime.py").read_text(encoding="utf-8")

    assert "ObstacleBridgeClient" in runtime
    assert "packet-tunnel-extension-python" in runtime
    assert "provider_configuration" in runtime
    assert "secure_link_mode" in runtime
    assert "compress_layer" in runtime


def test_m3_native_extension_webadmin_source_exists() -> None:
    webadmin = (NATIVE_DIR / "LocalWebAdminServer.swift").read_text(encoding="utf-8")

    assert "final class LocalWebAdminServer" in webadmin
    assert "NWListener" in webadmin
    assert '"/api/config"' in webadmin
    assert '"/api/status"' in webadmin
    assert '"/api/logs"' in webadmin
    assert '"packet-tunnel-extension"' in webadmin


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
