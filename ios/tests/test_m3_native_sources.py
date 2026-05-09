from __future__ import annotations

from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[2]
SHARED_NATIVE_DIR = ROOT / "ios" / "native" / "ObstacleBridgeShared"
APP_NATIVE_DIR = ROOT / "ios" / "native" / "ObstacleBridgeApp"
IPSERVER_DIR = ROOT / "ios" / "build" / "obstacle_bridge_ios" / "ios" / "xcode" / "IPServer"
IPSERVER_NATIVE_DIR = ROOT / "ios" / "native" / "IPServer"


def test_ipserver_packet_tunnel_provider_source_exists() -> None:
    provider = (IPSERVER_NATIVE_DIR / "PacketTunnelProvider.swift").read_text(encoding="utf-8")

    assert "NEPacketTunnelProvider" in provider
    assert "setTunnelNetworkSettings" in provider
    assert "start_embedded_webadmin" in provider
    assert "handleAppMessage" in provider
    assert "obstaclebridge.ios.packet-tunnel.v1" in provider


def test_ipserver_extension_plist_and_entitlements_exist() -> None:
    info_plist = (IPSERVER_NATIVE_DIR / "Info.plist").read_text(encoding="utf-8")
    entitlements = (IPSERVER_NATIVE_DIR / "IPServer.entitlements").read_text(encoding="utf-8")
    app_entitlements = (APP_NATIVE_DIR / "ObstacleBridge.entitlements").read_text(encoding="utf-8")

    assert "com.apple.networkextension.packet-tunnel" in info_plist
    assert "PacketTunnelProvider" in info_plist
    assert "com.apple.developer.networking.networkextension" in entitlements
    assert "packet-tunnel-provider" in entitlements
    assert "com.apple.security.application-groups" in entitlements
    assert "com.apple.developer.networking.networkextension" in app_entitlements
    assert "packet-tunnel-provider" in app_entitlements


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


def test_ipserver_extension_sources_bootstrap_python_runtime() -> None:
    provider = (IPSERVER_NATIVE_DIR / "PacketTunnelProvider.swift").read_text(encoding="utf-8")
    bridge = (IPSERVER_NATIVE_DIR / "ObstacleBridgePythonBridge.m").read_text(encoding="utf-8")
    entitlements = (IPSERVER_NATIVE_DIR / "IPServer.entitlements").read_text(encoding="utf-8")
    info_plist = (IPSERVER_NATIVE_DIR / "Info.plist").read_text(encoding="utf-8")

    assert "NEPacketTunnelProvider" in provider
    assert "start_embedded_webadmin" in provider
    assert "handleAppMessage" in provider
    assert "obstacle_bridge_ios.ipserver_extension" in bridge
    assert "Py_InitializeFromConfig" in bridge
    assert "app_packages" in bridge
    assert "com.apple.security.application-groups" in entitlements
    assert "com.apple.networkextension.packet-tunnel" in info_plist
