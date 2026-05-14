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
    assert "OB_IPSERVER_SWIFT_SMOKE" in provider
    assert "startTunnel_completed_swift_smoke" in provider
    assert "OB_IPSERVER_PYTHON_PROBE" in provider
    assert "python_probe_completed" in provider
    assert "obstaclebridge_module_probe_completed" in provider
    assert "probe_module:" in provider
    assert "single_module_probe_completed" in provider
    assert "startTunnel_completed_runtime_start_async" in provider
    assert "embedded_webadmin_started" in provider
    assert "handleAppMessage" in provider
    assert "obstaclebridge.ios.packet-tunnel.v1" in provider


def test_ipserver_extension_plist_and_entitlements_exist() -> None:
    info_plist = (IPSERVER_NATIVE_DIR / "Info.plist").read_text(encoding="utf-8")
    entitlements = (IPSERVER_NATIVE_DIR / "IPServer.entitlements").read_text(encoding="utf-8")
    app_entitlements = (APP_NATIVE_DIR / "ObstacleBridge.entitlements").read_text(encoding="utf-8")

    assert "com.apple.networkextension.packet-tunnel" in info_plist
    assert "PacketTunnelProvider" in info_plist
    assert "$(PRODUCT_MODULE_NAME).PacketTunnelProvider" not in info_plist
    assert "com.apple.developer.networking.networkextension" in entitlements
    assert "packet-tunnel-provider" in entitlements
    assert "com.apple.developer.networking.vpn.api" in entitlements
    assert "allow-vpn" in entitlements
    assert "com.apple.security.application-groups" in entitlements
    assert "com.apple.developer.networking.networkextension" in app_entitlements
    assert "packet-tunnel-provider" in app_entitlements
    assert "com.apple.developer.networking.vpn.api" in app_entitlements
    assert "allow-vpn" in app_entitlements


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


def test_ios_briefcase_configs_include_rubicon_for_native_crypto_bridge() -> None:
    pyproject = tomllib.loads((ROOT / "ios" / "pyproject.toml").read_text(encoding="utf-8"))

    app_requires = pyproject["tool"]["briefcase"]["app"]["obstacle_bridge_ios"]["requires"]
    requires = pyproject["tool"]["briefcase"]["app"]["obstacle_bridge_ios_e2e"]["requires"]

    assert "rubicon-objc>=0.5.3" in app_requires
    assert "websockets" in requires
    assert "rubicon-objc>=0.5.3" in requires


def test_ipserver_extension_sources_bootstrap_python_runtime() -> None:
    provider = (IPSERVER_NATIVE_DIR / "PacketTunnelProvider.swift").read_text(encoding="utf-8")
    bridge = (IPSERVER_NATIVE_DIR / "ObstacleBridgePythonBridge.m").read_text(encoding="utf-8")
    entitlements = (IPSERVER_NATIVE_DIR / "IPServer.entitlements").read_text(encoding="utf-8")
    info_plist = (IPSERVER_NATIVE_DIR / "Info.plist").read_text(encoding="utf-8")

    assert "NEPacketTunnelProvider" in provider
    assert "@objc(PacketTunnelProvider)" in provider
    assert "class PacketTunnelProvider: NEPacketTunnelProvider" in provider
    assert "start_embedded_webadmin" in provider
    assert "handleAppMessage" in provider
    assert "recordNativeEvent" in provider
    assert "stopTunnel_entered" in provider
    assert "obstacle_bridge_ios.ipserver_extension" in bridge
    assert "ObstacleBridgePythonBridge sendMessage" in bridge
    assert "probePythonRuntimeWithError" in bridge
    assert "probePythonModules" in bridge
    assert 'PyImport_ImportModule(moduleName.UTF8String)' in bridge
    assert "Py_InitializeFromConfig" in bridge
    assert "app_packages" in bridge
    assert "com.apple.security.application-groups" in entitlements
    assert "com.apple.networkextension.packet-tunnel" in info_plist


def test_app_tunnel_control_manages_ipserver_profile_without_blocking_main_thread() -> None:
    control = (APP_NATIVE_DIR / "ObstacleBridgeTunnelControl.swift").read_text(encoding="utf-8")

    assert "ObstacleBridgeTunnelControl" in control
    assert "NETunnelProviderManager.loadAllFromPreferences" in control
    assert "queue.async" in control
    assert "prepareIPServerTunnel" in control
    assert "harvestSharedLogs" in control
    assert "shared_logs_harvested" in control
    assert "profile_prepared" in control
    assert "startVPNTunnel" in control
    assert "sendProviderMessage" in control
    assert "requestProviderSnapshot" in control
    assert "requestProviderMessage" in control
    assert "native_python_probe" in control
    assert "probe_module:obstacle_bridge" in control
    assert "probe_module:obstacle_bridge_ios.ipserver_extension" in control
    assert "selectCanonicalManager" in control
    assert "removeFromPreferences" in control
    assert "preferences_reused" in control
    assert 'localizedDescription = "AdminWeb"' in control
    assert 'legacyLocalizedDescription = "ObstacleBridge"' in control
    assert 'connectionDisplayNamePrefix = "ObstacleBridge Local Admin"' in control
    assert "desiredProtocolUsername()" in control
    assert "applyIdentity(" in control
    assert "providerConfigurationPayload()" in control
    assert "tunnelProtocol.providerBundleIdentifier = providerBundleIdentifier" in control
    assert '"runtime_config_ref": "app-group:ObstacleBridge.cfg"' in control
    assert '"provider_configuration_mode": "minimal"' in control
    assert "needsNameRepair" in control
    assert "needsConfigurationRepair" in control
    assert "configuration_version" in control
    assert "provider_configuration_version" in control
    assert "localized_description" in control
    assert "protocol_server_address" in control
    assert "protocol_username" in control
    assert "restoreProtocolIdentityIfNeeded" in control
    assert "protocol_identity_repaired" in control
    assert "provider_snapshot_received" in control
    assert "provider_message_received" in control
    assert "provider_response" in control
    assert "tunnelProtocol.username" in control
    assert 'tunnelProtocol.serverAddress = tunnelAddress' in control
    assert '"runtime_config": ipserverRuntimeConfiguration()' in control
    assert "ios-native-tunnel-control.jsonl" in control
    assert "DispatchSemaphore" not in control
    assert "timed out loading VPN preferences" not in control
