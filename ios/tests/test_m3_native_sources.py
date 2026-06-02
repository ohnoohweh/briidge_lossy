from __future__ import annotations

from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[2]
SHARED_NATIVE_DIR = ROOT / "ios" / "native" / "ObstacleBridgeShared"
APP_NATIVE_DIR = ROOT / "ios" / "native" / "ObstacleBridgeApp"
IPSERVER_DIR = ROOT / "ios" / "build" / "obstacle_bridge_ios" / "ios" / "xcode" / "IPServer"
IPSERVER_NATIVE_DIR = ROOT / "ios" / "native" / "IPServer"


def test_shared_packet_tunnel_configuration_source_exists() -> None:
    shared = (SHARED_NATIVE_DIR / "ObstacleBridgePacketTunnelConfiguration.swift").read_text(encoding="utf-8")

    assert "struct ObstacleBridgePacketTunnelDefaults" in shared
    assert "struct ObstacleBridgePacketTunnelConfiguration" in shared
    assert "func makeNetworkSettings() -> NEPacketTunnelNetworkSettings" in shared
    assert "NEIPv6Settings" in shared
    assert "includedRoutes6" in shared
    assert "excludedRoutes6" in shared
    assert "ObstacleBridgeRuntimeConfig.tunnelRoutingOverride" in shared
    assert 'schema: String = "obstaclebridge.ios.packet-tunnel.v1"' in shared


def test_ipserver_packet_tunnel_provider_source_exists() -> None:
    provider = (IPSERVER_NATIVE_DIR / "PacketTunnelProvider.swift").read_text(encoding="utf-8")

    assert "NEPacketTunnelProvider" in provider
    assert "ObstacleBridgeAdminAPI" in provider
    assert '"admin_api_request"' in provider
    assert "setTunnelNetworkSettings" in provider
    assert "OB_IPSERVER_SWIFT_SMOKE" in provider
    assert "startTunnel_completed_swift_smoke" in provider
    assert "startTunnel_completed_swift_only" in provider
    assert "handleAppMessage" in provider
    assert "packet_pump_forwarded_packets" in provider
    assert "ipserver-native-provider-state.json" in provider
    assert "updateProviderState(" in provider
    assert "bridge_state" in provider
    assert "processMemorySnapshot()" in provider
    assert "resident_size" in provider
    assert "phys_footprint" in provider
    assert "task_vm_info_kern_return" in provider
    assert "SwiftSimpleUDPPeerBridge" in provider
    assert "ObstacleBridgeUdpOverlayTransportOwner" in provider
    assert "swift_simple_udp" in provider
    assert "swift_udp" in provider
    assert "packetflow_connector_mode_selected" in provider
    assert "ObstacleBridgeOverlayLayerTransportAdapter" in provider
    assert "connectionRows() -> (tcp: [[String: Any]], udp: [[String: Any]], tun: [[String: Any]])" in provider
    assert "startTCPServices()" in provider
    assert "localTCPServiceSpecs(providerConfiguration:" in provider
    assert "swift_udp_tcp_listener_ready" in provider
    assert "sendLocalTunPacket(packet)" in provider
    assert "loadSharedRuntimeConfigJSON" in provider
    assert "packet_pump_dropped_packets" not in provider
    assert "obstaclebridge.ios.packet-tunnel.v1" in provider
    assert "tunnel_address6" in provider
    assert "included_routes6" in provider
    assert "excluded_routes6" in provider
    assert "fallbackRuntimeConfig: loadSharedRuntimeConfigJSON()" in provider
    assert "ObstacleBridgePacketTunnelConfiguration(" in provider
    assert '"effective_tunnel_network_settings"' in provider
    assert '"shared_overlay_bootstrap_state"' in provider
    assert "configuration.makeNetworkSettings()" in provider
    assert "private var nativeRuntimeActive: Bool" in provider
    assert 'runtimeMode == "swift_simple_udp" || runtimeMode == "swift_udp"' in provider
    assert "private func nativeAppMessageResponse(for payload: [String: Any]) throws -> [String: Any]" in provider
    assert "adminUIPayload(runtimeConfig:" in provider
    assert "securityAdvisorPayload(runtimeConfig:" in provider
    assert "scheduleEmbeddedRuntimeReload(action:" in provider
    assert '"restart_embedded": true' in provider
    assert '"embedded_runtime_reload_completed"' in provider
    assert "startTunnel_completed_swift_udp" in provider
    assert "startTunnel_completed_swift_simple_udp" in provider
    assert "startTunnel_unsupported_runtime_mode" in provider
    assert "startTunnel_waiting_for_onboarding" in provider
    assert 'if !nativeRuntimeActive {' in provider
    assert "private static func decodedProviderRuntimeConfig" in provider
    assert "ObstacleBridgeConfigSecretCodec.decryptPayload(runtimeConfig)" in provider
    assert "if let runtimeConfig = Self.decodedProviderRuntimeConfig(providerConfiguration)" in provider
    assert '"myudp_runtime": myudpRuntime' in provider
    assert "ObstacleBridgeAdminSnapshotSupport.transportRuntimeEnvelope(" in provider
    assert "provider?.recordPacketBridgeEvent(" in provider
    assert "private var peerTrafficRateState:" in provider
    assert "private var secureLinkConnectedSinceUnixTS:" in provider
    assert '"rx_bytes_per_sec": rxRate' in provider
    assert '"connected_since_unix_ts": snapshot.sessionID == 0 ? NSNull() : (secureLinkConnectedSinceUnixTS ?? nowUnixTS)' in provider

    runtime_config = (SHARED_NATIVE_DIR / "ObstacleBridgeRuntimeConfig.swift").read_text(encoding="utf-8")
    assert "struct ObstacleBridgeAdminUIBootstrapState" in runtime_config
    assert "static func adminUIBootstrapState" in runtime_config


def test_native_packet_flow_bridge_source_exists() -> None:
    bridge = (IPSERVER_NATIVE_DIR / "ObstacleBridgePacketFlowBridge.swift").read_text(encoding="utf-8")

    assert "@objc(ObstacleBridgePacketFlowBridge)" in bridge
    assert "PacketFlowPCAPWriter" in bridge
    assert "dequeueIncomingPacket" in bridge
    assert "writePacket" in bridge
    assert "registerWakeupFD" in bridge
    assert "resetWakeupFD" in bridge
    assert "bridgeStateJSONData" in bridge
    assert "bridgeStateSnapshot" in bridge
    assert "packet_bridge_activated" in bridge
    assert "packet_bridge_outgoing_write_completed" in bridge
    assert "packet_bridge_outgoing_write_slow" in bridge
    assert "incoming_pcap_path" in bridge
    assert "outgoing_pcap_path" in bridge
    assert "ipserver-nepacketflow-in-" in bridge
    assert "ipserver-nepacketflow-out-" in bridge


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


def test_channel_mux_codec_source_exists() -> None:
    codec = (SHARED_NATIVE_DIR / "ObstacleBridgeChannelMuxCodec.swift").read_text(encoding="utf-8")

    assert "struct ObstacleBridgeChannelMuxCodec" in codec
    assert "enum Proto: Int" in codec
    assert "enum MType: Int" in codec
    assert "packMux(" in codec
    assert "unpackMux(" in codec
    assert "buildOpenPayload(" in codec
    assert "parseOpenPayload(" in codec
    assert "encodeRemoteServicesSetV2(" in codec
    assert "decodeRemoteServicesSetV2(" in codec
    assert "chunkControlPayload(" in codec
    assert "ControlChunkReassembler" in codec


def test_channel_mux_tun_runtime_source_exists() -> None:
    runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeChannelMuxTunRuntime.swift").read_text(encoding="utf-8")

    assert "final class ObstacleBridgeChannelMuxTunRuntime" in runtime
    assert "struct LocalTunSendSnapshot" in runtime
    assert "struct InboundTunOpenSnapshot" in runtime
    assert "struct InboundTunOpenChunkSnapshot" in runtime
    assert "struct InboundTunDataSnapshot" in runtime
    assert "struct InboundTunFragmentSnapshot" in runtime
    assert "struct CloseSnapshot" in runtime
    assert "handleLocalTunPacket(" in runtime
    assert "handleInboundTunOpen(" in runtime
    assert "handleInboundTunOpenChunk(" in runtime
    assert "handleInboundTunData(" in runtime
    assert "handleInboundTunFragment(" in runtime
    assert "handleInboundTunClose(" in runtime


def test_channel_mux_udp_runtime_source_exists() -> None:
    runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeChannelMuxUdpRuntime.swift").read_text(encoding="utf-8")

    assert "final class ObstacleBridgeChannelMuxUdpRuntime" in runtime
    assert "struct LocalServerDatagramSnapshot" in runtime
    assert "struct InboundServerDatagramSnapshot" in runtime
    assert "struct InboundServerFragmentSnapshot" in runtime
    assert "struct InboundClientOpenSnapshot" in runtime
    assert "struct InboundClientDataSnapshot" in runtime
    assert "struct InboundClientFragmentSnapshot" in runtime
    assert "struct ClientConnectSnapshot" in runtime
    assert "struct LocalClientDatagramSnapshot" in runtime
    assert "struct CloseSnapshot" in runtime
    assert "struct ClientCloseSnapshot" in runtime
    assert "handleLocalServerDatagram(" in runtime
    assert "handleInboundServerData(" in runtime
    assert "handleInboundServerFragment(" in runtime
    assert "handleInboundClientOpen(" in runtime
    assert "handleInboundClientData(" in runtime
    assert "handleInboundClientFragment(" in runtime
    assert "handleClientConnected(" in runtime
    assert "handleLocalClientDatagram(" in runtime
    assert "handleInboundClientClose(" in runtime
    assert "handleInboundClose(" in runtime


def test_channel_mux_tcp_runtime_source_exists() -> None:
    runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeChannelMuxTcpRuntime.swift").read_text(encoding="utf-8")

    assert "final class ObstacleBridgeChannelMuxTcpRuntime" in runtime
    assert "struct LocalServerAcceptSnapshot" in runtime
    assert "struct LocalServerDataSnapshot" in runtime
    assert "struct InboundServerDataSnapshot" in runtime
    assert "struct InboundClientOpenSnapshot" in runtime
    assert "struct InboundClientDataSnapshot" in runtime
    assert "struct ClientConnectSnapshot" in runtime
    assert "struct LocalClientDataSnapshot" in runtime
    assert "struct LocalClientCloseSnapshot" in runtime
    assert "struct ClientCloseSnapshot" in runtime
    assert "struct ServerCloseSnapshot" in runtime
    assert "localConnectionClosed" in runtime
    assert "handleAcceptedServerConnection(" in runtime
    assert "handleLocalServerData(" in runtime
    assert "handleInboundServerData(" in runtime
    assert "handleLocalServerEOF(" in runtime
    assert "handleInboundServerClose(" in runtime
    assert "handleInboundClientOpen(" in runtime
    assert "handleInboundClientData(" in runtime
    assert "handleClientConnected(" in runtime
    assert "handleLocalClientData(" in runtime
    assert "handleLocalClientEOF(" in runtime
    assert "handleInboundClientClose(" in runtime


def test_compress_layer_runtime_source_exists() -> None:
    runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeCompressLayerRuntime.swift").read_text(encoding="utf-8")

    assert "final class ObstacleBridgeCompressLayerRuntime" in runtime
    assert "struct StatusSnapshot" in runtime
    assert "struct SendSnapshot" in runtime
    assert "struct ReceiveSnapshot" in runtime
    assert "parseAllowedMTypes(" in runtime
    assert "handleInboundPayload(" in runtime
    assert "handleSendPayload(" in runtime
    assert "statusSnapshot(peerID:" in runtime
    assert "safeCompress(" in runtime
    assert "safeDecompress(" in runtime
    assert "compress2" in runtime
    assert "inflateInit_" in runtime


def test_overlay_stack_planner_source_exists() -> None:
    runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeOverlayStackPlanner.swift").read_text(encoding="utf-8")

    assert "enum ObstacleBridgeOverlayStackPlannerError" in runtime
    assert "final class ObstacleBridgeOverlayStackPlanner" in runtime
    assert "struct TransportPlan" in runtime
    assert "parseOverlayTransports(" in runtime
    assert "planTransport(" in runtime
    assert "unsupportedSecureLinkMode" in runtime
    assert "unsupportedCompressAlgo" in runtime


def test_runtime_config_source_exists() -> None:
    runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeRuntimeConfig.swift").read_text(encoding="utf-8")

    assert "enum ObstacleBridgeRuntimeConfig" in runtime
    assert "struct ObstacleBridgeRuntimeServiceSpec" in runtime
    assert "struct ObstacleBridgeDerivedTunnelSettings" in runtime
    assert "struct ObstacleBridgeTunnelRoutingOverride" in runtime
    assert "struct ObstacleBridgeOverlayBootstrapSettings" in runtime
    assert "static func flatten(" in runtime
    assert "static func ownServerSpecs(" in runtime
    assert "static func remoteServerSpecs(" in runtime
    assert "static func tunnelRoutingOverride(" in runtime
    assert "static func localTunServiceSpec(" in runtime
    assert "static func packetflowConnectorSelection(" in runtime
    assert "static func runtimeExecutionMode(" in runtime
    assert "static func swiftUDPPeerConfig(" in runtime
    assert '"TUN_routing"' in runtime
    assert "tunnel_gateway" in runtime
    assert "tunnel_gateway6" in runtime
    assert "log_TUN_routing" in runtime
    assert "included_routes6" in runtime
    assert "listenerHookEnvBlocks()" in runtime
    assert "derivedLocalTunnelSettings(" in runtime
    assert "derivedRemoteTunnelSettings(" in runtime


def test_webadmin_server_source_exists() -> None:
    runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeWebAdminServer.swift").read_text(encoding="utf-8")

    assert "final class ObstacleBridgeWebAdminServer" in runtime
    assert "normalizedListenerHost(" in runtime
    assert 'host == "0.0.0.0"' in runtime
    assert 'host == "localhost"' in runtime
    assert '"/api/status"' in runtime
    assert '"/api/live"' in runtime
    assert "101 Switching Protocols" in runtime
    assert "Sec-WebSocket-Accept" in runtime
    assert "broadcastLiveTopic(" in runtime
    assert "liveTopicInterval(" in runtime
    assert "type\": \"hello\"" in runtime


def test_admin_api_source_exists() -> None:
    runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeAdminAPI.swift").read_text(encoding="utf-8")

    assert "protocol ObstacleBridgeAdminAPIStateProvider" in runtime
    assert "struct ObstacleBridgeAdminAPIRequest" in runtime
    assert "struct ObstacleBridgeAdminAPIResponse" in runtime
    assert "enum ObstacleBridgeAdminAPI" in runtime
    assert '"/api/meta"' in runtime
    assert '"/api/connections"' in runtime
    assert '"/api/peers"' in runtime
    assert '"admin_api_request"' in runtime


def test_macos_swift_host_runner_source_exists() -> None:
    wrapper = (APP_NATIVE_DIR / "ObstacleBridgeHostRunnerMain.swift").read_text(encoding="utf-8")
    runtime = (APP_NATIVE_DIR / "ObstacleBridgeHostRunner.swift").read_text(encoding="utf-8")
    shared_runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeRuntimeConfig.swift").read_text(encoding="utf-8")

    assert "@main" in wrapper
    assert "ObstacleBridgeHostRunnerMain" in wrapper
    assert "ObstacleBridgeHostRunner.runMain" in wrapper
    assert "ObstacleBridgeHostRunner" in runtime
    assert "makeAppScopedRunner" in runtime
    assert "makeRunner(cli:" in runtime
    assert "appScopedRuntimeConfigPath" in runtime
    assert "ObstacleBridgeHostRunnerCLI.parse" in runtime
    assert "dispatchMain()" in runtime
    assert "ObstacleBridgeAdminAPI" in runtime
    assert "ObstacleBridgeWebAdminServer" in runtime
    assert "ObstacleBridgeRuntimeConfig.flatten" in runtime
    assert "ObstacleBridgeOverlayBootstrapSettings" in runtime
    assert "ObstacleBridgeCompressLayerRuntime" in runtime
    assert "ObstacleBridgeSecureLinkPskRuntime" in runtime
    assert "ObstacleBridgeWebSocketOverlayRuntime" in runtime
    assert "ObstacleBridgeTcpOverlayRuntime" in runtime
    assert "ObstacleBridgeTcpOverlayTransportOwner" in runtime
    assert "ObstacleBridgeSecureLinkPskTransportAdapter" in runtime
    assert '"TUN_routing"' in shared_runtime
    assert "tunnel_gateway" in shared_runtime
    assert "tunnel_gateway6" in shared_runtime
    assert "log_TUN_routing" in shared_runtime
    assert '"swift_host_runner"' in runtime


def test_shared_admin_api_exposes_status_and_bootstrap_routes() -> None:
    runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeAdminAPI.swift").read_text(encoding="utf-8")

    assert 'case ("GET", "/api/status")' in runtime
    assert 'provider.adminStatusSnapshot()' in runtime
    assert 'case ("GET", "/api/bootstrap")' in runtime
    assert 'provider.adminMetaSnapshot()["bootstrap_state"] ?? [:]' in runtime


def test_macos_app_main_source_exists() -> None:
    app_main = (APP_NATIVE_DIR / "ObstacleBridgeMacAppMain.swift").read_text(encoding="utf-8")
    build_script = (ROOT / "ios" / "scripts" / "build_macos_app.sh").read_text(encoding="utf-8")
    control = (APP_NATIVE_DIR / "ObstacleBridgeTunnelControl.swift").read_text(encoding="utf-8")
    runner = (APP_NATIVE_DIR / "ObstacleBridgeHostRunner.swift").read_text(encoding="utf-8")

    assert "@main" in app_main
    assert "WKWebView" in app_main
    assert "ObstacleBridgeTunnelControl.startIPServerTunnel" in app_main
    assert "seedDocumentsSurfaceIfNeeded" in app_main
    assert ".applicationSupportDirectory" in app_main
    assert '.appendingPathComponent("ObstacleBridge"' in app_main
    assert ".applicationSupportDirectory" in control
    assert "let root = base" in control
    assert ".applicationSupportDirectory" in runner
    assert '.appendingPathComponent("ObstacleBridge"' in runner
    assert 'ObstacleBridgeHostRunnerError.unreadableRuntimeConfig("Documents")' in runner
    assert "ObstacleBridge.app" in build_script
    assert "ObstacleBridgeMacAppMain.swift" in build_script
    assert "codesign" in build_script
    assert 'APP_ENTITLEMENTS="${OBSTACLEBRIDGE_CODESIGN_ENTITLEMENTS:-}"' in build_script


def test_websocket_payload_codec_source_exists() -> None:
    runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeWebSocketPayloadCodec.swift").read_text(encoding="utf-8")

    assert "protocol ObstacleBridgeWebSocketPayloadCodec" in runtime
    assert "enum ObstacleBridgeWebSocketPayloadCodecFactory" in runtime
    assert "struct ObstacleBridgeWebSocketBinaryPayloadCodec" in runtime
    assert "struct ObstacleBridgeWebSocketBase64PayloadCodec" in runtime
    assert "struct ObstacleBridgeWebSocketJsonBase64PayloadCodec" in runtime
    assert "struct ObstacleBridgeWebSocketSemiTextShapePayloadCodec" in runtime
    assert "maxEncodedSize(" in runtime
    assert "invalidSemiTextShapeTrailingPadding" in runtime


def test_websocket_overlay_runtime_source_exists() -> None:
    runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeWebSocketOverlayRuntime.swift").read_text(encoding="utf-8")

    assert "final class ObstacleBridgeWebSocketOverlayRuntime" in runtime
    assert "struct ConnectPlan" in runtime
    assert "struct SendSnapshot" in runtime
    assert "struct SocketConfigSnapshot" in runtime
    assert "struct DisconnectSnapshot" in runtime
    assert "struct HTTPPreflightSnapshot" in runtime
    assert "listenerPeerSnapshot(" in runtime
    assert "buildConnectPlan(" in runtime
    assert "validateHTTPPreflight(" in runtime
    assert "parseProxySpec(" in runtime
    assert "buildProxyConnectRequest(" in runtime


def test_tcp_overlay_runtime_source_exists() -> None:
    runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeTcpOverlayRuntime.swift").read_text(encoding="utf-8")

    assert "final class ObstacleBridgeTcpOverlayRuntime" in runtime
    assert "struct SendSnapshot" in runtime
    assert "struct ConnectSnapshot" in runtime
    assert "struct SocketConfigSnapshot" in runtime
    assert "struct ReconnectSnapshot" in runtime
    assert "struct AcceptSnapshot" in runtime
    assert "struct ServerOverlaySnapshot" in runtime
    assert "struct BackpressureSnapshot" in runtime
    assert "struct ReceiveSnapshot" in runtime
    assert "sendApp(payload:" in runtime
    assert "connect(host:" in runtime
    assert "handleInboundBytes(" in runtime
    assert "socketConfigSnapshot(" in runtime
    assert "requestReconnect(" in runtime
    assert "acceptServerPeer(" in runtime
    assert "closeServerPeer(" in runtime
    assert "backpressureSnapshot(" in runtime


def test_tcp_overlay_transport_owner_source_exists() -> None:
    runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeTcpOverlayTransportOwner.swift").read_text(encoding="utf-8")

    assert "final class ObstacleBridgeTcpOverlayTransportOwner" in runtime
    assert "handleInboundTCPMuxFrame(" in runtime
    assert "handleInboundUDPMuxFrame(" in runtime
    assert "ObstacleBridgeChannelMuxTCPTransportOwner" in runtime
    assert "ObstacleBridgeChannelMuxUdpRuntime" in runtime
    assert "ObstacleBridgeOverlayLayerTransportAdapter" in runtime
    assert "handleInboundBytes(" in runtime
    assert "sendMuxFrames(" in runtime


def test_channel_mux_tcp_transport_owner_source_exists() -> None:
    runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeChannelMuxTCPTransportOwner.swift").read_text(encoding="utf-8")

    assert "final class ObstacleBridgeChannelMuxTCPTransportOwner" in runtime
    assert "ControlChunkReassembler" in runtime
    assert "acceptLocalConnection(" in runtime
    assert "handleInboundMuxFrame(" in runtime
    assert "ObstacleBridgeChannelMuxTcpRuntime" in runtime
    assert "TransportEvent" in runtime


def test_secure_link_psk_codec_source_exists() -> None:
    codec = (SHARED_NATIVE_DIR / "ObstacleBridgeSecureLinkPskCodec.swift").read_text(encoding="utf-8")

    assert "struct ObstacleBridgeSecureLinkPskCodec" in codec
    assert "buildFrame(" in codec
    assert "parseFrame(" in codec
    assert "deriveKeys(" in codec
    assert "nonce(counter:" in codec
    assert "buildJSONPayload(" in codec
    assert "parseJSONPayload(" in codec


def test_secure_link_psk_runtime_source_exists() -> None:
    runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeSecureLinkPskRuntime.swift").read_text(encoding="utf-8")

    assert "final class ObstacleBridgeSecureLinkPskRuntime" in runtime
    assert "beginClientHandshake(" in runtime
    assert "handleInboundFrame(" in runtime
    assert "sendApp(" in runtime
    assert "serverProof(" in runtime
    assert "ChaChaPoly" in runtime
    assert "typeClientHello" in runtime
    assert "typeServerHello" in runtime
    assert "typeAuthFail" in runtime
    assert "typeData" in runtime


def test_secure_link_psk_transport_adapter_source_exists() -> None:
    runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeSecureLinkPskTransportAdapter.swift").read_text(encoding="utf-8")

    assert "final class ObstacleBridgeSecureLinkPskTransportAdapter" in runtime
    assert "handleOutboundPayload(" in runtime
    assert "handleInboundFrame(" in runtime
    assert "flushPendingPayloads(" in runtime
    assert "beginClientHandshake(" in runtime


def test_overlay_layer_transport_adapter_source_exists() -> None:
    runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeOverlayLayerTransportAdapter.swift").read_text(encoding="utf-8")

    assert "final class ObstacleBridgeOverlayLayerTransportAdapter" in runtime
    assert "handleOutboundPayload(" in runtime
    assert "handleInboundFrame(" in runtime
    assert "ObstacleBridgeCompressLayerRuntime" in runtime
    assert "ObstacleBridgeSecureLinkPskTransportAdapter" in runtime


def test_udp_overlay_codec_source_exists() -> None:
    codec = (SHARED_NATIVE_DIR / "ObstacleBridgeUdpOverlayCodec.swift").read_text(encoding="utf-8")

    assert "struct ObstacleBridgeUdpOverlayCodec" in codec
    assert "buildProtocolFrame(" in codec
    assert "parseProtocolFrame(" in codec
    assert "buildDataFrame(" in codec
    assert "parseDataFrame(" in codec
    assert "buildControlFrame(" in codec
    assert "parseControlFrame(" in codec


def test_udp_overlay_session_codec_source_exists() -> None:
    codec = (SHARED_NATIVE_DIR / "ObstacleBridgeUdpOverlaySessionCodec.swift").read_text(encoding="utf-8")

    assert "struct ObstacleBridgeUdpOverlaySessionCodec" in codec
    assert "segmentApplicationPayload(" in codec
    assert "final class ReceiveState" in codec
    assert "struct Reassembly" in codec


def test_udp_overlay_peer_runtime_source_exists() -> None:
    runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeUdpOverlayPeerRuntime.swift").read_text(encoding="utf-8")

    assert "final class ObstacleBridgeUdpOverlayPeerRuntime" in runtime
    assert "struct InboundControlSnapshot" in runtime
    assert "struct InboundIdleSnapshot" in runtime
    assert "struct InboundDataSnapshot" in runtime
    assert "struct ControlTimerSnapshot" in runtime
    assert "struct RetransmitTimerSnapshot" in runtime
    assert "struct OutboundDataSnapshot" in runtime
    assert "struct OutboundControlSnapshot" in runtime
    assert "handleInboundControlPacket(" in runtime
    assert "handleControlTimerTick(" in runtime
    assert "handleRetransmitTimerTick(" in runtime
    assert "handleInboundIdleFrame(" in runtime
    assert "handleInboundDataFrame(" in runtime
    assert "sendApplicationPayload(" in runtime
    assert "buildOutboundControl(" in runtime
    assert "updateControlTracking(" in runtime
    assert "noteControlSent(" in runtime


def test_ios_packaging_config_includes_rubicon_for_native_crypto_bridge() -> None:
    pyproject = tomllib.loads((ROOT / "ios" / "pyproject.toml").read_text(encoding="utf-8"))

    app_sources = pyproject["tool"]["briefcase"]["app"]["obstacle_bridge_ios"]["sources"]
    app_requires = pyproject["tool"]["briefcase"]["app"]["obstacle_bridge_ios"]["requires"]

    assert "../admin_web" in app_sources
    assert "rubicon-objc>=0.5.3" in app_requires


def test_ipserver_extension_sources_are_swift_only() -> None:
    provider = (IPSERVER_NATIVE_DIR / "PacketTunnelProvider.swift").read_text(encoding="utf-8")
    entitlements = (IPSERVER_NATIVE_DIR / "IPServer.entitlements").read_text(encoding="utf-8")
    info_plist = (IPSERVER_NATIVE_DIR / "Info.plist").read_text(encoding="utf-8")
    shim = (ROOT / "ios" / "src" / "obstacle_bridge_ios" / "ipserver_extension.py").read_text(encoding="utf-8")
    shim_runtime = (ROOT / "ios" / "src" / "obstacle_bridge_ios" / "ipserver_runtime.py").read_text(encoding="utf-8")
    config_support = (SHARED_NATIVE_DIR / "ObstacleBridgeAdminConfigSupport.swift").read_text(encoding="utf-8")

    assert "NEPacketTunnelProvider" in provider
    assert "@objc(PacketTunnelProvider)" in provider
    assert "class PacketTunnelProvider: NEPacketTunnelProvider" in provider
    assert "handleAppMessage" in provider
    assert "recordNativeEvent" in provider
    assert "stopTunnel_entered" in provider
    assert "ObstacleBridgeRuntimeConfig.flatten" in provider
    assert "ObstacleBridgeOverlayBootstrapSettings" in provider
    assert "ObstacleBridgeCompressLayerRuntime" in provider
    assert "ObstacleBridgeSecureLinkPskRuntime" in provider
    assert "ObstacleBridgeWebSocketOverlayRuntime" in provider
    assert "ObstacleBridgeTcpOverlayRuntime" in provider
    assert "shared_overlay_runtime_prepared" in provider
    assert "shared_overlay_bootstrap_state" in provider
    assert "adminOnboardingConnectionProfiles()" in provider
    assert "adminOnboardingInviteGenerate(request:" in provider
    assert "adminOnboardingInvitePreview(request:" in provider
    assert "invite_token" in config_support
    assert "ObstacleBridgePythonBridge" not in provider
    assert not (IPSERVER_NATIVE_DIR / "ObstacleBridgePythonBridge.m").exists()
    assert not (IPSERVER_NATIVE_DIR / "ObstacleBridgePythonBridge.h").exists()
    assert not (IPSERVER_NATIVE_DIR / "IPServer-Bridging-Header.h").exists()
    assert "Python-side stand-in for the iOS packet-tunnel extension used in E2E tests." in shim
    assert "ObstacleBridgeClient" in shim
    assert "handle_message" in shim
    assert "Minimal Python runtime shim used by iOS extension-style integration tests." in shim_runtime
    assert "LAST_PROVIDER_CONFIGURATION" in shim_runtime
    assert "com.apple.security.application-groups" in entitlements
    assert "com.apple.networkextension.packet-tunnel" in info_plist


def test_app_tunnel_control_manages_ipserver_profile_without_blocking_main_thread() -> None:
    control = (APP_NATIVE_DIR / "ObstacleBridgeTunnelControl.swift").read_text(encoding="utf-8")

    assert "ObstacleBridgeTunnelControl" in control
    assert "ObstacleBridgeWebAdminServer" in control
    assert "admin_api_request" in control
    assert "ObstacleBridgeIOSAppAdminWebProxy" in control
    assert "NETunnelProviderManager.loadAllFromPreferences" in control
    assert "queue.async" in control
    assert "prepareIPServerTunnel" in control
    assert "startIPServerTunnel" in control
    assert "harvestSharedLogs" in control
    assert "runtimeExecutionMode()" in control
    assert "ObstacleBridgeRuntimeConfig.runtimeExecutionMode" in control
    assert "startSwiftHostRunner()" in control
    assert "prepareSwiftHostRunner()" in control
    assert "refreshSwiftHostRunnerStatus()" in control
    assert '"swift_host_runner"' in control
    assert "shared_logs_harvested" in control
    assert "syncConfigurationFileInternal" in control
    assert "config_sync_completed" in control
    assert "config_sync_before_prepare" in control
    assert 'app-documents-root.json' in control
    assert 'ObstacleBridge.cfg' in control
    assert "profile_prepared" in control
    assert "startVPNTunnel" in control
    assert "sendProviderMessage" in control
    assert "requestProviderSnapshot" in control
    assert "requestProviderMessage" in control
    assert "stopVPNTunnel" in control
    assert "scheduleAdminTunnelReload" in control
    assert "restart_after_save" in control
    assert "selectCanonicalManager" in control
    assert "removeFromPreferences" in control
    assert "duplicate_cleanup_stop_requested" in control
    assert "preferences_reused" in control
    assert "desiredLocalizedDescription()" in control
    assert "providerBuildTimestampUTC" in control
    assert 'legacyLocalizedDescription = "ObstacleBridge"' in control
    assert 'legacyLocalizedDescriptionAlt = "AdminWeb"' in control
    assert "applyIdentity(" in control
    assert "tunnelProtocol.providerBundleIdentifier = providerBundleIdentifier" in control
    assert '"provider_configuration_mode": "config_derived_profile_persistence"' in control
    assert "needsConfigurationRepair" in control
    assert "desiredManagers" in control
    assert "let desiredManagers = managers.filter { hasCurrentProviderConfiguration($0) }" in control
    assert "let duplicates = managers.filter { $0 !== canonical }" in control
    assert "ObstacleBridgeRuntimeConfig.ownServerSpecs" in control
    assert "ObstacleBridgeRuntimeConfig.remoteServerSpecs" in control
    assert "derivedLocalTunnelSettings(" in control
    assert "derivedRemoteTunnelSettings(" in control
    assert "overlayPeerConfigured(payload:" in control
    assert "includedRoutes: []" in control
    assert "includedRoutes6: []" in control
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
    assert 'let runtimeConfig = ObstacleBridgeTunnelControl.loadRuntimeConfigJSON()' in control
    assert 'payload["runtime_config"] = runtimeConfig' in control
    assert "runtimeConfigForProviderConfiguration(" not in control
    assert "swiftUDPRuntimeConfig(payload: payload)" not in control
    assert "tunnelProtocol.username" in control
    assert "tunnelProtocol.username = nil" in control
    assert "manager.localizedDescription = desiredLocalizedDescription()" in control
    assert 'tunnelProtocol.serverAddress = derived.tunnelAddress' in control
    assert "tunnelProtocol.providerConfiguration = derived.providerConfiguration" in control
    assert 'defaultTunnelAddress6 = "fd20:106::1"' in control
    assert "TUN_ADDR6" not in control
    assert "PEER_ADDR6" not in control
    assert "TUN_SUBNET6" not in control
    assert "findLocalIOSTunnelService" in control
    assert "findRemoteTunnelServiceTargetingIOS" in control
    assert "ObstacleBridgeRuntimeConfig.tunnelRoutingOverride" in control
    assert "applyNetworkOverride(" not in control
    assert "loadRuntimeConfigJSON" in control
    assert "ios-native-tunnel-control.jsonl" in control
    assert "DispatchSemaphore" in control
    assert "timed out loading VPN preferences" not in control

    host_runner = (APP_NATIVE_DIR / "ObstacleBridgeHostRunner.swift").read_text(encoding="utf-8")
    assert "private func requestRestart()" in host_runner
    assert "private func requestReconnect()" in host_runner
    assert "private func reloadRuntimeStateForControlAction()" in host_runner
    assert '"restart_supported": true' in host_runner
    assert '"restart_mode": "immediate"' in host_runner
    assert '"restart_embedded": true' in host_runner
    assert '"reconnect_supported": true' in host_runner
    assert '"rtt_est_ms": myudpRuntime["rtt_est_ms"] ?? NSNull()' in host_runner
    assert '"confirmed_total": protocolStats["confirmed_total"] ?? 0' in host_runner


def test_ios_packet_tunnel_provider_owns_restart_without_app_process() -> None:
    provider = (IPSERVER_NATIVE_DIR / "PacketTunnelProvider.swift").read_text(encoding="utf-8")

    assert "private var runtimeReloadInProgress = false" in provider
    assert "private func stopEmbeddedRuntimeForReload()" in provider
    assert "private func scheduleEmbeddedRuntimeReload(action: String)" in provider
    assert 'recordNativeEvent("embedded_runtime_reload_requested"' in provider
    assert 'recordNativeEvent("embedded_runtime_reload_completed"' in provider
    assert 'self.startTunnel(options: nil)' in provider
    assert 'scheduleEmbeddedRuntimeReload(action: "restart")' in provider
    assert 'scheduleEmbeddedRuntimeReload(action: "reconnect")' in provider
    assert 'scheduleEmbeddedRuntimeReload(action: "restart_after_save")' in provider
    assert '"restart_embedded": true' in provider
    assert '"protocol_stats": overlayRuntime.protocolStatsSnapshot()' in (SHARED_NATIVE_DIR / "ObstacleBridgeUdpOverlayTransportOwner.swift").read_text(encoding="utf-8")
