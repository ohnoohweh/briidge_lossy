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
    assert "func makeNetworkSettings(includeRoutes: Bool = true) -> NEPacketTunnelNetworkSettings" in shared
    assert "let enabledOnStartup: Bool" in shared
    assert "routingOverride?.enabledOnStartup ?? true" in shared
    assert "NEIPv6Settings" in shared
    assert "includedRoutes6" in shared
    assert "excludedRoutes6" in shared
    assert "ObstacleBridgeRuntimeConfig.tunnelRoutingOverride" in shared
    assert 'schema: String = "obstaclebridge.ios.packet-tunnel.v1"' in shared


def test_ipserver_packet_tunnel_provider_source_exists() -> None:
    provider = (IPSERVER_NATIVE_DIR / "PacketTunnelProvider.swift").read_text(encoding="utf-8")
    snapshot_support = (SHARED_NATIVE_DIR / "ObstacleBridgeAdminSnapshotSupport.swift").read_text(encoding="utf-8")

    assert "NEPacketTunnelProvider" in provider
    assert "ObstacleBridgeAdminAPI" in provider
    assert '"admin_api_request"' in provider
    assert "setTunnelNetworkSettings" in provider
    assert "OB_IPSERVER_SWIFT_SMOKE" in provider
    assert "startTunnel_completed_swift_udp" in provider
    assert "startTunnel_completed_swift_simple_udp" in provider
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
    assert "ObstacleBridgeTcpOverlayTransportOwner" in provider
    assert "ObstacleBridgeWebSocketOverlayTransportOwner" in provider
    assert "ObstacleBridgeQuicOverlayTransportOwner" in provider
    assert "let protocolConnected = connectionLayers.first(where:" in provider
    assert '"connected": protocolConnected' in provider
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
    assert "configuration.makeNetworkSettings(includeRoutes: tunRoutingEnabled)" in provider
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
    assert '"myudp_runtime": selectedTransport == "myudp" ? selectedRuntime : [:]' in provider
    assert 'summary["websocket_runtime"] = "ready"' in provider
    assert 'summary["quic_runtime"] = "ready"' in provider
    assert "ObstacleBridgeAdminSnapshotSupport.transportRuntimeEnvelope(" in provider
    assert "provider?.recordPacketBridgeEvent(" in provider
    assert "private var peerTrafficRateState:" in provider
    assert "private var secureLinkConnectedSinceUnixTS:" in provider
    assert '"rx_bytes_per_sec": rxRate' in provider
    assert '"connected_since_unix_ts": snapshot.sessionID == 0 ? NSNull() : (secureLinkConnectedSinceUnixTS ?? nowUnixTS)' in provider
    assert '"rekey_supported": snapshot.rekeySupported' in provider
    assert '"rekey_in_progress": snapshot.rekeyInProgress' in provider
    assert '"last_event": snapshot.lastEvent' in provider
    assert '"last_event_unix_ts": snapshot.lastEventUnixTs ?? NSNull()' in provider
    assert '"authenticated_sessions_total": snapshot.authenticatedSessionsTotal' in provider
    assert '"rekeys_completed_total": snapshot.rekeysCompletedTotal' in provider
    assert '"last_rekey_trigger": snapshot.lastRekeyTrigger' in provider
    assert '"trust_validation_state": snapshot.trustValidationState' in provider
    assert '"disconnect_reason": snapshot.disconnectReason' in provider
    assert '"disconnect_detail": snapshot.disconnectDetail' in provider
    assert '"throttle": ObstacleBridgeAdminSnapshotSupport.peerThrottleSnapshot(peerID: 1, connectionsSnapshot: connections)' in provider
    assert 'summary["secure_link_rekey_after_frames"] = rekeyAfterFrames' in provider
    assert 'summary["secure_link_rekey_after_seconds"] = rekeyAfterSeconds' in provider
    assert 'summary["secure_link_retry_backoff_initial_ms"] = retryBackoffInitialMS' in provider
    assert 'summary["secure_link_retry_backoff_max_ms"] = retryBackoffMaxMS' in provider
    assert 'payload["channelmux_transport_delay_threshold_ms"]' in provider
    assert 'payload["channelmux_transport_delay_rotation_delay_ms"]' in provider
    assert 'summary["secure_link_recover_after_failure"]' not in provider
    assert 'summary["secure_link_recover_delay_seconds"]' not in provider
    assert "static func peerThrottleSnapshot(peerID: Int, connectionsSnapshot: [String: Any]) -> [String: Any]" in snapshot_support
    assert "static func peersSnapshotForAPI(_ peers: [[String: Any]]) -> [[String: Any]]" in snapshot_support
    assert "peerThrottleRatio" not in snapshot_support
    assert '"budget_bytes", "used_bytes", "remaining_bytes"' in snapshot_support

    runtime_config = (SHARED_NATIVE_DIR / "ObstacleBridgeRuntimeConfig.swift").read_text(encoding="utf-8")
    assert "struct ObstacleBridgeAdminUIBootstrapState" in runtime_config
    assert "static func adminUIBootstrapState" in runtime_config
    assert 'schemaItem(key: "ws_bind"' in runtime_config
    assert 'schemaItem(key: "ws_own_port"' in runtime_config
    assert 'schemaItem(key: "ws_path"' in runtime_config
    assert 'schemaItem(key: "ws_peer_addresses"' in runtime_config
    assert '"tun_execution"' in runtime_config
    assert 'schemaItem(key: "tun_execution_mode", description: "Desktop local TUN execution topology: inline current-process ownership or helper-backed ownership.", defaultValue: "inline", choices: ["inline", "helper"])' in runtime_config
    assert 'schemaItem(key: "tun_helper_backend", description: "Helper backend identifier for helper mode. Values include linux-native, linux-python, and darwin-native.", defaultValue: "linux-native")' in runtime_config
    assert 'schemaItem(key: "tun_helper_apply_network", description: "Whether the helper should own privileged address/route/DNS/firewall apply-remove work.", defaultValue: true)' in runtime_config
    assert 'private static let tunExecutionCompatibilityAliases = [' in runtime_config
    assert '"mode": "tun_execution_mode"' in runtime_config
    assert '"helper_backend": "tun_helper_backend"' in runtime_config
    assert '"proxy_provider"' in runtime_config
    assert 'schemaItem(key: "proxy_provider_enabled", description: "Enable the explicit HTTP CONNECT and SOCKS5 proxy provider."' in runtime_config
    assert 'schemaItem(key: "proxy_provider_http_port", description: "Local HTTP/CONNECT proxy listener port."' in runtime_config
    assert 'schemaItem(key: "proxy_provider_socks5_port", description: "Local SOCKS5 CONNECT proxy listener port."' in runtime_config
    assert 'schemaItem(key: "proxy_provider_http_port", description: "Local HTTP/CONNECT proxy listener port.", defaultValue: 13881)' in runtime_config
    assert 'schemaItem(key: "proxy_provider_socks5_port", description: "Local SOCKS5 CONNECT proxy listener port.", defaultValue: 13882)' in runtime_config
    assert 'schemaItem(key: "secure_link_rekey_after_frames", description: "Automatically rekey PSK sessions after this many protected data frames. 0 disables frame-triggered rekey.", defaultValue: 0)' in runtime_config
    assert 'schemaItem(key: "secure_link_rekey_after_seconds", description: "Automatically rekey PSK sessions after this many authenticated seconds. 0 disables time-triggered rekey.", defaultValue: 0.0)' in runtime_config
    assert 'schemaItem(key: "secure_link_retry_backoff_initial_ms", description: "Initial SecureLink client retry backoff after authentication failure, in milliseconds.", defaultValue: 1000)' in runtime_config
    assert 'schemaItem(key: "secure_link_retry_backoff_max_ms", description: "Maximum SecureLink client retry backoff after repeated authentication failures, in milliseconds.", defaultValue: 5000)' in runtime_config
    assert 'schemaItem(key: "secure_link_recover_after_failure"' not in runtime_config
    assert 'schemaItem(key: "secure_link_recover_delay_seconds"' not in runtime_config
    assert 'schemaItem(key: "proxy_provider_egress", description: "Proxy egress policy object for outbound connection behavior.", defaultValue: [' in runtime_config
    assert '"mode": "system"' in runtime_config
    assert 'schemaItem(key: "log_proxy_provider", description: "Proxy provider log level override."' in runtime_config
    assert 'schemaItem(key: "mux_tcp_bp_threshold", description: "Mux TCP write-buffer threshold in bytes before drain is triggered.", defaultValue: 1)' in runtime_config
    assert 'schemaItem(key: "channelmux_transport_delay_threshold_ms", description: "Estimated transport-delay threshold before ChannelMux sheds local traffic and arms sustained-delay rotation.", defaultValue: 5000)' in runtime_config
    assert 'schemaItem(key: "channelmux_transport_delay_rotation_delay_ms", description: "Continuous estimated-delay duration before ChannelMux requests a connection rotation.", defaultValue: 30000)' in runtime_config
    assert 'schemaItem(key: "max_inflight", description: "Maximum myUDP DATA frames allowed in flight before excess frames are queued.", defaultValue: 200)' in runtime_config
    assert 'flatPayload["proxy_provider_http_port"]) ?? 13881' in provider
    assert 'flatPayload["proxy_provider_socks5_port"]) ?? 13882' in provider
    assert '"mode": "system"' in provider
    host_runner = (APP_NATIVE_DIR / "ObstacleBridgeHostRunner.swift").read_text(encoding="utf-8")
    assert 'let egress = (section?["egress"] ?? runtimeConfig["proxy_provider_egress"]) as? [String: Any] ?? [' in host_runner
    assert '"mode": "system"' in host_runner
    assert 'let rekeyAfterFrames = Self.intValue(from: runtimeConfig["secure_link_rekey_after_frames"]) ?? 0' in host_runner
    assert 'let rekeyAfterSeconds = Self.doubleValue(from: runtimeConfig["secure_link_rekey_after_seconds"]) ?? 0.0' in host_runner
    assert 'let retryBackoffInitialMS = Self.intValue(from: runtimeConfig["secure_link_retry_backoff_initial_ms"]) ?? 1000' in host_runner
    assert 'let retryBackoffMaxMS = Self.intValue(from: runtimeConfig["secure_link_retry_backoff_max_ms"]) ?? 5000' in host_runner
    assert 'secure_link_recover_after_failure' not in host_runner
    assert 'secure_link_recover_delay_seconds' not in host_runner


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
    assert "struct LocalTunOpenSnapshot" in runtime
    assert "struct InboundTunOpenSnapshot" in runtime
    assert "struct InboundTunOpenChunkSnapshot" in runtime
    assert "struct InboundTunDataSnapshot" in runtime
    assert "struct InboundTunFragmentSnapshot" in runtime
    assert "struct CloseSnapshot" in runtime
    assert "handleLocalTunPacket(" in runtime
    assert "openLocalTunChannelIfNeeded(" in runtime
    assert "handleInboundTunOpen(" in runtime
    assert "handleInboundTunOpenChunk(" in runtime
    assert "handleInboundTunData(" in runtime
    assert "handleInboundTunFragment(" in runtime
    assert "handleInboundTunClose(" in runtime
    assert "func resetTransportEpoch()" in runtime


def test_swift_overlay_epoch_reset_reopens_local_tun_channels() -> None:
    for owner_name in (
        "ObstacleBridgeUdpOverlayTransportOwner.swift",
        "ObstacleBridgeTcpOverlayTransportOwner.swift",
        "ObstacleBridgeWebSocketOverlayTransportOwner.swift",
        "ObstacleBridgeQuicOverlayTransportOwner.swift",
    ):
        owner = (SHARED_NATIVE_DIR / owner_name).read_text(encoding="utf-8")
        assert "tunRuntime?.resetTransportEpoch()" in owner
        assert "activeTunChanIDs.removeAll()" in owner


def test_swift_websocket_reconnect_starts_a_fresh_tun_epoch_before_new_task() -> None:
    owner = (SHARED_NATIVE_DIR / "ObstacleBridgeWebSocketOverlayTransportOwner.swift").read_text(encoding="utf-8")
    connect_overlay = owner[owner.index("    private func connectOverlay() {") : owner.index("    private func connectNetworkWebSocket(")]

    assert "resetOverlayTransportEpoch()" in connect_overlay
    assert connect_overlay.index("resetOverlayTransportEpoch()") < connect_overlay.index(
        "websocketTransportGeneration += 1"
    )


def test_swift_overlay_remote_service_catalog_uses_current_tun_epoch() -> None:
    tun_runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeChannelMuxTunRuntime.swift").read_text(encoding="utf-8")
    overlay_core = (SHARED_NATIVE_DIR / "ObstacleBridgeOverlayChannelCore.swift").read_text(encoding="utf-8")
    host_runner = (APP_NATIVE_DIR / "ObstacleBridgeHostRunner.swift").read_text(encoding="utf-8")
    provider = (IPSERVER_NATIVE_DIR / "PacketTunnelProvider.swift").read_text(encoding="utf-8")

    owners = [
        (SHARED_NATIVE_DIR / name).read_text(encoding="utf-8")
        for name in (
            "ObstacleBridgeUdpOverlayTransportOwner.swift",
            "ObstacleBridgeTcpOverlayTransportOwner.swift",
            "ObstacleBridgeWebSocketOverlayTransportOwner.swift",
            "ObstacleBridgeQuicOverlayTransportOwner.swift",
        )
    ]

    assert "typealias ObstacleBridgeChannelMuxStartupFramesProvider" in tun_runtime
    assert "func currentConnectionSeq() -> UInt32" in tun_runtime
    assert "startupMuxFramesForNewTunOpen: (() -> [Data])? = nil" in overlay_core
    assert "framesAdmittedBeforeSecureLink(" in overlay_core
    assert "sendMuxFrames(outbound.frames)" in overlay_core
    assert "openConfiguredLocalTunIfReady(" in overlay_core
    for owner in owners:
        assert "startupMuxFramesProvider: ObstacleBridgeChannelMuxStartupFramesProvider?" in owner
        assert "tunRuntime?.currentConnectionSeq() ?? muxConnectionSeq" in owner
        assert "startupMuxFramesProvider?(muxInstanceID, connectionSeq) ?? startupMuxFrames" in owner
        assert "startupMuxFramesReplayedWithTunOpen = false" in owner
        assert "private func startupMuxFramesForNewTunOpen() -> [Data]" in owner
        assert "startupMuxFramesForNewTunOpen: startupMuxFramesForNewTunOpen" in owner
        assert "private func maybeOpenConfiguredTunIfReady()" in owner
        assert "maybeOpenConfiguredTunIfReady()" in owner

    assert host_runner.count("startupMuxFramesProvider: { [weak self] instanceID, connectionSeq in") == 4
    assert provider.count("startupMuxFramesProvider: { [weak self] instanceID, connectionSeq in") == 4


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
    assert "static func overlayPeerExcludedRoutes(" in runtime
    assert 'let wsAddresses = transport == "ws" ? wsPeerAddresses(from: flat["ws_peer_addresses"]) : []' in runtime
    assert "static func effectiveExcludedRoutes(" in runtime
    assert "static func localTunServiceSpec(" in runtime
    assert "static func packetflowConnectorSelection(" in runtime
    assert "static func runtimeExecutionMode(" in runtime
    assert "static func swiftUDPPeerConfig(" in runtime
    assert '"TUN_routing"' in runtime
    assert "tunnel_gateway" in runtime
    assert "tunnel_gateway6" in runtime
    assert "enableTCPMSS" in runtime
    assert "enableTunTcpdump" in runtime
    assert "tunTcpdumpPcapPath" in runtime
    assert "optionalStringValueAllowEmpty" in runtime
    assert "log_TUN_routing" in runtime
    assert "included_routes6" in runtime
    assert "listenerHookEnvBlocks()" in runtime
    assert "derivedLocalTunnelSettings(" in runtime
    assert "derivedRemoteTunnelSettings(" not in runtime


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
    assert '"tun_routing"' in runtime


def test_proxy_server_source_exists() -> None:
    runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeProxyServer.swift").read_text(encoding="utf-8")
    provider = (IPSERVER_NATIVE_DIR / "PacketTunnelProvider.swift").read_text(encoding="utf-8")
    host_runner = (APP_NATIVE_DIR / "ObstacleBridgeHostRunner.swift").read_text(encoding="utf-8")
    python_runtime = (ROOT / "src" / "obstacle_bridge" / "bridge_proxy_server.py").read_text(encoding="utf-8")

    assert "enum ObstacleBridgeProxyProtocolCodec" in runtime
    assert "final class ObstacleBridgeProxyServer" in runtime
    assert "NWListener" in runtime
    assert "NWConnection" in runtime
    assert "CONNECT" in runtime
    assert "parseHTTPRequestHead" in runtime
    assert "rewriteHTTPRequestForOriginServer" in runtime
    assert "parseSOCKS5ConnectRequest" in runtime
    assert "basicAuthorizationHeader" in runtime
    assert "Proxy-Authenticate" in runtime
    assert "UDP ASSOCIATE" not in runtime
    assert "private var proxyServers: [String: ObstacleBridgeProxyServer]" in provider
    assert "private var proxyProviderLastError" in provider
    assert "startProxyProviderIfConfigured(providerConfiguration:" in provider
    assert "stopProxyProvider()" in provider
    assert "proxyProviderSnapshot()" in provider
    assert '"proxy_provider"' in provider
    assert '"configured": config.configuredPayload()' in provider
    assert '"last_error": proxyProviderLastError' in provider
    assert 'flatPayload["proxy_provider_auth"]) as? [String: Any]' in provider
    assert 'flatPayload["proxy_provider_egress"]) as? [String: Any]' in provider
    assert 'flatPayload["proxy_provider_policy"]) as? [String: Any]' in provider
    assert '"rekey_supported": snapshot.rekeySupported' in host_runner
    assert '"rekey_in_progress": snapshot.rekeyInProgress' in host_runner
    assert '"last_event": snapshot.lastEvent' in host_runner
    assert '"last_event_unix_ts": snapshot.lastEventUnixTs ?? NSNull()' in host_runner
    assert '"authenticated_sessions_total": snapshot.authenticatedSessionsTotal' in host_runner
    assert '"rekeys_completed_total": snapshot.rekeysCompletedTotal' in host_runner
    assert '"last_rekey_trigger": snapshot.lastRekeyTrigger' in host_runner
    assert '"trust_validation_state": snapshot.trustValidationState' in host_runner
    assert '"disconnect_reason": snapshot.disconnectReason' in host_runner
    assert '"disconnect_detail": snapshot.disconnectDetail' in host_runner
    provider_js = (ROOT / "admin_web" / "app.js").read_text(encoding="utf-8")
    assert "const rekeySupported = secureLink.rekey_supported !== false;" in provider_js
    assert "renderMetric('last_rekey_trigger', rekeySupported ? secureLink.last_rekey_trigger : 'n/a')" in provider_js
    assert "class ObstacleBridgeProxyProtocolCodec" in python_runtime
    assert "class ObstacleBridgeProxyServer" in python_runtime
    assert "parse_http_request_head" in python_runtime
    assert "rewrite_http_request_for_origin_server" in python_runtime
    assert "parse_socks5_connect_request" in python_runtime


def test_admin_api_source_exists() -> None:
    runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeAdminAPI.swift").read_text(encoding="utf-8")

    assert "protocol ObstacleBridgeAdminAPIStateProvider" in runtime
    assert "struct ObstacleBridgeAdminAPIRequest" in runtime
    assert "struct ObstacleBridgeAdminAPIResponse" in runtime
    assert "enum ObstacleBridgeAdminAPI" in runtime
    assert "static func tunControlSnapshot(enabled: Bool, startupEnabled: Bool, supported: Bool)" in runtime
    assert '"/api/meta"' in runtime
    assert '"/api/connections"' in runtime
    assert '"/api/tun-routing/status"' in runtime
    assert '"/api/tun-routing/control"' in runtime
    assert '"/api/peers"' in runtime
    assert '"tun_routing"' in runtime
    assert "adminTunRoutingSnapshot()" in runtime
    assert "adminTunRoutingControl(request:" in runtime
    assert "tunRoutingSnapshot(fromConnections:" in runtime
    assert "physicalSharedTunRows(from: sharedRows)" in runtime
    assert 'physical["physical_interface"] = true' in runtime
    assert 'physical["peer_id"] = "physical"' in runtime
    assert 'physical["chan_id"] = NSNull()' in runtime
    assert '"shared_drop_by_reason": sharedDropByReason' in runtime
    assert '"icmp_stage_counts": icmpStageCounts' in runtime
    assert '"probe_boundary_counts": probeBoundaryCounts' in runtime
    assert '"local_reply_stage_counts": localReplyStageCounts' in runtime
    assert '"admin_api_request"' in runtime


def test_tun_probe_diagnostics_support_source_exists() -> None:
    support = (SHARED_NATIVE_DIR / "ObstacleBridgeTunProbeDiagnosticsSupport.swift").read_text(encoding="utf-8")

    assert "struct ObstacleBridgeTunProbeWaiterKey: Hashable" in support
    assert "final class ObstacleBridgeTunProbeWaiterState" in support
    assert "struct ObstacleBridgeTunProbeReply" in support
    assert "struct ObstacleBridgeTunProbeHistory" in support
    assert "enum ObstacleBridgeTunProbeDiagnosticsSupport" in support
    assert 'static let localReplyStageKeys = [' in support
    assert 'static let tunICMPStageKeys = [' in support
    assert 'static let tunProbeBoundaryKeys = [' in support
    assert 'static func makeTunICMPStageCounts() -> [String: Int]' in support
    assert 'static func makeTunProbeBoundaryCounts() -> [String: Int]' in support
    assert 'static func makeLocalReplyStageCounts() -> [String: Int]' in support
    assert 'static func recordTunICMPStage(' in support
    assert 'static func recordTunProbeBoundary(_ key: String, tunProbeBoundaryCounts: inout [String: Int])' in support
    assert 'static func tunProbeCacheKey(probeKind: String, ifname: String, target: String) -> String' in support
    assert 'static func tunProbeLabel(_ probeKind: String) -> String' in support
    assert 'static func tunProbeKindCode(_ probeKind: String) -> UInt8' in support
    assert 'static func tunProbeNameResolution(status: String, resolvedIP: String = "", detail: String = "") -> [String: Any]' in support
    assert 'static func tunProbeResult(' in support
    assert 'static func sourceProbeFamilies(tunnelAddress: String, tunnelAddress6: String) -> [Int32]' in support
    assert 'static func sourceAddressForProbeFamily(_ family: Int32, tunnelAddress: String, tunnelAddress6: String) -> String' in support
    assert 'static func resolveTunProbeTarget(_ target: String, candidateFamilies: [Int32]) -> (target: String?, family: Int32, error: String)' in support
    assert 'static func observeTunProbeReply(' in support
    assert 'static func tunProbeRuntimeDiagSnapshot(' in support


def test_ios_packet_tunnel_tun_routing_verification_source_exists() -> None:
    provider = (IPSERVER_NATIVE_DIR / "PacketTunnelProvider.swift").read_text(encoding="utf-8")
    support = (SHARED_NATIVE_DIR / "ObstacleBridgeTunProbeDiagnosticsSupport.swift").read_text(encoding="utf-8")
    packet_tunnel_probe_tests = (ROOT / "ios" / "tests" / "test_ios_packet_tunnel_provider_probe.py").read_text(encoding="utf-8")

    assert 'private enum ObstacleBridgeGeneratedBuildStamp {' in provider
    assert 'static let providerBuildTimestampUTC = "unknown"' in provider
    assert 'private func buildSummary() -> [String: Any]' in provider
    assert '"source": "embedded-build-info"' in provider
    assert '"build_timestamp_utc": timestamp' in provider
    assert 'private func adminSnapshotCachingEnabled() -> Bool' in provider
    assert 'ObstacleBridgeRuntimeConfig.boolValue(from: runtimeConfig["admin_snapshot_cache_enabled"]) ?? false' in provider
    assert "func adminStatusSnapshot() -> [String: Any] {\n        guard adminSnapshotCachingEnabled() else {\n            return adminStatusSnapshotUncached()\n        }" in provider
    assert "func adminConnectionsSnapshot() -> [String: Any] {\n        guard adminSnapshotCachingEnabled() else {\n            return adminConnectionsSnapshotUncached()\n        }" in provider
    assert "func adminTunRoutingSnapshot() -> [String: Any] {\n        guard adminSnapshotCachingEnabled() else {\n            return adminTunRoutingSnapshotUncached()\n        }" in provider
    assert "func adminPeersSnapshot() -> [[String: Any]] {\n        guard adminSnapshotCachingEnabled() else {\n            return adminPeersSnapshotUncached()\n        }" in provider
    assert "func adminMetaSnapshot() -> [String: Any] {\n        guard adminSnapshotCachingEnabled() else {\n            return adminMetaSnapshotUncached()\n        }" in provider
    assert 'let resolvedPeer = adminResolvedPeerSnapshot(transport: transport, transportRuntime: transportRuntime)' in provider
    assert '"peer": resolvedPeer ?? configuredEndpoint' in provider
    assert '"resolved_peer": resolvedPeer ?? NSNull()' in provider
    assert '"resolved_peer_family": resolvedPeer?["family"] ?? NSNull()' in provider
    assert "private func adminResolvedPeerSnapshot(transport: String, transportRuntime: [String: Any]) -> [String: Any]?" in provider
    assert 'ObstacleBridgeRuntimeConfig.stringValue(from: selectedRuntime["overlay_peer_host"])' in provider
    assert 'ObstacleBridgeRuntimeConfig.stringValue(from: selectedRuntime["resolved_peer_host"])' in provider
    assert 'private let adminSnapshotRefreshQueue = DispatchQueue(label: "PacketTunnelProvider.AdminSnapshotRefresh", qos: .utility)' in provider
    assert "let timer = DispatchSource.makeTimerSource(queue: adminSnapshotRefreshQueue)" in provider
    assert "private func adminPacketProcessingActive(bridgeSnapshot: [String: Any]? = nil) -> Bool" in provider
    assert 'if let active = snapshot["active"] as? Bool {' in provider
    assert 'payload["verification"] = adminTunRoutingVerificationPayload(payload: payload)' in provider
    assert 'payload["tun_control"] = ObstacleBridgeAdminAPI.tunControlSnapshot(' in provider
    assert 'private var packetTunnelConfiguration: ObstacleBridgePacketTunnelConfiguration?' in provider
    assert 'private var tunRoutingEnabled = false' in provider
    assert 'packetTunnelConfiguration = configuration' in provider
    assert 'tunRoutingEnabled = configuration.enabledOnStartup' in provider
    assert 'let settings = configuration.makeNetworkSettings(includeRoutes: enabled)' in provider
    assert 'setTunnelNetworkSettings(settings)' in provider
    assert 'effectivePacketTunnelSettingsState = Self.packetTunnelSettingsSnapshot(' in provider
    assert 'startupEnabled: packetTunnelConfiguration?.enabledOnStartup ?? true' in provider
    assert 'func adminTunRoutingControl(request: ObstacleBridgeAdminAPIRequest)' in provider
    assert 'enabled: tunRoutingEnabled && adminPacketProcessingActive()' in provider
    assert '"enabled_on_startup": configuration.enabledOnStartup' in provider
    assert 'supported: true' in provider
    assert "private func adminTunRoutingVerificationPayload(payload: [String: Any]) -> [String: Any]" in provider
    assert 'private let adminTunVerificationRefreshQueue = DispatchQueue(label: "PacketTunnelProvider.AdminTunVerificationRefresh", qos: .utility)' in provider
    assert "private func startAdminTunVerificationPublisher()" in provider
    assert "private func refreshAdminTunVerificationCache(sync: Bool = false)" in provider
    assert 'state: "pending"' in provider
    assert 'if !adminPacketProcessingActive() {' in provider
    assert 'state: "skipped"' in provider
    assert '"ifname": "NEPacketTunnelFlow"' in provider
    assert '"tun_config": Self.iOSVerificationResult(' in provider
    assert '"tun_connectivity": cachedTunConnectivityVerificationOrProbe(' in provider
    assert '"tun_global_connectivity": cachedTunConnectivityVerificationOrProbe(' in provider
    assert '?? "google.de")' in provider
    assert 'method: "network_extension_settings"' in provider
    assert '"name_resolution": nameResolution' in provider
    assert 'private func tunProbeNameResolution(status: String, resolvedIP: String = "", detail: String = "") -> [String: Any]' not in provider
    assert "} else if addressesPresent && !adminPacketProcessingActive() {" in provider
    assert '"Packet processing is not active yet."' in provider
    assert "guard adminPacketProcessingActive() else {" in provider
    assert 'return bridge.probeTunConnectivity(' in provider
    assert 'private var tunICMPStageCounts = ObstacleBridgeTunProbeDiagnosticsSupport.makeTunICMPStageCounts()' in provider
    assert 'private var tunProbeBoundaryCounts = ObstacleBridgeTunProbeDiagnosticsSupport.makeTunProbeBoundaryCounts()' in provider
    assert 'private var localReplyStageCounts = ObstacleBridgeTunProbeDiagnosticsSupport.makeLocalReplyStageCounts()' in provider
    assert 'private var tunProbeLastTimeoutDiag: [String: Any] = [:]' in provider
    assert 'recordTunProbeBoundary("probe_attempt_started")' in provider
    assert 'recordTunProbeBoundary("probe_waiter_registered")' in provider
    assert 'recordTunProbeBoundary("probe_injected_local_virtual")' in provider
    assert 'recordTunICMPStage("from_local_tun_read")' in provider
    assert 'recordTunICMPStage("overlay_tx_before_send_app")' in provider
    assert 'recordTunICMPStage("local_reply_before_overlay_send")' in provider
    assert 'recordTunProbeBoundary("probe_send_completed")' in provider
    assert 'recordTunProbeBoundary("probe_timeout")' in provider
    assert 'recordTunProbeBoundary("probe_reply_consumed_before_local_write")' in provider
    assert 'recordTunICMPStage("from_peer_before_local_write")' in provider
    assert 'recordTunICMPStage("to_local_tun_written")' in provider
    assert 'recordTunICMPStage("local_reply_virtual_probe_delivery")' in provider
    assert '"tun_icmp_stage_counts": tunICMPStageCounts,' in provider
    assert '"tun_probe_boundary_counts": tunProbeBoundaryCounts,' in provider
    assert '"tun_local_reply_stage_counts": localReplyStageCounts,' in provider
    assert '"tun_probe_last_timeout_diag": tunProbeLastTimeoutDiag,' in provider
    assert '"tun_icmp_stage_counts": bridgeSnapshot["tun_icmp_stage_counts"] as? [String: Any] ?? [:],' in provider
    assert '"tun_probe_boundary_counts": bridgeSnapshot["tun_probe_boundary_counts"] as? [String: Any] ?? [:],' in provider
    assert '"tun_local_reply_stage_counts": bridgeSnapshot["tun_local_reply_stage_counts"] as? [String: Any] ?? [:],' in provider
    assert '"tun_probe_last_timeout_diag": bridgeSnapshot["tun_probe_last_timeout_diag"] as? [String: Any] ?? [:],' in provider
    assert 'ObstacleBridgeTunProbeDiagnosticsSupport.recordTunICMPStage(' in provider
    assert 'ObstacleBridgeTunProbeDiagnosticsSupport.recordTunProbeBoundary(' in provider
    assert 'ObstacleBridgeTunProbeDiagnosticsSupport.tunProbeLabel(' in provider
    assert 'ObstacleBridgeTunProbeDiagnosticsSupport.tunProbeCacheKey(' in provider
    assert 'ObstacleBridgeTunProbeDiagnosticsSupport.tunProbeNameResolution(' in provider
    assert 'ObstacleBridgeTunProbeDiagnosticsSupport.tunProbeResult(' in provider
    assert 'ObstacleBridgeTunProbeDiagnosticsSupport.tunProbeKindCode(' in provider
    assert 'ObstacleBridgeTunProbeDiagnosticsSupport.sourceProbeFamilies(' in provider
    assert 'ObstacleBridgeTunProbeDiagnosticsSupport.sourceAddressForProbeFamily(' in provider
    assert 'ObstacleBridgeTunProbeDiagnosticsSupport.resolveTunProbeTarget(' in provider
    assert 'private func sourceProbeFamilies() -> [Int32]' not in provider
    assert 'private func sourceAddressForProbeFamily(_ family: Int32) -> String' not in provider
    assert 'private func resolveTunProbeTarget(_ target: String, candidateFamilies: [Int32]) -> (target: String?, family: Int32, error: String)' not in provider
    assert 'ObstacleBridgeTunProbeDiagnosticsSupport.observeTunProbeReply(' in provider
    assert 'ObstacleBridgeTunProbeDiagnosticsSupport.tunProbeRuntimeDiagSnapshot(' in provider
    assert 'struct PreparedProbe {' in provider
    assert 'let waiter: ObstacleBridgeTunProbeWaiterState' in provider
    assert 'let waiterKey: ObstacleBridgeTunProbeWaiterKey' in provider
    assert '"probe_reply_matched"' in support
    assert '"probe_reply_unmatched"' in support
    assert '"overlay_rx_after_unpack"' in support

    app_js = (ROOT / "admin_web" / "app.js").read_text(encoding="utf-8")
    assert "const buildTimestampUTC = String(build.build_timestamp_utc || '').trim();" in app_js
    assert "return `build ${buildTimestampUTC}`;" in app_js
    assert "function fmtHostPort(host, port) {" in app_js
    assert "const bracketedHost = hostText.includes(':') && !hostText.startsWith('[') ? `[${hostText}]` : hostText;" in app_js
    assert "if (Array.isArray(ep) && ep.length >= 2) return fmtHostPort(ep[0], ep[1]);" in app_js
    assert "if (dest.host != null && dest.port != null) return fmtHostPort(dest.host, dest.port);" in app_js
    assert '"method": "internal_icmp_echo"' in support
    assert "ObstacleBridgeTunPing.parseEchoReply(packet)" in support
    assert "ObstacleBridgeTunPing.buildIPv4EchoRequest(" in provider
    assert "ObstacleBridgeTunPing.buildIPv6EchoRequest(" in provider
    assert 'str(SHARED_NATIVE_DIR / "ObstacleBridgeTunProbeDiagnosticsSupport.swift")' in packet_tunnel_probe_tests


def test_macos_swift_host_runner_source_exists() -> None:
    wrapper = (APP_NATIVE_DIR / "ObstacleBridgeHostRunnerMain.swift").read_text(encoding="utf-8")
    runtime = (APP_NATIVE_DIR / "ObstacleBridgeHostRunner.swift").read_text(encoding="utf-8")
    shared_runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeRuntimeConfig.swift").read_text(encoding="utf-8")
    native_spec = (SHARED_NATIVE_DIR / "ObstacleBridgeNativeServiceSpec.swift").read_text(encoding="utf-8")

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
    assert "sharedTunOwnershipSnapshot(for: spec.toChannelMuxServiceSpec())" in runtime
    assert '"shared_tun_ownership"' in runtime
    assert "ObstacleBridgeRuntimeConfig.flatten" in runtime
    assert "ObstacleBridgeOverlayBootstrapSettings" in runtime
    assert "ObstacleBridgeCompressLayerRuntime" in runtime
    assert "ObstacleBridgeSecureLinkPskRuntime" in runtime
    assert "ObstacleBridgeWebSocketOverlayRuntime" in runtime
    assert '"throttle": ObstacleBridgeAdminSnapshotSupport.peerThrottleSnapshot(peerID: 1, connectionsSnapshot: connections)' in runtime
    assert "ObstacleBridgeTcpOverlayRuntime" in runtime
    assert "ObstacleBridgeTcpOverlayTransportOwner" in runtime
    assert "ObstacleBridgeSecureLinkPskTransportAdapter" in runtime
    assert '"TUN_routing"' in shared_runtime
    assert "tunnel_gateway" in shared_runtime
    assert "tunnel_gateway6" in shared_runtime
    assert "log_TUN_routing" in shared_runtime
    assert 'env["EXCLUDED_ROUTES"]' in runtime
    assert 'env["EXCLUDED_ROUTES6"]' in runtime
    assert '"swift_host_runner"' in runtime
    assert "let lifecycleHooks: [String: ObstacleBridgeChannelMuxCodec.JSONValue]?" in native_spec
    assert "let options: [String: ObstacleBridgeChannelMuxCodec.JSONValue]?" in native_spec
    assert "self.lifecycleHooks = sharedSpec.lifecycleHooks" in native_spec
    assert "self.options = sharedSpec.options" in native_spec
    assert "lifecycleHooks: lifecycleHooks" in native_spec
    assert "options: options" in native_spec


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
    macos_tun = (SHARED_NATIVE_DIR / "ObstacleBridgeMacOSTunAdapter.swift").read_text(encoding="utf-8")
    tun_helper_contract = (SHARED_NATIVE_DIR / "ObstacleBridgeTunHelperContract.swift").read_text(encoding="utf-8")

    assert "@main" in app_main
    assert "WKWebView" in app_main
    assert "ObstacleBridgeTunnelControl.startIPServerTunnel" in app_main
    assert "buildMenu()" in app_main
    assert 'NSButton(title: "Reload"' in app_main
    assert "@objc\n    private func reloadWebAdmin()" in app_main
    assert 'appMenu.addItem(withTitle: "Reload", action: #selector(reloadWebAdmin), keyEquivalent: "r")' in app_main
    assert "seedDocumentsSurfaceIfNeeded" in app_main
    assert ".applicationSupportDirectory" in app_main
    assert '.appendingPathComponent("ObstacleBridge"' in app_main
    assert ".applicationSupportDirectory" in control
    assert "let root = base" in control
    assert "#if os(macOS)" in control
    assert "return loadSharedRuntimeConfigJSON() ?? [:]" in control
    assert 'remoteAdminPort = 13081' in control
    assert 'remoteAdminName = "WebAdmin iphone"' in control
    assert '"admin_snapshot_cache_enabled": false' in control
    assert 'privilegedHostRunnerExecutableName = "ObstacleBridgeHostRunner"' in control
    assert "do shell script" in control
    assert "with administrator privileges" in control
    assert "bundledPrivilegedHostRunnerURL" in control
    assert "ensurePrivilegedSwiftHostRunnerRunning" in control
    assert "privilegedHostRunnerProcessPattern" in control
    assert 'process.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")' in control
    assert '/usr/bin/pkill -TERM -f' in control
    assert '/usr/bin/pkill -KILL -f' in control
    assert ".applicationSupportDirectory" in runner
    assert '.appendingPathComponent("ObstacleBridge"' in runner
    assert 'ObstacleBridgeHostRunnerError.unreadableRuntimeConfig("Documents")' in runner
    assert "ObstacleBridge.app" in build_script
    assert "ObstacleBridgeMacAppMain.swift" in build_script
    assert "ObstacleBridgeMacOSTunAdapter.swift" in build_script
    assert "ObstacleBridgeTunHelperContract.swift" in build_script
    assert "ObstacleBridgeTunHelperXPCTransport.swift" in build_script
    assert "ObstacleBridgeMacOSTunHelperService.swift" in build_script
    assert "ObstacleBridgeTunPrivilegedHelperMain.swift" in build_script
    assert "ObstacleBridgeTunHelper" in build_script
    assert "Library/LaunchServices" in build_script
    assert "Library/LaunchDaemons" in build_script
    assert 'cp "${BINARY_PATH}" "${APP_MACOS_DIR}/ObstacleBridgeHostRunner"' in build_script
    assert "codesign" in build_script
    assert 'APP_ENTITLEMENTS="${OBSTACLEBRIDGE_CODESIGN_ENTITLEMENTS:-}"' in build_script
    assert 'BUILD_VARIANT="${OBSTACLEBRIDGE_MACOS_BUILD_VARIANT:-normal}"' in build_script
    assert 'OBSTACLEBRIDGE_SWIFT_FAILURE_INJECTION' in build_script
    assert 'SWIFT_EXTRA_FLAGS+=("-DOBSTACLEBRIDGE_FAILURE_INJECTION")' in build_script
    assert "tunServiceSpec: tunService?.toChannelMuxServiceSpec()" in runner
    assert 'case openTun = "OPEN_TUN"' in tun_helper_contract
    assert "iOSUsesNetworkExtensionBoundary = true" in tun_helper_contract


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


def test_websocket_overlay_transport_owner_source_exists() -> None:
    runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeWebSocketOverlayTransportOwner.swift").read_text(encoding="utf-8")
    host_runner = (APP_NATIVE_DIR / "ObstacleBridgeHostRunner.swift").read_text(encoding="utf-8")
    provider = (IPSERVER_NATIVE_DIR / "PacketTunnelProvider.swift").read_text(encoding="utf-8")

    assert "final class ObstacleBridgeWebSocketOverlayTransportOwner" in runtime
    assert "URLSessionWebSocketTask" in runtime
    assert "NWProtocolWebSocket.Options" in runtime
    assert "sec_protocol_options_set_tls_server_name" in runtime
    assert 'headers.append((name: "Host"' in runtime
    assert "peerAddresses.isEmpty" in runtime
    assert 'peerAddresses: ObstacleBridgeRuntimeConfig.wsPeerAddresses(from: settings.runtimeConfig["ws_peer_addresses"])' in provider
    assert 'let peerAddresses = ObstacleBridgeRuntimeConfig.wsPeerAddresses(from: runtimeConfig["ws_peer_addresses"])' in host_runner
    assert "peerAddresses: peerAddresses" in host_runner
    assert "handleInboundTCPMuxFrame(" in runtime
    assert "handleInboundUDPMuxFrame(" in runtime
    assert "sendMuxFrames(" in runtime


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
    assert "authenticated && peerConfirmedAuthenticated" in runtime
    assert "authenticated: isAuthenticated" in runtime
    assert "framesFromClientPassedTotal" in runtime
    assert "framesFromClientDroppedTotal" in runtime
    assert "framesToClientPassedTotal" in runtime
    assert "private var pendingRekeyStartedAt: TimeInterval?" in runtime
    assert "(timeProvider() - pendingRekeyStartedAt) >= Self.handshakeTimeoutSeconds" in runtime


def test_secure_link_psk_transport_adapter_source_exists() -> None:
    runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeSecureLinkPskTransportAdapter.swift").read_text(encoding="utf-8")

    assert "final class ObstacleBridgeSecureLinkPskTransportAdapter" in runtime
    assert "handleOutboundPayload(" in runtime
    assert "handleInboundFrame(" in runtime
    assert "flushPendingPayloads(" in runtime
    assert "beginClientHandshake(" in runtime


def test_swift_secure_link_admin_snapshots_use_python_state_vocabulary() -> None:
    provider = (IPSERVER_NATIVE_DIR / "PacketTunnelProvider.swift").read_text(encoding="utf-8")
    host_runner = (APP_NATIVE_DIR / "ObstacleBridgeHostRunner.swift").read_text(encoding="utf-8")
    assert '"frames_from_client_passed_total": snapshot.framesFromClientPassedTotal' in host_runner
    assert '"frames_from_client_dropped_total": snapshot.framesFromClientDroppedTotal' in host_runner
    assert '"frames_to_client_passed_total": snapshot.framesToClientPassedTotal' in host_runner
    assert '"frames_from_client_passed_total": snapshot.framesFromClientPassedTotal' in provider
    assert '"frames_from_client_dropped_total": snapshot.framesFromClientDroppedTotal' in provider
    assert '"frames_to_client_passed_total": snapshot.framesToClientPassedTotal' in provider

    assert 'secureState = "failed"' in provider
    assert 'secureState = "waiting_transport"' in provider
    assert 'secureState = "listening"' in provider
    assert 'secureState = "auth_failed"' not in provider

    assert 'state = "failed"' in host_runner
    assert 'state = "waiting_transport"' in host_runner
    assert 'state = "listening"' in host_runner
    assert 'state = "auth_failed"' not in host_runner


def test_overlay_layer_transport_adapter_source_exists() -> None:
    runtime = (SHARED_NATIVE_DIR / "ObstacleBridgeOverlayLayerTransportAdapter.swift").read_text(encoding="utf-8")

    assert "final class ObstacleBridgeOverlayLayerTransportAdapter" in runtime
    assert "handleOutboundPayload(" in runtime
    assert "handleInboundFrame(" in runtime
    assert "ObstacleBridgeCompressLayerRuntime" in runtime
    assert "ObstacleBridgeSecureLinkPskTransportAdapter" in runtime
    assert "struct ObstacleBridgeConnectionLifecycleEvent" in runtime
    assert "struct ObstacleBridgeConnectionRotationResult" in runtime
    assert "func connectionRotationDue(candidateCount: Int)" in runtime
    assert "func transportDelayRotationDue(" in runtime
    assert "func rotationAttemptRejected(_ result: ObstacleBridgeConnectionRotationResult)" in runtime
    assert "defaultTransportDelayRotationGrace: TimeInterval = 30.0" in runtime
    assert "let transportDelayRotationGrace: TimeInterval" in runtime
    assert "transportDelayRotationThresholdMS: Double = ObstacleBridgeOverlayLayerTransportAdapter.defaultTransportDelayRotationThresholdMS" in runtime
    assert "transportDelayRotationGrace: TimeInterval = ObstacleBridgeOverlayLayerTransportAdapter.defaultTransportDelayRotationGrace" in runtime
    assert "enforceAuthenticatedTransportReadiness(transportConnected: transportConnected)" in runtime
    assert "private func enforceAuthenticatedTransportReadiness(transportConnected: Bool)" in runtime
    assert "secureLinkAdapter?.statusSnapshot().authenticated == true" in runtime


def test_peer_address_protocol_source_exists_and_is_below_secure_link() -> None:
    runtime = (SHARED_NATIVE_DIR / "ObstacleBridgePeerAddressProtocolRuntime.swift").read_text(encoding="utf-8")
    adapter = (SHARED_NATIVE_DIR / "ObstacleBridgeOverlayLayerTransportAdapter.swift").read_text(encoding="utf-8")

    assert "final class ObstacleBridgePeerAddressProtocolRuntime" in runtime
    assert "handleTransportConnected()" in runtime
    assert "observedPeerPort: Int? = nil" in runtime
    assert "private(set) var observedPublicPort: Int?" in runtime
    assert "private static func encodePort(_ port: Int) -> Data" in runtime
    assert "inet_pton" in runtime
    assert "bytes.prefix(10).allSatisfy({ $0 == 0 })" in runtime
    assert "return (4, Data(bytes.suffix(4)))" in runtime
    assert "peerAddressRuntime?.handleTransportConnected()" in adapter
    assert "peerAddressRuntime.handleInboundFrame(" in adapter


def test_udp_overlay_codec_source_exists() -> None:
    codec = (SHARED_NATIVE_DIR / "ObstacleBridgeUdpOverlayCodec.swift").read_text(encoding="utf-8")

    assert "struct ObstacleBridgeUdpOverlayCodec" in codec
    assert "buildProtocolFrame(" in codec
    assert "parseProtocolFrame(" in codec
    assert "buildControlFrame(" in codec
    assert "parseControlFrame(" in codec
    assert "encodeStreamRecord(" in codec
    assert "encodeDataBatch(" in codec
    assert "decodeDataBatch(" in codec
    assert "buildDataFrame(" not in codec
    assert "parseDataFrame(" not in codec
    assert "struct DataPacket" not in codec


def test_udp_overlay_peer_rotation_rebuilds_the_native_socket() -> None:
    owner = (SHARED_NATIVE_DIR / "ObstacleBridgeUdpOverlayTransportOwner.swift").read_text(encoding="utf-8")

    assert "private func rebuildSocketForPeerRotation() -> Bool" in owner
    assert "Darwin.close(socketFD)" in owner
    assert "installReadSource()" in owner
    assert "udp_overlay_socket_rebuilt" in owner
    assert "guard rebuildSocketForPeerRotation() else" in owner


def test_udp_overlay_session_codec_source_exists() -> None:
    codec = (SHARED_NATIVE_DIR / "ObstacleBridgeUdpOverlaySessionCodec.swift").read_text(encoding="utf-8")

    assert "struct ObstacleBridgeUdpOverlaySessionCodec" in codec
    assert "final class StreamReceiveState" in codec
    assert "segmentApplicationPayload(" not in codec
    assert "final class ReceiveState" not in codec
    assert "struct Reassembly" not in codec


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
    assert "enqueueApplicationPayload(" in runtime
    assert "flushSendQueue(" in runtime
    assert "buildOutboundControl(" in runtime
    assert "updateControlTracking(" in runtime
    assert '"frames_to_securelink": framesToSecureLink' in runtime
    assert '"frames_from_securelink": framesFromSecureLink' in runtime
    assert "recordSecureLinkBoundaryFrame(direction:" in runtime
    assert "noteControlSent(" in runtime


def test_ios_packaging_config_includes_native_bridge_and_local_webadmin_ats() -> None:
    pyproject = tomllib.loads((ROOT / "ios" / "pyproject.toml").read_text(encoding="utf-8"))

    app_sources = pyproject["tool"]["briefcase"]["app"]["obstacle_bridge_ios"]["sources"]
    app_requires = pyproject["tool"]["briefcase"]["app"]["obstacle_bridge_ios"]["requires"]
    ios_info = pyproject["tool"]["briefcase"]["app"]["obstacle_bridge_ios"]["iOS"]["info"]

    assert "../admin_web" in app_sources
    assert "rubicon-objc>=0.5.3" in app_requires
    assert ios_info["NSAppTransportSecurity"] == {"NSAllowsLocalNetworking": True}


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
    assert "if let payload = loadSharedRuntimeConfigJSON()" in provider
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
    macos_tun = (SHARED_NATIVE_DIR / "ObstacleBridgeMacOSTunAdapter.swift").read_text(encoding="utf-8")
    ios_app = (ROOT / "ios" / "src" / "obstacle_bridge_ios" / "app.py").read_text(encoding="utf-8")

    assert "ObstacleBridgeTunnelControl" in control
    assert "ObstacleBridgeWebAdminServer" in control
    assert "admin_api_request" in control
    assert "NETunnelProviderManager.loadAllFromPreferences" in control
    assert "queue.async" in control
    assert "prepareIPServerTunnel" in control
    assert "startIPServerTunnel" in control
    assert "stopIPServerTunnel" in control
    assert "enableIPServerTunRouting" in control
    assert "suspendIPServerTunRouting" in control
    assert "tunRoutingStatus" in control
    assert '"/api/tun-routing/control"' in control
    assert '"/api/tun-routing/status"' in control
    assert "iOS displays the extension's Admin API directly; no foreground proxy." in control
    provider = (IPSERVER_NATIVE_DIR / "PacketTunnelProvider.swift").read_text(encoding="utf-8")
    assert "tunnelInflowAllowed()" in provider
    assert "packet_pump_dropped_before_overlay_ready" in provider
    assert "swift_simple_udp_packetflow_dropped_before_overlay_ready" in provider
    assert "TUN verification waits for the connected overlay state." in provider
    assert "TUN verification is suspended while local TUN throttling is active." not in provider
    assert "framesAdmittedBeforeSecureLink(" in (SHARED_NATIVE_DIR / "ObstacleBridgeOverlayChannelCore.swift").read_text(encoding="utf-8")
    assert "prepare_runtime()" in ios_app
    assert "Network extension active" in ios_app
    assert "Network tunneling active" not in ios_app
    assert "_refresh_native_controls_until_settled" in ios_app
    assert "extension_state = _extension_state(extension)" in ios_app
    assert "_monitor_extension_state" in ios_app
    assert "await asyncio.sleep(5.0)" in ios_app
    assert "_start_extension_state_monitor()" in ios_app
    assert "_refresh_webadmin(force=True)" in ios_app
    assert 'MainWindow(title="")' in ios_app
    assert 'background_color="#15233b"' in ios_app
    assert "_set_operational_surface" in ios_app
    assert "Turn on Network Extension" in ios_app
    assert 'font_size=14, color="#e6edf7"' in ios_app
    assert "OFFLINE" in ios_app
    assert "_resolve_toga_switch_class" in ios_app
    assert "start_runtime if enabled else stop_runtime" in ios_app
    assert 'return _TogaObstacleBridgeApp("ObstacleBridge", "com.obstaclebridge")' in ios_app
    assert "harvestSharedLogs" in control
    assert "runtimeExecutionMode()" in control
    assert "ObstacleBridgeRuntimeConfig.runtimeExecutionMode" in control
    assert "loadSharedRuntimeConfigJSON()" in control
    assert "startSwiftHostRunner()" in control
    assert "prepareSwiftHostRunner()" in control
    assert "refreshSwiftHostRunnerStatus()" in control
    assert "waitForPrivilegedHostRunnerSnapshot" in control
    assert "terminatePrivilegedHostRunnerProcesses" in control
    assert '"swift_host_runner"' in control
    assert "shared_logs_harvested" in control
    assert "syncConfigurationFileInternal" in control
    assert "shared_semantically_newer" in control
    assert "isSemanticallyConfiguredConfig" in control
    assert "if !overlayPeerConfigured(payload: flattenedPayload)" in control
    assert "includedRoutes: []" in control
    assert "includedRoutes6: []" in control
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
    assert 'path == "/api/ios/vpn/status"' in control
    assert 'path == "/api/ios/vpn/control"' in control
    assert "private func appProxyStatusPayload(_ payload: [String: Any]) -> [String: Any]" in control
    assert 'adminUI["platform"] = "ios"' in control
    assert "scheduleAdminTunnelReload" in control
    assert "restart_after_save" in control
    assert "selectCanonicalManager" in control
    assert "removeFromPreferences" in control
    assert "duplicate_cleanup_stop_requested" in control
    assert "preferences_reused" in control
    assert "desiredLocalizedDescription()" in control
    assert "ObstacleBridgeGeneratedBuildStamp.providerBuildTimestampUTC" in control
    assert "legacyLocalizedDescription" not in control
    assert "applyIdentity(" in control
    assert "tunnelProtocol.providerBundleIdentifier = providerBundleIdentifier" in control
    assert '"provider_configuration_mode": "config_derived_profile_persistence"' in control
    assert "needsConfigurationRepair" in control
    assert "desiredManagers" in control
    assert "let desiredManagers = managers.filter { hasCurrentProviderConfiguration($0) }" in control
    assert "let duplicates = managers.filter { $0 !== canonical }" in control
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
    assert "applyingRemoteAdminDefaultsToGroupedPayload" in control
    assert "admin_web_remote_publish" in control
    assert 'channelMux["remote_servers"] = remoteServers' in control
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
    assert "ObstacleBridgeRuntimeConfig.tunnelRoutingOverride" in control
    assert "let routingOverride = ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: payload)" in control
    assert "derivedLocalTunnelSettings(" not in control
    assert "derivedRemoteTunnelSettings(" not in control
    assert "findLocalIOSTunnelService" not in control
    assert "findRemoteTunnelServiceTargetingIOS" not in control
    assert "applyNetworkOverride(" not in control
    assert "loadRuntimeConfigJSON" in control
    assert "ios-native-tunnel-control.jsonl" in control
    assert 'tunRouting["enable_tcpmss"] = false' in control
    assert 'tunRouting["enable_tun_tcpdump"] = false' in control
    assert 'tunRouting["tun_tcpdump_pcap_path"] = ""' in control
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
    assert "ObstacleBridgeAdminSnapshotSupport.selectedProtocolStats(" in host_runner
    assert 'ObstacleBridgeAdminSnapshotSupport.peerMetric(\n                "rtt_est_ms"' in host_runner
    assert '"confirmed_total": myudpProtocolStats["confirmed_total"] ?? 0' in host_runner
    assert "let tunService = ownServerSpecs.first { $0.listenProtocol == \"tun\" && $0.targetProtocol == \"tun\" }" in host_runner
    assert "tunIfname: tunService?.listenBind" in host_runner
    assert "tunPacketSink: { [weak self] packet in" in host_runner
    assert "ensureSharedMacOSTunAdapter(for: tunService)" in host_runner
    assert "deliverLocalTunPacketToActiveOverlay" in host_runner
    assert "deliverRemoteTunPacketToLocalAdapter" in host_runner
    assert '"tun": tunRows' in host_runner
    assert 'tunRouting["tun_control"] = tunControlSnapshot(for: tunHelper, routing: ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: runtimeConfig))' in host_runner
    assert 'payload["tun_control"] = tunControlSnapshot(for: tunHelper, routing: ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: runtimeConfig))' in host_runner
    assert 'routing: ObstacleBridgeTunnelRoutingOverride?' in host_runner
    assert 'let startupEnabled = routing?.enabledOnStartup ?? true' in host_runner
    assert 'env["INCLUDED_ROUTES"] = startupEnabled ? includedRoutes.joined(separator: ",") : ""' in host_runner
    assert 'env["INCLUDED_ROUTES6"] = startupEnabled ? includedRoutes6.joined(separator: ",") : ""' in host_runner
    assert "final class ObstacleBridgeMacOSTunAdapter" in macos_tun
    assert "packet(fromUTUNFrame:" in macos_tun
    assert "utunFrame(for:" in macos_tun


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
    udp_owner = (SHARED_NATIVE_DIR / "ObstacleBridgeUdpOverlayTransportOwner.swift").read_text(encoding="utf-8")
    assert "let protocolStats = overlayRuntime.protocolStatsSnapshot()" in udp_owner
    assert 'snapshot["protocol_stats"] = protocolStats' in udp_owner
