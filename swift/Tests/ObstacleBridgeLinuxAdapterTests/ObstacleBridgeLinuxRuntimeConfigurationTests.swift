import Foundation
import Testing
@testable import ObstacleBridgeLinuxAdapters

struct ObstacleBridgeLinuxRuntimeConfigurationTests {
    @Test func parsesSectionedTcpPskConfiguration() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "tcp"],
            "tcp_session": ["tcp_peer": "127.0.0.1", "tcp_peer_port": 4242],
            "secure_link": ["secure_link_mode": "psk", "secure_link_psk": "test-secret"],
        ]))
        #expect(config.transport == .tcp)
        #expect(config.host == "127.0.0.1")
        #expect(config.port == 4242)
        #expect(config.secureLinkPSK == Data("test-secret".utf8))
    }

    @Test func parsesTcpListenerConfigurationWithoutOutboundPeer() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "tcp", "listener_mode": true],
            "tcp_session": ["tcp_own_port": 4242],
            "secure_link": ["secure_link_mode": "psk", "secure_link_psk": "listener-secret"],
        ]))
        #expect(config.listenerMode)
        #expect(config.port == 4242)
        #expect(config.host == "listener")
    }

    @Test func parsesCleartextWebSocketListenerConfigurationWithoutOutboundPeer() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "ws", "listener_mode": true],
            "ws_session": ["ws_own_port": 4343, "ws_path": "/overlay"],
            "secure_link": ["secure_link_mode": "psk", "secure_link_psk": "listener-secret"],
        ]))
        #expect(config.listenerMode)
        #expect(config.transport == .ws)
        #expect(config.port == 4343)
        #expect(config.webSocketPath == "/overlay")
        #expect(config.host == "listener")
    }

    @Test func parsesCleartextWebSocketAndDefaultsPath() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "ws"],
            "ws_session": ["ws_peer": "peer.example", "ws_peer_port": 8080],
            "secure_link": ["secure_link_mode": "off"],
        ]))
        #expect(config.transport == .ws)
        #expect(config.webSocketPath == "/")
        #expect(config.secureLinkPSK == nil)
    }

    @Test func parsesVerifiedTLSWebSocketConfigurationWithCustomTrustRoots() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "ws"],
            "ws_session": [
                "ws_peer": "peer.example", "ws_peer_port": 443,
                "ws_tls": true, "ws_ca_cert": "/etc/obstaclebridge/wss-roots.pem",
            ],
        ]))
        #expect(config.webSocketTLS)
        #expect(config.webSocketTrustRootsPath == "/etc/obstaclebridge/wss-roots.pem")
    }

    @Test func parsesWebSocketTextPayloadMode() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "ws"],
            "ws_session": ["ws_peer": "peer.example", "ws_peer_port": 8080, "ws_payload_mode": "json-base64"],
        ]))
        #expect(config.webSocketPayloadMode == "json-base64")
    }

    @Test func parsesBoundedMuxCompressionConfiguration() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "tcp"],
            "tcp_session": ["tcp_peer": "peer.example", "tcp_peer_port": 4242],
            "compress_layer": true,
            "compress_layer_level": 99,
            "compress_layer_min_bytes": -1,
            "compress_layer_types": "data, open, unknown",
        ]))
        #expect(config.compressionPolicy.enabled)
        #expect(config.compressionPolicy.level == 9)
        #expect(config.compressionPolicy.minimumBodyBytes == 0)
        #expect(config.compressionPolicy.allowedMessageTypes == [0, 1])
        #expect(config.receiveIdleTimeoutMilliseconds == 5_000)
        #expect(throws: ObstacleBridgeLinuxRuntimeConfigurationError.unsupportedCompressionAlgorithm("Linux compress_layer_algo=brotli is unavailable")) {
            try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
                "runner": ["overlay_transport": "tcp"],
                "tcp_session": ["tcp_peer": "peer.example", "tcp_peer_port": 4242],
                "compress_layer_algo": "brotli",
            ]))
        }
    }

    @Test func parsesSectionedMyudpConfiguration() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "myudp"],
            "udp_session": ["udp_peer": "127.0.0.1", "udp_peer_port": 4242],
        ]))
        #expect(config.transport == .myudp)
        #expect(config.host == "127.0.0.1")
        #expect(config.port == 4242)
    }

    @Test func parsesSectionedQuicConfigurationWithExplicitTrustPosture() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "quic"],
            "quic_session": ["quic_peer": "127.0.0.1", "quic_peer_port": 4242, "quic_alpn": "hq-29", "quic_insecure": true, "quic_ca_cert": "/etc/obstaclebridge/roots.pem"],
        ]))
        #expect(config.transport == .quic)
        #expect(config.host == "127.0.0.1")
        #expect(config.port == 4242)
        #expect(config.quicALPN == "hq-29")
        #expect(config.quicInsecure)
        #expect(config.quicTrustRootsPath == "/etc/obstaclebridge/roots.pem")
    }

    @Test func parsesAuthenticatedMyudpListenerConfigurationWithoutOutboundPeer() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "myudp", "listener_mode": true],
            "udp_session": ["udp_own_port": 4242],
            "secure_link": ["secure_link_mode": "psk", "secure_link_psk": "listener-secret"],
        ]))
        #expect(config.listenerMode)
        #expect(config.transport == .myudp)
        #expect(config.port == 4242)
        #expect(config.host == "listener")
        #expect(config.secureLinkPSK == Data("listener-secret".utf8))
    }

    @Test func parsesStructuredOwnAndRemoteServices() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "tcp"],
            "tcp_session": ["tcp_peer": "127.0.0.1", "tcp_peer_port": 4242],
            "channel_mux": [
                "own_servers": [[
                    "name": "tcp-echo",
                    "listen": ["protocol": "tcp", "bind": "127.0.0.1", "port": 7001],
                    "target": ["protocol": "tcp", "host": "127.0.0.1", "port": 7002],
                ]],
                "remote_servers": [[
                    "listen": ["protocol": "udp", "bind": "127.0.0.1", "port": 8001],
                    "target": ["protocol": "udp", "host": "127.0.0.1", "port": 8002],
                ]],
            ],
        ]))
        #expect(config.ownServices.count == 1)
        #expect(config.ownServices[0].name == "tcp-echo")
        #expect(config.ownServices[0].listenProtocol == .tcp)
        #expect(config.remoteServices[0].targetProtocol == .udp)
    }

    @Test func rejectsUnsupportedOrMismatchedServiceDefinitions() {
        #expect(throws: ObstacleBridgeLinuxRuntimeConfigurationError.invalidService("runtime config has invalid own_servers service at index 0")) {
            try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
                "runner": ["overlay_transport": "tcp"],
                "tcp_session": ["tcp_peer": "127.0.0.1", "tcp_peer_port": 4242],
                "own_servers": [[
                    "listen": ["protocol": "tcp", "bind": "127.0.0.1", "port": 7001],
                    "target": ["protocol": "udp", "host": "127.0.0.1", "port": 7002],
                ]],
            ]))
        }
    }

    @Test func rejectsUnqualifiedOrUnsafeRuntimeChoicesBeforeNetworking() {
        #expect(throws: ObstacleBridgeLinuxRuntimeConfigurationError.missingValue("runtime config requires quic_session.quic_peer")) {
            try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json(["runner": ["overlay_transport": "quic"]]))
        }
        #expect(throws: ObstacleBridgeLinuxRuntimeConfigurationError.unavailableTransport("Linux QUIC listener mode is unavailable until LSW-005B.2 qualifies the backend's inbound-stream ownership")) {
            try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
                "runner": ["overlay_transport": "quic", "listener_mode": true],
                "quic_session": ["quic_own_port": 4242],
            ]))
        }
        #expect(throws: ObstacleBridgeLinuxRuntimeConfigurationError.missingPSK) {
            try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
                "runner": ["overlay_transport": "tcp"],
                "tcp_session": ["tcp_peer": "peer.example", "tcp_peer_port": 443],
                "secure_link": ["secure_link_mode": "psk"],
            ]))
        }
        #expect(throws: ObstacleBridgeLinuxRuntimeConfigurationError.unavailableTransport("Linux Swift TUN is unavailable until LSW-005 delivers the /dev/net/tun adapter; no Python fallback is used")) {
            try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
                "runner": ["overlay_transport": "tcp"],
                "tcp_session": ["tcp_peer": "peer.example", "tcp_peer_port": 443],
                "TUN_routing": ["enabled_on_startup": true],
            ]))
        }
        #expect(throws: ObstacleBridgeLinuxRuntimeConfigurationError.unavailableTransport("Linux Swift proxy mode is unavailable; run a supported Python deployment explicitly instead of expecting fallback")) {
            try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
                "runner": ["overlay_transport": "tcp"],
                "tcp_session": ["tcp_peer": "peer.example", "tcp_peer_port": 443],
                "proxy_provider": ["enabled": true],
            ]))
        }
        #expect(throws: ObstacleBridgeLinuxRuntimeConfigurationError.unavailableTransport("Linux Swift package/service-manager mode is unavailable; run the foreground executable under an operator-owned supervisor")) {
            try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
                "runner": ["overlay_transport": "tcp", "service_mode": true],
                "tcp_session": ["tcp_peer": "peer.example", "tcp_peer_port": 443],
            ]))
        }
    }

    @Test func runtimeStatusReportsAdmissionStateWithoutLeakingPsk() throws {
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(
            transport: .tcp,
            host: "first.example,second.example",
            port: 4242,
            secureLinkPSK: Data("must-not-appear".utf8)
        ))
        let status = runtime.status()
        #expect(status.transport == "tcp")
        #expect(status.state == "disconnected")
        #expect(status.configuredCandidates == ["first.example", "second.example"])
        #expect(status.activeHost == nil)
        #expect(status.secureLinkMode == "psk")
        #expect(status.secureLinkState == "disconnected")
        #expect(!status.appReady)
        let encoded = try JSONEncoder().encode(status)
        #expect(!String(decoding: encoded, as: UTF8.self).contains("must-not-appear"))
    }

    private func json(_ value: [String: Any]) -> Data {
        try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    }
}
