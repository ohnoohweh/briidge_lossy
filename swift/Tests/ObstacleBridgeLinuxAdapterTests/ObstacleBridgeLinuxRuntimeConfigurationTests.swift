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

    @Test func parsesSectionedMyudpConfiguration() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "myudp"],
            "udp_session": ["udp_peer": "127.0.0.1", "udp_peer_port": 4242],
        ]))
        #expect(config.transport == .myudp)
        #expect(config.host == "127.0.0.1")
        #expect(config.port == 4242)
    }

    @Test func rejectsUnqualifiedOrUnsafeRuntimeChoicesBeforeNetworking() {
        #expect(throws: ObstacleBridgeLinuxRuntimeConfigurationError.unavailableTransport("Linux QUIC is unavailable: the Network.framework owner has no qualified Linux backend")) {
            try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json(["runner": ["overlay_transport": "quic"]]))
        }
        #expect(throws: ObstacleBridgeLinuxRuntimeConfigurationError.unsupportedWebSocketTLS) {
            try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
                "runner": ["overlay_transport": "ws"],
                "ws_session": ["ws_peer": "peer.example", "ws_peer_port": 443, "ws_tls": true],
            ]))
        }
        #expect(throws: ObstacleBridgeLinuxRuntimeConfigurationError.missingPSK) {
            try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
                "runner": ["overlay_transport": "tcp"],
                "tcp_session": ["tcp_peer": "peer.example", "tcp_peer_port": 443],
                "secure_link": ["secure_link_mode": "psk"],
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
