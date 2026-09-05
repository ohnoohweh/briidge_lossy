import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Testing
@testable import ObstacleBridgeLinuxAdapters

struct ObstacleBridgeLinuxAdminServerTests {
    @Test func statusAndPeersAreRedactedAndDescribeLayeredState() async throws {
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(
            transport: .tcp,
            host: "first.example,second.example",
            port: 4242,
            secureLinkPSK: Data("never-expose-this".utf8)
        ))
        let server = ObstacleBridgeLinuxAdminServer(runtime: runtime)
        try server.start()
        defer { server.stop() }
        let status = try #require(try await getJSON("http://127.0.0.1:\(server.port)/api/status") as? [String: Any])
        #expect(status["overlay_transport"] as? String == "tcp")
        #expect(status["transport_state"] as? String == "disconnected")
        #expect(status["app_ready"] as? Bool == false)
        let layers = status["connection_layers"] as? [[String: Any]]
        #expect(layers?.count == 2)
        #expect(!String(decoding: try JSONSerialization.data(withJSONObject: status), as: UTF8.self).contains("never-expose-this"))

        let peers = try await getJSON("http://127.0.0.1:\(server.port)/api/peers")
        let rows = peers as? [[String: Any]]
        #expect(rows?.first?["configured_candidates"] as? [String] == ["first.example", "second.example"])
        #expect(rows?.first?["failure_reason"] is NSNull)
    }

    @Test func statusReflectsConnectAndDisconnectTransitions() async throws {
        let peer = try PythonOverlayPeer(mode: "tcp")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .tcp, host: "127.0.0.1", port: peer.port))
        let server = ObstacleBridgeLinuxAdminServer(runtime: runtime)
        try server.start()
        defer { server.stop() }
        _ = try runtime.connect(sessionID: 1, clientNonce: Data(repeating: 1, count: 32))
        let connected = try #require(try await getJSON("http://127.0.0.1:\(server.port)/api/status") as? [String: Any])
        #expect(connected["transport_state"] as? String == "connected")
        #expect(connected["app_ready"] as? Bool == true)
        runtime.disconnect()
        let disconnected = try #require(try await getJSON("http://127.0.0.1:\(server.port)/api/status") as? [String: Any])
        #expect(disconnected["transport_state"] as? String == "disconnected")
        #expect(disconnected["app_ready"] as? Bool == false)
    }

    private func getJSON(_ text: String) async throws -> Any {
        let (data, response) = try await URLSession.shared.data(from: try #require(URL(string: text)))
        #expect((response as? HTTPURLResponse)?.statusCode == 200)
        return try JSONSerialization.jsonObject(with: data)
    }
}
