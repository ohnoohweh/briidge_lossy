import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Testing
@testable import ObstacleBridgeLinuxAdapters
@testable import ObstacleBridgeCore

struct ObstacleBridgeLinuxAdminServerTests {
    @Test func configurationStoreUsesCoreValidationAndPersistsOnlyAcceptedUpdates() throws {
        let store = ObstacleBridgeLinuxAdminConfigurationStore(configuration: [
            "admin_web": ["admin_web_auth_disable": false, "admin_web_first_tab": "home"],
        ])
        let saved = try store.apply(updates: ["admin_web_auth_disable": true, "admin_web_first_tab": "status"])
        let admin = try #require(saved.configuration["admin_web"] as? [String: Any])
        #expect(admin["admin_web_auth_disable"] as? Bool == true)
        #expect(admin["admin_web_first_tab"] as? String == "status")
        #expect(throws: (any Error).self) { try store.apply(updates: ["admin_web_auth_disable": "true"]) }
        #expect(throws: (any Error).self) { try store.apply(updates: ["unknown": true]) }
        #expect((store.snapshot()["admin_web"] as? [String: Any])?["admin_web_auth_disable"] as? Bool == true)
    }

    @Test func configurationStoreUsesCoreAdminCredentialUpdatePolicy() throws {
        let store = ObstacleBridgeLinuxAdminConfigurationStore(configuration: [
            "admin_web": ["admin_web_auth_disable": false, "admin_web_username": "operator", "admin_web_password": "secret"],
        ])
        let disabled = try store.apply(updates: ["admin_web_auth_disable": true])
        let disabledAdmin = try #require(disabled.configuration["admin_web"] as? [String: Any])
        #expect(disabledAdmin["admin_web_auth_disable"] as? Bool == true)
        #expect(disabledAdmin["admin_web_username"] as? String == "")
        #expect(disabledAdmin["admin_web_password"] as? String == "")

        let preserved = try store.apply(updates: ["admin_web_password": ""])
        let preservedAdmin = try #require(preserved.configuration["admin_web"] as? [String: Any])
        #expect(preservedAdmin["admin_web_auth_disable"] as? Bool == true)
        #expect(preservedAdmin["admin_web_username"] as? String == "")
    }

    @Test func configHTTPUpdatePersistsValidatedFieldsAndRejectsInvalidInput() async throws {
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .tcp, host: "127.0.0.1", port: 1))
        let store = ObstacleBridgeLinuxAdminConfigurationStore(configuration: ["admin_web": ["admin_web_auth_disable": false]])
        let server = ObstacleBridgeLinuxAdminServer(runtime: runtime, configurationStore: store)
        try server.start(); defer { server.stop() }
        let accepted = try #require(try await requestJSON(
            "http://127.0.0.1:\(server.port)/api/config",
            method: "POST",
            body: ["updates": ["admin_web_auth_disable": true]]
        ).body as? [String: Any])
        #expect(accepted["ok"] as? Bool == true)
        #expect((store.snapshot()["admin_web"] as? [String: Any])?["admin_web_auth_disable"] as? Bool == true)
        let rejected = try await requestJSON(
            "http://127.0.0.1:\(server.port)/api/config",
            method: "POST",
            body: ["updates": ["admin_web_auth_disable": "true"]]
        )
        #expect(rejected.status == 400)
        #expect((rejected.body as? [String: Any])?["ok"] as? Bool == false)
    }

    @Test func onboardingHTTPUsesCoreTokenPolicyAndFailsClosedForSecrets() async throws {
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .tcp, host: "127.0.0.1", port: 1))
        let server = ObstacleBridgeLinuxAdminServer(runtime: runtime, adminConfiguration: [
            "runner": ["overlay_transport": "tcp"],
            "tcp_session": ["tcp_peer": "127.0.0.1", "tcp_peer_port": 4242],
        ])
        try server.start(); defer { server.stop() }
        let generated = try #require(try await requestJSON(
            "http://127.0.0.1:\(server.port)/api/onboarding/invite", method: "POST", body: [:]
        ).body as? [String: Any])
        let token = try #require(generated["invite_token"] as? String)
        let preview = try #require(try await requestJSON(
            "http://127.0.0.1:\(server.port)/api/onboarding/preview", method: "POST", body: ["invite_token": token]
        ).body as? [String: Any])
        #expect(preview["ok"] as? Bool == true)

        let secretServer = ObstacleBridgeLinuxAdminServer(runtime: runtime, adminConfiguration: ["secure_link_psk": "no-linux-key-owner"])
        try secretServer.start(); defer { secretServer.stop() }
        let rejected = try await requestJSON("http://127.0.0.1:\(secretServer.port)/api/onboarding/invite", method: "POST", body: [:])
        #expect(rejected.status == 400)
        #expect((rejected.body as? [String: Any])?["ok"] as? Bool == false)
    }

    @Test func statusAndPeersAreRedactedAndDescribeLayeredState() async throws {
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(
            transport: .tcp,
            host: "first.example,second.example",
            port: 4242,
            secureLinkPSK: Data("never-expose-this".utf8)
        ))
        let server = ObstacleBridgeLinuxAdminServer(runtime: runtime, adminConfiguration: [
            "runner": ["overlay_transport": "tcp"],
            "secure_link": ["secure_link_mode": "psk", "secure_link_psk": "never-expose-this"],
            "admin_web": ["admin_web": true, "admin_web_auth_disable": true],
        ])
        try server.start()
        defer { server.stop() }
        let status = try #require(try await getJSON("http://127.0.0.1:\(server.port)/api/status") as? [String: Any])
        #expect(status["overlay_transport"] as? String == "tcp")
        #expect(status["transport_state"] as? String == "disconnected")
        #expect(status["app_ready"] as? Bool == false)
        let layers = status["connection_layers"] as? [[String: Any]]
        #expect(layers?.count == 2)
        let mux = status["channel_mux"] as? [String: Any]
        #expect(mux?["tcp_open"] as? Int == 0)
        #expect(mux?["udp_open"] as? Int == 0)
        #expect(mux?["dropped_frames"] as? Int == 0)
        let receiveLoop = status["receive_loop"] as? [String: Any]
        #expect(receiveLoop?["state"] as? String == "stopped")
        #expect(receiveLoop?["queue_depth"] as? Int == 0)
        let capabilities = try #require(status["operator_capabilities"] as? [String: Any])
        #expect(capabilities["tun_device_present"] as? Bool != nil)
        #expect(capabilities["net_admin_effective"] as? Bool != nil)
        #expect(capabilities["ip_available"] as? Bool != nil)
        #expect(capabilities["resolvectl_available"] as? Bool != nil)
        #expect(capabilities["iptables_available"] as? Bool != nil)
        #expect(capabilities["privileged_tun_ready"] as? Bool != nil)
        #expect(capabilities["guidance"] as? [String] != nil)
        #expect(!String(decoding: try JSONSerialization.data(withJSONObject: status), as: UTF8.self).contains("never-expose-this"))

        let peers = try await getJSON("http://127.0.0.1:\(server.port)/api/peers")
        let rows = peers as? [[String: Any]]
        #expect(rows?.first?["configured_candidates"] as? [String] == ["first.example", "second.example"])
        #expect(rows?.first?["failure_reason"] is NSNull)
        let live = try #require(try await getJSON("http://127.0.0.1:\(server.port)/api/live?topic=status") as? [String: Any])
        #expect(live["overlay_transport"] as? String == "tcp")
        #expect(ObstacleBridgeAdminLiveTopicPolicyPort.normalizedTopic(" PeErS ") == "peers")
        #expect(ObstacleBridgeAdminLiveTopicPolicyPort.normalizedTopic("unknown") == nil)
        for _ in 0..<2 {
            let socket = URLSession.shared.webSocketTask(with: try #require(URL(string: "ws://127.0.0.1:\(server.port)/api/live?topic=status")))
            socket.resume()
            for _ in 0..<2 {
                let message = try await socket.receive()
                let data: Data
                switch message {
                case .data(let value): data = value
                case .string(let value): data = Data(value.utf8)
                @unknown default: throw URLError(.badServerResponse)
                }
                #expect((try JSONSerialization.jsonObject(with: data) as? [String: Any])?["overlay_transport"] as? String == "tcp")
            }
            socket.cancel()
        }
        let config = try #require(try await getJSON("http://127.0.0.1:\(server.port)/api/config") as? [String: Any])
        let exported = try #require(config["config"] as? [String: Any])
        let secure = try #require(exported["secure_link"] as? [String: Any])
        #expect(secure["secure_link_psk"] as? String == "***hidden***")
        #expect(secure["secure_link_psk_present"] as? Bool == true)
        #expect(!String(decoding: try JSONSerialization.data(withJSONObject: config), as: UTF8.self).contains("never-expose-this"))
        let advisor = try #require(try await getJSON("http://127.0.0.1:\(server.port)/api/security-advisor") as? [String: Any])
        #expect(advisor["highest_severity"] as? String == "recommended")
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

    @Test func liveStatusCorrelatesRedactedResourceHealth() async throws {
        let runtime = ObstacleBridgeLinuxLiveRuntime(configuration: .init(
            transport: .tcp, host: "127.0.0.1", port: 1,
            tunHelperSocketPath: "/tmp/obstaclebridge-helper-control.sock",
            tunHelperSessionToken: "never-expose-helper-token"
        ))
        let server = ObstacleBridgeLinuxAdminServer(liveRuntime: runtime)
        try server.start()
        defer { server.stop() }
        let status = try #require(try await getJSON("http://127.0.0.1:\(server.port)/api/status") as? [String: Any])
        let resources = try #require(status["resource_health"] as? [String: Any])
        let packetTunnel = try #require(resources["packet_tunnel"] as? [String: Any])
        let serviceSockets = try #require(resources["service_sockets"] as? [String: Any])
        #expect(packetTunnel["configured"] as? Bool == false)
        #expect(packetTunnel["helper_configured"] as? Bool == true)
        #expect(packetTunnel["managed_helper_running"] as? Bool == false)
        #expect(packetTunnel["device_open"] as? Bool == false)
        #expect(packetTunnel["network_policy_applied"] as? Bool == false)
        #expect(serviceSockets["configured_local"] as? Int == 0)
        #expect(serviceSockets["active_local"] as? Int == 0)
        #expect(serviceSockets["active_remote"] as? Int == 0)
        let serialized = String(decoding: try JSONSerialization.data(withJSONObject: status), as: UTF8.self)
        #expect(!serialized.contains("obstaclebridge-helper-control.sock"))
        #expect(!serialized.contains("never-expose-helper-token"))
    }

    @Test func peerProjectionUsesCoreCountersAndNeverSerializesPSK() async throws {
        let peer = try PythonOverlayPeer(mode: "tcp-securelink")
        defer { peer.stop() }
        let secret = "linux-swift-psk"
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(
            transport: .tcp,
            host: "127.0.0.1",
            port: peer.port,
            secureLinkPSK: Data(secret.utf8)
        ))
        let server = ObstacleBridgeLinuxAdminServer(runtime: runtime)
        try server.start()
        defer { server.stop(); runtime.disconnect() }

        let session = try runtime.connect(sessionID: 77, clientNonce: Data(repeating: 7, count: 32))
        #expect(try session.send(Data("projection".utf8)) == Data("python:projection".utf8))
        let peers = try #require(try await getJSON("http://127.0.0.1:\(server.port)/api/peers") as? [[String: Any]])
        let row = try #require(peers.first)
        let secureLink = try #require(row["secure_link"] as? [String: Any])
        let compression = try #require(row["compression_layer"] as? [String: Any])
        #expect(row["peer_id"] as? String == "configured-peer")
        #expect(row["transport"] as? String == "tcp")
        #expect(row["connection_epoch"] as? Int == 1)
        #expect(row["app_ready"] as? Bool == true)
        #expect(secureLink["authenticated"] as? Bool == true)
        #expect(secureLink["state"] as? String == "authenticated")
        #expect(secureLink["session_id"] as? UInt64 == 77)
        #expect(secureLink["protected_tx_counter"] as? UInt64 == 3)
        #expect(secureLink["protected_rx_counter"] as? UInt64 == 2)
        #expect(secureLink["protected_frames_sent_total"] as? UInt64 == 1)
        #expect(secureLink["protected_frames_received_total"] as? UInt64 == 1)
        #expect(secureLink["authenticated_generations_total"] as? UInt64 == 1)
        #expect(compression["enabled"] as? Bool == false)
        #expect(compression["algorithm"] as? String == "zlib")
        #expect(compression["compressed_frames_sent_total"] as? UInt64 == 0)
        #expect(compression["compressed_output_bytes_sent_total"] as? UInt64 == 0)
        #expect(compression["rejected_frames_total"] as? UInt64 == 0)
        #expect(!String(decoding: try JSONSerialization.data(withJSONObject: peers), as: UTF8.self).contains(secret))
    }

    @Test func peersSerializesNonzeroCompressionTelemetry() async throws {
        let peer = try PythonOverlayPeer(mode: "tcp-securelink-mux-compressed-echo")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(
            transport: .tcp, host: "127.0.0.1", port: peer.port,
            secureLinkPSK: Data("linux-swift-psk".utf8),
            compressionPolicy: .init(enabled: true, level: 3, minimumBodyBytes: 1, allowedMessageTypes: [0])
        ))
        let server = ObstacleBridgeLinuxAdminServer(runtime: runtime)
        try server.start()
        defer { server.stop(); runtime.disconnect() }
        let session = try runtime.connect(sessionID: 78, clientNonce: Data(repeating: 8, count: 32))
        let mux = try ObstacleBridgeLinuxChannelMuxSession(runtime: runtime, session: session)
        let frame = ObstacleBridgeChannelMuxFrame(channelID: 1, protocolType: .udp, counter: 1, messageType: .data, body: Data(repeating: 0x41, count: 256))
        #expect(try mux.exchange(frame) == frame)

        let peers = try #require(try await getJSON("http://127.0.0.1:\(server.port)/api/peers") as? [[String: Any]])
        let row = try #require(peers.first)
        let compression = try #require(row["compression_layer"] as? [String: Any])
        #expect(compression["enabled"] as? Bool == true)
        #expect(compression["compress_applied_total"] as? UInt64 == 1)
        #expect(compression["compressed_frames_sent_total"] as? UInt64 == 1)
        #expect(compression["compressed_frames_received_total"] as? UInt64 == 1)
        #expect((compression["compressed_output_bytes_sent_total"] as? UInt64 ?? 256) < 256)
    }

    @Test func myudpListenerAdminProjectsEachAuthenticatedPeerWithoutPSK() async throws {
        let secret = "linux-swift-psk"
        let listener = try ObstacleBridgeLinuxMyUDPListenerRuntime(configuration: .init(
            transport: .myudp, host: "listener", port: 0, listenerMode: true,
            secureLinkPSK: Data(secret.utf8)
        ))
        let server = ObstacleBridgeLinuxAdminServer(myudpListenerRuntime: listener)
        try server.start()
        listener.start()
        defer { listener.stop(); server.stop() }
        let connected = DispatchSemaphore(value: 0)
        for identifier in 1...2 {
            DispatchQueue.global().async {
                let client = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(
                    transport: .myudp, host: "127.0.0.1", port: listener.port,
                    secureLinkPSK: Data(secret.utf8)
                ))
                _ = try? client.connect(sessionID: UInt64(identifier), clientNonce: Data(repeating: UInt8(identifier), count: 32))
                connected.signal()
            }
        }
        #expect(connected.wait(timeout: .now() + 3) == .success)
        #expect(connected.wait(timeout: .now() + 3) == .success)
        let deadline = Date().addingTimeInterval(3)
        while listener.peers().count != 2, Date() < deadline { try await Task.sleep(for: .milliseconds(10)) }
        let rows = try #require(try await getJSON("http://127.0.0.1:\(server.port)/api/peers") as? [[String: Any]])
        #expect(rows.count == 2)
        #expect(Set(rows.compactMap { $0["peer_id"] as? String }).count == 2)
        #expect(rows.allSatisfy { ($0["secure_link"] as? [String: Any])?["authenticated"] as? Bool == true })
        #expect(!String(decoding: try JSONSerialization.data(withJSONObject: rows), as: UTF8.self).contains(secret))
    }

    private func getJSON(_ text: String) async throws -> Any {
        let (data, response) = try await URLSession.shared.data(from: try #require(URL(string: text)))
        #expect((response as? HTTPURLResponse)?.statusCode == 200)
        return try JSONSerialization.jsonObject(with: data)
    }

    private func requestJSON(_ text: String, method: String, body: [String: Any]) async throws -> (status: Int, body: Any) {
        var request = URLRequest(url: try #require(URL(string: text)))
        request.httpMethod = method
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let (data, response) = try await URLSession.shared.data(for: request)
        return (try #require((response as? HTTPURLResponse)?.statusCode), try JSONSerialization.jsonObject(with: data))
    }
}
