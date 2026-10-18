import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Testing
@testable import ObstacleBridgeLinuxAdapters
@testable import ObstacleBridgeCore

struct ObstacleBridgeLinuxAdminServerTests {
    @Test func logsEndpointReturnsBoundedRedactedNativeDiagnostics() async throws {
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .tcp, host: "127.0.0.1", port: 1))
        let server = ObstacleBridgeLinuxAdminServer(
            runtime: runtime,
            debugLogsProvider: { limit in Array(["attempt candidate=example.test", "failed reason=timeout"].suffix(limit)) }
        )
        try server.start(); defer { server.stop() }
        let payload = try #require(try await getJSON("http://127.0.0.1:\(server.port)/api/logs?limit=1") as? [String: Any])
        #expect(payload["ok"] as? Bool == true)
        #expect(payload["logger_available"] as? Bool == true)
        #expect(payload["lines"] as? [String] == ["failed reason=timeout"])
    }

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

    @Test func configurationStorePersistsPythonCompatibleEncryptedSecrets() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("ObstacleBridge.cfg").path
        let store = ObstacleBridgeLinuxAdminConfigurationStore(configuration: [
            "runner": ["overlay_transport": "tcp"],
            "tcp_session": ["tcp_peer": "127.0.0.1", "tcp_peer_port": 4242],
            "secure_link": ["secure_link_mode": "psk", "secure_link_psk": "old-secret"],
            "admin_web": ["admin_web_password": "old-admin-password"],
        ], path: path)

        let saved = try store.apply(updates: ["secure_link_psk": "new-secret", "admin_web_password": "new-admin-password"])
        let persisted = try String(contentsOfFile: path, encoding: .utf8)
        #expect(!persisted.contains("old-secret"))
        #expect(!persisted.contains("new-secret"))
        #expect(!persisted.contains("old-admin-password"))
        #expect(!persisted.contains("new-admin-password"))
        #expect(persisted.contains("enc:v1:"))
        #expect((saved.configuration["secure_link"] as? [String: Any])?["secure_link_psk"] as? String != "new-secret")
        #expect(try ObstacleBridgeLinuxRuntimeConfiguration.load(path: path).secureLinkPSK == Data("new-secret".utf8))
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

    @Test func adminAuthenticationUsesSharedCoreChallengesAndGuardsNativeRoutes() async throws {
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .tcp, host: "127.0.0.1", port: 1))
        let store = ObstacleBridgeLinuxAdminConfigurationStore(configuration: [
            "admin_web": ["admin_web_auth_disable": false, "admin_web_username": "operator", "admin_web_password": "secret"],
            "secure_link": ["secure_link_mode": "psk", "secure_link_psk": "linux-reveal-secret"],
        ])
        let server = ObstacleBridgeLinuxAdminServer(runtime: runtime, configurationStore: store)
        try server.start()
        defer { server.stop() }
        let base = "http://127.0.0.1:\(server.port)"

        let denied = try await requestJSON(base + "/api/status", method: "GET", body: [:])
        #expect(denied.status == 401)
        #expect((denied.body as? [String: Any])?["error"] as? String == "authentication required")

        let challenge = try #require((try await requestJSON(base + "/api/auth/challenge", method: "GET", body: [:])).body as? [String: Any])
        let challengeID = try #require(challenge["challenge_id"] as? String)
        let seed = try #require(challenge["seed"] as? String)
        let proof = digest("\(seed):operator:secret")
        let login = try await requestJSON(base + "/api/auth/login", method: "POST", body: ["challenge_id": challengeID, "proof": proof])
        #expect(login.status == 200)
        let cookie = try #require(login.headers["Set-Cookie"]?.split(separator: ";").first.map(String.init))

        let admitted = try await requestJSON(base + "/api/status", method: "GET", body: [:], headers: ["Cookie": cookie])
        #expect(admitted.status == 200)
        let unconfirmed = try await requestJSON(base + "/api/config", method: "POST", body: ["updates": ["admin_web_name": "Updated"]], headers: ["Cookie": cookie])
        #expect(unconfirmed.status == 428)

        let updates: [String: Any] = ["admin_web_name": "Updated"]
        let configChallenge = try #require((try await requestJSON(base + "/api/config/challenge", method: "POST", body: ["updates": updates], headers: ["Cookie": cookie])).body as? [String: Any])
        let configID = try #require(configChallenge["challenge_id"] as? String)
        let configSeed = try #require(configChallenge["seed"] as? String)
        let updatesDigest = try #require(configChallenge["updates_digest"] as? String)
        let configProof = digest("\(configSeed):operator:secret:\(updatesDigest)")
        let saved = try await requestJSON(base + "/api/config", method: "POST", body: ["updates": updates, "challenge_id": configID, "proof": configProof], headers: ["Cookie": cookie])
        #expect(saved.status == 200)
        #expect((saved.body as? [String: Any])?["ok"] as? Bool == true)
        #expect((store.snapshot()["admin_web"] as? [String: Any])?["admin_web_name"] as? String == "Updated")
        let effectiveConfiguration = try store.runtimeSnapshot()
        #expect((effectiveConfiguration["secure_link"] as? [String: Any])?["secure_link_psk"] as? String == "linux-reveal-secret")

        let revealChallenge = try #require((try await requestJSON(base + "/api/config/secret/secure-link-psk/challenge", method: "POST", body: [:], headers: ["Cookie": cookie])).body as? [String: Any])
        let revealID = try #require(revealChallenge["challenge_id"] as? String)
        let revealSeed = try #require(revealChallenge["seed"] as? String)
        let revealProof = digest("\(revealSeed):operator:secret:secure_link_psk")
        let revealed = try #require((try await requestJSON(base + "/api/config/secret/secure-link-psk", method: "POST", body: ["challenge_id": revealID, "proof": revealProof], headers: ["Cookie": cookie])).body as? [String: Any])
        let envelope = try #require(revealed["encrypted"] as? [String: Any])
        #expect(String(describing: envelope).contains("linux-reveal-secret") == false)
        let saltText = try #require(envelope["salt"] as? String)
        let nonceText = try #require(envelope["nonce"] as? String)
        let ciphertextText = try #require(envelope["ciphertext"] as? String)
        let aadText = try #require(envelope["aad"] as? String)
        let salt = try #require(Data(base64Encoded: saltText))
        let nonce = try #require(Data(base64Encoded: nonceText))
        let ciphertext = try #require(Data(base64Encoded: ciphertextText))
        let aad = try #require(Data(base64Encoded: aadText))
        let key = try ObstacleBridgeCrypto.pbkdf2SHA256(password: Data("secret".utf8), salt: salt, iterations: 200_000, outputByteCount: 32)
        let plaintext = try ObstacleBridgeCrypto.aesGCMOpen(ciphertextAndTag: ciphertext, key: key, nonce: nonce, authenticatedData: aad)
        #expect(String(decoding: plaintext, as: UTF8.self) == "linux-reveal-secret")
    }

    @Test func adminWebConfigurationAndLifecycleControlsMatchThePythonClientContract() async throws {
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .tcp, host: "127.0.0.1", port: 1))
        let store = ObstacleBridgeLinuxAdminConfigurationStore(configuration: [
            "admin_web": ["admin_web_auth_disable": true, "admin_web_name": "Linux native"],
        ])
        let reconnected = DispatchSemaphore(value: 0)
        let rekeyed = DispatchSemaphore(value: 0)
        let restarted = DispatchSemaphore(value: 0)
        let shutdownRequested = DispatchSemaphore(value: 0)
        let server = ObstacleBridgeLinuxAdminServer(
            runtime: runtime,
            configurationStore: store,
            reconnectHandler: { reconnected.signal() },
            secureLinkRekeyHandler: { peerID in
                guard peerID == "configured-peer" else { return ["ok": false, "reason": "unknown_peer_id"] }
                rekeyed.signal()
                return ["ok": true, "reason": "rekey_started"]
            },
            restartHandler: { restarted.signal() },
            shutdownHandler: { shutdownRequested.signal() }
        )
        try server.start(); defer { server.stop() }
        let base = "http://127.0.0.1:\(server.port)"

        let configuration = try #require(try await getJSON(base + "/api/config") as? [String: Any])
        #expect(configuration["ok"] as? Bool == true)
        let values = try #require(configuration["config"] as? [String: Any])
        #expect(values["admin_web_name"] as? String == "Linux native")
        let schema = try #require(configuration["schema"] as? [String: Any])
        #expect(schema["admin_web"] as? [[String: Any]] != nil)

        let challenge = try #require(try await requestJSON(base + "/api/config/challenge", method: "POST", body: ["updates": ["admin_web_name": "Updated"]]).body as? [String: Any])
        #expect(challenge["ok"] as? Bool == true)
        #expect(challenge["auth_required"] as? Bool == false)
        let saved = try #require(try await requestJSON(base + "/api/config", method: "POST", body: ["updates": ["admin_web_name": "Updated"]]).body as? [String: Any])
        #expect((saved["config"] as? [String: Any])?["admin_web_name"] as? String == "Updated")

        let reconnect = try await requestJSON(base + "/api/reconnect", method: "POST", body: [:])
        #expect(reconnect.status == 200)
        #expect((reconnect.body as? [String: Any])?["ok"] as? Bool == true)
        #expect(reconnected.wait(timeout: .now() + 1) == .success)
        let rekey = try await requestJSON(base + "/api/secure-link/rekey", method: "POST", body: ["peer_id": "configured-peer"])
        #expect(rekey.status == 200)
        #expect((rekey.body as? [String: Any])?["reason"] as? String == "rekey_started")
        #expect(rekeyed.wait(timeout: .now() + 1) == .success)
        let restart = try await requestJSON(base + "/api/restart", method: "POST", body: [:])
        #expect(restart.status == 200)
        #expect((restart.body as? [String: Any])?["restarting"] as? Bool == true)
        #expect(restarted.wait(timeout: .now() + 1) == .success)
        let shutdown = try await requestJSON(base + "/api/shutdown", method: "POST", body: [:])
        #expect(shutdown.status == 200)
        #expect((shutdown.body as? [String: Any])?["shutdown_requested"] as? Bool == true)
        #expect(shutdownRequested.wait(timeout: .now() + 1) == .success)
    }

    @Test func onboardingHTTPUsesCoreTokenPolicyAndCarriesSecretsForRecipientOwnedPersistence() async throws {
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

        let secretServer = ObstacleBridgeLinuxAdminServer(runtime: runtime, adminConfiguration: [
            "runner": ["overlay_transport": "tcp"],
            "tcp_session": ["tcp_peer": "127.0.0.1", "tcp_peer_port": 4242],
            "secure_link": ["secure_link_mode": "psk", "secure_link_psk": "portable-peer-secret"],
        ])
        try secretServer.start(); defer { secretServer.stop() }
        let secretInvite = try await requestJSON("http://127.0.0.1:\(secretServer.port)/api/onboarding/invite", method: "POST", body: [:])
        #expect(secretInvite.status == 200)
        let secretToken = try #require((secretInvite.body as? [String: Any])?["invite_token"] as? String)
        let secretPreview = try #require(try await requestJSON(
            "http://127.0.0.1:\(secretServer.port)/api/onboarding/preview", method: "POST", body: ["invite_token": secretToken]
        ).body as? [String: Any])
        let suggested = try #require(secretPreview["suggested_updates"] as? [String: Any])
        #expect(suggested["secure_link_psk"] as? String == "portable-peer-secret")
    }

    @Test func secretBearingInviteApplyPersistsForReceivingLinuxMachine() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("ObstacleBridge.cfg").path
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .tcp, host: "127.0.0.1", port: 1))
        let source = ObstacleBridgeLinuxAdminServer(runtime: runtime, adminConfiguration: [
            "runner": ["overlay_transport": "tcp"],
            "tcp_session": ["tcp_peer": "198.51.100.10", "tcp_peer_port": 4242],
            "secure_link": ["secure_link_mode": "psk", "secure_link_psk": "invite-secret"],
        ])
        let recipientStore = ObstacleBridgeLinuxAdminConfigurationStore(configuration: [
            "runner": ["overlay_transport": "tcp"],
            "tcp_session": ["tcp_peer": "127.0.0.1", "tcp_peer_port": 1],
        ], path: path)
        let recipient = ObstacleBridgeLinuxAdminServer(runtime: runtime, configurationStore: recipientStore)
        try source.start(); defer { source.stop() }
        try recipient.start(); defer { recipient.stop() }

        let invite = try #require(try await requestJSON(
            "http://127.0.0.1:\(source.port)/api/onboarding/invite", method: "POST", body: [:]
        ).body as? [String: Any])
        let token = try #require(invite["invite_token"] as? String)
        let preview = try #require(try await requestJSON(
            "http://127.0.0.1:\(recipient.port)/api/onboarding/preview", method: "POST", body: ["invite_token": token]
        ).body as? [String: Any])
        let updates = try #require(preview["suggested_updates"] as? [String: Any])
        let applied = try await requestJSON(
            "http://127.0.0.1:\(recipient.port)/api/config", method: "POST", body: ["updates": updates]
        )
        #expect(applied.status == 200)
        let persisted = try String(contentsOfFile: path, encoding: .utf8)
        #expect(!persisted.contains("invite-secret"))
        #expect(persisted.contains("enc:v1:"))
        #expect(try ObstacleBridgeLinuxRuntimeConfiguration.load(path: path).secureLinkPSK == Data("invite-secret".utf8))
    }

    @Test func metaAndOnboardingRoutesMatchTheShippedAdminWebContract() async throws {
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .tcp, host: "127.0.0.1", port: 1))
        let configuration: [String: Any] = [
            "admin_web": ["admin_web_name": "Linux Admin"],
            "runner": ["overlay_transport": "tcp"],
            "tcp_session": ["tcp_peer": "198.51.100.10", "tcp_peer_port": 4433],
        ]
        let server = ObstacleBridgeLinuxAdminServer(
            runtime: runtime, adminConfiguration: configuration,
            buildInfo: ["available": true, "commit": "0123456789ab", "build_timestamp_utc": "2026-10-18T00:00:00Z", "tainted": false, "tracked_changes": 0, "untracked_changes": 0]
        )
        try server.start(); defer { server.stop() }
        let base = "http://127.0.0.1:\(server.port)"

        let meta = try #require(try await getJSON(base + "/api/meta") as? [String: Any])
        #expect(meta["admin_web_name"] as? String == "Linux Admin")
        #expect((meta["build"] as? [String: Any])?["available"] as? Bool == true)
        #expect((meta["build"] as? [String: Any])?["commit"] as? String == "0123456789ab")
        let profiles = try #require(try await getJSON(base + "/api/onboarding/connection-profiles") as? [String: Any])
        let profile = try #require((profiles["profiles"] as? [[String: Any]])?.first)
        #expect(profile["transport"] as? String == "tcp")
        #expect(profile["peer_host"] as? String == "198.51.100.10")
        let blueprints = try #require(try await getJSON(base + "/api/onboarding/blueprints") as? [String: Any])
        #expect(blueprints["blueprints"] as? [[String: Any]] != nil)

        let generated = try #require(try await requestJSON(base + "/api/onboarding/invite/generate", method: "POST", body: ["connection_id": profile["id"] as? String ?? ""]).body as? [String: Any])
        let token = try #require(generated["invite_token"] as? String)
        let preview = try #require(try await requestJSON(base + "/api/onboarding/invite/preview", method: "POST", body: ["invite_token": token]).body as? [String: Any])
        #expect(preview["ok"] as? Bool == true)
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

        let peers = try #require(try await getJSON("http://127.0.0.1:\(server.port)/api/peers") as? [String: Any])
        let rows = peers["peers"] as? [[String: Any]]
        #expect(rows?.first?["configured_candidates"] as? [String] == ["first.example", "second.example"])
        #expect(rows?.first?["failure_reason"] is NSNull)
        let connections = try #require(try await getJSON("http://127.0.0.1:\(server.port)/api/connections") as? [String: Any])
        #expect((connections["tcp"] as? [[String: Any]])?.isEmpty == true)
        #expect((connections["udp"] as? [[String: Any]])?.isEmpty == true)
        let live = try #require(try await getJSON("http://127.0.0.1:\(server.port)/api/live?topic=status") as? [String: Any])
        #expect(live["overlay_transport"] as? String == "tcp")
        #expect(ObstacleBridgeAdminLiveTopicPolicyPort.normalizedTopic(" PeErS ") == "peers")
        #expect(ObstacleBridgeAdminLiveTopicPolicyPort.normalizedTopic("unknown") == nil)
        // The shared browser opens `/api/live` without a query string, then
        // controls topics with masked WebSocket messages.  Linux must use the
        // same subscription protocol and `{ type, data }` envelopes as Apple
        // and Python rather than treating this as a one-topic HTTP endpoint.
        let socket = URLSession.shared.webSocketTask(with: try #require(URL(string: "ws://127.0.0.1:\(server.port)/api/live")))
        socket.resume()
        try await socket.send(.string("{\"subscribe\":[\"status\",\"peers\"],\"active_tabs\":[\"status\"],\"request\":[\"status\",\"peers\"]}"))
        var liveTypes = Set<String>()
        for _ in 0..<4 {
            let message = try await socket.receive()
            let data: Data
            switch message {
            case .data(let value): data = value
            case .string(let value): data = Data(value.utf8)
            @unknown default: throw URLError(.badServerResponse)
            }
            let document = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
            if let type = document["type"] as? String { liveTypes.insert(type) }
            if document["type"] as? String == "status" {
                #expect((document["data"] as? [String: Any])?["overlay_transport"] as? String == "tcp")
            }
            if liveTypes.isSuperset(of: ["hello", "status", "peers"]) { break }
        }
        #expect(liveTypes.contains("hello"))
        #expect(liveTypes.contains("status"))
        #expect(liveTypes.contains("peers"))
        socket.cancel()
        let config = try #require(try await getJSON("http://127.0.0.1:\(server.port)/api/config") as? [String: Any])
        let exported = try #require(config["config"] as? [String: Any])
        #expect(exported["secure_link_psk"] as? String == "***hidden***")
        #expect(exported["secure_link_psk_present"] as? Bool == true)
        #expect(config["schema"] as? [String: Any] != nil)
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
        let peersDocument = try #require(try await getJSON("http://127.0.0.1:\(server.port)/api/peers") as? [String: Any])
        let peers = try #require(peersDocument["peers"] as? [[String: Any]])
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

        let peersDocument = try #require(try await getJSON("http://127.0.0.1:\(server.port)/api/peers") as? [String: Any])
        let peers = try #require(peersDocument["peers"] as? [[String: Any]])
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
        let peersDocument = try #require(try await getJSON("http://127.0.0.1:\(server.port)/api/peers") as? [String: Any])
        let rows = try #require(peersDocument["peers"] as? [[String: Any]])
        #expect(rows.count == 2)
        #expect(Set(rows.compactMap { $0["peer_id"] as? String }).count == 2)
        #expect(rows.allSatisfy { ($0["secure_link"] as? [String: Any])?["authenticated"] as? Bool == true })
        #expect(!String(decoding: try JSONSerialization.data(withJSONObject: rows), as: UTF8.self).contains(secret))
    }

    @Test func rootServesNativeAdminDashboard() async throws {
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .tcp, host: "127.0.0.1", port: 1))
        let server = ObstacleBridgeLinuxAdminServer(runtime: runtime)
        try server.start()
        defer { server.stop() }
        let (data, response) = try await URLSession.shared.data(from: try #require(URL(string: "http://127.0.0.1:\(server.port)/")))
        #expect((response as? HTTPURLResponse)?.statusCode == 200)
        #expect((response as? HTTPURLResponse)?.value(forHTTPHeaderField: "Content-Type")?.hasPrefix("text/html") == true)
        #expect(String(decoding: data, as: UTF8.self).contains("Native runtime Admin dashboard"))
    }

    @Test func configuredAdminWebAssetsAreServedAlongsideTheNativeAPI() async throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("obstaclebridge-admin-web-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try Data("<html><body>configured admin page</body></html>".utf8).write(to: directory.appendingPathComponent("index.html"))
        try Data("body{color:green}".utf8).write(to: directory.appendingPathComponent("style.css"))
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .tcp, host: "127.0.0.1", port: 1))
        let server = ObstacleBridgeLinuxAdminServer(runtime: runtime, staticDirectory: directory)
        try server.start(); defer { server.stop() }
        let base = "http://127.0.0.1:\(server.port)"
        let (page, pageResponse) = try await URLSession.shared.data(from: try #require(URL(string: base + "/")))
        #expect((pageResponse as? HTTPURLResponse)?.statusCode == 200)
        #expect(String(decoding: page, as: UTF8.self).contains("configured admin page"))
        let (style, styleResponse) = try await URLSession.shared.data(from: try #require(URL(string: base + "/style.css")))
        #expect((styleResponse as? HTTPURLResponse)?.value(forHTTPHeaderField: "Content-Type")?.hasPrefix("text/css") == true)
        #expect(String(decoding: style, as: UTF8.self).contains("green"))
        _ = try #require(try await getJSON(base + "/api/status") as? [String: Any])
    }

    private func getJSON(_ text: String) async throws -> Any {
        let (data, response) = try await URLSession.shared.data(from: try #require(URL(string: text)))
        #expect((response as? HTTPURLResponse)?.statusCode == 200)
        return try JSONSerialization.jsonObject(with: data)
    }

    private func requestJSON(_ text: String, method: String, body: [String: Any], headers: [String: String] = [:]) async throws -> (status: Int, body: Any, headers: [String: String]) {
        var request = URLRequest(url: try #require(URL(string: text)))
        request.httpMethod = method
        if method != "GET" {
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        for (name, value) in headers { request.setValue(value, forHTTPHeaderField: name) }
        let (data, response) = try await URLSession.shared.data(for: request)
        let httpResponse = try #require(response as? HTTPURLResponse)
        return (httpResponse.statusCode, try JSONSerialization.jsonObject(with: data), httpResponse.allHeaderFields.reduce(into: [:]) { headers, item in
            if let key = item.key as? String, let value = item.value as? String { headers[key] = value }
        })
    }

    private func digest(_ text: String) -> String {
        ObstacleBridgeCrypto.sha256(Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}
