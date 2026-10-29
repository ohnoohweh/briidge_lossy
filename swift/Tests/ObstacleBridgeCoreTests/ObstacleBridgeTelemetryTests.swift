import Foundation
import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgeTelemetryTests {
    @Test func adminServiceConnectionRolesFollowThePortableCatalogContract() {
        #expect(ObstacleBridgeAdminSnapshotSupport.serviceConnectionRole(catalog: "own_servers") == "server")
        #expect(ObstacleBridgeAdminSnapshotSupport.serviceConnectionRole(catalog: "remote_servers") == "client")
    }

    @Test func adminPeerEnvelopeOwnsTheSharedAPIShapeAndPreservesMeasuredFacts() {
        let peer = ObstacleBridgeAdminSnapshotSupport.peerEnvelope(
            id: 1,
            peerID: "configured-peer",
            transport: "myudp",
            state: "connected",
            connected: true,
            appReady: true,
            peer: ["host": "198.51.100.7", "port": 443],
            secureLink: ["state": "authenticated", "authenticated": true],
            compressionLayer: ["enabled": true, "decompress_ok_total": 7],
            extra: ["configured_candidates": ["198.51.100.7"]]
        )
        #expect(peer["peer_id"] as? String == "configured-peer")
        #expect(peer["connected"] as? Bool == true)
        #expect(peer["traffic"] as? [String: Any] != nil)
        #expect(peer["open_connections"] as? [String: Any] != nil)
        #expect((peer["secure_link"] as? [String: Any])?["authenticated"] as? Bool == true)
        #expect((peer["compress_layer"] as? [String: Any])?["decompress_ok_total"] as? Int == 7)
        #expect((peer["compression_layer"] as? [String: Any])?["decompress_ok_total"] as? Int == 7)
        #expect(peer["configured_candidates"] as? [String] == ["198.51.100.7"])
    }

    @Test func typedPeerFactsKeepProtocolAndCompressionSchemaInCore() {
        let compression = ObstacleBridgeMuxCompressionTelemetry(
            policy: .init(enabled: true)
        )
        compression.recordFailedDecompression(bodyBytes: 17)
        let peer = ObstacleBridgeAdminSnapshotSupport.peerEnvelope(facts: .init(
            identity: "configured-peer", transport: "myudp", lifecycleState: "connected",
            secureLinkState: "authenticated", connectionEpoch: 4, sessionID: 9,
            pendingRekeySessionID: 10, ready: true, authenticated: true,
            applicationSendingBlocked: false, attempts: 1, nextRetryMilliseconds: nil,
            protectedTxCounter: 12, protectedRxCounter: 13, protectedFramesSentTotal: 14,
            protectedFramesReceivedTotal: 15, authenticatedGenerationsTotal: 2,
            rekeysCompletedTotal: 1, connectedSinceUnixTS: 20, lastIncomingAgeSeconds: 1,
            observedPublicIP: "2001:db8::47", observedPublicPort: 44321,
            compression: compression.snapshot(), secureLinkMode: "psk",
            endpointHost: "198.51.100.7", endpointPort: 443,
            configuredCandidates: ["198.51.100.7"], activeTCPChannels: 3,
            activeUDPChannels: 4, activeTUNChannels: 1, failureReason: nil,
            traffic: ["rx_bytes": 321, "tx_bytes": 654, "rx_msgs": 3, "tx_msgs": 4],
            trafficRates: ["rx_bytes_per_sec": 12.5, "tx_bytes_per_sec": 25.0],
            myudpStats: ["rtt_est_ms": 7, "inflight": 2]
        ))
        let secureLink = try! #require(peer["secure_link"] as? [String: Any])
        let compressionLayer = try! #require(peer["compress_layer"] as? [String: Any])
        #expect(secureLink["pending_rekey_session_id"] as? UInt64 == 10)
        #expect(secureLink["rekey_in_progress"] as? Bool == true)
        #expect(compressionLayer["decompress_fail_total"] as? UInt64 == 1)
        #expect((peer["connection_layers"] as? [[String: Any]])?.count == 3)
        #expect(peer["rtt_est_ms"] as? UInt64 == 7)
        #expect(peer["observed_public_ip"] as? String == "2001:db8::47")
        #expect(peer["observed_public_port"] as? Int == 44321)
        #expect((peer["traffic"] as? [String: Any])?["rx_bytes"] as? UInt64 == 321)
        #expect((peer["traffic"] as? [String: Any])?["tx_bytes"] as? UInt64 == 654)
        #expect((peer["traffic"] as? [String: Any])?["rx_bytes_per_sec"] as? Double == 12.5)
        #expect((peer["open_connections"] as? [String: Any])?["tun"] as? Int == 1)
        #expect(JSONSerialization.isValidJSONObject(peer))
    }

    @Test func peerTrafficAggregationUsesOwnedConnectionRows() {
        let totals = ObstacleBridgeAdminSnapshotSupport.aggregateConnectionTraffic([
            "tcp": [
                ["stats": ["rx_bytes": 100, "tx_bytes": 200, "rx_msgs": 1, "tx_msgs": 2]],
                ["stats": ["rx_bytes": 50, "tx_bytes": 25, "rx_msgs": 3, "tx_msgs": 1]],
            ],
            "udp": [["stats": ["rx_bytes": 7, "tx_bytes": 9, "rx_msgs": 1, "tx_msgs": 1]]],
        ])
        #expect(totals["rx_bytes"] == 157)
        #expect(totals["tx_bytes"] == 234)
        #expect(totals["rx_msgs"] == 5)
        #expect(totals["tx_msgs"] == 4)
    }

    @Test func peerTrafficRatesAndOpenCountsUseTheCoreConnectionContract() {
        let sampler = ObstacleBridgeAdminPeerTrafficRateSampler()
        let first = sampler.sample(identity: "peer", traffic: ["rx_bytes": 100, "tx_bytes": 200], uptime: 10)
        let second = sampler.sample(identity: "peer", traffic: ["rx_bytes": 160, "tx_bytes": 260], uptime: 12)
        #expect(first["rx_bytes_per_sec"] == 0)
        #expect(second["rx_bytes_per_sec"] == 30)
        #expect(second["tx_bytes_per_sec"] == 30)
        let counts = ObstacleBridgeAdminSnapshotSupport.activeConnectionCounts([
            "tcp": [["chan_id": 3, "state": "connected"]],
            "udp": [["chan_id": NSNull(), "state": "listening"]],
            "tun": [["chan_id": 9, "state": "connected"]],
        ])
        #expect(counts == ["tcp": 1, "udp": 0, "tun": 1])
        let throttle = ObstacleBridgeAdminSnapshotSupport.peerThrottleSnapshot(peerID: 1, connectionsSnapshot: [
            "tun": [[
                "chan_id": 9,
                "state": "connected",
                "throttle": [
                    "applicable": true, "active": false, "disabled": true,
                    "waiting_count": 0, "inflight": 3, "max_inflight": 200,
                ],
            ]],
        ])
        #expect(throttle["applicable"] as? Bool == true)
        #expect(throttle["active"] as? Bool == false)
    }

    @Test func adminStatusEnvelopeOwnsSharedDashboardFields() {
        let status = ObstacleBridgeAdminSnapshotSupport.statusEnvelope(
            runtimeOwner: "native",
            runtimeMode: "linux-swift",
            adminWebName: "ObstacleBridge Fedora Native",
            adminUI: [:], securityAdvisor: [:],
            startedAt: 1, uptimeSec: 2,
            bootstrapState: ["status": "connected"],
            transportRuntime: ["kind": "myudp", "status": "connected", "app_ready": true],
            compressLayer: [:]
        )
        #expect(status["app"] as? String == "native")
        #expect(status["platform"] as? String == "linux-swift")
        #expect(status["overlay_transport"] as? String == "myudp")
        #expect(status["transport_state"] as? String == "connected")
        #expect(status["app_ready"] as? Bool == true)
        #expect(status["peer"] is NSNull)
        let live = ObstacleBridgeAdminSnapshotSupport.liveStatusEnvelope(status.merging([
            "runtime_metrics": ["history": Array(repeating: 1, count: 32)],
            "runtime_health_recent_records": [["state": "connected"]],
        ], uniquingKeysWith: { _, supplied in supplied }))
        #expect(live["overlay_transport"] as? String == "myudp")
        #expect((live["runtime_metrics"] as? [String: Any])?["history"] as? [Int] == Array(repeating: 1, count: 32))
        #expect(live["runtime_health_recent_records"] == nil)
    }

    private func vectorEvent() throws -> ObstacleBridgeTelemetryEvent {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("docs/TELEMETRY_V1_VECTORS.json")
        let payload = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
        let event = payload?["event"] as? [String: Any]
        return try ObstacleBridgeTelemetry.decodeEvent(JSONSerialization.data(withJSONObject: event ?? [:], options: [.sortedKeys]))
    }

    @Test func canonicalVectorRoundTripsThroughThePortableContract() throws {
        let event = try vectorEvent()
        #expect(event.installationID == "install-01")
        #expect(event.sessionID == "session-01")
        #expect(event.sequence == 1)
        #expect(event.fields["state"] == .string("ready"))
        let encoded = try ObstacleBridgeTelemetry.encode(event: event)
        #expect(try ObstacleBridgeTelemetry.decodeEvent(encoded) == event)
        let batch = try ObstacleBridgeTelemetryBatch(events: [event])
        #expect(try ObstacleBridgeTelemetry.decodeBatch(ObstacleBridgeTelemetry.encode(batch: batch)) == batch)
    }

    @Test func rejectsNonAllowlistedAndMalformedEvents() throws {
        let event = try vectorEvent()
        #expect(throws: ObstacleBridgeTelemetryError.malformedEncoding) {
            try ObstacleBridgeTelemetry.decodeEvent(Data("{}".utf8))
        }
        #expect(throws: ObstacleBridgeTelemetryError.invalidField) {
            try ObstacleBridgeTelemetryEvent(
                installationID: event.installationID,
                sessionID: event.sessionID,
                sequence: event.sequence,
                monotonicNanoseconds: event.monotonicNanoseconds,
                wallTime: event.wallTime,
                priority: event.priority,
                event: event.event,
                fields: ["payload": .string("must not be representable")]
            )
        }
        #expect(throws: ObstacleBridgeTelemetryError.invalidEvent) {
            try ObstacleBridgeTelemetryEvent(
                installationID: "",
                sessionID: event.sessionID,
                sequence: event.sequence,
                monotonicNanoseconds: event.monotonicNanoseconds,
                wallTime: event.wallTime,
                priority: event.priority,
                event: event.event,
                fields: [:]
            )
        }
    }

    @Test func enforcesEventAndBatchBounds() throws {
        let event = try vectorEvent()
        #expect(throws: ObstacleBridgeTelemetryError.invalidBatch) {
            try ObstacleBridgeTelemetryBatch(events: [])
        }
        #expect(throws: ObstacleBridgeTelemetryError.invalidField) {
            try ObstacleBridgeTelemetryEvent(
                installationID: event.installationID,
                sessionID: event.sessionID,
                sequence: event.sequence,
                monotonicNanoseconds: event.monotonicNanoseconds,
                wallTime: event.wallTime,
                priority: event.priority,
                event: event.event,
                fields: ["reason": .string(String(repeating: "x", count: ObstacleBridgeTelemetry.maximumFieldValueLength + 1))]
            )
        }
    }

    @Test func emitterDropsWhenFullButLetsCriticalEvidenceReplaceLowPriority() throws {
        let emitter = try ObstacleBridgeTelemetryEmitter(installationID: "install-01", sessionID: "session-01", capacity: 1)
        #expect(emitter.emit(event: "runtime.load", priority: .low))
        #expect(!emitter.emit(event: "runtime.load", priority: .normal))
        #expect(emitter.emit(event: "runtime.lifecycle", priority: .critical))
        let events = emitter.drain()
        #expect(events.count == 1)
        #expect(events[0].priority == .critical)
    }

    @Test func spoolRecoversAndAcknowledgesOnlyItsIdentity() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let spool = try ObstacleBridgeTelemetrySpool(directory: directory, maximumFiles: 4)
        let event = try vectorEvent()
        #expect(spool.append(event))
        #expect(spool.recover().map(\.sequence) == [event.sequence])
        #expect(spool.acknowledge(through: event.sequence, installationID: "other", sessionID: event.sessionID) == 0)
        #expect(spool.acknowledge(through: event.sequence, installationID: event.installationID, sessionID: event.sessionID) == 1)
        #expect(spool.recover().isEmpty)
    }

    @Test func concurrentEmissionStaysBoundedAndNeverThrows() async throws {
        let emitter = try ObstacleBridgeTelemetryEmitter(installationID: "install-01", sessionID: "session-01", capacity: 8)
        await withTaskGroup(of: Bool.self) { group in
            for _ in 0..<128 { group.addTask { emitter.emit(event: "runtime.load", priority: .low) } }
            for await _ in group {}
        }
        #expect(emitter.drain(limit: 128).count <= 8)
    }

    @Test func spoolQuarantinesCorruptSegmentsAndEvictsLowPriorityFirst() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let spool = try ObstacleBridgeTelemetrySpool(directory: directory, maximumFiles: 1)
        let vector = try vectorEvent()
        let base = try ObstacleBridgeTelemetryEvent(installationID: vector.installationID, sessionID: vector.sessionID, sequence: vector.sequence, monotonicNanoseconds: vector.monotonicNanoseconds, wallTime: vector.wallTime, priority: .low, event: "runtime.load", fields: ["queue_depth": .integer(1)])
        #expect(spool.append(base))
        let critical = try ObstacleBridgeTelemetryEvent(installationID: base.installationID, sessionID: base.sessionID, sequence: 2, monotonicNanoseconds: 2, wallTime: 2, priority: .critical, event: "runtime.lifecycle", fields: ["state": .string("failed")])
        #expect(spool.append(critical))
        #expect(spool.recover().map(\.sequence) == [2])
        let segment = try #require(try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil).first(where: { $0.pathExtension == "json" }))
        try Data("corrupt".utf8).write(to: segment)
        #expect(spool.recover().isEmpty)
        #expect((try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)).contains { $0.pathExtension == "corrupt" })
    }

    @Test func unavailableSpoolDirectoryFailsAtSetupNotOnEmitterPath() throws {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: file) }
        try Data().write(to: file)
        #expect(throws: Error.self) { try ObstacleBridgeTelemetrySpool(directory: file) }
        let emitter = try ObstacleBridgeTelemetryEmitter(installationID: "install-01", sessionID: "session-01")
        #expect(emitter.emit(event: "runtime.lifecycle", priority: .critical))
    }

    @Test func uploadPolicyScopesBatchAcknowledgementsAndBackoff() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let spool = try ObstacleBridgeTelemetrySpool(directory: directory)
        let first = try vectorEvent()
        let second = try ObstacleBridgeTelemetryEvent(installationID: first.installationID, sessionID: first.sessionID, sequence: 2, monotonicNanoseconds: 2, wallTime: 2, priority: .normal, event: "runtime.load", fields: ["queue_depth": .integer(2)])
        #expect(spool.append(first)); #expect(spool.append(second))
        var clock = 0.0
        let policy = try ObstacleBridgeTelemetryUploadPolicy(spool: spool, endpoint: try #require(URL(string: "https://collector.example/v1/telemetry/batches")), clock: { clock }, random: { 0 })
        let request = try #require(policy.nextRequest())
        #expect(try ObstacleBridgeTelemetry.decodeBatch(request.payload).events.map(\.sequence) == [1, 2])
        #expect(policy.accept(acceptedThrough: 1) == 1)
        #expect(spool.recover().map(\.sequence) == [2])
        let retry = try #require(policy.nextRequest())
        #expect(retry.firstSequence == 2)
        policy.fail()
        #expect(policy.nextRequest() == nil)
        clock = 2
        #expect(policy.nextRequest()?.firstSequence == 2)
    }

    @Test func uploadPolicyRejectsPlainHTTPAndOverBudgetRequests() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let spool = try ObstacleBridgeTelemetrySpool(directory: directory)
        #expect(throws: ObstacleBridgeTelemetryError.invalidBatch) {
            try ObstacleBridgeTelemetryUploadPolicy(spool: spool, endpoint: try #require(URL(string: "http://collector.example")))
        }
        let event = try vectorEvent()
        for sequence in 1...4 {
            let queued = try ObstacleBridgeTelemetryEvent(installationID: event.installationID, sessionID: event.sessionID, sequence: UInt64(sequence), monotonicNanoseconds: UInt64(sequence), wallTime: Double(sequence), priority: .normal, event: "runtime.load", fields: ["reason": .string(String(repeating: "x", count: 256))])
            #expect(spool.append(queued))
        }
        let policy = try ObstacleBridgeTelemetryUploadPolicy(spool: spool, endpoint: try #require(URL(string: "https://collector.example")), byteBudgetPerDay: 1)
        #expect(policy.nextRequest() == nil)
        #expect(spool.recover().count == 4)
    }
}
