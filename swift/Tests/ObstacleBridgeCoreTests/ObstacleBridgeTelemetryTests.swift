import Foundation
import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgeTelemetryTests {
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
}
