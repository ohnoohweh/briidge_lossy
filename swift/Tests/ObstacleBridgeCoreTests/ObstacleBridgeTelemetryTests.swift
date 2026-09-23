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
}
