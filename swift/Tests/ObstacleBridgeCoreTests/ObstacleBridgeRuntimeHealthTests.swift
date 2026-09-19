import Foundation
import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgeRuntimeHealthTests {
    @Test func recordUsesPortableRedactedSchema() throws {
        let record = ObstacleBridgeRuntimeHealthRecord(
            sequence: 7,
            timestampUnixMilliseconds: 1_700_000_000_123,
            event: "heartbeat",
            processFootprintBytes: 32_768,
            packetPumpRunning: true,
            overlayState: "connected",
            secureLinkState: "authenticated",
            transportEpoch: 4,
            incomingQueuedPackets: 3,
            outgoingQueuedPackets: 2,
            outgoingInflightWrites: 1,
            incomingDroppedPackets: 5,
            slowWrites: 6,
            packetsFromSystem: 7,
            packetsToSystem: 8
        )
        let payload = try JSONSerialization.jsonObject(with: JSONEncoder().encode(record)) as? [String: Any]
        #expect(payload?["schema_version"] as? Int == 1)
        #expect(payload?["timestamp_unix_milliseconds"] as? Int == 1_700_000_000_123)
        #expect(payload?["securelink_state"] as? String == "authenticated")
        #expect(payload?["process_footprint_bytes"] as? Int == 32_768)
        #expect(payload?["packets_to_system"] as? Int == 8)
        #expect(payload?["packet_contents"] == nil)
    }

    @Test func ringIsBoundedAndClassifiesOnlyTheLastLifecycleMarker() {
        var ring = ObstacleBridgeRuntimeHealthRing(capacity: 2)
        #expect(ring.previousLifetimeEndedCleanly == nil)
        ring.append(.init(sequence: 1, timestampUnixMilliseconds: 1, event: "start"))
        ring.append(.init(sequence: 2, timestampUnixMilliseconds: 2, event: "stop", controlledStop: true))
        #expect(ring.previousLifetimeEndedCleanly == true)
        ring.append(.init(sequence: 3, timestampUnixMilliseconds: 3, event: "start"))
        #expect(ring.records.map(\.sequence) == [2, 3])
        #expect(ring.previousLifetimeEndedCleanly == false)
    }

    @Test func persistenceKeepsOnlyCompleteRedactedRing() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let url = directory.appendingPathComponent("runtime-health.json")
        defer { try? FileManager.default.removeItem(at: directory) }
        var ring = ObstacleBridgeRuntimeHealthRing(capacity: 2)
        ring.append(.init(sequence: 1, timestampUnixMilliseconds: 1, event: "start"))
        ring.append(.init(sequence: 2, timestampUnixMilliseconds: 2, event: "stop", controlledStop: true))

        try ObstacleBridgeRuntimeHealthPersistence.save(ring, to: url)

        #expect(ObstacleBridgeRuntimeHealthPersistence.load(from: url) == ring)
        #expect(ObstacleBridgeRuntimeHealthPersistence.load(from: url)?.previousLifetimeEndedCleanly == true)
    }
}
