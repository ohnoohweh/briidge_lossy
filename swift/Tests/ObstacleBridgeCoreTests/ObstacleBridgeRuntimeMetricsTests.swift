import Foundation
import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgeRuntimeMetricsTests {
    @Test func retainsOnlyApprovedAggregateTimingAndTrailingWindow() async {
        let metrics = ObstacleBridgeRuntimeMetrics()
        await metrics.record(.overlayReceiveData, durationNS: 3_000_000, completedNS: 1_000_000_000)
        await metrics.record(.overlayReceiveControl, durationNS: 4_000_000, completedNS: 1_000_000_000)
        await metrics.record(.retransmitReportedMissing, durationNS: 5_000_000, completedNS: 1_000_000_000)
        await metrics.record(.retransmitUnconfirmed, durationNS: 6_000_000, completedNS: 1_000_000_000)
        await metrics.record(.secureLink, durationNS: 7_000_000, completedNS: 2_000_000_000)
        await metrics.record(.compressionEncode, durationNS: 8_000_000, completedNS: 2_000_000_000)
        await metrics.record(.appleTransportTunDataGuard, durationNS: 11_000_000, completedNS: 2_000_000_000)
        await metrics.record(.appleTransportTcpWriteEnqueue, durationNS: 12_000_000, completedNS: 2_000_000_000)
        await metrics.record(.appleTransportTcpConnectionStart, durationNS: 13_000_000, completedNS: 2_000_000_000)
        let payload = try! JSONSerialization.jsonObject(
            with: Data(await metrics.snapshotBytes(nowNS: 2_000_000_000))
        ) as! [String: Any]
        let rows = payload["categories"] as? [[String: Any]]
        let secureLink = rows?.first { ($0["category"] as? String) == "securelink" }
        #expect(secureLink?["count"] as? Int == 1)
        #expect(secureLink?["max_ms"] as? Double == 7.0)
        let retransmit = rows?.first { ($0["category"] as? String) == "retransmit_unconfirmed" }
        #expect(retransmit?["max_ms"] as? Double == 6.0)
        #expect(payload["longest_uninterrupted_category"] as? String == "apple_transport_tcp_connection_start")
        #expect(payload["payload"] == nil)

        let expired = try! JSONSerialization.jsonObject(
            with: Data(await metrics.snapshotBytes(nowNS: 5_000_000_001))
        ) as! [String: Any]
        let expiredRows = expired["categories"] as? [[String: Any]]
        let expiredSecureLink = expiredRows?.first { ($0["category"] as? String) == "securelink" }
        #expect(expiredSecureLink?["last_2_seconds_max_ms"] is NSNull)
        #expect(expiredSecureLink?["max_ms"] as? Double == 7.0)
    }

    @Test func projectsPythonCompatibleBoundedMemoryMetrics() async {
        let metrics = ObstacleBridgeRuntimeMetrics()
        await metrics.recordMemorySample(processMemoryBytes: 100, measurementKind: .resident, wallNS: 1_000_000_000)
        await metrics.recordMemorySample(processMemoryBytes: 250, measurementKind: .resident, wallNS: 2_000_000_000)
        await metrics.recordMemorySample(processMemoryBytes: 150, measurementKind: .resident, wallNS: 3_000_000_000)
        let payload = try! JSONSerialization.jsonObject(
            with: Data(await metrics.snapshotBytes(nowNS: 3_000_000_000))
        ) as! [String: Any]
        let memory = payload["memory_bytes"] as? [String: Any]
        #expect(memory?["current"] as? NSNumber == 150)
        #expect(memory?["overall_peak"] as? NSNumber == 250)
        #expect(memory?["last_2_seconds_peak"] as? NSNumber == 250)
        #expect(memory?["warning_limit"] is NSNull)
        #expect(memory?["warning_active"] as? Bool == false)
        #expect(memory?["measurement_kind"] as? String == "resident")
        let expired = try! JSONSerialization.jsonObject(
            with: Data(await metrics.snapshotBytes(nowNS: 6_000_000_001))
        ) as! [String: Any]
        let expiredMemory = expired["memory_bytes"] as? [String: Any]
        #expect(expiredMemory?["last_2_seconds_peak"] is NSNull)
    }
}
