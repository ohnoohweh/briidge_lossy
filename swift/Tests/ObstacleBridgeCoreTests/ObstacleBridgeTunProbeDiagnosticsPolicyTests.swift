import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgeTunProbeDiagnosticsPolicyTests {
    @Test func buildsPortableProbeCountersAndResultProjection() {
        var stages = ObstacleBridgeTunProbeDiagnosticsPolicy.makeCounts(ObstacleBridgeTunProbeDiagnosticsPolicy.tunICMPStageKeys)
        ObstacleBridgeTunProbeDiagnosticsPolicy.record("overlay_rx_after_unpack", counts: &stages)
        ObstacleBridgeTunProbeDiagnosticsPolicy.record("unknown", counts: &stages)
        #expect(stages["overlay_rx_after_unpack"] == 1)
        #expect(ObstacleBridgeTunProbeDiagnosticsPolicy.cacheKey(probeKind: " GLOBAL ", ifname: "utun7", target: "203.0.113.7") == "global|utun7|203.0.113.7")
        let result = ObstacleBridgeTunProbeDiagnosticsPolicy.result(probeKind: "peer", target: "203.0.113.7", ok: true, state: "ok", summary: "reachable", detail: "", checkedAtUnixTS: 7, valueMS: 3)
        #expect(result["label"] as? String == "TUN connectivity verified")
        #expect(result["value_ms"] as? Double == 3)
        #expect(result["checked_at_unix_ts"] as? Double == 7)
    }
}
