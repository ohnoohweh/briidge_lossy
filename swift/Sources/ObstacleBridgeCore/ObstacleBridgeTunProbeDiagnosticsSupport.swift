import Foundation

struct ObstacleBridgeTunProbeWaiterKey: Hashable {
    let family: Int32
    let identifier: UInt16
    let sequence: UInt16
    let nonce: Data
}

final class ObstacleBridgeTunProbeWaiterState {
    let semaphore = DispatchSemaphore(value: 0)
    var reply: ObstacleBridgeTunProbeReply?
}

struct ObstacleBridgeTunProbeReply {
    let sourceIP: String
    let destinationIP: String
    let payload: Data
    let receivedMonotonicNS: UInt64
}

struct ObstacleBridgeTunProbeHistory {
    let lastSuccessMonotonic: TimeInterval
    let lastSuccessRTTMS: Double
}

enum ObstacleBridgeTunProbeDiagnosticsSupport {
    static let ipv4Family: Int32 = 2
#if os(Linux)
    static let ipv6Family: Int32 = 10
#elseif os(Windows)
    static let ipv6Family: Int32 = 23
#else
    static let ipv6Family: Int32 = 30
#endif
    static let localReplyStageKeys = ObstacleBridgeTunProbeDiagnosticsPolicy.localReplyStageKeys
    static let tunICMPStageKeys = ObstacleBridgeTunProbeDiagnosticsPolicy.tunICMPStageKeys
    static let tunProbeBoundaryKeys = ObstacleBridgeTunProbeDiagnosticsPolicy.tunProbeBoundaryKeys

    static func makeTunICMPStageCounts() -> [String: Int] {
        ObstacleBridgeTunProbeDiagnosticsPolicy.makeCounts(tunICMPStageKeys)
    }

    static func makeTunProbeBoundaryCounts() -> [String: Int] {
        ObstacleBridgeTunProbeDiagnosticsPolicy.makeCounts(tunProbeBoundaryKeys)
    }

    static func makeLocalReplyStageCounts() -> [String: Int] {
        ObstacleBridgeTunProbeDiagnosticsPolicy.makeCounts(localReplyStageKeys)
    }

    static func recordTunICMPStage(
        _ key: String,
        tunICMPStageCounts: inout [String: Int],
        localReplyStageCounts: inout [String: Int]
    ) {
        ObstacleBridgeTunProbeDiagnosticsPolicy.record(key, counts: &tunICMPStageCounts)
        ObstacleBridgeTunProbeDiagnosticsPolicy.record(key, counts: &localReplyStageCounts)
    }

    static func recordTunProbeBoundary(_ key: String, tunProbeBoundaryCounts: inout [String: Int]) {
        ObstacleBridgeTunProbeDiagnosticsPolicy.record(key, counts: &tunProbeBoundaryCounts)
    }

    static func tunProbeCacheKey(probeKind: String, ifname: String, target: String) -> String {
        ObstacleBridgeTunProbeDiagnosticsPolicy.cacheKey(probeKind: probeKind, ifname: ifname, target: target)
    }

    static func tunProbeLabel(_ probeKind: String) -> String {
        ObstacleBridgeTunProbeDiagnosticsPolicy.label(probeKind)
    }

    static func tunProbeKindCode(_ probeKind: String) -> UInt8 {
        ObstacleBridgeTunProbeDiagnosticsPolicy.kindCode(probeKind)
    }

    static func tunProbeNameResolution(status: String, resolvedIP: String = "", detail: String = "") -> [String: Any] {
        ObstacleBridgeTunProbeDiagnosticsPolicy.nameResolution(status: status, resolvedIP: resolvedIP, detail: detail)
    }

    static func tunProbeResult(
        probeKind: String,
        target: String,
        ok: Bool,
        state: String,
        summary: String,
        detail: String,
        resolvedTarget: String = "",
        nameResolution: [String: Any] = [:],
        valueMS: Double? = nil,
        lastSuccessAgoS: Double? = nil,
        lastSuccessRTTMS: Double? = nil
    ) -> [String: Any] {
        ObstacleBridgeTunProbeDiagnosticsPolicy.result(
            probeKind: probeKind, target: target, ok: ok, state: state,
            summary: summary, detail: detail, checkedAtUnixTS: Date().timeIntervalSince1970,
            resolvedTarget: resolvedTarget, nameResolution: nameResolution, valueMS: valueMS,
            lastSuccessAgoS: lastSuccessAgoS, lastSuccessRTTMS: lastSuccessRTTMS
        )
    }

    static func sourceProbeFamilies(tunnelAddress: String, tunnelAddress6: String) -> [Int32] {
        var families: [Int32] = []
        if !tunnelAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            families.append(ipv4Family)
        }
        if !tunnelAddress6.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            families.append(ipv6Family)
        }
        if families.isEmpty {
            families.append(ipv4Family)
        }
        return families
    }

    static func sourceAddressForProbeFamily(_ family: Int32, tunnelAddress: String, tunnelAddress6: String) -> String {
        if family == ipv6Family {
            return tunnelAddress6.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return tunnelAddress.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    static func resolveTunProbeTarget(
        _ target: String,
        candidateFamilies: [Int32],
        resolver: (String, Int32) -> String? = { _, _ in nil }
    ) -> (target: String?, family: Int32, error: String) {
        var lastError = "target resolution failed"
        for family in candidateFamilies {
            if let directFamily = ObstacleBridgeTunPing.ipFamily(target), platformFamily(for: directFamily) == family {
                return (target, family, "")
            }
            if let resolved = resolver(target, family) {
                return (resolved, family, "")
            }
            lastError = "unable to resolve \(target) for family=\(family)"
        }
        return (nil, candidateFamilies.first ?? ipv4Family, lastError)
    }

    static func recordTunProbeSuccess(
        cacheKey: String,
        rttMS: Double,
        tunProbeHistory: inout [String: ObstacleBridgeTunProbeHistory],
        currentUptime: TimeInterval
    ) {
        tunProbeHistory[cacheKey] = ObstacleBridgeTunProbeHistory(
            lastSuccessMonotonic: currentUptime,
            lastSuccessRTTMS: rttMS
        )
    }

    static func tunProbeHistorySnapshot(
        cacheKey: String,
        tunProbeHistory: [String: ObstacleBridgeTunProbeHistory],
        currentUptime: TimeInterval
    ) -> (lastSuccessAgoS: Double?, lastSuccessRTTMS: Double?) {
        guard let history = tunProbeHistory[cacheKey] else {
            return (nil, nil)
        }
        return (
            max(0.0, currentUptime - history.lastSuccessMonotonic),
            history.lastSuccessRTTMS
        )
    }

    static func observeTunProbeReply(
        _ packet: Data,
        tunProbeWaiters: inout [ObstacleBridgeTunProbeWaiterKey: ObstacleBridgeTunProbeWaiterState],
        tunICMPStageCounts: inout [String: Int],
        localReplyStageCounts: inout [String: Int],
        tunProbeBoundaryCounts: inout [String: Int],
        receivedMonotonicNS: UInt64
    ) -> Bool {
        guard let parsed = ObstacleBridgeTunPing.parseEchoReply(packet) else {
            return false
        }
        let payload = parsed.payload
        let minimumPayloadLength = ObstacleBridgeTunPing.probeMagic.count + 1 + 8 + 8
        guard payload.count >= minimumPayloadLength,
              payload.prefix(ObstacleBridgeTunPing.probeMagic.count) == ObstacleBridgeTunPing.probeMagic else {
            return false
        }
        let nonce = payload.subdata(in: 5..<13)
        let key = ObstacleBridgeTunProbeWaiterKey(
            family: platformFamily(for: parsed.family),
            identifier: parsed.identifier,
            sequence: parsed.sequence,
            nonce: nonce
        )
        guard let waiter = tunProbeWaiters.removeValue(forKey: key) else {
            recordTunProbeBoundary("probe_reply_unmatched", tunProbeBoundaryCounts: &tunProbeBoundaryCounts)
            return false
        }
        recordTunProbeBoundary("probe_reply_matched", tunProbeBoundaryCounts: &tunProbeBoundaryCounts)
        recordTunICMPStage(
            "overlay_rx_after_unpack",
            tunICMPStageCounts: &tunICMPStageCounts,
            localReplyStageCounts: &localReplyStageCounts
        )
        waiter.reply = ObstacleBridgeTunProbeReply(
            sourceIP: parsed.sourceIP,
            destinationIP: parsed.destinationIP,
            payload: payload,
            receivedMonotonicNS: receivedMonotonicNS
        )
        waiter.semaphore.signal()
        return true
    }

    private static func platformFamily(for family: ObstacleBridgeTunPing.Family) -> Int32 {
        switch family {
        case .ipv4:
            return ipv4Family
        case .ipv6:
            return ipv6Family
        }
    }

    static func tunProbeRuntimeDiagSnapshot(
        probeKind: String,
        ifname: String,
        target: String,
        resolvedTarget: String,
        timeoutSeconds: TimeInterval,
        overlayTransport: String,
        overlayConnected: Bool,
        sessionConnected: Bool,
        sessionAppReady: Bool,
        acceptingEnabled: Bool,
        secureLinkState: String,
        secureLinkLastEvent: String,
        secureLinkFailureReason: String,
        backpressure: [String: Any]
    ) -> [String: Any] {
        ObstacleBridgeTunProbeDiagnosticsPolicy.runtimeSnapshot(
            probeKind: probeKind, ifname: ifname, target: target, resolvedTarget: resolvedTarget,
            timeoutSeconds: timeoutSeconds, capturedAtUnixTS: Date().timeIntervalSince1970,
            overlayTransport: overlayTransport, overlayConnected: overlayConnected,
            sessionConnected: sessionConnected, sessionAppReady: sessionAppReady,
            acceptingEnabled: acceptingEnabled, secureLinkState: secureLinkState,
            secureLinkLastEvent: secureLinkLastEvent,
            secureLinkFailureReason: secureLinkFailureReason, backpressure: backpressure
        )
    }

}
