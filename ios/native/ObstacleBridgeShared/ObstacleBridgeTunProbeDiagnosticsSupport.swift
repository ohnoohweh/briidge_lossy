import Darwin
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
    static let localReplyStageKeys = [
        "local_reply_skip_overlay_inactive",
        "local_reply_drop_oversize",
        "local_reply_drop_throttled",
        "local_reply_drop_shared_route",
        "local_reply_virtual_probe_delivery",
        "local_reply_drop_no_channel",
        "local_reply_drop_missing_service_spec",
        "local_reply_bound_new_channel",
        "local_reply_before_overlay_send",
    ]

    static let tunICMPStageKeys = [
        "from_local_tun_read",
        "overlay_tx_before_send_app",
        "overlay_rx_after_unpack",
        "from_peer_before_local_write",
        "to_local_tun_written",
    ] + localReplyStageKeys

    static let tunProbeBoundaryKeys = [
        "probe_attempt_started",
        "probe_waiter_registered",
        "probe_injected_local_virtual",
        "probe_injected_kernel",
        "probe_injected_channelmux",
        "probe_send_completed",
        "probe_reply_matched",
        "probe_reply_consumed_before_local_write",
        "probe_reply_late_after_timeout",
        "own_probe_reply_unmatched",
        "foreign_probe_reply_unmatched",
        "probe_reply_unmatched",
        "probe_timeout",
        "probe_exception",
        "helper_read_packet",
        "helper_read_probe_packet",
        "helper_write_packet",
        "helper_write_probe_packet",
        "helper_write_error",
    ]

    static func makeTunICMPStageCounts() -> [String: Int] {
        Dictionary(uniqueKeysWithValues: tunICMPStageKeys.map { ($0, 0) })
    }

    static func makeTunProbeBoundaryCounts() -> [String: Int] {
        Dictionary(uniqueKeysWithValues: tunProbeBoundaryKeys.map { ($0, 0) })
    }

    static func makeLocalReplyStageCounts() -> [String: Int] {
        Dictionary(uniqueKeysWithValues: localReplyStageKeys.map { ($0, 0) })
    }

    static func recordTunICMPStage(
        _ key: String,
        tunICMPStageCounts: inout [String: Int],
        localReplyStageCounts: inout [String: Int]
    ) {
        guard tunICMPStageCounts[key] != nil else {
            return
        }
        tunICMPStageCounts[key] = Int(tunICMPStageCounts[key] ?? 0) + 1
        if localReplyStageCounts[key] != nil {
            localReplyStageCounts[key] = Int(localReplyStageCounts[key] ?? 0) + 1
        }
    }

    static func recordTunProbeBoundary(_ key: String, tunProbeBoundaryCounts: inout [String: Int]) {
        guard tunProbeBoundaryCounts[key] != nil else {
            return
        }
        tunProbeBoundaryCounts[key] = Int(tunProbeBoundaryCounts[key] ?? 0) + 1
    }

    static func tunProbeCacheKey(probeKind: String, ifname: String, target: String) -> String {
        "\(probeKind.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())|\(ifname)|\(target)"
    }

    static func tunProbeLabel(_ probeKind: String) -> String {
        switch probeKind.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "peer":
            return "TUN connectivity verified"
        case "global":
            return "TUN global connectivity verified"
        default:
            return "TUN connectivity verification"
        }
    }

    static func tunProbeKindCode(_ probeKind: String) -> UInt8 {
        probeKind.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "global"
            ? ObstacleBridgeTunPing.probeKindGlobal
            : ObstacleBridgeTunPing.probeKindPeer
    }

    static func tunProbeNameResolution(status: String, resolvedIP: String = "", detail: String = "") -> [String: Any] {
        [
            "status": status,
            "resolved_ip": resolvedIP,
            "detail": detail,
        ]
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
        var result: [String: Any] = [
            "label": tunProbeLabel(probeKind),
            "ok": ok,
            "state": state,
            "summary": summary,
            "detail": detail,
            "target": target,
            "resolved_target": resolvedTarget,
            "name_resolution": nameResolution,
            "method": "internal_icmp_echo",
            "checked_at_unix_ts": Date().timeIntervalSince1970,
            "value_ms": NSNull(),
            "last_success_ago_s": NSNull(),
            "last_success_rtt_ms": NSNull(),
        ]
        if let valueMS {
            result["value_ms"] = valueMS
            result["last_success_rtt_ms"] = valueMS
        } else if let lastSuccessRTTMS {
            result["last_success_rtt_ms"] = lastSuccessRTTMS
        }
        if let lastSuccessAgoS {
            result["last_success_ago_s"] = lastSuccessAgoS
        }
        return result
    }

    static func sourceProbeFamilies(tunnelAddress: String, tunnelAddress6: String) -> [Int32] {
        var families: [Int32] = []
        if !tunnelAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            families.append(AF_INET)
        }
        if !tunnelAddress6.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            families.append(AF_INET6)
        }
        if families.isEmpty {
            families.append(AF_INET)
        }
        return families
    }

    static func sourceAddressForProbeFamily(_ family: Int32, tunnelAddress: String, tunnelAddress6: String) -> String {
        if family == AF_INET6 {
            return tunnelAddress6.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return tunnelAddress.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    static func resolveTunProbeTarget(_ target: String, candidateFamilies: [Int32]) -> (target: String?, family: Int32, error: String) {
        var lastError = "target resolution failed"
        for family in candidateFamilies {
            if let directFamily = ObstacleBridgeTunPing.ipFamily(target), directFamily == family {
                return (target, family, "")
            }
            if let resolved = resolveHost(target, family: family) {
                return (resolved, family, "")
            }
            lastError = "unable to resolve \(target) for family=\(family)"
        }
        return (nil, candidateFamilies.first ?? AF_INET, lastError)
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
            family: parsed.family,
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
        [
            "probe_kind": probeKind,
            "ifname": ifname.trimmingCharacters(in: .whitespacesAndNewlines),
            "target": target.trimmingCharacters(in: .whitespacesAndNewlines),
            "resolved_target": resolvedTarget.trimmingCharacters(in: .whitespacesAndNewlines),
            "timeout_s": timeoutSeconds,
            "captured_at_unix_ts": Date().timeIntervalSince1970,
            "overlay_transport": overlayTransport,
            "overlay_connected": overlayConnected,
            "session_connected": sessionConnected,
            "session_app_ready": sessionAppReady,
            "accepting_enabled": acceptingEnabled,
            "secure_link_state": secureLinkState,
            "secure_link_last_event": secureLinkLastEvent,
            "secure_link_failure_reason": secureLinkFailureReason,
            "backpressure": backpressure,
        ]
    }

    private static func resolveHost(_ host: String, family: Int32) -> String? {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return nil
        }
        var hints = addrinfo(
            ai_flags: AI_ADDRCONFIG,
            ai_family: family,
            ai_socktype: SOCK_RAW,
            ai_protocol: family == AF_INET6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )
        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(trimmed, nil, &hints, &result)
        guard status == 0, let result else {
            return nil
        }
        defer { freeaddrinfo(result) }
        var cursor: UnsafeMutablePointer<addrinfo>? = result
        while let info = cursor?.pointee {
            if info.ai_family == AF_INET,
               let addr = info.ai_addr?.withMemoryRebound(to: sockaddr_in.self, capacity: 1, { $0.pointee }) {
                var copy = addr.sin_addr
                var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                if inet_ntop(AF_INET, &copy, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil {
                    return String(cString: buffer)
                }
            } else if info.ai_family == AF_INET6,
                      let addr6 = info.ai_addr?.withMemoryRebound(to: sockaddr_in6.self, capacity: 1, { $0.pointee }) {
                var copy = addr6.sin6_addr
                var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                if inet_ntop(AF_INET6, &copy, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil {
                    return String(cString: buffer)
                }
            }
            cursor = info.ai_next
        }
        return nil
    }
}
