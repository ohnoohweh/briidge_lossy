import Foundation

/// Portable counters and diagnostic projections for TUN ICMP probes.
/// Packet I/O, name resolution, and waiter synchronization stay in adapters.
enum ObstacleBridgeTunProbeDiagnosticsPolicy {
    static let localReplyStageKeys = [
        "local_reply_skip_overlay_inactive", "local_reply_drop_oversize",
        "local_reply_drop_throttled", "local_reply_drop_shared_route",
        "local_reply_virtual_probe_delivery", "local_reply_drop_no_channel",
        "local_reply_drop_missing_service_spec", "local_reply_bound_new_channel",
        "local_reply_before_overlay_send",
    ]
    static let tunICMPStageKeys = [
        "from_local_tun_read", "overlay_tx_before_send_app", "overlay_rx_after_unpack",
        "from_peer_before_local_write", "to_local_tun_written",
    ] + localReplyStageKeys
    static let tunProbeBoundaryKeys = [
        "probe_attempt_started", "probe_waiter_registered", "probe_injected_local_virtual",
        "probe_injected_kernel", "probe_injected_channelmux", "probe_send_completed",
        "probe_reply_matched", "probe_reply_consumed_before_local_write",
        "probe_reply_late_after_timeout", "own_probe_reply_unmatched",
        "foreign_probe_reply_unmatched", "probe_reply_unmatched", "probe_timeout",
        "probe_exception", "helper_read_packet", "helper_read_probe_packet",
        "helper_write_packet", "helper_write_probe_packet", "helper_write_error",
    ]

    static func makeCounts(_ keys: [String]) -> [String: Int] {
        Dictionary(uniqueKeysWithValues: keys.map { ($0, 0) })
    }

    static func record(_ key: String, counts: inout [String: Int]) {
        guard counts[key] != nil else { return }
        counts[key, default: 0] += 1
    }

    static func cacheKey(probeKind: String, ifname: String, target: String) -> String {
        "\(probeKind.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())|\(ifname)|\(target)"
    }

    static func label(_ probeKind: String) -> String {
        switch probeKind.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "peer": return "TUN connectivity verified"
        case "global": return "TUN global connectivity verified"
        default: return "TUN connectivity verification"
        }
    }

    static func kindCode(_ probeKind: String) -> UInt8 {
        probeKind.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "global"
            ? ObstacleBridgeTunPing.probeKindGlobal : ObstacleBridgeTunPing.probeKindPeer
    }

    static func nameResolution(status: String, resolvedIP: String = "", detail: String = "") -> [String: Any] {
        ["status": status, "resolved_ip": resolvedIP, "detail": detail]
    }

    static func result(probeKind: String, target: String, ok: Bool, state: String, summary: String, detail: String, checkedAtUnixTS: TimeInterval, resolvedTarget: String = "", nameResolution: [String: Any] = [:], valueMS: Double? = nil, lastSuccessAgoS: Double? = nil, lastSuccessRTTMS: Double? = nil) -> [String: Any] {
        var result: [String: Any] = [
            "label": label(probeKind), "ok": ok, "state": state, "summary": summary,
            "detail": detail, "target": target, "resolved_target": resolvedTarget,
            "name_resolution": nameResolution, "method": "internal_icmp_echo",
            "checked_at_unix_ts": checkedAtUnixTS, "value_ms": NSNull(),
            "last_success_ago_s": NSNull(), "last_success_rtt_ms": NSNull(),
        ]
        if let valueMS { result["value_ms"] = valueMS; result["last_success_rtt_ms"] = valueMS }
        else if let lastSuccessRTTMS { result["last_success_rtt_ms"] = lastSuccessRTTMS }
        if let lastSuccessAgoS { result["last_success_ago_s"] = lastSuccessAgoS }
        return result
    }

    static func runtimeSnapshot(probeKind: String, ifname: String, target: String, resolvedTarget: String, timeoutSeconds: TimeInterval, capturedAtUnixTS: TimeInterval, overlayTransport: String, overlayConnected: Bool, sessionConnected: Bool, sessionAppReady: Bool, acceptingEnabled: Bool, secureLinkState: String, secureLinkLastEvent: String, secureLinkFailureReason: String, backpressure: [String: Any]) -> [String: Any] {
        [
            "probe_kind": probeKind, "ifname": ifname.trimmingCharacters(in: .whitespacesAndNewlines),
            "target": target.trimmingCharacters(in: .whitespacesAndNewlines),
            "resolved_target": resolvedTarget.trimmingCharacters(in: .whitespacesAndNewlines),
            "timeout_s": timeoutSeconds, "captured_at_unix_ts": capturedAtUnixTS,
            "overlay_transport": overlayTransport, "overlay_connected": overlayConnected,
            "session_connected": sessionConnected, "session_app_ready": sessionAppReady,
            "accepting_enabled": acceptingEnabled, "secure_link_state": secureLinkState,
            "secure_link_last_event": secureLinkLastEvent,
            "secure_link_failure_reason": secureLinkFailureReason, "backpressure": backpressure,
        ]
    }
}
