import Foundation

enum ObstacleBridgeAdminSnapshotSupport {
    static func statusEnvelope(
        runtimeOwner: String,
        runtimeMode: String,
        adminWebName: String,
        adminUI: [String: Any],
        securityAdvisor: [String: Any],
        startedAt: TimeInterval,
        uptimeSec: Int,
        bootstrapState: [String: Any],
        transportRuntime: [String: Any],
        compressLayer: Any,
        extra: [String: Any] = [:]
    ) -> [String: Any] {
        var payload: [String: Any] = [
            "runtime_owner": runtimeOwner,
            "runtime_mode": runtimeMode,
            "admin_web_name": adminWebName,
            "admin_ui": adminUI,
            "security_advisor": securityAdvisor,
            "started_at": startedAt,
            "uptime_sec": uptimeSec,
            "bootstrap_state": bootstrapState,
            "transport_runtime": transportRuntime,
            "compress_layer": compressLayer,
        ]
        for (key, value) in extra {
            payload[key] = value
        }
        return payload
    }

    static func metaEnvelope(
        runtimeOwner: String,
        runtimeMode: String,
        adminWebName: String,
        adminUI: [String: Any],
        securityAdvisor: [String: Any],
        startedAt: TimeInterval,
        uptimeSec: Int,
        bootstrapState: [String: Any],
        transportRuntime: [String: Any],
        compressLayer: Any,
        extra: [String: Any] = [:]
    ) -> [String: Any] {
        statusEnvelope(
            runtimeOwner: runtimeOwner,
            runtimeMode: runtimeMode,
            adminWebName: adminWebName,
            adminUI: adminUI,
            securityAdvisor: securityAdvisor,
            startedAt: startedAt,
            uptimeSec: uptimeSec,
            bootstrapState: bootstrapState,
            transportRuntime: transportRuntime,
            compressLayer: compressLayer,
            extra: extra
        )
    }

    static func configEnvelope(config: [String: Any], schema: [String: Any]) -> [String: Any] {
        [
            "config": config,
            "schema": schema,
        ]
    }

    static func transportRuntimeEnvelope(
        kind: String,
        status: Any,
        myudp: [String: Any]? = nil,
        tcp: [String: Any]? = nil,
        quic: [String: Any]? = nil,
        websocket: [String: Any]? = nil,
        extra: [String: Any] = [:]
    ) -> [String: Any] {
        var snapshot: [String: Any] = [
            "kind": kind,
            "status": status,
        ]
        if let websocket {
            snapshot["websocket"] = websocket
        }
        if let tcp {
            snapshot["tcp"] = tcp
        }
        if let quic {
            snapshot["quic"] = quic
        }
        if let myudp {
            snapshot["myudp"] = myudp
        }
        for (key, value) in extra {
            snapshot[key] = value
        }
        return snapshot
    }

    static func transportConnected(lastRttOKNSValue: Any?, lastRxWallNSValue: Any? = nil, fallbackConnected: Bool) -> Bool {
        let lastRttOkNS = uint64Value(lastRttOKNSValue) ?? 0
        let lastRxWallNS = uint64Value(lastRxWallNSValue) ?? 0
        let activityNS = max(lastRttOkNS, lastRxWallNS)
        guard activityNS > 0 else {
            return fallbackConnected
        }
        let now = DispatchTime.now().uptimeNanoseconds
        guard now >= activityNS else {
            return false
        }
        return (now - activityNS) <= 20_000_000_000
    }

    static func lastIncomingAgeSeconds(from runtime: [String: Any]) -> Any {
        guard let lastRxWall = uint64Value(runtime["last_rx_wall_ns"]), lastRxWall > 0 else {
            return NSNull()
        }
        let now = DispatchTime.now().uptimeNanoseconds
        guard now >= lastRxWall else {
            return NSNull()
        }
        return Double(now - lastRxWall) / 1_000_000_000.0
    }

    static func selectedTransportRuntime(from transportRuntime: [String: Any], preferredKind: String? = nil) -> [String: Any] {
        let kind = (preferredKind ?? stringValue(transportRuntime["kind"]) ?? "myudp").lowercased()
        let key: String
        switch kind {
        case "ws", "websocket":
            key = "websocket"
        case "tcp":
            key = "tcp"
        case "quic":
            key = "quic"
        default:
            key = "myudp"
        }
        return transportRuntime[key] as? [String: Any] ?? transportRuntime
    }

    static func selectedProtocolStats(from transportRuntime: [String: Any], preferredKind: String? = nil) -> [String: Any] {
        let selected = selectedTransportRuntime(from: transportRuntime, preferredKind: preferredKind)
        return selected["protocol_stats"] as? [String: Any]
            ?? transportRuntime["protocol_stats"] as? [String: Any]
            ?? [:]
    }

    static func connectionLayers(from transportRuntime: [String: Any], preferredKind: String? = nil) -> [[String: Any]] {
        let selected = selectedTransportRuntime(from: transportRuntime, preferredKind: preferredKind)
        return selected["connection_layers"] as? [[String: Any]] ?? []
    }

    static func appReady(from transportRuntime: [String: Any], preferredKind: String? = nil) -> Bool {
        let layers = connectionLayers(from: transportRuntime, preferredKind: preferredKind)
        if let last = layers.last, let ready = last["app_ready"] as? Bool {
            return ready
        }
        let selected = selectedTransportRuntime(from: transportRuntime, preferredKind: preferredKind)
        return (selected["app_ready"] as? Bool)
            ?? (selected["overlay_connected"] as? Bool)
            ?? false
    }

    static func peerMetric(_ key: String, from transportRuntime: [String: Any], preferredKind: String? = nil) -> Any {
        let selected = selectedTransportRuntime(from: transportRuntime, preferredKind: preferredKind)
        if let value = nonNullValue(selected[key]) {
            return value
        }
        let protocolStats = selectedProtocolStats(from: transportRuntime, preferredKind: preferredKind)
        if let value = nonNullValue(protocolStats[key]) {
            return value
        }
        if key == "rtt_est_ms",
           let transmitDelay = doubleValue(protocolStats["transmit_delay_est_ms"] ?? selected["transmit_delay_est_ms"]),
           transmitDelay > 0.0 {
            return max(0.0, transmitDelay * 2.0)
        }
        return NSNull()
    }

    static func peerLastIncomingAgeSeconds(from transportRuntime: [String: Any], preferredKind: String? = nil) -> Any {
        let selected = selectedTransportRuntime(from: transportRuntime, preferredKind: preferredKind)
        let selectedAge = lastIncomingAgeSeconds(from: selected)
        if !(selectedAge is NSNull) {
            return selectedAge
        }
        return lastIncomingAgeSeconds(from: transportRuntime)
    }

    static func peerThrottleSnapshot(peerID: Int, connectionsSnapshot: [String: Any]) -> [String: Any] {
        var summary: [String: Any]? = nil
        for key in ["udp", "tcp", "tun"] {
            guard let rows = connectionsSnapshot[key] as? [[String: Any]] else {
                continue
            }
            for row in rows {
                if let throttle = row["throttle"] as? [String: Any], rowMatchesPeer(row, peerID: peerID, protocolKey: key) {
                    summary = mergeThrottleSummary(current: summary, candidate: throttle)
                }
            }
        }
        return summary ?? [
            "applicable": false,
            "active": false,
            "reason": "no_local_ingress",
        ]
    }

    static func peersSnapshotForAPI(_ peers: [[String: Any]]) -> [[String: Any]] {
        peers.map { peer in
            guard let throttle = peer["throttle"] as? [String: Any] else {
                return peer
            }
            var sanitized = peer
            sanitized["throttle"] = throttle.filter { key, _ in
                ![
                    "scope_id", "mode", "budget_bytes", "used_bytes", "remaining_bytes",
                    "aggregate", "scope", "transport_prev_window_bytes", "prev_window_bytes",
                    "curr_window_bytes", "throttle_drop_count",
                ].contains(key)
            }
            return sanitized
        }
    }

    private static func mergeThrottleSummary(current: [String: Any]?, candidate: [String: Any]) -> [String: Any] {
        if boolValue(candidate["applicable"]) == false {
            return current ?? [
                "applicable": false,
                "active": false,
                "reason": String(describing: candidate["reason"] ?? "not_applicable"),
            ]
        }
        guard var current else {
            return [
                "applicable": true,
                "active": boolValue(candidate["active"]),
                "stalled": boolValue(candidate["stalled"]),
                "backpressure_active": boolValue(candidate["backpressure_active"]),
                "disabled": boolValue(candidate["disabled"]),
                "waiting_count": intValue(candidate["waiting_count"]),
                "inflight": intValue(candidate["inflight"]),
                "max_inflight": intValue(candidate["max_inflight"]),
                "transmit_delay_est_ms": doubleValue(candidate["transmit_delay_est_ms"]) ?? 0.0,
                "rtt_est_ms": doubleValue(candidate["rtt_est_ms"]) ?? 0.0,
            ]
        }
        current["applicable"] = true
        current["active"] = boolValue(current["active"]) || boolValue(candidate["active"])
        current["stalled"] = boolValue(current["stalled"]) || boolValue(candidate["stalled"])
        current["backpressure_active"] = boolValue(current["backpressure_active"]) || boolValue(candidate["backpressure_active"])
        current["disabled"] = boolValue(current["disabled"]) && boolValue(candidate["disabled"])
        current["waiting_count"] = max(intValue(current["waiting_count"]), intValue(candidate["waiting_count"]))
        current["inflight"] = max(intValue(current["inflight"]), intValue(candidate["inflight"]))
        current["max_inflight"] = max(intValue(current["max_inflight"]), intValue(candidate["max_inflight"]))
        current["transmit_delay_est_ms"] = max(doubleValue(current["transmit_delay_est_ms"]) ?? 0.0, doubleValue(candidate["transmit_delay_est_ms"]) ?? 0.0)
        current["rtt_est_ms"] = max(doubleValue(current["rtt_est_ms"]) ?? 0.0, doubleValue(candidate["rtt_est_ms"]) ?? 0.0)
        return current
    }

    private static func rowMatchesPeer(_ row: [String: Any], peerID: Int, protocolKey: String) -> Bool {
        if let value = row["peer_id"] as? Int {
            return value == peerID
        }
        if let value = row["peer_id"] as? String {
            if value == "\(peerID)" || value.hasSuffix(":\(peerID)") {
                return true
            }
        }
        if peerID == 1,
           protocolKey == "tun",
           row["throttle"] is [String: Any],
           row["chan_id"] != nil,
           String(describing: row["state"] ?? "connected").lowercased() != "listening" {
            return true
        }
        return false
    }

    private static func intValue(_ value: Any?) -> Int {
        if let value = value as? Int {
            return value
        }
        if let value = value as? NSNumber {
            return value.intValue
        }
        if let value = value as? String, let parsed = Int(value) {
            return parsed
        }
        return 0
    }

    private static func boolValue(_ value: Any?) -> Bool {
        if let value = value as? Bool {
            return value
        }
        if let value = value as? NSNumber {
            return value.boolValue
        }
        if let value = value as? String {
            let lowered = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            return ["1", "true", "yes", "on"].contains(lowered)
        }
        return false
    }

    private static func nonNullValue(_ value: Any?) -> Any? {
        guard let value, !(value is NSNull) else {
            return nil
        }
        return value
    }

    private static func doubleValue(_ value: Any?) -> Double? {
        if let value = value as? Double {
            return value
        }
        if let value = value as? Float {
            return Double(value)
        }
        if let value = value as? Int {
            return Double(value)
        }
        if let value = value as? UInt64 {
            return Double(value)
        }
        if let value = value as? NSNumber {
            return value.doubleValue
        }
        if let value = value as? String {
            return Double(value)
        }
        return nil
    }

    private static func stringValue(_ value: Any?) -> String? {
        if let value = value as? String {
            return value
        }
        if let value = value as? NSNumber {
            return value.stringValue
        }
        return nil
    }

    private static func uint64Value(_ value: Any?) -> UInt64? {
        if let value = value as? UInt64 {
            return value
        }
        if let value = value as? NSNumber {
            return value.uint64Value
        }
        return nil
    }
}
