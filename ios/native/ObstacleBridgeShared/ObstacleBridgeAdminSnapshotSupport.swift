import Foundation

enum ObstacleBridgeAdminSnapshotSupport {
    private static let peerThrottleRatio = 0.9

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
                guard let ownership = row["shared_tun_ownership"] as? [String: Any] else {
                    continue
                }
                let bindings = ownership["active_peer_bindings"] as? [[String: Any]] ?? []
                for binding in bindings where intValue(binding["peer_id"]) == peerID {
                    let prevWindowBytes = intValue(binding["throttle_prev_window_bytes"])
                    let usedBytes = intValue(binding["throttle_curr_window_bytes"])
                    let throttleDropCount = intValue(binding["throttle_drop_count"])
                    let budgetBytes = Int(Double(prevWindowBytes) * peerThrottleRatio)
                    let remainingBytes = max(0, budgetBytes - usedBytes)
                    let scopeID = "shared-tun-peer:\(peerID)"
                    summary = mergeThrottleSummary(
                        current: summary,
                        candidate: [
                            "applicable": true,
                            "active": usedBytes > 0 || throttleDropCount > 0,
                            "stalled": false,
                            "backpressure_active": false,
                            "disabled": false,
                            "budget_bytes": budgetBytes,
                            "used_bytes": usedBytes,
                            "remaining_bytes": remainingBytes,
                            "aggregate": [
                                "scope_id": scopeID,
                                "budget_bytes": budgetBytes,
                                "used_bytes": usedBytes,
                                "remaining_bytes": remainingBytes,
                                "prev_window_bytes": prevWindowBytes,
                                "throttle_drop_count": throttleDropCount,
                            ],
                            "scope": [
                                "scope_id": scopeID,
                                "budget_bytes": budgetBytes,
                                "used_bytes": usedBytes,
                                "remaining_bytes": remainingBytes,
                                "prev_window_bytes": prevWindowBytes,
                                "throttle_drop_count": throttleDropCount,
                            ],
                        ]
                    )
                }
            }
        }
        return summary ?? [
            "applicable": false,
            "active": false,
            "reason": "no_local_ingress",
        ]
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
                "budget_bytes": intValue(candidate["budget_bytes"]),
                "used_bytes": intValue(candidate["used_bytes"]),
                "remaining_bytes": intValue(candidate["remaining_bytes"]),
                "aggregate": (candidate["aggregate"] as? [String: Any]) ?? [:],
                "scope": candidate["scope"] ?? NSNull(),
            ]
        }
        current["applicable"] = true
        current["active"] = boolValue(current["active"]) || boolValue(candidate["active"])
        current["stalled"] = boolValue(current["stalled"]) || boolValue(candidate["stalled"])
        current["backpressure_active"] = boolValue(current["backpressure_active"]) || boolValue(candidate["backpressure_active"])
        current["disabled"] = boolValue(current["disabled"]) && boolValue(candidate["disabled"])
        current["budget_bytes"] = max(intValue(current["budget_bytes"]), intValue(candidate["budget_bytes"]))
        current["used_bytes"] = max(intValue(current["used_bytes"]), intValue(candidate["used_bytes"]))
        current["remaining_bytes"] = min(intValue(current["remaining_bytes"]), intValue(candidate["remaining_bytes"]))

        let currentAggregate = current["aggregate"] as? [String: Any] ?? [:]
        let candidateAggregate = candidate["aggregate"] as? [String: Any] ?? [:]
        if currentAggregate.isEmpty {
            current["aggregate"] = candidateAggregate
        } else if !candidateAggregate.isEmpty {
            current["aggregate"] = mergedThrottleScope(current: currentAggregate, candidate: candidateAggregate)
        }

        let currentScope = current["scope"] as? [String: Any]
        let candidateScope = candidate["scope"] as? [String: Any]
        if currentScope == nil {
            current["scope"] = candidateScope ?? NSNull()
        } else if let candidateScope, intValue(candidateScope["remaining_bytes"]) < intValue(currentScope?["remaining_bytes"]) {
            current["scope"] = candidateScope
        }
        return current
    }

    private static func mergedThrottleScope(current: [String: Any], candidate: [String: Any]) -> [String: Any] {
        [
            "scope_id": String(describing: current["scope_id"] ?? candidate["scope_id"] ?? ""),
            "budget_bytes": max(intValue(current["budget_bytes"]), intValue(candidate["budget_bytes"])),
            "used_bytes": max(intValue(current["used_bytes"]), intValue(candidate["used_bytes"])),
            "remaining_bytes": min(intValue(current["remaining_bytes"]), intValue(candidate["remaining_bytes"])),
            "prev_window_bytes": max(intValue(current["prev_window_bytes"]), intValue(candidate["prev_window_bytes"])),
            "throttle_drop_count": max(intValue(current["throttle_drop_count"]), intValue(candidate["throttle_drop_count"])),
        ]
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
