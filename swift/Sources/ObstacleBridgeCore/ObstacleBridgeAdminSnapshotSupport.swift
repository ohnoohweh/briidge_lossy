import Foundation

public enum ObstacleBridgeAdminSnapshotSupport {
    /// Maps the portable ChannelMux service catalog to the role shown by the
    /// Admin API. `own_servers` accepts local connections on this runtime;
    /// `remote_servers` represents a listener owned by the authenticated peer.
    /// This is protocol semantics, not a host socket implementation detail.
    public static func serviceConnectionRole(catalog: String) -> String {
        catalog == "own_servers" ? "server" : "client"
    }

    public static func statusEnvelope(
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
            // These keys are consumed directly by the shared Admin page. A
            // host supplies facts in `extra`, but Core owns the stable shape.
            "app": runtimeOwner,
            "platform": runtimeMode,
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
            "overlay_transport": stringValue(transportRuntime["kind"]) ?? "",
            "transport_state": transportRuntime["status"] ?? "disconnected",
            "app_ready": appReady(from: transportRuntime),
            "connection_layers": connectionLayers(from: transportRuntime),
            "peer": NSNull(),
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

    public static func transportRuntimeEnvelope(
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

    /// Builds the portable `/api/peers` row. Runtime hosts supply measured
    /// facts; Core supplies every field and nested object expected by the
    /// shared WebAdmin and API consumers. This prevents host-specific omitted
    /// fields from becoming misleading `n/a` values in the dashboard.
    public static func peerEnvelope(
        id: Any,
        peerID: Any? = nil,
        transport: String,
        state: String,
        connected: Bool,
        appReady: Bool,
        peer: Any = NSNull(),
        listen: Any = NSNull(),
        resolvedPeer: Any = NSNull(),
        connectionEpoch: Any = NSNull(),
        connectedSinceUnixTS: Any = NSNull(),
        lastIncomingAgeSeconds: Any = NSNull(),
        rttEstimateMS: Any = NSNull(),
        transmitDelayEstimateMS: Any = NSNull(),
        decodeErrors: Any = 0,
        inflight: Any = 0,
        traffic: [String: Any] = [:],
        openConnections: [String: Any] = [:],
        connectionLayers: [[String: Any]] = [],
        secureLink: [String: Any] = [:],
        compressionLayer: [String: Any] = [:],
        throttle: [String: Any] = [:],
        runtime: [String: Any] = [:],
        extra: [String: Any] = [:]
    ) -> [String: Any] {
        let normalizedSecureLink: [String: Any] = [
            "state": "disconnected", "authenticated": false,
            "enabled": false, "mode": "off",
            "rekey_in_progress": false,
            "frames_from_client_passed_total": 0,
            "frames_from_client_dropped_total": 0,
            "frames_to_client_passed_total": 0,
            "connected_since_unix_ts": NSNull(),
        ].merging(secureLink, uniquingKeysWith: { _, supplied in supplied })
        let normalizedCompression: [String: Any] = [
            "enabled": false, "algorithm": "",
            "compress_attempts_total": 0, "compress_applied_total": 0,
            "compress_input_bytes_total": 0, "compress_output_bytes_total": 0,
            "decompress_ok_total": 0, "decompress_fail_total": 0,
        ].merging(compressionLayer, uniquingKeysWith: { _, supplied in supplied })
        let normalizedTraffic: [String: Any] = [
            "rx_bytes": 0, "tx_bytes": 0, "rx_msgs": 0, "tx_msgs": 0,
        ].merging(traffic, uniquingKeysWith: { _, supplied in supplied })
        let normalizedConnections: [String: Any] = [
            "udp": 0, "tcp": 0, "tun": 0,
        ].merging(openConnections, uniquingKeysWith: { _, supplied in supplied })
        let normalizedThrottle: [String: Any] = [
            "applicable": false, "active": false, "reason": "no_local_ingress",
        ].merging(throttle, uniquingKeysWith: { _, supplied in supplied })

        var payload = extra
        payload["id"] = id
        payload["peer_id"] = peerID ?? id
        payload["transport"] = transport
        payload["state"] = state
        payload["connected"] = connected
        payload["app_ready"] = appReady
        payload["listen"] = listen
        payload["peer"] = peer
        payload["resolved_peer"] = resolvedPeer
        payload["connection_epoch"] = connectionEpoch
        payload["connected_since_unix_ts"] = connectedSinceUnixTS
        payload["last_incoming_age_seconds"] = lastIncomingAgeSeconds
        payload["rtt_est_ms"] = rttEstimateMS
        payload["transmit_delay_est_ms"] = transmitDelayEstimateMS
        payload["decode_errors"] = decodeErrors
        payload["inflight"] = inflight
        payload["traffic"] = normalizedTraffic
        payload["open_connections"] = normalizedConnections
        payload["connection_layers"] = connectionLayers
        payload["secure_link"] = normalizedSecureLink
        // Keep the legacy spelling while making the shared spelling canonical.
        payload["compress_layer"] = normalizedCompression
        payload["compression_layer"] = normalizedCompression
        payload["throttle"] = normalizedThrottle
        payload["runtime"] = runtime
        return payload
    }

    /// The live socket is a high-frequency rendering channel, not a transport
    /// for diagnostic histories. Keep its status schema identical for
    /// dashboard fields while leaving bounded-but-large diagnostics on the
    /// full `/api/status` document.
    public static func liveStatusEnvelope(_ status: [String: Any]) -> [String: Any] {
        var live = status
        live.removeValue(forKey: "runtime_metrics")
        live.removeValue(forKey: "runtime_health_recent_records")
        return live
    }

    /// Accept older host snapshots during the migration, but serialize all of
    /// them through the same Core-owned `/api/peers` structure.
    public static func canonicalPeerEnvelope(_ peer: [String: Any]) -> [String: Any] {
        let identifier = peer["id"] ?? peer["peer_id"] ?? "configured-peer"
        return peerEnvelope(
            id: identifier,
            peerID: peer["peer_id"],
            transport: stringValue(peer["transport"]) ?? "",
            state: stringValue(peer["state"]) ?? "disconnected",
            connected: boolValue(peer["connected"]),
            appReady: boolValue(peer["app_ready"]),
            peer: peer["peer"] ?? NSNull(),
            listen: peer["listen"] ?? NSNull(),
            resolvedPeer: peer["resolved_peer"] ?? NSNull(),
            connectionEpoch: peer["connection_epoch"] ?? NSNull(),
            connectedSinceUnixTS: peer["connected_since_unix_ts"] ?? NSNull(),
            lastIncomingAgeSeconds: peer["last_incoming_age_seconds"] ?? NSNull(),
            rttEstimateMS: peer["rtt_est_ms"] ?? NSNull(),
            transmitDelayEstimateMS: peer["transmit_delay_est_ms"] ?? NSNull(),
            decodeErrors: peer["decode_errors"] ?? 0,
            inflight: peer["inflight"] ?? 0,
            traffic: peer["traffic"] as? [String: Any] ?? [:],
            openConnections: peer["open_connections"] as? [String: Any] ?? [:],
            connectionLayers: peer["connection_layers"] as? [[String: Any]] ?? [],
            secureLink: peer["secure_link"] as? [String: Any] ?? [:],
            compressionLayer: (peer["compress_layer"] ?? peer["compression_layer"]) as? [String: Any] ?? [:],
            throttle: peer["throttle"] as? [String: Any] ?? [:],
            runtime: peer["runtime"] as? [String: Any] ?? [:],
            extra: peer
        )
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

    public static func selectedTransportRuntime(from transportRuntime: [String: Any], preferredKind: String? = nil) -> [String: Any] {
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

    public static func peersSnapshotForAPI(_ peers: [[String: Any]]) -> [[String: Any]] {
        peers.map { peer in
            var sanitized = canonicalPeerEnvelope(peer)
            guard let throttle = sanitized["throttle"] as? [String: Any] else { return sanitized }
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
