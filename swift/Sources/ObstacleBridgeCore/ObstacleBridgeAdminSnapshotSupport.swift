import Foundation

/// Redacted, host-neutral facts needed to render one protocol peer in the
/// Admin API. Runtime adapters translate their own state into this value; Core
/// owns the resulting JSON shape so Apple and Linux cannot drift by omission.
public struct ObstacleBridgeAdminPeerFacts: Sendable {
    public let identity: String
    public let transport: String
    public let lifecycleState: String
    public let secureLinkState: String
    public let connectionEpoch: UInt64
    public let sessionID: UInt64?
    public let pendingRekeySessionID: UInt64?
    public let ready: Bool
    public let authenticated: Bool
    public let applicationSendingBlocked: Bool
    public let attempts: Int
    public let nextRetryMilliseconds: Int?
    public let protectedTxCounter: UInt64
    public let protectedRxCounter: UInt64
    public let protectedFramesSentTotal: UInt64
    public let protectedFramesReceivedTotal: UInt64
    public let authenticatedGenerationsTotal: UInt64
    public let rekeysCompletedTotal: UInt64
    public let connectedSinceUnixTS: TimeInterval?
    public let lastIncomingAgeSeconds: TimeInterval?
    public let observedPublicIP: String
    public let observedPublicPort: Int?
    public let compression: ObstacleBridgeMuxCompressionSnapshot
    public let secureLinkMode: String
    public let endpointHost: String?
    public let endpointPort: Int
    public let configuredCandidates: [String]
    public let activeTCPChannels: Int
    public let activeUDPChannels: Int
    public let failureReason: String?
    public let traffic: [String: UInt64]
    public let myudpStats: [String: UInt64]

    public init(
        identity: String, transport: String, lifecycleState: String,
        secureLinkState: String, connectionEpoch: UInt64, sessionID: UInt64?,
        pendingRekeySessionID: UInt64?, ready: Bool, authenticated: Bool,
        applicationSendingBlocked: Bool, attempts: Int,
        nextRetryMilliseconds: Int?, protectedTxCounter: UInt64,
        protectedRxCounter: UInt64, protectedFramesSentTotal: UInt64,
        protectedFramesReceivedTotal: UInt64,
        authenticatedGenerationsTotal: UInt64, rekeysCompletedTotal: UInt64,
        connectedSinceUnixTS: TimeInterval?, lastIncomingAgeSeconds: TimeInterval?,
        observedPublicIP: String = "", observedPublicPort: Int? = nil,
        compression: ObstacleBridgeMuxCompressionSnapshot, secureLinkMode: String,
        endpointHost: String?, endpointPort: Int, configuredCandidates: [String],
        activeTCPChannels: Int, activeUDPChannels: Int, failureReason: String?,
        traffic: [String: UInt64] = [:], myudpStats: [String: UInt64]
    ) {
        self.identity = identity; self.transport = transport; self.lifecycleState = lifecycleState
        self.secureLinkState = secureLinkState; self.connectionEpoch = connectionEpoch
        self.sessionID = sessionID; self.pendingRekeySessionID = pendingRekeySessionID
        self.ready = ready; self.authenticated = authenticated
        self.applicationSendingBlocked = applicationSendingBlocked; self.attempts = attempts
        self.nextRetryMilliseconds = nextRetryMilliseconds; self.protectedTxCounter = protectedTxCounter
        self.protectedRxCounter = protectedRxCounter; self.protectedFramesSentTotal = protectedFramesSentTotal
        self.protectedFramesReceivedTotal = protectedFramesReceivedTotal
        self.authenticatedGenerationsTotal = authenticatedGenerationsTotal; self.rekeysCompletedTotal = rekeysCompletedTotal
        self.connectedSinceUnixTS = connectedSinceUnixTS; self.lastIncomingAgeSeconds = lastIncomingAgeSeconds
        self.observedPublicIP = observedPublicIP; self.observedPublicPort = observedPublicPort
        self.compression = compression; self.secureLinkMode = secureLinkMode
        self.endpointHost = endpointHost; self.endpointPort = endpointPort
        self.configuredCandidates = configuredCandidates; self.activeTCPChannels = activeTCPChannels
        self.activeUDPChannels = activeUDPChannels; self.failureReason = failureReason
        self.traffic = traffic; self.myudpStats = myudpStats
    }
}

public enum ObstacleBridgeAdminSnapshotSupport {
    /// Sums the common connection-table counters for the enclosing peer row.
    /// Connection rows retain per-channel detail while the peer page presents
    /// the complete authenticated ChannelMux traffic for that peer.
    public static func aggregateConnectionTraffic(_ connections: [String: Any]) -> [String: UInt64] {
        let keys = ["rx_bytes", "tx_bytes", "rx_msgs", "tx_msgs"]
        var totals = Dictionary(uniqueKeysWithValues: keys.map { ($0, UInt64(0)) })
        for protocolName in ["tcp", "udp", "tun"] {
            guard let rows = connections[protocolName] as? [[String: Any]] else { continue }
            for row in rows {
                guard let stats = row["stats"] as? [String: Any] else { continue }
                for key in keys {
                    let value: UInt64
                    if let number = stats[key] as? UInt64 { value = number }
                    else if let number = stats[key] as? Int { value = UInt64(max(0, number)) }
                    else if let number = stats[key] as? NSNumber { value = number.uint64Value }
                    else { value = 0 }
                    totals[key, default: 0] &+= value
                }
            }
        }
        return totals
    }

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
        var normalizedSecureLink: [String: Any] = [
            "state": "disconnected", "authenticated": false,
            "enabled": false, "mode": "off",
            "rekey_in_progress": false,
            "last_event": "bootstrap",
            "last_event_unix_ts": NSNull(),
            "last_authenticated_unix_ts": NSNull(),
            "authenticated_sessions_total": 0,
            "last_rekey_trigger": "none",
            "frames_from_client_passed_total": 0,
            "frames_from_client_dropped_total": 0,
            "frames_to_client_passed_total": 0,
            "connected_since_unix_ts": NSNull(),
        ].merging(secureLink, uniquingKeysWith: { _, supplied in supplied })
        // Older and platform-specific producers historically supplied only
        // the Core generation counter.  Preserve that as the API's durable
        // session-total spelling and derive lifecycle timestamps from the
        // authenticated epoch when a more specific protocol event is absent.
        if secureLink["authenticated_sessions_total"] == nil {
            normalizedSecureLink["authenticated_sessions_total"] = secureLink["authenticated_generations_total"] ?? 0
        }
        let secureLinkAuthenticated = normalizedSecureLink["authenticated"] as? Bool ?? false
        if secureLink["last_event"] == nil {
            normalizedSecureLink["last_event"] = secureLinkAuthenticated ? "authenticated" : (normalizedSecureLink["state"] ?? "bootstrap")
        }
        if secureLink["last_event_unix_ts"] == nil, secureLinkAuthenticated {
            normalizedSecureLink["last_event_unix_ts"] = connectedSinceUnixTS
        }
        if secureLink["last_authenticated_unix_ts"] == nil, secureLinkAuthenticated {
            normalizedSecureLink["last_authenticated_unix_ts"] = connectedSinceUnixTS
        }
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

    /// Renders a complete peer row from the portable facts used by every
    /// native host. No HTTP adapter constructs protocol or compression schema.
    public static func peerEnvelope(facts: ObstacleBridgeAdminPeerFacts) -> [String: Any] {
        let transportConnected = facts.lifecycleState == "connected"
        let secureLinkEnabled = facts.secureLinkMode != "off"
        let secureLinkConnected = secureLinkEnabled ? facts.authenticated : transportConnected
        let compressionConnected = facts.compression.enabled && facts.ready
        let compression: [String: Any] = [
            "enabled": facts.compression.enabled, "algorithm": facts.compression.algorithm,
            "level": facts.compression.level, "min_bytes": facts.compression.minimumBodyBytes,
            "compress_attempts_total": facts.compression.compressAttemptsTotal,
            "compress_applied_total": facts.compression.compressAppliedTotal,
            "compress_skipped_no_gain_total": facts.compression.compressSkippedNoGainTotal,
            "compress_input_bytes_total": facts.compression.compressInputBytesTotal,
            "compress_output_bytes_total": facts.compression.compressOutputBytesTotal,
            "compressed_frames_sent_total": facts.compression.compressedFramesSentTotal,
            "compressed_frames_received_total": facts.compression.compressedFramesReceivedTotal,
            "compressed_input_bytes_sent_total": facts.compression.compressedInputBytesSentTotal,
            "compressed_output_bytes_sent_total": facts.compression.compressedOutputBytesSentTotal,
            "compressed_input_bytes_received_total": facts.compression.compressedInputBytesReceivedTotal,
            "compressed_output_bytes_received_total": facts.compression.compressedOutputBytesReceivedTotal,
            "uncompressed_frames_sent_total": facts.compression.uncompressedFramesSentTotal,
            "uncompressed_frames_received_total": facts.compression.uncompressedFramesReceivedTotal,
            "uncompressed_bytes_sent_total": facts.compression.uncompressedBytesSentTotal,
            "uncompressed_bytes_received_total": facts.compression.uncompressedBytesReceivedTotal,
            "decompress_ok_total": facts.compression.decompressOKTotal,
            "decompress_fail_total": facts.compression.decompressFailTotal,
            "rejected_frames_total": facts.compression.rejectedFramesTotal,
            "rejected_bytes_total": facts.compression.rejectedBytesTotal,
        ]
        let layers: [[String: Any]] = [
            ["layer": "transport", "transport": facts.transport, "state": facts.lifecycleState, "epoch": facts.connectionEpoch, "connected": transportConnected, "app_ready": facts.ready],
            ["layer": "secure_link", "transport": facts.transport, "state": facts.secureLinkState, "epoch": facts.connectionEpoch, "connected": secureLinkConnected, "app_ready": facts.ready],
            ["layer": "compression", "transport": facts.transport, "state": compressionConnected ? "connected" : "disconnected", "epoch": facts.connectionEpoch, "connected": compressionConnected, "app_ready": facts.ready],
        ]
        var extra: [String: Any] = [
            "configured_candidates": facts.configuredCandidates,
            "active_host": facts.endpointHost ?? NSNull(),
            "port": facts.endpointPort,
            "failure_reason": facts.failureReason ?? NSNull(),
            "observed_public_ip": facts.observedPublicIP,
            "observed_public_port": facts.observedPublicPort ?? NSNull(),
        ]
        if facts.transport == "myudp" {
            extra["myudp"] = facts.myudpStats
        }
        let authenticatedTimestamp: Any = facts.authenticated && facts.connectedSinceUnixTS != nil
            ? facts.connectedSinceUnixTS! : NSNull()
        return peerEnvelope(
            id: facts.identity, peerID: facts.identity, transport: facts.transport,
            state: facts.lifecycleState, connected: transportConnected, appReady: facts.ready,
            peer: ["host": (facts.endpointHost as Any?) ?? NSNull(), "port": facts.endpointPort],
            connectionEpoch: facts.connectionEpoch,
            connectedSinceUnixTS: facts.connectedSinceUnixTS ?? NSNull(),
            lastIncomingAgeSeconds: facts.lastIncomingAgeSeconds ?? NSNull(),
            rttEstimateMS: facts.myudpStats["rtt_est_ms"] ?? 0,
            transmitDelayEstimateMS: facts.myudpStats["transmit_delay_est_ms"] ?? 0,
            decodeErrors: facts.myudpStats["stream_decode_errors"] ?? 0,
            inflight: facts.myudpStats["inflight"] ?? 0,
            traffic: facts.traffic.reduce(into: [String: Any]()) { $0[$1.key] = $1.value },
            openConnections: ["tcp": facts.activeTCPChannels, "udp": facts.activeUDPChannels, "tun": 0],
            connectionLayers: layers,
            secureLink: [
                "state": facts.secureLinkState, "authenticated": facts.authenticated,
                "session_id": facts.sessionID ?? NSNull(),
                "pending_rekey_session_id": facts.pendingRekeySessionID ?? NSNull(),
                "application_sending_blocked": facts.applicationSendingBlocked,
                "attempts": facts.attempts, "next_retry_milliseconds": facts.nextRetryMilliseconds ?? NSNull(),
                "protected_tx_counter": facts.protectedTxCounter, "protected_rx_counter": facts.protectedRxCounter,
                "protected_frames_sent_total": facts.protectedFramesSentTotal,
                "protected_frames_received_total": facts.protectedFramesReceivedTotal,
                "authenticated_generations_total": facts.authenticatedGenerationsTotal,
                "authenticated_sessions_total": facts.authenticatedGenerationsTotal,
                "rekeys_completed_total": facts.rekeysCompletedTotal,
                "enabled": secureLinkEnabled, "mode": facts.secureLinkMode,
                "rekey_in_progress": facts.pendingRekeySessionID != nil,
                "last_event": facts.authenticated ? "authenticated" : facts.secureLinkState,
                "last_event_unix_ts": authenticatedTimestamp,
                "last_authenticated_unix_ts": authenticatedTimestamp,
                "last_rekey_trigger": facts.rekeysCompletedTotal > 0 ? "completed" : "none",
                "frames_from_client_passed_total": facts.protectedFramesSentTotal,
                "frames_from_client_dropped_total": 0,
                "frames_to_client_passed_total": facts.protectedFramesReceivedTotal,
                "connected_since_unix_ts": facts.connectedSinceUnixTS ?? NSNull(),
            ],
            compressionLayer: compression, extra: extra
        )
    }

    /// The live socket is a high-frequency rendering channel. Runtime metrics
    /// are a bounded, current projection used by the Runtime Analysis tab, so
    /// they belong to every status frame just as they do in Python's Admin
    /// API. Keep only diagnostic history on the full `/api/status` document.
    ///
    /// Do not remove a field that the shared page renders here: a later live
    /// frame otherwise replaces the initial full snapshot and makes that page
    /// look empty on Swift hosts.
    public static func liveStatusEnvelope(_ status: [String: Any]) -> [String: Any] {
        var live = status
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
