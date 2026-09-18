import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// Rebuild ChannelMux control-plane frames whenever an overlay starts a new epoch.
typealias ObstacleBridgeChannelMuxStartupFramesProvider = (UInt64, UInt32) -> [Data]

final class ObstacleBridgeChannelMuxTunRuntime {
    private static let tunFragmentHeaderSize = 8
    private static let tunInflowThrottleWindowNS: UInt64 = 100_000_000
    private static let tunInflowThrottleRatio = 0.9

    struct LocalTunSendSnapshot {
        var chanID: Int
        var allocatedChannel: Bool
        var frames: [Data]
        var nextTunID: Int
        var nextCounter: Int
    }

    struct LocalTunOpenSnapshot {
        var chanID: Int
        var frames: [Data]
        var nextTunID: Int
        var nextCounter: Int
    }

    struct InboundTunOpenSnapshot {
        var accepted: Bool
        var chanID: Int
        var preferredChanID: Int?
        var remoteSpec: ObstacleBridgeChannelMuxCodec.ServiceSpec?
    }

    struct InboundTunOpenChunkSnapshot {
        var assembled: Bool
        var accepted: Bool
        var chanID: Int
        var preferredChanID: Int?
        var remoteSpec: ObstacleBridgeChannelMuxCodec.ServiceSpec?
    }

    struct InboundTunDataSnapshot {
        var delivered: Bool
        var packet: Data?
    }

    struct GuardedInboundTunDataSnapshot {
        var delivered: Bool
        var packet: Data?
        var ipVersion: Int?
        var sourceIP: String?
        var destinationIP: String?
        var dropReason: String?
    }

    struct SharedTunActivePeerBinding {
        var peerID: Int
        var preferredChanID: Int?
    }

    struct SharedTunPeerBindingState {
        var peerID: Int
        var preferredChanID: Int?
        var boundChanIDs: [Int]
        var rxPackets: Int = 0
        var rxBytes: Int = 0
        var txPackets: Int = 0
        var txBytes: Int = 0
        var learnedIPv4: [String] = []
        var learnedIPv6: [String] = []
    }

    struct SharedTunDisconnectCleanupSnapshot {
        var activePeerBindings: [SharedTunPeerBindingState]
        var peerRefByPeer: [Int: String]
        var peerIDByRef: [String: Int]
    }

    struct SharedTunOutboundRouteSnapshot {
        var routed: Bool
        var routeClass: String?
        var selectedPeerIDs: [Int]
        var selectedChanIDs: [Int]
        var ipVersion: Int?
        var destinationIP: String?
        var dropReason: String?
    }

    struct SharedTunInboundPeerRelaySnapshot {
        var relayToPeer: Bool
        var deliverLocal: Bool
        var routeClass: String?
        var selectedPeerIDs: [Int]
        var selectedChanIDs: [Int]
        var ipVersion: Int?
        var destinationIP: String?
        var dropReason: String?
    }

    struct ScopedTunThrottleSnapshot {
        var scopeID: String
        var allowed: Bool
        var prevWindowBytes: Int
        var currWindowBytes: Int
        var throttleDropCount: Int
    }

    struct OverlayBackpressureSnapshot {
        var waitingCount: Int
        var inflight: Int
        var maxInflight: Int
        var transmitDelayEstMS: Double
        var transportPrevWindowBytes: Int
        var stalled: Bool
    }

    struct InboundTunFragmentSnapshot {
        var delivered: Bool
        var packet: Data?
        var datagramID: Int
        var totalLen: Int
        var receivedBytes: Int
    }

    struct CloseSnapshot {
        var closed: Bool
        var chanID: Int
        var preferredChanID: Int?
        var boundChanIDs: [Int]
    }

    private struct SharedTunScopeMetadata {
        var routeClass: String
        var selectedPeerIDs: [Int]
        var selectedChanIDs: [Int]
    }

    private let instanceID: UInt64
    private var connectionSeq: UInt32
    private let chanIDStride: Int
    private let sessionMaxAppPayload: Int
    private let localSpec: ObstacleBridgeChannelMuxCodec.ServiceSpec?
    private let localTunnelAddress: String?
    private let localTunnelAddress6: String?
    private let sharedTunDisableOutgoingNormalization: Bool
    private let sharedTunDisableInflowFilter: Bool
    private let sharedTunDisableOutflowFilter: Bool
    private let sharedTunDisableScopedThrottle: Bool
    private let sharedTunOwnership: [String: Any]?
    private var nextFragmentDatagramID: UInt32
    /// Portable owner for TUN OPEN/DATA/CLOSE counters and control chunks.
    /// Native code retains packet-device delivery and shared-peer routing only.
    private var session: ObstacleBridgeChannelMuxSession
    private let channelState: ObstacleBridgeTunChannelState
    private let packetReassembler: ObstacleBridgePacketReassembler
    private var tunInflowScopeStates: [String: ObstacleBridgeTunThrottleState]
    private var sharedTunScopeMetadata: [String: SharedTunScopeMetadata]
    private var sharedTunRuntimeByPeer: [Int: SharedTunPeerBindingState]
    private var sharedTunPeerRefByPeer: [Int: String]
    private var sharedTunPeerIDByRef: [String: Int]
    private let sharedTunDropLedger: ObstacleBridgeTunDropLedger
    /// Compatibility path for direct component fixtures that intentionally
    /// omit wire counters. Production overlay calls supply counters to Core.
    private var controlChunkReassembler: ObstacleBridgeChannelMuxCodec.ControlChunkReassembler

    init(
        instanceID: UInt64,
        connectionSeq: UInt32,
        chanIDStart: Int = 1,
        chanIDStride: Int = 1,
        nextTunID: Int = 1,
        localSpec: ObstacleBridgeChannelMuxCodec.ServiceSpec? = nil,
        localTunnelAddress: String? = nil,
        localTunnelAddress6: String? = nil,
        sharedTunDisableOutgoingNormalization: Bool = false,
        sharedTunDisableInflowFilter: Bool = false,
        sharedTunDisableOutflowFilter: Bool = false,
        sharedTunDisableScopedThrottle: Bool = false,
        sessionMaxAppPayload: Int = 65535
    ) {
        self.instanceID = instanceID
        self.connectionSeq = connectionSeq
        self.chanIDStride = max(1, chanIDStride)
        self.sessionMaxAppPayload = sessionMaxAppPayload
        self.localSpec = localSpec
        self.localTunnelAddress = Self.normalizedIPAddress(localTunnelAddress, family: AF_INET)
        self.localTunnelAddress6 = Self.normalizedIPAddress(localTunnelAddress6, family: AF_INET6)
        self.sharedTunDisableOutgoingNormalization = sharedTunDisableOutgoingNormalization
        self.sharedTunDisableInflowFilter = sharedTunDisableInflowFilter
        self.sharedTunDisableOutflowFilter = sharedTunDisableOutflowFilter
        self.sharedTunDisableScopedThrottle = sharedTunDisableScopedThrottle
        if let localSpec,
           let ownershipValue = ObstacleBridgeChannelMuxCodec.sharedTunOwnershipSnapshot(for: localSpec),
           let ownership = ObstacleBridgeChannelMuxCodec.foundationObject(from: ownershipValue) as? [String: Any] {
            self.sharedTunOwnership = ownership
        } else {
            self.sharedTunOwnership = nil
        }
        self.nextFragmentDatagramID = 1
        self.session = Self.makeSession(
            instanceID: instanceID,
            connectionSeq: connectionSeq,
            nextTunID: nextTunID,
            chanIDStride: max(1, chanIDStride),
            sessionMaxAppPayload: sessionMaxAppPayload
        )
        self.channelState = ObstacleBridgeTunChannelState()
        self.packetReassembler = ObstacleBridgePacketReassembler()
        self.tunInflowScopeStates = [:]
        self.sharedTunScopeMetadata = [:]
        self.sharedTunRuntimeByPeer = [:]
        self.sharedTunPeerRefByPeer = [:]
        self.sharedTunPeerIDByRef = [:]
        self.sharedTunDropLedger = ObstacleBridgeTunDropLedger()
        self.controlChunkReassembler = ObstacleBridgeChannelMuxCodec.ControlChunkReassembler()
    }

    func sharedTunRuntimeSnapshot() -> [String: Any]? {
        guard var snapshot = sharedTunOwnership else {
            return nil
        }
        let throttleScopes = sharedTunThrottleScopeSnapshots()
        var throttleByPeer: [Int: [String: Any]] = [:]
        for scope in throttleScopes {
            let selectedPeerIDs = scope["selected_peer_ids"] as? [Int] ?? []
            if selectedPeerIDs.count == 1 {
                throttleByPeer[selectedPeerIDs[0]] = scope
            }
        }
        let peerDetailsByRef: [String: [String: Any]] = Dictionary(
            uniqueKeysWithValues: ((snapshot["peers"] as? [[String: Any]]) ?? []).compactMap { entry in
                guard let peerRef = entry["peer_ref"] as? String, peerRef.isEmpty == false else {
                    return nil
                }
                return (peerRef, entry)
            }
        )
        var activeBindings: [[String: Any]] = sharedTunRuntimeByPeer.values
            .sorted { $0.peerID < $1.peerID }
            .map { state in
                let peerRef = sharedTunPeerRefByPeer[state.peerID]
                    ?? sharedTunPeerIDByRef.first(where: { $0.value == state.peerID })?.key
                    ?? ""
                let peerDetails = peerDetailsByRef[peerRef]
                    ?? (peerDetailsByRef.count == 1 ? peerDetailsByRef.values.first : nil)
                    ?? [:]
                var entry: [String: Any] = [
                    "peer_id": state.peerID,
                    "peer_ref": peerRef.isEmpty ? ((peerDetails["peer_ref"] as? String) ?? "") : peerRef,
                    "preferred_chan_id": state.preferredChanID as Any,
                    "bound_chan_ids": state.boundChanIDs.sorted(),
                    "ipv4": peerDetails["ipv4"] as? [String] ?? [],
                    "ipv6": peerDetails["ipv6"] as? [String] ?? [],
                    "address_count": peerDetails["address_count"] as? Int ?? 0,
                    "rx_packets": state.rxPackets,
                    "rx_bytes": state.rxBytes,
                    "tx_packets": state.txPackets,
                    "tx_bytes": state.txBytes,
                    "learned_ipv4": state.learnedIPv4,
                    "learned_ipv6": state.learnedIPv6,
                    "throttle_prev_window_bytes": 0,
                    "throttle_curr_window_bytes": 0,
                    "throttle_drop_count": 0,
                ]
                if let scope = throttleByPeer[state.peerID] {
                    entry["throttle_prev_window_bytes"] = scope["prev_window_bytes"] as? Int ?? 0
                    entry["throttle_curr_window_bytes"] = scope["curr_window_bytes"] as? Int ?? 0
                    entry["throttle_drop_count"] = scope["throttle_drop_count"] as? Int ?? 0
                }
                return entry
            }
        activeBindings.sort { ($0["peer_id"] as? Int ?? 0) < ($1["peer_id"] as? Int ?? 0) }
        snapshot["active_peer_bindings"] = activeBindings
        snapshot["throttle_scopes"] = throttleScopes
        let drops = sharedTunDropLedger.snapshot()
        snapshot["drop_counters"] = [
            "total": drops.total,
            "by_reason": drops.byReason,
        ]
        snapshot["recent_drops"] = drops.recent.map { event in
            var entry: [String: Any] = ["reason": event.reason, "direction": event.direction]
            if let peerID = event.peerID { entry["peer_id"] = peerID }
            if let channelID = event.channelID { entry["chan_id"] = channelID }
            if let ipVersion = event.ipVersion { entry["ip_version"] = ipVersion }
            if let sourceAddress = event.sourceAddress { entry["source_ip"] = sourceAddress }
            if let destinationAddress = event.destinationAddress { entry["destination_ip"] = destinationAddress }
            if let routeClass = event.routeClass { entry["route_class"] = routeClass }
            if let packetBytes = event.packetBytes { entry["packet_bytes"] = packetBytes }
            return entry
        }
        return snapshot
    }

    private func throttleBudgetBytes(previousBytes: Int) -> Int {
        ObstacleBridgeTunThrottlePolicy.budget(
            previousBytes: previousBytes,
            ratio: Self.tunInflowThrottleRatio
        )
    }

    private func throttleSummary(
        scopeID: String,
        snapshot: OverlayBackpressureSnapshot,
        states: [(String, ObstacleBridgeTunThrottleState)]
    ) -> [String: Any] {
        let backpressureActive = overlayBackpressureActive(snapshot)
        let details: [[String: Any]] = states.map { currentScopeID, state in
            let budgetBytes = max(0, localIngressScopeAllowanceBytes(snapshot: snapshot, state: state, scopeID: currentScopeID))
            let usedBytes = max(0, state.currentBytes)
            let remainingBytes = max(0, budgetBytes - usedBytes)
            return [
                "scope_id": currentScopeID,
                "budget_bytes": budgetBytes,
                "used_bytes": usedBytes,
                "remaining_bytes": remainingBytes,
                "prev_window_bytes": state.previousBytes,
                "throttle_drop_count": state.throttleDropCount,
            ]
        }
        let aggregate = details.first ?? [
            "scope_id": aggregateLocalIngressScopeID(),
            "budget_bytes": 0,
            "used_bytes": 0,
            "remaining_bytes": 0,
            "prev_window_bytes": 0,
            "throttle_drop_count": 0,
        ]
        let scoped = details.count > 1 ? details[1] : nil
        let remainingCandidates = details.compactMap { $0["remaining_bytes"] as? Int }
        return [
            "applicable": true,
            "scope_id": scopeID,
            "mode": scoped == nil ? "aggregate_only" : "aggregate_and_scope",
            "active": backpressureActive,
            "stalled": backpressureActive ? snapshot.stalled : false,
            "backpressure_active": backpressureActive,
            "disabled": sharedTunDisableScopedThrottle,
            "transport_prev_window_bytes": snapshot.transportPrevWindowBytes,
            "waiting_count": snapshot.waitingCount,
            "inflight": snapshot.inflight,
            "max_inflight": snapshot.maxInflight,
            "transmit_delay_est_ms": snapshot.transmitDelayEstMS,
            "budget_bytes": remainingCandidates.isEmpty ? 0 : (remainingCandidates.min() ?? 0) + Int(aggregate["used_bytes"] as? Int ?? 0),
            "used_bytes": max(Int(aggregate["used_bytes"] as? Int ?? 0), Int(scoped?["used_bytes"] as? Int ?? 0)),
            "remaining_bytes": remainingCandidates.min() ?? 0,
            "aggregate": aggregate,
            "scope": scoped ?? NSNull(),
        ]
    }

    func directTunThrottleSnapshot(snapshot: OverlayBackpressureSnapshot, nowNS: UInt64) -> [String: Any] {
        let scopeID = directTunScopeID()
        let states = localIngressScopeIDs(scopeID).map { currentScopeID in
            (currentScopeID, advanceTunInflowWindow(scopeID: currentScopeID, nowNS: nowNS))
        }
        return throttleSummary(scopeID: scopeID, snapshot: snapshot, states: states)
    }

    func directTunThrottleSnapshot(bufferedFrames: Int, nowNS: UInt64) -> [String: Any] {
        directTunThrottleSnapshot(
            snapshot: OverlayBackpressureSnapshot(
                waitingCount: max(0, bufferedFrames),
                inflight: max(0, bufferedFrames),
                maxInflight: 0,
                transmitDelayEstMS: 0.0,
                transportPrevWindowBytes: 0,
                stalled: false
            ),
            nowNS: nowNS
        )
    }

    func sharedTunThrottleSnapshot(snapshot: OverlayBackpressureSnapshot, nowNS: UInt64) -> [String: Any] {
        var worstScope: [String: Any]? = nil
        for (scopeID, metadata) in sharedTunScopeMetadata {
            let state = advanceTunInflowWindow(scopeID: scopeID, nowNS: nowNS)
            let budgetBytes = max(0, throttleBudgetBytes(previousBytes: state.previousBytes))
            let usedBytes = max(0, state.currentBytes)
            let remainingBytes = max(0, budgetBytes - usedBytes)
            let scoped: [String: Any] = [
                "scope_id": scopeID,
                "route_class": metadata.routeClass,
                "selected_peer_ids": metadata.selectedPeerIDs,
                "selected_chan_ids": metadata.selectedChanIDs,
                "budget_bytes": budgetBytes,
                "used_bytes": usedBytes,
                "remaining_bytes": remainingBytes,
                "prev_window_bytes": state.previousBytes,
                "throttle_drop_count": state.throttleDropCount,
            ]
            if worstScope == nil || Int(scoped["remaining_bytes"] as? Int ?? 0) < Int(worstScope?["remaining_bytes"] as? Int ?? 0) {
                worstScope = scoped
            }
        }
        guard let worstScope else {
            return directTunThrottleSnapshot(snapshot: snapshot, nowNS: nowNS)
        }
        let scopeID = String(describing: worstScope["scope_id"] ?? "")
        let states = localIngressScopeIDs(scopeID).map { currentScopeID in
            (currentScopeID, advanceTunInflowWindow(scopeID: currentScopeID, nowNS: nowNS))
        }
        return throttleSummary(scopeID: scopeID, snapshot: snapshot, states: states)
    }

    func sharedTunThrottleSnapshot(bufferedFrames: Int, nowNS: UInt64) -> [String: Any] {
        sharedTunThrottleSnapshot(
            snapshot: OverlayBackpressureSnapshot(
                waitingCount: max(0, bufferedFrames),
                inflight: max(0, bufferedFrames),
                maxInflight: 0,
                transmitDelayEstMS: 0.0,
                transportPrevWindowBytes: 0,
                stalled: false
            ),
            nowNS: nowNS
        )
    }

    /// Drop channel state that belongs to the previous overlay transport epoch.
    ///
    /// A peer restart loses its ChannelMux channel table even when the local
    /// tunnel interface remains open. Retaining its preferred channel would
    /// make the next local packet send DATA on that stale channel without a
    /// replacement OPEN.
    func resetTransportEpoch() {
        connectionSeq &+= 1
        session = Self.makeSession(
            instanceID: instanceID,
            connectionSeq: connectionSeq,
            nextTunID: Int(session.nextAvailableChannelID),
            chanIDStride: chanIDStride,
            sessionMaxAppPayload: sessionMaxAppPayload
        )
        channelState.reset()
        packetReassembler.reset()
        controlChunkReassembler = ObstacleBridgeChannelMuxCodec.ControlChunkReassembler()
        sharedTunRuntimeByPeer.removeAll(keepingCapacity: true)
        sharedTunPeerRefByPeer.removeAll(keepingCapacity: true)
        sharedTunPeerIDByRef.removeAll(keepingCapacity: true)
        sharedTunScopeMetadata.removeAll(keepingCapacity: true)
        tunInflowScopeStates.removeAll(keepingCapacity: true)
    }

    func currentConnectionSeq() -> UInt32 {
        connectionSeq
    }

    /// Allocate and announce the configured local TUN endpoint for this epoch.
    ///
    /// A TUN interface is long-lived, unlike a TCP connection accepted on demand.
    /// Publishing its OPEN after authenticated readiness prevents the peer from
    /// receiving the first TUN DATA before it has bound the channel.
    func openLocalTunChannelIfNeeded(
        spec: ObstacleBridgeChannelMuxCodec.ServiceSpec
    ) throws -> LocalTunOpenSnapshot? {
        guard channelState.preferredChannel == nil else {
            return nil
        }
        guard let coreSpec = Self.coreServiceSpec(spec),
              let effects = try? session.acceptLocal(service: coreSpec),
              let chanID = Self.channelID(from: effects),
              let frames = try? wireFrames(from: effects) else {
            return nil
        }
        channelState.bind(chanID)
        return LocalTunOpenSnapshot(
            chanID: chanID,
            frames: frames,
            nextTunID: Int(session.nextAvailableChannelID),
            nextCounter: Int(session.nextOutboundCounter(channelID: UInt16(clamping: chanID)) ?? 0)
        )
    }

    func handleLocalTunPacket(
        packet: Data,
        mtu: Int,
        existingChanID: Int? = nil,
        spec: ObstacleBridgeChannelMuxCodec.ServiceSpec,
        overlayConnected: Bool,
        acceptingEnabled: Bool,
        backpressure: OverlayBackpressureSnapshot,
        nowNS: UInt64? = nil,
        recordInflow: Bool = true,
        scopeID: String? = nil
    ) throws -> LocalTunSendSnapshot? {
        guard overlayConnected, acceptingEnabled else {
            return nil
        }
        guard packet.count <= mtu else {
            return nil
        }
        let sendNowNS = nowNS ?? DispatchTime.now().uptimeNanoseconds
        let appliedScopeID = scopeID ?? "direct:\(spec.svcID)"

        let normalizedPacket = normalizedLocalPacketForTunnel(packet: packet)

        var frames: [Data] = []
        let preferredChanID = existingChanID ?? channelState.preferredChannel
        let allocatedChannel = preferredChanID == nil
        let chanID: Int
        if allocatedChannel {
            guard let coreSpec = Self.coreServiceSpec(spec),
                  let effects = try? session.acceptLocal(service: coreSpec),
                  let allocatedID = Self.channelID(from: effects),
                  let openFrames = try? wireFrames(from: effects) else {
                return nil
            }
            chanID = allocatedID
            frames.append(contentsOf: openFrames)
        } else {
            chanID = preferredChanID!
        }
        channelState.bind(chanID)

        guard let dataFrames = try buildDataFrames(chanID: chanID, packet: normalizedPacket) else {
            return nil
        }
        frames.append(contentsOf: dataFrames)
        if recordInflow {
            recordLocalTunForward(packetBytes: normalizedPacket.count, nowNS: sendNowNS, scopeID: appliedScopeID)
        }
        return LocalTunSendSnapshot(
            chanID: chanID,
            allocatedChannel: allocatedChannel,
            frames: frames,
            nextTunID: Int(session.nextAvailableChannelID),
            nextCounter: Int(session.nextOutboundCounter(channelID: UInt16(clamping: chanID)) ?? 0)
        )
    }

    func handleLocalTunPacket(
        packet: Data,
        mtu: Int,
        existingChanID: Int? = nil,
        spec: ObstacleBridgeChannelMuxCodec.ServiceSpec,
        overlayConnected: Bool,
        acceptingEnabled: Bool,
        bufferedFrames: Int = 0,
        nowNS: UInt64? = nil,
        recordInflow: Bool = true,
        scopeID: String? = nil
    ) throws -> LocalTunSendSnapshot? {
        try handleLocalTunPacket(
            packet: packet,
            mtu: mtu,
            existingChanID: existingChanID,
            spec: spec,
            overlayConnected: overlayConnected,
            acceptingEnabled: acceptingEnabled,
            backpressure: OverlayBackpressureSnapshot(
                waitingCount: max(0, bufferedFrames),
                inflight: max(0, bufferedFrames),
                maxInflight: 0,
                transmitDelayEstMS: 0.0,
                transportPrevWindowBytes: 0,
                stalled: false
            ),
            nowNS: nowNS,
            recordInflow: recordInflow,
            scopeID: scopeID
        )
    }

    func normalizedLocalPacketForTunnel(packet: Data) -> Data {
        if sharedTunDisableOutgoingNormalization {
            return packet
        }
        return Self.normalizeLocalPacketSource(
            packet,
            ipv4Source: localTunnelAddress,
            ipv6Source: localTunnelAddress6
        ) ?? packet
    }

    func packetDebugFields(packet: Data) -> [String: Any] {
        if let parsed = Self.parsePacketEndpoints(packet) {
            return [
                "ip_version": parsed.ipVersion,
                "source_ip": parsed.sourceIP,
                "destination_ip": parsed.destinationIP,
                "packet_bytes": packet.count,
            ]
        }
        return [
            "packet_bytes": packet.count,
            "parse_error": Self.parsePacketDropReason(packet),
        ]
    }

    private func advanceTunInflowWindow(scopeID: String, nowNS: UInt64) -> ObstacleBridgeTunThrottleState {
        var state = tunInflowScopeStates[scopeID] ?? ObstacleBridgeTunThrottleState()
        state.advance(nowNS: nowNS, windowNS: Self.tunInflowThrottleWindowNS)
        tunInflowScopeStates[scopeID] = state
        return state
    }

    private func localTunSendAllowed(
        packetBytes: Int,
        snapshot: OverlayBackpressureSnapshot,
        nowNS: UInt64,
        scopeID: String
    ) -> Bool {
        let backpressureActive = overlayBackpressureActive(snapshot)
        guard backpressureActive else {
            return true
        }
        if snapshot.stalled {
            return false
        }
        if sharedTunDisableScopedThrottle {
            return true
        }
        let aggregateScopeID = aggregateLocalIngressScopeID()
        let scopes = localIngressScopeIDs(scopeID).map { currentScopeID in
            (
                isAggregate: currentScopeID == aggregateScopeID,
                state: advanceTunInflowWindow(scopeID: currentScopeID, nowNS: nowNS)
            )
        }
        return ObstacleBridgeTunThrottlePolicy.admits(
            packetBytes: packetBytes,
            transportPreviousBytes: snapshot.transportPrevWindowBytes,
            scopes: scopes
        )
    }

    private func recordLocalTunForward(packetBytes: Int, nowNS: UInt64, scopeID: String) {
        var state = advanceTunInflowWindow(scopeID: scopeID, nowNS: nowNS)
        state.recordForwarded(bytes: packetBytes)
        tunInflowScopeStates[scopeID] = state
    }

    private func sharedTunThrottleScopeSnapshots() -> [[String: Any]] {
        var snapshots: [[String: Any]] = []
        for (scopeID, metadata) in sharedTunScopeMetadata {
            guard let state = tunInflowScopeStates[scopeID] else {
                continue
            }
            snapshots.append([
                "scope_id": scopeID,
                "route_class": metadata.routeClass,
                "selected_peer_ids": metadata.selectedPeerIDs,
                "selected_chan_ids": metadata.selectedChanIDs,
                "prev_window_bytes": state.previousBytes,
                "curr_window_bytes": state.currentBytes,
                "throttle_drop_count": state.throttleDropCount,
            ])
        }
        snapshots.sort { String(describing: $0["scope_id"] ?? "") < String(describing: $1["scope_id"] ?? "") }
        return snapshots
    }

    private func directTunScopeID() -> String {
        "direct:\(localSpec?.svcID ?? 0)"
    }

    private func aggregateLocalIngressScopeID() -> String {
        "aggregate:local_ingress"
    }

    private func localIngressScopeIDs(_ scopeID: String) -> [String] {
        let aggregate = aggregateLocalIngressScopeID()
        return scopeID == aggregate ? [aggregate] : [aggregate, scopeID]
    }

    private func overlayBackpressureActive(_ snapshot: OverlayBackpressureSnapshot) -> Bool {
        snapshot.maxInflight > 0 && snapshot.inflight >= snapshot.maxInflight
    }

    private func localIngressScopeAllowanceBytes(
        snapshot: OverlayBackpressureSnapshot,
        state: ObstacleBridgeTunThrottleState,
        scopeID: String
    ) -> Int {
        let previousBytes = scopeID == aggregateLocalIngressScopeID() && snapshot.transportPrevWindowBytes > 0
            ? snapshot.transportPrevWindowBytes
            : state.previousBytes
        return ObstacleBridgeTunThrottlePolicy.budget(
            previousBytes: previousBytes,
            ratio: Self.tunInflowThrottleRatio
        )
    }

    private func sharedTunInflowScopeID(route: SharedTunOutboundRouteSnapshot) -> String? {
        guard route.routed else {
            return nil
        }
        let routeClass = route.routeClass ?? ""
        let peerIDs = route.selectedPeerIDs.map(String.init).joined(separator: ",")
        let chanIDs = route.selectedChanIDs.map(String.init).joined(separator: ",")
        let scopeID = "shared:\(localSpec?.svcID ?? 0):\(routeClass):peers=\(peerIDs):chans=\(chanIDs)"
        sharedTunScopeMetadata[scopeID] = SharedTunScopeMetadata(
            routeClass: routeClass,
            selectedPeerIDs: route.selectedPeerIDs,
            selectedChanIDs: route.selectedChanIDs
        )
        return scopeID
    }

    func scopedTunThrottle(
        packetBytes: Int,
        bufferedFrames: Int,
        nowNS: UInt64,
        route: SharedTunOutboundRouteSnapshot?
    ) -> ScopedTunThrottleSnapshot {
        let scopeID = sharedTunInflowScopeID(route: route ?? SharedTunOutboundRouteSnapshot(
            routed: false,
            routeClass: nil,
            selectedPeerIDs: [],
            selectedChanIDs: [],
            ipVersion: nil,
            destinationIP: nil,
            dropReason: nil
        )) ?? directTunScopeID()
        return handleScopedTunThrottle(
            packetBytes: packetBytes,
            bufferedFrames: bufferedFrames,
            nowNS: nowNS,
            scopeID: scopeID
        )
    }

    func scopedTunThrottle(
        packetBytes: Int,
        snapshot: OverlayBackpressureSnapshot,
        nowNS: UInt64,
        route: SharedTunOutboundRouteSnapshot?
    ) -> ScopedTunThrottleSnapshot {
        let scopeID = sharedTunInflowScopeID(route: route ?? SharedTunOutboundRouteSnapshot(
            routed: false,
            routeClass: nil,
            selectedPeerIDs: [],
            selectedChanIDs: [],
            ipVersion: nil,
            destinationIP: nil,
            dropReason: nil
        )) ?? directTunScopeID()
        let allowed = localTunSendAllowed(
            packetBytes: packetBytes,
            snapshot: snapshot,
            nowNS: nowNS,
            scopeID: scopeID
        )
        var state = advanceTunInflowWindow(scopeID: scopeID, nowNS: nowNS)
        if !allowed {
            state.recordDrop()
            tunInflowScopeStates[scopeID] = state
        }
        let states = localIngressScopeIDs(scopeID).map { currentScopeID in
            (currentScopeID, advanceTunInflowWindow(scopeID: currentScopeID, nowNS: nowNS))
        }
        let summaryState = states.last?.1 ?? state
        return ScopedTunThrottleSnapshot(
            scopeID: scopeID,
            allowed: allowed,
            prevWindowBytes: summaryState.previousBytes,
            currWindowBytes: summaryState.currentBytes,
            throttleDropCount: summaryState.throttleDropCount
        )
    }

    func scopeID(for route: SharedTunOutboundRouteSnapshot?) -> String {
        sharedTunInflowScopeID(route: route ?? SharedTunOutboundRouteSnapshot(
            routed: false,
            routeClass: nil,
            selectedPeerIDs: [],
            selectedChanIDs: [],
            ipVersion: nil,
            destinationIP: nil,
            dropReason: nil
        )) ?? directTunScopeID()
    }

    func recordLocalTunForward(packetBytes: Int, nowNS: UInt64, route: SharedTunOutboundRouteSnapshot?) {
        let scopeID = sharedTunInflowScopeID(route: route ?? SharedTunOutboundRouteSnapshot(
            routed: false,
            routeClass: nil,
            selectedPeerIDs: [],
            selectedChanIDs: [],
            ipVersion: nil,
            destinationIP: nil,
            dropReason: nil
        )) ?? directTunScopeID()
        recordLocalTunForward(packetBytes: packetBytes, nowNS: nowNS, scopeID: scopeID)
    }

    func handleScopedTunThrottle(packetBytes: Int, bufferedFrames: Int, nowNS: UInt64, scopeID: String) -> ScopedTunThrottleSnapshot {
        let snapshot = OverlayBackpressureSnapshot(
            waitingCount: max(0, bufferedFrames),
            inflight: max(0, bufferedFrames),
            maxInflight: 0,
            transmitDelayEstMS: 0.0,
            transportPrevWindowBytes: 0,
            stalled: false
        )
        let allowed = localTunSendAllowed(
            packetBytes: packetBytes,
            snapshot: snapshot,
            nowNS: nowNS,
            scopeID: scopeID
        )
        var state = advanceTunInflowWindow(scopeID: scopeID, nowNS: nowNS)
        if allowed {
            state.recordForwarded(bytes: packetBytes)
        } else {
            state.recordDrop()
        }
        tunInflowScopeStates[scopeID] = state
        return ScopedTunThrottleSnapshot(
            scopeID: scopeID,
            allowed: allowed,
            prevWindowBytes: state.previousBytes,
            currWindowBytes: state.currentBytes,
            throttleDropCount: state.throttleDropCount
        )
    }

    func handleInboundTunOpen(chanID: Int, payload: Data, counter: Int? = nil) -> InboundTunOpenSnapshot {
        let admittedCounter = counter ?? 0
        if (try? session.receive(.init(
                channelID: UInt16(clamping: chanID),
                protocolType: ObstacleBridgeChannelMuxSessionProtocol.tun.rawValue,
                counter: UInt16(clamping: admittedCounter),
                messageType: ObstacleBridgeChannelMuxSessionMessageType.open.rawValue,
                body: payload
           ))) == nil {
            return .init(accepted: false, chanID: chanID, preferredChanID: channelState.preferredChannel, remoteSpec: nil)
        }
        guard
            let parsed = ObstacleBridgeChannelMuxCodec.parseOpenPayload(payload),
            parsed.spec.lProto == "tun",
            parsed.spec.rProto == "tun"
        else {
            return InboundTunOpenSnapshot(
                accepted: false,
                chanID: chanID,
                preferredChanID: channelState.preferredChannel,
                remoteSpec: nil
            )
        }
        if let localSpec,
           (parsed.spec.rHost != localSpec.lBind || parsed.spec.rPort != localSpec.lPort) {
            return InboundTunOpenSnapshot(
                accepted: false,
                chanID: chanID,
                preferredChanID: channelState.preferredChannel,
                remoteSpec: parsed.spec
            )
        }
        channelState.bind(chanID)
        return InboundTunOpenSnapshot(
            accepted: true,
            chanID: chanID,
            preferredChanID: channelState.preferredChannel,
            remoteSpec: parsed.spec
        )
    }

    func recordSharedTunPeerBinding(peerID: Int?, chanID: Int) {
        guard sharedTunOwnership != nil, let peerID else {
            return
        }
        let uniqueBound = Array(Set((sharedTunRuntimeByPeer[peerID]?.boundChanIDs ?? []) + [chanID])).sorted()
        let preferredChanID = uniqueBound.contains(sharedTunRuntimeByPeer[peerID]?.preferredChanID ?? -1)
            ? sharedTunRuntimeByPeer[peerID]?.preferredChanID
            : uniqueBound.first
        sharedTunRuntimeByPeer[peerID] = SharedTunPeerBindingState(
            peerID: peerID,
            preferredChanID: preferredChanID,
            boundChanIDs: uniqueBound,
            rxPackets: sharedTunRuntimeByPeer[peerID]?.rxPackets ?? 0,
            rxBytes: sharedTunRuntimeByPeer[peerID]?.rxBytes ?? 0,
            txPackets: sharedTunRuntimeByPeer[peerID]?.txPackets ?? 0,
            txBytes: sharedTunRuntimeByPeer[peerID]?.txBytes ?? 0,
            learnedIPv4: sharedTunRuntimeByPeer[peerID]?.learnedIPv4 ?? [],
            learnedIPv6: sharedTunRuntimeByPeer[peerID]?.learnedIPv6 ?? []
        )
    }

    func recordSharedTunPeerTraffic(peerID: Int?, chanID: Int, packet: Data, direction: String) {
        guard sharedTunOwnership != nil, let peerID, direction == "rx" || direction == "tx" else {
            return
        }
        recordSharedTunPeerBinding(peerID: peerID, chanID: chanID)
        guard var state = sharedTunRuntimeByPeer[peerID] else {
            return
        }
        if direction == "rx" {
            state.rxPackets += 1
            state.rxBytes += packet.count
            if let endpoints = Self.parsePacketEndpoints(packet) {
                if endpoints.ipVersion == 4, !state.learnedIPv4.contains(endpoints.sourceIP) {
                    state.learnedIPv4 = Array((state.learnedIPv4 + [endpoints.sourceIP]).suffix(8))
                } else if endpoints.ipVersion == 6, !state.learnedIPv6.contains(endpoints.sourceIP) {
                    state.learnedIPv6 = Array((state.learnedIPv6 + [endpoints.sourceIP]).suffix(8))
                }
            }
        } else {
            state.txPackets += 1
            state.txBytes += packet.count
        }
        sharedTunRuntimeByPeer[peerID] = state
    }

    func dropSharedTunPeerBinding(peerID: Int?, chanID: Int) {
        guard sharedTunOwnership != nil, let peerID, var state = sharedTunRuntimeByPeer[peerID] else {
            return
        }
        let remaining = state.boundChanIDs.filter { $0 != chanID }
        if remaining.isEmpty {
            sharedTunRuntimeByPeer.removeValue(forKey: peerID)
            return
        }
        state.boundChanIDs = remaining
        if !remaining.contains(state.preferredChanID ?? -1) {
            state.preferredChanID = remaining.first
        }
        sharedTunRuntimeByPeer[peerID] = state
    }

    func cleanupSharedTunPeerStateOnDisconnect(peerID: Int?) {
        guard sharedTunOwnership != nil, let peerID else {
            return
        }
        sharedTunRuntimeByPeer.removeValue(forKey: peerID)
        if let peerRef = sharedTunPeerRefByPeer.removeValue(forKey: peerID),
           sharedTunPeerIDByRef[peerRef] == peerID {
            sharedTunPeerIDByRef.removeValue(forKey: peerRef)
        }
        sharedTunScopeMetadata = sharedTunScopeMetadata.filter { !$0.value.selectedPeerIDs.contains(peerID) }
        tunInflowScopeStates = tunInflowScopeStates.filter { !($0.key.contains("peers=\(peerID)")) }
    }

    func handleInboundTunOpenChunk(
        chanID: Int,
        payload: Data,
        counter: Int? = nil,
        peerID: Int? = nil
    ) -> InboundTunOpenChunkSnapshot {
        if let counter {
            guard let effects = try? session.receive(.init(
                channelID: UInt16(clamping: chanID),
                protocolType: ObstacleBridgeChannelMuxSessionProtocol.tun.rawValue,
                counter: UInt16(clamping: counter),
                messageType: ObstacleBridgeChannelMuxSessionMessageType.openChunk.rawValue,
                body: payload
            )) else {
                return .init(assembled: false, accepted: false, chanID: chanID, preferredChanID: channelState.preferredChannel, remoteSpec: nil)
            }
            guard case .connectLocal(_, let service) = effects.first,
                  let assembled = ObstacleBridgeChannelMuxCodec.serviceSpec(service),
                  assembled.lProto == "tun", assembled.rProto == "tun" else {
                return .init(assembled: false, accepted: false, chanID: chanID, preferredChanID: channelState.preferredChannel, remoteSpec: nil)
            }
            guard localSpec == nil || (assembled.rHost == localSpec!.lBind && assembled.rPort == localSpec!.lPort) else {
                return .init(assembled: true, accepted: false, chanID: chanID, preferredChanID: channelState.preferredChannel, remoteSpec: assembled)
            }
            channelState.bind(chanID)
            return .init(assembled: true, accepted: true, chanID: chanID, preferredChanID: channelState.preferredChannel, remoteSpec: assembled)
        }
        guard let assembled = controlChunkReassembler.consume(
            chanID: chanID,
            proto: .tun,
            mtype: .openChunk,
            payload: payload,
            peerID: peerID
        ) else {
            return InboundTunOpenChunkSnapshot(
                assembled: false,
                accepted: false,
                chanID: chanID,
                preferredChanID: channelState.preferredChannel,
                remoteSpec: nil
            )
        }
        let openSnapshot = handleInboundTunOpen(chanID: chanID, payload: assembled)
        return InboundTunOpenChunkSnapshot(
            assembled: true,
            accepted: openSnapshot.accepted,
            chanID: openSnapshot.chanID,
            preferredChanID: openSnapshot.preferredChanID,
            remoteSpec: openSnapshot.remoteSpec
        )
    }

    func handleInboundTunData(
        chanID: Int,
        body: Data,
        mtu: Int,
        boundChanID: Int? = nil,
        counter: Int? = nil
    ) -> InboundTunDataSnapshot {
        if let counter,
           (try? session.receive(.init(
                channelID: UInt16(clamping: chanID), protocolType: ObstacleBridgeChannelMuxSessionProtocol.tun.rawValue,
                counter: UInt16(clamping: counter), messageType: ObstacleBridgeChannelMuxSessionMessageType.data.rawValue, body: body
           ))) == nil {
            return .init(delivered: false, packet: nil)
        }
        let isBound: Bool
        if let boundChanID {
            isBound = boundChanID == chanID
        } else {
            isBound = channelState.isBound(chanID)
        }
        guard isBound, body.count <= mtu else {
            return InboundTunDataSnapshot(delivered: false, packet: nil)
        }
        return InboundTunDataSnapshot(delivered: true, packet: body)
    }

    func handleInboundTunDataGuarded(
        chanID: Int,
        body: Data,
        mtu: Int,
        boundChanID: Int? = nil,
        allowedSourceIPs: Set<String>? = nil,
        counter: Int? = nil
    ) -> GuardedInboundTunDataSnapshot {
        let base = handleInboundTunData(chanID: chanID, body: body, mtu: mtu, boundChanID: boundChanID, counter: counter)
        guard base.delivered else {
            return GuardedInboundTunDataSnapshot(
                delivered: false,
                packet: nil,
                ipVersion: nil,
                sourceIP: nil,
                destinationIP: nil,
                dropReason: nil
            )
        }
        guard let parsed = Self.parsePacketEndpoints(body) else {
            return GuardedInboundTunDataSnapshot(
                delivered: false,
                packet: nil,
                ipVersion: nil,
                sourceIP: nil,
                destinationIP: nil,
                dropReason: Self.parsePacketDropReason(body)
            )
        }
        if !ObstacleBridgeTunInboundAdmissionPolicy.admits(
            sourceAddress: parsed.sourceIP,
            allowedSourceAddresses: allowedSourceIPs
        ) {
            return GuardedInboundTunDataSnapshot(
                delivered: false,
                packet: nil,
                ipVersion: parsed.ipVersion,
                sourceIP: parsed.sourceIP,
                destinationIP: parsed.destinationIP,
                dropReason: "source_not_owned_by_peer"
            )
        }
        return GuardedInboundTunDataSnapshot(
            delivered: true,
            packet: body,
            ipVersion: parsed.ipVersion,
            sourceIP: parsed.sourceIP,
            destinationIP: parsed.destinationIP,
            dropReason: nil
        )
    }

    private func sharedTunBoundPeerRef(forPeerID peerID: Int, sourceIP: String) -> String? {
        guard
            let ownership = sharedTunOwnership,
            !sourceIP.isEmpty
        else {
            return nil
        }
        let ownerByIPv4 = ownership["owner_by_ipv4"] as? [String: String] ?? [:]
        let ownerByIPv6 = ownership["owner_by_ipv6"] as? [String: String] ?? [:]
        guard let ownerRef = ObstacleBridgeTunInboundAdmissionPolicy.ownerReference(
            for: sourceIP,
            ownerByIPv4: ownerByIPv4,
            ownerByIPv6: ownerByIPv6
        ) else {
            return nil
        }
        if let existing = sharedTunPeerRefByPeer[peerID] {
            return existing == ownerRef ? existing : nil
        }
        sharedTunPeerRefByPeer[peerID] = ownerRef
        sharedTunPeerIDByRef[ownerRef] = peerID
        return ownerRef
    }

    func handleInboundTunDataSharedGuarded(
        peerID: Int?,
        chanID: Int,
        body: Data,
        mtu: Int,
        boundChanID: Int? = nil,
        counter: Int? = nil
    ) -> GuardedInboundTunDataSnapshot {
        guard sharedTunOwnership != nil else {
            return handleInboundTunDataGuarded(chanID: chanID, body: body, mtu: mtu, boundChanID: boundChanID, counter: counter)
        }
        let base = handleInboundTunDataGuarded(chanID: chanID, body: body, mtu: mtu, boundChanID: boundChanID, counter: counter)
        guard base.delivered, let peerID, let sourceIP = base.sourceIP else {
            return base
        }
        if sharedTunDisableInflowFilter {
            return base
        }
        guard sharedTunBoundPeerRef(forPeerID: peerID, sourceIP: sourceIP) != nil else {
            return GuardedInboundTunDataSnapshot(
                delivered: false,
                packet: nil,
                ipVersion: base.ipVersion,
                sourceIP: base.sourceIP,
                destinationIP: base.destinationIP,
                dropReason: "source_not_owned_by_peer"
            )
        }
        return base
    }

    static func planSharedTunOutboundRoute(
        ownerByIPv4: [String: String],
        ownerByIPv6: [String: String],
        peerIDByRef: [String: Int],
        activePeerBindings: [SharedTunActivePeerBinding],
        packet: Data
    ) -> SharedTunOutboundRouteSnapshot {
        guard let parsed = parsePacketEndpoints(packet) else {
            return SharedTunOutboundRouteSnapshot(
                routed: false,
                routeClass: nil,
                selectedPeerIDs: [],
                selectedChanIDs: [],
                ipVersion: nil,
                destinationIP: nil,
                dropReason: parsePacketDropReason(packet)
            )
        }
        let decision = ObstacleBridgeTunRoutingPolicy.plan(
            ipVersion: parsed.ipVersion,
            destinationAddress: parsed.destinationIP,
            ownerByIPv4: ownerByIPv4,
            ownerByIPv6: ownerByIPv6,
            peerIDByReference: peerIDByRef,
            activePeers: activePeerBindings.map {
                .init(peerID: $0.peerID, preferredChannelID: $0.preferredChanID)
            }
        )
        return SharedTunOutboundRouteSnapshot(
            routed: decision.routed,
            routeClass: decision.routeClass,
            selectedPeerIDs: decision.peerIDs,
            selectedChanIDs: decision.channelIDs,
            ipVersion: decision.ipVersion,
            destinationIP: decision.destinationAddress,
            dropReason: decision.dropReason
        )
    }

    func planSharedTunOutboundRoute(packet: Data) -> SharedTunOutboundRouteSnapshot? {
        if sharedTunDisableOutflowFilter {
            return nil
        }
        guard
            let ownership = sharedTunOwnership
        else {
            return nil
        }
        let ownerByIPv4 = ownership["owner_by_ipv4"] as? [String: String] ?? [:]
        let ownerByIPv6 = ownership["owner_by_ipv6"] as? [String: String] ?? [:]
        let active = sharedTunRuntimeByPeer.values
            .sorted { $0.peerID < $1.peerID }
            .map { SharedTunActivePeerBinding(peerID: $0.peerID, preferredChanID: $0.preferredChanID) }
        return Self.planSharedTunOutboundRoute(
            ownerByIPv4: ownerByIPv4,
            ownerByIPv6: ownerByIPv6,
            peerIDByRef: sharedTunPeerIDByRef,
            activePeerBindings: active,
            packet: packet
        )
    }

    static func planSharedTunInboundPeerRelay(
        ownerByIPv4: [String: String],
        ownerByIPv6: [String: String],
        peerIDByRef: [String: Int],
        activePeerBindings: [SharedTunActivePeerBinding],
        sourcePeerID: Int,
        packet: Data
    ) -> SharedTunInboundPeerRelaySnapshot {
        let route = planSharedTunOutboundRoute(
            ownerByIPv4: ownerByIPv4,
            ownerByIPv6: ownerByIPv6,
            peerIDByRef: peerIDByRef,
            activePeerBindings: activePeerBindings,
            packet: packet
        )
        if route.routed,
           route.routeClass == "unicast",
           let selectedPeerID = route.selectedPeerIDs.first,
           selectedPeerID != sourcePeerID {
            return SharedTunInboundPeerRelaySnapshot(
                relayToPeer: true,
                deliverLocal: false,
                routeClass: route.routeClass,
                selectedPeerIDs: route.selectedPeerIDs,
                selectedChanIDs: route.selectedChanIDs,
                ipVersion: route.ipVersion,
                destinationIP: route.destinationIP,
                dropReason: route.dropReason
            )
        }
        return SharedTunInboundPeerRelaySnapshot(
            relayToPeer: false,
            deliverLocal: true,
            routeClass: route.routeClass,
            selectedPeerIDs: route.selectedPeerIDs,
            selectedChanIDs: route.selectedChanIDs,
            ipVersion: route.ipVersion,
            destinationIP: route.destinationIP,
            dropReason: route.dropReason
        )
    }

    func planSharedTunInboundPeerRelay(sourcePeerID: Int?, packet: Data) -> SharedTunInboundPeerRelaySnapshot? {
        if sharedTunDisableOutflowFilter {
            return nil
        }
        guard
            let sharedTunOwnership,
            let sourcePeerID
        else {
            return nil
        }
        let ownerByIPv4 = sharedTunOwnership["owner_by_ipv4"] as? [String: String] ?? [:]
        let ownerByIPv6 = sharedTunOwnership["owner_by_ipv6"] as? [String: String] ?? [:]
        let active = sharedTunRuntimeByPeer.values
            .sorted { $0.peerID < $1.peerID }
            .map { SharedTunActivePeerBinding(peerID: $0.peerID, preferredChanID: $0.preferredChanID) }
        return Self.planSharedTunInboundPeerRelay(
            ownerByIPv4: ownerByIPv4,
            ownerByIPv6: ownerByIPv6,
            peerIDByRef: sharedTunPeerIDByRef,
            activePeerBindings: active,
            sourcePeerID: sourcePeerID,
            packet: packet
        )
    }

    func recordSharedTunDrop(
        reason: String,
        direction: String,
        peerID: Int? = nil,
        chanID: Int? = nil,
        ipVersion: Int? = nil,
        sourceIP: String? = nil,
        destinationIP: String? = nil,
        routeClass: String? = nil,
        packetBytes: Int? = nil
    ) {
        guard sharedTunOwnership != nil else {
            return
        }
        sharedTunDropLedger.record(.init(
            reason: reason,
            direction: direction,
            peerID: peerID,
            channelID: chanID,
            ipVersion: ipVersion,
            sourceAddress: sourceIP,
            destinationAddress: destinationIP,
            routeClass: routeClass,
            packetBytes: packetBytes
        ))
    }

    static func applySharedTunPeerBindingSequence(
        initialBindings: [SharedTunPeerBindingState],
        operations: [(peerID: Int, chanID: Int, drop: Bool)]
    ) -> [SharedTunPeerBindingState] {
        ObstacleBridgeTunPeerBindingPolicy.apply(
            initialBindings: initialBindings.map {
                .init(peerID: $0.peerID, preferredChannelID: $0.preferredChanID, channelIDs: $0.boundChanIDs)
            },
            operations: operations.map { (peerID: $0.peerID, channelID: $0.chanID, drop: $0.drop) }
        ).map {
            .init(peerID: $0.peerID, preferredChanID: $0.preferredChannelID, boundChanIDs: $0.channelIDs)
        }
    }

    static func cleanupSharedTunPeerStateOnDisconnect(
        activePeerBindings: [SharedTunPeerBindingState],
        peerRefByPeer: [Int: String],
        peerIDByRef: [String: Int],
        disconnectedPeerID: Int
    ) -> SharedTunDisconnectCleanupSnapshot {
        let cleanup = ObstacleBridgeTunPeerBindingPolicy.cleanup(
            bindings: activePeerBindings.map {
                .init(peerID: $0.peerID, preferredChannelID: $0.preferredChanID, channelIDs: $0.boundChanIDs)
            },
            peerReferenceByID: peerRefByPeer,
            peerIDByReference: peerIDByRef,
            disconnectedPeerID: disconnectedPeerID
        )
        return SharedTunDisconnectCleanupSnapshot(
            activePeerBindings: cleanup.bindings.map {
                .init(peerID: $0.peerID, preferredChanID: $0.preferredChannelID, boundChanIDs: $0.channelIDs)
            },
            peerRefByPeer: cleanup.peerReferenceByID,
            peerIDByRef: cleanup.peerIDByReference
        )
    }

    func handleInboundTunFragment(
        chanID: Int,
        payload: Data,
        mtu: Int,
        boundChanID: Int? = nil,
        counter: Int? = nil
    ) -> InboundTunFragmentSnapshot {
        let empty = InboundTunFragmentSnapshot(
            delivered: false,
            packet: nil,
            datagramID: 0,
            totalLen: 0,
            receivedBytes: 0
        )
        if let counter,
           (try? session.receive(.init(
                channelID: UInt16(clamping: chanID), protocolType: ObstacleBridgeChannelMuxSessionProtocol.tun.rawValue,
                counter: UInt16(clamping: counter), messageType: ObstacleBridgeChannelMuxSessionMessageType.dataFragment.rawValue, body: payload
           ))) == nil {
            return empty
        }
        let isBound: Bool
        if let boundChanID {
            isBound = boundChanID == chanID
        } else {
            isBound = channelState.isBound(chanID)
        }
        guard isBound else {
            return empty
        }
        guard let fragment = try? ObstacleBridgePacketFragment(wire: payload),
              fragment.totalLength <= UInt16(clamping: mtu),
              let coreChannelID = UInt16(exactly: chanID) else { return empty }
        let datagramID = Int(fragment.datagramID)
        let totalLen = Int(fragment.totalLength)
        switch packetReassembler.consume(channelID: coreChannelID, wire: payload) {
        case .pending:
            return .init(
                delivered: false,
                packet: nil,
                datagramID: datagramID,
                totalLen: totalLen,
                receivedBytes: packetReassembler.receivedBytes(channelID: coreChannelID, datagramID: fragment.datagramID)
            )
        case .complete(let assembled):
            let dataSnapshot = handleInboundTunData(chanID: chanID, body: assembled, mtu: mtu, boundChanID: boundChanID)
            return .init(
                delivered: dataSnapshot.delivered,
                packet: dataSnapshot.packet,
                datagramID: datagramID,
                totalLen: totalLen,
                receivedBytes: totalLen
            )
        case .rejected:
            return .init(delivered: false, packet: nil, datagramID: datagramID, totalLen: totalLen, receivedBytes: 0)
        }
    }

    func handleInboundTunClose(chanID: Int, counter: Int? = nil) -> CloseSnapshot {
        if let counter,
           (try? session.receive(.init(
                channelID: UInt16(clamping: chanID), protocolType: ObstacleBridgeChannelMuxSessionProtocol.tun.rawValue,
                counter: UInt16(clamping: counter), messageType: ObstacleBridgeChannelMuxSessionMessageType.close.rawValue, body: Data()
           ))) == nil {
            return .init(closed: false, chanID: chanID, preferredChanID: channelState.preferredChannel, boundChanIDs: channelState.channels)
        }
        let closed = channelState.close(chanID)
        if let coreChannelID = UInt16(exactly: chanID) {
            packetReassembler.withdraw(channelID: coreChannelID)
        }
        return CloseSnapshot(
            closed: closed,
            chanID: chanID,
            preferredChanID: channelState.preferredChannel,
            boundChanIDs: channelState.channels
        )
    }

    private func buildDataFrames(chanID: Int, packet: Data) throws -> [Data]? {
        if ObstacleBridgeChannelMuxCodec.muxHeaderSize + packet.count <= sessionMaxAppPayload {
            return try wireFrames(from: session.localData(channelID: UInt16(clamping: chanID), payload: packet))
        }
        let fragmentPayloadLimit = max(0, sessionMaxAppPayload - ObstacleBridgeChannelMuxCodec.muxHeaderSize - Self.tunFragmentHeaderSize)
        guard fragmentPayloadLimit > 0, packet.count <= 0xFFFF else {
            return nil
        }
        let datagramID = nextTunFragmentDatagramID()
        let fragments = try ObstacleBridgePacketFragment.fragment(
            packet,
            datagramID: datagramID,
            maximumPayload: fragmentPayloadLimit
        )
        return try fragments.flatMap { fragment in
            try wireFrames(from: session.localDataFragment(channelID: UInt16(clamping: chanID), payload: fragment.wire))
        }
    }

    private func nextTunFragmentDatagramID() -> UInt32 {
        var datagramID = nextFragmentDatagramID & 0xFFFFFFFF
        if datagramID == 0 {
            datagramID = 1
        }
        nextFragmentDatagramID = datagramID == 0xFFFFFFFF ? 1 : datagramID &+ 1
        return datagramID
    }

    private static func makeSession(
        instanceID: UInt64,
        connectionSeq: UInt32,
        nextTunID: Int,
        chanIDStride: Int,
        sessionMaxAppPayload: Int
    ) -> ObstacleBridgeChannelMuxSession {
        .init(
            maximumApplicationPayload: sessionMaxAppPayload,
            instanceID: instanceID,
            connectionSequence: connectionSeq,
            initialChannelID: UInt16(clamping: max(1, nextTunID)),
            channelStride: UInt16(clamping: max(1, chanIDStride))
        )
    }

    private static func coreServiceSpec(_ spec: ObstacleBridgeChannelMuxCodec.ServiceSpec) -> ObstacleBridgeServiceSpec? {
        try? ObstacleBridgeChannelMuxCodec.coreServiceSpec(spec)
    }

    private static func channelID(from effects: [ObstacleBridgeChannelMuxSessionEffect]) -> Int? {
        effects.compactMap { effect in
            guard case .outbound(let frame) = effect else { return nil }
            return Int(frame.channelID)
        }.first
    }

    private func wireFrames(from effects: [ObstacleBridgeChannelMuxSessionEffect]) throws -> [Data] {
        try effects.compactMap { effect in
            guard case .outbound(let frame) = effect,
                  let proto = ObstacleBridgeChannelMuxCodec.Proto(rawValue: Int(frame.protocolType)),
                  let mtype = ObstacleBridgeChannelMuxCodec.MType(rawValue: Int(frame.messageType)) else { return nil }
            return try ObstacleBridgeChannelMuxCodec.packMux(
                chanID: Int(frame.channelID), proto: proto,
                counter: Int(frame.counter), mtype: mtype, body: frame.body
            )
        }
    }

    private static func parsePacketDropReason(_ packet: Data) -> String {
        do {
            _ = try ObstacleBridgeIPPacket.parse(packet)
            return "unknown"
        } catch ObstacleBridgePacketModelError.emptyPacket {
            return "empty"
        } catch ObstacleBridgePacketModelError.malformedIPv4 {
            return packet.count < 20 ? "ipv4_too_short" : "ipv4_header_truncated"
        } catch ObstacleBridgePacketModelError.malformedIPv6 {
            return "ipv6_too_short"
        } catch ObstacleBridgePacketModelError.unsupportedVersion {
            return "unsupported_ip_version"
        } catch {
            return "unknown"
        }
    }

    private static func parsePacketEndpoints(_ packet: Data) -> (ipVersion: Int, sourceIP: String, destinationIP: String)? {
        guard let parsed = try? ObstacleBridgeIPPacket.parse(packet) else {
            return nil
        }
        switch parsed.version {
        case .ipv4:
            return (
                Int(ObstacleBridgeIPVersion.ipv4.rawValue),
                parsed.sourceAddress.map(String.init).joined(separator: "."),
                parsed.destinationAddress.map(String.init).joined(separator: ".")
            )
        case .ipv6:
            return (
                Int(ObstacleBridgeIPVersion.ipv6.rawValue),
                ipv6String(from: parsed.sourceAddress),
                ipv6String(from: parsed.destinationAddress)
            )
        }
    }

    private static func ipv6String(from data: Data) -> String {
        var bytes = [UInt8](data)
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let rendered = bytes.withUnsafeMutableBytes { srcPtr in
            buffer.withUnsafeMutableBufferPointer { dstPtr in
                inet_ntop(AF_INET6, srcPtr.baseAddress, dstPtr.baseAddress, socklen_t(INET6_ADDRSTRLEN))
            }
        }
        if rendered != nil {
            return String(cString: buffer)
        }
        let groups = stride(from: 0, to: bytes.count, by: 2).map { idx in
            String(format: "%x", Int((UInt16(bytes[idx]) << 8) | UInt16(bytes[idx + 1])))
        }
        return groups.joined(separator: ":")
    }

    private static func normalizedIPAddress(_ value: String?, family: Int32) -> String? {
        guard let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines), !trimmed.isEmpty else {
            return nil
        }
        switch family {
        case AF_INET:
            var addr = in_addr()
            guard inet_pton(AF_INET, trimmed, &addr) == 1 else { return nil }
            return trimmed
        case AF_INET6:
            var addr6 = in6_addr()
            guard inet_pton(AF_INET6, trimmed, &addr6) == 1 else { return nil }
            return trimmed
        default:
            return nil
        }
    }

    private static func normalizeLocalPacketSource(_ packet: Data, ipv4Source: String?, ipv6Source: String?) -> Data? {
        guard let parsed = try? ObstacleBridgeIPPacket.parse(packet) else { return nil }
        switch parsed.version {
        case .ipv4:
            guard let ipv4Source else { return nil }
            return normalizeIPv4PacketSource(packet, sourceIP: ipv4Source)
        case .ipv6:
            guard let ipv6Source else { return nil }
            return normalizeIPv6PacketSource(packet, sourceIP: ipv6Source)
        }
    }

    private static func normalizeIPv4PacketSource(_ packet: Data, sourceIP: String) -> Data? {
        guard let sourceBytes = ipv4Bytes(sourceIP) else { return nil }
        return try? ObstacleBridgeIPPacket.replacingSourceAndRepairingChecksums(in: packet, with: Data(sourceBytes))
    }

    private static func normalizeIPv6PacketSource(_ packet: Data, sourceIP: String) -> Data? {
        guard let sourceBytes = ipv6Bytes(sourceIP) else { return nil }
        return try? ObstacleBridgeIPPacket.replacingSourceAndRepairingChecksums(in: packet, with: Data(sourceBytes))
    }

    private static func ipv4Bytes(_ address: String) -> [UInt8]? {
        var storage = in_addr()
        guard inet_pton(AF_INET, address, &storage) == 1 else { return nil }
        return withUnsafeBytes(of: &storage) { rawBytes in
            Array(rawBytes.prefix(4))
        }
    }

    private static func ipv6Bytes(_ address: String) -> [UInt8]? {
        var storage = in6_addr()
        guard inet_pton(AF_INET6, address, &storage) == 1 else { return nil }
        return withUnsafeBytes(of: &storage) { Array($0) }
    }

}
