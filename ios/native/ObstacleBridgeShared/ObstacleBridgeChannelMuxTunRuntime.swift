import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

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

    private struct FragmentKey: Hashable {
        var chanID: Int
        var datagramID: Int
    }

    private struct FragmentState {
        var totalLen: Int
        var parts: [Int: Data]
        var receivedBytes: Int
    }

    private struct TunInflowScopeState {
        var windowStartNS: UInt64?
        var previousBytes: Int
        var currentBytes: Int
        var throttleDropCount: Int
    }

    private struct SharedTunScopeMetadata {
        var routeClass: String
        var selectedPeerIDs: [Int]
        var selectedChanIDs: [Int]
    }

    private let instanceID: UInt64
    private let connectionSeq: UInt32
    private let chanIDStart: Int
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
    private var nextTunID: Int
    private var nextFragmentDatagramID: UInt32
    private var controlChunkNextTxID: UInt32
    private var counters: [Int: Int]
    private var boundTunChanIDs: Set<Int>
    private var preferredTunChanID: Int?
    private var fragmentStates: [FragmentKey: FragmentState]
    private var tunInflowScopeStates: [String: TunInflowScopeState]
    private var sharedTunScopeMetadata: [String: SharedTunScopeMetadata]
    private var sharedTunRuntimeByPeer: [Int: SharedTunPeerBindingState]
    private var sharedTunPeerRefByPeer: [Int: String]
    private var sharedTunPeerIDByRef: [String: Int]
    private var sharedTunDropTotal: Int
    private var sharedTunDropByReason: [String: Int]
    private var sharedTunRecentDrops: [[String: Any]]
    private let controlChunkReassembler: ObstacleBridgeChannelMuxCodec.ControlChunkReassembler

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
        self.chanIDStart = chanIDStart
        self.chanIDStride = max(1, chanIDStride)
        self.nextTunID = nextTunID
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
        self.controlChunkNextTxID = 1
        self.counters = [:]
        self.boundTunChanIDs = []
        self.preferredTunChanID = nil
        self.fragmentStates = [:]
        self.tunInflowScopeStates = [:]
        self.sharedTunScopeMetadata = [:]
        self.sharedTunRuntimeByPeer = [:]
        self.sharedTunPeerRefByPeer = [:]
        self.sharedTunPeerIDByRef = [:]
        self.sharedTunDropTotal = 0
        self.sharedTunDropByReason = [:]
        self.sharedTunRecentDrops = []
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
        var activeBindings: [[String: Any]] = sharedTunRuntimeByPeer.values
            .sorted { $0.peerID < $1.peerID }
            .map { state in
                var entry: [String: Any] = [
                    "peer_id": state.peerID,
                    "preferred_chan_id": state.preferredChanID as Any,
                    "bound_chan_ids": state.boundChanIDs.sorted(),
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
        snapshot["drop_counters"] = [
            "total": sharedTunDropTotal,
            "by_reason": sharedTunDropByReason,
        ]
        snapshot["recent_drops"] = sharedTunRecentDrops
        return snapshot
    }

    private func throttleBudgetBytes(previousBytes: Int) -> Int {
        Int(Double(previousBytes) * Self.tunInflowThrottleRatio)
    }

    private func throttleSummary(
        scopeID: String,
        snapshot: OverlayBackpressureSnapshot,
        states: [(String, TunInflowScopeState)]
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
        guard localTunSendAllowed(packetBytes: packet.count, snapshot: backpressure, nowNS: sendNowNS, scopeID: appliedScopeID) else {
            return nil
        }

        let normalizedPacket = normalizedLocalPacketForTunnel(packet: packet)

        var frames: [Data] = []
        let preferredChanID = existingChanID ?? preferredTunChanID
        let allocatedChannel = preferredChanID == nil
        let chanID = preferredChanID ?? allocateTunID()
        if allocatedChannel {
            guard let openFrames = try buildOpenFrames(chanID: chanID, spec: spec) else {
                return nil
            }
            frames.append(contentsOf: openFrames)
        }
        boundTunChanIDs.insert(chanID)
        if preferredTunChanID == nil {
            preferredTunChanID = chanID
        }

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
            nextTunID: nextTunID,
            nextCounter: counters[chanID] ?? 0
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

    private func advanceTunInflowWindow(scopeID: String, nowNS: UInt64) -> TunInflowScopeState {
        var state = tunInflowScopeStates[scopeID] ?? TunInflowScopeState(
            windowStartNS: nil,
            previousBytes: 0,
            currentBytes: 0,
            throttleDropCount: 0
        )
        guard let startNS = state.windowStartNS else {
            state.windowStartNS = nowNS
            tunInflowScopeStates[scopeID] = state
            return state
        }
        let elapsed = nowNS &- startNS
        guard elapsed >= Self.tunInflowThrottleWindowNS else {
            return state
        }
        let windows = elapsed / Self.tunInflowThrottleWindowNS
        if windows == 1 {
            state.previousBytes = state.currentBytes
        } else {
            state.previousBytes = 0
        }
        state.currentBytes = 0
        state.windowStartNS = startNS &+ windows &* Self.tunInflowThrottleWindowNS
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
        for currentScopeID in localIngressScopeIDs(scopeID) {
            let state = advanceTunInflowWindow(scopeID: currentScopeID, nowNS: nowNS)
            let allowanceBytes = localIngressScopeAllowanceBytes(
                snapshot: snapshot,
                state: state,
                scopeID: currentScopeID
            )
            guard allowanceBytes > 0 else {
                return false
            }
            if (state.currentBytes + max(0, packetBytes)) > allowanceBytes {
                return false
            }
        }
        return true
    }

    private func recordLocalTunForward(packetBytes: Int, nowNS: UInt64, scopeID: String) {
        var state = advanceTunInflowWindow(scopeID: scopeID, nowNS: nowNS)
        state.currentBytes += max(0, packetBytes)
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
        state: TunInflowScopeState,
        scopeID: String
    ) -> Int {
        let aggregateScopeID = aggregateLocalIngressScopeID()
        let statePrevWindowBytes = max(0, state.previousBytes)
        let basePrevWindowBytes: Int
        if scopeID == aggregateScopeID {
            let transportPrevWindowBytes = max(0, snapshot.transportPrevWindowBytes)
            basePrevWindowBytes = transportPrevWindowBytes > 0 ? transportPrevWindowBytes : statePrevWindowBytes
        } else {
            basePrevWindowBytes = statePrevWindowBytes
        }
        return throttleBudgetBytes(previousBytes: basePrevWindowBytes)
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
            state.throttleDropCount += 1
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
            state.currentBytes += max(0, packetBytes)
        } else {
            state.throttleDropCount += 1
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

    func handleInboundTunOpen(chanID: Int, payload: Data) -> InboundTunOpenSnapshot {
        guard
            let parsed = ObstacleBridgeChannelMuxCodec.parseOpenPayload(payload),
            parsed.spec.lProto == "tun",
            parsed.spec.rProto == "tun"
        else {
            return InboundTunOpenSnapshot(
                accepted: false,
                chanID: chanID,
                preferredChanID: preferredTunChanID,
                remoteSpec: nil
            )
        }
        if let localSpec,
           (parsed.spec.rHost != localSpec.lBind || parsed.spec.rPort != localSpec.lPort) {
            return InboundTunOpenSnapshot(
                accepted: false,
                chanID: chanID,
                preferredChanID: preferredTunChanID,
                remoteSpec: parsed.spec
            )
        }
        boundTunChanIDs.insert(chanID)
        if preferredTunChanID == nil {
            preferredTunChanID = chanID
        }
        return InboundTunOpenSnapshot(
            accepted: true,
            chanID: chanID,
            preferredChanID: preferredTunChanID,
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
            boundChanIDs: uniqueBound
        )
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
        peerID: Int? = nil
    ) -> InboundTunOpenChunkSnapshot {
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
                preferredChanID: preferredTunChanID,
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
        boundChanID: Int? = nil
    ) -> InboundTunDataSnapshot {
        let isBound: Bool
        if let boundChanID {
            isBound = boundChanID == chanID
        } else {
            isBound = boundTunChanIDs.contains(chanID)
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
        allowedSourceIPs: Set<String>? = nil
    ) -> GuardedInboundTunDataSnapshot {
        let base = handleInboundTunData(chanID: chanID, body: body, mtu: mtu, boundChanID: boundChanID)
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
        if let allowedSourceIPs, !allowedSourceIPs.isEmpty, !allowedSourceIPs.contains(parsed.sourceIP) {
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
        guard let ownerRef = ownerByIPv4[sourceIP] ?? ownerByIPv6[sourceIP] else {
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
        boundChanID: Int? = nil
    ) -> GuardedInboundTunDataSnapshot {
        guard sharedTunOwnership != nil else {
            return handleInboundTunDataGuarded(chanID: chanID, body: body, mtu: mtu, boundChanID: boundChanID)
        }
        let base = handleInboundTunDataGuarded(chanID: chanID, body: body, mtu: mtu, boundChanID: boundChanID)
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
        if parsed.ipVersion == 4, parsed.destinationIP == "255.255.255.255" {
            let selected = activePeerBindings
                .filter { $0.preferredChanID != nil }
                .sorted { lhs, rhs in lhs.peerID < rhs.peerID }
            return SharedTunOutboundRouteSnapshot(
                routed: !selected.isEmpty,
                routeClass: "broadcast",
                selectedPeerIDs: selected.map(\.peerID),
                selectedChanIDs: selected.compactMap(\.preferredChanID),
                ipVersion: parsed.ipVersion,
                destinationIP: parsed.destinationIP,
                dropReason: selected.isEmpty ? "broadcast_no_active_peers" : nil
            )
        }
        let ownerRef = ownerByIPv4[parsed.destinationIP] ?? ownerByIPv6[parsed.destinationIP]
        guard let ownerRef else {
            return SharedTunOutboundRouteSnapshot(
                routed: false,
                routeClass: "unicast",
                selectedPeerIDs: [],
                selectedChanIDs: [],
                ipVersion: parsed.ipVersion,
                destinationIP: parsed.destinationIP,
                dropReason: "unknown_destination"
            )
        }
        guard let peerID = peerIDByRef[ownerRef] else {
            return SharedTunOutboundRouteSnapshot(
                routed: false,
                routeClass: "unicast",
                selectedPeerIDs: [],
                selectedChanIDs: [],
                ipVersion: parsed.ipVersion,
                destinationIP: parsed.destinationIP,
                dropReason: "destination_peer_unmapped"
            )
        }
        let selectedBinding = activePeerBindings.first { $0.peerID == peerID }
        guard let selectedBinding, let preferredChanID = selectedBinding.preferredChanID else {
            return SharedTunOutboundRouteSnapshot(
                routed: false,
                routeClass: "unicast",
                selectedPeerIDs: [peerID],
                selectedChanIDs: [],
                ipVersion: parsed.ipVersion,
                destinationIP: parsed.destinationIP,
                dropReason: "destination_peer_inactive"
            )
        }
        return SharedTunOutboundRouteSnapshot(
            routed: true,
            routeClass: "unicast",
            selectedPeerIDs: [peerID],
            selectedChanIDs: [preferredChanID],
            ipVersion: parsed.ipVersion,
            destinationIP: parsed.destinationIP,
            dropReason: nil
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
        let reasonKey = reason.isEmpty ? "unknown" : reason
        sharedTunDropTotal += 1
        sharedTunDropByReason[reasonKey, default: 0] += 1
        var entry: [String: Any] = [
            "reason": reasonKey,
            "direction": direction,
        ]
        if let peerID { entry["peer_id"] = peerID }
        if let chanID { entry["chan_id"] = chanID }
        if let ipVersion { entry["ip_version"] = ipVersion }
        if let sourceIP { entry["source_ip"] = sourceIP }
        if let destinationIP { entry["destination_ip"] = destinationIP }
        if let routeClass { entry["route_class"] = routeClass }
        if let packetBytes { entry["packet_bytes"] = packetBytes }
        sharedTunRecentDrops.append(entry)
        if sharedTunRecentDrops.count > 64 {
            sharedTunRecentDrops = Array(sharedTunRecentDrops.suffix(64))
        }
    }

    static func applySharedTunPeerBindingSequence(
        initialBindings: [SharedTunPeerBindingState],
        operations: [(peerID: Int, chanID: Int, drop: Bool)]
    ) -> [SharedTunPeerBindingState] {
        var states: [Int: SharedTunPeerBindingState] = [:]
        for binding in initialBindings {
            let uniqueBound = Array(Set(binding.boundChanIDs)).sorted()
            let preferredChanID = uniqueBound.contains(binding.preferredChanID ?? -1)
                ? binding.preferredChanID
                : uniqueBound.first
            states[binding.peerID] = SharedTunPeerBindingState(
                peerID: binding.peerID,
                preferredChanID: preferredChanID,
                boundChanIDs: uniqueBound
            )
        }
        for operation in operations {
            if operation.drop {
                guard var state = states[operation.peerID] else {
                    continue
                }
                let remaining = state.boundChanIDs.filter { $0 != operation.chanID }
                if remaining.isEmpty {
                    states.removeValue(forKey: operation.peerID)
                    continue
                }
                state.boundChanIDs = remaining
                if !remaining.contains(state.preferredChanID ?? -1) {
                    state.preferredChanID = remaining.first
                }
                states[operation.peerID] = state
                continue
            }
            var state = states[operation.peerID] ?? SharedTunPeerBindingState(
                peerID: operation.peerID,
                preferredChanID: nil,
                boundChanIDs: []
            )
            let merged = Array(Set(state.boundChanIDs + [operation.chanID])).sorted()
            state.boundChanIDs = merged
            if state.preferredChanID == nil || !merged.contains(state.preferredChanID ?? -1) {
                state.preferredChanID = merged.first
            }
            states[operation.peerID] = state
        }
        return states.values.sorted { lhs, rhs in lhs.peerID < rhs.peerID }
    }

    static func cleanupSharedTunPeerStateOnDisconnect(
        activePeerBindings: [SharedTunPeerBindingState],
        peerRefByPeer: [Int: String],
        peerIDByRef: [String: Int],
        disconnectedPeerID: Int
    ) -> SharedTunDisconnectCleanupSnapshot {
        let remainingBindings = activePeerBindings
            .filter { $0.peerID != disconnectedPeerID }
            .sorted { lhs, rhs in lhs.peerID < rhs.peerID }
        let remainingPeerRefByPeer = peerRefByPeer.filter { $0.key != disconnectedPeerID }
        var remainingPeerIDByRef = peerIDByRef
        for (peerID, peerRef) in peerRefByPeer where peerID == disconnectedPeerID {
            if remainingPeerIDByRef[peerRef] == disconnectedPeerID {
                remainingPeerIDByRef.removeValue(forKey: peerRef)
            }
        }
        return SharedTunDisconnectCleanupSnapshot(
            activePeerBindings: remainingBindings,
            peerRefByPeer: remainingPeerRefByPeer,
            peerIDByRef: remainingPeerIDByRef
        )
    }

    func handleInboundTunFragment(
        chanID: Int,
        payload: Data,
        mtu: Int,
        boundChanID: Int? = nil
    ) -> InboundTunFragmentSnapshot {
        let empty = InboundTunFragmentSnapshot(
            delivered: false,
            packet: nil,
            datagramID: 0,
            totalLen: 0,
            receivedBytes: 0
        )
        let isBound: Bool
        if let boundChanID {
            isBound = boundChanID == chanID
        } else {
            isBound = boundTunChanIDs.contains(chanID)
        }
        guard isBound else {
            return empty
        }
        guard payload.count >= Self.tunFragmentHeaderSize else {
            return empty
        }
        let datagramID = Self.readUInt32(payload, offset: 0)
        let totalLen = Int(Self.readUInt16(payload, offset: 4))
        let offset = Int(Self.readUInt16(payload, offset: 6))
        let chunk = payload.subdata(in: Self.tunFragmentHeaderSize..<payload.count)
        let key = FragmentKey(chanID: chanID, datagramID: Int(datagramID))
        guard totalLen > 0, totalLen <= mtu else {
            fragmentStates.removeValue(forKey: key)
            return InboundTunFragmentSnapshot(
                delivered: false,
                packet: nil,
                datagramID: Int(datagramID),
                totalLen: totalLen,
                receivedBytes: 0
            )
        }
        guard offset <= totalLen, (offset + chunk.count) <= totalLen, !chunk.isEmpty else {
            return InboundTunFragmentSnapshot(
                delivered: false,
                packet: nil,
                datagramID: Int(datagramID),
                totalLen: totalLen,
                receivedBytes: fragmentStates[key]?.receivedBytes ?? 0
            )
        }
        var state = fragmentStates[key] ?? FragmentState(totalLen: totalLen, parts: [:], receivedBytes: 0)
        if state.totalLen != totalLen {
            fragmentStates.removeValue(forKey: key)
            return InboundTunFragmentSnapshot(
                delivered: false,
                packet: nil,
                datagramID: Int(datagramID),
                totalLen: totalLen,
                receivedBytes: 0
            )
        }
        if state.parts[offset] == nil {
            state.parts[offset] = chunk
            state.receivedBytes += chunk.count
        }
        fragmentStates[key] = state
        guard state.receivedBytes >= totalLen else {
            return InboundTunFragmentSnapshot(
                delivered: false,
                packet: nil,
                datagramID: Int(datagramID),
                totalLen: totalLen,
                receivedBytes: state.receivedBytes
            )
        }
        var assembled = Data(count: totalLen)
        var cursor = 0
        for partOffset in state.parts.keys.sorted() {
            guard let part = state.parts[partOffset], partOffset == cursor else {
                return InboundTunFragmentSnapshot(
                    delivered: false,
                    packet: nil,
                    datagramID: Int(datagramID),
                    totalLen: totalLen,
                    receivedBytes: state.receivedBytes
                )
            }
            let nextCursor = partOffset + part.count
            guard nextCursor <= totalLen else {
                fragmentStates.removeValue(forKey: key)
                return InboundTunFragmentSnapshot(
                    delivered: false,
                    packet: nil,
                    datagramID: Int(datagramID),
                    totalLen: totalLen,
                    receivedBytes: state.receivedBytes
                )
            }
            assembled.replaceSubrange(partOffset..<nextCursor, with: part)
            cursor = nextCursor
        }
        guard cursor == totalLen else {
            return InboundTunFragmentSnapshot(
                delivered: false,
                packet: nil,
                datagramID: Int(datagramID),
                totalLen: totalLen,
                receivedBytes: state.receivedBytes
            )
        }
        fragmentStates.removeValue(forKey: key)
        let dataSnapshot = handleInboundTunData(chanID: chanID, body: assembled, mtu: mtu, boundChanID: boundChanID)
        return InboundTunFragmentSnapshot(
            delivered: dataSnapshot.delivered,
            packet: dataSnapshot.packet,
            datagramID: Int(datagramID),
            totalLen: totalLen,
            receivedBytes: state.receivedBytes
        )
    }

    func handleInboundTunClose(chanID: Int) -> CloseSnapshot {
        let closed = boundTunChanIDs.remove(chanID) != nil
        fragmentStates = fragmentStates.filter { $0.key.chanID != chanID }
        if preferredTunChanID == chanID {
            preferredTunChanID = boundTunChanIDs.sorted().first
        }
        return CloseSnapshot(
            closed: closed,
            chanID: chanID,
            preferredChanID: preferredTunChanID,
            boundChanIDs: boundTunChanIDs.sorted()
        )
    }

    private func allocateTunID() -> Int {
        let start = chanIDStart
        var channelID = nextTunID
        if channelID < start || channelID > 65535 {
            channelID = start
        }
        let next = channelID + chanIDStride
        nextTunID = next <= 65535 ? next : start
        return channelID
    }

    private func nextCounter(chanID: Int, mtype: ObstacleBridgeChannelMuxCodec.MType) -> Int {
        if mtype == .open {
            counters[chanID] = 0
            return 0
        }
        let previous = counters[chanID] ?? 0
        let next = (previous + 1) & 0xFFFF
        counters[chanID] = next
        return next
    }

    private func buildOpenFrames(
        chanID: Int,
        spec: ObstacleBridgeChannelMuxCodec.ServiceSpec
    ) throws -> [Data]? {
        let openPayload = try ObstacleBridgeChannelMuxCodec.buildOpenPayload(
            instanceID: instanceID,
            connectionSeq: connectionSeq,
            spec: spec
        )
        if ObstacleBridgeChannelMuxCodec.muxHeaderSize + openPayload.count <= sessionMaxAppPayload {
            return [
                try ObstacleBridgeChannelMuxCodec.packMux(
                    chanID: chanID,
                    proto: .tun,
                    counter: nextCounter(chanID: chanID, mtype: .open),
                    mtype: .open,
                    body: openPayload
                )
            ]
        }
        let txID = ObstacleBridgeChannelMuxCodec.nextControlChunkTxID(current: controlChunkNextTxID)
        controlChunkNextTxID = txID.next
        let chunks = ObstacleBridgeChannelMuxCodec.chunkControlPayload(
            txID: txID.txID,
            maxAppPayload: sessionMaxAppPayload,
            payload: openPayload
        )
        guard !chunks.isEmpty else {
            return nil
        }
        return try chunks.map { chunk in
            try ObstacleBridgeChannelMuxCodec.packMux(
                chanID: chanID,
                proto: .tun,
                counter: nextCounter(chanID: chanID, mtype: .openChunk),
                mtype: .openChunk,
                body: chunk
            )
        }
    }

    private func buildDataFrames(chanID: Int, packet: Data) throws -> [Data]? {
        if ObstacleBridgeChannelMuxCodec.muxHeaderSize + packet.count <= sessionMaxAppPayload {
            return [
                try ObstacleBridgeChannelMuxCodec.packMux(
                    chanID: chanID,
                    proto: .tun,
                    counter: nextCounter(chanID: chanID, mtype: .data),
                    mtype: .data,
                    body: packet
                )
            ]
        }
        let fragmentPayloadLimit = max(0, sessionMaxAppPayload - ObstacleBridgeChannelMuxCodec.muxHeaderSize - Self.tunFragmentHeaderSize)
        guard fragmentPayloadLimit > 0, packet.count <= 0xFFFF else {
            return nil
        }
        let datagramID = nextTunFragmentDatagramID()
        var frames: [Data] = []
        for offset in stride(from: 0, to: packet.count, by: fragmentPayloadLimit) {
            let end = min(offset + fragmentPayloadLimit, packet.count)
            let part = packet.subdata(in: offset..<end)
            var body = Data()
            body.appendUInt32(datagramID)
            body.appendUInt16(UInt16(packet.count & 0xFFFF))
            body.appendUInt16(UInt16(offset & 0xFFFF))
            body.append(part)
            frames.append(
                try ObstacleBridgeChannelMuxCodec.packMux(
                    chanID: chanID,
                    proto: .tun,
                    counter: nextCounter(chanID: chanID, mtype: .dataFrag),
                    mtype: .dataFrag,
                    body: body
                )
            )
        }
        return frames
    }

    private func nextTunFragmentDatagramID() -> UInt32 {
        var datagramID = nextFragmentDatagramID & 0xFFFFFFFF
        if datagramID == 0 {
            datagramID = 1
        }
        nextFragmentDatagramID = datagramID == 0xFFFFFFFF ? 1 : datagramID &+ 1
        return datagramID
    }

    private static func readUInt16(_ data: Data, offset: Int) -> UInt16 {
        let bytes = [UInt8](data[offset..<(offset + 2)])
        return (UInt16(bytes[0]) << 8) | UInt16(bytes[1])
    }

    private static func readUInt32(_ data: Data, offset: Int) -> UInt32 {
        let bytes = [UInt8](data[offset..<(offset + 4)])
        return
            (UInt32(bytes[0]) << 24) |
            (UInt32(bytes[1]) << 16) |
            (UInt32(bytes[2]) << 8) |
            UInt32(bytes[3])
    }

    private static func parsePacketDropReason(_ packet: Data) -> String {
        guard !packet.isEmpty else {
            return "empty"
        }
        let version = Int((packet[packet.startIndex] >> 4) & 0x0F)
        switch version {
        case 4:
            if packet.count < 20 {
                return "ipv4_too_short"
            }
            let ihl = Int(packet[packet.startIndex] & 0x0F) * 4
            if ihl < 20 || packet.count < ihl {
                return "ipv4_header_truncated"
            }
            return "unknown"
        case 6:
            return packet.count < 40 ? "ipv6_too_short" : "unknown"
        default:
            return "unsupported_ip_version"
        }
    }

    private static func parsePacketEndpoints(_ packet: Data) -> (ipVersion: Int, sourceIP: String, destinationIP: String)? {
        guard !packet.isEmpty else {
            return nil
        }
        let version = Int((packet[packet.startIndex] >> 4) & 0x0F)
        switch version {
        case 4:
            guard packet.count >= 20 else {
                return nil
            }
            let ihl = Int(packet[packet.startIndex] & 0x0F) * 4
            guard ihl >= 20, packet.count >= ihl else {
                return nil
            }
            let source = packet.subdata(in: 12..<16).map(String.init).joined(separator: ".")
            let destination = packet.subdata(in: 16..<20).map(String.init).joined(separator: ".")
            return (4, source, destination)
        case 6:
            guard packet.count >= 40 else {
                return nil
            }
            return (
                6,
                ipv6String(from: packet.subdata(in: 8..<24)),
                ipv6String(from: packet.subdata(in: 24..<40))
            )
        default:
            return nil
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
        guard !packet.isEmpty else { return nil }
        let version = Int((packet[packet.startIndex] >> 4) & 0x0F)
        switch version {
        case 4:
            guard let ipv4Source else { return nil }
            return normalizeIPv4PacketSource(packet, sourceIP: ipv4Source)
        case 6:
            guard let ipv6Source else { return nil }
            return normalizeIPv6PacketSource(packet, sourceIP: ipv6Source)
        default:
            return nil
        }
    }

    private static func normalizeIPv4PacketSource(_ packet: Data, sourceIP: String) -> Data? {
        guard packet.count >= 20 else { return nil }
        let ihl = Int(packet[packet.startIndex] & 0x0F) * 4
        guard ihl >= 20, packet.count >= ihl else { return nil }
        guard let sourceBytes = ipv4Bytes(sourceIP) else { return nil }
        if Array(packet[12..<16]) == sourceBytes {
            return packet
        }
        var bytes = [UInt8](packet)
        for (index, value) in sourceBytes.enumerated() {
            bytes[12 + index] = value
        }
        bytes[10] = 0
        bytes[11] = 0
        let headerChecksum = internetChecksum(bytes, start: 0, count: ihl)
        bytes[10] = UInt8((headerChecksum >> 8) & 0xFF)
        bytes[11] = UInt8(headerChecksum & 0xFF)

        let protocolNumber = bytes[9]
        switch protocolNumber {
        case 1:
            let payloadStart = ihl
            guard bytes.count >= payloadStart + 4 else { break }
            bytes[payloadStart + 2] = 0
            bytes[payloadStart + 3] = 0
            let checksum = internetChecksum(bytes, start: payloadStart, count: bytes.count - payloadStart)
            bytes[payloadStart + 2] = UInt8((checksum >> 8) & 0xFF)
            bytes[payloadStart + 3] = UInt8(checksum & 0xFF)
        case 6:
            recomputeIPv4TransportChecksum(&bytes, headerLength: ihl, checksumOffset: 16, protocolNumber: protocolNumber)
        case 17:
            recomputeIPv4TransportChecksum(&bytes, headerLength: ihl, checksumOffset: 6, protocolNumber: protocolNumber, zeroMeansFFFF: true)
        default:
            break
        }
        return Data(bytes)
    }

    private static func normalizeIPv6PacketSource(_ packet: Data, sourceIP: String) -> Data? {
        guard packet.count >= 40 else { return nil }
        guard let sourceBytes = ipv6Bytes(sourceIP) else { return nil }
        if Array(packet[8..<24]) == sourceBytes {
            return packet
        }
        var bytes = [UInt8](packet)
        for (index, value) in sourceBytes.enumerated() {
            bytes[8 + index] = value
        }
        let nextHeader = bytes[6]
        let payloadStart = 40
        switch nextHeader {
        case 6:
            recomputeIPv6TransportChecksum(&bytes, payloadStart: payloadStart, checksumOffset: 16, nextHeader: nextHeader)
        case 17:
            recomputeIPv6TransportChecksum(&bytes, payloadStart: payloadStart, checksumOffset: 6, nextHeader: nextHeader, zeroMeansFFFF: true)
        case 58:
            recomputeIPv6TransportChecksum(&bytes, payloadStart: payloadStart, checksumOffset: 2, nextHeader: nextHeader)
        default:
            break
        }
        return Data(bytes)
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

    private static func recomputeIPv4TransportChecksum(
        _ bytes: inout [UInt8],
        headerLength: Int,
        checksumOffset: Int,
        protocolNumber: UInt8,
        zeroMeansFFFF: Bool = false
    ) {
        let payloadLength = bytes.count - headerLength
        guard payloadLength > checksumOffset + 1 else { return }
        let checksumIndex = headerLength + checksumOffset
        bytes[checksumIndex] = 0
        bytes[checksumIndex + 1] = 0
        var pseudoHeader = [UInt8]()
        pseudoHeader.append(contentsOf: bytes[12..<16])
        pseudoHeader.append(contentsOf: bytes[16..<20])
        pseudoHeader.append(0)
        pseudoHeader.append(protocolNumber)
        pseudoHeader.append(UInt8((payloadLength >> 8) & 0xFF))
        pseudoHeader.append(UInt8(payloadLength & 0xFF))
        pseudoHeader.append(contentsOf: bytes[headerLength...])
        var checksum = internetChecksum(pseudoHeader, start: 0, count: pseudoHeader.count)
        if zeroMeansFFFF && checksum == 0 {
            checksum = 0xFFFF
        }
        bytes[checksumIndex] = UInt8((checksum >> 8) & 0xFF)
        bytes[checksumIndex + 1] = UInt8(checksum & 0xFF)
    }

    private static func recomputeIPv6TransportChecksum(
        _ bytes: inout [UInt8],
        payloadStart: Int,
        checksumOffset: Int,
        nextHeader: UInt8,
        zeroMeansFFFF: Bool = false
    ) {
        let payloadLength = bytes.count - payloadStart
        guard payloadLength > checksumOffset + 1 else { return }
        let checksumIndex = payloadStart + checksumOffset
        bytes[checksumIndex] = 0
        bytes[checksumIndex + 1] = 0
        var pseudoHeader = [UInt8]()
        pseudoHeader.append(contentsOf: bytes[8..<24])
        pseudoHeader.append(contentsOf: bytes[24..<40])
        pseudoHeader.append(UInt8((payloadLength >> 24) & 0xFF))
        pseudoHeader.append(UInt8((payloadLength >> 16) & 0xFF))
        pseudoHeader.append(UInt8((payloadLength >> 8) & 0xFF))
        pseudoHeader.append(UInt8(payloadLength & 0xFF))
        pseudoHeader.append(0)
        pseudoHeader.append(0)
        pseudoHeader.append(0)
        pseudoHeader.append(nextHeader)
        pseudoHeader.append(contentsOf: bytes[payloadStart...])
        var checksum = internetChecksum(pseudoHeader, start: 0, count: pseudoHeader.count)
        if zeroMeansFFFF && checksum == 0 {
            checksum = 0xFFFF
        }
        bytes[checksumIndex] = UInt8((checksum >> 8) & 0xFF)
        bytes[checksumIndex + 1] = UInt8(checksum & 0xFF)
    }

    private static func internetChecksum(_ bytes: [UInt8], start: Int, count: Int) -> UInt16 {
        var sum: UInt32 = 0
        var index = start
        let end = start + count
        while index + 1 < end {
            let word = (UInt32(bytes[index]) << 8) | UInt32(bytes[index + 1])
            sum &+= word
            index += 2
        }
        if index < end {
            sum &+= UInt32(bytes[index]) << 8
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) &+ (sum >> 16)
        }
        return UInt16(~sum & 0xFFFF)
    }
}
