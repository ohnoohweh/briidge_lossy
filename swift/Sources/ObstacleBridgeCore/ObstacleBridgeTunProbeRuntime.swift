import Foundation

/// Core-owned state machine for one in-flight TUN ICMP diagnostic probe.
///
/// Adapters provide packet-device writes, monotonic timestamps, and received
/// packets.  This type retains the matching key, counters, cache, and result
/// projection so those decisions do not leak into a platform packet-device
/// owner.
public final class ObstacleBridgeTunProbeRuntime {
    public struct Launch {
        public let token: UUID
        public let packet: Data
        public let resolvedTarget: String
        public let family: Int32
    }

    public struct Observation {
        public let matched: Bool
        public let result: [String: Any]?
    }

    private struct Pending {
        let key: ObstacleBridgeTunProbeWaiterKey
        let probeKind: String
        let target: String
        let resolvedTarget: String
        let nameResolution: [String: Any]
        let cacheKey: String
        let sentMonotonicNS: UInt64
    }

    private let lock = NSLock()
    private let identifier: UInt16
    private var sequence: UInt16 = 1
    private var pendingByToken: [UUID: Pending] = [:]
    private var tokenByKey: [ObstacleBridgeTunProbeWaiterKey: UUID] = [:]
    private var history: [String: ObstacleBridgeTunProbeHistory] = [:]
    private var tunICMPStageCounts = ObstacleBridgeTunProbeDiagnosticsSupport.makeTunICMPStageCounts()
    private var localReplyStageCounts = ObstacleBridgeTunProbeDiagnosticsSupport.makeLocalReplyStageCounts()
    private var boundaryCounts = ObstacleBridgeTunProbeDiagnosticsSupport.makeTunProbeBoundaryCounts()

    public init(identifier: UInt16 = 1) {
        self.identifier = identifier == 0 ? 1 : identifier
    }

    /// Builds an ICMP request and registers the Core-owned reply matcher.
    public func begin(
        probeKind: String,
        target: String,
        resolvedTarget: String,
        family: Int32,
        sourceIP: String,
        ifname: String,
        sentMonotonicNS: UInt64,
        nonce: Data
    ) -> Launch? {
        let kindCode = ObstacleBridgeTunProbeDiagnosticsSupport.tunProbeKindCode(probeKind)
        let payload = ObstacleBridgeTunPing.probePayload(
            probeKind: kindCode,
            nonce: nonce,
            sentMonotonicNS: sentMonotonicNS
        )
        lock.lock()
        let currentSequence = sequence == 0 ? 1 : sequence
        sequence = currentSequence &+ 1
        if sequence == 0 { sequence = 1 }
        let packet = family == ObstacleBridgeTunProbeDiagnosticsSupport.ipv6Family
            ? ObstacleBridgeTunPing.buildIPv6EchoRequest(sourceIP: sourceIP, destinationIP: resolvedTarget, identifier: identifier, sequence: currentSequence, payload: payload)
            : ObstacleBridgeTunPing.buildIPv4EchoRequest(sourceIP: sourceIP, destinationIP: resolvedTarget, identifier: identifier, sequence: currentSequence, payload: payload)
        guard let packet else {
            lock.unlock()
            return nil
        }
        let token = UUID()
        let key = ObstacleBridgeTunProbeWaiterKey(family: family, identifier: identifier, sequence: currentSequence, nonce: Data(payload.dropFirst(5).prefix(8)))
        let pending = Pending(
            key: key, probeKind: probeKind, target: target, resolvedTarget: resolvedTarget,
            nameResolution: ObstacleBridgeTunProbeDiagnosticsSupport.tunProbeNameResolution(status: "successful", resolvedIP: resolvedTarget, detail: "Resolved \(target) to \(resolvedTarget)."),
            cacheKey: ObstacleBridgeTunProbeDiagnosticsSupport.tunProbeCacheKey(probeKind: probeKind, ifname: ifname, target: target),
            sentMonotonicNS: sentMonotonicNS
        )
        pendingByToken[token] = pending
        tokenByKey[key] = token
        recordBoundary("probe_attempt_started")
        recordBoundary("probe_waiter_registered")
        lock.unlock()
        return Launch(token: token, packet: packet, resolvedTarget: resolvedTarget, family: family)
    }

    /// Records the Core-defined effects after an adapter writes a launched packet.
    public func packetInjected(_ token: UUID) {
        lock.lock()
        defer { lock.unlock() }
        guard pendingByToken[token] != nil else { return }
        recordBoundary("probe_injected_kernel")
        recordBoundary("probe_send_completed")
        recordStage("from_local_tun_read")
        recordStage("overlay_tx_before_send_app")
        recordStage("local_reply_before_overlay_send")
    }

    /// Matches a returned IPv4 or IPv6 echo reply against the Core-owned waiter.
    public func receive(_ packet: Data, receivedMonotonicNS: UInt64) -> Observation {
        lock.lock()
        defer { lock.unlock() }
        guard let parsed = ObstacleBridgeTunPing.parseEchoReply(packet),
              parsed.payload.count >= ObstacleBridgeTunPing.probeMagic.count + 1 + 8 + 8,
              parsed.payload.prefix(ObstacleBridgeTunPing.probeMagic.count) == ObstacleBridgeTunPing.probeMagic else {
            return Observation(matched: false, result: nil)
        }
        let family: Int32
        switch parsed.family {
        case .ipv4:
            family = ObstacleBridgeTunProbeDiagnosticsSupport.ipv4Family
        case .ipv6:
            family = ObstacleBridgeTunProbeDiagnosticsSupport.ipv6Family
        }
        let key = ObstacleBridgeTunProbeWaiterKey(family: family, identifier: parsed.identifier, sequence: parsed.sequence, nonce: parsed.payload.subdata(in: 5..<13))
        guard let token = tokenByKey.removeValue(forKey: key), let pending = pendingByToken.removeValue(forKey: token) else {
            recordBoundary("probe_reply_unmatched")
            return Observation(matched: false, result: nil)
        }
        recordBoundary("probe_reply_matched")
        recordBoundary("probe_reply_consumed_before_local_write")
        recordStage("overlay_rx_after_unpack")
        recordStage("from_peer_before_local_write")
        recordStage("local_reply_virtual_probe_delivery")
        let rttMS = max(0, Double(receivedMonotonicNS &- pending.sentMonotonicNS) / 1_000_000)
        ObstacleBridgeTunProbeDiagnosticsSupport.recordTunProbeSuccess(cacheKey: pending.cacheKey, rttMS: rttMS, tunProbeHistory: &history, currentUptime: Double(receivedMonotonicNS) / 1_000_000_000)
        return Observation(matched: true, result: result(for: pending, ok: true, state: "verified", detail: "ICMP echo reply received from \(pending.resolvedTarget).", nowNS: receivedMonotonicNS, valueMS: rttMS))
    }

    /// Resolves a pending waiter after the adapter's monotonic timeout fires.
    public func timeout(_ token: UUID, at monotonicNS: UInt64) -> [String: Any]? {
        lock.lock()
        defer { lock.unlock() }
        guard let pending = pendingByToken.removeValue(forKey: token) else { return nil }
        tokenByKey.removeValue(forKey: pending.key)
        recordBoundary("probe_timeout")
        return result(for: pending, ok: false, state: "failed", detail: "No ICMP echo reply received from \(pending.resolvedTarget).", nowNS: monotonicNS)
    }

    /// Resolves a pending waiter when an admitted packet-device adapter reports an I/O failure.
    public func packetDeviceFailed(_ token: UUID, detail: String, at monotonicNS: UInt64) -> [String: Any]? {
        lock.lock()
        defer { lock.unlock() }
        guard let pending = pendingByToken.removeValue(forKey: token) else { return nil }
        tokenByKey.removeValue(forKey: pending.key)
        recordBoundary("probe_exception")
        return result(for: pending, ok: false, state: "failed", detail: detail, nowNS: monotonicNS)
    }

    public func counterSnapshot() -> [String: Int] {
        lock.lock()
        defer { lock.unlock() }
        return boundaryCounts.merging(tunICMPStageCounts) { $0 + $1 }
    }

    private func result(for pending: Pending, ok: Bool, state: String, detail: String, nowNS: UInt64, valueMS: Double? = nil) -> [String: Any] {
        let snapshot = ObstacleBridgeTunProbeDiagnosticsSupport.tunProbeHistorySnapshot(cacheKey: pending.cacheKey, tunProbeHistory: history, currentUptime: Double(nowNS) / 1_000_000_000)
        return ObstacleBridgeTunProbeDiagnosticsSupport.tunProbeResult(probeKind: pending.probeKind, target: pending.target, ok: ok, state: state, summary: "\(ObstacleBridgeTunProbeDiagnosticsSupport.tunProbeLabel(pending.probeKind)): \(state)", detail: detail, resolvedTarget: pending.resolvedTarget, nameResolution: pending.nameResolution, valueMS: valueMS, lastSuccessAgoS: snapshot.lastSuccessAgoS, lastSuccessRTTMS: snapshot.lastSuccessRTTMS)
    }

    private func recordBoundary(_ key: String) {
        ObstacleBridgeTunProbeDiagnosticsSupport.recordTunProbeBoundary(key, tunProbeBoundaryCounts: &boundaryCounts)
    }

    private func recordStage(_ key: String) {
        ObstacleBridgeTunProbeDiagnosticsSupport.recordTunICMPStage(key, tunICMPStageCounts: &tunICMPStageCounts, localReplyStageCounts: &localReplyStageCounts)
    }
}
