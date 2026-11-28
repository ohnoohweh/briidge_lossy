import Foundation

/// The one delivery/RTT authority for stream overlays.
///
/// Records enter this runtime before compression and SecureLink.  Pending
/// entries are therefore plaintext ChannelMux records and can be protected by
/// a replacement SecureLink session after a lower transport epoch changes.
public final class ObstacleBridgeDeliveryFenceRuntime {
    public struct InboundResult: Sendable {
        public let emittedRecords: [Data]
        public let deliveredPayloads: [Data]
        public let connected: Bool
    }

    public let maximumPendingBytes: Int
    private var nextSequence: UInt64 = 0
    private var deliveredSequence: UInt64 = 0
    private var confirmedSequence: UInt64 = 0
    // OBSTACLEBRIDGE-MEMORY-ALLOW: reason=delivery ledger retains only peer-unconfirmed plaintext; bounds=maximumPendingBytes; test=deliveryFenceRetainsOnlyUnconfirmedPlaintextAcrossLowerEpoch
    private var pending: [UInt64: Data] = [:]
    private var pendingBytes = 0
    private var ready = false

    public init(maximumPendingBytes: Int = 4 * 1_024 * 1_024) {
        self.maximumPendingBytes = max(0, maximumPendingBytes)
    }

    public var isConnected: Bool { ready }
    public var pendingByteCount: Int { pendingBytes }
    public var receivedWatermark: UInt64 { deliveredSequence }
    public var confirmedWatermark: UInt64 { confirmedSequence }

    /// Retains one plaintext application payload and returns its outer record.
    /// `nil` means the bounded retention limit rejected admission.
    public func enqueue(_ payload: Data) -> Data? {
        guard !payload.isEmpty else { return nil }
        let sequence = nextSequence &+ 1
        guard sequence != 0 else { return nil }
        let record = ObstacleBridgeDeliveryFenceCodec.encodeData(sequence: sequence, payload: payload)
        guard pendingBytes <= maximumPendingBytes - record.count else { return nil }
        nextSequence = sequence
        pending[sequence] = record
        pendingBytes += record.count
        return record
    }

    /// A new lower authenticated epoch must receive every unconfirmed record
    /// before its probe.  The transport owns actual I/O ordering.
    public func lowerReady(nowNanoseconds: UInt64) -> [Data] {
        var records = pending.keys.sorted().compactMap { pending[$0] }
        records.append(ObstacleBridgeDeliveryFenceCodec.encodePing(
            txNS: nowNanoseconds,
            echoNS: 0,
            deliveredSequence: deliveredSequence
        ))
        return records
    }

    public func heartbeat(nowNanoseconds: UInt64) -> Data {
        ObstacleBridgeDeliveryFenceCodec.encodePing(
            txNS: nowNanoseconds,
            echoNS: 0,
            deliveredSequence: deliveredSequence
        )
    }

    public func lowerDisconnected() {
        ready = false
    }

    public func handleInbound(_ record: Data) -> InboundResult? {
        guard let decoded = try? ObstacleBridgeDeliveryFenceCodec.decode(record) else { return nil }
        switch decoded.kind {
        case .data:
            if decoded.sequence <= deliveredSequence {
                return .init(
                    emittedRecords: [ObstacleBridgeDeliveryFenceCodec.encodePong(echoTxNS: 0, deliveredSequence: deliveredSequence)],
                    deliveredPayloads: [], connected: ready
                )
            }
            guard decoded.sequence == deliveredSequence &+ 1 else {
                return .init(emittedRecords: [], deliveredPayloads: [], connected: ready)
            }
            deliveredSequence = decoded.sequence
            return .init(
                emittedRecords: [ObstacleBridgeDeliveryFenceCodec.encodePong(echoTxNS: 0, deliveredSequence: deliveredSequence)],
                deliveredPayloads: [decoded.body], connected: ready
            )
        case .ping:
            guard let fields = try? ObstacleBridgeDeliveryFenceCodec.pingFields(decoded.body) else { return nil }
            ready = true
            return .init(
                emittedRecords: [ObstacleBridgeDeliveryFenceCodec.encodePong(echoTxNS: fields.txNS, deliveredSequence: deliveredSequence)],
                deliveredPayloads: [], connected: ready
            )
        case .pong:
            guard let fields = try? ObstacleBridgeDeliveryFenceCodec.pongFields(decoded.body) else { return nil }
            acknowledge(fields.deliveredSequence)
            ready = true
            return .init(emittedRecords: [], deliveredPayloads: [], connected: ready)
        }
    }

    private func acknowledge(_ watermark: UInt64) {
        guard watermark > confirmedSequence else { return }
        confirmedSequence = watermark
        for sequence in pending.keys.filter({ $0 <= watermark }) {
            if let record = pending.removeValue(forKey: sequence) {
                pendingBytes -= record.count
            }
        }
    }
}
