import Foundation

public enum ObstacleBridgeMyUDPCodecError: Error, Equatable { case payloadTooLarge, invalidFrame }

public struct ObstacleBridgeMyUDPDataFrame: Equatable, Sendable {
    public let counter: UInt16
    public let payload: Data
    public let transmittedNanoseconds: UInt64
    public let echoedNanoseconds: UInt64
}

public struct ObstacleBridgeMyUDPStreamChunk: Equatable, Sendable {
    public let counter: UInt16
    public let payload: Data
    public init(counter: UInt16, payload: Data) { self.counter = counter; self.payload = payload }
}

public struct ObstacleBridgeMyUDPWireFrame: Equatable, Sendable {
    public let type: UInt8
    public let payload: Data
    public let transmittedNanoseconds: UInt64
    public let echoedNanoseconds: UInt64
    public init(type: UInt8, payload: Data, transmittedNanoseconds: UInt64, echoedNanoseconds: UInt64) {
        self.type = type; self.payload = payload; self.transmittedNanoseconds = transmittedNanoseconds; self.echoedNanoseconds = echoedNanoseconds
    }
}

public struct ObstacleBridgeMyUDPControlFrame: Equatable, Sendable {
    public let lastInOrder: UInt16
    public let highestReceived: UInt16
    public let missing: [UInt16]
    public let transmittedNanoseconds: UInt64
    public let echoedNanoseconds: UInt64
}

public struct ObstacleBridgeMyUDPAcknowledgement: Equatable, Sendable {
    public let lastInOrder: UInt16
    public let highestReceived: UInt16
    public let missing: [UInt16]
    public init(lastInOrder: UInt16, highestReceived: UInt16, missing: [UInt16]) {
        self.lastInOrder = lastInOrder
        self.highestReceived = highestReceived
        self.missing = missing
    }
}

public struct ObstacleBridgeMyUDPControlPolicyDecision: Equatable, Sendable {
    public let shouldEmit: Bool
    public let reason: String?
    public init(shouldEmit: Bool, reason: String?) {
        self.shouldEmit = shouldEmit
        self.reason = reason
    }
}

/// Pure CONTROL emission policy. Runtime owners schedule the resulting effect,
/// but cannot differ on when receiver progress or a gap requires feedback.
public enum ObstacleBridgeMyUDPControlPolicy {
    public static func inbound(
        nowNanoseconds: UInt64,
        expectedCounter: UInt16,
        missingCount: Int,
        grewMissing: Bool,
        lastSentLastInOrder: UInt16,
        lastControlSentNanoseconds: UInt64,
        establishedNanoseconds: UInt64,
        rttEstimateMilliseconds: Double
    ) -> ObstacleBridgeMyUDPControlPolicyDecision {
        if grewMissing { return .init(shouldEmit: true, reason: "inbound_grew_missing") }
        return evaluate(
            nowNanoseconds: nowNanoseconds,
            expectedCounter: expectedCounter,
            missingCount: missingCount,
            lastSentLastInOrder: lastSentLastInOrder,
            lastControlSentNanoseconds: lastControlSentNanoseconds,
            establishedNanoseconds: establishedNanoseconds,
            rttEstimateMilliseconds: rttEstimateMilliseconds,
            clearReason: "advanced_in_order",
            missingReason: "paced_with_missing",
            requiresEstablishedReference: false
        )
    }

    public static func timer(
        nowNanoseconds: UInt64,
        expectedCounter: UInt16,
        missingCount: Int,
        lastSentLastInOrder: UInt16,
        lastControlSentNanoseconds: UInt64,
        establishedNanoseconds: UInt64,
        rttEstimateMilliseconds: Double
    ) -> ObstacleBridgeMyUDPControlPolicyDecision {
        evaluate(
            nowNanoseconds: nowNanoseconds,
            expectedCounter: expectedCounter,
            missingCount: missingCount,
            lastSentLastInOrder: lastSentLastInOrder,
            lastControlSentNanoseconds: lastControlSentNanoseconds,
            establishedNanoseconds: establishedNanoseconds,
            rttEstimateMilliseconds: rttEstimateMilliseconds,
            clearReason: "timer_paced_clear_miss",
            missingReason: "timer_paced_with_missing",
            requiresEstablishedReference: true
        )
    }

    private static func evaluate(
        nowNanoseconds: UInt64,
        expectedCounter: UInt16,
        missingCount: Int,
        lastSentLastInOrder: UInt16,
        lastControlSentNanoseconds: UInt64,
        establishedNanoseconds: UInt64,
        rttEstimateMilliseconds: Double,
        clearReason: String,
        missingReason: String,
        requiresEstablishedReference: Bool
    ) -> ObstacleBridgeMyUDPControlPolicyDecision {
        let lastInOrder = expectedCounter == 1 ? 0 : expectedCounter &- 1
        let interval = controlIntervalNanoseconds(rttEstimateMilliseconds)
        if missingCount == 0 {
            guard isAhead(lastInOrder, of: lastSentLastInOrder) else { return .init(shouldEmit: false, reason: nil) }
            let reference = lastControlSentNanoseconds != 0 ? lastControlSentNanoseconds : establishedNanoseconds
            guard reference != 0 || !requiresEstablishedReference else { return .init(shouldEmit: false, reason: nil) }
            guard reference == 0 || nowNanoseconds >= reference + interval else { return .init(shouldEmit: false, reason: nil) }
            return .init(shouldEmit: true, reason: clearReason)
        }
        let elapsed = lastControlSentNanoseconds == 0 || nowNanoseconds >= lastControlSentNanoseconds + interval
        return .init(shouldEmit: elapsed, reason: elapsed ? missingReason : nil)
    }

    private static func isAhead(_ value: UInt16, of reference: UInt16) -> Bool {
        guard value != reference else { return false }
        let distance = Int(value) - Int(reference)
        let normalized = distance >= 0 ? distance : distance + Int(UInt16.max)
        return normalized < 32_768
    }
    private static func controlIntervalNanoseconds(_ rttEstimateMilliseconds: Double) -> UInt64 {
        guard rttEstimateMilliseconds > 0 else { return 0 }
        return UInt64(0.5 * rttEstimateMilliseconds * 1_000_000.0)
    }
}

public struct ObstacleBridgeMyUDPRetransmissionPlan: Equatable, Sendable {
    public let emittedCounters: [UInt16]
    public let lastRetransmissionNanoseconds: [UInt16: UInt64]
    public let sendAttempts: [UInt16: Int]
    public let peerReportedMissing: [UInt16]
    public let peerMissedCount: Int
    public let lastSendNanoseconds: UInt64
}

/// Decides which outstanding chunks may be retransmitted. The runtime owner
/// rebuilds a fresh DATA envelope and performs I/O for each emitted counter.
public enum ObstacleBridgeMyUDPRetransmissionPolicy {
    public static func plan(
        nowNanoseconds: UInt64,
        candidateCounters: [UInt16],
        availableCounters: Set<UInt16>,
        firstTransmitNanoseconds: [UInt16: UInt64],
        lastRetransmissionNanoseconds: [UInt16: UInt64],
        sendAttempts: [UInt16: Int],
        peerReportedMissing: [UInt16],
        peerMissedCount: Int,
        lastSendNanoseconds: UInt64,
        windowNanoseconds: UInt64,
        useFirstTransmitWhenNoRetransmission: Bool
    ) -> ObstacleBridgeMyUDPRetransmissionPlan {
        var updatedLastRetransmission = lastRetransmissionNanoseconds
        var updatedAttempts = sendAttempts
        var emitted: [UInt16] = []
        var seen: Set<UInt16> = []
        for counter in candidateCounters where counter != 0 && seen.insert(counter).inserted {
            guard availableCounters.contains(counter) else { continue }
            let lastRetransmission = updatedLastRetransmission[counter] ?? 0
            let firstTransmit = useFirstTransmitWhenNoRetransmission ? (firstTransmitNanoseconds[counter] ?? 0) : 0
            let anchor = lastRetransmission != 0 ? lastRetransmission : firstTransmit
            guard anchor == 0 || (nowNanoseconds >= anchor && nowNanoseconds - anchor >= windowNanoseconds) else { continue }
            emitted.append(counter)
            updatedLastRetransmission[counter] = nowNanoseconds
            updatedAttempts[counter] = (updatedAttempts[counter] ?? 0) + 1
        }
        return .init(
            emittedCounters: emitted,
            lastRetransmissionNanoseconds: updatedLastRetransmission,
            sendAttempts: updatedAttempts,
            peerReportedMissing: Array(Set(peerReportedMissing)).sorted(),
            peerMissedCount: peerMissedCount,
            lastSendNanoseconds: emitted.isEmpty ? lastSendNanoseconds : nowNanoseconds
        )
    }
}

public struct ObstacleBridgeMyUDPOutboundBatch: Equatable, Sendable {
    public let chunks: [ObstacleBridgeMyUDPStreamChunk]
    public let queuedAtNanoseconds: UInt64
    public let waitingRecordCount: Int
}

/// Bounded application-record queue for myUDP DATA batches. It deliberately
/// has no socket dependency: a runtime provides its outstanding count, emits
/// the returned chunks, and records the resulting transport effects.
public final class ObstacleBridgeMyUDPSendQueue: @unchecked Sendable {
    private struct QueuedRecord: Sendable {
        var bytes: Data
        let queuedAtNanoseconds: UInt64
    }

    public let maximumInFlight: Int
    public private(set) var nextCounter: UInt16
    private var records: [QueuedRecord] = []

    public init(nextCounter: UInt16 = 1, maximumInFlight: Int = 200) {
        self.nextCounter = nextCounter == 0 ? 1 : nextCounter
        self.maximumInFlight = max(1, min(32_767, maximumInFlight))
    }

    public var waitingRecordCount: Int { records.count }

    public func reset() {
        records.removeAll()
        nextCounter = 1
    }

    public func enqueue(_ payload: Data, queuedAtNanoseconds: UInt64) throws {
        records.append(.init(bytes: try ObstacleBridgeMyUDPCodec.encodeStreamRecord(payload), queuedAtNanoseconds: queuedAtNanoseconds))
    }

    /// Removes one bounded batch when there is room in the supplied flight
    /// window. `nil` means no queued work or no available counter slot.
    public func dequeueBatch(inFlightCount: Int) -> ObstacleBridgeMyUDPOutboundBatch? {
        let slots = maximumInFlight - max(0, inFlightCount)
        guard slots > 0, !records.isEmpty else { return nil }
        var chunks: [ObstacleBridgeMyUDPStreamChunk] = []
        var consumed: [Int] = []
        var payloadUsed = ObstacleBridgeMyUDPCodec.batchHeaderSize
        var recordIndex = 0
        var recordOffset = 0
        var counter = nextCounter
        while recordIndex < records.count && chunks.count < min(ObstacleBridgeMyUDPCodec.maximumBatchRecords, slots) {
            let budget = ObstacleBridgeMyUDPCodec.maximumBatchPayloadSize - payloadUsed - ObstacleBridgeMyUDPCodec.batchRecordLengthSize - ObstacleBridgeMyUDPCodec.chunkHeaderSize
            guard budget > 0 else { break }
            let record = records[recordIndex].bytes
            guard recordOffset < record.count else { recordIndex += 1; recordOffset = 0; continue }
            let length = min(ObstacleBridgeMyUDPCodec.maximumPayloadSize, budget, record.count - recordOffset)
            guard length > 0 else { break }
            let start = record.index(record.startIndex, offsetBy: recordOffset)
            let end = record.index(start, offsetBy: length)
            let bytes = Data(record[start..<end])
            chunks.append(.init(counter: counter, payload: bytes))
            consumed.append(length)
            payloadUsed += ObstacleBridgeMyUDPCodec.batchRecordLengthSize + ObstacleBridgeMyUDPCodec.chunkHeaderSize + length
            recordOffset += length
            if recordOffset == record.count { recordIndex += 1; recordOffset = 0 }
            counter = increment(counter)
        }
        guard !chunks.isEmpty else { return nil }
        let queuedAt = records[0].queuedAtNanoseconds
        for length in consumed {
            records[0].bytes.removeFirst(length)
            if records[0].bytes.isEmpty { records.removeFirst() }
        }
        nextCounter = counter
        return .init(chunks: chunks, queuedAtNanoseconds: queuedAt, waitingRecordCount: records.count)
    }

    private func increment(_ value: UInt16) -> UInt16 { value == .max ? 1 : value &+ 1 }
}

public struct ObstacleBridgeMyUDPAcknowledgementPlan: Equatable, Sendable {
    public let retainedCounters: [UInt16]
    public let peerReportedMissing: [UInt16]
    public let lastAcknowledgedByPeer: UInt16
}

/// Applies peer CONTROL feedback to outstanding local counters. Metrics and
/// transport-specific cleanup stay with the runtime owner; acknowledgement
/// range and saturation semantics are common protocol state.
public enum ObstacleBridgeMyUDPAcknowledgementPolicy {
    public static func plan(
        outstandingCounters: [UInt16],
        peerReportedMissing: [UInt16],
        lastInOrder: UInt16,
        highestReceived: UInt16,
        missing: [UInt16]
    ) -> ObstacleBridgeMyUDPAcknowledgementPlan {
        guard !(lastInOrder == 0 && highestReceived == 0 && missing.isEmpty) else {
            return .init(retainedCounters: outstandingCounters.sorted(), peerReportedMissing: Array(Set(peerReportedMissing)).sorted(), lastAcknowledgedByPeer: 0)
        }
        var retained = Set(outstandingCounters.filter { $0 != 0 })
        var reported = Set(peerReportedMissing.filter { $0 != 0 })
        let missed = Set(missing.filter { $0 != 0 })
        let acknowledged = retained.filter { ringCompare(lastInOrder, $0) >= 0 }
        retained.subtract(acknowledged)
        reported.subtract(acknowledged)

        let reference = lastInOrder == 0 ? UInt16(1) : lastInOrder
        let upperBound: UInt16
        if missing.count >= ObstacleBridgeMyUDPCodec.maximumControlMissingCount, !missing.isEmpty {
            upperBound = missing.max { forwardDistance($0, from: reference) < forwardDistance($1, from: reference) } ?? lastInOrder
        } else {
            upperBound = highestReceived
        }
        let maximumSpan = forwardDistance(upperBound, from: reference)
        let implicitlyAcknowledged = retained.filter { counter in
            let distance = forwardDistance(counter, from: reference)
            return distance > 0 && distance <= maximumSpan && !missed.contains(counter) && !reported.contains(counter)
        }
        retained.subtract(implicitlyAcknowledged)
        reported.subtract(implicitlyAcknowledged)
        reported = reported.intersection(retained)
        reported.formUnion(missed.intersection(retained))
        return .init(retainedCounters: retained.sorted(), peerReportedMissing: reported.sorted(), lastAcknowledgedByPeer: lastInOrder)
    }

    private static func ringCompare(_ lhs: UInt16, _ rhs: UInt16) -> Int {
        if lhs == rhs { return 0 }
        var delta = ((Int(lhs) - 1) - (Int(rhs) - 1)) % Int(UInt16.max)
        if delta < 0 { delta += Int(UInt16.max) }
        if delta >= 32_768 { delta -= Int(UInt16.max) }
        return delta
    }
    private static func forwardDistance(_ value: UInt16, from reference: UInt16) -> Int {
        var distance = ((Int(value) - 1) - (Int(reference) - 1)) % Int(UInt16.max)
        if distance < 0 { distance += Int(UInt16.max) }
        return distance
    }
}

public struct ObstacleBridgeMyUDPConfirmationMetrics: Equatable, Sendable {
    public let transmitDelaySampleMilliseconds: Double
    public let transmitDelayEstimateMilliseconds: Double
    public let confirmedTotal: Int
    public let firstPassTotal: Int
    public let repeatedOnceTotal: Int
    public let repeatedMultipleTotal: Int
    public init(
        transmitDelaySampleMilliseconds: Double,
        transmitDelayEstimateMilliseconds: Double,
        confirmedTotal: Int,
        firstPassTotal: Int,
        repeatedOnceTotal: Int,
        repeatedMultipleTotal: Int
    ) {
        self.transmitDelaySampleMilliseconds = transmitDelaySampleMilliseconds
        self.transmitDelayEstimateMilliseconds = transmitDelayEstimateMilliseconds
        self.confirmedTotal = confirmedTotal
        self.firstPassTotal = firstPassTotal
        self.repeatedOnceTotal = repeatedOnceTotal
        self.repeatedMultipleTotal = repeatedMultipleTotal
    }
}

/// Finalizes transport metrics for counters cumulatively acknowledged by peer
/// CONTROL feedback. The caller owns payload disposal; its timestamps and
/// attempt ledger are immutable inputs so metrics stay portable and testable.
public enum ObstacleBridgeMyUDPConfirmationMetricsPolicy {
    public static let transmitDelayEwmaAlpha = 0.125

    public static func finalize(
        confirmedCounters: Set<UInt16>,
        pathStartNanoseconds: [UInt16: UInt64],
        firstTransmitNanoseconds: [UInt16: UInt64],
        sendAttempts: [UInt16: Int],
        acknowledgementNanoseconds: UInt64,
        rttEstimateMilliseconds: Double,
        prior: ObstacleBridgeMyUDPConfirmationMetrics
    ) -> ObstacleBridgeMyUDPConfirmationMetrics {
        var sample = prior.transmitDelaySampleMilliseconds
        var estimate = prior.transmitDelayEstimateMilliseconds
        var confirmedTotal = prior.confirmedTotal
        var firstPassTotal = prior.firstPassTotal
        var repeatedOnceTotal = prior.repeatedOnceTotal
        var repeatedMultipleTotal = prior.repeatedMultipleTotal

        for counter in confirmedCounters.filter({ $0 != 0 }).sorted() {
            confirmedTotal += 1
            switch max(1, sendAttempts[counter] ?? 1) {
            case 1: firstPassTotal += 1
            case 2: repeatedOnceTotal += 1
            default: repeatedMultipleTotal += 1
            }

            let pathStart = pathStartNanoseconds[counter] ?? firstTransmitNanoseconds[counter] ?? 0
            guard pathStart > 0, acknowledgementNanoseconds > pathStart else { continue }
            let elapsed = Double(acknowledgementNanoseconds - pathStart) / 1_000_000.0
            sample = max(0, elapsed - (rttEstimateMilliseconds > 0 ? 0.5 * rttEstimateMilliseconds : 0))
            if estimate <= 0 {
                estimate = sample
            } else if estimate < sample {
                estimate = sample
            } else {
                estimate = ((1 - transmitDelayEwmaAlpha) * estimate) + (transmitDelayEwmaAlpha * sample)
            }
        }
        return .init(
            transmitDelaySampleMilliseconds: sample,
            transmitDelayEstimateMilliseconds: estimate,
            confirmedTotal: confirmedTotal,
            firstPassTotal: firstPassTotal,
            repeatedOnceTotal: repeatedOnceTotal,
            repeatedMultipleTotal: repeatedMultipleTotal
        )
    }

    public static func rebaseTransmitDelayEstimate(
        outstandingCount: Int,
        rttEstimateMilliseconds: Double,
        priorEstimateMilliseconds: Double
    ) -> Double {
        outstandingCount == 0 && rttEstimateMilliseconds > 0 ? 0.5 * rttEstimateMilliseconds : priorEstimateMilliseconds
    }
}

public struct ObstacleBridgeMyUDPHeartbeatSnapshot: Equatable, Sendable {
    public let establishedNanoseconds: UInt64
    public let lastReceivedTransmitNanoseconds: UInt64
    public let lastReceivedWallNanoseconds: UInt64
    public let lastRTTOkNanoseconds: UInt64
    public let rttSampleMilliseconds: Double
    public let rttEstimateMilliseconds: Double
    public let transmitDelayEstimateMilliseconds: Double
    public init(
        establishedNanoseconds: UInt64,
        lastReceivedTransmitNanoseconds: UInt64,
        lastReceivedWallNanoseconds: UInt64,
        lastRTTOkNanoseconds: UInt64,
        rttSampleMilliseconds: Double,
        rttEstimateMilliseconds: Double,
        transmitDelayEstimateMilliseconds: Double
    ) {
        self.establishedNanoseconds = establishedNanoseconds
        self.lastReceivedTransmitNanoseconds = lastReceivedTransmitNanoseconds
        self.lastReceivedWallNanoseconds = lastReceivedWallNanoseconds
        self.lastRTTOkNanoseconds = lastRTTOkNanoseconds
        self.rttSampleMilliseconds = rttSampleMilliseconds
        self.rttEstimateMilliseconds = rttEstimateMilliseconds
        self.transmitDelayEstimateMilliseconds = transmitDelayEstimateMilliseconds
    }
}

public enum ObstacleBridgeMyUDPHeartbeatPolicy {
    public static let connectedLossNanoseconds: UInt64 = 20_000_000_000
    public static func update(nowNanoseconds: UInt64, transmittedNanoseconds: UInt64, echoedNanoseconds: UInt64, fromIdle: Bool, prior: ObstacleBridgeMyUDPHeartbeatSnapshot) -> ObstacleBridgeMyUDPHeartbeatSnapshot {
        guard echoedNanoseconds != 0, nowNanoseconds >= echoedNanoseconds else {
            return .init(establishedNanoseconds: prior.establishedNanoseconds, lastReceivedTransmitNanoseconds: transmittedNanoseconds, lastReceivedWallNanoseconds: nowNanoseconds, lastRTTOkNanoseconds: prior.lastRTTOkNanoseconds, rttSampleMilliseconds: prior.rttSampleMilliseconds, rttEstimateMilliseconds: prior.rttEstimateMilliseconds, transmitDelayEstimateMilliseconds: prior.transmitDelayEstimateMilliseconds)
        }
        let sample = Double(nowNanoseconds - echoedNanoseconds) / 1_000_000.0
        let estimate = prior.rttEstimateMilliseconds < sample ? sample : (0.875 * prior.rttEstimateMilliseconds + 0.125 * sample)
        return .init(establishedNanoseconds: prior.establishedNanoseconds == 0 ? nowNanoseconds : prior.establishedNanoseconds, lastReceivedTransmitNanoseconds: transmittedNanoseconds, lastReceivedWallNanoseconds: nowNanoseconds, lastRTTOkNanoseconds: nowNanoseconds, rttSampleMilliseconds: sample, rttEstimateMilliseconds: estimate, transmitDelayEstimateMilliseconds: fromIdle && estimate > 0 ? 0.5 * estimate : prior.transmitDelayEstimateMilliseconds)
    }
    public static func isConnected(nowNanoseconds: UInt64, lastRTTOkNanoseconds: UInt64) -> Bool {
        lastRTTOkNanoseconds != 0 && nowNanoseconds >= lastRTTOkNanoseconds && nowNanoseconds - lastRTTOkNanoseconds <= connectedLossNanoseconds
    }
}

/// Calculates the echoed peer timestamp carried by every outbound myUDP
/// envelope. Runtime owners retain only the last received timestamp pair.
public enum ObstacleBridgeMyUDPEchoPolicy {
    public static func echoedNanoseconds(
        nowNanoseconds: UInt64,
        lastReceivedTransmitNanoseconds: UInt64,
        lastReceivedWallNanoseconds: UInt64
    ) -> UInt64 {
        guard lastReceivedTransmitNanoseconds != 0,
              lastReceivedWallNanoseconds != 0,
              nowNanoseconds >= lastReceivedWallNanoseconds else { return 0 }
        return lastReceivedTransmitNanoseconds &+ (nowNanoseconds - lastReceivedWallNanoseconds)
    }
}

/// A non-echoed IDLE is a probe and receives one reflection when the transport
/// is writable. An echoed IDLE only updates heartbeat state.
public enum ObstacleBridgeMyUDPIdlePolicy {
    public static func shouldReflect(echoedNanoseconds: UInt64, transportWritable: Bool) -> Bool {
        echoedNanoseconds == 0 && transportWritable
    }
}

/// Ordered myUDP stream reassembly shared by datagram runtime owners. It owns
/// counter-ring ordering, duplicate suppression, missing-counter discovery,
/// and four-byte application-record buffering; adapters only submit chunks and
/// deliver completed records.
public final class ObstacleBridgeMyUDPStreamReceiveState: @unchecked Sendable {
    public private(set) var expected: UInt16 = 1
    public private(set) var pending: [UInt16: ObstacleBridgeMyUDPStreamChunk] = [:]
    public private(set) var missing: Set<UInt16> = []
    private var pendingHighest: UInt16?
    private var streamBuffer = Data()
    private var expectedRecordLength: Int?

    public init() {}

    public func reset() {
        expected = 1; pending.removeAll(); missing.removeAll(); pendingHighest = nil
        streamBuffer.removeAll(); expectedRecordLength = nil
    }

    public func process(_ chunk: ObstacleBridgeMyUDPStreamChunk) -> (accepted: Bool, completedRecords: [Data])? {
        guard chunk.counter != 0 else { return nil }
        let comparison = ringCompare(chunk.counter, expected)
        if comparison < 0 { return (false, []) }
        if comparison > 0 { enqueue(chunk); return (false, []) }

        var completed: [Data] = []
        guard appendContiguous(chunk.payload, completed: &completed) else { return nil }
        expected = increment(expected)
        while let next = pending.removeValue(forKey: expected) {
            missing.remove(expected)
            guard appendContiguous(next.payload, completed: &completed) else { return nil }
            expected = increment(expected)
        }
        if pending.isEmpty { pendingHighest = nil; missing.removeAll() } else { identifyMissing() }
        return (true, completed)
    }

    /// Receiver feedback derived from the same counter-ring state that orders
    /// application records. Transport adapters only put this value on the
    /// wire; they do not reconstruct ACK or missing-counter policy.
    public var acknowledgement: ObstacleBridgeMyUDPAcknowledgement {
        let last = expected == 1 ? 0 : decrement(expected)
        let reference = last == 0 ? UInt16(1) : last
        let candidates = pending.keys + (last == 0 ? [] : [last])
        let highest = candidates.max { forwardDistance($0, from: reference) < forwardDistance($1, from: reference) } ?? 0
        let missingCounters = missing
            .filter { counter in highest != 0 && forwardDistance(counter, from: reference) <= forwardDistance(highest, from: reference) }
            .sorted { forwardDistance($0, from: reference) < forwardDistance($1, from: reference) }
        return .init(
            lastInOrder: last,
            highestReceived: highest,
            missing: Array(missingCounters.prefix(ObstacleBridgeMyUDPCodec.maximumControlMissingCount))
        )
    }

    private func enqueue(_ chunk: ObstacleBridgeMyUDPStreamChunk) {
        guard pending[chunk.counter] == nil else { return }
        pending[chunk.counter] = chunk
        if pendingHighest == nil || ringCompare(chunk.counter, pendingHighest ?? chunk.counter) > 0 {
            let gapStart = pendingHighest.map(increment) ?? expected
            for value in counterRange(gapStart, chunk.counter) where pending[value] == nil { missing.insert(value) }
            pendingHighest = chunk.counter
        }
        missing.remove(chunk.counter)
    }

    private func appendContiguous(_ bytes: Data, completed: inout [Data]) -> Bool {
        streamBuffer.append(bytes)
        while true {
            if expectedRecordLength == nil {
                guard streamBuffer.count >= ObstacleBridgeMyUDPCodec.streamRecordHeaderSize else { return true }
                let header = Data(streamBuffer.prefix(ObstacleBridgeMyUDPCodec.streamRecordHeaderSize))
                guard let length = try? ObstacleBridgeMyUDPCodec.decodeStreamRecordLength(header) else {
                    streamBuffer.removeAll(); return false
                }
                streamBuffer.removeFirst(ObstacleBridgeMyUDPCodec.streamRecordHeaderSize)
                expectedRecordLength = length
            }
            guard let length = expectedRecordLength, streamBuffer.count >= length else { return true }
            completed.append(Data(streamBuffer.prefix(length)))
            streamBuffer.removeFirst(length); expectedRecordLength = nil
        }
    }

    private func identifyMissing() {
        missing.removeAll(); pendingHighest = nil
        guard let highest = highestRing(Array(pending.keys), reference: expected) else { return }
        pendingHighest = highest
        for value in counterRange(expected, highest) where pending[value] == nil { missing.insert(value) }
    }

    private func ringCompare(_ lhs: UInt16, _ rhs: UInt16) -> Int {
        if lhs == rhs { return 0 }
        let distance = forwardDistance(lhs, from: rhs)
        return distance < 32_768 ? 1 : -1
    }
    private func increment(_ value: UInt16) -> UInt16 { value == .max ? 1 : value &+ 1 }
    private func decrement(_ value: UInt16) -> UInt16 { value == 1 ? .max : value &- 1 }
    private func forwardDistance(_ value: UInt16, from reference: UInt16) -> Int {
        let distance = Int(value) - Int(reference)
        return distance >= 0 ? distance : distance + Int(UInt16.max)
    }
    private func counterRange(_ start: UInt16, _ end: UInt16) -> [UInt16] {
        guard start != end else { return [] }
        var result: [UInt16] = [], cursor = start
        while cursor != end { result.append(cursor); cursor = increment(cursor) }
        return result
    }
    private func highestRing(_ values: [UInt16], reference: UInt16) -> UInt16? {
        values.max { (Int($0) - Int(reference) + 65_536) & 0xffff < (Int($1) - Int(reference) + 65_536) & 0xffff }
    }
}

public struct ObstacleBridgeMyUDPInboundDataResult: Equatable, Sendable {
    public let completedRecords: [Data]
    public let acknowledgement: ObstacleBridgeMyUDPAcknowledgement
    public let controlReasons: [String]
    public let heartbeat: ObstacleBridgeMyUDPHeartbeatSnapshot
}

public struct ObstacleBridgeMyUDPInboundIdleResult: Equatable, Sendable {
    public let shouldReflect: Bool
    public let heartbeat: ObstacleBridgeMyUDPHeartbeatSnapshot
}

/// Peer-scoped receive-side myUDP runtime. It composes ordered stream state,
/// RTT/liveness, and CONTROL pacing. Socket owners submit decoded chunks and
/// execute the resulting delivery and outbound-control effects.
public final class ObstacleBridgeMyUDPReceiverEngine: @unchecked Sendable {
    public private(set) var receiveState = ObstacleBridgeMyUDPStreamReceiveState()
    public private(set) var heartbeat: ObstacleBridgeMyUDPHeartbeatSnapshot
    public private(set) var lastSentLastInOrder: UInt16
    public private(set) var lastControlSentNanoseconds: UInt64

    public init(
        heartbeat: ObstacleBridgeMyUDPHeartbeatSnapshot = .init(
            establishedNanoseconds: 0, lastReceivedTransmitNanoseconds: 0,
            lastReceivedWallNanoseconds: 0, lastRTTOkNanoseconds: 0,
            rttSampleMilliseconds: 0, rttEstimateMilliseconds: 0,
            transmitDelayEstimateMilliseconds: 0
        ),
        lastSentLastInOrder: UInt16 = 0,
        lastControlSentNanoseconds: UInt64 = 0
    ) {
        self.heartbeat = heartbeat
        self.lastSentLastInOrder = lastSentLastInOrder
        self.lastControlSentNanoseconds = lastControlSentNanoseconds
    }

    public func reset() {
        receiveState.reset()
        heartbeat = .init(establishedNanoseconds: 0, lastReceivedTransmitNanoseconds: 0,
                          lastReceivedWallNanoseconds: 0, lastRTTOkNanoseconds: 0,
                          rttSampleMilliseconds: 0, rttEstimateMilliseconds: 0,
                          transmitDelayEstimateMilliseconds: 0)
        lastSentLastInOrder = 0
        lastControlSentNanoseconds = 0
    }

    public func processData(
        chunks: [ObstacleBridgeMyUDPStreamChunk],
        nowNanoseconds: UInt64,
        transmittedNanoseconds: UInt64,
        echoedNanoseconds: UInt64,
        transportWritable: Bool
    ) -> ObstacleBridgeMyUDPInboundDataResult? {
        heartbeat = ObstacleBridgeMyUDPHeartbeatPolicy.update(
            nowNanoseconds: nowNanoseconds, transmittedNanoseconds: transmittedNanoseconds,
            echoedNanoseconds: echoedNanoseconds, fromIdle: false, prior: heartbeat
        )
        let priorMissing = receiveState.missing
        var records: [Data] = []
        var gapFilled = false
        for chunk in chunks {
            if priorMissing.contains(chunk.counter) { gapFilled = true }
            guard let result = receiveState.process(chunk) else {
                receiveState.reset()
                return nil
            }
            records.append(contentsOf: result.completedRecords)
        }
        var reasons: [String] = []
        if gapFilled && transportWritable { reasons.append("gap_filled_ack") }
        let grewMissing = !receiveState.missing.subtracting(priorMissing).isEmpty
        let decision = ObstacleBridgeMyUDPControlPolicy.inbound(
            nowNanoseconds: nowNanoseconds, expectedCounter: receiveState.expected,
            missingCount: receiveState.missing.count, grewMissing: grewMissing,
            lastSentLastInOrder: lastSentLastInOrder,
            lastControlSentNanoseconds: lastControlSentNanoseconds,
            establishedNanoseconds: heartbeat.establishedNanoseconds,
            rttEstimateMilliseconds: heartbeat.rttEstimateMilliseconds
        )
        if transportWritable, decision.shouldEmit, let reason = decision.reason { reasons.append(reason) }
        return .init(completedRecords: records, acknowledgement: receiveState.acknowledgement,
                     controlReasons: reasons, heartbeat: heartbeat)
    }

    public func processIdle(
        nowNanoseconds: UInt64,
        transmittedNanoseconds: UInt64,
        echoedNanoseconds: UInt64,
        transportWritable: Bool
    ) -> ObstacleBridgeMyUDPInboundIdleResult {
        heartbeat = ObstacleBridgeMyUDPHeartbeatPolicy.update(
            nowNanoseconds: nowNanoseconds, transmittedNanoseconds: transmittedNanoseconds,
            echoedNanoseconds: echoedNanoseconds, fromIdle: true, prior: heartbeat
        )
        return .init(
            shouldReflect: ObstacleBridgeMyUDPIdlePolicy.shouldReflect(
                echoedNanoseconds: echoedNanoseconds, transportWritable: transportWritable
            ),
            heartbeat: heartbeat
        )
    }

    public func updateHeartbeat(
        nowNanoseconds: UInt64,
        transmittedNanoseconds: UInt64,
        echoedNanoseconds: UInt64,
        fromIdle: Bool
    ) {
        heartbeat = ObstacleBridgeMyUDPHeartbeatPolicy.update(
            nowNanoseconds: nowNanoseconds, transmittedNanoseconds: transmittedNanoseconds,
            echoedNanoseconds: echoedNanoseconds, fromIdle: fromIdle, prior: heartbeat
        )
    }

    public func replaceHeartbeat(_ heartbeat: ObstacleBridgeMyUDPHeartbeatSnapshot) {
        self.heartbeat = heartbeat
    }

    public func controlTimer(nowNanoseconds: UInt64, transportWritable: Bool) -> ObstacleBridgeMyUDPControlPolicyDecision {
        let decision = ObstacleBridgeMyUDPControlPolicy.timer(
            nowNanoseconds: nowNanoseconds, expectedCounter: receiveState.expected,
            missingCount: receiveState.missing.count, lastSentLastInOrder: lastSentLastInOrder,
            lastControlSentNanoseconds: lastControlSentNanoseconds,
            establishedNanoseconds: heartbeat.establishedNanoseconds,
            rttEstimateMilliseconds: heartbeat.rttEstimateMilliseconds
        )
        if transportWritable, decision.shouldEmit { noteControlSent(nowNanoseconds: nowNanoseconds) }
        return transportWritable ? decision : .init(shouldEmit: false, reason: nil)
    }

    public func noteControlSent(nowNanoseconds: UInt64) {
        lastControlSentNanoseconds = nowNanoseconds
        lastSentLastInOrder = receiveState.expected == 1 ? 0 : receiveState.expected &- 1
    }

    public func updateControlTracking(lastSentLastInOrder: UInt16, lastControlSentNanoseconds: UInt64) {
        self.lastSentLastInOrder = lastSentLastInOrder
        self.lastControlSentNanoseconds = lastControlSentNanoseconds
    }

    public func buildControlDatagram(nowNanoseconds: UInt64) throws -> Data {
        let acknowledgement = receiveState.acknowledgement
        defer { noteControlSent(nowNanoseconds: nowNanoseconds) }
        return try ObstacleBridgeMyUDPCodec.encodeControl(
            lastInOrder: acknowledgement.lastInOrder, highestReceived: acknowledgement.highestReceived,
            missing: acknowledgement.missing, transmittedNanoseconds: nowNanoseconds,
            echoedNanoseconds: ObstacleBridgeMyUDPEchoPolicy.echoedNanoseconds(
                nowNanoseconds: nowNanoseconds,
                lastReceivedTransmitNanoseconds: heartbeat.lastReceivedTransmitNanoseconds,
                lastReceivedWallNanoseconds: heartbeat.lastReceivedWallNanoseconds
            )
        )
    }
}

/// Socket-independent myUDP peer state. Adapters submit application records,
/// wire frames, timer ticks, and epoch resets; they only execute emitted wire
/// effects and deliver completed records.
public final class ObstacleBridgeMyUDPPeerEngine: @unchecked Sendable {
    /// Default portable cadence used when an adapter services timer effects.
    public static let defaultRetransmissionWindowNanoseconds: UInt64 = 250_000_000
    public static let defaultIdleIntervalNanoseconds: UInt64 = 1_000_000_000
    public struct Metrics: Equatable, Sendable {
        public let outstandingCount: Int
        public let queuedRecordCount: Int
        public let peerMissingCount: Int
        public let rttEstimateMilliseconds: Double
        public let connected: Bool
    }
    public struct Effect: Equatable, Sendable {
        public let outboundDatagrams: [Data]
        /// Counters assigned to DATA chunks emitted by this transition, in
        /// wire order. Adapters use this only for compatibility-facing
        /// reporting and never allocate or interpret counters themselves.
        public let outboundDataCounters: [UInt16]
        public let deliveredRecords: [Data]
        public let nextControlDeadlineNanoseconds: UInt64?
    }

    private let sender: ObstacleBridgeMyUDPSendQueue
    private let receiver = ObstacleBridgeMyUDPReceiverEngine()
    private var outstanding: [UInt16: ObstacleBridgeMyUDPStreamChunk] = [:]
    private var peerMissing: [UInt16] = []
    private var firstTransmitNanoseconds: [UInt16: UInt64] = [:]
    private var lastRetransmissionNanoseconds: [UInt16: UInt64] = [:]
    private var sendAttempts: [UInt16: Int] = [:]
    private var lastIdleSentNanoseconds: UInt64 = 0
    private var pendingDeliveredRecords: [Data] = []

    public init(maximumInFlight: Int = 200) { sender = .init(maximumInFlight: maximumInFlight) }

    public func resetEpoch() { sender.reset(); receiver.reset(); outstanding.removeAll(); peerMissing.removeAll(); firstTransmitNanoseconds.removeAll(); lastRetransmissionNanoseconds.removeAll(); sendAttempts.removeAll(); lastIdleSentNanoseconds = 0; pendingDeliveredRecords.removeAll() }
    public func takeDeliveredRecord() -> Data? { pendingDeliveredRecords.isEmpty ? nil : pendingDeliveredRecords.removeFirst() }

    public func enqueueApplicationRecord(_ record: Data, nowNanoseconds: UInt64) throws {
        try sender.enqueue(record, queuedAtNanoseconds: nowNanoseconds)
    }

    public func metrics(nowNanoseconds: UInt64) -> Metrics {
        .init(outstandingCount: outstanding.count, queuedRecordCount: sender.waitingRecordCount, peerMissingCount: peerMissing.count, rttEstimateMilliseconds: receiver.heartbeat.rttEstimateMilliseconds, connected: ObstacleBridgeMyUDPHeartbeatPolicy.isConnected(nowNanoseconds: nowNanoseconds, lastRTTOkNanoseconds: receiver.heartbeat.lastRTTOkNanoseconds))
    }

    public func flush(nowNanoseconds: UInt64) throws -> Effect {
        guard let batch = sender.dequeueBatch(inFlightCount: outstanding.count) else { return .init(outboundDatagrams: [], outboundDataCounters: [], deliveredRecords: [], nextControlDeadlineNanoseconds: nil) }
        for chunk in batch.chunks { outstanding[chunk.counter] = chunk; firstTransmitNanoseconds[chunk.counter] = nowNanoseconds; sendAttempts[chunk.counter] = 1 }
        let echo = ObstacleBridgeMyUDPEchoPolicy.echoedNanoseconds(nowNanoseconds: nowNanoseconds, lastReceivedTransmitNanoseconds: receiver.heartbeat.lastReceivedTransmitNanoseconds, lastReceivedWallNanoseconds: receiver.heartbeat.lastReceivedWallNanoseconds)
        return .init(outboundDatagrams: [try ObstacleBridgeMyUDPCodec.encodeData(chunks: batch.chunks, transmittedNanoseconds: nowNanoseconds, echoedNanoseconds: echo)], outboundDataCounters: batch.chunks.map(\.counter), deliveredRecords: [], nextControlDeadlineNanoseconds: nil)
    }

    public func tick(nowNanoseconds: UInt64, retransmissionWindowNanoseconds: UInt64 = defaultRetransmissionWindowNanoseconds, idleIntervalNanoseconds: UInt64 = defaultIdleIntervalNanoseconds) throws -> Effect {
        let idleDeadline = nowNanoseconds.addingReportingOverflow(idleIntervalNanoseconds).overflow ? UInt64.max : nowNanoseconds + idleIntervalNanoseconds
        let plan = ObstacleBridgeMyUDPRetransmissionPolicy.plan(nowNanoseconds: nowNanoseconds, candidateCounters: peerMissing, availableCounters: Set(outstanding.keys), firstTransmitNanoseconds: firstTransmitNanoseconds, lastRetransmissionNanoseconds: lastRetransmissionNanoseconds, sendAttempts: sendAttempts, peerReportedMissing: peerMissing, peerMissedCount: peerMissing.count, lastSendNanoseconds: 0, windowNanoseconds: retransmissionWindowNanoseconds, useFirstTransmitWhenNoRetransmission: true)
        lastRetransmissionNanoseconds = plan.lastRetransmissionNanoseconds; sendAttempts = plan.sendAttempts; peerMissing = plan.peerReportedMissing
        let chunks = plan.emittedCounters.compactMap { outstanding[$0] }
        let echo = ObstacleBridgeMyUDPEchoPolicy.echoedNanoseconds(nowNanoseconds: nowNanoseconds, lastReceivedTransmitNanoseconds: receiver.heartbeat.lastReceivedTransmitNanoseconds, lastReceivedWallNanoseconds: receiver.heartbeat.lastReceivedWallNanoseconds)
        var datagrams: [Data] = []
        if receiver.controlTimer(nowNanoseconds: nowNanoseconds, transportWritable: true).shouldEmit { datagrams.append(try receiver.buildControlDatagram(nowNanoseconds: nowNanoseconds)) }
        if chunks.isEmpty, idleIntervalNanoseconds != .max, (lastIdleSentNanoseconds == 0 || (nowNanoseconds >= lastIdleSentNanoseconds && nowNanoseconds - lastIdleSentNanoseconds >= idleIntervalNanoseconds)) {
            datagrams.append(try ObstacleBridgeMyUDPCodec.encodeWire(type: ObstacleBridgeMyUDPCodec.idleType, payload: Data(), transmittedNanoseconds: nowNanoseconds, echoedNanoseconds: echo))
            lastIdleSentNanoseconds = nowNanoseconds
        }
        guard !chunks.isEmpty else { return .init(outboundDatagrams: datagrams, outboundDataCounters: [], deliveredRecords: [], nextControlDeadlineNanoseconds: idleDeadline) }
        datagrams.append(try ObstacleBridgeMyUDPCodec.encodeData(chunks: chunks, transmittedNanoseconds: nowNanoseconds, echoedNanoseconds: echo))
        return .init(outboundDatagrams: datagrams, outboundDataCounters: plan.emittedCounters, deliveredRecords: [], nextControlDeadlineNanoseconds: idleDeadline)
    }

    public func receiveWire(_ wire: Data, nowNanoseconds: UInt64, transportWritable: Bool = true) throws -> Effect {
        let frame = try ObstacleBridgeMyUDPCodec.decodeWire(wire)
        switch frame.type {
        case ObstacleBridgeMyUDPCodec.dataType:
            let data = try ObstacleBridgeMyUDPCodec.decodeDataChunks(wire)
            guard let inbound = receiver.processData(chunks: data.chunks, nowNanoseconds: nowNanoseconds, transmittedNanoseconds: data.transmittedNanoseconds, echoedNanoseconds: data.echoedNanoseconds, transportWritable: transportWritable) else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
            pendingDeliveredRecords.append(contentsOf: inbound.completedRecords)
            let control = inbound.controlReasons.isEmpty ? [] : [try receiver.buildControlDatagram(nowNanoseconds: nowNanoseconds)]
            return .init(outboundDatagrams: control, outboundDataCounters: [], deliveredRecords: inbound.completedRecords, nextControlDeadlineNanoseconds: nil)
        case ObstacleBridgeMyUDPCodec.controlType:
            let control = try ObstacleBridgeMyUDPCodec.decodeControl(wire)
            peerMissing = control.missing
            let plan = ObstacleBridgeMyUDPAcknowledgementPolicy.plan(outstandingCounters: Array(outstanding.keys), peerReportedMissing: peerMissing, lastInOrder: control.lastInOrder, highestReceived: control.highestReceived, missing: control.missing)
            outstanding = outstanding.filter { plan.retainedCounters.contains($0.key) }
            peerMissing = plan.peerReportedMissing
            return .init(outboundDatagrams: [], outboundDataCounters: [], deliveredRecords: [], nextControlDeadlineNanoseconds: nil)
        case ObstacleBridgeMyUDPCodec.idleType:
            let idle = receiver.processIdle(nowNanoseconds: nowNanoseconds, transmittedNanoseconds: frame.transmittedNanoseconds, echoedNanoseconds: frame.echoedNanoseconds, transportWritable: transportWritable)
            let reply = idle.shouldReflect ? [try ObstacleBridgeMyUDPCodec.encodeWire(type: ObstacleBridgeMyUDPCodec.idleType, payload: Data(), transmittedNanoseconds: nowNanoseconds, echoedNanoseconds: frame.transmittedNanoseconds)] : []
            return .init(outboundDatagrams: reply, outboundDataCounters: [], deliveredRecords: [], nextControlDeadlineNanoseconds: nil)
        default: throw ObstacleBridgeMyUDPCodecError.invalidFrame
        }
    }
}

/// Socket-independent owner for listener-side myUDP peer state. Datagram
/// adapters choose the peer identity and execute effects; this registry keeps
/// epochs, queues, and receive state isolated from one another.
public final class ObstacleBridgeMyUDPPeerRegistry: @unchecked Sendable {
    public struct PeerKey: Hashable, Sendable { public let identity: String; public let epoch: UInt64; public init(identity: String, epoch: UInt64) { self.identity = identity; self.epoch = epoch } }
    private var peers: [PeerKey: ObstacleBridgeMyUDPPeerEngine] = [:]
    private var lastActivityNanoseconds: [PeerKey: UInt64] = [:]
    public init() {}
    public func admit(_ key: PeerKey, maximumInFlight: Int = 200) -> ObstacleBridgeMyUDPPeerEngine { if let peer = peers[key] { return peer }; let peer = ObstacleBridgeMyUDPPeerEngine(maximumInFlight: maximumInFlight); peers[key] = peer; return peer }
    public func touch(_ key: PeerKey, nowNanoseconds: UInt64) { guard peers[key] != nil else { return }; lastActivityNanoseconds[key] = nowNanoseconds }
    public func receiveWire(_ wire: Data, from key: PeerKey, nowNanoseconds: UInt64, maximumInFlight: Int = 200, transportWritable: Bool = true) throws -> ObstacleBridgeMyUDPPeerEngine.Effect {
        let peer = admit(key, maximumInFlight: maximumInFlight)
        touch(key, nowNanoseconds: nowNanoseconds)
        return try peer.receiveWire(wire, nowNanoseconds: nowNanoseconds, transportWritable: transportWritable)
    }
    public func tick(_ key: PeerKey, nowNanoseconds: UInt64, retransmissionWindowNanoseconds: UInt64 = ObstacleBridgeMyUDPPeerEngine.defaultRetransmissionWindowNanoseconds, idleIntervalNanoseconds: UInt64 = ObstacleBridgeMyUDPPeerEngine.defaultIdleIntervalNanoseconds) throws -> ObstacleBridgeMyUDPPeerEngine.Effect? {
        guard let peer = peers[key] else { return nil }
        return try peer.tick(nowNanoseconds: nowNanoseconds, retransmissionWindowNanoseconds: retransmissionWindowNanoseconds, idleIntervalNanoseconds: idleIntervalNanoseconds)
    }
    public func expire(nowNanoseconds: UInt64, idleTimeoutNanoseconds: UInt64) -> [PeerKey] { let expired = peers.keys.filter { key in guard let last = lastActivityNanoseconds[key], nowNanoseconds >= last else { return false }; return nowNanoseconds - last >= idleTimeoutNanoseconds }; expired.forEach(withdraw); return expired }
    public func withdraw(_ key: PeerKey) { peers.removeValue(forKey: key); lastActivityNanoseconds.removeValue(forKey: key) }
    public func withdraw(identity: String, exceptEpoch: UInt64? = nil) { peers.keys.filter { $0.identity == identity && $0.epoch != exceptEpoch }.forEach(withdraw) }
    public var activeKeys: Set<PeerKey> { Set(peers.keys) }
}

/// myudp v2 framing shared with Python. DATA batches carry a reliable byte
/// stream; upper-layer messages are length-prefixed records in that stream.
public enum ObstacleBridgeMyUDPCodec {
    public static let protocolHeaderSize = 19
    public static let streamRecordHeaderSize = 4
    public static let maximumStreamRecordSize = Int(UInt16.max)
    public static let batchHeaderSize = 2
    public static let batchRecordLengthSize = 2
    public static let chunkHeaderSize = 4
    public static let maximumBatchRecords = 64
    public static let maximumPayloadSize = 1425
    public static let maximumBatchPayloadSize = 1433
    public static let controlFixedPayloadSize = 6
    /// CONTROL's missing-counter list is bounded by the myudp wire payload,
    /// not the DATA_BATCH record-count limit.
    public static let maximumControlMissingCount = (maximumBatchPayloadSize - controlFixedPayloadSize) / 2
    public static let dataType: UInt8 = 1
    public static let controlType: UInt8 = 2
    public static let idleType: UInt8 = 0

    public static func encodeStreamRecord(_ payload: Data) throws -> Data {
        guard payload.count <= maximumStreamRecordSize else { throw ObstacleBridgeMyUDPCodecError.payloadTooLarge }
        var writer = ObstacleBridgeBinaryWriter(capacity: payload.count + streamRecordHeaderSize)
        writer.append(UInt32(payload.count)); writer.append(payload)
        return writer.encoded
    }

    public static func decodeStreamRecordLength(_ header: Data) throws -> Int {
        do {
            var reader = ObstacleBridgeBinaryReader(header)
            let length = Int(try reader.readUInt32())
            guard reader.isAtEnd, length <= maximumStreamRecordSize else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
            return length
        } catch { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
    }

    public static func encodeData(payload: Data, counter: UInt16, transmittedNanoseconds: UInt64, echoedNanoseconds: UInt64 = 0) throws -> Data {
        try encodeData(chunks: [.init(counter: counter, payload: payload)], transmittedNanoseconds: transmittedNanoseconds, echoedNanoseconds: echoedNanoseconds)
    }

    public static func encodeData(chunks: [ObstacleBridgeMyUDPStreamChunk], transmittedNanoseconds: UInt64, echoedNanoseconds: UInt64 = 0) throws -> Data {
        try encodeWire(type: dataType, payload: encodeDataBatchPayload(chunks), transmittedNanoseconds: transmittedNanoseconds, echoedNanoseconds: echoedNanoseconds)
    }

    public static func encodeDataBatchPayload(_ chunks: [ObstacleBridgeMyUDPStreamChunk]) throws -> Data {
        guard !chunks.isEmpty, chunks.count <= maximumBatchRecords else { throw ObstacleBridgeMyUDPCodecError.payloadTooLarge }
        var batch = ObstacleBridgeBinaryWriter(capacity: maximumBatchPayloadSize)
        batch.append(UInt8(1)); batch.append(UInt8(chunks.count))
        for chunk in chunks {
            guard chunk.counter != 0, !chunk.payload.isEmpty, chunk.payload.count <= maximumPayloadSize else { throw ObstacleBridgeMyUDPCodecError.payloadTooLarge }
            batch.append(UInt16(chunk.payload.count + 4)); batch.append(chunk.counter)
            batch.append(UInt16(chunk.payload.count)); batch.append(chunk.payload)
        }
        guard batch.encoded.count <= maximumBatchPayloadSize else { throw ObstacleBridgeMyUDPCodecError.payloadTooLarge }
        return batch.encoded
    }

    public static func encodeControl(lastInOrder: UInt16, highestReceived: UInt16, missing: [UInt16] = [], transmittedNanoseconds: UInt64, echoedNanoseconds: UInt64 = 0) throws -> Data {
        guard missing.count <= maximumControlMissingCount else { throw ObstacleBridgeMyUDPCodecError.payloadTooLarge }
        var payload = ObstacleBridgeBinaryWriter(capacity: controlFixedPayloadSize + missing.count * 2)
        payload.append(lastInOrder); payload.append(highestReceived); payload.append(UInt16(missing.count))
        for counter in missing { payload.append(counter) }
        return try encodeWire(type: controlType, payload: payload.encoded, transmittedNanoseconds: transmittedNanoseconds, echoedNanoseconds: echoedNanoseconds)
    }

    public static func decodeControl(_ wire: Data) throws -> ObstacleBridgeMyUDPControlFrame {
        do {
            let frame = try decodeWire(wire)
            guard frame.type == controlType else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
            var reader = ObstacleBridgeBinaryReader(frame.payload)
            let lastInOrder = try reader.readUInt16()
            let highestReceived = try reader.readUInt16()
            let count = Int(try reader.readUInt16())
            guard count <= maximumControlMissingCount else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
            let missing = try (0..<count).map { _ in try reader.readUInt16() }
            guard reader.isAtEnd else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
            return .init(lastInOrder: lastInOrder, highestReceived: highestReceived, missing: missing, transmittedNanoseconds: frame.transmittedNanoseconds, echoedNanoseconds: frame.echoedNanoseconds)
        } catch { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
    }

    public static func decodeWire(_ wire: Data) throws -> ObstacleBridgeMyUDPWireFrame {
        do {
            var reader = ObstacleBridgeBinaryReader(wire)
            let type = try reader.readUInt8(), bodyLength = Int(try reader.readUInt16())
            let transmittedNanoseconds = try reader.readUInt64(), echoedNanoseconds = try reader.readUInt64()
            let payload = try reader.readData(count: bodyLength)
            guard reader.isAtEnd else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
            return .init(type: type, payload: payload, transmittedNanoseconds: transmittedNanoseconds, echoedNanoseconds: echoedNanoseconds)
        } catch { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
    }

    public static func decodeDataChunks(_ wire: Data) throws -> (chunks: [ObstacleBridgeMyUDPStreamChunk], transmittedNanoseconds: UInt64, echoedNanoseconds: UInt64) {
        let frame = try decodeWire(wire)
        guard frame.type == dataType else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
        return (try decodeDataBatchPayload(frame.payload), frame.transmittedNanoseconds, frame.echoedNanoseconds)
    }

    public static func decodeDataBatchPayload(_ payload: Data) throws -> [ObstacleBridgeMyUDPStreamChunk] {
        guard payload.count >= 2, payload[0] == 1 else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
        let count = Int(payload[1])
        guard count > 0, count <= maximumBatchRecords else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
        var reader = ObstacleBridgeBinaryReader(Data(payload.dropFirst(2)))
        var chunks: [ObstacleBridgeMyUDPStreamChunk] = []
        for _ in 0..<count {
            do {
                let recordLength = Int(try reader.readUInt16())
                guard recordLength >= 5 else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
                let counter = try reader.readUInt16(), payloadLength = Int(try reader.readUInt16())
                guard counter != 0, payloadLength > 0, payloadLength <= maximumPayloadSize, recordLength == payloadLength + 4 else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
                chunks.append(.init(counter: counter, payload: try reader.readData(count: payloadLength)))
            } catch { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
        }
        guard reader.isAtEnd else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
        return chunks
    }

    /// Compatibility helper for callers that deliberately use a single DATA
    /// record. Production transport code uses `decodeDataChunks`.
    public static func decodeData(_ wire: Data) throws -> ObstacleBridgeMyUDPDataFrame {
        let decoded = try decodeDataChunks(wire)
        guard decoded.chunks.count == 1 else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
        let chunk = decoded.chunks[0]
        return .init(counter: chunk.counter, payload: chunk.payload, transmittedNanoseconds: decoded.transmittedNanoseconds, echoedNanoseconds: decoded.echoedNanoseconds)
    }

    public static func encodeWire(type: UInt8, payload: Data, transmittedNanoseconds: UInt64, echoedNanoseconds: UInt64) throws -> Data {
        guard payload.count <= maximumBatchPayloadSize else { throw ObstacleBridgeMyUDPCodecError.payloadTooLarge }
        var writer = ObstacleBridgeBinaryWriter(capacity: protocolHeaderSize + payload.count)
        writer.append(type); writer.append(UInt16(payload.count)); writer.append(transmittedNanoseconds); writer.append(echoedNanoseconds); writer.append(payload)
        return writer.encoded
    }
}
