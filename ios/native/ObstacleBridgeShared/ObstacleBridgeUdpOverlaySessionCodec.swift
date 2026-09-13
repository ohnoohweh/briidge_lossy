import Foundation

struct ObstacleBridgeUdpOverlaySessionCodec {
    struct OutgoingChunk {
        var data: Data
    }

    final class StreamReceiveState {
        private let core = ObstacleBridgeMyUDPStreamReceiveState()
        private(set) var expected = 1
        private(set) var pending: [Int: ObstacleBridgeUdpOverlayCodec.StreamChunk] = [:]
        private(set) var missing: Set<Int> = []

        func reset() {
            core.reset()
            expected = 1
            pending.removeAll()
            missing.removeAll()
        }

        func process(_ chunk: ObstacleBridgeUdpOverlayCodec.StreamChunk) -> (Bool, [Data])? {
            guard (1...Int(UInt16.max)).contains(chunk.counter) else { return nil }
            guard let result = core.process(.init(counter: UInt16(chunk.counter), payload: chunk.data)) else { return nil }
            expected = Int(core.expected)
            pending = Dictionary(uniqueKeysWithValues: core.pending.map {
                (Int($0.key), .init(counter: Int($0.value.counter), data: $0.value.payload))
            })
            missing = Set(core.missing.map(Int.init))
            return (result.accepted, result.completedRecords)
        }
    }

    struct RetransmitSnapshot {
        var emittedCounters: [Int]
        var emittedFrames: [Data]
        var lastRetxNS: [Int: UInt64]
        var sendAttempts: [Int: Int]
        var peerReportedMissing: [Int]
        var peerMissedCount: Int
        var lastSendNS: UInt64
    }

    struct InboundControlHandlingSnapshot {
        var feedback: ControlStateSnapshot
        var retransmit: RetransmitSnapshot
        var flushRequested: Bool
        var controlDecision: ControlPolicyDecision
    }

    struct InboundIdleHandlingSnapshot {
        var reflectedFrame: Data?
        var reflected: Bool
        var establishedNS: UInt64
        var lastRxTxNS: UInt64
        var lastRxWallNS: UInt64
        var rttSampleMS: Double
        var rttEstMS: Double
        var transmitDelayEstMS: Double
    }

    struct InboundDataHandlingSnapshot {
        var controlReasons: [String]
        var completedPayloads: [Data]
        var expected: Int
        var pending: [Int]
        var missing: [Int]
        var establishedNS: UInt64
        var lastRxTxNS: UInt64
        var lastRxWallNS: UInt64
        var rttSampleMS: Double
        var rttEstMS: Double
        var transmitDelayEstMS: Double
    }

    struct ControlPolicyDecision {
        var shouldEmit: Bool
        var reason: String?
    }

    struct ControlStateSnapshot {
        var sendBufferKeys: [Int]
        var peerReportedMissing: [Int]
        var lastAckPeer: Int
    }

    static func buildControl(
        expected: Int,
        pendingKeys: [Int],
        missing: [Int],
        txNS: UInt64,
        echoNS: UInt64 = 0
    ) throws -> ObstacleBridgeUdpOverlayCodec.ControlPacket {
        let lastInOrder = lastInOrderFromExpected(expected)
        let highestRX = computeHighestRX(lastInOrder: lastInOrder, pendingKeys: pendingKeys)
        let filteredMissed: [Int]
        if highestRX == 0 {
            filteredMissed = []
        } else {
            filteredMissed = missing.filter { value in
                value != 0 && ringCmp(highestRX, value) >= 0
            }
        }
        let missedSorted = sortMissedForControl(Set(filteredMissed), ref: lastInOrder)
        let raw = try ObstacleBridgeUdpOverlayCodec.buildControlFrame(
            lastInOrderRX: lastInOrder,
            highestRX: highestRX,
            missed: missedSorted,
            txNS: txNS,
            echoNS: echoNS
        )
        guard let parsed = ObstacleBridgeUdpOverlayCodec.parseControlFrame(raw) else {
            throw ObstacleBridgeUdpOverlayCodecError.invalidField
        }
        return parsed
    }

    static func confirmFeedback(
        sendBufferKeys: [Int],
        peerReportedMissing: [Int],
        lastInOrder: Int,
        highest: Int,
        missed: [Int]
    ) -> ControlStateSnapshot {
        guard let lastInOrder = UInt16(exactly: lastInOrder), let highest = UInt16(exactly: highest) else {
            return .init(sendBufferKeys: [], peerReportedMissing: [], lastAckPeer: 0)
        }
        let plan = ObstacleBridgeMyUDPAcknowledgementPolicy.plan(
            outstandingCounters: sendBufferKeys.compactMap(UInt16.init(exactly:)),
            peerReportedMissing: peerReportedMissing.compactMap(UInt16.init(exactly:)),
            lastInOrder: lastInOrder,
            highestReceived: highest,
            missing: missed.compactMap(UInt16.init(exactly:))
        )
        return .init(
            sendBufferKeys: plan.retainedCounters.map(Int.init),
            peerReportedMissing: plan.peerReportedMissing.map(Int.init),
            lastAckPeer: Int(plan.lastAcknowledgedByPeer)
        )
    }

    static func evaluateInboundControlPolicy(
        nowNS: UInt64,
        expected: Int,
        missingCount: Int,
        grewMissing: Bool,
        lastSentLastInOrder: Int,
        lastControlSentNS: UInt64,
        establishedNS: UInt64,
        rttEstMS: Double
    ) -> ControlPolicyDecision {
        guard let expected = UInt16(exactly: expected), let lastSent = UInt16(exactly: lastSentLastInOrder) else {
            return ControlPolicyDecision(shouldEmit: false, reason: nil)
        }
        let decision = ObstacleBridgeMyUDPControlPolicy.inbound(
            nowNanoseconds: nowNS, expectedCounter: expected, missingCount: missingCount,
            grewMissing: grewMissing, lastSentLastInOrder: lastSent,
            lastControlSentNanoseconds: lastControlSentNS, establishedNanoseconds: establishedNS,
            rttEstimateMilliseconds: rttEstMS
        )
        return .init(shouldEmit: decision.shouldEmit, reason: decision.reason)
    }

    static func evaluateTimerControlPolicy(
        nowNS: UInt64,
        expected: Int,
        missingCount: Int,
        lastSentLastInOrder: Int,
        lastControlSentNS: UInt64,
        establishedNS: UInt64,
        rttEstMS: Double
    ) -> ControlPolicyDecision {
        guard let expected = UInt16(exactly: expected), let lastSent = UInt16(exactly: lastSentLastInOrder) else {
            return ControlPolicyDecision(shouldEmit: false, reason: nil)
        }
        let decision = ObstacleBridgeMyUDPControlPolicy.timer(
            nowNanoseconds: nowNS, expectedCounter: expected, missingCount: missingCount,
            lastSentLastInOrder: lastSent, lastControlSentNanoseconds: lastControlSentNS,
            establishedNanoseconds: establishedNS, rttEstimateMilliseconds: rttEstMS
        )
        return .init(shouldEmit: decision.shouldEmit, reason: decision.reason)
    }

    static func scheduleRetransmitDueToControl(
        nowNS: UInt64,
        missed: [Int],
        rttEstMS: Double,
        sendBufferKeys: [Int],
        sendMeta: [Int: OutgoingChunk],
        sendTXNS: [Int: UInt64],
        lastRetxNS: [Int: UInt64],
        sendAttempts: [Int: Int],
        peerReportedMissing: [Int],
        lastSendNS: UInt64,
        lastRxTxNS: UInt64,
        lastRxWallNS: UInt64
    ) throws -> RetransmitSnapshot {
        return try retransmitCounters(
            nowNS: nowNS,
            counters: missed,
            reasonPeerMissedCount: missed.count,
            windowNS: retransWindowNS(rttEstMS: rttEstMS, multiplier: 1.0),
            useFirstTXWhenNoRetx: false,
            sendBufferKeys: sendBufferKeys,
            sendMeta: sendMeta,
            sendTXNS: sendTXNS,
            lastRetxNS: lastRetxNS,
            sendAttempts: sendAttempts,
            peerReportedMissing: peerReportedMissing,
            lastSendNS: lastSendNS,
            lastRxTxNS: lastRxTxNS,
            lastRxWallNS: lastRxWallNS
        )
    }

    static func sweepReportedMissingRetransmit(
        nowNS: UInt64,
        rttEstMS: Double,
        sendBufferKeys: [Int],
        sendMeta: [Int: OutgoingChunk],
        sendTXNS: [Int: UInt64],
        lastRetxNS: [Int: UInt64],
        sendAttempts: [Int: Int],
        peerReportedMissing: [Int],
        peerMissedCount: Int,
        lastSendNS: UInt64,
        lastRxTxNS: UInt64,
        lastRxWallNS: UInt64
    ) throws -> RetransmitSnapshot {
        let sendBuf = Set(sendBufferKeys)
        let filteredMissing = peerReportedMissing.filter { counter in
            counter != 0 && sendBuf.contains(counter)
        }.sorted()
        return try retransmitCounters(
            nowNS: nowNS,
            counters: filteredMissing,
            reasonPeerMissedCount: peerMissedCount,
            windowNS: retransWindowNS(rttEstMS: rttEstMS, multiplier: 1.0),
            useFirstTXWhenNoRetx: true,
            sendBufferKeys: sendBufferKeys,
            sendMeta: sendMeta,
            sendTXNS: sendTXNS,
            lastRetxNS: lastRetxNS,
            sendAttempts: sendAttempts,
            peerReportedMissing: filteredMissing,
            lastSendNS: lastSendNS,
            lastRxTxNS: lastRxTxNS,
            lastRxWallNS: lastRxWallNS
        )
    }

    static func sweepUnconfirmedRetransmit(
        nowNS: UInt64,
        rttEstMS: Double,
        sendBufferKeys: [Int],
        sendMeta: [Int: OutgoingChunk],
        sendTXNS: [Int: UInt64],
        lastRetxNS: [Int: UInt64],
        sendAttempts: [Int: Int],
        peerReportedMissing: [Int],
        peerMissedCount: Int,
        lastSendNS: UInt64,
        lastRxTxNS: UInt64,
        lastRxWallNS: UInt64
    ) throws -> RetransmitSnapshot {
        let counters = sendBufferKeys.filter { $0 != 0 }.sorted()
        return try retransmitCounters(
            nowNS: nowNS,
            counters: counters,
            reasonPeerMissedCount: peerMissedCount,
            windowNS: retransWindowNS(rttEstMS: rttEstMS, multiplier: 1.5),
            useFirstTXWhenNoRetx: true,
            sendBufferKeys: sendBufferKeys,
            sendMeta: sendMeta,
            sendTXNS: sendTXNS,
            lastRetxNS: lastRetxNS,
            sendAttempts: sendAttempts,
            peerReportedMissing: peerReportedMissing,
            lastSendNS: lastSendNS,
            lastRxTxNS: lastRxTxNS,
            lastRxWallNS: lastRxWallNS
        )
    }

    static func handleInboundControlPacket(
        nowNS: UInt64,
        packetLastInOrder: Int,
        packetHighest: Int,
        packetMissed: [Int],
        sendPortPresent: Bool,
        sendBufferKeys: [Int],
        peerReportedMissing: [Int],
        sendMeta: [Int: OutgoingChunk],
        sendTXNS: [Int: UInt64],
        lastRetxNS: [Int: UInt64],
        sendAttempts: [Int: Int],
        lastSendNS: UInt64,
        lastRxTxNS: UInt64,
        lastRxWallNS: UInt64,
        receiverExpected: Int,
        receiverMissingCount: Int,
        lastSentLastInOrder: Int,
        lastControlSentNS: UInt64,
        establishedNS: UInt64,
        rttEstMS: Double
    ) throws -> InboundControlHandlingSnapshot {
        let feedback = confirmFeedback(
            sendBufferKeys: sendBufferKeys,
            peerReportedMissing: peerReportedMissing,
            lastInOrder: packetLastInOrder,
            highest: packetHighest,
            missed: packetMissed
        )

        let retransmit: RetransmitSnapshot
        if sendPortPresent {
            retransmit = try scheduleRetransmitDueToControl(
                nowNS: nowNS,
                missed: packetMissed,
                rttEstMS: rttEstMS,
                sendBufferKeys: feedback.sendBufferKeys,
                sendMeta: sendMeta,
                sendTXNS: sendTXNS,
                lastRetxNS: lastRetxNS,
                sendAttempts: sendAttempts,
                peerReportedMissing: feedback.peerReportedMissing,
                lastSendNS: lastSendNS,
                lastRxTxNS: lastRxTxNS,
                lastRxWallNS: lastRxWallNS
            )
        } else {
            retransmit = RetransmitSnapshot(
                emittedCounters: [],
                emittedFrames: [],
                lastRetxNS: lastRetxNS,
                sendAttempts: sendAttempts,
                peerReportedMissing: feedback.peerReportedMissing,
                peerMissedCount: packetMissed.count,
                lastSendNS: lastSendNS
            )
        }

        let controlDecision = evaluateInboundControlPolicy(
            nowNS: nowNS,
            expected: receiverExpected,
            missingCount: receiverMissingCount,
            grewMissing: false,
            lastSentLastInOrder: lastSentLastInOrder,
            lastControlSentNS: lastControlSentNS,
            establishedNS: establishedNS,
            rttEstMS: rttEstMS
        )

        return InboundControlHandlingSnapshot(
            feedback: feedback,
            retransmit: retransmit,
            flushRequested: sendPortPresent,
            controlDecision: controlDecision
        )
    }

    static func handleInboundIdleFrame(
        nowNS: UInt64,
        txNS: UInt64,
        echoNS: UInt64,
        sendPortPresent: Bool,
        establishedNS: UInt64,
        priorRTTEstMS: Double,
        priorTransmitDelayEstMS: Double
    ) throws -> InboundIdleHandlingSnapshot {
        let lastRxTxNS = txNS
        let lastRxWallNS = nowNS

        var rttSampleMS: Double = 0
        var rttEstMS = priorRTTEstMS
        var transmitDelayEstMS = priorTransmitDelayEstMS
        var nextEstablishedNS = establishedNS

        if echoNS != 0 {
            let sample = Double(nowNS - echoNS) / 1_000_000.0
            rttSampleMS = sample
            if rttEstMS < sample {
                rttEstMS = sample
            } else {
                rttEstMS = (1.0 - 0.125) * rttEstMS + (0.125 * sample)
            }
            if rttEstMS > 0 {
                transmitDelayEstMS = 0.5 * rttEstMS
            }
            if nextEstablishedNS == 0 {
                nextEstablishedNS = nowNS
            }
        }

        let reflected = ObstacleBridgeMyUDPIdlePolicy.shouldReflect(
            echoedNanoseconds: echoNS,
            transportWritable: sendPortPresent
        )
        let reflectedFrame: Data?
        if reflected {
            reflectedFrame = try ObstacleBridgeUdpOverlayCodec.buildProtocolFrame(
                ptype: ObstacleBridgeUdpOverlayCodec.ptypeIdle,
                payload: Data(),
                txNS: nowNS,
                echoNS: txNS
            )
        } else {
            reflectedFrame = nil
        }

        return InboundIdleHandlingSnapshot(
            reflectedFrame: reflectedFrame,
            reflected: reflected,
            establishedNS: nextEstablishedNS,
            lastRxTxNS: lastRxTxNS,
            lastRxWallNS: lastRxWallNS,
            rttSampleMS: rttSampleMS,
            rttEstMS: rttEstMS,
            transmitDelayEstMS: transmitDelayEstMS
        )
    }

    private static func ringCmp(_ a: Int, _ b: Int) -> Int {
        if a == b {
            return 0
        }
        let ar = a - 1
        let br = b - 1
        var delta = (ar - br) % 65535
        if delta < 0 {
            delta += 65535
        }
        if delta >= 32768 {
            delta -= 65535
        }
        return delta
    }

    private static func c16Inc(_ value: Int) -> Int {
        return value == 65535 ? 1 : value + 1
    }

    private static func c16Dec(_ value: Int) -> Int {
        return value == 1 ? 65535 : value - 1
    }

    private static func lastInOrderFromExpected(_ expected: Int) -> Int {
        return expected == 1 ? 0 : c16Dec(expected)
    }

    private static func retransWindowNS(rttEstMS: Double, multiplier: Double) -> UInt64 {
        let window = rttEstMS * 1_000_000.0 * multiplier
        return max(1, UInt64(window))
    }

    private static func retransmitCounters(
        nowNS: UInt64,
        counters: [Int],
        reasonPeerMissedCount: Int,
        windowNS: UInt64,
        useFirstTXWhenNoRetx: Bool,
        sendBufferKeys: [Int],
        sendMeta: [Int: OutgoingChunk],
        sendTXNS: [Int: UInt64],
        lastRetxNS: [Int: UInt64],
        sendAttempts: [Int: Int],
        peerReportedMissing: [Int],
        lastSendNS: UInt64,
        lastRxTxNS: UInt64,
        lastRxWallNS: UInt64
    ) throws -> RetransmitSnapshot {
        let candidates = counters.compactMap(UInt16.init(exactly:))
        let available = Set(sendBufferKeys.compactMap(UInt16.init(exactly:)))
        let firstTransmit = Dictionary(uniqueKeysWithValues: sendTXNS.compactMap { key, value in
            UInt16(exactly: key).map { ($0, value) }
        })
        let retransmissions = Dictionary(uniqueKeysWithValues: lastRetxNS.compactMap { key, value in
            UInt16(exactly: key).map { ($0, value) }
        })
        let attempts = Dictionary(uniqueKeysWithValues: sendAttempts.compactMap { key, value in
            UInt16(exactly: key).map { ($0, value) }
        })
        let reportedMissing = peerReportedMissing.compactMap(UInt16.init(exactly:))
        let plan = ObstacleBridgeMyUDPRetransmissionPolicy.plan(
            nowNanoseconds: nowNS,
            candidateCounters: candidates,
            availableCounters: available,
            firstTransmitNanoseconds: firstTransmit,
            lastRetransmissionNanoseconds: retransmissions,
            sendAttempts: attempts,
            peerReportedMissing: reportedMissing,
            peerMissedCount: reasonPeerMissedCount,
            lastSendNanoseconds: lastSendNS,
            windowNanoseconds: windowNS,
            useFirstTransmitWhenNoRetransmission: useFirstTXWhenNoRetx
        )
        var emittedFrames: [Data] = []
        for coreCounter in plan.emittedCounters {
            let counter = Int(coreCounter)
            guard let meta = sendMeta[counter] else { continue }
            let echoNS = ObstacleBridgeMyUDPEchoPolicy.echoedNanoseconds(
                nowNanoseconds: nowNS,
                lastReceivedTransmitNanoseconds: lastRxTxNS,
                lastReceivedWallNanoseconds: lastRxWallNS
            )
            let frame = try ObstacleBridgeUdpOverlayCodec.buildDataBatchFrame(
                chunks: [.init(counter: counter, data: meta.data)],
                txNS: nowNS,
                echoNS: echoNS
            )
            emittedFrames.append(frame)
        }

        return RetransmitSnapshot(
            emittedCounters: plan.emittedCounters.map(Int.init),
            emittedFrames: emittedFrames,
            lastRetxNS: Dictionary(uniqueKeysWithValues: plan.lastRetransmissionNanoseconds.map { (Int($0.key), $0.value) }),
            sendAttempts: Dictionary(uniqueKeysWithValues: plan.sendAttempts.map { (Int($0.key), $0.value) }),
            peerReportedMissing: plan.peerReportedMissing.map(Int.init),
            peerMissedCount: plan.peerMissedCount,
            lastSendNS: plan.lastSendNanoseconds
        )
    }

    private static func computeHighestRX(lastInOrder: Int, pendingKeys: [Int]) -> Int {
        var candidates: [Int] = []
        if lastInOrder != 0 {
            candidates.append(lastInOrder)
        }
        candidates.append(contentsOf: pendingKeys.filter { $0 != 0 })
        guard !candidates.isEmpty else {
            return 0
        }
        return highestRing(candidates, ref: lastInOrder != 0 ? lastInOrder : 1) ?? 0
    }

    private static func sortMissedForControl(_ missed: Set<Int>, ref: Int) -> [Int] {
        let filtered = missed.filter { $0 != 0 }
        guard !filtered.isEmpty else {
            return []
        }
        return filtered.sorted { ringCmp($0, ref) < ringCmp($1, ref) }
            .prefix(ObstacleBridgeUdpOverlayCodec.controlMaxMissed())
            .map { $0 }
    }

    private static func c16Range(_ startInclusive: Int, _ endExclusive: Int) -> [Int] {
        var result: [Int] = []
        var value = startInclusive
        while value != endExclusive {
            result.append(value)
            value = c16Inc(value)
        }
        return result
    }

    private static func highestRing(_ keys: [Int], ref: Int) -> Int? {
        guard !keys.isEmpty else {
            return nil
        }
        func orderKey(_ value: Int) -> Int {
            let ar = value - 1
            let br = ref - 1
            var delta = (ar - br) % 65535
            if delta < 0 {
                delta += 65535
            }
            return delta
        }
        return keys.max(by: { orderKey($0) < orderKey($1) })
    }

    private static func aheadDistance(_ value: Int, _ ref: Int) -> Int {
        let ar = value - 1
        let br = ref - 1
        var delta = (ar - br) % 65535
        if delta < 0 {
            delta += 65535
        }
        return delta
    }
}
