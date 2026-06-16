import Foundation

struct ObstacleBridgeUdpOverlaySessionCodec {
    struct OutgoingSegment {
        var frameType: Int
        var lenOrOffset: Int
        var data: Data
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

    struct Reassembly {
        var totalLength: Int
        var buffer: Data
        var marks: [Bool]
        var filled: Int

        init(totalLength: Int) {
            self.totalLength = totalLength
            self.buffer = Data(repeating: 0, count: totalLength)
            self.marks = Array(repeating: false, count: totalLength)
            self.filled = 0
        }

        mutating func apply(offset: Int, data: Data) {
            let end = offset + data.count
            guard offset >= 0, end <= totalLength else {
                return
            }
            buffer.replaceSubrange(offset..<end, with: data)
            for index in offset..<end where !marks[index] {
                marks[index] = true
                filled += 1
            }
        }

        func complete() -> Bool {
            return filled >= totalLength
        }
    }

    final class ReceiveState {
        private(set) var expected = 1
        private(set) var pending: [Int: ObstacleBridgeUdpOverlayCodec.DataPacket] = [:]
        private(set) var missing: Set<Int> = []
        private var pendingHighest: Int?
        private(set) var reassembly: Reassembly?

        func process(_ packet: ObstacleBridgeUdpOverlayCodec.DataPacket) -> (Bool, [Data]) {
            if packet.pktCounter == 0 {
                return (false, [])
            }
            var advanced = false
            var completed: [Data] = []
            let counter = packet.pktCounter
            let comparison = ringCmp(counter, expected)

            if comparison < 0 {
                return (advanced, completed)
            }
            if comparison == 0 {
                advanced = true
                expected = c16Inc(expected)
            } else {
                enqueueOutOfOrder(packet, counter: counter)
                return (advanced, completed)
            }

            apply(packet, counter: counter, completed: &completed)

            if advanced {
                while let next = pending.removeValue(forKey: expected) {
                    missing.remove(expected)
                    let counter = expected
                    expected = c16Inc(expected)
                    apply(next, counter: counter, completed: &completed)
                }
                if pending.isEmpty {
                    pendingHighest = nil
                    missing.removeAll()
                } else {
                    identifyMissing()
                }
            }
            return (advanced, completed)
        }

        private func enqueueOutOfOrder(
            _ packet: ObstacleBridgeUdpOverlayCodec.DataPacket,
            counter: Int
        ) {
            let alreadyPending = pending[counter] != nil
            pending[counter] = packet
            guard !alreadyPending else {
                return
            }
            if missing.contains(counter) {
                missing.remove(counter)
            } else {
                var gapStart = expected
                if let highest = pendingHighest, ringCmp(counter, highest) > 0 {
                    gapStart = c16Inc(highest)
                }
                if pendingHighest == nil || ringCmp(counter, pendingHighest ?? counter) > 0 {
                    for value in c16Range(gapStart, counter) where pending[value] == nil {
                        missing.insert(value)
                    }
                }
                missing.remove(counter)
            }
            if pendingHighest == nil || ringCmp(counter, pendingHighest ?? counter) > 0 {
                pendingHighest = counter
            }
        }

        private func apply(
            _ packet: ObstacleBridgeUdpOverlayCodec.DataPacket,
            counter: Int,
            completed: inout [Data]
        ) {
            if packet.frameType == 1 {
                if reassembly == nil {
                    let total = packet.lenOrOffset
                    if total > 0 && total <= 0xFFFF {
                        reassembly = Reassembly(totalLength: total)
                    }
                }
                if reassembly != nil {
                    reassembly?.apply(offset: 0, data: packet.data)
                }
            } else if reassembly != nil {
                reassembly?.apply(offset: packet.lenOrOffset, data: packet.data)
            }

            if let current = reassembly, current.complete() {
                completed.append(current.buffer)
                reassembly = nil
            }
        }

        private func identifyMissing() {
            let pendingKeys = pending.keys.filter { $0 != 0 }
            missing.removeAll()
            pendingHighest = nil
            guard !pendingKeys.isEmpty else {
                return
            }
            if let highest = highestRing(Array(pendingKeys), ref: expected) {
                pendingHighest = highest
                for value in c16Range(expected, highest) where pending[value] == nil {
                    missing.insert(value)
                }
            }
        }
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
        if lastInOrder == 0 && highest == 0 && missed.isEmpty {
            return ControlStateSnapshot(
                sendBufferKeys: sendBufferKeys.sorted(),
                peerReportedMissing: Array(Set(peerReportedMissing)).sorted(),
                lastAckPeer: 0
            )
        }

        var sendBuf = Set(sendBufferKeys)
        var reportedMissing = Set(peerReportedMissing)
        let missedSet = Set(missed)
        let listAtCapacity = missed.count >= ObstacleBridgeUdpOverlayCodec.controlMaxMissed()

        let toDelete = sendBuf.filter { counter in
            ringCmp(lastInOrder, counter) >= 0
        }
        sendBuf.subtract(toDelete)
        reportedMissing.subtract(toDelete)

        let ref = lastInOrder != 0 ? lastInOrder : 1
        let upperBound: Int
        if listAtCapacity && !missed.isEmpty {
            upperBound = highestRing(missed, ref: ref) ?? lastInOrder
        } else {
            upperBound = highest
        }
        let maxSpan = aheadDistance(upperBound, ref)
        let toDeleteWithinSpan = sendBuf.filter { counter in
            let distance = aheadDistance(counter, ref)
            return distance > 0 && distance <= maxSpan && !missedSet.contains(counter) && !reportedMissing.contains(counter)
        }
        sendBuf.subtract(toDeleteWithinSpan)
        reportedMissing.subtract(toDeleteWithinSpan)

        reportedMissing = reportedMissing.intersection(sendBuf)
        for counter in missedSet where counter != 0 && sendBuf.contains(counter) {
            reportedMissing.insert(counter)
        }

        return ControlStateSnapshot(
            sendBufferKeys: sendBuf.sorted(),
            peerReportedMissing: reportedMissing.sorted(),
            lastAckPeer: lastInOrder
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
        let lastInOrder = lastInOrderFromExpected(expected)
        if grewMissing {
            return ControlPolicyDecision(shouldEmit: true, reason: "inbound_grew_missing")
        }
        if missingCount == 0 {
            if ringCmp(lastInOrder, lastSentLastInOrder) > 0 {
                let ref = lastControlSentNS != 0 ? lastControlSentNS : establishedNS
                let interval = controlIntervalNS(rttEstMS: rttEstMS)
                let elapsed = ref != 0 ? nowNS >= ref + interval : true
                if elapsed {
                    return ControlPolicyDecision(shouldEmit: true, reason: "advanced_in_order")
                }
            }
            return ControlPolicyDecision(shouldEmit: false, reason: nil)
        }
        let interval = controlIntervalNS(rttEstMS: rttEstMS)
        let elapsed = lastControlSentNS != 0 ? nowNS >= lastControlSentNS + interval : true
        if elapsed {
            return ControlPolicyDecision(shouldEmit: true, reason: "paced_with_missing")
        }
        return ControlPolicyDecision(shouldEmit: false, reason: nil)
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
        let lastInOrder = lastInOrderFromExpected(expected)
        if missingCount == 0 {
            if ringCmp(lastInOrder, lastSentLastInOrder) > 0 {
                let ref = lastControlSentNS != 0 ? lastControlSentNS : establishedNS
                let interval = controlIntervalNS(rttEstMS: rttEstMS)
                if ref != 0 && nowNS >= ref + interval {
                    return ControlPolicyDecision(shouldEmit: true, reason: "timer_paced_clear_miss")
                }
            }
            return ControlPolicyDecision(shouldEmit: false, reason: nil)
        }
        let interval = controlIntervalNS(rttEstMS: rttEstMS)
        let elapsed = lastControlSentNS != 0 ? nowNS >= lastControlSentNS + interval : true
        if elapsed {
            return ControlPolicyDecision(shouldEmit: true, reason: "timer_paced_with_missing")
        }
        return ControlPolicyDecision(shouldEmit: false, reason: nil)
    }

    static func scheduleRetransmitDueToControl(
        nowNS: UInt64,
        missed: [Int],
        rttEstMS: Double,
        sendBufferKeys: [Int],
        sendMeta: [Int: OutgoingSegment],
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
        sendMeta: [Int: OutgoingSegment],
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
        sendMeta: [Int: OutgoingSegment],
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
        sendMeta: [Int: OutgoingSegment],
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

        let reflected = echoNS == 0 && sendPortPresent
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

    static func handleInboundDataFrames(
        preFrames: [Data],
        frame: Data,
        nowNS: UInt64,
        txNS: UInt64,
        echoNS: UInt64,
        sendPortPresent: Bool,
        establishedNS: UInt64,
        lastSentLastInOrder: Int,
        lastControlSentNS: UInt64,
        priorRTTEstMS: Double,
        priorTransmitDelayEstMS: Double
    ) -> InboundDataHandlingSnapshot? {
        let state = ReceiveState()
        for raw in preFrames {
            guard let packet = ObstacleBridgeUdpOverlayCodec.parseDataFrame(raw) else {
                return nil
            }
            _ = state.process(packet)
        }
        guard let packet = ObstacleBridgeUdpOverlayCodec.parseDataFrame(frame) else {
            return nil
        }

        var nextEstablishedNS = establishedNS
        let lastRxTxNS = txNS
        let lastRxWallNS = nowNS
        var rttSampleMS: Double = 0
        var rttEstMS = priorRTTEstMS
        let transmitDelayEstMS = priorTransmitDelayEstMS

        if echoNS != 0 {
            let sample = Double(nowNS - echoNS) / 1_000_000.0
            rttSampleMS = sample
            if rttEstMS < sample {
                rttEstMS = sample
            } else {
                rttEstMS = (1.0 - 0.125) * rttEstMS + (0.125 * sample)
            }
            if nextEstablishedNS == 0 {
                nextEstablishedNS = nowNS
            }
        }

        let previousMissing = state.missing
        let result = state.process(packet)
        var controlReasons: [String] = []
        if previousMissing.contains(packet.pktCounter) && !state.missing.contains(packet.pktCounter) && sendPortPresent {
            controlReasons.append("gap_filled_ack")
        }
        let grewMissing = !state.missing.subtracting(previousMissing).isEmpty
        let controlDecision = evaluateInboundControlPolicy(
            nowNS: nowNS,
            expected: state.expected,
            missingCount: state.missing.count,
            grewMissing: grewMissing,
            lastSentLastInOrder: lastSentLastInOrder,
            lastControlSentNS: lastControlSentNS,
            establishedNS: nextEstablishedNS,
            rttEstMS: rttEstMS
        )
        if sendPortPresent, let reason = controlDecision.reason, controlDecision.shouldEmit {
            controlReasons.append(reason)
        }

        return InboundDataHandlingSnapshot(
            controlReasons: controlReasons,
            completedPayloads: result.1,
            expected: state.expected,
            pending: state.pending.keys.sorted(),
            missing: Array(state.missing).sorted(),
            establishedNS: nextEstablishedNS,
            lastRxTxNS: lastRxTxNS,
            lastRxWallNS: lastRxWallNS,
            rttSampleMS: rttSampleMS,
            rttEstMS: rttEstMS,
            transmitDelayEstMS: transmitDelayEstMS
        )
    }

    static func segmentApplicationPayload(
        _ data: Data,
        txNS: UInt64,
        echoNS: UInt64 = 0,
        startingCounter: Int = 1
    ) throws -> [Data] {
        guard !data.isEmpty, data.count <= 0xFFFF else {
            return []
        }
        var frames: [Data] = []
        var counter = startingCounter
        let firstChunk = data.prefix(ObstacleBridgeUdpOverlayCodec.dataMaxChunk())
        frames.append(
            try ObstacleBridgeUdpOverlayCodec.buildDataFrame(
                pktCounter: counter,
                frameType: 1,
                lenOrOffset: data.count,
                data: Data(firstChunk),
                txNS: txNS,
                echoNS: echoNS
            )
        )
        counter = c16Inc(counter)

        var offset = firstChunk.count
        while offset < data.count {
            let end = min(offset + ObstacleBridgeUdpOverlayCodec.dataMaxChunk(), data.count)
            let chunk = data.subdata(in: offset..<end)
            frames.append(
                try ObstacleBridgeUdpOverlayCodec.buildDataFrame(
                    pktCounter: counter,
                    frameType: 2,
                    lenOrOffset: offset,
                    data: chunk,
                    txNS: txNS,
                    echoNS: echoNS
                )
            )
            counter = c16Inc(counter)
            offset = end
        }
        return frames
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

    private static func controlIntervalNS(rttEstMS: Double) -> UInt64 {
        let seconds = 0.5 * (rttEstMS / 1000.0)
        if seconds <= 0 {
            return 0
        }
        return UInt64(seconds * 1_000_000_000.0)
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
        sendMeta: [Int: OutgoingSegment],
        sendTXNS: [Int: UInt64],
        lastRetxNS: [Int: UInt64],
        sendAttempts: [Int: Int],
        peerReportedMissing: [Int],
        lastSendNS: UInt64,
        lastRxTxNS: UInt64,
        lastRxWallNS: UInt64
    ) throws -> RetransmitSnapshot {
        let sendBuf = Set(sendBufferKeys)
        var updatedLastRetxNS = lastRetxNS
        var updatedSendAttempts = sendAttempts
        var updatedLastSendNS = lastSendNS
        var emittedCounters: [Int] = []
        var emittedFrames: [Data] = []
        var seen: Set<Int> = []

        for counter in counters {
            if counter == 0 || seen.contains(counter) {
                continue
            }
            seen.insert(counter)
            guard sendBuf.contains(counter), let meta = sendMeta[counter] else {
                continue
            }
            let lastRetx = updatedLastRetxNS[counter] ?? 0
            let firstTX = useFirstTXWhenNoRetx ? (sendTXNS[counter] ?? 0) : 0
            let anchor = lastRetx != 0 ? lastRetx : firstTX
            if anchor != 0 && nowNS - anchor < windowNS {
                continue
            }
            let echoNS: UInt64
            if lastRxTxNS != 0 && lastRxWallNS != 0 {
                echoNS = lastRxTxNS + (nowNS - lastRxWallNS)
            } else {
                echoNS = 0
            }
            let frame = try ObstacleBridgeUdpOverlayCodec.buildDataFrame(
                pktCounter: counter,
                frameType: meta.frameType,
                lenOrOffset: meta.lenOrOffset,
                data: meta.data,
                txNS: nowNS,
                echoNS: echoNS
            )
            emittedCounters.append(counter)
            emittedFrames.append(frame)
            updatedLastRetxNS[counter] = nowNS
            updatedLastSendNS = nowNS
            updatedSendAttempts[counter] = (updatedSendAttempts[counter] ?? 0) + 1
        }

        return RetransmitSnapshot(
            emittedCounters: emittedCounters,
            emittedFrames: emittedFrames,
            lastRetxNS: updatedLastRetxNS,
            sendAttempts: updatedSendAttempts,
            peerReportedMissing: Array(Set(peerReportedMissing)).sorted(),
            peerMissedCount: reasonPeerMissedCount,
            lastSendNS: updatedLastSendNS
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
