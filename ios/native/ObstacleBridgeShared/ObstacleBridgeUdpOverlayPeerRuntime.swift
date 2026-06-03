import Foundation

final class ObstacleBridgeUdpOverlayPeerRuntime {
    struct OutboundDataSnapshot {
        var counters: [Int]
        var frames: [Data]
        var sendBuffer: [Int]
        var sendTXNS: [Int: UInt64]
        var sendAttempts: [Int: Int]
        var lastSendNS: UInt64
        var nextCounter: Int
    }

    struct OutboundControlSnapshot {
        var frame: Data
        var lastSentLastInOrder: Int
        var lastControlSentNS: UInt64
    }

    struct InboundControlSnapshot {
        var sendBuffer: [Int]
        var peerReportedMissing: [Int]
        var lastAckPeer: Int
        var emittedCounters: [Int]
        var emittedFrames: [Data]
        var lastRetxNS: [Int: UInt64]
        var sendAttempts: [Int: Int]
        var peerMissedCount: Int
        var lastSendNS: UInt64
        var flushRequested: Bool
        var controlShouldEmit: Bool
        var controlReason: String?
        var lastSentLastInOrder: Int
        var lastControlSentNS: UInt64
    }

    struct InboundIdleSnapshot {
        var reflectedFrame: Data?
        var reflected: Bool
        var establishedNS: UInt64
        var lastRxTxNS: UInt64
        var lastRxWallNS: UInt64
        var rttSampleMS: Double
        var rttEstMS: Double
        var transmitDelayEstMS: Double
    }

    struct InboundDataSnapshot {
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
        var lastSentLastInOrder: Int
        var lastControlSentNS: UInt64
    }

    struct ControlTimerSnapshot {
        var controlShouldEmit: Bool
        var controlReason: String?
        var lastSentLastInOrder: Int
        var lastControlSentNS: UInt64
    }

    struct RetransmitTimerSnapshot {
        var emittedCounters: [Int]
        var emittedFrames: [Data]
        var lastRetxNS: [Int: UInt64]
        var sendAttempts: [Int: Int]
        var peerReportedMissing: [Int]
        var peerMissedCount: Int
        var lastSendNS: UInt64
    }

    private let receiveState = ObstacleBridgeUdpOverlaySessionCodec.ReceiveState()
    private var sendBuffer: [Int]
    private var sendMeta: [Int: ObstacleBridgeUdpOverlaySessionCodec.OutgoingSegment]
    private var sendTXNS: [Int: UInt64]
    private var lastRetxNS: [Int: UInt64]
    private var sendAttempts: [Int: Int]
    private var peerReportedMissing: [Int]
    private var lastAckPeer: Int
    private var peerMissedCount: Int
    private var lastSendNS: UInt64
    private var nextCounter: Int

    private(set) var establishedNS: UInt64
    private(set) var lastRxTxNS: UInt64
    private(set) var lastRxWallNS: UInt64
    private(set) var lastRttOkNS: UInt64
    private(set) var rttSampleMS: Double
    private(set) var rttEstMS: Double
    private(set) var transmitDelayEstMS: Double
    private(set) var lastSentLastInOrder: Int
    private(set) var lastControlSentNS: UInt64
    private(set) var createdTotal: Int
    private(set) var confirmedTotal: Int
    private(set) var firstPassTotal: Int
    private(set) var repeatedOnceTotal: Int
    private(set) var repeatedMultipleTotal: Int

    private let connectedLossNS: UInt64 = 20_000_000_000

    init(
        establishedNS: UInt64 = 0,
        lastSentLastInOrder: Int = 0,
        lastControlSentNS: UInt64 = 0,
        rttEstMS: Double = 0,
        transmitDelayEstMS: Double = 0,
        sendBuffer: [Int] = [],
        sendMeta: [Int: ObstacleBridgeUdpOverlaySessionCodec.OutgoingSegment] = [:],
        sendTXNS: [Int: UInt64] = [:],
        lastRetxNS: [Int: UInt64] = [:],
        sendAttempts: [Int: Int] = [:],
        peerReportedMissing: [Int] = [],
        lastAckPeer: Int = 0,
        peerMissedCount: Int = 0,
        lastSendNS: UInt64 = 0,
        nextCounter: Int = 1
    ) {
        self.sendBuffer = sendBuffer.sorted()
        self.sendMeta = sendMeta
        self.sendTXNS = sendTXNS
        self.lastRetxNS = lastRetxNS
        self.sendAttempts = sendAttempts
        self.peerReportedMissing = peerReportedMissing.sorted()
        self.lastAckPeer = lastAckPeer
        self.peerMissedCount = peerMissedCount
        self.lastSendNS = lastSendNS
        self.nextCounter = nextCounter
        self.establishedNS = establishedNS
        self.lastRxTxNS = 0
        self.lastRxWallNS = 0
        self.lastRttOkNS = 0
        self.rttSampleMS = 0
        self.rttEstMS = rttEstMS
        self.transmitDelayEstMS = transmitDelayEstMS
        self.lastSentLastInOrder = lastSentLastInOrder
        self.lastControlSentNS = lastControlSentNS
        self.createdTotal = 0
        self.confirmedTotal = 0
        self.firstPassTotal = 0
        self.repeatedOnceTotal = 0
        self.repeatedMultipleTotal = 0
    }

    func isConnected(nowNS: UInt64? = nil) -> Bool {
        let now = nowNS ?? DispatchTime.now().uptimeNanoseconds
        let activityNS = max(lastRttOkNS, lastRxWallNS)
        guard activityNS > 0 else {
            return false
        }
        return now >= activityNS && (now - activityNS) <= connectedLossNS
    }

    func sendApplicationPayload(_ payload: Data, nowNS: UInt64, echoNS: UInt64 = 0) throws -> OutboundDataSnapshot {
        let frames = try ObstacleBridgeUdpOverlaySessionCodec.segmentApplicationPayload(
            payload,
            txNS: nowNS,
            echoNS: echoNS,
            startingCounter: nextCounter
        )
        var counters: [Int] = []
        for frame in frames {
            guard let packet = ObstacleBridgeUdpOverlayCodec.parseDataFrame(frame) else {
                continue
            }
            let counter = packet.pktCounter
            counters.append(counter)
            sendBuffer.append(counter)
            sendMeta[counter] = ObstacleBridgeUdpOverlaySessionCodec.OutgoingSegment(
                frameType: packet.frameType,
                lenOrOffset: packet.lenOrOffset,
                data: packet.data
            )
            sendTXNS[counter] = nowNS
            sendAttempts[counter] = (sendAttempts[counter] ?? 0) + 1
            lastSendNS = nowNS
            nextCounter = counter == 65535 ? 1 : counter + 1
            createdTotal += 1
        }
        sendBuffer = Array(Set(sendBuffer)).sorted()
        return OutboundDataSnapshot(
            counters: counters,
            frames: frames,
            sendBuffer: sendBuffer,
            sendTXNS: sendTXNS,
            sendAttempts: sendAttempts,
            lastSendNS: lastSendNS,
            nextCounter: nextCounter
        )
    }

    func buildOutboundControl(nowNS: UInt64, echoNS: UInt64 = 0) throws -> OutboundControlSnapshot {
        let control = try ObstacleBridgeUdpOverlaySessionCodec.buildControl(
            expected: receiveState.expected,
            pendingKeys: pending,
            missing: missing,
            txNS: nowNS,
            echoNS: echoNS
        )
        noteControlSent(at: nowNS)
        return OutboundControlSnapshot(
            frame: control.raw,
            lastSentLastInOrder: lastSentLastInOrder,
            lastControlSentNS: lastControlSentNS
        )
    }

    var expected: Int {
        return receiveState.expected
    }

    var pending: [Int] {
        return receiveState.pending.keys.sorted()
    }

    var missing: [Int] {
        return Array(receiveState.missing).sorted()
    }

    func updateControlTracking(lastSentLastInOrder: Int, lastControlSentNS: UInt64) {
        self.lastSentLastInOrder = lastSentLastInOrder
        self.lastControlSentNS = lastControlSentNS
    }

    func noteControlSent(at nowNS: UInt64) {
        lastControlSentNS = nowNS
        lastSentLastInOrder = receiveState.expected == 1 ? 0 : receiveState.expected - 1
    }

    func handleControlTimerTick(nowNS: UInt64, sendPortPresent: Bool) -> ControlTimerSnapshot {
        let decision = ObstacleBridgeUdpOverlaySessionCodec.evaluateTimerControlPolicy(
            nowNS: nowNS,
            expected: receiveState.expected,
            missingCount: receiveState.missing.count,
            lastSentLastInOrder: lastSentLastInOrder,
            lastControlSentNS: lastControlSentNS,
            establishedNS: establishedNS,
            rttEstMS: rttEstMS
        )
        if sendPortPresent, decision.shouldEmit {
            noteControlSent(at: nowNS)
        }
        return ControlTimerSnapshot(
            controlShouldEmit: sendPortPresent && decision.shouldEmit,
            controlReason: sendPortPresent ? decision.reason : nil,
            lastSentLastInOrder: lastSentLastInOrder,
            lastControlSentNS: lastControlSentNS
        )
    }

    func handleRetransmitTimerTick(nowNS: UInt64, sendPortPresent: Bool) throws -> RetransmitTimerSnapshot {
        guard sendPortPresent else {
            return RetransmitTimerSnapshot(
                emittedCounters: [],
                emittedFrames: [],
                lastRetxNS: lastRetxNS,
                sendAttempts: sendAttempts,
                peerReportedMissing: peerReportedMissing,
                peerMissedCount: peerMissedCount,
                lastSendNS: lastSendNS
            )
        }

        var emittedCounters: [Int] = []
        var emittedFrames: [Data] = []

        let reportedMissingSnapshot = try ObstacleBridgeUdpOverlaySessionCodec.sweepReportedMissingRetransmit(
            nowNS: nowNS,
            rttEstMS: rttEstMS,
            sendBufferKeys: sendBuffer,
            sendMeta: sendMeta,
            sendTXNS: sendTXNS,
            lastRetxNS: lastRetxNS,
            sendAttempts: sendAttempts,
            peerReportedMissing: peerReportedMissing,
            peerMissedCount: peerMissedCount,
            lastSendNS: lastSendNS,
            lastRxTxNS: lastRxTxNS,
            lastRxWallNS: lastRxWallNS
        )
        emittedCounters.append(contentsOf: reportedMissingSnapshot.emittedCounters)
        emittedFrames.append(contentsOf: reportedMissingSnapshot.emittedFrames)
        lastRetxNS = reportedMissingSnapshot.lastRetxNS
        sendAttempts = reportedMissingSnapshot.sendAttempts
        peerReportedMissing = reportedMissingSnapshot.peerReportedMissing.sorted()
        peerMissedCount = reportedMissingSnapshot.peerMissedCount
        lastSendNS = reportedMissingSnapshot.lastSendNS

        let unconfirmedSnapshot = try ObstacleBridgeUdpOverlaySessionCodec.sweepUnconfirmedRetransmit(
            nowNS: nowNS,
            rttEstMS: rttEstMS,
            sendBufferKeys: sendBuffer,
            sendMeta: sendMeta,
            sendTXNS: sendTXNS,
            lastRetxNS: lastRetxNS,
            sendAttempts: sendAttempts,
            peerReportedMissing: peerReportedMissing,
            peerMissedCount: peerMissedCount,
            lastSendNS: lastSendNS,
            lastRxTxNS: lastRxTxNS,
            lastRxWallNS: lastRxWallNS
        )
        emittedCounters.append(contentsOf: unconfirmedSnapshot.emittedCounters)
        emittedFrames.append(contentsOf: unconfirmedSnapshot.emittedFrames)
        lastRetxNS = unconfirmedSnapshot.lastRetxNS
        sendAttempts = unconfirmedSnapshot.sendAttempts
        peerReportedMissing = unconfirmedSnapshot.peerReportedMissing.sorted()
        peerMissedCount = unconfirmedSnapshot.peerMissedCount
        lastSendNS = unconfirmedSnapshot.lastSendNS

        return RetransmitTimerSnapshot(
            emittedCounters: emittedCounters,
            emittedFrames: emittedFrames,
            lastRetxNS: lastRetxNS,
            sendAttempts: sendAttempts,
            peerReportedMissing: peerReportedMissing,
            peerMissedCount: peerMissedCount,
            lastSendNS: lastSendNS
        )
    }

    func handleInboundControlPacket(
        nowNS: UInt64,
        txNS: UInt64,
        echoNS: UInt64,
        packetLastInOrder: Int,
        packetHighest: Int,
        packetMissed: [Int],
        sendPortPresent: Bool
    ) throws -> InboundControlSnapshot {
        updateInboundHeartbeat(nowNS: nowNS, txNS: txNS, echoNS: echoNS, fromIdle: false)
        let snapshot = try ObstacleBridgeUdpOverlaySessionCodec.handleInboundControlPacket(
            nowNS: nowNS,
            packetLastInOrder: packetLastInOrder,
            packetHighest: packetHighest,
            packetMissed: packetMissed,
            sendPortPresent: sendPortPresent,
            sendBufferKeys: sendBuffer,
            peerReportedMissing: peerReportedMissing,
            sendMeta: sendMeta,
            sendTXNS: sendTXNS,
            lastRetxNS: lastRetxNS,
            sendAttempts: sendAttempts,
            lastSendNS: lastSendNS,
            lastRxTxNS: lastRxTxNS,
            lastRxWallNS: lastRxWallNS,
            receiverExpected: receiveState.expected,
            receiverMissingCount: receiveState.missing.count,
            lastSentLastInOrder: lastSentLastInOrder,
            lastControlSentNS: lastControlSentNS,
            establishedNS: establishedNS,
            rttEstMS: rttEstMS
        )

        let priorCounters = Set(sendBuffer)
        let updatedCounters = Set(snapshot.feedback.sendBufferKeys)
        let confirmedCounters = priorCounters.subtracting(updatedCounters)
        if !confirmedCounters.isEmpty {
            for counter in confirmedCounters {
                tallyConfirmedCounter(counter)
            }
        }

        sendBuffer = snapshot.feedback.sendBufferKeys
        peerReportedMissing = snapshot.retransmit.peerReportedMissing.sorted()
        lastAckPeer = snapshot.feedback.lastAckPeer
        let activeCounters = Set(sendBuffer)
        sendMeta = sendMeta.filter { activeCounters.contains($0.key) }
        sendTXNS = sendTXNS.filter { activeCounters.contains($0.key) }
        lastRetxNS = snapshot.retransmit.lastRetxNS.filter { activeCounters.contains($0.key) }
        sendAttempts = snapshot.retransmit.sendAttempts.filter { activeCounters.contains($0.key) }
        peerMissedCount = snapshot.retransmit.peerMissedCount
        lastSendNS = snapshot.retransmit.lastSendNS

        return InboundControlSnapshot(
            sendBuffer: sendBuffer,
            peerReportedMissing: peerReportedMissing,
            lastAckPeer: lastAckPeer,
            emittedCounters: snapshot.retransmit.emittedCounters,
            emittedFrames: snapshot.retransmit.emittedFrames,
            lastRetxNS: lastRetxNS,
            sendAttempts: sendAttempts,
            peerMissedCount: peerMissedCount,
            lastSendNS: lastSendNS,
            flushRequested: snapshot.flushRequested,
            controlShouldEmit: snapshot.controlDecision.shouldEmit,
            controlReason: snapshot.controlDecision.reason,
            lastSentLastInOrder: lastSentLastInOrder,
            lastControlSentNS: lastControlSentNS
        )
    }

    func handleInboundIdleFrame(
        nowNS: UInt64,
        txNS: UInt64,
        echoNS: UInt64,
        sendPortPresent: Bool
    ) throws -> InboundIdleSnapshot {
        updateInboundHeartbeat(nowNS: nowNS, txNS: txNS, echoNS: echoNS, fromIdle: true)

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

        return InboundIdleSnapshot(
            reflectedFrame: reflectedFrame,
            reflected: reflected,
            establishedNS: establishedNS,
            lastRxTxNS: lastRxTxNS,
            lastRxWallNS: lastRxWallNS,
            rttSampleMS: rttSampleMS,
            rttEstMS: rttEstMS,
            transmitDelayEstMS: transmitDelayEstMS
        )
    }

    func handleInboundDataFrame(
        frame: Data,
        nowNS: UInt64,
        txNS: UInt64,
        echoNS: UInt64,
        sendPortPresent: Bool
    ) -> InboundDataSnapshot? {
        guard let packet = ObstacleBridgeUdpOverlayCodec.parseDataFrame(frame) else {
            return nil
        }
        updateInboundHeartbeat(nowNS: nowNS, txNS: txNS, echoNS: echoNS, fromIdle: false)

        let previousMissing = receiveState.missing
        let result = receiveState.process(packet)
        var controlReasons: [String] = []
        if previousMissing.contains(packet.pktCounter) && !receiveState.missing.contains(packet.pktCounter) && sendPortPresent {
            controlReasons.append("gap_filled_ack")
        }

        let grewMissing = !receiveState.missing.subtracting(previousMissing).isEmpty
        let decision = ObstacleBridgeUdpOverlaySessionCodec.evaluateInboundControlPolicy(
            nowNS: nowNS,
            expected: receiveState.expected,
            missingCount: receiveState.missing.count,
            grewMissing: grewMissing,
            lastSentLastInOrder: lastSentLastInOrder,
            lastControlSentNS: lastControlSentNS,
            establishedNS: establishedNS,
            rttEstMS: rttEstMS
        )
        if sendPortPresent, let reason = decision.reason, decision.shouldEmit {
            controlReasons.append(reason)
        }

        return InboundDataSnapshot(
            controlReasons: controlReasons,
            completedPayloads: result.1,
            expected: receiveState.expected,
            pending: pending,
            missing: missing,
            establishedNS: establishedNS,
            lastRxTxNS: lastRxTxNS,
            lastRxWallNS: lastRxWallNS,
            rttSampleMS: rttSampleMS,
            rttEstMS: rttEstMS,
            transmitDelayEstMS: transmitDelayEstMS,
            lastSentLastInOrder: lastSentLastInOrder,
            lastControlSentNS: lastControlSentNS
        )
    }

    func protocolStatsSnapshot() -> [String: Any] {
        [
            "buffered_frames": sendBuffer.count,
            "first_pass": firstPassTotal,
            "repeated_once": repeatedOnceTotal,
            "repeated_multiple": repeatedMultipleTotal,
            "confirmed_total": confirmedTotal,
        ]
    }

    private func updateInboundHeartbeat(nowNS: UInt64, txNS: UInt64, echoNS: UInt64, fromIdle: Bool) {
        lastRxTxNS = txNS
        lastRxWallNS = nowNS

        guard echoNS != 0 else {
            return
        }

        let sample = Double(nowNS - echoNS) / 1_000_000.0
        rttSampleMS = sample
        if rttEstMS < sample {
            rttEstMS = sample
        } else {
            rttEstMS = (1.0 - 0.125) * rttEstMS + (0.125 * sample)
        }
        if fromIdle, rttEstMS > 0 {
            transmitDelayEstMS = 0.5 * rttEstMS
        }
        if establishedNS == 0 {
            establishedNS = nowNS
        }
        lastRttOkNS = nowNS
    }

    private func tallyConfirmedCounter(_ counter: Int) {
        let attempts = max(1, sendAttempts[counter] ?? 1)
        confirmedTotal += 1
        if attempts <= 1 {
            firstPassTotal += 1
        } else if attempts == 2 {
            repeatedOnceTotal += 1
        } else {
            repeatedMultipleTotal += 1
        }
    }
}
