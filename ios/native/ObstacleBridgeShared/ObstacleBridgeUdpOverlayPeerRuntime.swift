import Foundation

final class ObstacleBridgeUdpOverlayPeerRuntime {
    struct OutboundDataSnapshot {
        var counters: [Int]
        var frames: [Data]
        var sendBuffer: [Int]
        var waitingCount: Int
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
        var transmitDelayEstMS: Double
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

    private let receiveState = ObstacleBridgeUdpOverlaySessionCodec.StreamReceiveState()
    private var sendBuffer: [Int]
    private var sendMeta: [Int: ObstacleBridgeUdpOverlaySessionCodec.OutgoingChunk]
    private var sendTXNS: [Int: UInt64]
    private var sendPathStartNS: [Int: UInt64]
    private var lastRetxNS: [Int: UInt64]
    private var sendAttempts: [Int: Int]
    private var peerReportedMissing: [Int]
    private var lastAckPeer: Int
    private var peerMissedCount: Int
    private var lastSendNS: UInt64
    private var nextCounter: Int
    private var waitQueue: [Data]
    private var waitQueueStartNS: [UInt64]
    private let maxInFlight: Int

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
    private(set) var batchDatagramsSent = 0
    private(set) var batchChunksSent = 0
    private(set) var batchDatagramsReceived = 0
    private(set) var batchChunksReceived = 0
    private(set) var batchStreamBytesSent = 0
    private(set) var batchStreamBytesReceived = 0
    private(set) var retransmittedChunks = 0
    private(set) var malformedBatches = 0
    private(set) var streamDecodeErrors = 0
    private(set) var framesToSecureLink = 0
    private(set) var framesFromSecureLink = 0

    private let connectedLossNS: UInt64 = 20_000_000_000
    private let transmitDelayEwmaAlpha = 0.125

    init(
        establishedNS: UInt64 = 0,
        lastSentLastInOrder: Int = 0,
        lastControlSentNS: UInt64 = 0,
        rttEstMS: Double = 0,
        transmitDelayEstMS: Double = 0,
        sendBuffer: [Int] = [],
        sendMeta: [Int: ObstacleBridgeUdpOverlaySessionCodec.OutgoingChunk] = [:],
        sendTXNS: [Int: UInt64] = [:],
        sendPathStartNS: [Int: UInt64] = [:],
        lastRetxNS: [Int: UInt64] = [:],
        sendAttempts: [Int: Int] = [:],
        peerReportedMissing: [Int] = [],
        lastAckPeer: Int = 0,
        peerMissedCount: Int = 0,
        lastSendNS: UInt64 = 0,
        nextCounter: Int = 1,
        maxInFlight: Int = 200
    ) {
        self.sendBuffer = sendBuffer.sorted()
        self.sendMeta = sendMeta
        self.sendTXNS = sendTXNS
        self.sendPathStartNS = sendPathStartNS
        self.lastRetxNS = lastRetxNS
        self.sendAttempts = sendAttempts
        self.peerReportedMissing = peerReportedMissing.sorted()
        self.lastAckPeer = lastAckPeer
        self.peerMissedCount = peerMissedCount
        self.lastSendNS = lastSendNS
        self.nextCounter = nextCounter
        self.waitQueue = []
        self.waitQueueStartNS = []
        self.maxInFlight = max(1, min(32767, maxInFlight))
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
        guard lastRttOkNS > 0 else {
            return false
        }
        return now >= lastRttOkNS && (now - lastRttOkNS) <= connectedLossNS
    }

    func resetTransportEpoch() {
        resetSender()
        receiveState.reset()
        establishedNS = 0
        lastRxTxNS = 0
        lastRxWallNS = 0
        lastRttOkNS = 0
        rttSampleMS = 0
        rttEstMS = 0
        transmitDelayEstMS = 0
        lastSentLastInOrder = 0
        lastControlSentNS = 0
        batchDatagramsSent = 0
        batchChunksSent = 0
        batchDatagramsReceived = 0
        batchChunksReceived = 0
        batchStreamBytesSent = 0
        batchStreamBytesReceived = 0
        retransmittedChunks = 0
        malformedBatches = 0
        streamDecodeErrors = 0
    }

    func resetSender() {
        sendBuffer.removeAll()
        sendMeta.removeAll()
        sendTXNS.removeAll()
        sendPathStartNS.removeAll()
        lastRetxNS.removeAll()
        sendAttempts.removeAll()
        peerReportedMissing.removeAll()
        waitQueue.removeAll()
        waitQueueStartNS.removeAll()
        lastAckPeer = 0
        peerMissedCount = 0
        lastSendNS = 0
        nextCounter = 1
        transmitDelayEstMS = 0
    }

    func sendApplicationPayload(_ payload: Data, nowNS: UInt64, echoNS: UInt64 = 0) throws -> OutboundDataSnapshot {
        try enqueueApplicationPayload(payload, nowNS: nowNS)
        return try flushSendQueue(nowNS: nowNS, echoNS: echoNS)
    }

    // The owner can enqueue a burst before its next queue turn so small records
    // share a DATA_BATCH without delaying control or retransmission datagrams.
    func enqueueApplicationPayload(_ payload: Data, nowNS: UInt64) throws {
        waitQueue.append(try ObstacleBridgeUdpOverlayCodec.encodeStreamRecord(payload))
        waitQueueStartNS.append(nowNS)
    }

    func flushSendQueue(nowNS: UInt64, echoNS: UInt64 = 0) throws -> OutboundDataSnapshot {
        var counters: [Int] = []
        var frames: [Data] = []
        while sendBuffer.count < maxInFlight && !waitQueue.isEmpty {
            let slots = maxInFlight - sendBuffer.count
            var chunks: [ObstacleBridgeUdpOverlayCodec.StreamChunk] = []
            var consumed: [Int] = []
            var payloadUsed = ObstacleBridgeUdpOverlayCodec.batchHeaderSize
            var recordIndex = 0
            var recordOffset = 0
            var counter = nextCounter
            while recordIndex < waitQueue.count && chunks.count < min(ObstacleBridgeUdpOverlayCodec.maxBatchRecords, slots) {
                let budget = ObstacleBridgeUdpOverlayCodec.maxBatchPayloadBytes - payloadUsed -
                    ObstacleBridgeUdpOverlayCodec.batchRecordLengthSize - ObstacleBridgeUdpOverlayCodec.chunkHeaderSize
                guard budget > 0 else { break }
                let record = waitQueue[recordIndex]
                guard recordOffset < record.count else {
                    recordIndex += 1
                    recordOffset = 0
                    continue
                }
                let remaining = record.count - recordOffset
                let length = min(ObstacleBridgeUdpOverlayCodec.maxChunkBytes, budget, remaining)
                guard length > 0 else { break }
                let endOffset = recordOffset + length
                guard endOffset <= record.count else { break }
                let start = record.index(record.startIndex, offsetBy: recordOffset)
                let end = record.index(start, offsetBy: length)
                let bytes = record.subdata(in: start..<end)
                chunks.append(.init(counter: counter, data: bytes))
                consumed.append(length)
                payloadUsed += ObstacleBridgeUdpOverlayCodec.batchRecordLengthSize + ObstacleBridgeUdpOverlayCodec.chunkHeaderSize + length
                recordOffset += length
                if recordOffset == record.count {
                    recordIndex += 1
                    recordOffset = 0
                }
                counter = counter == 65535 ? 1 : counter + 1
            }
            guard !chunks.isEmpty else { break }
            let queuedAtNS = waitQueueStartNS.first ?? nowNS
            let frame = try ObstacleBridgeUdpOverlayCodec.buildDataBatchFrame(chunks: chunks, txNS: nowNS, echoNS: echoNS)
            for length in consumed {
                var record = waitQueue[0]
                record.removeFirst(length)
                if record.isEmpty {
                    waitQueue.removeFirst()
                    if !waitQueueStartNS.isEmpty { waitQueueStartNS.removeFirst() }
                } else {
                    waitQueue[0] = record
                }
            }
            for chunk in chunks {
                counters.append(chunk.counter)
                sendBuffer.append(chunk.counter)
                sendMeta[chunk.counter] = .init(data: chunk.data)
                sendTXNS[chunk.counter] = nowNS
                sendPathStartNS[chunk.counter] = queuedAtNS
                sendAttempts[chunk.counter] = (sendAttempts[chunk.counter] ?? 0) + 1
                createdTotal += 1
            }
            frames.append(frame)
            batchDatagramsSent += 1
            batchChunksSent += chunks.count
            batchStreamBytesSent += chunks.reduce(0) { $0 + $1.data.count }
            lastSendNS = nowNS
            nextCounter = counter
        }
        sendBuffer = Array(Set(sendBuffer)).sorted()
        return OutboundDataSnapshot(
            counters: counters,
            frames: frames,
            sendBuffer: sendBuffer,
            waitingCount: waitQueue.count,
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
        retransmittedChunks += reportedMissingSnapshot.emittedCounters.count
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
        retransmittedChunks += unconfirmedSnapshot.emittedCounters.count
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
        sendPortPresent: Bool,
        flushEchoNS: UInt64 = 0
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
        retransmittedChunks += snapshot.retransmit.emittedCounters.count
        let updatedCounters = Set(snapshot.feedback.sendBufferKeys)
        let confirmedCounters = priorCounters.subtracting(updatedCounters)
        if !confirmedCounters.isEmpty {
            for counter in confirmedCounters {
                recordTransmitDelaySample(counter: counter, ackNowNS: nowNS)
                tallyConfirmedCounter(counter)
            }
        }

        sendBuffer = snapshot.feedback.sendBufferKeys
        let flushedSnapshot = try flushSendQueue(nowNS: nowNS, echoNS: flushEchoNS)
        rebaseTransmitDelayIfPipelineEmpty()
        peerReportedMissing = snapshot.retransmit.peerReportedMissing.sorted()
        lastAckPeer = snapshot.feedback.lastAckPeer
        let activeCounters = Set(sendBuffer)
        sendMeta = sendMeta.filter { activeCounters.contains($0.key) }
        sendTXNS = sendTXNS.filter { activeCounters.contains($0.key) }
        sendPathStartNS = sendPathStartNS.filter { activeCounters.contains($0.key) }
        lastRetxNS = snapshot.retransmit.lastRetxNS.filter { activeCounters.contains($0.key) }
        sendAttempts = snapshot.retransmit.sendAttempts.filter { activeCounters.contains($0.key) }
        peerMissedCount = snapshot.retransmit.peerMissedCount
        lastSendNS = snapshot.retransmit.lastSendNS

        return InboundControlSnapshot(
            sendBuffer: sendBuffer,
            peerReportedMissing: peerReportedMissing,
            lastAckPeer: lastAckPeer,
            emittedCounters: snapshot.retransmit.emittedCounters + flushedSnapshot.counters,
            emittedFrames: snapshot.retransmit.emittedFrames + flushedSnapshot.frames,
            lastRetxNS: lastRetxNS,
            sendAttempts: sendAttempts,
            peerMissedCount: peerMissedCount,
            lastSendNS: lastSendNS,
            flushRequested: snapshot.flushRequested,
            controlShouldEmit: snapshot.controlDecision.shouldEmit,
            controlReason: snapshot.controlDecision.reason,
            transmitDelayEstMS: transmitDelayEstMS,
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
        guard let parsed = ObstacleBridgeUdpOverlayCodec.parseProtocolFrame(frame),
              parsed.ptype == ObstacleBridgeUdpOverlayCodec.ptypeData else {
            return nil
        }
        guard let chunks = ObstacleBridgeUdpOverlayCodec.decodeDataBatch(parsed.payload) else {
            malformedBatches += 1
            return nil
        }
        updateInboundHeartbeat(nowNS: nowNS, txNS: txNS, echoNS: echoNS, fromIdle: false)
        batchDatagramsReceived += 1
        batchChunksReceived += chunks.count
        batchStreamBytesReceived += chunks.reduce(0) { $0 + $1.data.count }

        let previousMissing = receiveState.missing
        var completedPayloads: [Data] = []
        var gapFilled = false
        for chunk in chunks {
            if previousMissing.contains(chunk.counter) {
                gapFilled = true
            }
            guard let result = receiveState.process(chunk) else {
                receiveState.reset()
                streamDecodeErrors += 1
                return nil
            }
            completedPayloads.append(contentsOf: result.1)
        }
        var controlReasons: [String] = []
        if gapFilled && sendPortPresent {
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
            completedPayloads: completedPayloads,
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
            "buffered_frames": waitQueue.count,
            "waiting_count": waitQueue.count,
            "inflight": sendBuffer.count,
            "max_inflight": maxInFlight,
            "first_pass": firstPassTotal,
            "repeated_once": repeatedOnceTotal,
            "repeated_multiple": repeatedMultipleTotal,
            "confirmed_total": confirmedTotal,
            "batch_datagrams_sent": batchDatagramsSent,
            "batch_chunks_sent": batchChunksSent,
            "batch_datagrams_received": batchDatagramsReceived,
            "batch_chunks_received": batchChunksReceived,
            "batch_stream_bytes_sent": batchStreamBytesSent,
            "batch_stream_bytes_received": batchStreamBytesReceived,
            "retransmitted_chunks": retransmittedChunks,
            "malformed_batches": malformedBatches,
            "stream_decode_errors": streamDecodeErrors,
            "frames_to_securelink": framesToSecureLink,
            "frames_from_securelink": framesFromSecureLink,
        ]
    }

    func recordSecureLinkBoundaryFrame(direction: String) {
        if direction == "to_securelink" {
            framesToSecureLink &+= 1
        } else {
            framesFromSecureLink &+= 1
        }
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

    private func recordTransmitDelaySample(counter: Int, ackNowNS: UInt64) {
        let pathStartNS = sendPathStartNS[counter] ?? sendTXNS[counter] ?? 0
        guard pathStartNS > 0, ackNowNS > pathStartNS else {
            return
        }
        let elapsedMS = Double(ackNowNS - pathStartNS) / 1_000_000.0
        let halfRTTMS = rttEstMS > 0 ? 0.5 * rttEstMS : 0.0
        let sampleMS = max(0.0, elapsedMS - halfRTTMS)
        if transmitDelayEstMS <= 0.0 {
            transmitDelayEstMS = sampleMS
        } else if transmitDelayEstMS < sampleMS {
            transmitDelayEstMS = sampleMS
        } else {
            transmitDelayEstMS = ((1.0 - transmitDelayEwmaAlpha) * transmitDelayEstMS) + (transmitDelayEwmaAlpha * sampleMS)
        }
    }

    private func rebaseTransmitDelayIfPipelineEmpty() {
        if sendBuffer.isEmpty, rttEstMS > 0.0 {
            transmitDelayEstMS = 0.5 * rttEstMS
        }
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
