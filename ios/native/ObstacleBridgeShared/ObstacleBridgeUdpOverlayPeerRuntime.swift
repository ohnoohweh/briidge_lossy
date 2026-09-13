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

    private let receiverEngine: ObstacleBridgeMyUDPReceiverEngine
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
    private let sendQueue: ObstacleBridgeMyUDPSendQueue

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
        self.sendQueue = .init(nextCounter: UInt16(exactly: nextCounter) ?? 1, maximumInFlight: maxInFlight)
        self.receiverEngine = .init(
            heartbeat: .init(
                establishedNanoseconds: establishedNS, lastReceivedTransmitNanoseconds: 0,
                lastReceivedWallNanoseconds: 0, lastRTTOkNanoseconds: 0,
                rttSampleMilliseconds: 0, rttEstimateMilliseconds: rttEstMS,
                transmitDelayEstimateMilliseconds: transmitDelayEstMS
            ),
            lastSentLastInOrder: UInt16(exactly: lastSentLastInOrder) ?? 0,
            lastControlSentNanoseconds: lastControlSentNS
        )
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
        return ObstacleBridgeMyUDPHeartbeatPolicy.isConnected(nowNanoseconds: now, lastRTTOkNanoseconds: lastRttOkNS)
    }

    func resetTransportEpoch() {
        resetSender()
        receiverEngine.reset()
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
        lastAckPeer = 0
        peerMissedCount = 0
        lastSendNS = 0
        sendQueue.reset()
        transmitDelayEstMS = 0
        synchronizeRuntimeHeartbeatIntoReceiverEngine()
    }

    func sendApplicationPayload(_ payload: Data, nowNS: UInt64, echoNS: UInt64 = 0) throws -> OutboundDataSnapshot {
        try enqueueApplicationPayload(payload, nowNS: nowNS)
        return try flushSendQueue(nowNS: nowNS, echoNS: echoNS)
    }

    // The owner can enqueue a burst before its next queue turn so small records
    // share a DATA_BATCH without delaying control or retransmission datagrams.
    func enqueueApplicationPayload(_ payload: Data, nowNS: UInt64) throws {
        try sendQueue.enqueue(payload, queuedAtNanoseconds: nowNS)
    }

    func flushSendQueue(nowNS: UInt64, echoNS: UInt64 = 0) throws -> OutboundDataSnapshot {
        var counters: [Int] = []
        var frames: [Data] = []
        while let batch = sendQueue.dequeueBatch(inFlightCount: sendBuffer.count) {
            let chunks = batch.chunks.map { ObstacleBridgeUdpOverlayCodec.StreamChunk(counter: Int($0.counter), data: $0.payload) }
            let frame = try ObstacleBridgeUdpOverlayCodec.buildDataBatchFrame(chunks: chunks, txNS: nowNS, echoNS: echoNS)
            for chunk in batch.chunks {
                let counter = Int(chunk.counter)
                counters.append(counter)
                sendBuffer.append(counter)
                sendMeta[counter] = .init(data: chunk.payload)
                sendTXNS[counter] = nowNS
                sendPathStartNS[counter] = batch.queuedAtNanoseconds
                sendAttempts[counter] = (sendAttempts[counter] ?? 0) + 1
                createdTotal += 1
            }
            frames.append(frame)
            batchDatagramsSent += 1
            batchChunksSent += batch.chunks.count
            batchStreamBytesSent += batch.chunks.reduce(0) { $0 + $1.payload.count }
            lastSendNS = nowNS
        }
        sendBuffer = Array(Set(sendBuffer)).sorted()
        return OutboundDataSnapshot(
            counters: counters,
            frames: frames,
            sendBuffer: sendBuffer,
            waitingCount: sendQueue.waitingRecordCount,
            sendTXNS: sendTXNS,
            sendAttempts: sendAttempts,
            lastSendNS: lastSendNS,
            nextCounter: Int(sendQueue.nextCounter)
        )
    }

    func buildOutboundControl(nowNS: UInt64, echoNS: UInt64 = 0) throws -> OutboundControlSnapshot {
        let control = try receiverEngine.buildControlDatagram(nowNanoseconds: nowNS)
        synchronizeReceiverEngine()
        return OutboundControlSnapshot(
            frame: control,
            lastSentLastInOrder: lastSentLastInOrder,
            lastControlSentNS: lastControlSentNS
        )
    }

    var expected: Int {
        return Int(receiverEngine.receiveState.expected)
    }

    var pending: [Int] {
        return receiverEngine.receiveState.pending.keys.map(Int.init).sorted()
    }

    var missing: [Int] {
        return receiverEngine.receiveState.missing.map(Int.init).sorted()
    }

    func updateControlTracking(lastSentLastInOrder: Int, lastControlSentNS: UInt64) {
        self.lastSentLastInOrder = lastSentLastInOrder
        self.lastControlSentNS = lastControlSentNS
        receiverEngine.updateControlTracking(
            lastSentLastInOrder: UInt16(exactly: lastSentLastInOrder) ?? 0,
            lastControlSentNanoseconds: lastControlSentNS
        )
    }

    func noteControlSent(at nowNS: UInt64) {
        receiverEngine.noteControlSent(nowNanoseconds: nowNS)
        synchronizeReceiverEngine()
    }

    func handleControlTimerTick(nowNS: UInt64, sendPortPresent: Bool) -> ControlTimerSnapshot {
        let decision = receiverEngine.controlTimer(nowNanoseconds: nowNS, transportWritable: sendPortPresent)
        synchronizeReceiverEngine()
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
            receiverExpected: expected,
            receiverMissingCount: missing.count,
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
            let corePathStarts = Dictionary(uniqueKeysWithValues: sendPathStartNS.compactMap { entry -> (UInt16, UInt64)? in
                guard let counter = UInt16(exactly: entry.key) else { return nil }
                return (counter, entry.value)
            })
            let coreFirstTransmits = Dictionary(uniqueKeysWithValues: sendTXNS.compactMap { entry -> (UInt16, UInt64)? in
                guard let counter = UInt16(exactly: entry.key) else { return nil }
                return (counter, entry.value)
            })
            let coreAttempts = Dictionary(uniqueKeysWithValues: sendAttempts.compactMap { entry -> (UInt16, Int)? in
                guard let counter = UInt16(exactly: entry.key) else { return nil }
                return (counter, entry.value)
            })
            let metrics = ObstacleBridgeMyUDPConfirmationMetricsPolicy.finalize(
                confirmedCounters: Set(confirmedCounters.compactMap(UInt16.init(exactly:))),
                pathStartNanoseconds: corePathStarts,
                firstTransmitNanoseconds: coreFirstTransmits,
                sendAttempts: coreAttempts,
                acknowledgementNanoseconds: nowNS,
                rttEstimateMilliseconds: rttEstMS,
                prior: .init(
                    transmitDelaySampleMilliseconds: 0,
                    transmitDelayEstimateMilliseconds: transmitDelayEstMS,
                    confirmedTotal: confirmedTotal,
                    firstPassTotal: firstPassTotal,
                    repeatedOnceTotal: repeatedOnceTotal,
                    repeatedMultipleTotal: repeatedMultipleTotal
                )
            )
            transmitDelayEstMS = metrics.transmitDelayEstimateMilliseconds
            confirmedTotal = metrics.confirmedTotal
            firstPassTotal = metrics.firstPassTotal
            repeatedOnceTotal = metrics.repeatedOnceTotal
            repeatedMultipleTotal = metrics.repeatedMultipleTotal
        }

        sendBuffer = snapshot.feedback.sendBufferKeys
        let flushedSnapshot = try flushSendQueue(nowNS: nowNS, echoNS: flushEchoNS)
        transmitDelayEstMS = ObstacleBridgeMyUDPConfirmationMetricsPolicy.rebaseTransmitDelayEstimate(
            outstandingCount: sendBuffer.count,
            rttEstimateMilliseconds: rttEstMS,
            priorEstimateMilliseconds: transmitDelayEstMS
        )
        synchronizeRuntimeHeartbeatIntoReceiverEngine()
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
        let idle = receiverEngine.processIdle(
            nowNanoseconds: nowNS, transmittedNanoseconds: txNS,
            echoedNanoseconds: echoNS, transportWritable: sendPortPresent
        )
        synchronizeReceiverEngine()
        let reflected = idle.shouldReflect
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
        batchDatagramsReceived += 1
        batchChunksReceived += chunks.count
        batchStreamBytesReceived += chunks.reduce(0) { $0 + $1.data.count }
        let coreChunks = chunks.map { ObstacleBridgeMyUDPStreamChunk(counter: UInt16($0.counter), payload: $0.data) }
        guard let inbound = receiverEngine.processData(
            chunks: coreChunks, nowNanoseconds: nowNS, transmittedNanoseconds: txNS,
            echoedNanoseconds: echoNS, transportWritable: sendPortPresent
        ) else {
            streamDecodeErrors += 1
            return nil
        }
        synchronizeReceiverEngine()

        return InboundDataSnapshot(
            controlReasons: inbound.controlReasons,
            completedPayloads: inbound.completedRecords,
            expected: expected,
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
            "buffered_frames": sendQueue.waitingRecordCount,
            "waiting_count": sendQueue.waitingRecordCount,
            "inflight": sendBuffer.count,
            "max_inflight": sendQueue.maximumInFlight,
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
        let state = ObstacleBridgeMyUDPHeartbeatPolicy.update(
            nowNanoseconds: nowNS, transmittedNanoseconds: txNS, echoedNanoseconds: echoNS, fromIdle: fromIdle,
            prior: .init(establishedNanoseconds: establishedNS, lastReceivedTransmitNanoseconds: lastRxTxNS, lastReceivedWallNanoseconds: lastRxWallNS, lastRTTOkNanoseconds: lastRttOkNS, rttSampleMilliseconds: rttSampleMS, rttEstimateMilliseconds: rttEstMS, transmitDelayEstimateMilliseconds: transmitDelayEstMS)
        )
        establishedNS = state.establishedNanoseconds; lastRxTxNS = state.lastReceivedTransmitNanoseconds; lastRxWallNS = state.lastReceivedWallNanoseconds; lastRttOkNS = state.lastRTTOkNanoseconds; rttSampleMS = state.rttSampleMilliseconds; rttEstMS = state.rttEstimateMilliseconds; transmitDelayEstMS = state.transmitDelayEstimateMilliseconds
        receiverEngine.replaceHeartbeat(state)
    }

    private func synchronizeReceiverEngine() {
        let state = receiverEngine.heartbeat
        establishedNS = state.establishedNanoseconds
        lastRxTxNS = state.lastReceivedTransmitNanoseconds
        lastRxWallNS = state.lastReceivedWallNanoseconds
        lastRttOkNS = state.lastRTTOkNanoseconds
        rttSampleMS = state.rttSampleMilliseconds
        rttEstMS = state.rttEstimateMilliseconds
        transmitDelayEstMS = state.transmitDelayEstimateMilliseconds
        lastSentLastInOrder = Int(receiverEngine.lastSentLastInOrder)
        lastControlSentNS = receiverEngine.lastControlSentNanoseconds
    }

    private func synchronizeRuntimeHeartbeatIntoReceiverEngine() {
        receiverEngine.replaceHeartbeat(.init(
            establishedNanoseconds: establishedNS,
            lastReceivedTransmitNanoseconds: lastRxTxNS,
            lastReceivedWallNanoseconds: lastRxWallNS,
            lastRTTOkNanoseconds: lastRttOkNS,
            rttSampleMilliseconds: rttSampleMS,
            rttEstimateMilliseconds: rttEstMS,
            transmitDelayEstimateMilliseconds: transmitDelayEstMS
        ))
    }

}
