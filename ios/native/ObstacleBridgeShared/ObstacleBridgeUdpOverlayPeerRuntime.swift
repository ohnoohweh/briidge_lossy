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
        var emittedFrames: [Data]
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

    private let peerEngine: ObstacleBridgeMyUDPPeerEngine

    private(set) var establishedNS: UInt64
    private(set) var lastRxTxNS: UInt64
    private(set) var lastRxWallNS: UInt64
    private(set) var lastRttOkNS: UInt64
    private(set) var rttSampleMS: Double
    private(set) var rttEstMS: Double
    private(set) var transmitDelayEstMS: Double
    private(set) var lastSentLastInOrder: Int
    private(set) var lastControlSentNS: UInt64
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
        nextCounter: Int = 1,
        maxInFlight: Int = 200
    ) {
        self.peerEngine = .init(
            nextCounter: UInt16(exactly: nextCounter) ?? 1,
            maximumInFlight: maxInFlight,
            heartbeat: .init(
                establishedNanoseconds: establishedNS,
                lastReceivedTransmitNanoseconds: 0,
                lastReceivedWallNanoseconds: 0,
                lastRTTOkNanoseconds: 0,
                rttSampleMilliseconds: 0,
                rttEstimateMilliseconds: rttEstMS,
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
        peerEngine.resetEpoch()
        transmitDelayEstMS = 0
    }

    func sendApplicationPayload(_ payload: Data, nowNS: UInt64, echoNS: UInt64 = 0) throws -> OutboundDataSnapshot {
        try enqueueApplicationPayload(payload, nowNS: nowNS)
        return try flushSendQueue(nowNS: nowNS, echoNS: echoNS)
    }

    // The owner can enqueue a burst before its next queue turn so small records
    // share a DATA_BATCH without delaying control or retransmission datagrams.
    func enqueueApplicationPayload(_ payload: Data, nowNS: UInt64) throws {
        try peerEngine.enqueueApplicationRecord(payload, nowNanoseconds: nowNS)
    }

    func flushSendQueue(nowNS: UInt64, echoNS: UInt64 = 0) throws -> OutboundDataSnapshot {
        let effect = try peerEngine.flush(nowNanoseconds: nowNS)
        let snapshot = peerEngine.snapshot()
        synchronizePeerEngine(snapshot)
        let counters = effect.outboundDataCounters.map(Int.init)
        let frames = effect.outboundDatagrams
        if !frames.isEmpty { batchDatagramsSent += frames.count; batchChunksSent += counters.count }
        return OutboundDataSnapshot(
            counters: counters,
            frames: frames,
            sendBuffer: snapshot.outstandingCounters.map(Int.init),
            waitingCount: snapshot.waitingRecordCount,
            sendTXNS: [:],
            sendAttempts: Dictionary(uniqueKeysWithValues: snapshot.sendAttempts.map { (Int($0.key), $0.value) }),
            lastSendNS: snapshot.lastSendNanoseconds,
            nextCounter: Int(snapshot.nextCounter)
        )
    }

    func buildOutboundControl(nowNS: UInt64, echoNS: UInt64 = 0) throws -> OutboundControlSnapshot {
        let control = try peerEngine.buildControlDatagram(nowNanoseconds: nowNS)
        let core = peerEngine.snapshot()
        synchronizePeerEngine(core)
        return OutboundControlSnapshot(
            frame: control,
            lastSentLastInOrder: Int(core.lastSentLastInOrder),
            lastControlSentNS: core.lastControlSentNanoseconds
        )
    }

    var expected: Int {
        return Int(peerEngine.snapshot().expectedCounter)
    }

    var pending: [Int] {
        return peerEngine.snapshot().pendingCounters.map(Int.init)
    }

    var missing: [Int] {
        return peerEngine.snapshot().missingCounters.map(Int.init)
    }

    func updateControlTracking(lastSentLastInOrder: Int, lastControlSentNS: UInt64) {
        self.lastSentLastInOrder = lastSentLastInOrder
        self.lastControlSentNS = lastControlSentNS
        peerEngine.updateControlTracking(
            lastSentLastInOrder: UInt16(exactly: lastSentLastInOrder) ?? 0,
            lastControlSentNanoseconds: lastControlSentNS
        )
    }

    func noteControlSent(at nowNS: UInt64) {
        peerEngine.noteControlSent(nowNanoseconds: nowNS)
        synchronizePeerEngine(peerEngine.snapshot())
    }

    func handleControlTimerTick(nowNS: UInt64, sendPortPresent: Bool) -> ControlTimerSnapshot {
        let decision = peerEngine.controlTimer(nowNanoseconds: nowNS, transportWritable: sendPortPresent)
        let core = peerEngine.snapshot()
        synchronizePeerEngine(core)
        return ControlTimerSnapshot(
            controlShouldEmit: sendPortPresent && decision.shouldEmit,
            controlReason: sendPortPresent ? decision.reason : nil,
            lastSentLastInOrder: Int(core.lastSentLastInOrder),
            lastControlSentNS: core.lastControlSentNanoseconds
        )
    }

    func handleRetransmitTimerTick(nowNS: UInt64, sendPortPresent: Bool) throws -> RetransmitTimerSnapshot {
        guard sendPortPresent else {
            let core = peerEngine.snapshot()
            return RetransmitTimerSnapshot(
                emittedCounters: [],
                emittedFrames: [],
                lastRetxNS: Dictionary(uniqueKeysWithValues: core.lastRetransmissionNanoseconds.map { (Int($0.key), $0.value) }),
                sendAttempts: Dictionary(uniqueKeysWithValues: core.sendAttempts.map { (Int($0.key), $0.value) }),
                peerReportedMissing: core.peerReportedMissing.map(Int.init),
                peerMissedCount: core.peerReportedMissing.count,
                lastSendNS: core.lastSendNanoseconds
            )
        }

        let effect = try peerEngine.retransmit(nowNanoseconds: nowNS)
        let core = peerEngine.snapshot()
        synchronizePeerEngine(core)
        retransmittedChunks += effect.outboundDataCounters.count
        return .init(
            emittedCounters: effect.outboundDataCounters.map(Int.init),
            emittedFrames: effect.outboundDatagrams,
            lastRetxNS: Dictionary(uniqueKeysWithValues: core.lastRetransmissionNanoseconds.map { (Int($0.key), $0.value) }),
            sendAttempts: Dictionary(uniqueKeysWithValues: core.sendAttempts.map { (Int($0.key), $0.value) }),
            peerReportedMissing: core.peerReportedMissing.map(Int.init),
            peerMissedCount: core.peerReportedMissing.count,
            lastSendNS: core.lastSendNanoseconds
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
        let wire = try ObstacleBridgeMyUDPCodec.encodeControl(
            lastInOrder: UInt16(exactly: packetLastInOrder) ?? 0,
            highestReceived: UInt16(exactly: packetHighest) ?? 0,
            missing: packetMissed.compactMap(UInt16.init(exactly:)),
            transmittedNanoseconds: txNS, echoedNanoseconds: echoNS
        )
        let effect = try peerEngine.receiveWire(wire, nowNanoseconds: nowNS, transportWritable: sendPortPresent)
        let core = peerEngine.snapshot()
        synchronizePeerEngine(core)
        retransmittedChunks += effect.outboundDataCounters.count
        return .init(
            sendBuffer: core.outstandingCounters.map(Int.init),
            peerReportedMissing: core.peerReportedMissing.map(Int.init),
            lastAckPeer: Int(core.lastAcknowledgedByPeer),
            emittedCounters: effect.outboundDataCounters.map(Int.init),
            emittedFrames: effect.outboundDatagrams,
            lastRetxNS: Dictionary(uniqueKeysWithValues: core.lastRetransmissionNanoseconds.map { (Int($0.key), $0.value) }),
            sendAttempts: Dictionary(uniqueKeysWithValues: core.sendAttempts.map { (Int($0.key), $0.value) }),
            peerMissedCount: core.peerReportedMissing.count,
            lastSendNS: core.lastSendNanoseconds,
            flushRequested: !effect.outboundDatagrams.isEmpty,
            controlShouldEmit: false, controlReason: nil,
            transmitDelayEstMS: core.confirmation.transmitDelayEstimateMilliseconds,
            lastSentLastInOrder: Int(core.lastSentLastInOrder),
            lastControlSentNS: core.lastControlSentNanoseconds
        )
    }

    func handleInboundIdleFrame(
        nowNS: UInt64,
        txNS: UInt64,
        echoNS: UInt64,
        sendPortPresent: Bool
    ) throws -> InboundIdleSnapshot {
        let wire = try ObstacleBridgeMyUDPCodec.encodeWire(type: ObstacleBridgeMyUDPCodec.idleType, payload: Data(), transmittedNanoseconds: txNS, echoedNanoseconds: echoNS)
        let effect = try peerEngine.receiveWire(wire, nowNanoseconds: nowNS, transportWritable: sendPortPresent)
        synchronizePeerEngine(peerEngine.snapshot())
        let reflectedFrame = effect.outboundDatagrams.first
        let reflected = reflectedFrame != nil

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
        do {
            let effect = try peerEngine.receiveWire(frame, nowNanoseconds: nowNS, transportWritable: sendPortPresent)
            let core = peerEngine.snapshot()
            synchronizePeerEngine(core)
            if let parsed = ObstacleBridgeUdpOverlayCodec.parseProtocolFrame(frame),
               let chunks = ObstacleBridgeUdpOverlayCodec.decodeDataBatch(parsed.payload) {
                batchDatagramsReceived += 1
                batchChunksReceived += chunks.count
                batchStreamBytesReceived += chunks.reduce(0) { $0 + $1.data.count }
            }
            return .init(
                controlReasons: effect.outboundDatagrams.isEmpty ? [] : ["core"],
                emittedFrames: effect.outboundDatagrams,
                completedPayloads: effect.deliveredRecords,
                expected: Int(core.expectedCounter), pending: core.pendingCounters.map(Int.init),
                missing: core.missingCounters.map(Int.init),
                establishedNS: core.heartbeat.establishedNanoseconds,
                lastRxTxNS: core.heartbeat.lastReceivedTransmitNanoseconds,
                lastRxWallNS: core.heartbeat.lastReceivedWallNanoseconds,
                rttSampleMS: core.heartbeat.rttSampleMilliseconds,
                rttEstMS: core.heartbeat.rttEstimateMilliseconds,
                transmitDelayEstMS: core.confirmation.transmitDelayEstimateMilliseconds,
                lastSentLastInOrder: Int(core.lastSentLastInOrder),
                lastControlSentNS: core.lastControlSentNanoseconds
            )
        } catch {
            malformedBatches += 1
            return nil
        }
    }

    func protocolStatsSnapshot() -> [String: Any] {
        let core = peerEngine.snapshot()
        return [
            "buffered_frames": core.waitingRecordCount,
            "waiting_count": core.waitingRecordCount,
            "inflight": core.outstandingCounters.count,
            "max_inflight": core.maximumInFlight,
            "first_pass": core.confirmation.firstPassTotal,
            "repeated_once": core.confirmation.repeatedOnceTotal,
            "repeated_multiple": core.confirmation.repeatedMultipleTotal,
            "confirmed_total": core.confirmation.confirmedTotal,
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

    private func synchronizePeerEngine(_ snapshot: ObstacleBridgeMyUDPPeerEngine.Snapshot) {
        let heartbeat = snapshot.heartbeat
        establishedNS = heartbeat.establishedNanoseconds
        lastRxTxNS = heartbeat.lastReceivedTransmitNanoseconds
        lastRxWallNS = heartbeat.lastReceivedWallNanoseconds
        lastRttOkNS = heartbeat.lastRTTOkNanoseconds
        rttSampleMS = heartbeat.rttSampleMilliseconds
        rttEstMS = heartbeat.rttEstimateMilliseconds
        transmitDelayEstMS = snapshot.confirmation.transmitDelayEstimateMilliseconds
        confirmedTotal = snapshot.confirmation.confirmedTotal
        firstPassTotal = snapshot.confirmation.firstPassTotal
        repeatedOnceTotal = snapshot.confirmation.repeatedOnceTotal
        repeatedMultipleTotal = snapshot.confirmation.repeatedMultipleTotal
    }

}
