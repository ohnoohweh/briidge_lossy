import Foundation
import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgeCryptoTests {
    @Test func secureLinkRetryStateUsesBoundedMonotonicBackoff() {
        var state = ObstacleBridgeSecureLinkPSKRetryState(
            policy: .init(initialBackoff: 1, maximumBackoff: 5)
        )
        #expect(state.recordUnauthenticatedFailure(now: 10) == 1)
        #expect(state.consecutiveFailures == 1)
        #expect(state.remainingBackoff(now: 10.5) == 0.5)
        #expect(!state.isDue(now: 10.5))
        #expect(state.isDue(now: 11))
        #expect(state.recordUnauthenticatedFailure(now: 11) == 2)
        #expect(state.recordUnauthenticatedFailure(now: 13) == 4)
        #expect(state.recordUnauthenticatedFailure(now: 17) == 5)
        state.reset()
        #expect(state.consecutiveFailures == 0)
        #expect(state.retryNotBefore == nil)
    }

    @Test func channelMuxHeaderMatchesEstablishedWireShape() throws {
        let wire = try ObstacleBridgeChannelMuxCodec.encode(
            channelID: 0x0102,
            protocolType: .tcp,
            counter: 0x0304,
            messageType: .data,
            body: Data([0xaa, 0xbb])
        )
        #expect(wire == Data([0x01, 0x02, 0x01, 0x03, 0x04, 0x00, 0x00, 0x02, 0xaa, 0xbb]))
        #expect(try ObstacleBridgeChannelMuxCodec.decode(wire).body == Data([0xaa, 0xbb]))
        #expect(try ObstacleBridgeChannelMuxFrameCodec.decode(wire) == .init(channelID: 0x0102, protocolType: 1, counter: 0x0304, messageType: 0, body: Data([0xaa, 0xbb])))
        #expect(throws: ObstacleBridgeChannelMuxFrameCodecError.invalidFrame) {
            try ObstacleBridgeChannelMuxFrameCodec.decode(wire + Data([0]))
        }
        #expect(throws: ObstacleBridgeChannelMuxCodecError.invalidFrame) { try ObstacleBridgeChannelMuxCodec.decode(Data([0])) }
    }

    @Test func myudpDataFrameMatchesPythonV2Layout() throws {
        let wire = try ObstacleBridgeMyUDPCodec.encodeData(payload: Data("udp".utf8), counter: 7, transmittedNanoseconds: 0x0102, echoedNanoseconds: 0x0304)
        #expect(wire == Data([1, 0, 11, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 3, 4, 1, 1, 0, 7, 0, 7, 0, 3, 117, 100, 112]))
        #expect(try ObstacleBridgeMyUDPCodec.decodeData(wire) == .init(counter: 7, payload: Data("udp".utf8), transmittedNanoseconds: 0x0102, echoedNanoseconds: 0x0304))
        #expect(throws: ObstacleBridgeMyUDPCodecError.invalidFrame) { try ObstacleBridgeMyUDPCodec.decodeData(Data([1])) }
    }
    @Test func myudpBatchPayloadAndGenericEnvelopeAreCoreOwned() throws {
        let chunks: [ObstacleBridgeMyUDPStreamChunk] = [
            .init(counter: 7, payload: Data("abc".utf8)),
            .init(counter: 8, payload: Data("de".utf8)),
        ]
        let payload = try ObstacleBridgeMyUDPCodec.encodeDataBatchPayload(chunks)
        #expect(payload == Data([1, 2, 0, 7, 0, 7, 0, 3, 97, 98, 99, 0, 6, 0, 8, 0, 2, 100, 101]))
        #expect(try ObstacleBridgeMyUDPCodec.decodeDataBatchPayload(payload) == chunks)
        let idle = try ObstacleBridgeMyUDPCodec.encodeWire(type: ObstacleBridgeMyUDPCodec.idleType, payload: Data(), transmittedNanoseconds: 1, echoedNanoseconds: 2)
        #expect(try ObstacleBridgeMyUDPCodec.decodeWire(idle) == .init(type: 0, payload: Data(), transmittedNanoseconds: 1, echoedNanoseconds: 2))
    }
    @Test func myudpControlFrameRoundTripsAndRejectsTrailingBytes() throws {
        let wire = try ObstacleBridgeMyUDPCodec.encodeControl(lastInOrder: 4, highestReceived: 7, missing: [5, 6], transmittedNanoseconds: 8, echoedNanoseconds: 9)
        #expect(try ObstacleBridgeMyUDPCodec.decodeControl(wire) == .init(lastInOrder: 4, highestReceived: 7, missing: [5, 6], transmittedNanoseconds: 8, echoedNanoseconds: 9))
        #expect(throws: ObstacleBridgeMyUDPCodecError.invalidFrame) { try ObstacleBridgeMyUDPCodec.decodeControl(wire + Data([0])) }
    }
    @Test func myudpControlMissingListUsesPayloadDerivedLimit() throws {
        #expect(ObstacleBridgeMyUDPCodec.maximumControlMissingCount == 713)
        let missing = (1...ObstacleBridgeMyUDPCodec.maximumControlMissingCount).map(UInt16.init)
        let wire = try ObstacleBridgeMyUDPCodec.encodeControl(lastInOrder: 0, highestReceived: 713, missing: missing, transmittedNanoseconds: 8)
        #expect(wire.count == ObstacleBridgeMyUDPCodec.protocolHeaderSize + ObstacleBridgeMyUDPCodec.maximumBatchPayloadSize - 1)
        #expect(try ObstacleBridgeMyUDPCodec.decodeControl(wire).missing == missing)
        #expect(throws: ObstacleBridgeMyUDPCodecError.payloadTooLarge) {
            try ObstacleBridgeMyUDPCodec.encodeControl(lastInOrder: 0, highestReceived: 714, missing: missing + [714], transmittedNanoseconds: 8)
        }
    }

    @Test func myudpCoreStreamReceiveStateReordersSuppressesDuplicatesAndResets() throws {
        let state = ObstacleBridgeMyUDPStreamReceiveState()
        let record = try ObstacleBridgeMyUDPCodec.encodeStreamRecord(Data("ordered".utf8))
        let first = Data(record.prefix(3))
        let second = Data(record.dropFirst(3))

        #expect(try #require(state.process(.init(counter: 2, payload: second))).accepted == false)
        let delivered = try #require(state.process(.init(counter: 1, payload: first)))
        #expect(delivered.accepted)
        #expect(delivered.completedRecords == [Data("ordered".utf8)])
        #expect(state.expected == 3)
        #expect(state.missing.isEmpty)
        #expect(try #require(state.process(.init(counter: 1, payload: first))).accepted == false)

        state.reset()
        #expect(state.expected == 1)
        #expect(state.pending.isEmpty && state.missing.isEmpty)
    }
    @Test func myudpCoreStreamReceiveStateDerivesBoundedControlAcknowledgements() throws {
        let state = ObstacleBridgeMyUDPStreamReceiveState()
        let record = try ObstacleBridgeMyUDPCodec.encodeStreamRecord(Data("ack".utf8))
        let split = Data(record.prefix(2))
        let rest = Data(record.dropFirst(2))

        #expect(try #require(state.process(.init(counter: 2, payload: rest))).accepted == false)
        #expect(state.acknowledgement == .init(lastInOrder: 0, highestReceived: 2, missing: [1]))
        #expect(try #require(state.process(.init(counter: 1, payload: split))).completedRecords == [Data("ack".utf8)])
        #expect(state.acknowledgement == .init(lastInOrder: 2, highestReceived: 2, missing: []))
    }
    @Test func myudpCoreStreamReceiveStateUsesTheWireDerivedMissingLimit() throws {
        let state = ObstacleBridgeMyUDPStreamReceiveState()
        #expect(try #require(state.process(.init(counter: 714, payload: Data([0])))).accepted == false)
        let acknowledgement = state.acknowledgement
        #expect(acknowledgement.lastInOrder == 0)
        #expect(acknowledgement.highestReceived == 714)
        #expect(acknowledgement.missing == (1...713).map(UInt16.init))
        #expect(try ObstacleBridgeMyUDPCodec.encodeControl(
            lastInOrder: acknowledgement.lastInOrder,
            highestReceived: acknowledgement.highestReceived,
            missing: acknowledgement.missing,
            transmittedNanoseconds: 1
        ).count == ObstacleBridgeMyUDPCodec.protocolHeaderSize + ObstacleBridgeMyUDPCodec.maximumBatchPayloadSize - 1)
    }
    @Test func myudpCoreControlPolicyDistinguishesNewGapsAndTimerPacing() throws {
        #expect(ObstacleBridgeMyUDPControlPolicy.inbound(
            nowNanoseconds: 10, expectedCounter: 2, missingCount: 1, grewMissing: true,
            lastSentLastInOrder: 0, lastControlSentNanoseconds: 10, establishedNanoseconds: 1,
            rttEstimateMilliseconds: 100
        ) == .init(shouldEmit: true, reason: "inbound_grew_missing"))
        #expect(ObstacleBridgeMyUDPControlPolicy.timer(
            nowNanoseconds: 49_999_999, expectedCounter: 2, missingCount: 1,
            lastSentLastInOrder: 0, lastControlSentNanoseconds: 1, establishedNanoseconds: 1,
            rttEstimateMilliseconds: 100
        ) == .init(shouldEmit: false, reason: nil))
        #expect(ObstacleBridgeMyUDPControlPolicy.timer(
            nowNanoseconds: 50_000_001, expectedCounter: 2, missingCount: 1,
            lastSentLastInOrder: 0, lastControlSentNanoseconds: 1, establishedNanoseconds: 1,
            rttEstimateMilliseconds: 100
        ) == .init(shouldEmit: true, reason: "timer_paced_with_missing"))
    }
    @Test func myudpCoreRetransmissionPolicyPacesAndDeduplicatesCandidates() throws {
        let first = ObstacleBridgeMyUDPRetransmissionPolicy.plan(
            nowNanoseconds: 100, candidateCounters: [7, 7, 8], availableCounters: [7],
            firstTransmitNanoseconds: [7: 1], lastRetransmissionNanoseconds: [:],
            sendAttempts: [7: 1], peerReportedMissing: [7, 7], peerMissedCount: 2,
            lastSendNanoseconds: 1, windowNanoseconds: 50,
            useFirstTransmitWhenNoRetransmission: true
        )
        #expect(first.emittedCounters == [7])
        #expect(first.lastRetransmissionNanoseconds == [7: 100])
        #expect(first.sendAttempts == [7: 2])
        #expect(first.peerReportedMissing == [7])
        #expect(first.lastSendNanoseconds == 100)
        let paced = ObstacleBridgeMyUDPRetransmissionPolicy.plan(
            nowNanoseconds: 120, candidateCounters: [7], availableCounters: [7],
            firstTransmitNanoseconds: [7: 1], lastRetransmissionNanoseconds: first.lastRetransmissionNanoseconds,
            sendAttempts: first.sendAttempts, peerReportedMissing: first.peerReportedMissing,
            peerMissedCount: 1, lastSendNanoseconds: first.lastSendNanoseconds,
            windowNanoseconds: 50, useFirstTransmitWhenNoRetransmission: true
        )
        #expect(paced.emittedCounters.isEmpty)
        #expect(paced.lastSendNanoseconds == 100)
    }
    @Test func myudpCoreSendQueueCoalescesRecordsRespectsFlightWindowAndRollsCounters() throws {
        let queue = ObstacleBridgeMyUDPSendQueue(nextCounter: .max, maximumInFlight: 2)
        try queue.enqueue(Data("one".utf8), queuedAtNanoseconds: 10)
        try queue.enqueue(Data("two".utf8), queuedAtNanoseconds: 11)
        let batch = try #require(queue.dequeueBatch(inFlightCount: 0))
        #expect(batch.chunks.map(\.counter) == [.max, 1])
        #expect(batch.chunks.map(\.payload) == [try ObstacleBridgeMyUDPCodec.encodeStreamRecord(Data("one".utf8)), try ObstacleBridgeMyUDPCodec.encodeStreamRecord(Data("two".utf8))])
        #expect(batch.queuedAtNanoseconds == 10 && batch.waitingRecordCount == 0)
        #expect(queue.nextCounter == 2)
        try queue.enqueue(Data("blocked".utf8), queuedAtNanoseconds: 12)
        #expect(queue.dequeueBatch(inFlightCount: 2) == nil)
    }
    @Test func myudpCorePeerEngineOwnsQueueReceiveControlAndEpochReset() throws {
        let sender = ObstacleBridgeMyUDPPeerEngine(maximumInFlight: 2)
        try sender.enqueueApplicationRecord(Data("core-peer".utf8), nowNanoseconds: 1)
        #expect(sender.snapshot().waitingRecordCount == 1)
        let outbound = try sender.flush(nowNanoseconds: 2)
        #expect(outbound.outboundDatagrams.count == 1)
        #expect(sender.snapshot().outstandingCounters == outbound.outboundDataCounters)
        #expect(sender.snapshot().sendAttempts[outbound.outboundDataCounters[0]] == 1)
        let receiver = ObstacleBridgeMyUDPPeerEngine()
        let delivered = try receiver.receiveWire(outbound.outboundDatagrams[0], nowNanoseconds: 3)
        #expect(delivered.deliveredRecords == [Data("core-peer".utf8)])
        #expect(receiver.snapshot().expectedCounter == 2)
        #expect(try ObstacleBridgeMyUDPCodec.decodeControl(receiver.buildControlDatagram(nowNanoseconds: 4)).lastInOrder == 1)
        #expect(receiver.takeDeliveredRecord() == Data("core-peer".utf8))
        #expect(receiver.takeDeliveredRecord() == nil)
        #expect(delivered.outboundDatagrams.count == 1)
        _ = try sender.receiveWire(delivered.outboundDatagrams[0], nowNanoseconds: 4)
        sender.resetEpoch()
        #expect(try sender.flush(nowNanoseconds: 5).outboundDatagrams.isEmpty)
    }
    @Test func myudpCorePeerEngineUsesImmediateMissingAndTimedUnconfirmedRetransmission() throws {
        let engine = ObstacleBridgeMyUDPPeerEngine()
        try engine.enqueueApplicationRecord(Data("retry".utf8), nowNanoseconds: 1)
        let original = try engine.flush(nowNanoseconds: 10).outboundDatagrams[0]
        let sent = try ObstacleBridgeMyUDPCodec.decodeDataChunks(original)
        let control = try ObstacleBridgeMyUDPCodec.encodeControl(lastInOrder: 0, highestReceived: sent.chunks[0].counter, missing: [sent.chunks[0].counter], transmittedNanoseconds: 20)
        // Python retransmits a newly reported missing counter immediately;
        // timer sweeps then remain paced from that fresh envelope.
        #expect(try engine.receiveWire(control, nowNanoseconds: 20).outboundDatagrams.count == 1)
        #expect(try engine.tick(nowNanoseconds: 30, retransmissionWindowNanoseconds: 21, idleIntervalNanoseconds: .max).outboundDatagrams.isEmpty)
        #expect(try engine.tick(nowNanoseconds: 41, retransmissionWindowNanoseconds: 21, idleIntervalNanoseconds: .max).outboundDatagrams.count == 1)

        let unconfirmed = ObstacleBridgeMyUDPPeerEngine()
        try unconfirmed.enqueueApplicationRecord(Data("timeout".utf8), nowNanoseconds: 1)
        _ = try unconfirmed.flush(nowNanoseconds: 10)
        #expect(try unconfirmed.tick(nowNanoseconds: 30, retransmissionWindowNanoseconds: 21, idleIntervalNanoseconds: .max).outboundDatagrams.isEmpty)
        #expect(try unconfirmed.tick(nowNanoseconds: 31, retransmissionWindowNanoseconds: 21, idleIntervalNanoseconds: .max).outboundDatagrams.count == 1)
    }
    @Test func myudpCorePeerEngineSplitsMaximumControlRetransmissionIntoBoundedDatagrams() throws {
        let engine = ObstacleBridgeMyUDPPeerEngine(maximumInFlight: 800)
        let missing = (1...ObstacleBridgeMyUDPCodec.maximumControlMissingCount).map(UInt16.init)
        for counter in missing {
            try engine.enqueueApplicationRecord(Data([UInt8(truncatingIfNeeded: counter)]), nowNanoseconds: 1)
        }
        _ = try engine.flush(nowNanoseconds: 1)
        let control = try ObstacleBridgeMyUDPCodec.encodeControl(
            lastInOrder: 0,
            highestReceived: UInt16(ObstacleBridgeMyUDPCodec.maximumControlMissingCount),
            missing: missing,
            transmittedNanoseconds: 2
        )

        let retransmission = try engine.receiveWire(control, nowNanoseconds: 3)
        let retransmittedCounters = try retransmission.outboundDatagrams.flatMap {
            try ObstacleBridgeMyUDPCodec.decodeDataChunks($0).chunks.map(\.counter)
        }
        #expect(retransmittedCounters == missing)
        #expect(retransmission.outboundDatagrams.count == 12)
        #expect(retransmission.outboundDatagrams.allSatisfy {
            (try? ObstacleBridgeMyUDPCodec.decodeDataChunks($0).chunks.count) ?? 0 <= ObstacleBridgeMyUDPCodec.maximumBatchRecords
        })
    }
    @Test func myudpCorePeerRegistryIsolatesEpochsAndWithdrawals() throws {
        let registry = ObstacleBridgeMyUDPPeerRegistry()
        let old = ObstacleBridgeMyUDPPeerRegistry.PeerKey(identity: "peer", epoch: 1)
        let fresh = ObstacleBridgeMyUDPPeerRegistry.PeerKey(identity: "peer", epoch: 2)
        let reconnect = ObstacleBridgeMyUDPPeerRegistry.PeerKey(identity: "peer", epoch: 3)
        let concurrent = ObstacleBridgeMyUDPPeerRegistry.PeerKey(identity: "other-peer", epoch: 1)
        func inbound(_ payload: String, counter: UInt16, at time: UInt64) throws -> Data {
            try ObstacleBridgeMyUDPCodec.encodeData(
                payload: try ObstacleBridgeMyUDPCodec.encodeStreamRecord(Data(payload.utf8)),
                counter: counter,
                transmittedNanoseconds: time
            )
        }
        #expect(try registry.receiveWire(inbound("other", counter: 1, at: 1), from: concurrent, nowNanoseconds: 1).deliveredRecords == [Data("other".utf8)])
        #expect(try registry.receiveWire(inbound("late", counter: 2, at: 2), from: old, nowNanoseconds: 2).deliveredRecords.isEmpty)
        #expect(try registry.receiveWire(inbound("old", counter: 1, at: 3), from: old, nowNanoseconds: 3).deliveredRecords == [Data("old".utf8), Data("late".utf8)])
        #expect(try registry.receiveWire(inbound("duplicate", counter: 1, at: 5), from: old, nowNanoseconds: 5).deliveredRecords.isEmpty)
        #expect(try registry.receiveWire(inbound("fresh", counter: 1, at: 2), from: fresh, nowNanoseconds: 2).deliveredRecords == [Data("fresh".utf8)])
        #expect(registry.activeKeys == Set([fresh, concurrent]))
        #expect(throws: ObstacleBridgeMyUDPPeerRegistryError.staleEpoch) {
            _ = try registry.receiveWire(inbound("stale", counter: 2, at: 3), from: old, nowNanoseconds: 3)
        }
        #expect(try registry.receiveWire(inbound("other-again", counter: 2, at: 6), from: concurrent, nowNanoseconds: 6).deliveredRecords == [Data("other-again".utf8)])
        registry.touch(fresh, nowNanoseconds: 20)
        #expect(registry.expire(nowNanoseconds: 25, idleTimeoutNanoseconds: 10) == [concurrent])
        #expect(try registry.receiveWire(inbound("fresh-again", counter: 2, at: 26), from: fresh, nowNanoseconds: 26).deliveredRecords == [Data("fresh-again".utf8)])
        registry.withdraw(identity: "peer", exceptEpoch: 2)
        #expect(registry.activeKeys == Set([fresh]))
        registry.withdraw(identity: "peer", exceptEpoch: reconnect.epoch)
        #expect(try registry.receiveWire(inbound("reconnected", counter: 1, at: 30), from: reconnect, nowNanoseconds: 30).deliveredRecords == [Data("reconnected".utf8)])
        #expect(registry.activeKeys == Set([reconnect]))
    }
    @Test func myudpCoreAcknowledgementPolicyRetainsOnlyReportedGaps() throws {
        let plan = ObstacleBridgeMyUDPAcknowledgementPolicy.plan(
            outstandingCounters: [1, 2, 3], peerReportedMissing: [3],
            lastInOrder: 1, highestReceived: 3, missing: [3]
        )
        #expect(plan.retainedCounters == [3])
        #expect(plan.peerReportedMissing == [3])
        #expect(plan.lastAcknowledgedByPeer == 1)
        #expect(ObstacleBridgeMyUDPAcknowledgementPolicy.plan(
            outstandingCounters: [4], peerReportedMissing: [4],
            lastInOrder: 0, highestReceived: 0, missing: []
        ) == .init(retainedCounters: [4], peerReportedMissing: [4], lastAcknowledgedByPeer: 0))
    }
    @Test func myudpCoreHeartbeatPolicyTracksRttIdleDelayAndLiveness() throws {
        let initial = ObstacleBridgeMyUDPHeartbeatSnapshot(establishedNanoseconds: 0, lastReceivedTransmitNanoseconds: 0, lastReceivedWallNanoseconds: 0, lastRTTOkNanoseconds: 0, rttSampleMilliseconds: 0, rttEstimateMilliseconds: 0, transmitDelayEstimateMilliseconds: 0)
        let update = ObstacleBridgeMyUDPHeartbeatPolicy.update(nowNanoseconds: 200_000_000, transmittedNanoseconds: 9, echoedNanoseconds: 100_000_000, fromIdle: true, prior: initial)
        #expect(update.rttSampleMilliseconds == 100 && update.rttEstimateMilliseconds == 100 && update.transmitDelayEstimateMilliseconds == 50)
        #expect(ObstacleBridgeMyUDPHeartbeatPolicy.isConnected(nowNanoseconds: 20_100_000_000, lastRTTOkNanoseconds: update.lastRTTOkNanoseconds))
        #expect(!ObstacleBridgeMyUDPHeartbeatPolicy.isConnected(nowNanoseconds: 20_200_000_001, lastRTTOkNanoseconds: update.lastRTTOkNanoseconds))
    }
    @Test func myudpCoreEchoAndIdlePoliciesPinOutboundTimingEffects() throws {
        #expect(ObstacleBridgeMyUDPEchoPolicy.echoedNanoseconds(
            nowNanoseconds: 150, lastReceivedTransmitNanoseconds: 90, lastReceivedWallNanoseconds: 100
        ) == 140)
        #expect(ObstacleBridgeMyUDPEchoPolicy.echoedNanoseconds(
            nowNanoseconds: 99, lastReceivedTransmitNanoseconds: 90, lastReceivedWallNanoseconds: 100
        ) == 0)
        #expect(ObstacleBridgeMyUDPIdlePolicy.shouldReflect(echoedNanoseconds: 0, transportWritable: true))
        #expect(!ObstacleBridgeMyUDPIdlePolicy.shouldReflect(echoedNanoseconds: 1, transportWritable: true))
        #expect(!ObstacleBridgeMyUDPIdlePolicy.shouldReflect(echoedNanoseconds: 0, transportWritable: false))
    }
    @Test func myudpCoreReceiverEngineComposesReassemblyHeartbeatAndControl() throws {
        let engine = ObstacleBridgeMyUDPReceiverEngine()
        let record = try ObstacleBridgeMyUDPCodec.encodeStreamRecord(Data("engine".utf8))
        let delayed = try #require(engine.processData(
            chunks: [.init(counter: 2, payload: Data(record.dropFirst(3)))],
            nowNanoseconds: 100, transmittedNanoseconds: 10, echoedNanoseconds: 0, transportWritable: true
        ))
        #expect(delayed.completedRecords.isEmpty)
        #expect(delayed.acknowledgement == .init(lastInOrder: 0, highestReceived: 2, missing: [1]))
        #expect(delayed.controlReasons == ["inbound_grew_missing"])
        let control = try ObstacleBridgeMyUDPCodec.decodeControl(try engine.buildControlDatagram(nowNanoseconds: 101))
        #expect(control.missing == [1] && control.echoedNanoseconds == 11)
        let delivered = try #require(engine.processData(
            chunks: [.init(counter: 1, payload: Data(record.prefix(3)))],
            nowNanoseconds: 102, transmittedNanoseconds: 12, echoedNanoseconds: 0, transportWritable: true
        ))
        #expect(delivered.completedRecords == [Data("engine".utf8)])
        #expect(delivered.controlReasons == ["gap_filled_ack", "advanced_in_order"])
        #expect(engine.processIdle(
            nowNanoseconds: 103, transmittedNanoseconds: 13, echoedNanoseconds: 0, transportWritable: true
        ).shouldReflect)
        engine.reset()
        #expect(engine.receiveState.expected == 1 && engine.heartbeat.establishedNanoseconds == 0)
    }
    @Test func myudpCoreConfirmationMetricsMatchPythonDelayAndAttemptBuckets() throws {
        let initial = ObstacleBridgeMyUDPConfirmationMetrics(
            transmitDelaySampleMilliseconds: 0, transmitDelayEstimateMilliseconds: 10,
            confirmedTotal: 2, firstPassTotal: 1, repeatedOnceTotal: 1, repeatedMultipleTotal: 0
        )
        let finalized = ObstacleBridgeMyUDPConfirmationMetricsPolicy.finalize(
            confirmedCounters: [7, 8, 9], pathStartNanoseconds: [7: 100_000_000, 8: 120_000_000],
            firstTransmitNanoseconds: [9: 150_000_000], sendAttempts: [7: 1, 8: 2, 9: 4],
            acknowledgementNanoseconds: 300_000_000, rttEstimateMilliseconds: 100, prior: initial
        )
        #expect(finalized.transmitDelaySampleMilliseconds == 100)
        #expect(abs(finalized.transmitDelayEstimateMilliseconds - 141.5625) < 0.0001)
        #expect(finalized.confirmedTotal == 5)
        #expect(finalized.firstPassTotal == 2)
        #expect(finalized.repeatedOnceTotal == 2)
        #expect(finalized.repeatedMultipleTotal == 1)
        #expect(ObstacleBridgeMyUDPConfirmationMetricsPolicy.rebaseTransmitDelayEstimate(
            outstandingCount: 0, rttEstimateMilliseconds: 80, priorEstimateMilliseconds: finalized.transmitDelayEstimateMilliseconds
        ) == 40)
    }
    @Test func myudpCoreSenderLedgerCleansAcknowledgedChunksAndMetrics() throws {
        let ledger = ObstacleBridgeMyUDPSenderLedger(maximumInFlight: 2)
        try ledger.enqueue(Data("one".utf8), at: 10)
        try ledger.enqueue(Data("two".utf8), at: 20)
        #expect(try #require(ledger.dequeueBatch(nowNanoseconds: 100)).chunks.map(\.counter) == [1, 2])
        let feedback = ledger.applyControl(lastInOrder: 1, highestReceived: 2, missing: [2], nowNanoseconds: 200_000_000, rttEstimateMilliseconds: 100)
        #expect(feedback.retainedCounters == [2])
        #expect(feedback.metrics.confirmedTotal == 1 && feedback.metrics.firstPassTotal == 1)
        #expect(ledger.outstandingCounters == [2])
    }
    @Test func secureLinkFrameEnvelopePreservesFlagsAndRejectsTruncation() throws {
        let wire = ObstacleBridgeSecureLinkFrameCodec.encode(
            type: 4, sessionID: 0x0102, counter: 3, payload: Data("payload".utf8), flags: 0x7f
        )
        #expect(try ObstacleBridgeSecureLinkFrameCodec.decode(wire) == .init(
            type: 4, sessionID: 0x0102, counter: 3,
            header: Data(wire.prefix(ObstacleBridgeSecureLinkFrameCodec.headerLength)), payload: Data("payload".utf8)
        ))
        #expect(throws: ObstacleBridgeSecureLinkFrameCodecError.invalidFrame) {
            try ObstacleBridgeSecureLinkFrameCodec.decode(Data(wire.prefix(19)))
        }
    }
    @Test func hashesAndKeyDerivationMatchKnownAnswerVectors() throws {
        #expect(ObstacleBridgeCrypto.sha256(Data("abc".utf8)).hex == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        #expect(try ObstacleBridgeCrypto.hmacSHA256(key: Data("key".utf8), message: Data("The quick brown fox jumps over the lazy dog".utf8)).hex == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
        #expect(try ObstacleBridgeCrypto.hkdfSHA256(salt: .hex("000102030405060708090a0b0c"), info: .hex("f0f1f2f3f4f5f6f7f8f9"), keyMaterial: Data(repeating: 0x0b, count: 22), outputByteCount: 42).hex == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        #expect(try ObstacleBridgeCrypto.pbkdf2SHA256(password: Data("password".utf8), salt: Data("salt".utf8), iterations: 2, outputByteCount: 32).hex == "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
    }

    @Test func authenticatedEncryptionMatchesKnownAnswerVectorsAndFailsClosed() throws {
        let zeroKey = Data(repeating: 0, count: 32)
        let zeroNonce = Data(repeating: 0, count: 12)
        let aes = try ObstacleBridgeCrypto.aesGCMSeal(plaintext: Data(repeating: 0, count: 16), key: zeroKey, nonce: zeroNonce)
        #expect(aes.hex == "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919")
        #expect(try ObstacleBridgeCrypto.aesGCMOpen(ciphertextAndTag: aes, key: zeroKey, nonce: zeroNonce) == Data(repeating: 0, count: 16))

        let chacha = try ObstacleBridgeCrypto.chaChaPolySeal(
            plaintext: Data("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".utf8),
            key: .hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
            nonce: .hex("070000004041424344454647"),
            authenticatedData: .hex("50515253c0c1c2c3c4c5c6c7")
        )
        #expect(chacha.hex == "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691")
        var tampered = chacha
        tampered[tampered.startIndex] ^= 0x01
        #expect(throws: ObstacleBridgeCryptoError.authenticationFailed) {
            try ObstacleBridgeCrypto.chaChaPolyOpen(ciphertextAndTag: tampered, key: .hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"), nonce: .hex("070000004041424344454647"), authenticatedData: .hex("50515253c0c1c2c3c4c5c6c7"))
        }
    }

    @Test func curve25519MatchesKnownAnswerVectors() throws {
        let edPrivate = Data.hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        let edPublic = try ObstacleBridgeCrypto.ed25519PublicKey(privateKey: edPrivate)
        #expect(edPublic.hex == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        let signature = try ObstacleBridgeCrypto.ed25519Sign(message: Data(), privateKey: edPrivate)
        #expect(signature.hex == "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\n5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b".replacingOccurrences(of: "\n", with: ""))
        #expect(try ObstacleBridgeCrypto.ed25519Verify(signature: signature, message: Data(), publicKey: edPublic))

        let alicePrivate = Data.hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let bobPrivate = Data.hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        let shared = try ObstacleBridgeCrypto.x25519SharedSecret(privateKey: alicePrivate, peerPublicKey: try ObstacleBridgeCrypto.x25519PublicKey(privateKey: bobPrivate))
        #expect(shared.hex == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

        let generatedEdPrivate = ObstacleBridgeCrypto.generateEd25519PrivateKey()
        #expect(generatedEdPrivate.count == 32)
        let generatedEdPublic = try ObstacleBridgeCrypto.ed25519PublicKey(privateKey: generatedEdPrivate)
        #expect(try ObstacleBridgeCrypto.ed25519Verify(
            signature: ObstacleBridgeCrypto.ed25519Sign(message: Data("core".utf8), privateKey: generatedEdPrivate),
            message: Data("core".utf8), publicKey: generatedEdPublic
        ))

        let generatedXPrivate = ObstacleBridgeCrypto.generateX25519PrivateKey()
        #expect(generatedXPrivate.count == 32)
        #expect(try ObstacleBridgeCrypto.x25519PublicKey(privateKey: generatedXPrivate).count == 32)
    }

    @Test func secureLinkPskTranscriptMatchesPythonVector() throws {
        let psk = Data(0..<32)
        let clientNonce = Data(0x20..<0x40)
        let serverNonce = Data(0x40..<0x60)
        let sessionID: UInt64 = 0x0102_0304_0506_0708
        let keys = try ObstacleBridgeSecureLinkPSKCrypto.deriveKeys(psk: psk, sessionID: sessionID, clientNonce: clientNonce, serverNonce: serverNonce)
        #expect(keys.clientToServer.hex == "585889eaa8cfcdb9ffc033d5959a54a086e823a3c7e491fe451d94ba824d1361")
        #expect(keys.serverToClient.hex == "026e7f54ab86773658da9ded1bfecd6216d5a3275c7b658adb290b80a8973570")
        #expect(try ObstacleBridgeSecureLinkPSKCrypto.serverProof(psk: psk, sessionID: sessionID, clientNonce: clientNonce, serverNonce: serverNonce).hex == "ad55f84b7533f9b4358694fd88069ab9de2d53708fd66471e83d82db2b4a9e60")
        #expect(try ObstacleBridgeSecureLinkPSKCrypto.clientRekeyCommitProof(psk: psk, sessionID: sessionID, clientNonce: clientNonce, serverNonce: serverNonce).hex == "ad06b7c23e7cd546b0b700ed1dc4dbb3a655f14ca3df8d580e98cd398b196991")
    }

    @Test func secureLinkPskServerCompletesPortableClientHandshake() throws {
        let psk = Data("linux-server-psk".utf8)
        let sessionID: UInt64 = 0x0102_0304_0506_0708
        let clientNonce = Data(0..<32)
        let serverNonce = Data(0x20..<0x40)
        let client = try ObstacleBridgeSecureLinkPSKClient(psk: psk)
        let server = try ObstacleBridgeSecureLinkPSKServer(psk: psk)
        let proof = try client.handleServerHello(server.handleClientHello(try client.begin(sessionID: sessionID, clientNonce: clientNonce), serverNonce: serverNonce))
        try client.handleServerAcknowledgement(server.handleClientProof(proof))
        #expect(client.isAuthenticated && server.isAuthenticated)
        #expect(client.state.authenticatedGenerationsTotal == 1)
        #expect(server.state.authenticatedGenerationsTotal == 1)
        #expect(client.state.rekeysCompletedTotal == 0)
        #expect(server.state.rekeysCompletedTotal == 0)
        #expect(try server.unprotect(client.protect(Data("python-client".utf8))) == Data("python-client".utf8))
        #expect(try client.unprotect(server.protect(Data("linux-server".utf8))) == Data("linux-server".utf8))
    }

    @Test func secureLinkPskClientPollsInjectedFrameAndTimeRekeyPolicies() throws {
        var monotonicTime: TimeInterval = 0
        let psk = Data("automatic-rekey-psk".utf8)
        let frameClient = try ObstacleBridgeSecureLinkPSKClient(
            psk: psk,
            timeProvider: { monotonicTime },
            rekeyPolicy: .init(afterProtectedFrames: 1),
            sessionIDProvider: { 8 },
            randomBytes: { _ in Data(repeating: 3, count: 32) }
        )
        let frameServer = try ObstacleBridgeSecureLinkPSKServer(psk: psk)
        let frameProof = try frameClient.handleServerHello(frameServer.handleClientHello(
            try frameClient.begin(sessionID: 7, clientNonce: Data(repeating: 1, count: 32)),
            serverNonce: Data(repeating: 2, count: 32)
        ))
        try frameClient.handleServerAcknowledgement(frameServer.handleClientProof(frameProof))
        #expect(try frameClient.pollAutomaticRekey() == nil)
        _ = try frameClient.protect(Data("one-frame".utf8))
        let frameTriggeredHello = try #require(try frameClient.pollAutomaticRekey())
        let decodedFrameHello = try ObstacleBridgeSecureLinkFrameCodec.decode(frameTriggeredHello)
        #expect(decodedFrameHello.type == ObstacleBridgeSecureLinkPSKFrameType.rekeyHello)
        #expect(decodedFrameHello.sessionID == 8)
        #expect(decodedFrameHello.payload == Data(repeating: 3, count: 32) + Data([1, 0]))

        let timeClient = try ObstacleBridgeSecureLinkPSKClient(
            psk: psk,
            timeProvider: { monotonicTime },
            rekeyPolicy: .init(afterAuthenticatedSeconds: 60),
            sessionIDProvider: { 10 },
            randomBytes: { _ in Data(repeating: 5, count: 32) }
        )
        let timeServer = try ObstacleBridgeSecureLinkPSKServer(psk: psk)
        let timeProof = try timeClient.handleServerHello(timeServer.handleClientHello(
            try timeClient.begin(sessionID: 9, clientNonce: Data(repeating: 4, count: 32)),
            serverNonce: Data(repeating: 6, count: 32)
        ))
        try timeClient.handleServerAcknowledgement(timeServer.handleClientProof(timeProof))
        monotonicTime = 59
        #expect(try timeClient.pollAutomaticRekey() == nil)
        monotonicTime = 60
        let timeTriggeredHello = try #require(try timeClient.pollAutomaticRekey())
        #expect(try ObstacleBridgeSecureLinkFrameCodec.decode(timeTriggeredHello).sessionID == 10)
    }

    @Test func secureLinkPskPeersCompleteRekeyAndResetDirectionalCounters() throws {
        let psk = Data("portable-rekey-psk".utf8)
        var monotonicTime: TimeInterval = 0
        let client = try ObstacleBridgeSecureLinkPSKClient(psk: psk)
        let server = try ObstacleBridgeSecureLinkPSKServer(psk: psk, timeProvider: { monotonicTime })
        let proof = try client.handleServerHello(server.handleClientHello(
            try client.begin(sessionID: 7, clientNonce: Data(repeating: 1, count: 32)),
            serverNonce: Data(repeating: 2, count: 32)
        ))
        try client.handleServerAcknowledgement(server.handleClientProof(proof))
        #expect(client.state == .init(
            sessionID: 7,
            txCounter: 2,
            rxCounter: 1,
            authenticated: true,
            pendingRekeySessionID: 0,
            applicationSendingBlocked: false,
            authenticatedGenerationsTotal: 1,
            rekeysCompletedTotal: 0
        ))

        let oldGenerationFrame = try client.protect(Data("before-rekey".utf8))
        #expect(try server.unprotect(oldGenerationFrame) == Data("before-rekey".utf8))

        let rekeyHello = try client.beginRekey(
            sessionID: 8,
            clientNonce: Data(repeating: 3, count: 32)
        )
        let rekeyReply = try server.handleRekeyHello(
            rekeyHello,
            serverNonce: Data(repeating: 4, count: 32)
        )
        // This DATA has already left the client on the active generation when
        // the server processes the later commit. The bounded server overlap
        // admits it instead of turning a healthy in-flight packet into loss.
        let inFlightOldGenerationFrame = try client.protect(Data("in-flight-old-generation".utf8))
        let expiredInFlightOldGenerationFrame = try client.protect(Data("expired-in-flight-old-generation".utf8))
        let rekeyCommit = try client.handleRekeyReply(rekeyReply)
        #expect(client.state.pendingRekeySessionID == 8)
        #expect(client.state.applicationSendingBlocked)
        #expect(try client.handleRekeyReply(rekeyReply) == rekeyCommit)
        #expect(throws: ObstacleBridgeSecureLinkPSKClientError.invalidState) {
            try client.protect(Data("between-commit-and-done".utf8))
        }
        let rekeyDone = try server.handleRekeyCommit(rekeyCommit)
        #expect(try server.handleRekeyCommit(rekeyCommit) == rekeyDone)
        #expect(try server.unprotect(inFlightOldGenerationFrame) == Data("in-flight-old-generation".utf8))
        #expect(throws: ObstacleBridgeSecureLinkPSKClientError.replayedFrame) {
            try server.unprotect(oldGenerationFrame)
        }
        let oldParsed = try ObstacleBridgeSecureLinkFrameCodec.decode(expiredInFlightOldGenerationFrame)
        let unrelatedSessionFrame = ObstacleBridgeSecureLinkFrameCodec.encode(
            type: ObstacleBridgeSecureLinkPSKFrameType.authenticatedData,
            sessionID: 99,
            counter: oldParsed.counter,
            payload: oldParsed.payload
        )
        #expect(throws: ObstacleBridgeSecureLinkPSKClientError.invalidFrame) {
            try server.unprotect(unrelatedSessionFrame)
        }
        monotonicTime = 5.001
        #expect(throws: ObstacleBridgeSecureLinkPSKClientError.invalidFrame) {
            try server.unprotect(expiredInFlightOldGenerationFrame)
        }
        try client.handleRekeyDone(rekeyDone)
        #expect(client.state.authenticatedGenerationsTotal == 2)
        #expect(server.state.authenticatedGenerationsTotal == 2)
        #expect(client.state.rekeysCompletedTotal == 1)
        #expect(server.state.rekeysCompletedTotal == 1)
        #expect(client.state == .init(
            sessionID: 8,
            txCounter: 1,
            rxCounter: 0,
            authenticated: true,
            pendingRekeySessionID: 0,
            applicationSendingBlocked: false,
            authenticatedGenerationsTotal: 2,
            rekeysCompletedTotal: 1
        ))
        #expect(server.state == .init(
            sessionID: 8,
            txCounter: 1,
            rxCounter: 0,
            authenticated: true,
            pendingRekeySessionID: 0,
            applicationSendingBlocked: false,
            authenticatedGenerationsTotal: 2,
            rekeysCompletedTotal: 1
        ))

        #expect(try ObstacleBridgeSecureLinkFrameCodec.decode(rekeyHello).type == ObstacleBridgeSecureLinkPSKFrameType.rekeyHello)
        #expect(try ObstacleBridgeSecureLinkFrameCodec.decode(rekeyReply).type == ObstacleBridgeSecureLinkPSKFrameType.rekeyReply)
        #expect(try ObstacleBridgeSecureLinkFrameCodec.decode(rekeyCommit).type == ObstacleBridgeSecureLinkPSKFrameType.rekeyCommit)
        #expect(try ObstacleBridgeSecureLinkFrameCodec.decode(rekeyDone).type == ObstacleBridgeSecureLinkPSKFrameType.rekeyDone)
        #expect(client.isAuthenticated && server.isAuthenticated)

        let clientFrame = try client.protect(Data("new-client".utf8))
        let decodedClientFrame = try ObstacleBridgeSecureLinkFrameCodec.decode(clientFrame)
        #expect(decodedClientFrame.sessionID == 8 && decodedClientFrame.counter == 1)
        #expect(try server.unprotect(clientFrame) == Data("new-client".utf8))

        let serverFrame = try server.protect(Data("new-server".utf8))
        let decodedServerFrame = try ObstacleBridgeSecureLinkFrameCodec.decode(serverFrame)
        #expect(decodedServerFrame.sessionID == 8 && decodedServerFrame.counter == 1)
        #expect(try client.unprotect(serverFrame) == Data("new-server".utf8))
    }

    @Test func secureLinkPskClientExpiresPendingRekeyUsingInjectedClock() throws {
        var monotonicTime: TimeInterval = 0
        let psk = Data("client-rekey-deadline-psk".utf8)
        let client = try ObstacleBridgeSecureLinkPSKClient(
            psk: psk,
            handshakeTimeout: 60,
            timeProvider: { monotonicTime }
        )
        let server = try ObstacleBridgeSecureLinkPSKServer(psk: psk)
        let proof = try client.handleServerHello(server.handleClientHello(
            try client.begin(sessionID: 7, clientNonce: Data(repeating: 1, count: 32)),
            serverNonce: Data(repeating: 2, count: 32)
        ))
        try client.handleServerAcknowledgement(server.handleClientProof(proof))
        _ = try client.beginRekey(sessionID: 8, clientNonce: Data(repeating: 3, count: 32))
        monotonicTime = 60
        #expect(throws: ObstacleBridgeSecureLinkPSKClientError.handshakeTimedOut) {
            try client.expireHandshakeIfNeeded()
        }
        #expect(!client.isAuthenticated)
        #expect(throws: ObstacleBridgeSecureLinkPSKClientError.invalidState) {
            try client.protect(Data("after-rekey-timeout".utf8))
        }
    }

    @Test func secureLinkPskServerExpiresPendingRekeyWithoutRenewingRetransmitDeadline() throws {
        var monotonicTime: TimeInterval = 0
        let psk = Data("server-rekey-deadline-psk".utf8)
        let client = try ObstacleBridgeSecureLinkPSKClient(psk: psk)
        let server = try ObstacleBridgeSecureLinkPSKServer(
            psk: psk,
            handshakeTimeout: 60,
            timeProvider: { monotonicTime }
        )
        let proof = try client.handleServerHello(server.handleClientHello(
            try client.begin(sessionID: 7, clientNonce: Data(repeating: 1, count: 32)),
            serverNonce: Data(repeating: 2, count: 32)
        ))
        try client.handleServerAcknowledgement(server.handleClientProof(proof))
        let rekeyHello = try client.beginRekey(sessionID: 8, clientNonce: Data(repeating: 3, count: 32))
        let firstReply = try server.handleRekeyHello(rekeyHello, serverNonce: Data(repeating: 4, count: 32))
        monotonicTime = 30
        let retransmitReply = try server.handleRekeyHello(rekeyHello, serverNonce: Data(repeating: 5, count: 32))
        #expect(retransmitReply == firstReply)
        monotonicTime = 60
        #expect(throws: ObstacleBridgeSecureLinkPSKClientError.handshakeTimedOut) {
            try server.expireHandshakeIfNeeded()
        }
        #expect(!server.isAuthenticated)
        #expect(throws: ObstacleBridgeSecureLinkPSKClientError.invalidState) {
            try server.protect(Data("after-rekey-timeout".utf8))
        }
    }

    @Test func secureLinkPskClientExpiresUnconfirmedHandshakeUsingInjectedClock() throws {
        var monotonicTime: TimeInterval = 100
        let client = try ObstacleBridgeSecureLinkPSKClient(
            psk: Data("deadline-psk".utf8),
            handshakeTimeout: 60,
            timeProvider: { monotonicTime }
        )
        _ = try client.begin(sessionID: 7, clientNonce: Data(repeating: 1, count: 32))
        monotonicTime = 160
        #expect(throws: ObstacleBridgeSecureLinkPSKClientError.handshakeTimedOut) {
            try client.expireHandshakeIfNeeded()
        }
        #expect(!client.isAuthenticated)
        #expect(throws: ObstacleBridgeSecureLinkPSKClientError.invalidState) {
            try client.protect(Data("after-timeout".utf8))
        }
    }

    @Test func secureLinkPskServerExpiresUnconfirmedHandshakeUsingInjectedClock() throws {
        var monotonicTime: TimeInterval = 10
        let client = try ObstacleBridgeSecureLinkPSKClient(psk: Data("deadline-psk".utf8))
        let server = try ObstacleBridgeSecureLinkPSKServer(
            psk: Data("deadline-psk".utf8),
            handshakeTimeout: 60,
            timeProvider: { monotonicTime }
        )
        let hello = try client.begin(sessionID: 7, clientNonce: Data(repeating: 1, count: 32))
        _ = try server.handleClientHello(hello, serverNonce: Data(repeating: 2, count: 32))
        monotonicTime = 70
        #expect(throws: ObstacleBridgeSecureLinkPSKClientError.handshakeTimedOut) {
            try server.expireHandshakeIfNeeded()
        }
        #expect(!server.isAuthenticated)
        #expect(throws: ObstacleBridgeSecureLinkPSKClientError.invalidState) {
            try server.protect(Data("after-timeout".utf8))
        }
    }

    @Test func secureLinkPskServerSerializesConcurrentProtectedSends() async throws {
        let psk = Data("concurrent-server-psk".utf8)
        let client = try ObstacleBridgeSecureLinkPSKClient(psk: psk)
        let server = try ObstacleBridgeSecureLinkPSKServer(psk: psk)
        let proof = try client.handleServerHello(server.handleClientHello(
            try client.begin(sessionID: 9, clientNonce: Data(repeating: 1, count: 32)),
            serverNonce: Data(repeating: 2, count: 32)
        ))
        try client.handleServerAcknowledgement(server.handleClientProof(proof))

        let frames = try await withThrowingTaskGroup(of: Data.self, returning: [Data].self) { group in
            for value in 0..<32 {
                group.addTask {
                    try server.protect(Data([UInt8(value)]))
                }
            }
            var collected = [Data]()
            for try await frame in group {
                collected.append(frame)
            }
            return collected
        }
        let counters = try frames.map { try ObstacleBridgeSecureLinkFrameCodec.decode($0).counter }
        #expect(Set(counters).count == 32)
        #expect(Set(counters) == Set(2...33))
    }

    @Test func invalidSizesAreRejectedBeforeCryptoOperations() throws {
        #expect(throws: ObstacleBridgeCryptoError.invalidKeyLength(expected: 32, actual: 31)) {
            try ObstacleBridgeCrypto.aesGCMSeal(plaintext: Data(), key: Data(repeating: 0, count: 31), nonce: Data(repeating: 0, count: 12))
        }
        #expect(throws: ObstacleBridgeCryptoError.invalidNonceLength(expected: 12, actual: 11)) {
            try ObstacleBridgeCrypto.chaChaPolySeal(plaintext: Data(), key: Data(repeating: 0, count: 32), nonce: Data(repeating: 0, count: 11))
        }
    }
}

struct ObstacleBridgeCorePortTests {
    @Test func channelMuxReplyPolicyAdmitsOneAwaitedFrame() throws {
        let policy = ObstacleBridgeChannelMuxReplyPolicy()
        let frame = ObstacleBridgeChannelMuxFrame(channelID: 3, protocolType: .tcp, counter: 4, messageType: .data, body: Data())
        #expect(try !policy.beginExchange(frame))
        #expect(throws: ObstacleBridgeChannelMuxReplyPolicyError.tooManyInFlightFrames) { try policy.beginExchange(frame) }
        policy.finishExchange(); policy.activateReceiveOwner()
        #expect(try policy.beginExchange(frame))
        #expect(policy.matchesAwaitedReply(frame))
        #expect(!policy.matchesAwaitedReply(.init(channelID: 4, protocolType: .tcp, counter: 4, messageType: .data, body: Data())))
        policy.finishExchange()
    }

    @Test func corePortsUseOnlyValueTypesAtTheAdapterBoundary() throws {
        let endpoint = ObstacleBridgeEndpoint(host: "192.0.2.10", port: 443)
        #expect(endpoint == ObstacleBridgeEndpoint(host: "192.0.2.10", port: 443))
        #expect(ObstacleBridgeIPAddress("2001:db8::10").text == "2001:db8::10")
        #expect(
            ObstacleBridgeCoreEvent.transportConnected(epoch: 4, endpoint: endpoint)
                == .transportConnected(epoch: 4, endpoint: endpoint)
        )

        let resolver = StaticResolver()
        #expect(try resolver.resolve("bridge.example", port: 443) == [endpoint])
        #expect(FixedClock().nowNanoseconds() == 42)
    }

    private struct FixedClock: ObstacleBridgeClock {
        func nowNanoseconds() -> UInt64 { 42 }
    }

    private struct StaticResolver: ObstacleBridgeResolver {
        func resolve(_ host: String, port: UInt16) throws -> [ObstacleBridgeEndpoint] {
            [ObstacleBridgeEndpoint(host: "192.0.2.10", port: port)]
        }
    }
}

struct ObstacleBridgeCoreCodecTests {
    @Test func boundedBinaryCodecAndServiceWireFormatsRoundTrip() throws {
        var writer = ObstacleBridgeBinaryWriter()
        writer.append(UInt8(7)); writer.append(UInt16(0x0102)); writer.append(UInt32(0x0304_0506)); writer.append(UInt64(0x0708_090a_0b0c_0d0e))
        var reader = ObstacleBridgeBinaryReader(writer.encoded)
        #expect(try reader.readUInt8() == 7)
        #expect(try reader.readUInt16() == 0x0102)
        #expect(try reader.readUInt32() == 0x0304_0506)
        #expect(try reader.readUInt64() == 0x0708_090a_0b0c_0d0e)
        #expect(reader.isAtEnd)
        #expect(throws: ObstacleBridgeBinaryCodecError.truncated) { try reader.readUInt8() }

        let service = ObstacleBridgeServiceSpec(serviceID: 7, name: "echo", listenProtocol: 1, listenHost: "127.0.0.1", listenPort: 7001, targetProtocol: 1, targetHost: "127.0.0.1", targetPort: 7002)
        let open = try ObstacleBridgeServiceCodec.encodeOpen(instanceID: 9, connectionSequence: 4, service: service)
        #expect(open.starts(with: Data("O5".utf8)))
        #expect(try ObstacleBridgeServiceCodec.decodeOpen(open) == .init(instanceID: 9, connectionSequence: 4, service: service))

        var legacyOpen = ObstacleBridgeBinaryWriter()
        legacyOpen.appendUTF8("O4"); legacyOpen.append(UInt64(9)); legacyOpen.append(UInt32(4)); legacyOpen.append(UInt16(7)); legacyOpen.append(ObstacleBridgeChannelMuxProtocol.tcp.rawValue); legacyOpen.append(UInt8(9)); legacyOpen.appendUTF8("127.0.0.1"); legacyOpen.append(UInt16(7001)); legacyOpen.append(ObstacleBridgeChannelMuxProtocol.tcp.rawValue); legacyOpen.append(UInt8(9)); legacyOpen.appendUTF8("127.0.0.1"); legacyOpen.append(UInt16(7002))
        #expect(try ObstacleBridgeServiceCodec.decodeOpen(legacyOpen.encoded).service == serviceWithoutMetadata(service))

        let catalog = try ObstacleBridgeServiceCodec.encodeRemoteServices(instanceID: 9, connectionSequence: 4, services: [service])
        #expect(catalog.starts(with: Data("RS3".utf8)))
        #expect(String(decoding: catalog.dropFirst(19), as: UTF8.self) == "[{\"svc_id\":7,\"l_proto\":\"tcp\",\"l_bind\":\"127.0.0.1\",\"l_port\":7001,\"r_proto\":\"tcp\",\"r_host\":\"127.0.0.1\",\"r_port\":7002,\"name\":\"echo\",\"lifecycle_hooks\":null,\"options\":null}]")
        let decoded = try ObstacleBridgeServiceCodec.decodeRemoteServices(catalog)
        #expect(decoded.instanceID == 9 && decoded.connectionSequence == 4 && decoded.services == [service])
        #expect(throws: ObstacleBridgeServiceCodecError.invalidPayload) { try ObstacleBridgeServiceCodec.decodeOpen(Data("O5".utf8)) }
    }

    @Test func controlChunksMatchPythonLayoutAndRemainBounded() throws {
        let payload = Data(0..<25)
        let chunks = try ObstacleBridgeControlChunkCodec.chunk(transactionID: 9, maximumApplicationPayload: 32, payload: payload)
        #expect(chunks.count == 3)
        #expect(chunks[0].hex == "434b56310000000900000003000102030405060708090a0b")
        #expect(chunks[2].hex == "434b5631000000090002000318")
        #expect(ObstacleBridgeControlChunkCodec.nextTransactionID(current: 0).transactionID == 1)
        #expect(ObstacleBridgeControlChunkCodec.nextTransactionID(current: .max).next == 1)
        #expect(throws: ObstacleBridgeControlChunkCodecError.invalidMaximumPayload) {
            try ObstacleBridgeControlChunkCodec.chunk(transactionID: 1, maximumApplicationPayload: 20, payload: Data())
        }

        let reassembler = ObstacleBridgeControlChunkReassembler(maximumInflight: 1, maximumReassembledBytes: 25, ttl: 1)
        #expect(reassembler.consume(channelID: 2, protocolType: 1, messageType: 7, payload: chunks[1], peerID: 3, now: 10) == nil)
        #expect(reassembler.consume(channelID: 2, protocolType: 1, messageType: 7, payload: chunks[1], peerID: 3, now: 11) == nil)
        #expect(reassembler.consume(channelID: 2, protocolType: 1, messageType: 7, payload: chunks[0], peerID: 3, now: 11) == nil)
        #expect(reassembler.consume(channelID: 2, protocolType: 1, messageType: 7, payload: chunks[2], peerID: 3, now: 11) == payload)
        #expect(reassembler.consume(channelID: 2, protocolType: 1, messageType: 7, payload: Data("CKV1".utf8), peerID: 3, now: 12) == nil)

        let expired = ObstacleBridgeControlChunkReassembler(ttl: 1)
        #expect(expired.consume(channelID: 2, protocolType: 1, messageType: 7, payload: chunks[0], peerID: 3, now: 10) == nil)
        expired.prune(now: 11)
        #expect(expired.consume(channelID: 2, protocolType: 1, messageType: 7, payload: chunks[1], peerID: 3, now: 11) == nil)
    }

    @Test func overlayAppPingPongFramesMatchPythonLayout() throws {
        let application = ObstacleBridgeOverlayFrame(kind: .application, payload: Data("hello".utf8))
        let wire = try ObstacleBridgeOverlayFrameCodec.encodeTCP(application)
        #expect(wire.hex == "000000060068656c6c6f")
        #expect(try ObstacleBridgeOverlayFrameCodec.decodeTCP(wire) == application)
        #expect(try ObstacleBridgeOverlayFrameCodec.decodeTCPBodyLength(Data(wire.prefix(4))) == 6)
        #expect(try ObstacleBridgeOverlayFrameCodec.decodeTCPBodyLength(Data([0, 0, 0, 0])) == 0)
        #expect(throws: ObstacleBridgeOverlayFrameCodecError.invalidFrame) {
            try ObstacleBridgeOverlayFrameCodec.decodeTCPBodyLength(Data([0, 0, 0]))
        }
        let ping = ObstacleBridgeOverlayFrame(kind: .ping, payload: Data.hex("01020304050607080000000000000000"))
        #expect(try ObstacleBridgeOverlayFrameCodec.pong(forPing: ping) == .init(kind: .pong, payload: Data.hex("0102030405060708")))
        #expect(ObstacleBridgeOverlayFrameCodec.pingPayload(txNS: 0x0102030405060708, echoNS: 0x1112131415161718).hex == "01020304050607081112131415161718")
        #expect(try ObstacleBridgeOverlayFrameCodec.pingTimestamps(ping).txNS == 0x0102030405060708)
        #expect(try ObstacleBridgeOverlayFrameCodec.pongEchoTimestamp(.init(kind: .pong, payload: Data.hex("0102030405060708"))) == 0x0102030405060708)
        #expect(throws: ObstacleBridgeOverlayFrameCodecError.invalidFrame) {
            try ObstacleBridgeOverlayFrameCodec.decodeTCP(Data.hex("0000000101"))
        }
        #expect(throws: ObstacleBridgeOverlayFrameCodecError.invalidFrame) {
            try ObstacleBridgeOverlayFrameCodec.decodeTCP(wire + Data([0]))
        }
    }

    @Test func webSocketTextPayloadModesRoundTripInCore() throws {
        let wire = Data([0, 1, 2, 0xff])
        for mode in [ObstacleBridgeWebSocketPayloadMode.base64, .jsonBase64, .semiTextShape] {
            let payload = try ObstacleBridgeWebSocketPayloadCodec.encode(wire, mode: mode)
            #expect(try ObstacleBridgeWebSocketPayloadCodec.decode(payload, mode: mode) == wire)
        }
        #expect(ObstacleBridgeWebSocketPayloadCodec.maximumEncodedSize(4, mode: .base64) == 8)
        #expect(ObstacleBridgeWebSocketPayloadCodec.maximumEncodedSize(4, mode: .jsonBase64) == 19)
        #expect(throws: ObstacleBridgeWebSocketPayloadCodecError.invalidPayload) {
            try ObstacleBridgeWebSocketPayloadCodec.decode(.text("!"), mode: .semiTextShape)
        }
    }

    @Test func sharedPythonWireCorpusAcceptsCoreAndRejectsMalformedRecords() throws {
        let url = try #require(Bundle.module.url(forResource: "python_wire_codec_corpus", withExtension: "json"))
        let corpus = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        let tcp = try #require(corpus["tcp_application"] as? [String: Any])
        let payload = Data.hex(try #require(tcp["payload_hex"] as? String))
        let wire = Data.hex(try #require(tcp["wire_hex"] as? String))
        #expect(try ObstacleBridgeOverlayFrameCodec.encodeTCP(.init(kind: .application, payload: payload)) == wire)
        for value in try #require(tcp["malformed_wire_hex"] as? [String]) {
            #expect(throws: ObstacleBridgeOverlayFrameCodecError.invalidFrame) { try ObstacleBridgeOverlayFrameCodec.decodeTCP(.hex(value)) }
        }
        let channelMux = try #require(corpus["channelmux_header"] as? [String: Any])
        let channelMuxBody = Data.hex(try #require(channelMux["body_hex"] as? String))
        let channelMuxWire = Data.hex(try #require(channelMux["wire_hex"] as? String))
        #expect(try ObstacleBridgeChannelMuxFrameCodec.encode(
            channelID: UInt16(try #require(channelMux["channel_id"] as? Int)),
            protocolType: UInt8(try #require(channelMux["protocol_type"] as? Int)),
            counter: UInt16(try #require(channelMux["counter"] as? Int)),
            messageType: UInt8(try #require(channelMux["message_type"] as? Int)),
            body: channelMuxBody
        ) == channelMuxWire)
        #expect(try ObstacleBridgeChannelMuxFrameCodec.decode(channelMuxWire) == .init(
            channelID: UInt16(try #require(channelMux["channel_id"] as? Int)),
            protocolType: UInt8(try #require(channelMux["protocol_type"] as? Int)),
            counter: UInt16(try #require(channelMux["counter"] as? Int)),
            messageType: UInt8(try #require(channelMux["message_type"] as? Int)),
            body: channelMuxBody
        ))
        for value in try #require(channelMux["malformed_wire_hex"] as? [String]) {
            #expect(throws: ObstacleBridgeChannelMuxFrameCodecError.invalidFrame) {
                try ObstacleBridgeChannelMuxFrameCodec.decode(.hex(value))
            }
        }
        let myudp = try #require(corpus["myudp_data"] as? [String: Any])
        let myudpPayload = Data.hex(try #require(myudp["payload_hex"] as? String))
        let myudpWire = Data.hex(try #require(myudp["wire_hex"] as? String))
        #expect(try ObstacleBridgeMyUDPCodec.encodeData(
            payload: myudpPayload,
            counter: UInt16(try #require(myudp["counter"] as? Int)),
            transmittedNanoseconds: UInt64(try #require(myudp["transmitted_nanoseconds"] as? Int)),
            echoedNanoseconds: UInt64(try #require(myudp["echoed_nanoseconds"] as? Int))
        ) == myudpWire)
        #expect(try ObstacleBridgeMyUDPCodec.decodeData(myudpWire) == .init(
            counter: UInt16(try #require(myudp["counter"] as? Int)),
            payload: myudpPayload,
            transmittedNanoseconds: UInt64(try #require(myudp["transmitted_nanoseconds"] as? Int)),
            echoedNanoseconds: UInt64(try #require(myudp["echoed_nanoseconds"] as? Int))
        ))
        for value in try #require(myudp["malformed_wire_hex"] as? [String]) {
            #expect(throws: ObstacleBridgeMyUDPCodecError.invalidFrame) { try ObstacleBridgeMyUDPCodec.decodeData(.hex(value)) }
        }
        let control = try #require(corpus["myudp_control"] as? [String: Any])
        let controlWire = Data.hex(try #require(control["wire_hex"] as? String))
        #expect(try ObstacleBridgeMyUDPCodec.decodeControl(controlWire) == .init(lastInOrder: 4, highestReceived: 7, missing: [5, 6], transmittedNanoseconds: 8, echoedNanoseconds: 9))
        for value in try #require(control["malformed_wire_hex"] as? [String]) {
            #expect(throws: ObstacleBridgeMyUDPCodecError.invalidFrame) { try ObstacleBridgeMyUDPCodec.decodeControl(.hex(value)) }
        }
        let websocket = try #require(corpus["websocket_binary"] as? [String: Any])
        let websocketPayload = Data.hex(try #require(websocket["payload_hex"] as? String))
        let websocketWire = Data.hex(try #require(websocket["wire_hex"] as? String))
        #expect(try ObstacleBridgeOverlayFrameCodec.encodeBody(.init(kind: .application, payload: websocketPayload)) == websocketWire)
        #expect(try ObstacleBridgeOverlayFrameCodec.decodeBody(websocketWire) == .init(kind: .application, payload: websocketPayload))
        for value in try #require(websocket["malformed_wire_hex"] as? [String]) {
            #expect(throws: ObstacleBridgeOverlayFrameCodecError.invalidFrame) { try ObstacleBridgeOverlayFrameCodec.decodeBody(.hex(value)) }
        }
        let websocketText = try #require(corpus["websocket_text_modes"] as? [String: Any])
        let websocketTextWire = Data.hex(try #require(websocketText["wire_hex"] as? String))
        let textModes: [(ObstacleBridgeWebSocketPayloadMode, String, String)] = [
            (.base64, "base64", "malformed_base64"),
            (.jsonBase64, "json_base64", "malformed_json_base64"),
            (.semiTextShape, "semi_text_shape", "malformed_semi_text_shape"),
        ]
        for (mode, encodedKey, malformedKey) in textModes {
            let encoded = try #require(websocketText[encodedKey] as? String)
            #expect(try ObstacleBridgeWebSocketPayloadCodec.encode(websocketTextWire, mode: mode) == .text(encoded))
            #expect(try ObstacleBridgeWebSocketPayloadCodec.decode(.text(encoded), mode: mode) == websocketTextWire)
            #expect(throws: ObstacleBridgeWebSocketPayloadCodecError.invalidPayload) {
                try ObstacleBridgeWebSocketPayloadCodec.decode(.text(try #require(websocketText[malformedKey] as? String)), mode: mode)
            }
        }
        let secureLink = try #require(corpus["securelink_psk"] as? [String: Any])
        let psk = Data.hex(try #require(secureLink["psk_hex"] as? String))
        let clientNonce = Data.hex(try #require(secureLink["client_nonce_hex"] as? String))
        let serverNonce = Data.hex(try #require(secureLink["server_nonce_hex"] as? String))
        let sessionID = UInt64(try #require(secureLink["session_id"] as? Int))
        let expectedClientToServer = try #require(secureLink["client_to_server_key_hex"] as? String)
        let expectedServerToClient = try #require(secureLink["server_to_client_key_hex"] as? String)
        let expectedServerProof = try #require(secureLink["server_proof_hex"] as? String)
        let expectedRekeyCommitProof = try #require(secureLink["client_rekey_commit_proof_hex"] as? String)
        let keys = try ObstacleBridgeSecureLinkPSKCrypto.deriveKeys(psk: psk, sessionID: sessionID, clientNonce: clientNonce, serverNonce: serverNonce)
        #expect(keys.clientToServer.hex == expectedClientToServer)
        #expect(keys.serverToClient.hex == expectedServerToClient)
        #expect(try ObstacleBridgeSecureLinkPSKCrypto.serverProof(psk: psk, sessionID: sessionID, clientNonce: clientNonce, serverNonce: serverNonce).hex == expectedServerProof)
        #expect(try ObstacleBridgeSecureLinkPSKCrypto.clientRekeyCommitProof(psk: psk, sessionID: sessionID, clientNonce: clientNonce, serverNonce: serverNonce).hex == expectedRekeyCommitProof)
        let expectedClientHello = Data.hex(try #require(secureLink["client_hello_hex"] as? String))
        let expectedServerHello = Data.hex(try #require(secureLink["server_hello_hex"] as? String))
        let client = try ObstacleBridgeSecureLinkPSKClient(psk: psk)
        #expect(try client.begin(sessionID: sessionID, clientNonce: clientNonce) == expectedClientHello)
        let server = try ObstacleBridgeSecureLinkPSKServer(psk: psk)
        #expect(try server.handleClientHello(expectedClientHello, serverNonce: serverNonce) == expectedServerHello)
        for value in try #require(secureLink["malformed_envelope_hex"] as? [String]) {
            #expect(throws: ObstacleBridgeSecureLinkPSKClientError.invalidFrame) { try server.handleClientHello(.hex(value), serverNonce: serverNonce) }
            #expect(throws: ObstacleBridgeSecureLinkPSKClientError.invalidFrame) { try client.handleServerHello(.hex(value)) }
        }
        let chunk = try #require(corpus["control_chunk"] as? [String: Any])
        let transactionID = try #require(chunk["transaction_id"] as? Int)
        let maximumPayload = try #require(chunk["maximum_application_payload"] as? Int)
        let chunkPayload = Data.hex(try #require(chunk["payload_hex"] as? String))
        let expectedChunks = try #require(chunk["chunks_hex"] as? [String])
        let chunks = try ObstacleBridgeControlChunkCodec.chunk(transactionID: UInt32(transactionID), maximumApplicationPayload: maximumPayload, payload: chunkPayload)
        #expect(chunks.map(\.hex) == expectedChunks)
        let malformedChunkReassembler = ObstacleBridgeControlChunkReassembler()
        for value in try #require(chunk["malformed_chunks_hex"] as? [String]) {
            #expect(malformedChunkReassembler.consume(
                channelID: 1,
                protocolType: 1,
                messageType: 7,
                payload: .hex(value),
                peerID: nil,
                now: 1
            ) == nil)
        }
        let serviceRecord = try #require(corpus["service_records"] as? [String: Any])
        let service = ObstacleBridgeServiceSpec(serviceID: 7, name: "echo", listenProtocol: 1, listenHost: "127.0.0.1", listenPort: 7001, targetProtocol: 1, targetHost: "127.0.0.1", targetPort: 7002)
        let o4 = Data.hex(try #require(serviceRecord["open_o4_hex"] as? String))
        let o5 = Data.hex(try #require(serviceRecord["open_o5_hex"] as? String))
        let rs3 = Data.hex(try #require(serviceRecord["rs3_hex"] as? String))
        #expect(try ObstacleBridgeServiceCodec.decodeOpen(o4) == .init(instanceID: 9, connectionSequence: 4, service: serviceWithoutMetadata(service)))
        #expect(try ObstacleBridgeServiceCodec.encodeOpen(instanceID: 9, connectionSequence: 4, service: service) == o5)
        let rs2 = Data.hex(try #require(serviceRecord["rs2_hex"] as? String))
        #expect(try ObstacleBridgeServiceCodec.decodeRemoteServices(rs2).services == [serviceWithoutMetadata(service)])
        #expect(try ObstacleBridgeServiceCodec.encodeRemoteServices(instanceID: 9, connectionSequence: 4, services: [service]) == rs3)
        let trailing = Data.hex(try #require(serviceRecord["trailing_hex"] as? String))
        #expect(throws: ObstacleBridgeServiceCodecError.invalidPayload) { try ObstacleBridgeServiceCodec.decodeOpen(o4 + trailing) }
        #expect(throws: ObstacleBridgeServiceCodecError.invalidPayload) { try ObstacleBridgeServiceCodec.decodeRemoteServices(rs3 + trailing) }
        for bytes in try #require(serviceRecord["truncated_bytes"] as? [Int]) {
            #expect(throws: ObstacleBridgeServiceCodecError.invalidPayload) { try ObstacleBridgeServiceCodec.decodeOpen(Data(o4.dropLast(bytes))) }
            #expect(throws: ObstacleBridgeServiceCodecError.invalidPayload) { try ObstacleBridgeServiceCodec.decodeOpen(Data(o5.dropLast(bytes))) }
            #expect(throws: ObstacleBridgeServiceCodecError.invalidPayload) { try ObstacleBridgeServiceCodec.decodeRemoteServices(Data(rs2.dropLast(bytes))) }
            #expect(throws: ObstacleBridgeServiceCodecError.invalidPayload) { try ObstacleBridgeServiceCodec.decodeRemoteServices(Data(rs3.dropLast(bytes))) }
        }
    }

    private func serviceWithoutMetadata(_ service: ObstacleBridgeServiceSpec) -> ObstacleBridgeServiceSpec {
        .init(serviceID: service.serviceID, name: nil, listenProtocol: service.listenProtocol, listenHost: service.listenHost, listenPort: service.listenPort, targetProtocol: service.targetProtocol, targetHost: service.targetHost, targetPort: service.targetPort)
    }
}

private extension Data {
    static func hex(_ value: String) -> Data {
        Data(stride(from: 0, to: value.count, by: 2).map {
            UInt8(value[value.index(value.startIndex, offsetBy: $0)...value.index(value.startIndex, offsetBy: $0 + 1)], radix: 16)!
        })
    }

    var hex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
