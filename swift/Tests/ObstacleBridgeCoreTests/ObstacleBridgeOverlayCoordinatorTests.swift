import Foundation
import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgeOverlayCoordinatorTests {
    @Test func logicalEnvelopeUsesOneAppPingPongPolicyForTCPAndWebSocket() throws {
        let application = ObstacleBridgeOverlayFrame(kind: .application, payload: Data("payload".utf8))
        #expect(try ObstacleBridgeOverlayEnvelope.decodeTCP(ObstacleBridgeOverlayEnvelope.encodeTCP(application)) == .application(Data("payload".utf8)))

        let ping = ObstacleBridgeOverlayFrame(kind: .ping, payload: ObstacleBridgeOverlayFrameCodec.pingPayload(txNS: 7, echoNS: 3))
        let websocket = try ObstacleBridgeOverlayEnvelope.encodeWebSocket(ping, mode: .base64)
        #expect(try ObstacleBridgeOverlayEnvelope.decodeWebSocket(websocket, mode: .base64) == .reply(.init(kind: .pong, payload: ObstacleBridgeOverlayFrameCodec.pongPayload(echoTxNS: 7))))
        #expect(try ObstacleBridgeOverlayEnvelope.consume(.init(kind: .pong, payload: Data())) == .ignore)
    }

    @Test func authenticatedEpochStartsExactlyOneReceiveOwner() {
        let coordinator = ObstacleBridgeOverlayCoordinator(
            candidateCount: 2,
            policy: .init(initialDelayMilliseconds: 10, maximumDelayMilliseconds: 40, maximumAttempts: 3)
        )

        let started = coordinator.handle(.start)
        #expect(started.snapshot.state == .connecting)
        #expect(started.snapshot.epoch == 1)
        #expect(started.effects == [.openTransport(epoch: 1, candidateIndex: 0, attempt: 1)])
        #expect(coordinator.handle(.transportConnected(epoch: 1)).effects.isEmpty)

        let authenticated = coordinator.handle(.authenticated(epoch: 1))
        #expect(authenticated.snapshot.state == .connected)
        #expect(authenticated.snapshot.appReady)
        #expect(authenticated.snapshot.receiveActive)
        #expect(authenticated.effects == [.startReceive(epoch: 1)])
        #expect(coordinator.handle(.authenticated(epoch: 1)).effects.isEmpty)
    }

    @Test func admittedInboundSessionGetsCoreEpochWithoutOpeningOutboundTransport() {
        let coordinator = ObstacleBridgeOverlayCoordinator(candidateCount: 2)

        let admitted = coordinator.handle(.adoptAuthenticated)

        #expect(admitted.snapshot.state == .connected)
        #expect(admitted.snapshot.epoch == 1)
        #expect(admitted.snapshot.appReady)
        #expect(admitted.effects == [.startReceive(epoch: 1)])
    }

    @Test func staleGenerationCannotChangeReplacementEpoch() {
        let coordinator = ObstacleBridgeOverlayCoordinator(
            candidateCount: 2,
            policy: .init(initialDelayMilliseconds: 10, maximumDelayMilliseconds: 40, maximumAttempts: 3)
        )
        _ = coordinator.handle(.start)
        _ = coordinator.handle(.authenticated(epoch: 1))

        let failure = coordinator.handle(.receiveFinished(epoch: 1, reason: "eof"))
        #expect(failure.snapshot.state == .reconnecting)
        #expect(failure.snapshot.appReady == false)
        #expect(failure.snapshot.candidateIndex == 1)
        #expect(failure.effects == [
            .cancelReceive(epoch: 1),
            .cancelTransport(epoch: 1),
            .scheduleRetry(token: 1, afterMilliseconds: 10),
        ])

        let replacement = coordinator.handle(.retryTimerFired(token: 1))
        #expect(replacement.snapshot.epoch == 2)
        #expect(replacement.effects == [.openTransport(epoch: 2, candidateIndex: 1, attempt: 2)])
        #expect(coordinator.handle(.authenticated(epoch: 1)).effects.isEmpty)
        #expect(coordinator.snapshot.state == .connecting)
        #expect(coordinator.snapshot.epoch == 2)
    }

    @Test func retryIsBoundedAndCancelledStopCannotReviveIt() {
        let coordinator = ObstacleBridgeOverlayCoordinator(
            candidateCount: 3,
            policy: .init(initialDelayMilliseconds: 10, maximumDelayMilliseconds: 25, maximumAttempts: 3)
        )
        _ = coordinator.handle(.start)
        let firstFailure = coordinator.handle(.transportFailed(epoch: 1, reason: "first"))
        #expect(firstFailure.effects == [
            .cancelTransport(epoch: 1),
            .scheduleRetry(token: 1, afterMilliseconds: 10),
        ])
        _ = coordinator.handle(.retryTimerFired(token: 1))
        let secondFailure = coordinator.handle(.transportFailed(epoch: 2, reason: "second"))
        #expect(secondFailure.effects == [
            .cancelTransport(epoch: 2),
            .scheduleRetry(token: 2, afterMilliseconds: 20),
        ])

        let stopped = coordinator.handle(.stop)
        #expect(stopped.snapshot.state == .stopped)
        #expect(stopped.effects == [.cancelRetry(token: 2)])
        #expect(coordinator.handle(.retryTimerFired(token: 2)).effects.isEmpty)
        #expect(coordinator.snapshot.state == .stopped)

        _ = coordinator.handle(.start)
        _ = coordinator.handle(.transportFailed(epoch: 3, reason: "first"))
        _ = coordinator.handle(.retryTimerFired(token: 3))
        let secondRetry = coordinator.handle(.transportFailed(epoch: 4, reason: "second"))
        _ = coordinator.handle(.retryTimerFired(token: 999))
        _ = coordinator.handle(.retryTimerFired(token: 4))
        let terminal = coordinator.handle(.transportFailed(epoch: 5, reason: "third"))
        #expect(secondRetry.snapshot.state == .reconnecting)
        #expect(terminal.snapshot.state == .failed)
        #expect(terminal.snapshot.attempts == 3)
        #expect(terminal.snapshot.nextRetryMilliseconds == nil)
    }
}
