import Dispatch
import Foundation
import ObstacleBridgeCore

public typealias ObstacleBridgeLinuxReconnectPolicy = ObstacleBridgeOverlayReconnectPolicy

public struct ObstacleBridgeLinuxReconnectSnapshot: Equatable, Sendable {
    public let state: String; public let attempts: Int; public let nextRetryMilliseconds: Int?; public let failureReason: String?
}

/// Core owns retry epochs, candidate rotation and timer invalidation. Linux
/// executes only configured-runtime I/O and Dispatch timer effects.
public final class ObstacleBridgeLinuxReconnectSupervisor: @unchecked Sendable {
    public var onSnapshot: ((ObstacleBridgeLinuxReconnectSnapshot) -> Void)?
    private let runtime: ObstacleBridgeLinuxConfiguredRuntime
    private let coordinator: ObstacleBridgeOverlayCoordinator
    private let queue = DispatchQueue(label: "org.obstaclebridge.linux.reconnect")
    private var timer: DispatchSourceTimer?
    private var stopped = true
    private var payload = Data(); private var baseSessionID: UInt64 = 0; private var baseNonce = Data()
    private(set) public var snapshot = ObstacleBridgeLinuxReconnectSnapshot(state: "stopped", attempts: 0, nextRetryMilliseconds: nil, failureReason: nil)

    public init(runtime: ObstacleBridgeLinuxConfiguredRuntime, policy: ObstacleBridgeLinuxReconnectPolicy = .init()) {
        self.runtime = runtime; self.coordinator = .init(candidateCount: runtime.configuration.peerCandidates.count, policy: policy)
    }
    public func start(probe: Data, sessionID: UInt64, clientNonce: Data) { queue.async { [weak self] in guard let self else { return }; self.stopped = false; self.payload = probe; self.baseSessionID = sessionID; self.baseNonce = clientNonce; self.apply(self.coordinator.handle(.start)) } }
    public func stop() { queue.async { [weak self] in guard let self else { return }; self.stopped = true; self.apply(self.coordinator.handle(.stop)) } }

    private func apply(_ transition: ObstacleBridgeOverlayCoordinatorTransition) {
        for effect in transition.effects { switch effect {
        case .openTransport(let epoch, _, let attempt): performAttempt(epoch: epoch, attempt: attempt)
        case .cancelTransport: runtime.disconnect(); runtime.advanceCandidate()
        case .scheduleRetry(let token, let delay): scheduleRetry(token: token, afterMilliseconds: delay)
        case .cancelRetry: cancelTimer()
        case .startReceive, .cancelReceive: break
        } }
        let core = coordinator.snapshot
        let value = ObstacleBridgeLinuxReconnectSnapshot(state: core.state == .connecting ? "reconnecting" : core.state.rawValue, attempts: core.attempts, nextRetryMilliseconds: core.nextRetryMilliseconds, failureReason: core.failureReason)
        snapshot = value; onSnapshot?(value)
    }
    private func performAttempt(epoch: UInt64, attempt: Int) {
        guard !stopped, coordinator.snapshot.epoch == epoch else { return }
        var nonce = baseNonce; if attempt > 1, !nonce.isEmpty { nonce[nonce.count - 1] ^= UInt8(truncatingIfNeeded: attempt - 1) }
        do { let session = try runtime.connect(sessionID: normalizedSessionID(baseSessionID &+ UInt64(attempt - 1)), clientNonce: nonce); _ = try session.send(payload); apply(coordinator.handle(.transportConnected(epoch: epoch))); apply(coordinator.handle(.authenticated(epoch: epoch))) }
        catch { apply(coordinator.handle(.transportFailed(epoch: epoch, reason: error.localizedDescription))) }
    }
    private func scheduleRetry(token: UInt64, afterMilliseconds delay: Int) { cancelTimer(); let timer = DispatchSource.makeTimerSource(queue: queue); self.timer = timer; timer.schedule(deadline: .now() + .milliseconds(delay)); timer.setEventHandler { [weak self] in guard let self else { return }; self.cancelTimer(); self.apply(self.coordinator.handle(.retryTimerFired(token: token))) }; timer.resume() }
    private func normalizedSessionID(_ value: UInt64) -> UInt64 { value == 0 ? 1 : value }
    private func cancelTimer() { timer?.setEventHandler {}; timer?.cancel(); timer = nil }
    deinit { timer?.cancel() }
}
