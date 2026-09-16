import Dispatch
import Foundation
import ObstacleBridgeCore

/// Compatibility name for the Linux adapter. Retry bounds and delay arithmetic
/// are Core policy so Apple and future adapters cannot diverge.
public typealias ObstacleBridgeLinuxReconnectPolicy = ObstacleBridgeOverlayReconnectPolicy

public struct ObstacleBridgeLinuxReconnectSnapshot: Equatable, Sendable {
    public let state: String
    public let attempts: Int
    public let nextRetryMilliseconds: Int?
    public let failureReason: String?
}

/// A bounded, cancellation-safe reconnect loop for an admitted configured
/// runtime. Work is serialized so a stop request cannot race a later timer
/// firing into a new transport epoch.
public final class ObstacleBridgeLinuxReconnectSupervisor: @unchecked Sendable {
    public var onSnapshot: ((ObstacleBridgeLinuxReconnectSnapshot) -> Void)?

    private let runtime: ObstacleBridgeLinuxConfiguredRuntime
    private let policy: ObstacleBridgeLinuxReconnectPolicy
    private let queue = DispatchQueue(label: "org.obstaclebridge.linux.reconnect")
    private var timer: DispatchSourceTimer?
    private var stopped = true
    private var attempts = 0
    private var payload = Data()
    private var baseSessionID: UInt64 = 0
    private var baseNonce = Data()
    private(set) public var snapshot = ObstacleBridgeLinuxReconnectSnapshot(state: "stopped", attempts: 0, nextRetryMilliseconds: nil, failureReason: nil)

    public init(runtime: ObstacleBridgeLinuxConfiguredRuntime, policy: ObstacleBridgeLinuxReconnectPolicy = .init()) {
        self.runtime = runtime
        self.policy = policy
    }

    public func start(probe: Data, sessionID: UInt64, clientNonce: Data) {
        queue.async { [weak self] in
            guard let self else { return }
            self.cancelTimer()
            self.runtime.disconnect()
            self.stopped = false
            self.attempts = 0
            self.payload = probe
            self.baseSessionID = sessionID
            self.baseNonce = clientNonce
            self.publish(state: "reconnecting", nextRetryMilliseconds: 0, failureReason: nil)
            self.scheduleAttempt(afterMilliseconds: 0)
        }
    }

    public func stop() {
        queue.async { [weak self] in
            guard let self else { return }
            self.stopped = true
            self.cancelTimer()
            self.runtime.disconnect()
            self.publish(state: "stopped", nextRetryMilliseconds: nil, failureReason: nil)
        }
    }

    private func scheduleAttempt(afterMilliseconds delay: Int) {
        guard !stopped else { return }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        self.timer = timer
        timer.schedule(deadline: .now() + .milliseconds(delay))
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            self.cancelTimer()
            self.performAttempt()
        }
        timer.resume()
    }

    private func performAttempt() {
        guard !stopped else { return }
        attempts += 1
        let sessionID = normalizedSessionID(baseSessionID &+ UInt64(attempts - 1))
        var nonce = baseNonce
        if attempts > 1, !nonce.isEmpty { nonce[nonce.count - 1] ^= UInt8(truncatingIfNeeded: attempts - 1) }
        do {
            let session = try runtime.connect(sessionID: sessionID, clientNonce: nonce)
            _ = try session.send(payload)
            publish(state: "connected", nextRetryMilliseconds: nil, failureReason: nil)
        } catch {
            runtime.disconnect()
            runtime.advanceCandidate()
            guard attempts < policy.maximumAttempts, !stopped else {
                publish(state: "failed", nextRetryMilliseconds: nil, failureReason: error.localizedDescription)
                return
            }
            let delay = policy.delayMilliseconds(afterAttempt: attempts)
            publish(state: "reconnecting", nextRetryMilliseconds: delay, failureReason: error.localizedDescription)
            scheduleAttempt(afterMilliseconds: delay)
        }
    }

    private func publish(state: String, nextRetryMilliseconds: Int?, failureReason: String?) {
        let value = ObstacleBridgeLinuxReconnectSnapshot(state: state, attempts: attempts, nextRetryMilliseconds: nextRetryMilliseconds, failureReason: failureReason)
        snapshot = value
        onSnapshot?(value)
    }

    private func normalizedSessionID(_ value: UInt64) -> UInt64 { value == 0 ? 1 : value }

    private func cancelTimer() {
        timer?.setEventHandler {}
        timer?.cancel()
        timer = nil
    }

    deinit { timer?.cancel() }
}
