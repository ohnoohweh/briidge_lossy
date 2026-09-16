import Foundation

/// The portable lifecycle visible to an overlay consumer. Native connection,
/// scheduler, and receive APIs are deliberately expressed as effects below.
public enum ObstacleBridgeOverlayLifecycleState: String, Equatable, Sendable {
    case stopped
    case connecting
    case reconnecting
    case connected
    case failed
}

/// Bounded retry policy for one logical overlay peer. The policy makes no
/// assumptions about a socket implementation or scheduler.
public struct ObstacleBridgeOverlayReconnectPolicy: Equatable, Sendable {
    public let initialDelayMilliseconds: Int
    public let maximumDelayMilliseconds: Int
    public let maximumAttempts: Int

    public init(
        initialDelayMilliseconds: Int = 250,
        maximumDelayMilliseconds: Int = 5_000,
        maximumAttempts: Int = 5
    ) {
        self.initialDelayMilliseconds = max(1, initialDelayMilliseconds)
        self.maximumDelayMilliseconds = max(self.initialDelayMilliseconds, maximumDelayMilliseconds)
        self.maximumAttempts = max(1, maximumAttempts)
    }

    public func delayMilliseconds(afterAttempt attempt: Int) -> Int {
        let exponent = min(max(0, attempt - 1), 10)
        return min(maximumDelayMilliseconds, initialDelayMilliseconds * (1 << exponent))
    }
}

/// Redacted, deterministic projection of the one active overlay epoch.
public struct ObstacleBridgeOverlayCoordinatorSnapshot: Equatable, Sendable {
    public let state: ObstacleBridgeOverlayLifecycleState
    public let epoch: UInt64?
    public let attempts: Int
    public let candidateIndex: Int
    public let nextRetryMilliseconds: Int?
    public let failureReason: String?
    public let appReady: Bool
    public let receiveActive: Bool

    public init(
        state: ObstacleBridgeOverlayLifecycleState,
        epoch: UInt64?,
        attempts: Int,
        candidateIndex: Int,
        nextRetryMilliseconds: Int?,
        failureReason: String?,
        appReady: Bool,
        receiveActive: Bool
    ) {
        self.state = state
        self.epoch = epoch
        self.attempts = attempts
        self.candidateIndex = candidateIndex
        self.nextRetryMilliseconds = nextRetryMilliseconds
        self.failureReason = failureReason
        self.appReady = appReady
        self.receiveActive = receiveActive
    }
}

/// Completion events supplied by the platform adapter. Epoch and retry tokens
/// make delayed callbacks harmless after replacement or shutdown.
public enum ObstacleBridgeOverlayCoordinatorInput: Equatable, Sendable {
    case start
    /// A platform listener has already admitted and authenticated a native
    /// session. Core still allocates its portable epoch and receive owner.
    case adoptAuthenticated
    case transportConnected(epoch: UInt64)
    case authenticated(epoch: UInt64)
    case transportFailed(epoch: UInt64, reason: String)
    case receiveFinished(epoch: UInt64, reason: String)
    case retryTimerFired(token: UInt64)
    case stop
}

/// Ordered work requested by the coordinator. Adapters perform these effects
/// with native primitives and report their completion through an input above.
public enum ObstacleBridgeOverlayCoordinatorEffect: Equatable, Sendable {
    case openTransport(epoch: UInt64, candidateIndex: Int, attempt: Int)
    case cancelTransport(epoch: UInt64)
    case startReceive(epoch: UInt64)
    case cancelReceive(epoch: UInt64)
    case scheduleRetry(token: UInt64, afterMilliseconds: Int)
    case cancelRetry(token: UInt64)
}

public struct ObstacleBridgeOverlayCoordinatorTransition: Equatable, Sendable {
    public let snapshot: ObstacleBridgeOverlayCoordinatorSnapshot
    public let effects: [ObstacleBridgeOverlayCoordinatorEffect]

    public init(snapshot: ObstacleBridgeOverlayCoordinatorSnapshot, effects: [ObstacleBridgeOverlayCoordinatorEffect]) {
        self.snapshot = snapshot
        self.effects = effects
    }
}

/// Single owner for portable overlay epoch, readiness, retry, and receive
/// admission decisions. It is synchronous by design: serialization, timers,
/// and I/O remain platform-adapter mechanics.
public final class ObstacleBridgeOverlayCoordinator: @unchecked Sendable {
    private let policy: ObstacleBridgeOverlayReconnectPolicy
    private let candidateCount: Int
    private var nextEpoch: UInt64 = 1
    private var nextRetryToken: UInt64 = 1
    private var activeEpoch: UInt64?
    private var scheduledRetryToken: UInt64?
    private var state: ObstacleBridgeOverlayLifecycleState = .stopped
    private var attempts = 0
    private var candidateIndex = 0
    private var failureReason: String?
    private var receiveActive = false

    public init(candidateCount: Int, policy: ObstacleBridgeOverlayReconnectPolicy = .init()) {
        self.candidateCount = max(1, candidateCount)
        self.policy = policy
    }

    public var snapshot: ObstacleBridgeOverlayCoordinatorSnapshot { makeSnapshot() }

    @discardableResult
    public func handle(_ input: ObstacleBridgeOverlayCoordinatorInput) -> ObstacleBridgeOverlayCoordinatorTransition {
        switch input {
        case .start:
            var effects = stopEffects()
            attempts = 0
            candidateIndex = 0
            failureReason = nil
            effects += beginAttempt()
            return transition(effects)

        case .adoptAuthenticated:
            var effects = stopEffects()
            attempts = 1
            candidateIndex = 0
            failureReason = nil
            let epoch = consumeEpoch()
            activeEpoch = epoch
            state = .connected
            receiveActive = true
            effects.append(.startReceive(epoch: epoch))
            return transition(effects)

        case .transportConnected(let epoch):
            guard epoch == activeEpoch, state == .connecting else { return transition([]) }
            return transition([])

        case .authenticated(let epoch):
            guard epoch == activeEpoch, state == .connecting else { return transition([]) }
            state = .connected
            failureReason = nil
            receiveActive = true
            return transition([.startReceive(epoch: epoch)])

        case .transportFailed(let epoch, let reason), .receiveFinished(let epoch, let reason):
            guard epoch == activeEpoch, state != .stopped else { return transition([]) }
            return failActiveEpoch(reason: reason)

        case .retryTimerFired(let token):
            guard token == scheduledRetryToken, state == .reconnecting else { return transition([]) }
            scheduledRetryToken = nil
            return transition(beginAttempt())

        case .stop:
            return transition(stopEffects())
        }
    }

    private func beginAttempt() -> [ObstacleBridgeOverlayCoordinatorEffect] {
        attempts += 1
        let epoch = consumeEpoch()
        activeEpoch = epoch
        state = .connecting
        failureReason = nil
        receiveActive = false
        return [.openTransport(epoch: epoch, candidateIndex: candidateIndex, attempt: attempts)]
    }

    private func failActiveEpoch(reason: String) -> ObstacleBridgeOverlayCoordinatorTransition {
        guard let epoch = activeEpoch else { return transition([]) }
        var effects: [ObstacleBridgeOverlayCoordinatorEffect] = []
        if receiveActive {
            effects.append(.cancelReceive(epoch: epoch))
        }
        effects.append(.cancelTransport(epoch: epoch))
        activeEpoch = nil
        receiveActive = false
        failureReason = reason
        candidateIndex = (candidateIndex + 1) % candidateCount
        guard attempts < policy.maximumAttempts else {
            state = .failed
            return transition(effects)
        }
        state = .reconnecting
        let token = consumeRetryToken()
        scheduledRetryToken = token
        effects.append(.scheduleRetry(token: token, afterMilliseconds: policy.delayMilliseconds(afterAttempt: attempts)))
        return transition(effects)
    }

    private func stopEffects() -> [ObstacleBridgeOverlayCoordinatorEffect] {
        var effects: [ObstacleBridgeOverlayCoordinatorEffect] = []
        if let token = scheduledRetryToken {
            effects.append(.cancelRetry(token: token))
        }
        if let epoch = activeEpoch {
            if receiveActive { effects.append(.cancelReceive(epoch: epoch)) }
            effects.append(.cancelTransport(epoch: epoch))
        }
        activeEpoch = nil
        scheduledRetryToken = nil
        receiveActive = false
        state = .stopped
        failureReason = nil
        return effects
    }

    private func transition(_ effects: [ObstacleBridgeOverlayCoordinatorEffect]) -> ObstacleBridgeOverlayCoordinatorTransition {
        .init(snapshot: makeSnapshot(), effects: effects)
    }

    private func makeSnapshot() -> ObstacleBridgeOverlayCoordinatorSnapshot {
        .init(
            state: state,
            epoch: activeEpoch,
            attempts: attempts,
            candidateIndex: candidateIndex,
            nextRetryMilliseconds: scheduledRetryToken == nil ? nil : policy.delayMilliseconds(afterAttempt: attempts),
            failureReason: failureReason,
            appReady: state == .connected,
            receiveActive: receiveActive
        )
    }

    private func consumeEpoch() -> UInt64 {
        defer { nextEpoch &+= 1 }
        return nextEpoch == 0 ? 1 : nextEpoch
    }

    private func consumeRetryToken() -> UInt64 {
        defer { nextRetryToken &+= 1 }
        return nextRetryToken == 0 ? 1 : nextRetryToken
    }
}
