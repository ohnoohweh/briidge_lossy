import Dispatch
import Foundation

public struct ObstacleBridgeLinuxLiveRuntimeSnapshot: Equatable, Sendable {
    public let state: String
    public let attempts: Int
    public let failureReason: String?
}

public enum ObstacleBridgeLinuxLiveRuntimeError: Error, Equatable, LocalizedError {
    case notRunning

    public var errorDescription: String? {
        switch self {
        case .notRunning: return "Linux overlay runtime is not application ready"
        }
    }
}

/// Foreground owner for one admitted overlay epoch. All session, retry, and
/// shutdown work is serialized here so lower transport callbacks cannot revive
/// a stopped runtime or retain a stale SecureLink epoch.
public final class ObstacleBridgeLinuxLiveRuntime: @unchecked Sendable {
    public var onSnapshot: ((ObstacleBridgeLinuxLiveRuntimeSnapshot) -> Void)?

    public let configuredRuntime: ObstacleBridgeLinuxConfiguredRuntime
    private let policy: ObstacleBridgeLinuxReconnectPolicy
    private let queue = DispatchQueue(label: "org.obstaclebridge.linux.live-runtime")
    private var session: ObstacleBridgeLinuxConfiguredSession?
    private var channelMux: ObstacleBridgeLinuxChannelMuxSession?
    private var retryTimer: DispatchSourceTimer?
    private var stopped = true
    private var attempts = 0
    private var failureReason: String?
    private(set) public var snapshot = ObstacleBridgeLinuxLiveRuntimeSnapshot(state: "stopped", attempts: 0, failureReason: nil)

    public init(configuration: ObstacleBridgeLinuxRuntimeConfiguration, policy: ObstacleBridgeLinuxReconnectPolicy = .init()) {
        self.configuredRuntime = ObstacleBridgeLinuxConfiguredRuntime(configuration: configuration)
        self.policy = policy
    }

    public func start() {
        queue.async { [weak self] in
            guard let self else { return }
            self.cancelRetry()
            self.configuredRuntime.disconnect()
            self.stopped = false
            self.attempts = 0
            self.failureReason = nil
            self.connectOrSchedule()
        }
    }

    public func stop() {
        queue.sync {
            stopped = true
            cancelRetry()
            session?.close()
            session = nil
            channelMux = nil
            configuredRuntime.disconnect()
            publish(state: "stopped", failureReason: nil)
        }
    }

    /// Sends on the live epoch. A transport or authentication failure tears
    /// down that epoch and starts the bounded reconnect policy.
    public func send(_ payload: Data) throws -> Data {
        try queue.sync {
            guard !stopped, let session, configuredRuntime.status().appReady else {
                throw ObstacleBridgeLinuxLiveRuntimeError.notRunning
            }
            do {
                return try session.send(payload)
            } catch {
                session.close()
                self.session = nil
                self.channelMux = nil
                configuredRuntime.disconnect()
                configuredRuntime.advanceCandidate()
                failureReason = error.localizedDescription
                connectOrSchedule()
                throw error
            }
        }
    }

    /// Forces a fresh authenticated epoch without allowing callbacks from the
    /// previous session to become current again.
    public func reconnect() {
        queue.async { [weak self] in
            guard let self, !self.stopped else { return }
            self.session?.close()
            self.session = nil
            self.channelMux = nil
            self.configuredRuntime.disconnect()
            self.configuredRuntime.advanceCandidate()
            self.attempts = 0
            self.connectOrSchedule()
        }
    }

    private func connectOrSchedule() {
        guard !stopped else { return }
        attempts += 1
        do {
            let sessionID = freshSessionID()
            let nonce = freshNonce()
            let connectedSession = try configuredRuntime.connect(sessionID: sessionID, clientNonce: nonce)
            session = connectedSession
            channelMux = try ObstacleBridgeLinuxChannelMuxSession(runtime: configuredRuntime, session: connectedSession)
            failureReason = nil
            publish(state: "connected", failureReason: nil)
        } catch {
            session = nil
            channelMux = nil
            configuredRuntime.disconnect()
            configuredRuntime.advanceCandidate()
            failureReason = error.localizedDescription
            guard attempts < policy.maximumAttempts else {
                publish(state: "failed", failureReason: failureReason)
                return
            }
            let delay = min(policy.maximumDelayMilliseconds, policy.initialDelayMilliseconds * (1 << min(attempts - 1, 10)))
            publish(state: "reconnecting", failureReason: failureReason)
            scheduleRetry(afterMilliseconds: delay)
        }
    }

    private func scheduleRetry(afterMilliseconds delay: Int) {
        cancelRetry()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        retryTimer = timer
        timer.schedule(deadline: .now() + .milliseconds(delay))
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            self.cancelRetry()
            self.connectOrSchedule()
        }
        timer.resume()
    }

    private func cancelRetry() {
        retryTimer?.setEventHandler {}
        retryTimer?.cancel()
        retryTimer = nil
    }

    private func publish(state: String, failureReason: String?) {
        let value = ObstacleBridgeLinuxLiveRuntimeSnapshot(state: state, attempts: attempts, failureReason: failureReason)
        snapshot = value
        onSnapshot?(value)
    }

    private func freshSessionID() -> UInt64 {
        var generator = SystemRandomNumberGenerator()
        return UInt64.random(in: 1...UInt64.max, using: &generator)
    }

    private func freshNonce() -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    }

    deinit {
        retryTimer?.cancel()
        configuredRuntime.disconnect()
    }
}
