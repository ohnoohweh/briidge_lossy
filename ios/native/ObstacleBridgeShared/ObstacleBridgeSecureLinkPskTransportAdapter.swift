import Foundation

final class ObstacleBridgeSecureLinkPskTransportAdapter {
    struct OutboundSnapshot {
        var emittedFrames: [Data]
        var queuedPayloads: Int
        var authenticated: Bool
        var sessionID: UInt64
    }

    struct InboundSnapshot {
        var emittedFrames: [Data]
        var deliveredPayloads: [Data]
        var queuedPayloads: Int
        var authenticated: Bool
        var sessionID: UInt64
        var authFailCode: Int?
    }

    private let runtime: ObstacleBridgeSecureLinkPskRuntime
    private let retryBackoffInitialSec: TimeInterval
    private let retryBackoffMaxSec: TimeInterval
    private let timeProvider: () -> TimeInterval
    private let unixTimeProvider: () -> TimeInterval
    private var pendingPayloads: [Data] = []
    private var transportConnected = false
    private var handshakeAttemptsTotal = 0
    private var consecutiveFailures = 0
    private var retryNotBeforeMono: TimeInterval = 0.0
    private var retryNotBeforeUnixTs: TimeInterval?

    init(
        runtime: ObstacleBridgeSecureLinkPskRuntime,
        retryBackoffInitialMS: Int = 1000,
        retryBackoffMaxMS: Int = 5000,
        timeProvider: (() -> TimeInterval)? = nil,
        unixTimeProvider: (() -> TimeInterval)? = nil
    ) {
        self.runtime = runtime
        self.retryBackoffInitialSec = max(0.0, Double(max(0, retryBackoffInitialMS)) / 1000.0)
        self.retryBackoffMaxSec = max(self.retryBackoffInitialSec, Double(max(0, retryBackoffMaxMS)) / 1000.0)
        self.timeProvider = timeProvider ?? { ProcessInfo.processInfo.systemUptime }
        self.unixTimeProvider = unixTimeProvider ?? { Date().timeIntervalSince1970 }
    }

    func statusSnapshot() -> ObstacleBridgeSecureLinkPskRuntime.StatusSnapshot {
        var snapshot = runtime.statusSnapshot()
        let nowMono = timeProvider()
        snapshot.handshakeAttemptsTotal = handshakeAttemptsTotal
        snapshot.consecutiveFailures = consecutiveFailures
        snapshot.retryBackoffSec = max(0.0, retryNotBeforeMono - nowMono)
        snapshot.nextRetryUnixTs = retryNotBeforeUnixTs
        return snapshot
    }

    func requestSecureLinkRekey() throws -> OutboundSnapshot {
        let snapshot = try runtime.requestClientRekey()
        return OutboundSnapshot(
            emittedFrames: snapshot.emittedFrames,
            queuedPayloads: pendingPayloads.count,
            authenticated: snapshot.authenticated,
            sessionID: snapshot.sessionID
        )
    }

    func pollDueFrames() throws -> OutboundSnapshot {
        var emittedFrames = try runtime.pollDueFrames()
        if emittedFrames.isEmpty,
           transportConnected,
           shouldRetryClientHandshake(nowMono: timeProvider()) {
            let handshake = try runtime.beginClientHandshake()
            handshakeAttemptsTotal += 1
            clearRetrySchedule()
            emittedFrames.append(contentsOf: handshake.emittedFrames)
        }
        return OutboundSnapshot(
            emittedFrames: emittedFrames,
            queuedPayloads: pendingPayloads.count,
            authenticated: runtime.statusSnapshot().authenticated,
            sessionID: runtime.statusSnapshot().sessionID
        )
    }

    func handleTransportDisconnected() {
        transportConnected = false
        pendingPayloads.removeAll(keepingCapacity: false)
        runtime.handleTransportDisconnected()
    }

    func handleTransportConnected() throws -> OutboundSnapshot {
        transportConnected = true
        let status = runtime.statusSnapshot()
        guard status.clientMode, !status.authenticated else {
            return OutboundSnapshot(
                emittedFrames: [],
                queuedPayloads: pendingPayloads.count,
                authenticated: status.authenticated,
                sessionID: status.sessionID
            )
        }
        let nowMono = timeProvider()
        if retryNotBeforeMono > nowMono {
            return OutboundSnapshot(
                emittedFrames: [],
                queuedPayloads: pendingPayloads.count,
                authenticated: status.authenticated,
                sessionID: status.sessionID
            )
        }
        if status.sessionID != 0, status.authFailCode == 0 {
            return OutboundSnapshot(
                emittedFrames: [],
                queuedPayloads: pendingPayloads.count,
                authenticated: status.authenticated,
                sessionID: status.sessionID
            )
        }

        let handshake = try runtime.beginClientHandshake()
        handshakeAttemptsTotal += 1
        let emittedFrames = handshake.emittedFrames

        let updatedStatus = runtime.statusSnapshot()
        return OutboundSnapshot(
            emittedFrames: emittedFrames,
            queuedPayloads: pendingPayloads.count,
            authenticated: updatedStatus.authenticated,
            sessionID: updatedStatus.sessionID
        )
    }

    func handleOutboundPayload(_ payload: Data) throws -> OutboundSnapshot {
        let status = runtime.statusSnapshot()
        if status.appDataSendingBlocked {
            pendingPayloads.append(payload)
            return OutboundSnapshot(
                emittedFrames: [],
                queuedPayloads: pendingPayloads.count,
                authenticated: status.authenticated,
                sessionID: status.sessionID
            )
        }
        if status.authenticated {
            let snapshot = try runtime.sendApp(payload)
            return OutboundSnapshot(
                emittedFrames: snapshot.emittedFrames,
                queuedPayloads: pendingPayloads.count,
                authenticated: snapshot.authenticated,
                sessionID: snapshot.sessionID
            )
        }

        pendingPayloads.append(payload)
        let primed = try handleTransportConnected()

        let updatedStatus = runtime.statusSnapshot()
        return OutboundSnapshot(
            emittedFrames: primed.emittedFrames,
            queuedPayloads: pendingPayloads.count,
            authenticated: updatedStatus.authenticated,
            sessionID: updatedStatus.sessionID
        )
    }

    func handleInboundFrame(_ payload: Data) -> InboundSnapshot {
        let previousStatus = runtime.statusSnapshot()
        let snapshot = runtime.handleInboundFrame(payload)
        var emittedFrames = snapshot.emittedFrames
        let deliveredPayloads = snapshot.deliveredPayloads
        if snapshot.authFailCode != nil {
            pendingPayloads.removeAll()
            handleClientAuthFailure(wasAuthenticated: previousStatus.authenticated)
        }
        let status = runtime.statusSnapshot()
        if status.authenticated {
            resetClientRetryPolicy()
        }
        if status.authenticated, !status.appDataSendingBlocked, !pendingPayloads.isEmpty {
            do {
                emittedFrames.append(contentsOf: try flushPendingPayloads())
            } catch {
            }
        }
        return InboundSnapshot(
            emittedFrames: emittedFrames,
            deliveredPayloads: deliveredPayloads,
            queuedPayloads: pendingPayloads.count,
            authenticated: status.authenticated,
            sessionID: status.sessionID,
            authFailCode: snapshot.authFailCode
        )
    }

    private func flushPendingPayloads() throws -> [Data] {
        guard runtime.statusSnapshot().authenticated, !pendingPayloads.isEmpty else {
            return []
        }
        let payloads = pendingPayloads
        pendingPayloads.removeAll()
        var emittedFrames: [Data] = []
        do {
            for payload in payloads {
                let snapshot = try runtime.sendApp(payload)
                emittedFrames.append(contentsOf: snapshot.emittedFrames)
            }
            return emittedFrames
        } catch {
            pendingPayloads = payloads + pendingPayloads
            throw error
        }
    }

    private func handleClientAuthFailure(wasAuthenticated: Bool) {
        let status = runtime.statusSnapshot()
        guard status.clientMode else {
            return
        }
        if wasAuthenticated {
            clearRetrySchedule()
            return
        }
        guard transportConnected, retryBackoffMaxSec > 0.0 else {
            return
        }
        consecutiveFailures += 1
        let exponent = max(0, consecutiveFailures - 1)
        let delaySec = min(retryBackoffMaxSec, retryBackoffInitialSec * pow(2.0, Double(exponent)))
        retryNotBeforeMono = timeProvider() + delaySec
        retryNotBeforeUnixTs = unixTimeProvider() + delaySec
    }

    private func resetClientRetryPolicy() {
        clearRetrySchedule()
        consecutiveFailures = 0
    }

    private func clearRetrySchedule() {
        retryNotBeforeMono = 0.0
        retryNotBeforeUnixTs = nil
    }

    private func shouldRetryClientHandshake(nowMono: TimeInterval) -> Bool {
        let status = runtime.statusSnapshot()
        guard status.clientMode,
              transportConnected,
              !status.authenticated,
              status.authFailCode != 0,
              retryNotBeforeMono > 0.0,
              retryNotBeforeMono <= nowMono else {
            return false
        }
        return true
    }
}
