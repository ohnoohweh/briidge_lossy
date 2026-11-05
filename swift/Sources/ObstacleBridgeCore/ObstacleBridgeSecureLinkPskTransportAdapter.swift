import Foundation

/// Severity is deliberately owned by Core so every Swift host can apply the
/// same operator contract without exposing protected payload material.
public enum ObstacleBridgeRuntimeDiagnosticLevel: Int, Sendable {
    case debug = 10
    case info = 20
    case warning = 30

    public var name: String {
        switch self {
        case .debug: return "DEBUG"
        case .info: return "INFO"
        case .warning: return "WARNING"
        }
    }
}

public final class ObstacleBridgeSecureLinkPskTransportAdapter {
    /// Emits bounded lifecycle evidence only.  It never includes protected
    /// payload bytes, nonces, or key material.
    public typealias DiagnosticSink = (ObstacleBridgeRuntimeDiagnosticLevel, String, [String: Any]) -> Void
    public struct OutboundSnapshot {
        public var emittedFrames: [Data]
        var queuedPayloads: Int
        var authenticated: Bool
        var sessionID: UInt64
    }

    public struct InboundSnapshot {
        public var emittedFrames: [Data]
        public var deliveredPayloads: [Data]
        var queuedPayloads: Int
        var authenticated: Bool
        var sessionID: UInt64
        var authFailCode: Int?
    }

    private let runtime: ObstacleBridgeSecureLinkPskRuntime
    private let timeProvider: () -> TimeInterval
    private let unixTimeProvider: () -> TimeInterval
    private let diagnosticSink: DiagnosticSink?
    private var pendingPayloads: [Data] = []
    private var pendingPayloadWorkSink: (() -> Void)?
    private var transportConnected = false
    private var transportConnectedAtMono: TimeInterval?
    private var handshakeStartedAtMono: TimeInterval?
    private var handshakeAttemptsTotal = 0
    private var retryState: ObstacleBridgeSecureLinkPSKRetryState
    private var retryNotBeforeUnixTs: TimeInterval?

    init(
        runtime: ObstacleBridgeSecureLinkPskRuntime,
        retryBackoffInitialMS: Int = 1000,
        retryBackoffMaxMS: Int = 5000,
        timeProvider: (() -> TimeInterval)? = nil,
        unixTimeProvider: (() -> TimeInterval)? = nil,
        diagnosticSink: DiagnosticSink? = nil
    ) {
        self.runtime = runtime
        self.retryState = .init(policy: .init(
            initialBackoff: Double(max(0, retryBackoffInitialMS)) / 1000.0,
            maximumBackoff: Double(max(0, retryBackoffMaxMS)) / 1000.0
        ))
        self.timeProvider = timeProvider ?? { ProcessInfo.processInfo.systemUptime }
        self.unixTimeProvider = unixTimeProvider ?? { Date().timeIntervalSince1970 }
        self.diagnosticSink = diagnosticSink
    }

    public convenience init(
        clientPSK: String,
        rekeyAfterFrames: Int = 0,
        rekeyAfterSeconds: TimeInterval = 0,
        diagnosticSink: DiagnosticSink? = nil
    ) {
        self.init(
            runtime: .init(
                clientMode: true,
                psk: clientPSK,
                rekeyAfterFrames: rekeyAfterFrames,
                rekeyAfterSeconds: rekeyAfterSeconds
            ),
            diagnosticSink: diagnosticSink
        )
    }

    public var protocolState: ObstacleBridgeSecureLinkPSKState? {
        runtime.protocolState
    }

    func statusSnapshot() -> ObstacleBridgeSecureLinkPskRuntime.StatusSnapshot {
        var snapshot = runtime.statusSnapshot()
        let nowMono = timeProvider()
        snapshot.handshakeAttemptsTotal = handshakeAttemptsTotal
        snapshot.consecutiveFailures = retryState.consecutiveFailures
        snapshot.retryBackoffSec = retryState.remainingBackoff(now: nowMono)
        snapshot.nextRetryUnixTs = retryNotBeforeUnixTs
        return snapshot
    }

    public func requestSecureLinkRekey(sessionID: UInt64? = nil, clientNonce: Data? = nil) throws -> OutboundSnapshot {
        let snapshot = try runtime.requestClientRekey(sessionID: sessionID, clientNonce: clientNonce)
        emitDiagnostic(.info, "secure_link_rekey_started", [
            "trigger": "operator",
            "session_id": diagnosticSessionID(snapshot.sessionID),
            "frame_types": diagnosticFrameTypes(snapshot.emittedFrames),
        ])
        return OutboundSnapshot(
            emittedFrames: snapshot.emittedFrames,
            queuedPayloads: pendingPayloads.count,
            authenticated: snapshot.authenticated,
            sessionID: snapshot.sessionID
        )
    }

    func setPendingPayloadWorkSink(_ sink: @escaping () -> Void) {
        pendingPayloadWorkSink = sink
    }

    func pendingPayloadCount() -> Int { pendingPayloads.count }

    public func pollDueFrames() throws -> OutboundSnapshot {
        var emittedFrames = try runtime.pollDueFrames()
        if emittedFrames.isEmpty,
           transportConnected,
           shouldRetryClientHandshake(nowMono: timeProvider()) {
            let handshake = try runtime.beginClientHandshake()
            handshakeAttemptsTotal += 1
            clearRetrySchedule()
            emittedFrames.append(contentsOf: handshake.emittedFrames)
            recordHandshakeStarted(reason: "retry_due", frames: handshake.emittedFrames)
        }
        if !emittedFrames.isEmpty, runtime.statusSnapshot().rekeyInProgress {
            emitDiagnostic(.info, "secure_link_rekey_started", [
                "trigger": runtime.statusSnapshot().lastRekeyTrigger,
                "session_id": diagnosticSessionID(runtime.statusSnapshot().sessionID),
                "frame_types": diagnosticFrameTypes(emittedFrames),
            ])
        }
        recordControlFrames(direction: "tx", source: "due", frames: emittedFrames)
        return OutboundSnapshot(
            emittedFrames: emittedFrames,
            queuedPayloads: pendingPayloads.count,
            authenticated: runtime.statusSnapshot().authenticated,
            sessionID: runtime.statusSnapshot().sessionID
        )
    }

    public func handleTransportDisconnected() {
        let status = runtime.statusSnapshot()
        emitDiagnostic(.warning, "secure_link_transport_disconnected", [
            "session_id": diagnosticSessionID(status.sessionID),
            "authenticated": status.authenticated,
            "last_event": status.lastEvent,
            "handshake_attempts_total": handshakeAttemptsTotal,
        ])
        transportConnected = false
        transportConnectedAtMono = nil
        handshakeStartedAtMono = nil
        pendingPayloads.removeAll(keepingCapacity: false)
        runtime.handleTransportDisconnected()
    }

    public func handleTransportConnected(sessionID: UInt64? = nil, clientNonce: Data? = nil) throws -> OutboundSnapshot {
        transportConnected = true
        if transportConnectedAtMono == nil {
            transportConnectedAtMono = timeProvider()
        }
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
        if retryState.remainingBackoff(now: nowMono) > 0 {
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

        let handshake = try runtime.beginClientHandshake(sessionID: sessionID, clientNonce: clientNonce)
        handshakeAttemptsTotal += 1
        let emittedFrames = handshake.emittedFrames
        recordHandshakeStarted(reason: "transport_connected", frames: emittedFrames)

        let updatedStatus = runtime.statusSnapshot()
        return OutboundSnapshot(
            emittedFrames: emittedFrames,
            queuedPayloads: pendingPayloads.count,
            authenticated: updatedStatus.authenticated,
            sessionID: updatedStatus.sessionID
        )
    }

    public func handleOutboundPayload(_ payload: Data) throws -> OutboundSnapshot {
        let status = runtime.statusSnapshot()
        if status.appDataSendingBlocked || !pendingPayloads.isEmpty {
            pendingPayloads.append(payload)
            // A REKEY_COMMIT keeps the active keys installed, but Core
            // deliberately blocks application encryption until REKEY_DONE.
            // Match Python's post-commit hold: only ask the owner to drain
            // after that barrier has lifted.
            if status.authenticated, !status.appDataSendingBlocked {
                pendingPayloadWorkSink?()
            }
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

    public func handleInboundFrame(_ payload: Data) -> InboundSnapshot {
        let previousStatus = runtime.statusSnapshot()
        let inboundFrame = ObstacleBridgeSecureLinkPskCodec.parseFrame(payload)
        let snapshot = runtime.handleInboundFrame(payload)
        let emittedFrames = snapshot.emittedFrames
        let deliveredPayloads = snapshot.deliveredPayloads
        if snapshot.authFailCode != nil {
            pendingPayloads.removeAll()
            handleClientAuthFailure(wasAuthenticated: previousStatus.authenticated)
        }
        let status = runtime.statusSnapshot()
        if snapshot.authFailCode != nil {
            emitDiagnostic(.warning, "secure_link_authentication_failed", [
                "session_id": diagnosticSessionID(status.sessionID),
                "auth_fail_code": snapshot.authFailCode ?? -1,
                "last_event": status.lastEvent,
            ])
        }
        recordInboundControlFrame(
            inboundFrame,
            previousStatus: previousStatus,
            status: status,
            emittedFrames: emittedFrames,
            authFailCode: snapshot.authFailCode
        )
        if status.authenticated {
            resetClientRetryPolicy()
            if !previousStatus.authenticated {
                recordAuthenticated(status: status)
            }
        }
        if status.authenticated, !status.appDataSendingBlocked, !pendingPayloads.isEmpty {
            pendingPayloadWorkSink?()
        }
        if status.rekeysCompletedTotal > previousStatus.rekeysCompletedTotal {
            emitDiagnostic(.info, "secure_link_rekey_completed", [
                "session_id": diagnosticSessionID(status.sessionID),
                "rekeys_completed_total": status.rekeysCompletedTotal,
                "trigger": status.lastRekeyTrigger,
            ])
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

    /// Encrypt one FIFO payload and leave the rest for a later owner-queue
    /// continuation.  A reconnect cannot turn a backlog into one large,
    /// non-interruptible worker turn.
    func drainOnePendingPayload() throws -> OutboundSnapshot {
        let status = runtime.statusSnapshot()
        // Keep FIFO application data behind the rekey commit/done cutover.
        // Python uses _client_rekey_hold_after_commit for the same behavior.
        guard status.authenticated, !status.appDataSendingBlocked, !pendingPayloads.isEmpty else {
            return OutboundSnapshot(emittedFrames: [], queuedPayloads: pendingPayloads.count, authenticated: status.authenticated, sessionID: status.sessionID)
        }
        let payload = pendingPayloads.removeFirst()
        do {
            let snapshot = try runtime.sendApp(payload)
            return OutboundSnapshot(emittedFrames: snapshot.emittedFrames, queuedPayloads: pendingPayloads.count, authenticated: snapshot.authenticated, sessionID: snapshot.sessionID)
        } catch {
            pendingPayloads.insert(payload, at: 0)
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
        guard transportConnected else {
            return
        }
        guard let delaySec = retryState.recordUnauthenticatedFailure(now: timeProvider()) else { return }
        retryNotBeforeUnixTs = unixTimeProvider() + delaySec
    }

    private func resetClientRetryPolicy() {
        clearRetrySchedule()
        retryState.reset()
    }

    private func clearRetrySchedule() {
        retryState.clearSchedule()
        retryNotBeforeUnixTs = nil
    }

    private func shouldRetryClientHandshake(nowMono: TimeInterval) -> Bool {
        let status = runtime.statusSnapshot()
        guard status.clientMode,
              transportConnected,
              !status.authenticated,
              status.authFailCode != 0,
              retryState.isDue(now: nowMono) else {
            return false
        }
        return true
    }

    private func recordHandshakeStarted(reason: String, frames: [Data]) {
        handshakeStartedAtMono = timeProvider()
        let status = runtime.statusSnapshot()
        emitDiagnostic(.info, "secure_link_handshake_started", [
            "reason": reason,
            "session_id": diagnosticSessionID(status.sessionID),
            "handshake_attempt": handshakeAttemptsTotal,
            "transport_connected_age_ms": elapsedMilliseconds(since: transportConnectedAtMono) ?? NSNull(),
            "frame_types": diagnosticFrameTypes(frames),
        ])
    }

    private func recordInboundControlFrame(
        _ frame: ObstacleBridgeSecureLinkPskCodec.ParsedFrame?,
        previousStatus: ObstacleBridgeSecureLinkPskRuntime.StatusSnapshot,
        status: ObstacleBridgeSecureLinkPskRuntime.StatusSnapshot,
        emittedFrames: [Data],
        authFailCode: Int?
    ) {
        emitDiagnostic(.debug, "secure_link_frame_received", [
            "frame_type": frame?.slType ?? -1,
            "frame_session_id": diagnosticSessionID(frame?.sessionID ?? 0),
            "frame_counter": diagnosticSessionID(frame?.counter ?? 0),
            "session_id_before": diagnosticSessionID(previousStatus.sessionID),
            "session_id_after": diagnosticSessionID(status.sessionID),
            "authenticated_before": previousStatus.authenticated,
            "authenticated_after": status.authenticated,
            "auth_fail_code": authFailCode ?? NSNull(),
            "response_frame_types": diagnosticFrameTypes(emittedFrames),
            "handshake_attempt": handshakeAttemptsTotal,
        ])
        recordControlFrames(direction: "tx", source: "inbound_response", frames: emittedFrames)
    }

    private func recordControlFrames(direction: String, source: String, frames: [Data]) {
        for frame in frames {
            guard let parsed = ObstacleBridgeSecureLinkPskCodec.parseFrame(frame) else {
                continue
            }
            emitDiagnostic(.debug, "secure_link_frame_emitted", [
                "direction": direction,
                "source": source,
                "frame_type": parsed.slType,
                "frame_session_id": diagnosticSessionID(parsed.sessionID),
                "frame_counter": diagnosticSessionID(parsed.counter),
                "handshake_attempt": handshakeAttemptsTotal,
            ])
        }
    }

    private func recordAuthenticated(status: ObstacleBridgeSecureLinkPskRuntime.StatusSnapshot) {
        emitDiagnostic(.info, "secure_link_authenticated", [
            "session_id": diagnosticSessionID(status.sessionID),
            "handshake_attempt": handshakeAttemptsTotal,
            "handshake_duration_ms": elapsedMilliseconds(since: handshakeStartedAtMono) ?? NSNull(),
            "transport_connected_age_ms": elapsedMilliseconds(since: transportConnectedAtMono) ?? NSNull(),
        ])
    }

    private func emitDiagnostic(_ level: ObstacleBridgeRuntimeDiagnosticLevel, _ event: String, _ fields: [String: Any]) {
        diagnosticSink?(level, event, fields)
    }

    private func diagnosticFrameTypes(_ frames: [Data]) -> [Int] {
        frames.compactMap { ObstacleBridgeSecureLinkPskCodec.parseFrame($0)?.slType }
    }

    private func diagnosticSessionID(_ value: UInt64) -> String {
        String(value)
    }

    private func elapsedMilliseconds(since start: TimeInterval?) -> Double? {
        guard let start else { return nil }
        return max(0, (timeProvider() - start) * 1_000)
    }
}
