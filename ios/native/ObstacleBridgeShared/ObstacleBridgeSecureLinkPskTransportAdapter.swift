import Foundation

final class ObstacleBridgeSecureLinkPskTransportAdapter {
    /// Emits bounded lifecycle evidence only.  It never includes protected
    /// payload bytes, nonces, or key material.
    typealias DiagnosticSink = (String, [String: Any]) -> Void
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
    private let timeProvider: () -> TimeInterval
    private let unixTimeProvider: () -> TimeInterval
    private let diagnosticSink: DiagnosticSink?
    private var pendingPayloads: [Data] = []
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

    func statusSnapshot() -> ObstacleBridgeSecureLinkPskRuntime.StatusSnapshot {
        var snapshot = runtime.statusSnapshot()
        let nowMono = timeProvider()
        snapshot.handshakeAttemptsTotal = handshakeAttemptsTotal
        snapshot.consecutiveFailures = retryState.consecutiveFailures
        snapshot.retryBackoffSec = retryState.remainingBackoff(now: nowMono)
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
            recordHandshakeStarted(reason: "retry_due", frames: handshake.emittedFrames)
        }
        recordControlFrames(direction: "tx", source: "due", frames: emittedFrames)
        return OutboundSnapshot(
            emittedFrames: emittedFrames,
            queuedPayloads: pendingPayloads.count,
            authenticated: runtime.statusSnapshot().authenticated,
            sessionID: runtime.statusSnapshot().sessionID
        )
    }

    func handleTransportDisconnected() {
        let status = runtime.statusSnapshot()
        emitDiagnostic("secure_link_transport_disconnected", [
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

    func handleTransportConnected() throws -> OutboundSnapshot {
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

        let handshake = try runtime.beginClientHandshake()
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
        let inboundFrame = ObstacleBridgeSecureLinkPskCodec.parseFrame(payload)
        let snapshot = runtime.handleInboundFrame(payload)
        var emittedFrames = snapshot.emittedFrames
        let deliveredPayloads = snapshot.deliveredPayloads
        if snapshot.authFailCode != nil {
            pendingPayloads.removeAll()
            handleClientAuthFailure(wasAuthenticated: previousStatus.authenticated)
        }
        let status = runtime.statusSnapshot()
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
        emitDiagnostic("secure_link_handshake_started", [
            "reason": reason,
            "session_id": diagnosticSessionID(status.sessionID),
            "handshake_attempt": handshakeAttemptsTotal,
            "transport_connected_age_ms": elapsedMilliseconds(since: transportConnectedAtMono),
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
        let shouldRecord = frame?.slType != ObstacleBridgeSecureLinkPskRuntime.typeData
            || !previousStatus.authenticated
            || previousStatus.authenticated != status.authenticated
            || authFailCode != nil
        guard shouldRecord else { return }
        emitDiagnostic("secure_link_frame_received", [
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
            guard let parsed = ObstacleBridgeSecureLinkPskCodec.parseFrame(frame),
                  parsed.slType != ObstacleBridgeSecureLinkPskRuntime.typeData else {
                continue
            }
            emitDiagnostic("secure_link_frame_emitted", [
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
        emitDiagnostic("secure_link_authenticated", [
            "session_id": diagnosticSessionID(status.sessionID),
            "handshake_attempt": handshakeAttemptsTotal,
            "handshake_duration_ms": elapsedMilliseconds(since: handshakeStartedAtMono),
            "transport_connected_age_ms": elapsedMilliseconds(since: transportConnectedAtMono),
        ])
    }

    private func emitDiagnostic(_ event: String, _ fields: [String: Any]) {
        diagnosticSink?(event, fields)
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
