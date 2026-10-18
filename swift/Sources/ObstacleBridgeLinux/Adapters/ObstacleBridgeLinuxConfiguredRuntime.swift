import Foundation
import ObstacleBridgeCore

/// One redacted peer projection assembled from the Core SecureLink state and
/// the adapter-owned transport lifecycle. It deliberately has no PSK, nonce,
/// key, or raw frame material, so the Linux Admin surface can publish one
/// authoritative peer row without independently rebuilding protocol fields.
public struct ObstacleBridgeLinuxPeerSnapshot: Codable, Equatable, Sendable {
    public let transport: String
    public let lifecycleState: String
    /// SecureLink's protocol state is deliberately distinct from the outer
    /// transport lifecycle: an admitted protected epoch is `connected` while
    /// SecureLink itself is `authenticated`.
    public let secureLinkState: String
    public let connectionEpoch: UInt64
    public let sessionID: UInt64?
    public let pendingRekeySessionID: UInt64?
    public let ready: Bool
    public let authenticated: Bool
    public let applicationSendingBlocked: Bool
    public let attempts: Int
    public let nextRetryMilliseconds: Int?
    public let protectedTxCounter: UInt64
    public let protectedRxCounter: UInt64
    public let protectedFramesSentTotal: UInt64
    public let protectedFramesReceivedTotal: UInt64
    public let authenticatedGenerationsTotal: UInt64
    public let rekeysCompletedTotal: UInt64
    public let compression: ObstacleBridgeMuxCompressionSnapshot
}

public struct ObstacleBridgeLinuxRuntimeStatus: Codable, Equatable, Sendable {
    public let transport: String
    public let state: String
    public let attempts: Int
    public let failureReason: String?
    public let configuredCandidates: [String]
    public let activeHost: String?
    public let port: Int
    public let secureLinkMode: String
    public let secureLinkState: String
    public let appReady: Bool
    public let activeTCPChannels: Int
    public let activeUDPChannels: Int
    public let queuedServiceFrames: Int
    public let droppedServiceFrames: Int
    public let malformedServiceFrames: Int
    public let serviceFailures: Int
    public let openedTCPChannels: Int
    public let openedUDPChannels: Int
    public let receiveLoopState: String
    public let receiveEpoch: UInt64
    public let receivedFrames: Int
    public let droppedReceiveFrames: Int
    public let receiveQueueDepth: Int
    public let receiveFailureReason: String?
    public let peer: ObstacleBridgeLinuxPeerSnapshot
}

/// Config-driven lower transport plus optional SecureLink PSK state. The
/// session is explicit: callers must close it when their higher-level runtime
/// decides the transport epoch has ended.
public final class ObstacleBridgeLinuxConfiguredSession: @unchecked Sendable {
    // The lower session's closures deliberately retain the client weakly to
    // avoid a client/session cycle. Keep the client alive for this configured
    // epoch so those closures remain usable after `connect` returns.
    private let lower: ObstacleBridgeLinuxOverlayTransportClient?
    private let lowerSession: ObstacleBridgeLinuxOverlayTransportSession
    private let secureLink: ObstacleBridgeSecureLinkPSKClient?
    private let overlayAdapter: ObstacleBridgeOverlayLayerTransportAdapter?
    private let secureLinkServer: ObstacleBridgeSecureLinkPSKServer?
    private let requestLock = NSLock()
    private var receiveOwnerActive = false
    private var pendingCompatibilityReply: (signal: DispatchSemaphore, value: Data?)?
    /// The resource owner supplies measured request/reply latency. The Core
    /// lifecycle decides whether sustained delay retires the epoch.
    public var onTransportLivenessSample: ((Double) -> Void)?
    private(set) public var snapshot: ObstacleBridgeLinuxOverlaySnapshot

    init(lower: ObstacleBridgeLinuxOverlayTransportClient, lowerSession: ObstacleBridgeLinuxOverlayTransportSession, secureLink: ObstacleBridgeSecureLinkPSKClient?, secureLinkServer: ObstacleBridgeSecureLinkPSKServer? = nil, transport: ObstacleBridgeLinuxTransport) {
        self.lower = lower
        self.lowerSession = lowerSession
        self.secureLink = secureLink
        self.overlayAdapter = nil
        self.secureLinkServer = secureLinkServer
        self.snapshot = .init(transport: transport.rawValue, state: "connected", attempts: 1, failureReason: nil)
        lowerSession.onLivenessSample = { [weak self] delayMilliseconds in
            self?.onTransportLivenessSample?(delayMilliseconds)
        }
    }

    init(lowerSession: ObstacleBridgeLinuxOverlayTransportSession, secureLink: ObstacleBridgeSecureLinkPSKClient?, secureLinkServer: ObstacleBridgeSecureLinkPSKServer? = nil, transport: ObstacleBridgeLinuxTransport) {
        self.lower = nil
        self.lowerSession = lowerSession
        self.secureLink = secureLink
        self.overlayAdapter = nil
        self.secureLinkServer = secureLinkServer
        self.snapshot = .init(transport: transport.rawValue, state: "connected", attempts: 1, failureReason: nil)
        lowerSession.onLivenessSample = { [weak self] delayMilliseconds in
            self?.onTransportLivenessSample?(delayMilliseconds)
        }
    }

    init(lower: ObstacleBridgeLinuxOverlayTransportClient, lowerSession: ObstacleBridgeLinuxOverlayTransportSession, overlayAdapter: ObstacleBridgeOverlayLayerTransportAdapter, transport: ObstacleBridgeLinuxTransport) {
        self.lower = lower
        self.lowerSession = lowerSession
        self.secureLink = nil
        self.overlayAdapter = overlayAdapter
        self.secureLinkServer = nil
        self.snapshot = .init(transport: transport.rawValue, state: "connected", attempts: 1, failureReason: nil)
        lowerSession.onLivenessSample = { [weak self] delayMilliseconds in
            self?.onTransportLivenessSample?(delayMilliseconds)
        }
    }

    public func send(_ payload: Data) throws -> Data {
        do {
            requestLock.lock()
            let ownerActive = receiveOwnerActive
            requestLock.unlock()
            if ownerActive { return try sendThroughReceiveOwner(payload) }
            let startedAt = ProcessInfo.processInfo.systemUptime
            if let overlayAdapter {
                let delivered = try exchangeAdapterFrames(try overlayAdapter.handleOutboundPayload(payload).emittedFrames)
                guard let reply = delivered.first else { throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF }
                recordTransportLiveness(since: startedAt)
                return reply
            }
            if let secureLink { let reply = try secureLink.unprotect(lowerSession.exchange(secureLink.protect(payload))); recordTransportLiveness(since: startedAt); return reply }
            if let secureLinkServer { let reply = try secureLinkServer.unprotect(lowerSession.exchange(secureLinkServer.protect(payload))); recordTransportLiveness(since: startedAt); return reply }
            let reply = try lowerSession.exchange(payload)
            recordTransportLiveness(since: startedAt)
            return reply
        } catch {
            snapshot = .init(transport: snapshot.transport, state: "failed", attempts: snapshot.attempts, failureReason: error.localizedDescription)
            throw error
        }
    }

    /// Separately scheduled transport directions. SecureLink owns the
    /// directional counters, so the receive worker never observes ciphertext
    /// outside this boundary.
    public var supportsDuplexReceive: Bool { true }
    public func sendOneWay(_ payload: Data) throws {
        do {
            if let overlayAdapter {
                for wire in try overlayAdapter.handleOutboundPayload(payload).emittedFrames { try lowerSession.send(wire) }
            }
            else if let secureLink { try lowerSession.send(secureLink.protect(payload)) }
            else if let secureLinkServer { try lowerSession.send(secureLinkServer.protect(payload)) }
            else { try lowerSession.send(payload) }
        } catch {
            fail(error)
            throw error
        }
    }

    public func receiveInbound() throws -> Data {
        do {
            let wire = try lowerSession.receive()
            if let overlayAdapter {
                let inbound = overlayAdapter.handleInboundFrame(wire)
                for reply in inbound.emittedFrames { try lowerSession.send(reply) }
                guard let payload = inbound.deliveredPayloads.first else { throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF }
                return payload
            }
            if let secureLink { return try secureLink.unprotect(wire) }
            if let secureLinkServer { return try secureLinkServer.unprotect(wire) }
            return wire
        } catch {
            fail(error)
            throw error
        }
    }

    /// Rotates the authenticated PSK generation while preserving this lower
    /// transport epoch. The role-neutral SecureLink Core owns transcript
    /// validation and atomic key cutover; this adapter only performs the
    /// request/response exchanges required by its platform transport.
    public func rekey(sessionID: UInt64, clientNonce: Data) throws {
        if let overlayAdapter {
            _ = try exchangeAdapterFrames(try overlayAdapter.requestSecureLinkRekey(sessionID: sessionID, clientNonce: clientNonce).emittedFrames)
            return
        }
        guard let secureLink else { throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame }
        do {
            let reply = try lowerSession.exchange(secureLink.beginRekey(sessionID: sessionID, clientNonce: clientNonce))
            let commit = try secureLink.handleRekeyReply(reply)
            try secureLink.handleRekeyDone(lowerSession.exchange(commit))
        } catch {
            fail(error)
            throw error
        }
    }

    /// Starts a live owner-driven rekey without creating a competing reader.
    /// The receive owner consumes the reply/commit/done control frames and
    /// forwards any Core-emitted response on the existing lower transport.
    public func requestSecureLinkRekey(sessionID: UInt64, clientNonce: Data) throws -> Int {
        guard let overlayAdapter else { throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame }
        do {
            let outbound = try overlayAdapter.requestSecureLinkRekey(sessionID: sessionID, clientNonce: clientNonce).emittedFrames
            for frame in outbound { try lowerSession.send(frame) }
            return outbound.count
        } catch {
            fail(error)
            throw error
        }
    }

    /// Used exclusively by the epoch's receive worker. Compatibility request
    /// replies are consumed here, so an older diagnostic caller cannot create
    /// a second descriptor reader beside ChannelMux dispatch.
    public func receiveForOwner() throws -> Data? {
        do {
            while true {
                let wire = try lowerSession.receive()
                let payload: Data?
                if let overlayAdapter {
                    let inbound = overlayAdapter.handleInboundFrame(wire)
                    for reply in inbound.emittedFrames { try lowerSession.send(reply) }
                    payload = inbound.deliveredPayloads.first
                } else if let secureLink {
                    payload = try secureLink.unprotect(wire)
                } else if let secureLinkServer {
                    payload = try secureLinkServer.unprotect(wire)
                } else {
                    payload = wire
                }
                // SecureLink rekey controls have no application payload. They
                // are fully handled by Core above and must not retire a live
                // receive epoch merely because ChannelMux has nothing to read.
                guard let payload else { continue }
                requestLock.lock()
                if let pending = pendingCompatibilityReply {
                    pendingCompatibilityReply?.value = payload
                    pending.signal.signal()
                    requestLock.unlock()
                    return nil
                }
                requestLock.unlock()
                return payload
            }
        } catch {
            fail(error)
            throw error
        }
    }

    public func activateReceiveOwner() {
        requestLock.lock(); receiveOwnerActive = true; requestLock.unlock()
    }

    public var supportsLivenessProbes: Bool { lowerSession.supportsLivenessProbes }

    /// Cleartext peers may carry diagnostics before a ChannelMux owner is
    /// installed. Protected records are authenticated and therefore a decode
    /// rejection must retire the epoch instead of being treated as noise.
    public var isProtected: Bool { overlayAdapter != nil || secureLink != nil || secureLinkServer != nil }

    public func probeLiveness() throws { try lowerSession.probeLiveness() }
    public func cancelReceive() { lowerSession.close() }

    /// Redacted Core-owned SecureLink state for the current adapter epoch.
    /// Neither role exposes its PSK, nonces, or traffic plaintext here.
    public var secureLinkProtocolState: ObstacleBridgeSecureLinkPSKState? {
        overlayAdapter?.secureLinkProtocolState() ?? secureLink?.state ?? secureLinkServer?.state
    }

    public func close() {
        overlayAdapter?.handleTransportDisconnected()
        lowerSession.close()
        if snapshot.state != "failed" {
            snapshot = .init(transport: snapshot.transport, state: "disconnected", attempts: snapshot.attempts, failureReason: nil)
        }
    }

    deinit { close() }

    private func fail(_ error: Error) {
        snapshot = .init(transport: snapshot.transport, state: "failed", attempts: snapshot.attempts, failureReason: error.localizedDescription)
    }

    func completeClientHandshake(sessionID: UInt64, clientNonce: Data) throws {
        guard let overlayAdapter else { return }
        _ = try exchangeAdapterFrames(try overlayAdapter.handleTransportConnected(sessionID: sessionID, clientNonce: clientNonce).emittedFrames)
        guard overlayAdapter.secureLinkProtocolState()?.authenticated == true else {
            throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame
        }
    }

    private func exchangeAdapterFrames(_ initialFrames: [Data]) throws -> [Data] {
        guard let overlayAdapter else { return [] }
        var pending = initialFrames
        var delivered: [Data] = []
        while !pending.isEmpty {
            let outbound = pending.removeFirst()
            let inbound = overlayAdapter.handleInboundFrame(try lowerSession.exchange(outbound))
            pending.append(contentsOf: inbound.emittedFrames)
            delivered.append(contentsOf: inbound.deliveredPayloads)
        }
        return delivered
    }

    private func recordTransportLiveness(since startedAt: TimeInterval) {
        onTransportLivenessSample?(max(0, (ProcessInfo.processInfo.systemUptime - startedAt) * 1_000))
    }

    private func sendThroughReceiveOwner(_ payload: Data) throws -> Data {
        let startedAt = ProcessInfo.processInfo.systemUptime
        let signal = DispatchSemaphore(value: 0)
        requestLock.lock()
        guard pendingCompatibilityReply == nil else {
            requestLock.unlock()
            throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame
        }
        pendingCompatibilityReply = (signal, nil)
        requestLock.unlock()
        do { try sendOneWay(payload) }
        catch {
            requestLock.lock(); pendingCompatibilityReply = nil; requestLock.unlock()
            throw error
        }
        guard signal.wait(timeout: .now() + 10) == .success else {
            requestLock.lock(); pendingCompatibilityReply = nil; requestLock.unlock()
            throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF
        }
        requestLock.lock()
        let reply = pendingCompatibilityReply?.value
        pendingCompatibilityReply = nil
        requestLock.unlock()
        guard let reply else { throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF }
        recordTransportLiveness(since: startedAt)
        return reply
    }
}

/// Mutable admission state belongs to one concrete transport lifecycle owner.
/// `ObstacleBridgeLinuxConfiguredRuntime` only publishes the active state's
/// redacted projection for Admin and ChannelMux consumers; it does not retain
/// candidate rotation or a SecureLink handshake across transport owners.
final class ObstacleBridgeLinuxConnectionAdmission: @unchecked Sendable {
    let configuration: ObstacleBridgeLinuxRuntimeConfiguration
    var snapshot: ObstacleBridgeLinuxOverlaySnapshot
    var activeSession: ObstacleBridgeLinuxConfiguredSession?
    var activeHost: String?
    var secureLinkState: String
    var connectionEpoch: UInt64 = 0
    var candidateStartIndex = 0
    // `connect` runs on the live runtime's serialized queue, but `stop` must
    // be able to interrupt an authenticated-handshake read from another
    // caller.  This slot is deliberately separate from `activeSession`: an
    // epoch becomes active only after peer confirmation succeeds.
    private let inFlightConnectionLock = NSLock()
    private var inFlightConnection: ObstacleBridgeLinuxConfiguredSession?
    private var inFlightConnectionCancelled = false

    init(configuration: ObstacleBridgeLinuxRuntimeConfiguration) {
        self.configuration = configuration
        self.snapshot = .init(transport: configuration.transport.rawValue, state: "disconnected", attempts: 0, failureReason: nil)
        self.secureLinkState = configuration.secureLinkPSK == nil ? "off" : "disconnected"
    }

    func cancelInFlightConnection() {
        inFlightConnectionLock.lock()
        inFlightConnectionCancelled = true
        let pending = inFlightConnection
        inFlightConnectionLock.unlock()
        pending?.close()
    }

    func beginInFlightConnection() {
        inFlightConnectionLock.lock()
        inFlightConnectionCancelled = false
        inFlightConnection = nil
        inFlightConnectionLock.unlock()
    }

    var isInFlightConnectionCancelled: Bool {
        inFlightConnectionLock.lock()
        let cancelled = inFlightConnectionCancelled
        inFlightConnectionLock.unlock()
        return cancelled
    }

    func installInFlightConnection(_ pending: ObstacleBridgeLinuxConfiguredSession) -> Bool {
        inFlightConnectionLock.lock()
        inFlightConnection = pending
        let cancelled = inFlightConnectionCancelled
        inFlightConnectionLock.unlock()
        if cancelled { pending.close() }
        return !cancelled
    }

    func clearInFlightConnection(_ pending: ObstacleBridgeLinuxConfiguredSession? = nil) {
        inFlightConnectionLock.lock()
        if pending == nil || inFlightConnection === pending { inFlightConnection = nil }
        inFlightConnectionLock.unlock()
    }
}

/// Config-driven session construction and redacted projection. Candidate
/// admission, SecureLink handshake state, cancellation, and epoch rotation are
/// held by the concrete lifecycle owner's `ObstacleBridgeLinuxConnectionAdmission`.
public final class ObstacleBridgeLinuxConfiguredRuntime {
    public let configuration: ObstacleBridgeLinuxRuntimeConfiguration
    private let defaultAdmission: ObstacleBridgeLinuxConnectionAdmission
    private var publishedAdmission: ObstacleBridgeLinuxConnectionAdmission
    let compressionTelemetry: ObstacleBridgeMuxCompressionTelemetry
    /// Redacted connection-attempt evidence supplied by the foreground owner.
    /// Values are restricted to transport metadata and error text; no key or
    /// packet data crosses this callback.
    public var onDiagnostic: ((String, [String: String]) -> Void)?

    public var snapshot: ObstacleBridgeLinuxOverlaySnapshot { publishedAdmission.snapshot }
    public var connectionEpoch: UInt64 { publishedAdmission.connectionEpoch }

    public init(configuration: ObstacleBridgeLinuxRuntimeConfiguration) {
        self.configuration = configuration
        let admission = ObstacleBridgeLinuxConnectionAdmission(configuration: configuration)
        self.defaultAdmission = admission
        self.publishedAdmission = admission
        self.compressionTelemetry = .init(policy: configuration.compressionPolicy)
    }

    func makeConnectionAdmission() -> ObstacleBridgeLinuxConnectionAdmission {
        ObstacleBridgeLinuxConnectionAdmission(configuration: configuration)
    }

    public func connect(sessionID: UInt64, clientNonce: Data) throws -> ObstacleBridgeLinuxConfiguredSession {
        try connect(sessionID: sessionID, clientNonce: clientNonce, admission: defaultAdmission) { [configuration] host in
            let lower = try ObstacleBridgeLinuxOverlayTransportClient(
                host: host, port: configuration.port, transport: configuration.transport,
                wsPath: configuration.webSocketPath, wsPayloadMode: configuration.webSocketPayloadMode,
                wsTLS: configuration.webSocketTLS, wsTrustRootsPath: configuration.webSocketTrustRootsPath,
                wsProxy: configuration.webSocketProxy, quicALPN: configuration.quicALPN,
                quicInsecure: configuration.quicInsecure, quicTrustRootsPath: configuration.quicTrustRootsPath,
                receiveTimeoutMilliseconds: configuration.receiveIdleTimeoutMilliseconds
            )
            return (lower, try lower.openSession())
        }
    }

    /// The lifecycle owner supplies the native lower-session construction for
    /// a Core-assigned epoch. This runtime retains candidate admission and
    /// SecureLink state, while it no longer chooses the transport mechanism.
    func connect(
        sessionID: UInt64,
        clientNonce: Data,
        admission: ObstacleBridgeLinuxConnectionAdmission,
        openLowerSession: (String) throws -> (ObstacleBridgeLinuxOverlayTransportClient, ObstacleBridgeLinuxOverlayTransportSession)
    ) throws -> ObstacleBridgeLinuxConfiguredSession {
        publishedAdmission = admission
        admission.beginInFlightConnection()
        admission.activeSession?.close()
        admission.activeSession = nil
        var lastError: Error?
        for offset in configuration.peerCandidates.indices {
            let index = (admission.candidateStartIndex + offset) % configuration.peerCandidates.count
            let host = configuration.peerCandidates[index]
            let startedAt = ProcessInfo.processInfo.systemUptime
            onDiagnostic?("overlay.connect.attempt", [
                "transport": configuration.transport.rawValue,
                "candidate_index": String(index), "candidate": host,
                "port": String(configuration.port),
            ])
            do {
                let (lower, lowerSession) = try openLowerSession(host)
                let session: ObstacleBridgeLinuxConfiguredSession
                if let psk = configuration.secureLinkPSK {
                    let adapter = ObstacleBridgeOverlayLayerTransportAdapter(clientPSK: String(decoding: psk, as: UTF8.self))
                    session = ObstacleBridgeLinuxConfiguredSession(lower: lower, lowerSession: lowerSession, overlayAdapter: adapter, transport: configuration.transport)
                    guard admission.installInFlightConnection(session) else { throw ObstacleBridgeLinuxOverlayTransportError.cancelled }
                    try session.completeClientHandshake(sessionID: sessionID, clientNonce: clientNonce)
                    admission.secureLinkState = "authenticated"
                    admission.clearInFlightConnection(session)
                } else {
                    session = ObstacleBridgeLinuxConfiguredSession(lower: lower, lowerSession: lowerSession, secureLink: nil, transport: configuration.transport)
                    guard admission.installInFlightConnection(session) else { throw ObstacleBridgeLinuxOverlayTransportError.cancelled }
                    admission.secureLinkState = "off"
                    admission.clearInFlightConnection(session)
                }
                admission.snapshot = .init(transport: configuration.transport.rawValue, state: "connected", attempts: index + 1, failureReason: nil)
                admission.connectionEpoch &+= 1
                admission.activeHost = host
                admission.candidateStartIndex = index
                admission.activeSession = session
                onDiagnostic?("overlay.connect.authenticated", [
                    "transport": configuration.transport.rawValue,
                    "candidate_index": String(index), "candidate": host,
                    "elapsed_ms": String(Int((ProcessInfo.processInfo.systemUptime - startedAt) * 1_000)),
                ])
                return session
            } catch {
                if admission.isInFlightConnectionCancelled {
                    admission.clearInFlightConnection()
                    throw ObstacleBridgeLinuxOverlayTransportError.cancelled
                }
                lastError = error
                admission.activeHost = nil
                admission.secureLinkState = configuration.secureLinkPSK == nil ? "off" : "failed"
                admission.snapshot = .init(transport: configuration.transport.rawValue, state: "failed", attempts: index + 1, failureReason: error.localizedDescription)
                onDiagnostic?("overlay.connect.failed", [
                    "transport": configuration.transport.rawValue,
                    "candidate_index": String(index), "candidate": host,
                    "elapsed_ms": String(Int((ProcessInfo.processInfo.systemUptime - startedAt) * 1_000)),
                    "reason": error.localizedDescription,
                ])
            }
        }
        throw lastError ?? ObstacleBridgeLinuxOverlayTransportError.invalidFrame
    }

    /// Interrupts an in-progress lower transport or SecureLink handshake
    /// without waiting for the live-runtime queue.  The next explicit
    /// connection attempt resets this cancellation state.
    public func cancelInFlightConnection() {
        publishedAdmission.cancelInFlightConnection()
    }

    /// Ends the current transport epoch and establishes a fresh one. A caller
    /// supplies fresh SecureLink identifiers so protected counters can never be
    /// reused across a reconnect.
    public func reconnect(sessionID: UInt64, clientNonce: Data) throws -> ObstacleBridgeLinuxConfiguredSession {
        disconnect()
        return try connect(sessionID: sessionID, clientNonce: clientNonce)
    }

    /// Promotes an already-authenticated listener-side epoch. The caller owns
    /// admission/handshake; subsequent ChannelMux, receive-worker, and close
    /// behavior shares the ordinary configured-session contract.
    func adoptInbound(_ session: ObstacleBridgeLinuxConfiguredSession, host: String = "listener") {
        let admission = publishedAdmission
        admission.activeSession?.close()
        admission.activeSession = session
        admission.connectionEpoch &+= 1
        admission.activeHost = host
        admission.secureLinkState = configuration.secureLinkPSK == nil ? "off" : "authenticated"
        admission.snapshot = .init(transport: configuration.transport.rawValue, state: "connected", attempts: 1, failureReason: nil)
    }

    /// Advances the configured peer order after a connected epoch proves
    /// unusable (for example, a myudp receive timeout).
    public func advanceCandidate() {
        guard !configuration.peerCandidates.isEmpty else { return }
        publishedAdmission.candidateStartIndex = (publishedAdmission.candidateStartIndex + 1) % configuration.peerCandidates.count
    }

    public func disconnect() {
        let admission = publishedAdmission
        admission.activeSession?.close()
        admission.activeSession = nil
        admission.activeHost = nil
        admission.secureLinkState = configuration.secureLinkPSK == nil ? "off" : "disconnected"
        if admission.snapshot.state != "failed" {
            admission.snapshot = .init(transport: configuration.transport.rawValue, state: "disconnected", attempts: admission.snapshot.attempts, failureReason: nil)
        }
    }

    /// Redacted state suitable for an Admin/API adapter. It deliberately
    /// identifies only the configured secure-link mode, never its secret.
    public func status() -> ObstacleBridgeLinuxRuntimeStatus {
        let admission = publishedAdmission
        let coreState = admission.activeSession?.secureLinkProtocolState
        let appReady = ObstacleBridgeOverlayLayerTransportAdapter.applicationReady(
            transportConnected: admission.snapshot.state == "connected",
            secureLinkRequired: configuration.secureLinkPSK != nil,
            secureLinkAuthenticated: admission.secureLinkState == "authenticated",
            compressionHealthy: true
        )
        return .init(
            transport: configuration.transport.rawValue,
            state: admission.snapshot.state,
            attempts: admission.snapshot.attempts,
            failureReason: admission.snapshot.failureReason,
            configuredCandidates: configuration.peerCandidates,
            activeHost: admission.activeHost,
            port: configuration.port,
            secureLinkMode: configuration.secureLinkPSK == nil ? "off" : "psk",
            secureLinkState: admission.secureLinkState,
            appReady: appReady,
            activeTCPChannels: 0,
            activeUDPChannels: 0,
            queuedServiceFrames: 0,
            droppedServiceFrames: 0,
            malformedServiceFrames: 0,
            serviceFailures: 0,
            openedTCPChannels: 0,
            openedUDPChannels: 0,
            receiveLoopState: "stopped",
            receiveEpoch: admission.connectionEpoch,
            receivedFrames: 0,
            droppedReceiveFrames: 0,
            receiveQueueDepth: 0,
            receiveFailureReason: nil,
            peer: .init(
                transport: configuration.transport.rawValue,
                lifecycleState: admission.snapshot.state,
                secureLinkState: admission.secureLinkState,
                connectionEpoch: admission.connectionEpoch,
                sessionID: coreState.map { $0.sessionID == 0 ? nil : $0.sessionID } ?? nil,
                pendingRekeySessionID: coreState.map { $0.pendingRekeySessionID == 0 ? nil : $0.pendingRekeySessionID } ?? nil,
                ready: appReady,
                authenticated: coreState?.authenticated ?? false,
                applicationSendingBlocked: coreState?.applicationSendingBlocked ?? false,
                attempts: admission.snapshot.attempts,
                nextRetryMilliseconds: nil,
                protectedTxCounter: coreState?.txCounter ?? 0,
                protectedRxCounter: coreState?.rxCounter ?? 0,
                protectedFramesSentTotal: coreState?.protectedFramesSentTotal ?? 0,
                protectedFramesReceivedTotal: coreState?.protectedFramesReceivedTotal ?? 0,
                authenticatedGenerationsTotal: coreState?.authenticatedGenerationsTotal ?? 0,
                rekeysCompletedTotal: coreState?.rekeysCompletedTotal ?? 0,
                compression: compressionTelemetry.snapshot()
            )
        )
    }

    /// Sends one payload with bounded fresh-epoch retries. This is a small
    /// synchronous admission primitive, not the timer-driven reconnect policy
    /// that a future long-lived ChannelMux runtime will own.
    public func roundTrip(_ payload: Data, sessionID: UInt64, clientNonce: Data, retryCount: Int = 1) throws -> Data {
        let totalAttempts = max(1, retryCount + 1)
        var lastError: Error?
        for attempt in 0..<totalAttempts {
            let retrySessionID = sessionID &+ UInt64(attempt)
            let effectiveSessionID = retrySessionID == 0 ? 1 : retrySessionID
            var retryNonce = clientNonce
            if attempt > 0, !retryNonce.isEmpty {
                retryNonce[retryNonce.count - 1] ^= UInt8(truncatingIfNeeded: attempt)
            }
            do {
                let session = try connect(sessionID: effectiveSessionID, clientNonce: retryNonce)
                let reply = try session.send(payload)
                disconnect()
                defaultAdmission.snapshot = .init(transport: configuration.transport.rawValue, state: "disconnected", attempts: attempt + 1, failureReason: nil)
                return reply
            } catch {
                lastError = error
                disconnect()
            }
        }
        defaultAdmission.snapshot = .init(transport: configuration.transport.rawValue, state: "failed", attempts: totalAttempts, failureReason: lastError?.localizedDescription)
        throw lastError ?? ObstacleBridgeLinuxOverlayTransportError.invalidFrame
    }

    deinit { disconnect() }
}
