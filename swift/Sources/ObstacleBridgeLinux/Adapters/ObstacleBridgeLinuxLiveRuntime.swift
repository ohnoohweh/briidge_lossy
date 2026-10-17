import Dispatch
import Foundation
import ObstacleBridgeCore

public struct ObstacleBridgeLinuxLiveRuntimeSnapshot: Equatable, Sendable {
    public let state: String
    public let attempts: Int
    public let failureReason: String?
    public let nextRetryMilliseconds: Int?
    public let runtimeHealthRecordCount: Int
    public let previousRuntimeLifetimeEndedCleanly: Bool?
}

public enum ObstacleBridgeLinuxLiveRuntimeError: Error, Equatable, LocalizedError {
    case notRunning

    public var errorDescription: String? {
        switch self {
        case .notRunning: return "Linux overlay runtime is not application ready"
        }
    }
}

/// Owns one configured lower transport epoch. Core assigns the epoch through
/// an `openTransport` effect; this owner ensures that a late completion or a
/// stale cancellation cannot replace or tear down a newer epoch.
private class ObstacleBridgeLinuxTransportLifecycleOwner: @unchecked Sendable {
    private let runtime: ObstacleBridgeLinuxConfiguredRuntime
    private let expectedTransport: ObstacleBridgeLinuxTransport
    /// Candidate rotation, in-flight cancellation, authenticated-session
    /// publication, and connection epoch are per concrete owner. The
    /// configured runtime only reads this admission for its redacted status.
    private let admission: ObstacleBridgeLinuxConnectionAdmission
    private let lock = NSLock()
    private var activeEpoch: UInt64?
    private var retryTimer: DispatchSourceTimer?
    private var receiveWorker: ObstacleBridgeLinuxReceiveWorker?

    init(runtime: ObstacleBridgeLinuxConfiguredRuntime, expectedTransport: ObstacleBridgeLinuxTransport) {
        self.runtime = runtime
        self.expectedTransport = expectedTransport
        self.admission = runtime.makeConnectionAdmission()
    }

    func open(epoch: UInt64, sessionID: UInt64, clientNonce: Data) throws -> ObstacleBridgeLinuxConfiguredSession {
        guard runtime.configuration.transport == expectedTransport else {
            throw ObstacleBridgeLinuxOverlayTransportError.invalidEndpoint
        }
        lock.lock()
        guard activeEpoch == nil || activeEpoch! < epoch else {
            lock.unlock()
            throw ObstacleBridgeLinuxOverlayTransportError.cancelled
        }
        activeEpoch = epoch
        lock.unlock()
        do {
            let session = try runtime.connect(sessionID: sessionID, clientNonce: clientNonce, admission: admission) { [expectedTransport, runtime] host in
                let configuration = runtime.configuration
                let lower = try ObstacleBridgeLinuxOverlayTransportClient(
                    host: host, port: configuration.port, transport: expectedTransport,
                    wsPath: configuration.webSocketPath, wsPayloadMode: configuration.webSocketPayloadMode,
                    wsTLS: configuration.webSocketTLS, wsTrustRootsPath: configuration.webSocketTrustRootsPath,
                    wsProxy: configuration.webSocketProxy, quicALPN: configuration.quicALPN,
                    quicInsecure: configuration.quicInsecure, quicTrustRootsPath: configuration.quicTrustRootsPath,
                    receiveTimeoutMilliseconds: configuration.receiveIdleTimeoutMilliseconds
                )
                return (lower, try lower.openSession())
            }
            lock.lock()
            let admitted = activeEpoch == epoch
            lock.unlock()
            guard admitted else {
                session.close()
                throw ObstacleBridgeLinuxOverlayTransportError.cancelled
            }
            return session
        } catch {
            lock.lock()
            if activeEpoch == epoch { activeEpoch = nil }
            lock.unlock()
            throw error
        }
    }

    func cancel(epoch: UInt64) {
        lock.lock()
        // A connect failure clears `activeEpoch` before Core emits its
        // matching cancellation effect. Accept that cleanup, but never let a
        // retired epoch close a newer in-flight connection.
        guard activeEpoch == nil || activeEpoch == epoch else { lock.unlock(); return }
        activeEpoch = nil
        lock.unlock()
        runtime.disconnect()
    }

    func cancelInFlightConnection() {
        runtime.cancelInFlightConnection()
    }

    /// Core lifecycle effects are dispatched to the selected resource owner,
    /// not retained by the shared coordinator adapter.  Each concrete owner
    /// therefore fences its own reader and retry callback with its epoch.
    func replaceReceiveWorker(with worker: ObstacleBridgeLinuxReceiveWorker?) {
        lock.lock()
        let previous = receiveWorker
        receiveWorker = worker
        lock.unlock()
        previous?.stop()
    }

    func receiveSnapshot() -> ObstacleBridgeLinuxReceiveWorkerSnapshot? {
        lock.lock()
        let worker = receiveWorker
        lock.unlock()
        return worker?.snapshot()
    }

    func scheduleRetry(on queue: DispatchQueue, token: UInt64, afterMilliseconds delay: Int, fired: @escaping () -> Void) {
        cancelRetry()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        lock.lock()
        retryTimer = timer
        lock.unlock()
        timer.schedule(deadline: .now() + .milliseconds(delay))
        timer.setEventHandler { [weak self] in
            self?.cancelRetry()
            fired()
        }
        timer.resume()
    }

    func cancelRetry() {
        lock.lock()
        let timer = retryTimer
        retryTimer = nil
        lock.unlock()
        timer?.setEventHandler {}
        timer?.cancel()
    }
}

private final class ObstacleBridgeLinuxTCPLifecycleOwner: ObstacleBridgeLinuxTransportLifecycleOwner, @unchecked Sendable {
    init(runtime: ObstacleBridgeLinuxConfiguredRuntime) { super.init(runtime: runtime, expectedTransport: .tcp) }
}

private final class ObstacleBridgeLinuxQUICLifecycleOwner: ObstacleBridgeLinuxTransportLifecycleOwner, @unchecked Sendable {
    init(runtime: ObstacleBridgeLinuxConfiguredRuntime) { super.init(runtime: runtime, expectedTransport: .quic) }
}

private final class ObstacleBridgeLinuxWebSocketLifecycleOwner: ObstacleBridgeLinuxTransportLifecycleOwner, @unchecked Sendable {
    init(runtime: ObstacleBridgeLinuxConfiguredRuntime) { super.init(runtime: runtime, expectedTransport: .ws) }
}

/// Foreground owner for one admitted overlay epoch. All session, retry, and
/// shutdown work is serialized here so lower transport callbacks cannot revive
/// a stopped runtime or retain a stale SecureLink epoch.
public enum ObstacleBridgeLinuxShutdownSignal: String, Sendable {
    case interrupt = "SIGINT"
    case terminate = "SIGTERM"
}

public final class ObstacleBridgeLinuxLiveRuntime: @unchecked Sendable {
    public var onSnapshot: ((ObstacleBridgeLinuxLiveRuntimeSnapshot) -> Void)?
    public var onDiagnostic: ((String, [String: String]) -> Void)?

    public let configuredRuntime: ObstacleBridgeLinuxConfiguredRuntime
    private let transportLifecycleOwner: ObstacleBridgeLinuxTransportLifecycleOwner
    private let coordinator: ObstacleBridgeOverlayCoordinator
    private let queue = DispatchQueue(label: "org.obstaclebridge.linux.live-runtime")
    private let statusLock = NSLock()
    private var statusProjection: ObstacleBridgeLinuxRuntimeStatus
    private var session: ObstacleBridgeLinuxConfiguredSession?
    private var channelMux: ObstacleBridgeLinuxChannelMuxSession?
    private var tunDevice: (any ObstacleBridgeLinuxPacketDevice)?
    private var tunHelperPacketDevice: ObstacleBridgeLinuxTunHelperPacketDevice?
    private var managedTunHelper: ObstacleBridgeLinuxManagedTunHelper?
    private var tunChannelAdapter: ObstacleBridgeLinuxOverlayChannelAdapter?
    private var tunNetworkApplied = false
    private var serviceOwners: [ObstacleBridgeLinuxServiceSocketOwner] = []
    private var remoteServiceOwners: [ObstacleBridgeLinuxServiceSocketOwner] = []
    private var channelOwners: [String: ObstacleBridgeLinuxServiceSocketOwner] = [:]
    private var proxyProvider: ObstacleBridgeLinuxProxyProvider?
    private let remoteCatalogStore = ObstacleBridgeLinuxServiceCatalogStore()
    private let catalogInstanceID: UInt64
    private var stopped = true
    private let runtimeHealthURL: URL?
    private let runtimeHealthLock = NSLock()
    private var runtimeHealthRing = ObstacleBridgeRuntimeHealthRing()
    private var runtimeHealthSequence: UInt64 = 0
    private var previousRuntimeLifetimeEndedCleanly: Bool?
    private var runtimeHealthTimer: DispatchSourceTimer?
    private var livenessProbeTimer: DispatchSourceTimer?
    private var activeCoordinatorEpoch: UInt64?
    /// Listener-owned child sessions are retired by their shared listener;
    /// they must never turn a peer close into an outbound reconnect attempt.
    private var inboundOnly = false
    private var liveSnapshotProjection = ObstacleBridgeLinuxLiveRuntimeSnapshot(state: "stopped", attempts: 0, failureReason: nil, nextRetryMilliseconds: nil, runtimeHealthRecordCount: 0, previousRuntimeLifetimeEndedCleanly: nil)
    private(set) public var snapshot = ObstacleBridgeLinuxLiveRuntimeSnapshot(state: "stopped", attempts: 0, failureReason: nil, nextRetryMilliseconds: nil, runtimeHealthRecordCount: 0, previousRuntimeLifetimeEndedCleanly: nil)

    public init(configuration: ObstacleBridgeLinuxRuntimeConfiguration, policy: ObstacleBridgeLinuxReconnectPolicy = .init(), runtimeHealthURL: URL? = nil) {
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: configuration)
        self.configuredRuntime = runtime
        switch configuration.transport {
        case .tcp:
            self.transportLifecycleOwner = ObstacleBridgeLinuxTCPLifecycleOwner(runtime: runtime)
        case .quic:
            self.transportLifecycleOwner = ObstacleBridgeLinuxQUICLifecycleOwner(runtime: runtime)
        case .ws:
            self.transportLifecycleOwner = ObstacleBridgeLinuxWebSocketLifecycleOwner(runtime: runtime)
        case .myudp:
            self.transportLifecycleOwner = ObstacleBridgeLinuxTransportLifecycleOwner(runtime: runtime, expectedTransport: .myudp)
        }
        self.statusProjection = runtime.status()
        self.coordinator = .init(candidateCount: configuration.peerCandidates.count, policy: policy)
        self.runtimeHealthURL = runtimeHealthURL
        var generator = SystemRandomNumberGenerator()
        self.catalogInstanceID = UInt64.random(in: 1...UInt64.max, using: &generator)
        runtime.onDiagnostic = { [weak self] event, fields in
            self?.emitDiagnostic(event, fields: fields)
        }
    }

    /// A redacted snapshot that Admin workers may read without touching the
    /// serialized transport owner.
    public func status() -> ObstacleBridgeLinuxRuntimeStatus {
        statusLock.lock()
        let receive = transportLifecycleOwner.receiveSnapshot()
        let summaries = (serviceOwners + remoteServiceOwners).map { $0.snapshot() }
        let activeTCPChannels = summaries.reduce(0) { $0 + $1.activeTCPChannels }
        let activeUDPChannels = summaries.reduce(0) { $0 + $1.activeUDPChannels }
        let queuedServiceFrames = summaries.reduce(0) { $0 + $1.queuedFrames }
        let droppedServiceFrames = summaries.reduce(0) { $0 + $1.droppedFrames }
        let malformedServiceFrames = summaries.reduce(0) { $0 + $1.malformedFrames }
        let serviceFailures = summaries.reduce(0) { $0 + $1.serviceFailures }
        let openedTCPChannels = summaries.reduce(0) { $0 + $1.openedTCPChannels }
        let openedUDPChannels = summaries.reduce(0) { $0 + $1.openedUDPChannels }
        let base = statusProjection
        let live = liveSnapshotProjection
        statusLock.unlock()
        return .init(
            // The configured transport is deliberately reset during failed
            // epoch cleanup.  The coordinator remains the authority for the
            // live lifecycle, retry count, and actionable failure reason;
            // publishing the reset projection here hid a terminal connect
            // failure from the Admin Web UI.
            transport: base.transport, state: live.state, attempts: live.attempts,
            failureReason: live.failureReason, configuredCandidates: base.configuredCandidates,
            activeHost: base.activeHost, port: base.port, secureLinkMode: base.secureLinkMode,
            secureLinkState: base.secureLinkState, appReady: base.appReady,
            activeTCPChannels: activeTCPChannels, activeUDPChannels: activeUDPChannels,
            queuedServiceFrames: queuedServiceFrames, droppedServiceFrames: droppedServiceFrames,
            malformedServiceFrames: malformedServiceFrames, serviceFailures: serviceFailures,
            openedTCPChannels: openedTCPChannels, openedUDPChannels: openedUDPChannels,
            receiveLoopState: receive?.state ?? "stopped",
            receiveEpoch: receive?.epoch ?? base.receiveEpoch,
            receivedFrames: receive?.receivedFrames ?? 0,
            droppedReceiveFrames: receive?.droppedFrames ?? 0,
            receiveQueueDepth: receive?.queueDepth ?? 0,
            receiveFailureReason: receive?.failureReason,
            peer: .init(
                transport: base.peer.transport,
                lifecycleState: live.state,
                secureLinkState: base.peer.secureLinkState,
                connectionEpoch: base.peer.connectionEpoch,
                sessionID: base.peer.sessionID,
                pendingRekeySessionID: base.peer.pendingRekeySessionID,
                ready: live.state == "connected" && base.peer.ready,
                authenticated: base.peer.authenticated,
                applicationSendingBlocked: base.peer.applicationSendingBlocked,
                attempts: live.attempts,
                nextRetryMilliseconds: live.nextRetryMilliseconds,
                protectedTxCounter: base.peer.protectedTxCounter,
                protectedRxCounter: base.peer.protectedRxCounter,
                protectedFramesSentTotal: base.peer.protectedFramesSentTotal,
                protectedFramesReceivedTotal: base.peer.protectedFramesReceivedTotal,
                authenticatedGenerationsTotal: base.peer.authenticatedGenerationsTotal,
                rekeysCompletedTotal: base.peer.rekeysCompletedTotal,
                // Compression telemetry changes on the live ChannelMux data
                // path, so do not reuse the connection-start status cache.
                // Core remains the single counter owner.
                compression: configuredRuntime.compressionTelemetry.snapshot()
            )
        )
    }

    public func start() {
        queue.async { [weak self] in
            guard let self else { return }
            self.beginRuntimeHealthLifetime()
            self.stopped = false
            do {
                let provider = ObstacleBridgeLinuxProxyProvider(configuration: self.configuredRuntime.configuration.proxyProvider)
                try provider.start()
                self.proxyProvider = provider
            } catch {
                self.stopped = true
                self.publish(state: "failed", attempts: 0, nextRetryMilliseconds: nil, failureReason: "proxy provider: \(error.localizedDescription)")
                return
            }
            self.apply(self.coordinator.handle(.start))
            self.startRuntimeHealthHeartbeat()
            self.startLivenessProbes()
        }
    }

    /// Listener-side entry point. The TCP/WS/myudp acceptor authenticates the
    /// peer first, then hands the resulting configured session to the same
    /// ChannelMux, receive-worker, service-owner, and Admin lifecycle used by
    /// an outgoing epoch.
    public func adoptInboundSession(_ connectedSession: ObstacleBridgeLinuxConfiguredSession, host: String = "listener") {
        queue.async { [weak self] in
            guard let self else { return }
            self.apply(self.coordinator.handle(.stop))
            self.inboundOnly = true
            self.configuredRuntime.disconnect()
            self.stopped = false
            self.configuredRuntime.adoptInbound(connectedSession, host: host)
            do {
                self.session = connectedSession
                let mux = try ObstacleBridgeLinuxChannelMuxSession(runtime: self.configuredRuntime, session: connectedSession)
                mux.onUnsolicitedFrame = { [weak self] frame in self?.queue.async { [weak self] in self?.routeInboundFrame(frame) } }
                mux.activateReceiveOwner(); connectedSession.activateReceiveOwner()
                self.channelMux = mux
                try self.publishRemoteCatalog(); try self.startOwnServiceOwners()
                self.refreshStatusProjection()
                self.apply(self.coordinator.handle(.adoptAuthenticated))
                guard let epoch = self.coordinator.snapshot.epoch else { return }
                self.activeCoordinatorEpoch = epoch
            } catch {
                connectedSession.close(); self.session = nil; self.channelMux = nil
                self.replaceReceiveWorker(with: nil); self.stopServiceOwners(); self.stopRemoteServiceOwners()
                self.refreshStatusProjection(); self.publish(state: "failed", attempts: 1, nextRetryMilliseconds: nil, failureReason: error.localizedDescription)
            }
        }
    }

    public func stop() {
        // A SecureLink handshake performs synchronous lower-transport I/O on
        // `queue`.  Cancel its published session before entering that queue so
        // shutdown cannot wait for the receive timeout.
        transportLifecycleOwner.cancelInFlightConnection()
        queue.sync {
            stopped = true
            apply(coordinator.handle(.stop))
            stopRuntimeHealthHeartbeat()
            proxyProvider?.stop(); proxyProvider = nil
            appendRuntimeHealth(event: "runtime_stopped", controlledStop: true)
        }
    }

    /// Records the externally observed shutdown cause without accepting
    /// arbitrary process data into the persisted Admin health projection.
    public func recordShutdownSignal(_ signal: ObstacleBridgeLinuxShutdownSignal) {
        queue.sync {
            guard !stopped else { return }
            appendRuntimeHealth(event: "shutdown_signal:\(signal.rawValue)")
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
                if inboundOnly {
                    apply(coordinator.handle(.stop))
                } else if let epoch = activeCoordinatorEpoch {
                    apply(coordinator.handle(.transportFailed(epoch: epoch, reason: error.localizedDescription)))
                }
                throw error
            }
        }
    }

    /// Forces a fresh authenticated epoch without allowing callbacks from the
    /// previous session to become current again.
    public func reconnect() {
        queue.async { [weak self] in
            guard let self, !self.stopped else { return }
            if self.inboundOnly {
                self.apply(self.coordinator.handle(.stop))
            } else if let epoch = self.activeCoordinatorEpoch {
                self.apply(self.coordinator.handle(.transportFailed(epoch: epoch, reason: "manual reconnect")))
            } else {
                self.apply(self.coordinator.handle(.start))
            }
        }
    }

    /// Bound ports for configured local services. This supports operational
    /// discovery when a service deliberately requests port zero in tests or a
    /// managed deployment; it contains no peer, payload, or secret material.
    public func localServicePorts() -> [UInt16: Int] {
        queue.sync { Dictionary(uniqueKeysWithValues: serviceOwners.map { ($0.specification.serviceID, $0.port) }) }
    }

    /// Small redacted lifecycle classification for the local Admin surface.
    public func runtimeHealthMetadataForAdmin() -> (count: Int, previousClean: Bool?) {
        runtimeHealthMetadata()
    }

    /// The local Admin server serializes this redacted bounded tail. It exists
    /// so evidence of an unclean preceding lifetime survives a restart.
    public func runtimeHealthRecentRecordsForAdmin() -> [ObstacleBridgeRuntimeHealthRecord] {
        runtimeHealthLock.lock()
        defer { runtimeHealthLock.unlock() }
        return Array(runtimeHealthRing.records.suffix(16))
    }

    /// Redacted correlation of foreground-owned resource state with lifecycle
    /// health. Resource locators and helper authentication material stay in
    /// their owners and never reach Admin.
    public func resourceHealthForAdmin() -> [String: Any] {
        // Admin workers must never synchronously enter the serialized
        // transport queue: a lower-layer connection attempt can be blocked on
        // network I/O. Derive a redacted, non-blocking projection from the
        // immutable configuration and already-published status instead.
        let configured = configuredRuntime.configuration
        let current = status()
        return [
            "packet_tunnel": [
                "configured": configured.packetTunnelEnabled,
                "helper_configured": configured.tunHelperSocketPath != nil,
                "managed_helper": configured.launchSwiftTunHelper,
                "managed_helper_running": current.appReady && configured.launchSwiftTunHelper,
                "device_open": current.appReady && configured.packetTunnelEnabled,
                "network_policy_applied": current.appReady && configured.packetTunnelEnabled,
            ],
            "service_sockets": [
                "configured_local": configured.ownServices.count,
                "active_local": current.appReady ? configured.ownServices.count : 0,
                "active_remote": current.appReady ? current.activeTCPChannels + current.activeUDPChannels : 0,
            ],
            "proxy_provider": [
                "configured": configured.proxyProvider.enabled,
                "http_port": configured.proxyProvider.httpEnabled ? configured.proxyProvider.httpPort : 0,
                "socks5_port": configured.proxyProvider.socks5Enabled ? configured.proxyProvider.socks5Port : 0,
                "starts_before_overlay": configured.proxyProvider.enabled,
            ],
        ]
    }

    /// Delivers one authenticated ChannelMux frame from the overlay reader.
    /// The current lower transport supplies replies synchronously; this API is
    /// also the receive-side handoff used by a future duplex reader.
    public func receiveChannelMuxFrame(_ frame: ObstacleBridgeChannelMuxFrame) {
        queue.async { [weak self] in self?.routeInboundFrame(frame) }
    }

    public func remoteServicePorts() -> [UInt16: Int] {
        queue.sync { Dictionary(uniqueKeysWithValues: remoteServiceOwners.map { ($0.specification.serviceID, $0.port) }) }
    }

    private func openTransport(epoch: UInt64) {
        guard !stopped, coordinator.snapshot.epoch == epoch else { return }
        var phase = "transport"
        do {
            let sessionID = freshSessionID()
            let nonce = freshNonce()
            let connectedSession = try transportLifecycleOwner.open(epoch: epoch, sessionID: sessionID, clientNonce: nonce)
            session = connectedSession
            let mux = try ObstacleBridgeLinuxChannelMuxSession(runtime: configuredRuntime, session: connectedSession)
            mux.onUnsolicitedFrame = { [weak self] frame in
                self?.queue.async { [weak self] in self?.routeInboundFrame(frame) }
            }
            mux.activateReceiveOwner()
            connectedSession.activateReceiveOwner()
            channelMux = mux
            // Refresh the adapter projection before Core publishes ready so
            // an Admin reader cannot observe a connected lifecycle paired
            // with the preceding transport epoch.
            refreshStatusProjection()
            // The peer may send a post-authentication datagram immediately.
            // Admit the Core-owned receive effect before optional service
            // publication so the Linux socket never drops that notification.
            activeCoordinatorEpoch = epoch
            connectedSession.onTransportLivenessSample = { [weak self] delayMilliseconds in
                self?.queue.async { [weak self] in
                    guard let self, self.activeCoordinatorEpoch == epoch else { return }
                    self.apply(self.coordinator.handle(.transportLivenessSample(
                        epoch: epoch,
                        delayMilliseconds: delayMilliseconds,
                        nowMilliseconds: UInt64(ProcessInfo.processInfo.systemUptime * 1_000)
                    )))
                }
            }
            apply(coordinator.handle(.transportConnected(epoch: epoch)))
            apply(coordinator.handle(.authenticated(epoch: epoch)))
            phase = "remote_catalog"
            try publishRemoteCatalog()
            phase = "service_owners"
            try startOwnServiceOwners()
            phase = "packet_tunnel"
            try startPacketDeviceIfNeeded()
            emitDiagnostic("overlay.post_auth.ready", fields: ["epoch": String(epoch)])
        } catch ObstacleBridgeLinuxOverlayTransportError.cancelled {
            // `stop()` has already interrupted the in-flight lower session.
            // Do not publish a retry that could briefly outlive shutdown.
            return
        } catch {
            emitDiagnostic("overlay.post_auth.failed", fields: [
                "epoch": String(epoch), "phase": phase, "reason": error.localizedDescription,
            ])
            apply(coordinator.handle(.transportFailed(epoch: epoch, reason: error.localizedDescription)))
        }
    }

    private func scheduleRetry(token: UInt64, afterMilliseconds delay: Int) {
        emitDiagnostic("overlay.retry.scheduled", fields: ["delay_ms": String(delay)])
        transportLifecycleOwner.scheduleRetry(on: queue, token: token, afterMilliseconds: delay) { [weak self] in
            guard let self else { return }
            self.apply(self.coordinator.handle(.retryTimerFired(token: token)))
        }
    }

    private func cancelRetry() {
        transportLifecycleOwner.cancelRetry()
    }

    /// Executes only platform mechanics requested by Core.  The coordinator
    /// owns epoch admission, candidate selection, retry bounds, and stale
    /// callback rejection; this adapter owns Dispatch and socket teardown.
    private func apply(_ transition: ObstacleBridgeOverlayCoordinatorTransition) {
        // An outbound open can block while the lower transport performs its
        // SecureLink handshake. Publish Core's transition first so Admin sees
        // `connecting` and its attempt count instead of the stale `stopped`
        // snapshot for the whole handshake window.
        publishCoordinatorSnapshot()
        for effect in transition.effects {
            switch effect {
            case .openTransport(let epoch, _, _):
                openTransport(epoch: epoch)
            case .cancelTransport(let epoch):
                guard activeCoordinatorEpoch == nil || activeCoordinatorEpoch == epoch else { continue }
                session?.close()
                session = nil
                channelMux = nil
                stopPacketDevice()
                activeCoordinatorEpoch = nil
                replaceReceiveWorker(with: nil)
                stopServiceOwners()
                stopRemoteServiceOwners()
                _ = remoteCatalogStore.withdraw()
                transportLifecycleOwner.cancel(epoch: epoch)
                configuredRuntime.advanceCandidate()
                refreshStatusProjection()
            case .startReceive(let epoch):
                guard coordinator.snapshot.epoch == epoch, let session, let channelMux else { continue }
                startReceiveWorker(session: session, mux: channelMux, coordinatorEpoch: epoch)
            case .cancelReceive:
                replaceReceiveWorker(with: nil)
            case .scheduleRetry(let token, let delay):
                scheduleRetry(token: token, afterMilliseconds: delay)
            case .cancelRetry:
                cancelRetry()
            }
        }
        publishCoordinatorSnapshot()
    }

    private func publishCoordinatorSnapshot() {
        let core = coordinator.snapshot
        publish(
            state: core.state.rawValue,
            attempts: core.attempts,
            nextRetryMilliseconds: core.nextRetryMilliseconds,
            failureReason: core.failureReason
        )
    }

    private func publish(state: String, attempts: Int, nextRetryMilliseconds: Int?, failureReason: String?) {
        appendRuntimeHealth(event: "lifecycle")
        let health = runtimeHealthMetadata()
        let value = ObstacleBridgeLinuxLiveRuntimeSnapshot(state: state, attempts: attempts, failureReason: failureReason, nextRetryMilliseconds: nextRetryMilliseconds, runtimeHealthRecordCount: health.count, previousRuntimeLifetimeEndedCleanly: health.previousClean)
        statusLock.lock()
        liveSnapshotProjection = value
        statusLock.unlock()
        snapshot = value
        onSnapshot?(value)
    }

    private func refreshStatusProjection() {
        let value = configuredRuntime.status()
        statusLock.lock()
        statusProjection = value
        statusLock.unlock()
    }

    /// Fans a diagnostic out to both the public Admin/log observer and the
    /// durable runtime-health journal.  The journal must not depend on the
    /// public callback: the foreground runner installs that callback for the
    /// Admin log view after this runtime has been constructed.
    private func emitDiagnostic(_ event: String, fields: [String: String]) {
        let detail = fields.map { "\($0.key)=\($0.value)" }.sorted().joined(separator: " ")
        appendRuntimeHealth(event: detail.isEmpty ? event : "\(event) \(detail)")
        onDiagnostic?(event, fields)
    }

    private func startOwnServiceOwners() throws {
        stopServiceOwners()
        let sequence = UInt32(truncatingIfNeeded: configuredRuntime.connectionEpoch)
        for spec in configuredRuntime.configuration.ownServices {
            let owner = ObstacleBridgeLinuxServiceSocketOwner(spec: spec, maximumApplicationPayload: configuredRuntime.configuration.channelMuxMaximumApplicationPayload, instanceID: catalogInstanceID, connectionSequence: sequence) { [weak self] owner, frames in
                guard let runtime = self else { return }
                runtime.queue.async { [weak runtime] in runtime?.sendServiceFrames(frames, from: owner) }
            }
            do {
                try owner.start()
            } catch {
                let protocolName: String = spec.listenProtocol == .tcp ? "tcp" : "udp"
                let fields: [String: String] = [
                    "service_id": String(spec.serviceID),
                    "name": spec.name ?? "unnamed",
                    "host": spec.listenHost,
                    "port": String(spec.listenPort),
                    "protocol": protocolName,
                    "reason": error.localizedDescription,
                ]
                emitDiagnostic("service.listener.failed", fields: fields)
                throw error
            }
            serviceOwners.append(owner)
        }
    }

    private func stopServiceOwners() {
        for owner in serviceOwners { owner.stop() }
        serviceOwners.removeAll()
    }

    private func startPacketDeviceIfNeeded() throws {
        guard tunDevice == nil,
              let plan = configuredRuntime.configuration.packetTunnelPlan,
              configuredRuntime.configuration.packetTunnelEnabled,
              channelMux != nil
        else { return }
        let runtime = self
        if configuredRuntime.configuration.launchSwiftTunHelper, managedTunHelper == nil {
            guard let socketPath = configuredRuntime.configuration.tunHelperSocketPath,
                  let token = configuredRuntime.configuration.tunHelperSessionToken else {
                throw ObstacleBridgeLinuxRuntimeConfigurationError.unavailableTransport("managed Swift TUN helper requires an explicit socket and session token")
            }
            let owner = try ObstacleBridgeLinuxManagedTunHelper(socketPath: socketPath, sessionToken: token, executable: configuredRuntime.configuration.tunHelperExecutable)
            try owner.start()
            managedTunHelper = owner
        }
        guard let helper = try configuredRuntime.configuration.makeTunHelperAdapter() else {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.unavailableTransport("Linux packet-tunnel startup requires an explicit helper owner")
        }
        let device = ObstacleBridgeLinuxTunHelperPacketDevice(
            adapter: helper,
            packetSink: { packet in runtime.queue.async { runtime.tunChannelAdapter?.receivedPacketFromDevice(packet) } },
            eventSink: { detail in runtime.appendRuntimeHealth(event: "tun_helper: \(detail)") }
        )
        let adapter = ObstacleBridgeLinuxOverlayChannelAdapter(
            interfaceName: configuredRuntime.configuration.tunInterfaceName,
            mtu: plan.mtu,
            instanceID: catalogInstanceID,
            connectionSequence: UInt32(truncatingIfNeeded: configuredRuntime.connectionEpoch),
            packetDevice: device,
            localAddress: plan.tunnelAddress,
            localAddress6: plan.tunnelAddress6,
            backpressureSnapshot: { .init(bufferedFrames: 0) },
            startupFrames: { [] },
            sendMuxFrames: { frames in
                runtime.queue.async {
                    for data in frames {
                        guard let frame = try? ObstacleBridgeChannelMuxCodec.decode(data) else { continue }
                        guard let mux = runtime.channelMux else { return }
                        do { try mux.sendUnsolicited(frame) }
                        catch {
                            if let epoch = runtime.activeCoordinatorEpoch {
                                runtime.apply(runtime.coordinator.handle(.transportFailed(epoch: epoch, reason: error.localizedDescription)))
                            }
                            return
                        }
                    }
                }
            },
            diagnosticSink: { event, _ in runtime.appendRuntimeHealth(event: event) }
        )
        tunDevice = device
        tunHelperPacketDevice = device
        tunChannelAdapter = adapter
        do {
            _ = try helper.send(command: .openTun, payload: ["ifname": configuredRuntime.configuration.tunInterfaceName, "mtu": plan.mtu])
            try device.start()
            _ = try configuredRuntime.configuration.applyPacketTunnelPlanThroughHelper(interfaceName: configuredRuntime.configuration.tunInterfaceName)
            tunNetworkApplied = true
            adapter.overlayLifecycleChanged(ready: true)
        }
        catch { stopPacketDevice(); throw error }
    }

    private func stopPacketDevice() {
        tunChannelAdapter?.stop()
        tunChannelAdapter = nil
        if tunNetworkApplied {
            _ = try? configuredRuntime.configuration.removePacketTunnelPlanThroughHelper(interfaceName: configuredRuntime.configuration.tunInterfaceName)
            tunNetworkApplied = false
        }
        tunHelperPacketDevice?.stop()
        tunHelperPacketDevice = nil
        tunDevice = nil
        managedTunHelper?.stop()
        managedTunHelper = nil
    }

    private func startRemoteServiceOwners(_ specs: [ObstacleBridgeLinuxServiceSpec]) throws {
        stopRemoteServiceOwners()
        let sequence = UInt32(truncatingIfNeeded: configuredRuntime.connectionEpoch)
        for spec in specs {
            let owner = ObstacleBridgeLinuxServiceSocketOwner(spec: spec, maximumApplicationPayload: configuredRuntime.configuration.channelMuxMaximumApplicationPayload, instanceID: catalogInstanceID, connectionSequence: sequence) { [weak self] owner, frames in
                guard let runtime = self else { return }
                runtime.queue.async { [weak runtime] in runtime?.sendServiceFrames(frames, from: owner) }
            }
            try owner.start()
            remoteServiceOwners.append(owner)
        }
    }

    private func stopRemoteServiceOwners() {
        for owner in remoteServiceOwners { owner.stop() }
        remoteServiceOwners.removeAll()
        channelOwners.removeAll()
    }

    private func publishRemoteCatalog() throws {
        guard let channelMux, !configuredRuntime.configuration.remoteServices.isEmpty else { return }
        let sequence = UInt32(truncatingIfNeeded: configuredRuntime.connectionEpoch)
        let frames = try ObstacleBridgeLinuxServiceCatalog.frames(
            instanceID: catalogInstanceID, connectionSequence: sequence,
            services: configuredRuntime.configuration.remoteServices
        )
        for frame in frames {
            try channelMux.sendUnsolicited(frame)
        }
    }

    private func sendServiceFrames(_ frames: [ObstacleBridgeChannelMuxFrame], from owner: ObstacleBridgeLinuxServiceSocketOwner) {
        guard !stopped, let channelMux else { return }
        for frame in frames {
            if frame.messageType == .open { channelOwners[channelKey(frame)] = owner }
            do { try channelMux.sendUnsolicited(frame) }
            catch {
                if let epoch = activeCoordinatorEpoch {
                    apply(coordinator.handle(.transportFailed(epoch: epoch, reason: error.localizedDescription)))
                }
                return
            }
        }
    }

    private func startReceiveWorker(session: ObstacleBridgeLinuxConfiguredSession, mux: ObstacleBridgeLinuxChannelMuxSession, coordinatorEpoch: UInt64) {
        guard session.supportsDuplexReceive else { return }
        let epoch = configuredRuntime.connectionEpoch
        let worker = ObstacleBridgeLinuxReceiveWorker(
            epoch: epoch,
            receive: {
                while true {
                    if let payload = try session.receiveForOwner() { return payload }
                }
            },
            cancelReceive: { session.cancelReceive() },
            sink: { [weak self] workerEpoch, payload in
                guard let self, self.configuredRuntime.connectionEpoch == workerEpoch else { return }
                do {
                    mux.receive(try mux.decodeInbound(payload))
                } catch {
                    // Compression and ChannelMux framing are Core decisions.
                    // A rejected protected record cannot be discarded as if it
                    // were benign traffic: retire this epoch through the same
                    // Core retry effects as any other receive-path failure.
                    guard session.isProtected else { return }
                    self.queue.async { [weak self] in
                        self?.receiveFailed(
                            workerEpoch: workerEpoch,
                            coordinatorEpoch: coordinatorEpoch,
                            reason: "protected ChannelMux decode failed: \(error.localizedDescription)"
                        )
                    }
                }
            },
            onFailure: { [weak self] workerEpoch, reason in
                self?.queue.async { [weak self] in self?.receiveFailed(workerEpoch: workerEpoch, coordinatorEpoch: coordinatorEpoch, reason: reason) }
            }
        )
        replaceReceiveWorker(with: worker)
        worker.start()
    }

    /// The Admin queue may snapshot this reference while the serialized runtime
    /// replaces an epoch. Keep the publication atomic and cancel an old reader
    /// only after no status reader can retain the mutable owner slot.
    private func replaceReceiveWorker(with worker: ObstacleBridgeLinuxReceiveWorker?) {
        transportLifecycleOwner.replaceReceiveWorker(with: worker)
    }

    private func receiveFailed(workerEpoch: UInt64, coordinatorEpoch: UInt64, reason: String) {
        guard !stopped, configuredRuntime.connectionEpoch == workerEpoch,
              activeCoordinatorEpoch == coordinatorEpoch else { return }
        if inboundOnly { apply(coordinator.handle(.stop)) }
        else { apply(coordinator.handle(.receiveFinished(epoch: coordinatorEpoch, reason: reason))) }
    }

    private func routeInboundFrame(_ frame: ObstacleBridgeChannelMuxFrame) {
        if frame.protocolType == .tun, let tunChannelAdapter {
            tunChannelAdapter.receivedMuxFrame(frame)
            return
        }
        if frame.messageType == .remoteServicesSetV2 {
            guard let decoded = try? ObstacleBridgeLinuxServiceCatalog.decode(frame.body),
                  let install = try? remoteCatalogStore.install(instanceID: decoded.instanceID, connectionSequence: decoded.connectionSequence, services: decoded.services),
                  install.accepted else { return }
            do { try startRemoteServiceOwners(install.installed) }
            catch { publishCoordinatorSnapshot() }
            return
        }
        let key = channelKey(frame)
        if frame.messageType == .open {
            if let existing = channelOwners[key] {
                existing.handleInbound(frame)
                return
            }
            guard let owner = remoteServiceOwners.first(where: { $0.acceptsInboundOpen(frame) }) else { return }
            channelOwners[key] = owner
            owner.handleInbound(frame)
            return
        }
        guard let owner = channelOwners[key] else { return }
        owner.handleInbound(frame)
        if frame.messageType == .close { channelOwners.removeValue(forKey: key) }
    }

    private func channelKey(_ frame: ObstacleBridgeChannelMuxFrame) -> String { "\(frame.protocolType.rawValue):\(frame.channelID)" }

    private func freshSessionID() -> UInt64 {
        var generator = SystemRandomNumberGenerator()
        return UInt64.random(in: 1...UInt64.max, using: &generator)
    }

    private func freshNonce() -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    }

    private func beginRuntimeHealthLifetime() {
        runtimeHealthLock.lock()
        let previous = runtimeHealthURL.flatMap { ObstacleBridgeRuntimeHealthPersistence.load(from: $0) }
        previousRuntimeLifetimeEndedCleanly = previous?.previousLifetimeEndedCleanly
        runtimeHealthRing = previous ?? ObstacleBridgeRuntimeHealthRing()
        runtimeHealthSequence = previous?.records.last?.sequence ?? 0
        runtimeHealthLock.unlock()
        appendRuntimeHealth(event: "runtime_started")
    }

    private func startRuntimeHealthHeartbeat() {
        stopRuntimeHealthHeartbeat()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .seconds(15), repeating: .seconds(15))
        timer.setEventHandler { [weak self] in self?.appendRuntimeHealth(event: "heartbeat") }
        runtimeHealthTimer = timer
        timer.resume()
    }

    private func startLivenessProbes() {
        stopLivenessProbes()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .seconds(15), repeating: .seconds(15))
        timer.setEventHandler { [weak self] in
            guard let self, !self.stopped, let session = self.session, session.supportsLivenessProbes else { return }
            do { try session.probeLiveness() }
            catch {
                guard let epoch = self.activeCoordinatorEpoch else { return }
                self.apply(self.coordinator.handle(.transportFailed(epoch: epoch, reason: "liveness probe failed: \(error.localizedDescription)")))
            }
        }
        livenessProbeTimer = timer
        timer.resume()
    }

    private func stopLivenessProbes() {
        livenessProbeTimer?.setEventHandler {}
        livenessProbeTimer?.cancel()
        livenessProbeTimer = nil
    }

    private func stopRuntimeHealthHeartbeat() {
        runtimeHealthTimer?.setEventHandler {}
        runtimeHealthTimer?.cancel()
        runtimeHealthTimer = nil
        stopLivenessProbes()
    }

    private func appendRuntimeHealth(event: String, controlledStop: Bool = false) {
        let status = configuredRuntime.status()
        let receive = transportLifecycleOwner.receiveSnapshot()
        runtimeHealthLock.lock()
        runtimeHealthSequence += 1
        runtimeHealthRing.append(.init(
            sequence: runtimeHealthSequence,
            timestampUnixMilliseconds: UInt64(Date().timeIntervalSince1970 * 1_000),
            event: event,
            controlledStop: controlledStop,
            packetPumpRunning: receive?.state == "running",
            overlayState: coordinator.snapshot.state.rawValue,
            secureLinkState: status.secureLinkState,
            transportEpoch: status.receiveEpoch,
            incomingQueuedPackets: UInt64(max(0, receive?.queueDepth ?? 0)),
            incomingDroppedPackets: UInt64(max(0, receive?.droppedFrames ?? 0)),
            packetsFromSystem: UInt64(max(0, receive?.receivedFrames ?? 0))
        ))
        let ring = runtimeHealthRing
        let url = runtimeHealthURL
        runtimeHealthLock.unlock()
        if let url { try? ObstacleBridgeRuntimeHealthPersistence.save(ring, to: url) }
    }

    private func runtimeHealthMetadata() -> (count: Int, previousClean: Bool?) {
        runtimeHealthLock.lock()
        defer { runtimeHealthLock.unlock() }
        return (runtimeHealthRing.records.count, previousRuntimeLifetimeEndedCleanly)
    }

    deinit {
        runtimeHealthTimer?.cancel()
        livenessProbeTimer?.cancel()
        transportLifecycleOwner.cancelRetry()
        transportLifecycleOwner.replaceReceiveWorker(with: nil)
        stopServiceOwners()
        stopRemoteServiceOwners()
        configuredRuntime.disconnect()
    }
}
