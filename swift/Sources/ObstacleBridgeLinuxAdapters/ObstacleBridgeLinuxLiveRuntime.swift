import Dispatch
import Foundation
import ObstacleBridgeCore

public struct ObstacleBridgeLinuxLiveRuntimeSnapshot: Equatable, Sendable {
    public let state: String
    public let attempts: Int
    public let failureReason: String?
    public let nextRetryMilliseconds: Int?
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
    private let coordinator: ObstacleBridgeOverlayCoordinator
    private let queue = DispatchQueue(label: "org.obstaclebridge.linux.live-runtime")
    private let statusLock = NSLock()
    private var statusProjection: ObstacleBridgeLinuxRuntimeStatus
    private var session: ObstacleBridgeLinuxConfiguredSession?
    private var channelMux: ObstacleBridgeLinuxChannelMuxSession?
    private var retryTimer: DispatchSourceTimer?
    private var receiveWorker: ObstacleBridgeLinuxReceiveWorker?
    private var serviceOwners: [ObstacleBridgeLinuxServiceSocketOwner] = []
    private var remoteServiceOwners: [ObstacleBridgeLinuxServiceSocketOwner] = []
    private var channelOwners: [String: ObstacleBridgeLinuxServiceSocketOwner] = [:]
    private let remoteCatalogStore = ObstacleBridgeLinuxServiceCatalogStore()
    private let catalogInstanceID: UInt64
    private var stopped = true
    private var activeCoordinatorEpoch: UInt64?
    private var liveSnapshotProjection = ObstacleBridgeLinuxLiveRuntimeSnapshot(state: "stopped", attempts: 0, failureReason: nil, nextRetryMilliseconds: nil)
    private(set) public var snapshot = ObstacleBridgeLinuxLiveRuntimeSnapshot(state: "stopped", attempts: 0, failureReason: nil, nextRetryMilliseconds: nil)

    public init(configuration: ObstacleBridgeLinuxRuntimeConfiguration, policy: ObstacleBridgeLinuxReconnectPolicy = .init()) {
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: configuration)
        self.configuredRuntime = runtime
        self.statusProjection = runtime.status()
        self.coordinator = .init(candidateCount: configuration.peerCandidates.count, policy: policy)
        var generator = SystemRandomNumberGenerator()
        self.catalogInstanceID = UInt64.random(in: 1...UInt64.max, using: &generator)
    }

    /// A redacted snapshot that Admin workers may read without touching the
    /// serialized transport owner.
    public func status() -> ObstacleBridgeLinuxRuntimeStatus {
        statusLock.lock()
        let receive = receiveWorker?.snapshot()
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
            transport: base.transport, state: base.state, attempts: base.attempts,
            failureReason: base.failureReason, configuredCandidates: base.configuredCandidates,
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
            self.stopped = false
            self.apply(self.coordinator.handle(.start))
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
        configuredRuntime.cancelInFlightConnection()
        queue.sync {
            stopped = true
            apply(coordinator.handle(.stop))
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
                if let epoch = activeCoordinatorEpoch {
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
            if let epoch = self.activeCoordinatorEpoch {
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
        do {
            let sessionID = freshSessionID()
            let nonce = freshNonce()
            let connectedSession = try configuredRuntime.connect(sessionID: sessionID, clientNonce: nonce)
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
            apply(coordinator.handle(.transportConnected(epoch: epoch)))
            apply(coordinator.handle(.authenticated(epoch: epoch)))
            try publishRemoteCatalog()
            try startOwnServiceOwners()
        } catch ObstacleBridgeLinuxOverlayTransportError.cancelled {
            // `stop()` has already interrupted the in-flight lower session.
            // Do not publish a retry that could briefly outlive shutdown.
            return
        } catch {
            apply(coordinator.handle(.transportFailed(epoch: epoch, reason: error.localizedDescription)))
        }
    }

    private func scheduleRetry(token: UInt64, afterMilliseconds delay: Int) {
        cancelRetry()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        retryTimer = timer
        timer.schedule(deadline: .now() + .milliseconds(delay))
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            self.cancelRetry()
            self.apply(self.coordinator.handle(.retryTimerFired(token: token)))
        }
        timer.resume()
    }

    private func cancelRetry() {
        retryTimer?.setEventHandler {}
        retryTimer?.cancel()
        retryTimer = nil
    }

    /// Executes only platform mechanics requested by Core.  The coordinator
    /// owns epoch admission, candidate selection, retry bounds, and stale
    /// callback rejection; this adapter owns Dispatch and socket teardown.
    private func apply(_ transition: ObstacleBridgeOverlayCoordinatorTransition) {
        for effect in transition.effects {
            switch effect {
            case .openTransport(let epoch, _, _):
                openTransport(epoch: epoch)
            case .cancelTransport(let epoch):
                guard activeCoordinatorEpoch == nil || activeCoordinatorEpoch == epoch else { continue }
                session?.close()
                session = nil
                channelMux = nil
                activeCoordinatorEpoch = nil
                replaceReceiveWorker(with: nil)
                stopServiceOwners()
                stopRemoteServiceOwners()
                _ = remoteCatalogStore.withdraw()
                configuredRuntime.disconnect()
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
        let value = ObstacleBridgeLinuxLiveRuntimeSnapshot(state: state, attempts: attempts, failureReason: failureReason, nextRetryMilliseconds: nextRetryMilliseconds)
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

    private func startOwnServiceOwners() throws {
        stopServiceOwners()
        let sequence = UInt32(truncatingIfNeeded: configuredRuntime.connectionEpoch)
        for spec in configuredRuntime.configuration.ownServices {
            let owner = ObstacleBridgeLinuxServiceSocketOwner(spec: spec, instanceID: catalogInstanceID, connectionSequence: sequence) { [weak self] owner, frames in
                guard let runtime = self else { return }
                runtime.queue.async { [weak runtime] in runtime?.sendServiceFrames(frames, from: owner) }
            }
            try owner.start()
            serviceOwners.append(owner)
        }
    }

    private func stopServiceOwners() {
        for owner in serviceOwners { owner.stop() }
        serviceOwners.removeAll()
    }

    private func startRemoteServiceOwners(_ specs: [ObstacleBridgeLinuxServiceSpec]) throws {
        stopRemoteServiceOwners()
        let sequence = UInt32(truncatingIfNeeded: configuredRuntime.connectionEpoch)
        for spec in specs {
            let owner = ObstacleBridgeLinuxServiceSocketOwner(spec: spec, instanceID: catalogInstanceID, connectionSequence: sequence) { [weak self] owner, frames in
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
        let payload = try ObstacleBridgeLinuxServiceCatalog.encode(instanceID: catalogInstanceID, connectionSequence: sequence, services: configuredRuntime.configuration.remoteServices)
        try channelMux.sendUnsolicited(.init(channelID: 0, protocolType: .udp, counter: 0, messageType: .remoteServicesSetV2, body: payload))
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
                guard let self, self.configuredRuntime.connectionEpoch == workerEpoch,
                      let frame = try? mux.decodeInbound(payload) else { return }
                mux.receive(frame)
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
        statusLock.lock()
        let previous = receiveWorker
        receiveWorker = worker
        statusLock.unlock()
        previous?.stop()
    }

    private func receiveFailed(workerEpoch: UInt64, coordinatorEpoch: UInt64, reason: String) {
        guard !stopped, configuredRuntime.connectionEpoch == workerEpoch,
              activeCoordinatorEpoch == coordinatorEpoch else { return }
        apply(coordinator.handle(.receiveFinished(epoch: coordinatorEpoch, reason: reason)))
    }

    private func routeInboundFrame(_ frame: ObstacleBridgeChannelMuxFrame) {
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

    deinit {
        retryTimer?.cancel()
        stopServiceOwners()
        stopRemoteServiceOwners()
        configuredRuntime.disconnect()
    }
}
