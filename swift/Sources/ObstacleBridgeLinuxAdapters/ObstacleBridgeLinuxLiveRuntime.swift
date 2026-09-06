import Dispatch
import Foundation
import ObstacleBridgePortable

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
    private var attempts = 0
    private var failureReason: String?
    private(set) public var snapshot = ObstacleBridgeLinuxLiveRuntimeSnapshot(state: "stopped", attempts: 0, failureReason: nil)

    public init(configuration: ObstacleBridgeLinuxRuntimeConfiguration, policy: ObstacleBridgeLinuxReconnectPolicy = .init()) {
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: configuration)
        self.configuredRuntime = runtime
        self.statusProjection = runtime.status()
        self.policy = policy
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
            receiveFailureReason: receive?.failureReason
        )
    }

    public func start() {
        queue.async { [weak self] in
            guard let self else { return }
            self.cancelRetry()
            self.configuredRuntime.disconnect()
            self.refreshStatusProjection()
            self.stopped = false
            self.attempts = 0
            self.failureReason = nil
            self.connectOrSchedule()
        }
    }

    /// Listener-side entry point. The TCP/WS/myudp acceptor authenticates the
    /// peer first, then hands the resulting configured session to the same
    /// ChannelMux, receive-worker, service-owner, and Admin lifecycle used by
    /// an outgoing epoch.
    public func adoptInboundSession(_ connectedSession: ObstacleBridgeLinuxConfiguredSession, host: String = "listener") {
        queue.async { [weak self] in
            guard let self else { return }
            self.cancelRetry()
            self.configuredRuntime.disconnect()
            self.stopped = false
            self.attempts = 1
            self.configuredRuntime.adoptInbound(connectedSession, host: host)
            do {
                self.session = connectedSession
                let mux = try ObstacleBridgeLinuxChannelMuxSession(runtime: self.configuredRuntime, session: connectedSession)
                mux.onUnsolicitedFrame = { [weak self] frame in self?.queue.async { [weak self] in self?.routeInboundFrame(frame) } }
                mux.activateReceiveOwner(); connectedSession.activateReceiveOwner()
                self.channelMux = mux
                self.startReceiveWorker(session: connectedSession, mux: mux)
                try self.publishRemoteCatalog(); try self.startOwnServiceOwners()
                self.refreshStatusProjection(); self.failureReason = nil
                self.publish(state: "connected", failureReason: nil)
            } catch {
                self.failureReason = error.localizedDescription
                connectedSession.close(); self.session = nil; self.channelMux = nil
                self.replaceReceiveWorker(with: nil); self.stopServiceOwners(); self.stopRemoteServiceOwners()
                self.refreshStatusProjection(); self.publish(state: "failed", failureReason: self.failureReason)
            }
        }
    }

    public func stop() {
        queue.sync {
            stopped = true
            cancelRetry()
            session?.close()
            session = nil
            channelMux = nil
            replaceReceiveWorker(with: nil)
            stopServiceOwners()
            stopRemoteServiceOwners()
            configuredRuntime.disconnect()
            refreshStatusProjection()
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
                refreshStatusProjection()
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
            self.replaceReceiveWorker(with: nil)
            self.stopServiceOwners()
            self.stopRemoteServiceOwners()
            self.configuredRuntime.disconnect()
            self.refreshStatusProjection()
            self.configuredRuntime.advanceCandidate()
            self.attempts = 0
            self.connectOrSchedule()
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

    private func connectOrSchedule() {
        guard !stopped else { return }
        attempts += 1
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
            startReceiveWorker(session: connectedSession, mux: mux)
            try publishRemoteCatalog()
            try startOwnServiceOwners()
            refreshStatusProjection()
            failureReason = nil
            publish(state: "connected", failureReason: nil)
        } catch {
            session = nil
            channelMux = nil
            replaceReceiveWorker(with: nil)
            stopServiceOwners()
            stopRemoteServiceOwners()
            configuredRuntime.disconnect()
            refreshStatusProjection()
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
                failureReason = error.localizedDescription
                reconnect()
                return
            }
        }
    }

    private func startReceiveWorker(session: ObstacleBridgeLinuxConfiguredSession, mux: ObstacleBridgeLinuxChannelMuxSession) {
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
                      let frame = try? ObstacleBridgeChannelMuxCodec.decode(payload) else { return }
                mux.receive(frame)
            },
            onFailure: { [weak self] workerEpoch, reason in
                self?.queue.async { [weak self] in self?.receiveFailed(epoch: workerEpoch, reason: reason) }
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

    private func receiveFailed(epoch: UInt64, reason: String) {
        guard !stopped, configuredRuntime.connectionEpoch == epoch else { return }
        failureReason = reason
        reconnect()
    }

    private func routeInboundFrame(_ frame: ObstacleBridgeChannelMuxFrame) {
        if frame.messageType == .remoteServicesSetV2 {
            guard let decoded = try? ObstacleBridgeLinuxServiceCatalog.decode(frame.body),
                  let install = try? remoteCatalogStore.install(instanceID: decoded.instanceID, connectionSequence: decoded.connectionSequence, services: decoded.services),
                  install.accepted else { return }
            do { try startRemoteServiceOwners(install.installed) }
            catch { failureReason = error.localizedDescription }
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
