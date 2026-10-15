import Dispatch
import Foundation
import ObstacleBridgeCore

/// Foreground owner for a shared myudp listener.  It keeps the socket reader,
/// Core registry, authenticated child sessions, and child runtime lifecycles
/// separate so one admitted endpoint cannot replace another endpoint's epoch.
public final class ObstacleBridgeLinuxMyUDPListenerRuntime: @unchecked Sendable {
    public struct Peer: Sendable {
        public let identity: String
        public let snapshot: ObstacleBridgeLinuxPeerSnapshot
    }

    private let configuration: ObstacleBridgeLinuxRuntimeConfiguration
    private let listener: ObstacleBridgeLinuxMyUDPPSKListener
    private let queue = DispatchQueue(label: "org.obstaclebridge.linux.myudp-listener")
    private let lock = NSLock()
    private var children: [String: ObstacleBridgeLinuxLiveRuntime] = [:]
    private var stopped = true

    public init(
        configuration: ObstacleBridgeLinuxRuntimeConfiguration,
        maximumPeers: Int = 32,
        maximumQueuedRecordsPerPeer: Int = 64,
        idleTimeoutMilliseconds: Int = 30_000
    ) throws {
        guard configuration.listenerMode, configuration.transport == .myudp,
              let psk = configuration.secureLinkPSK else {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.unavailableTransport(
                "myudp listener runtime requires listener_mode=true and secure_link_mode=psk"
            )
        }
        guard configuration.ownServices.isEmpty, configuration.remoteServices.isEmpty else {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.unavailableTransport(
                "myudp listener rejects ambiguous own_servers and remote_servers; omit both"
            )
        }
        self.configuration = configuration
        self.listener = try .init(
            port: configuration.port, psk: psk, maximumPeers: maximumPeers,
            maximumQueuedRecordsPerPeer: maximumQueuedRecordsPerPeer,
            serverNonce: { Self.freshNonce() }
        )
        self.idleTimeoutNanoseconds = UInt64(max(1, idleTimeoutMilliseconds)) * 1_000_000
        listener.onAuthenticatedSession = { [weak self] identity, session in
            self?.admit(identity: identity, session: session)
        }
    }

    private let idleTimeoutNanoseconds: UInt64
    public var port: Int { listener.port }
    public var activePeerCount: Int { listener.activePeerCount }

    public func start() {
        lock.lock()
        guard stopped else { lock.unlock(); return }
        stopped = false
        lock.unlock()
        queue.async { [weak self] in self?.run() }
    }

    public func stop() {
        lock.lock()
        stopped = true
        let active = Array(children.values)
        children.removeAll()
        lock.unlock()
        listener.close()
        active.forEach { $0.stop() }
    }

    public func peers() -> [Peer] {
        lock.lock()
        let rows = children.map { Peer(identity: $0.key, snapshot: $0.value.status().peer) }
        lock.unlock()
        return rows.sorted { $0.identity < $1.identity }
    }

    /// Aggregate redacted status for `/api/status`; `/api/peers` preserves the
    /// individual child projections.
    public func status() -> ObstacleBridgeLinuxRuntimeStatus {
        lock.lock()
        let rows = Array(children.values).map { $0.status() }
        lock.unlock()
        guard let first = rows.first else {
            return ObstacleBridgeLinuxConfiguredRuntime(configuration: configuration).status()
        }
        return .init(
            transport: first.transport,
            state: rows.isEmpty ? "listening" : "connected",
            attempts: rows.count,
            failureReason: nil,
            configuredCandidates: ["listener"],
            activeHost: "listener",
            port: port,
            secureLinkMode: "psk",
            secureLinkState: rows.contains(where: { $0.secureLinkState == "authenticated" }) ? "authenticated" : "disconnected",
            appReady: !rows.isEmpty,
            activeTCPChannels: rows.reduce(0) { $0 + $1.activeTCPChannels },
            activeUDPChannels: rows.reduce(0) { $0 + $1.activeUDPChannels },
            queuedServiceFrames: rows.reduce(0) { $0 + $1.queuedServiceFrames },
            droppedServiceFrames: rows.reduce(0) { $0 + $1.droppedServiceFrames },
            malformedServiceFrames: rows.reduce(0) { $0 + $1.malformedServiceFrames },
            serviceFailures: rows.reduce(0) { $0 + $1.serviceFailures },
            openedTCPChannels: rows.reduce(0) { $0 + $1.openedTCPChannels },
            openedUDPChannels: rows.reduce(0) { $0 + $1.openedUDPChannels },
            receiveLoopState: rows.isEmpty ? "listening" : "running",
            receiveEpoch: first.receiveEpoch,
            receivedFrames: rows.reduce(0) { $0 + $1.receivedFrames },
            droppedReceiveFrames: rows.reduce(0) { $0 + $1.droppedReceiveFrames },
            receiveQueueDepth: rows.reduce(0) { $0 + $1.receiveQueueDepth },
            receiveFailureReason: nil,
            peer: first.peer
        )
    }

    private func run() {
        while true {
            lock.lock(); let shouldStop = stopped; lock.unlock()
            guard !shouldStop else { return }
            do {
                try listener.pump()
                _ = try listener.serviceTimers()
                let expired = listener.expireIdlePeers(idleTimeoutNanoseconds: idleTimeoutNanoseconds)
                withdraw(expired)
            } catch {
                lock.lock(); let shouldStop = stopped; lock.unlock()
                if !shouldStop { continue }
                return
            }
        }
    }

    private func admit(identity: String, session: ObstacleBridgeLinuxConfiguredSession) {
        let child = ObstacleBridgeLinuxLiveRuntime(configuration: configuration)
        lock.lock()
        guard !stopped, children[identity] == nil else { lock.unlock(); session.close(); return }
        children[identity] = child
        lock.unlock()
        child.adoptInboundSession(session, host: identity)
    }

    private func withdraw(_ identities: [String]) {
        lock.lock()
        let retired = identities.compactMap { children.removeValue(forKey: $0) }
        lock.unlock()
        retired.forEach { $0.stop() }
    }

    private static func freshNonce() -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    }

    deinit { stop() }
}
