import Foundation
import Network

/// Serial-owner Network.framework sender. A connection is permitted one
/// submitted write and a bounded payload FIFO behind it; Network.framework is
/// never used as an unbounded application queue.
final class ObstacleBridgeBoundedConnectionDataSender {
    private struct PendingWrite {
        let data: Data
        let completion: (NWError?) -> Void
    }

    private let connection: NWConnection
    private let pending: ObstacleBridgeBoundedFIFO<PendingWrite>
    private var sendInFlight = false
    private var stopped = false

    init(connection: NWConnection, maximumItems: Int = 128, maximumBytes: Int = 2 * 1_024 * 1_024) {
        self.connection = connection
        self.pending = .init(
            limits: .init(maximumItems: maximumItems, maximumBytes: maximumBytes, maximumAge: 60),
            byteCount: { $0.data.count }
        )
    }

    /// Returns false when the bounded application queue rejected the write.
    @discardableResult
    func submit(_ data: Data, completion: @escaping (NWError?) -> Void = { _ in }) -> Bool {
        guard !stopped, pending.append(.init(data: data, completion: completion)) else { return false }
        drainOne()
        return true
    }

    func stop() {
        stopped = true
        pending.removeAll(keepingCapacity: false)
    }

    private func drainOne() {
        guard !stopped, !sendInFlight, let write = pending.popFirst() else { return }
        sendInFlight = true
        // OBSTACLEBRIDGE-NETWORK-SEND-BOUNDS: inflight=1; queue=ObstacleBridgeBoundedConnectionDataSender; test=test_native_proxy_connections_keep_callbacks_on_owner_queue
        connection.send(content: write.data, completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            self.sendInFlight = false
            write.completion(error)
            self.drainOne()
        })
    }
}

/// Redacted lifecycle vocabulary shared by Apple proxy owners. Desktop hosts
/// map supervisor failures onto these values; no configuration detail crosses
/// into status or Admin snapshots.
public enum ObstacleBridgeProxyLifecycleErrorCode {
    public static let unavailable = "unavailable"
    public static let startupFailed = "startup_failed"
    public static let invalidConfiguration = "invalid_configuration"
}

/// Keeps configured intent distinct from a listener/worker's live state in
/// every Apple proxy status projection.
public enum ObstacleBridgeProxyStatusProjection {
    public static func configuredEnabled(_ enabled: Bool) -> Bool { enabled }
}

/// Both Network connections are started on the injected proxy-owner queue;
/// all mutable proxy state is accessed only by callbacks on that queue.
final class ObstacleBridgeTCPProxyConnection: @unchecked Sendable {
    // OBSTACLEBRIDGE-CONCURRENCY: serial; test=test_native_proxy_connections_keep_callbacks_on_owner_queue
    private let chanID: Int
    private let spec: ObstacleBridgeNativeServiceSpec
    private let listenerHost: String
    private let listenerPort: Int
    private let runtime: ObstacleBridgeChannelMuxTcpRuntime
    private let localConnection: NWConnection
    private let remoteConnection: NWConnection
    private let queue: DispatchQueue
    private let updateState: ([String: Any]) -> Void
    private let finish: (Int) -> Void

    private var localClosed = false
    private var remoteClosed = false
    private var state = "connecting"
    private var sourceHost: String?
    private var sourcePort: Int?
    private lazy var localSender = ObstacleBridgeBoundedConnectionDataSender(connection: localConnection)
    private lazy var remoteSender = ObstacleBridgeBoundedConnectionDataSender(connection: remoteConnection)
    private var stats: [String: Int] = [
        "rx_msgs": 0,
        "tx_msgs": 0,
        "rx_bytes": 0,
        "tx_bytes": 0,
    ]

    init(
        chanID: Int,
        spec: ObstacleBridgeNativeServiceSpec,
        listenerHost: String,
        listenerPort: Int,
        runtime: ObstacleBridgeChannelMuxTcpRuntime,
        localConnection: NWConnection,
        remoteConnection: NWConnection,
        queue: DispatchQueue,
        updateState: @escaping ([String: Any]) -> Void,
        finish: @escaping (Int) -> Void
    ) {
        self.chanID = chanID
        self.spec = spec
        self.listenerHost = listenerHost
        self.listenerPort = listenerPort
        self.runtime = runtime
        self.localConnection = localConnection
        self.remoteConnection = remoteConnection
        self.queue = queue
        self.updateState = updateState
        self.finish = finish
    }

    func start() {
        captureSourceEndpoint()
        localConnection.stateUpdateHandler = { [weak self] state in
            self?.handleLocalState(state)
        }
        remoteConnection.stateUpdateHandler = { [weak self] state in
            self?.handleRemoteState(state)
        }
        localConnection.start(queue: queue)
        remoteConnection.start(queue: queue)
        updateState(snapshot())
    }

    func stop() {
        localClosed = true
        remoteClosed = true
        localSender.stop()
        remoteSender.stop()
        localConnection.cancel()
        remoteConnection.cancel()
        state = "closed"
        updateState(snapshot())
        finish(chanID)
    }

    func snapshot() -> [String: Any] {
        ObstacleBridgeNativeConnectionSnapshot.make(
            proto: "tcp",
            role: "server",
            state: state,
            chanID: chanID,
            svcID: spec.svcID,
            serviceName: spec.name ?? "",
            sourceHost: sourceHost,
            sourcePort: sourcePort,
            localHost: listenerHost,
            localPort: listenerPort,
            remoteHost: spec.targetHost,
            remotePort: spec.targetPort,
            stats: stats
        )
    }

    private func captureSourceEndpoint() {
        if case let .hostPort(host, port) = localConnection.endpoint {
            sourceHost = host.debugDescription
            sourcePort = Int(port.rawValue)
        }
    }

    private func handleLocalState(_ state: NWConnection.State) {
        switch state {
        case .ready:
            receiveFromLocal()
        case .failed, .cancelled:
            closeLocal()
        default:
            break
        }
    }

    private func handleRemoteState(_ state: NWConnection.State) {
        switch state {
        case .ready:
            self.state = "connected"
            updateState(snapshot())
            receiveFromRemote()
        case .failed, .cancelled:
            closeRemote()
        default:
            break
        }
    }

    private func receiveFromLocal() {
        localConnection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                _ = try? self.runtime.handleLocalServerData(chanID: self.chanID, payload: data, overlayConnected: true)
                self.stats["tx_msgs", default: 0] += 1
                self.stats["tx_bytes", default: 0] += data.count
                self.updateState(self.snapshot())
                guard self.remoteSender.submit(data, completion: { [weak self] error in
                    if error != nil { self?.closeRemote() }
                }) else {
                    self.closeRemote()
                    return
                }
            }
            if isComplete || error != nil {
                self.closeLocal()
                return
            }
            self.receiveFromLocal()
        }
    }

    private func receiveFromRemote() {
        remoteConnection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                let inbound = self.runtime.handleInboundServerData(chanID: self.chanID, body: data)
                if inbound.delivered {
                    for buffer in inbound.writtenBuffers {
                        self.stats["rx_msgs", default: 0] += 1
                        self.stats["rx_bytes", default: 0] += buffer.count
                        guard self.localSender.submit(buffer, completion: { [weak self] error in
                            if error != nil { self?.closeLocal() }
                        }) else {
                            self.closeLocal()
                            return
                        }
                    }
                    self.updateState(self.snapshot())
                }
            }
            if isComplete || error != nil {
                self.closeRemote()
                return
            }
            self.receiveFromRemote()
        }
    }

    private func closeLocal() {
        guard !localClosed else { return }
        localClosed = true
        localSender.stop()
        _ = try? runtime.handleLocalServerEOF(chanID: chanID, overlayConnected: true)
        localConnection.cancel()
        maybeFinish()
    }

    private func closeRemote() {
        guard !remoteClosed else { return }
        remoteClosed = true
        remoteSender.stop()
        _ = runtime.handleInboundServerClose(chanID: chanID)
        remoteConnection.cancel()
        maybeFinish()
    }

    private func maybeFinish() {
        if localClosed || remoteClosed {
            state = "closed"
            updateState(snapshot())
        }
        if localClosed && remoteClosed {
            finish(chanID)
        } else if localClosed {
            remoteConnection.cancel()
            remoteClosed = true
            finish(chanID)
        } else if remoteClosed {
            localConnection.cancel()
            localClosed = true
            finish(chanID)
        }
    }
}

/// The UDP proxy shares the same injected serial owner queue.
final class ObstacleBridgeUDPProxyConnection: @unchecked Sendable {
    // OBSTACLEBRIDGE-CONCURRENCY: serial; test=test_native_proxy_connections_keep_callbacks_on_owner_queue
    private let spec: ObstacleBridgeNativeServiceSpec
    private let listenerHost: String
    private let listenerPort: Int
    private let runtime: ObstacleBridgeChannelMuxUdpRuntime
    private let localConnection: NWConnection
    private let remoteConnection: NWConnection
    private let queue: DispatchQueue
    private let updateState: ([String: Any]?) -> Void
    private let finish: (Int?) -> Void

    private var chanID: Int?
    private var sourceHost: String?
    private var sourcePort: Int?
    private var closed = false
    private lazy var localSender = ObstacleBridgeBoundedConnectionDataSender(connection: localConnection)
    private lazy var remoteSender = ObstacleBridgeBoundedConnectionDataSender(connection: remoteConnection)
    private var stats: [String: Int] = [
        "rx_msgs": 0,
        "tx_msgs": 0,
        "rx_bytes": 0,
        "tx_bytes": 0,
    ]

    init(
        spec: ObstacleBridgeNativeServiceSpec,
        listenerHost: String,
        listenerPort: Int,
        runtime: ObstacleBridgeChannelMuxUdpRuntime,
        localConnection: NWConnection,
        remoteConnection: NWConnection,
        queue: DispatchQueue,
        updateState: @escaping ([String: Any]?) -> Void,
        finish: @escaping (Int?) -> Void
    ) {
        self.spec = spec
        self.listenerHost = listenerHost
        self.listenerPort = listenerPort
        self.runtime = runtime
        self.localConnection = localConnection
        self.remoteConnection = remoteConnection
        self.queue = queue
        self.updateState = updateState
        self.finish = finish
    }

    func start() {
        captureSourceEndpoint()
        localConnection.stateUpdateHandler = { [weak self] state in
            self?.handleState(state, isLocal: true)
        }
        remoteConnection.stateUpdateHandler = { [weak self] state in
            self?.handleState(state, isLocal: false)
        }
        localConnection.start(queue: queue)
        remoteConnection.start(queue: queue)
    }

    func stop() {
        guard !closed else { return }
        closed = true
        localSender.stop()
        remoteSender.stop()
        localConnection.cancel()
        remoteConnection.cancel()
        if let chanID {
            _ = runtime.handleInboundClose(chanID: chanID)
        }
        updateState(nil)
        finish(chanID)
    }

    func snapshot() -> [String: Any]? {
        guard let chanID else {
            return nil
        }
        return ObstacleBridgeNativeConnectionSnapshot.make(
            proto: "udp",
            role: "server",
            state: "connected",
            chanID: chanID,
            svcID: spec.svcID,
            serviceName: spec.name ?? "",
            sourceHost: sourceHost,
            sourcePort: sourcePort,
            localHost: listenerHost,
            localPort: listenerPort,
            remoteHost: spec.targetHost,
            remotePort: spec.targetPort,
            stats: stats
        )
    }

    private func captureSourceEndpoint() {
        if case let .hostPort(host, port) = localConnection.endpoint {
            sourceHost = host.debugDescription
            sourcePort = Int(port.rawValue)
        }
    }

    private func handleState(_ state: NWConnection.State, isLocal: Bool) {
        switch state {
        case .ready:
            if isLocal {
                receiveFromLocal()
            } else {
                receiveFromRemote()
            }
        case .failed, .cancelled:
            stop()
        default:
            break
        }
    }

    private func receiveFromLocal() {
        localConnection.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                let snapshot = try? self.runtime.handleLocalServerDatagram(
                    spec: self.spec.toChannelMuxServiceSpec(),
                    serviceKey: "svc-\(self.spec.svcID)",
                    payload: data,
                    addrHost: self.sourceHost ?? "127.0.0.1",
                    addrPort: self.sourcePort ?? 0,
                    overlayConnected: true,
                    acceptingEnabled: true
                )
                if let snapshot {
                    self.chanID = snapshot.chanID
                    self.stats["tx_msgs", default: 0] += 1
                    self.stats["tx_bytes", default: 0] += data.count
                    self.updateState(self.snapshot())
                    guard self.remoteSender.submit(data, completion: { [weak self] error in
                        if error != nil { self?.stop() }
                    }) else {
                        self.stop()
                        return
                    }
                }
            }
            if error != nil || self.closed {
                self.stop()
                return
            }
            self.receiveFromLocal()
        }
    }

    private func receiveFromRemote() {
        remoteConnection.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            if let data, !data.isEmpty, let chanID = self.chanID {
                let inbound = self.runtime.handleInboundServerData(chanID: chanID, body: data)
                if inbound.delivered, let packet = inbound.packet {
                    self.stats["rx_msgs", default: 0] += 1
                    self.stats["rx_bytes", default: 0] += packet.count
                    self.updateState(self.snapshot())
                    guard self.localSender.submit(packet, completion: { [weak self] error in
                        if error != nil { self?.stop() }
                    }) else {
                        self.stop()
                        return
                    }
                }
            }
            if error != nil || self.closed {
                self.stop()
                return
            }
            self.receiveFromRemote()
        }
    }
}
