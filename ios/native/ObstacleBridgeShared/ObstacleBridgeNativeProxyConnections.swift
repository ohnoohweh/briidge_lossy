import Foundation
import Network

enum ObstacleBridgeNativeConnectionSnapshot {
    static func endpoint(host: String?, port: Int?) -> Any {
        guard let host, let port else {
            return NSNull()
        }
        return ["host": host, "port": port]
    }

    static func make(
        proto: String,
        role: String,
        state: String,
        chanID: Int,
        svcID: Int,
        serviceName: String,
        sourceHost: String?,
        sourcePort: Int?,
        localHost: String?,
        localPort: Int?,
        remoteHost: String,
        remotePort: Int,
        stats: [String: Int]
    ) -> [String: Any] {
        [
            "protocol": proto,
            "role": role,
            "state": state,
            "chan_id": chanID,
            "svc_id": svcID,
            "service_name": serviceName,
            "source": endpoint(host: sourceHost, port: sourcePort),
            "local": endpoint(host: localHost, port: localPort),
            "local_port": localPort ?? NSNull(),
            "remote_destination": endpoint(host: remoteHost, port: remotePort),
            "stats": stats,
        ]
    }
}

final class ObstacleBridgeTCPProxyConnection {
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
                self.remoteConnection.send(content: data, completion: .contentProcessed { _ in })
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
                        self.localConnection.send(content: buffer, completion: .contentProcessed { _ in })
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
        _ = try? runtime.handleLocalServerEOF(chanID: chanID, overlayConnected: true)
        localConnection.cancel()
        maybeFinish()
    }

    private func closeRemote() {
        guard !remoteClosed else { return }
        remoteClosed = true
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

final class ObstacleBridgeUDPProxyConnection {
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
                    self.remoteConnection.send(content: data, completion: .contentProcessed { _ in })
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
                    self.localConnection.send(content: packet, completion: .contentProcessed { _ in })
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
