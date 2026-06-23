import Foundation
import Network

struct ObstacleBridgeOverlayConnectionState {
    let proto: String
    let role: String
    let chanID: Int
    let svcID: Int
    let serviceName: String
    let remoteHost: String
    let remotePort: Int
    var state: String
    var localHost: String?
    var localPort: Int?
    var stats: [String: Int]

    func snapshot() -> [String: Any] {
        ObstacleBridgeNativeConnectionSnapshot.make(
            proto: proto,
            role: role,
            state: state,
            chanID: chanID,
            svcID: svcID,
            serviceName: serviceName,
            sourceHost: nil,
            sourcePort: nil,
            localHost: localHost,
            localPort: localPort,
            remoteHost: remoteHost,
            remotePort: remotePort,
            stats: stats
        )
    }
}

enum ObstacleBridgeOverlayConnectionSupport {
    static func endpointDescription(_ endpoint: NWEndpoint) -> (host: String, port: Int) {
        if case let .hostPort(host, port) = endpoint {
            return (host.debugDescription, Int(port.rawValue))
        }
        return ("127.0.0.1", 0)
    }

    static func connectionRows(from states: [Int: ObstacleBridgeOverlayConnectionState]) -> [[String: Any]] {
        states.values.map { $0.snapshot() }.sorted { lhs, rhs in
            (lhs["chan_id"] as? Int ?? -1) < (rhs["chan_id"] as? Int ?? -1)
        }
    }

    static func makeState(
        proto: String,
        role: String,
        chanID: Int,
        spec: ObstacleBridgeChannelMuxCodec.ServiceSpec,
        serviceName: String,
        state: String,
        localHost: String?,
        localPort: Int?
    ) -> ObstacleBridgeOverlayConnectionState {
        ObstacleBridgeOverlayConnectionState(
            proto: proto,
            role: role,
            chanID: chanID,
            svcID: spec.svcID,
            serviceName: serviceName,
            remoteHost: spec.rHost,
            remotePort: spec.rPort,
            state: state,
            localHost: localHost,
            localPort: localPort,
            stats: ["rx_msgs": 0, "tx_msgs": 0, "rx_bytes": 0, "tx_bytes": 0]
        )
    }

    static func updateConnectedState(
        states: inout [Int: ObstacleBridgeOverlayConnectionState],
        proto: String,
        chanID: Int,
        localHost: String?,
        localPort: Int?
    ) {
        guard var state = states[chanID], state.proto == proto else { return }
        state.state = "connected"
        if let localHost {
            state.localHost = localHost
        }
        if let localPort {
            state.localPort = localPort
        }
        states[chanID] = state
    }

    static func recordTraffic(
        states: inout [Int: ObstacleBridgeOverlayConnectionState],
        proto: String,
        chanID: Int,
        direction: String,
        bytes: Int
    ) {
        guard var state = states[chanID], state.proto == proto else { return }
        let keyMessages = direction == "inbound" ? "rx_msgs" : "tx_msgs"
        let keyBytes = direction == "inbound" ? "rx_bytes" : "tx_bytes"
        state.stats[keyMessages, default: 0] += 1
        state.stats[keyBytes, default: 0] += bytes
        states[chanID] = state
    }
}

final class ObstacleBridgeUDPServerConnectionDriver {
    struct SnapshotEvent {
        let chanID: Int
        let frames: [Data]
        let bytes: Int
    }

    private let connection: NWConnection
    private let spec: ObstacleBridgeChannelMuxCodec.ServiceSpec
    private let serviceKey: String
    private let queue: DispatchQueue
    private let runtime: ObstacleBridgeChannelMuxUdpRuntime
    private let startedProvider: () -> Bool
    private let overlayConnectedProvider: () -> Bool
    private let handleSnapshot: (SnapshotEvent) -> Void
    private let handleClosed: (Int?) -> Void
    private let eventSink: (String, [String: Any]) -> Void
    private let eventPrefix: String

    private var chanID: Int?

    init(
        connection: NWConnection,
        spec: ObstacleBridgeChannelMuxCodec.ServiceSpec,
        serviceKey: String,
        queue: DispatchQueue,
        runtime: ObstacleBridgeChannelMuxUdpRuntime,
        startedProvider: @escaping () -> Bool,
        overlayConnectedProvider: @escaping () -> Bool,
        handleSnapshot: @escaping (SnapshotEvent) -> Void,
        handleClosed: @escaping (Int?) -> Void,
        eventSink: @escaping (String, [String: Any]) -> Void = { _, _ in },
        eventPrefix: String = "overlay"
    ) {
        self.connection = connection
        self.spec = spec
        self.serviceKey = serviceKey
        self.queue = queue
        self.runtime = runtime
        self.startedProvider = startedProvider
        self.overlayConnectedProvider = overlayConnectedProvider
        self.handleSnapshot = handleSnapshot
        self.handleClosed = handleClosed
        self.eventSink = eventSink
        self.eventPrefix = eventPrefix
    }

    func start() {
        eventSink("\(eventPrefix)_udp_server_driver_started", [
            "service_id": spec.svcID,
            "service_name": spec.name ?? "",
            "target_host": spec.rHost,
            "target_port": spec.rPort,
        ])
        receiveNext()
    }

    private func receiveNext() {
        guard startedProvider() else {
            return
        }
        connection.receiveMessage { [weak self] data, _, _, error in
            self?.queue.async {
                guard let self, self.startedProvider() else { return }
                if let data, !data.isEmpty {
                    let endpoint = ObstacleBridgeOverlayConnectionSupport.endpointDescription(self.connection.endpoint)
                    self.eventSink("\(self.eventPrefix)_udp_server_datagram_read", [
                        "bytes": data.count,
                        "source_host": endpoint.host,
                        "source_port": endpoint.port,
                        "service_id": self.spec.svcID,
                        "overlay_connected": self.overlayConnectedProvider(),
                    ])
                    do {
                        if let snapshot = try self.runtime.handleLocalServerDatagram(
                            spec: self.spec,
                            serviceKey: self.serviceKey,
                            payload: data,
                            addrHost: endpoint.host,
                            addrPort: endpoint.port,
                            overlayConnected: self.overlayConnectedProvider(),
                            acceptingEnabled: true
                        ) {
                            self.chanID = snapshot.chanID
                            self.eventSink("\(self.eventPrefix)_udp_server_datagram_mux", [
                                "chan_id": snapshot.chanID,
                                "bytes": data.count,
                                "frames": snapshot.frames.count,
                            ])
                            self.handleSnapshot(.init(chanID: snapshot.chanID, frames: snapshot.frames, bytes: data.count))
                        } else {
                            self.eventSink("\(self.eventPrefix)_udp_server_datagram_rejected", [
                                "bytes": data.count,
                                "service_id": self.spec.svcID,
                                "overlay_connected": self.overlayConnectedProvider(),
                            ])
                        }
                    } catch {
                        self.eventSink("\(self.eventPrefix)_udp_server_datagram_failed", [
                            "bytes": data.count,
                            "error": error.localizedDescription,
                        ])
                    }
                }
                if error != nil {
                    self.eventSink("\(self.eventPrefix)_udp_server_receive_error", [
                        "chan_id": self.chanID ?? -1,
                        "error": error?.localizedDescription ?? "",
                    ])
                    if let chanID = self.chanID {
                        let snapshot = self.runtime.handleInboundClose(chanID: chanID)
                        self.handleClosed(snapshot.closed ? chanID : nil)
                    } else {
                        self.handleClosed(nil)
                    }
                    self.connection.cancel()
                    return
                }
                self.receiveNext()
            }
        }
    }
}

final class ObstacleBridgeUDPClientConnectionDriver {
    private let chanID: Int
    private let spec: ObstacleBridgeChannelMuxCodec.ServiceSpec
    private let queue: DispatchQueue
    private let runtime: ObstacleBridgeChannelMuxUdpRuntime
    private let startedProvider: () -> Bool
    private let registerConnection: (NWConnection) -> Void
    private let updateConnected: (String?, Int?) -> Void
    private let sendOnUDPConnection: (NWConnection, Data, Int) -> Void
    private let sendMuxFrames: ([Data]) -> Void
    private let recordInbound: (Int) -> Void
    private let recordOutbound: (Int) -> Void
    private let eventSink: (String, [String: Any]) -> Void
    private let failureEvent: String
    private let handleClosed: () -> Void

    private var connection: NWConnection?
    private var closed = false

    init(
        chanID: Int,
        spec: ObstacleBridgeChannelMuxCodec.ServiceSpec,
        queue: DispatchQueue,
        runtime: ObstacleBridgeChannelMuxUdpRuntime,
        startedProvider: @escaping () -> Bool,
        registerConnection: @escaping (NWConnection) -> Void,
        updateConnected: @escaping (String?, Int?) -> Void,
        sendOnUDPConnection: @escaping (NWConnection, Data, Int) -> Void,
        sendMuxFrames: @escaping ([Data]) -> Void,
        recordInbound: @escaping (Int) -> Void,
        recordOutbound: @escaping (Int) -> Void,
        eventSink: @escaping (String, [String: Any]) -> Void,
        failureEvent: String,
        handleClosed: @escaping () -> Void
    ) {
        self.chanID = chanID
        self.spec = spec
        self.queue = queue
        self.runtime = runtime
        self.startedProvider = startedProvider
        self.registerConnection = registerConnection
        self.updateConnected = updateConnected
        self.sendOnUDPConnection = sendOnUDPConnection
        self.sendMuxFrames = sendMuxFrames
        self.recordInbound = recordInbound
        self.recordOutbound = recordOutbound
        self.eventSink = eventSink
        self.failureEvent = failureEvent
        self.handleClosed = handleClosed
    }

    func start() {
        guard !closed, connection == nil,
              let port = NWEndpoint.Port(rawValue: UInt16(spec.rPort))
        else {
            eventSink(failureEvent, ["chan_id": chanID, "error": "invalid or duplicate UDP client start", "host": spec.rHost, "port": spec.rPort])
            return
        }
        eventSink("\(failureEvent.replacingOccurrences(of: "_failed", with: ""))_start", [
            "chan_id": chanID,
            "service_id": spec.svcID,
            "service_name": spec.name ?? "",
            "host": spec.rHost,
            "port": spec.rPort,
        ])
        let connection = NWConnection(host: NWEndpoint.Host(spec.rHost), port: port, using: .udp)
        self.connection = connection
        registerConnection(connection)
        connection.stateUpdateHandler = { [weak self] state in
            self?.queue.async {
                self?.handleState(state)
            }
        }
        connection.start(queue: queue)
        let snapshot = runtime.handleClientConnected(
            chanID: chanID,
            peerAddrHost: spec.rHost,
            peerAddrPort: spec.rPort
        )
        updateConnected(snapshot.localAddrHost, snapshot.localAddrPort)
        eventSink("\(failureEvent.replacingOccurrences(of: "_failed", with: ""))_activated", [
            "chan_id": chanID,
            "service_id": spec.svcID,
            "service_name": spec.name ?? "",
            "host": spec.rHost,
            "port": spec.rPort,
            "pending_flushed": snapshot.flushedPackets.count,
        ])
        for packet in snapshot.flushedPackets {
            sendOnUDPConnection(connection, packet, chanID)
            recordInbound(packet.count)
        }
        receiveNext()
    }

    func stop(notifyClosed: Bool = false) {
        guard !closed else { return }
        closed = true
        connection?.stateUpdateHandler = nil
        connection?.cancel()
        connection = nil
        if notifyClosed {
            handleClosed()
        }
    }

    private func handleState(_ state: NWConnection.State) {
        switch state {
        case .ready:
            eventSink("\(failureEvent.replacingOccurrences(of: "_failed", with: ""))_ready", [
                "chan_id": chanID,
                "host": spec.rHost,
                "port": spec.rPort,
            ])
            updateConnected(nil, nil)
        case .failed(let error):
            eventSink(failureEvent, ["chan_id": chanID, "error": error.localizedDescription, "host": spec.rHost, "port": spec.rPort])
            stop(notifyClosed: true)
        case .cancelled:
            stop(notifyClosed: true)
        default:
            break
        }
    }

    private func receiveNext() {
        guard startedProvider(), !closed, let connection else {
            return
        }
        connection.receiveMessage { [weak self] data, _, _, error in
            self?.queue.async {
                guard let self, self.startedProvider(), !self.closed else { return }
                if let data, !data.isEmpty,
                   let snapshot = try? self.runtime.handleLocalClientDatagram(chanID: self.chanID, payload: data) {
                    self.eventSink("\(self.failureEvent.replacingOccurrences(of: "_failed", with: ""))_data_read", [
                        "chan_id": self.chanID,
                        "bytes": data.count,
                        "frames": snapshot.frames.count,
                    ])
                    self.sendMuxFrames(snapshot.frames)
                    self.recordOutbound(data.count)
                }
                if error != nil {
                    self.eventSink("\(self.failureEvent.replacingOccurrences(of: "_failed", with: ""))_receive_error", [
                        "chan_id": self.chanID,
                        "error": error?.localizedDescription ?? "",
                    ])
                    self.stop(notifyClosed: true)
                    return
                }
                self.receiveNext()
            }
        }
    }
}
