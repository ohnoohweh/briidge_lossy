import Foundation
import Network

final class ObstacleBridgeChannelMuxTCPTransportOwner {
    typealias EventSink = (String, [String: Any]) -> Void
    typealias MuxFrameSink = ([Data]) -> Void
    typealias MetricSink = (String) -> Void
    enum TransportEvent {
        case clientAccepted(chanID: Int, spec: ObstacleBridgeChannelMuxCodec.ServiceSpec, connected: Bool)
        case clientConnected(chanID: Int, localHost: String?, localPort: Int?)
        case clientInbound(chanID: Int, bytes: Int)
        case clientOutbound(chanID: Int, bytes: Int)
        case clientClosed(chanID: Int)
        case serverConnected(chanID: Int)
        case serverInbound(chanID: Int, bytes: Int)
        case serverOutbound(chanID: Int, bytes: Int)
        case serverClosed(chanID: Int)
    }
    typealias TransportEventSink = (TransportEvent) -> Void

    private let runtime: ObstacleBridgeChannelMuxTcpRuntime
    private let queue: DispatchQueue
    private let eventPrefix: String
    private let eventSink: EventSink?
    private let muxFrameSink: MuxFrameSink
    private let metricSink: MetricSink?
    private let transportEventSink: TransportEventSink?
    private let overlayConnectedProvider: () -> Bool
    private let activateClientOnReady: Bool
    private let maxReadSize: Int
    private let openChunkReassembler = ObstacleBridgeChannelMuxCodec.ControlChunkReassembler()

    private var serverConnections: [Int: NWConnection] = [:]
    private var pendingServerOpenFrames: [Int: [Data]] = [:]
    private var startedServerChannels: Set<Int> = []
    private var clientConnections: [Int: NWConnection] = [:]
    private var activatedClientChannels: Set<Int> = []
    private var active = true

    init(
        runtime: ObstacleBridgeChannelMuxTcpRuntime = ObstacleBridgeChannelMuxTcpRuntime(),
        sessionMaxAppPayload: Int = 65535,
        queue: DispatchQueue,
        eventPrefix: String,
        eventSink: EventSink? = nil,
        muxFrameSink: @escaping MuxFrameSink,
        metricSink: MetricSink? = nil,
        transportEventSink: TransportEventSink? = nil,
        overlayConnectedProvider: @escaping () -> Bool = { true },
        activateClientOnReady: Bool = false
    ) {
        self.runtime = runtime
        self.queue = queue
        self.eventPrefix = eventPrefix
        self.eventSink = eventSink
        self.muxFrameSink = muxFrameSink
        self.metricSink = metricSink
        self.transportEventSink = transportEventSink
        self.overlayConnectedProvider = overlayConnectedProvider
        self.activateClientOnReady = activateClientOnReady
        self.maxReadSize = max(1, sessionMaxAppPayload - ObstacleBridgeChannelMuxCodec.muxHeaderSize)
    }

    var serverConnectionCount: Int {
        serverConnections.count
    }

    var clientConnectionCount: Int {
        clientConnections.count
    }

    func stop() {
        guard active else {
            return
        }
        active = false
        for connection in serverConnections.values {
            cancelConnection(connection)
        }
        for connection in clientConnections.values {
            cancelConnection(connection)
        }
        serverConnections.removeAll()
        pendingServerOpenFrames.removeAll()
        startedServerChannels.removeAll()
        clientConnections.removeAll()
        activatedClientChannels.removeAll()
    }

    func acceptLocalConnection(
        _ connection: NWConnection,
        spec: ObstacleBridgeChannelMuxCodec.ServiceSpec
    ) -> Int? {
        guard active else {
            cancelConnection(connection)
            return nil
        }
        do {
            guard let acceptSnapshot = try runtime.handleAcceptedServerConnection(
                spec: spec,
                overlayConnected: overlayConnectedProvider(),
                acceptingEnabled: true
            ) else {
                cancelConnection(connection)
                return nil
            }
            let chanID = acceptSnapshot.chanID
            serverConnections[chanID] = connection
            metricSink?("server_accepted")
            connection.stateUpdateHandler = { [weak self] state in
                self?.queue.async {
                    self?.handleServerConnectionState(state, chanID: chanID)
                }
            }
            connection.start(queue: queue)
            pendingServerOpenFrames[chanID] = acceptSnapshot.frames
            return chanID
        } catch {
            eventSink?("\(eventPrefix)_tcp_accept_failed", ["service_id": spec.svcID, "error": error.localizedDescription])
            cancelConnection(connection)
            return nil
        }
    }

    func handleInboundMuxFrame(_ frame: ObstacleBridgeChannelMuxCodec.MuxFrame) {
        guard active else {
            return
        }
        if let connection = serverConnections[frame.chanID] {
            switch frame.mtype {
            case .data:
                let snapshot = runtime.handleInboundServerData(chanID: frame.chanID, body: frame.body)
                for buffer in snapshot.writtenBuffers {
                    sendOnTCPConnection(connection, payload: buffer, chanID: frame.chanID, event: "\(eventPrefix)_tcp_server_write_failed")
                    transportEventSink?(.serverInbound(chanID: frame.chanID, bytes: buffer.count))
                }
            case .close:
                let snapshot = runtime.handleInboundServerClose(chanID: frame.chanID)
                if snapshot.localConnectionClosed {
                    serverConnections.removeValue(forKey: frame.chanID)
                    cancelConnection(connection)
                    transportEventSink?(.serverClosed(chanID: frame.chanID))
                }
            default:
                break
            }
            return
        }

        switch frame.mtype {
        case .open:
            handleInboundClientOpen(chanID: frame.chanID, payload: frame.body)
        case .openChunk:
            handleInboundClientOpenChunk(chanID: frame.chanID, payload: frame.body)
        case .data:
            let snapshot = runtime.handleInboundClientData(chanID: frame.chanID, body: frame.body)
            if let connection = clientConnections[frame.chanID] {
                for buffer in snapshot.writtenBuffers {
                    sendOnTCPConnection(connection, payload: buffer, chanID: frame.chanID, event: "\(eventPrefix)_tcp_client_write_failed")
                    transportEventSink?(.clientInbound(chanID: frame.chanID, bytes: buffer.count))
                }
            } else if snapshot.buffered || snapshot.sentImmediately {
                transportEventSink?(.clientInbound(chanID: frame.chanID, bytes: frame.body.count))
            }
        case .close:
            let snapshot = runtime.handleInboundClientClose(chanID: frame.chanID)
            if snapshot.closed, let connection = clientConnections.removeValue(forKey: frame.chanID) {
                cancelConnection(connection)
            }
            activatedClientChannels.remove(frame.chanID)
            transportEventSink?(.clientClosed(chanID: frame.chanID))
        default:
            break
        }
    }

    private func handleServerConnectionState(_ state: NWConnection.State, chanID: Int) {
        switch state {
        case .ready:
            eventSink?("\(eventPrefix)_tcp_server_connection_ready", ["chan_id": chanID])
            if !startedServerChannels.contains(chanID) {
                startedServerChannels.insert(chanID)
                receiveFromServerConnection(chanID: chanID)
                if let frames = pendingServerOpenFrames.removeValue(forKey: chanID) {
                    muxFrameSink(frames)
                }
            }
            transportEventSink?(.serverConnected(chanID: chanID))
        case .failed(let error):
            eventSink?("\(eventPrefix)_tcp_server_connection_failed", ["chan_id": chanID, "error": error.localizedDescription])
            closeServerConnection(chanID: chanID)
        case .cancelled:
            closeServerConnection(chanID: chanID)
        default:
            break
        }
    }

    private func receiveFromServerConnection(chanID: Int) {
        guard active, let connection = serverConnections[chanID] else {
            return
        }
        connection.receive(minimumIncompleteLength: 1, maximumLength: maxReadSize) { [weak self] data, _, isComplete, error in
            self?.queue.async {
                guard let self, self.active else { return }
                if let data, !data.isEmpty {
                    self.eventSink?("\(self.eventPrefix)_tcp_server_data_read", ["chan_id": chanID, "bytes": data.count])
                    do {
                        let snapshot = try self.runtime.handleLocalServerData(
                            chanID: chanID,
                            payload: data,
                            overlayConnected: self.overlayConnectedProvider()
                        )
                        self.eventSink?("\(self.eventPrefix)_tcp_server_data_mux", ["chan_id": chanID, "bytes": data.count, "frames": snapshot.frames.count, "sent": snapshot.sent])
                        self.muxFrameSink(snapshot.frames)
                        self.transportEventSink?(.serverOutbound(chanID: chanID, bytes: data.count))
                    } catch {
                        self.eventSink?("\(self.eventPrefix)_tcp_server_data_failed", ["chan_id": chanID, "error": error.localizedDescription])
                    }
                }
                if isComplete || error != nil {
                    self.eventSink?("\(self.eventPrefix)_tcp_server_receive_done", ["chan_id": chanID, "is_complete": isComplete, "has_error": error != nil])
                    self.closeServerConnection(chanID: chanID)
                    return
                }
                self.receiveFromServerConnection(chanID: chanID)
            }
        }
    }

    private func closeServerConnection(chanID: Int) {
        let connection = serverConnections.removeValue(forKey: chanID)
        pendingServerOpenFrames.removeValue(forKey: chanID)
        startedServerChannels.remove(chanID)
        do {
            let snapshot = try runtime.handleLocalServerEOF(chanID: chanID, overlayConnected: overlayConnectedProvider())
            muxFrameSink(snapshot.frames)
        } catch {
            eventSink?("\(eventPrefix)_tcp_server_close_failed", ["chan_id": chanID, "error": error.localizedDescription])
        }
        if let connection {
            cancelConnection(connection)
        }
        transportEventSink?(.serverClosed(chanID: chanID))
    }

    private func handleInboundClientOpen(chanID: Int, payload: Data) {
        guard let parsed = ObstacleBridgeChannelMuxCodec.parseOpenPayload(payload) else {
            eventSink?("\(eventPrefix)_tcp_client_open_parse_failed", ["chan_id": chanID])
            return
        }
        let snapshot = runtime.handleInboundClientOpen(chanID: chanID, payload: payload)
        if snapshot.accepted {
            transportEventSink?(.clientAccepted(chanID: chanID, spec: parsed.spec, connected: snapshot.connected))
        }
        if snapshot.accepted && snapshot.connectRequested {
            startOutboundConnection(chanID: chanID, spec: parsed.spec)
            return
        }
        if !snapshot.accepted {
            eventSink?("\(eventPrefix)_tcp_client_open_rejected", ["chan_id": chanID])
        }
    }

    private func handleInboundClientOpenChunk(chanID: Int, payload: Data) {
        guard let assembled = openChunkReassembler.consume(
            chanID: chanID,
            proto: .tcp,
            mtype: .open,
            payload: payload,
            peerID: nil
        ) else {
            return
        }
        handleInboundClientOpen(chanID: chanID, payload: assembled)
    }

    private func startOutboundConnection(chanID: Int, spec: ObstacleBridgeChannelMuxCodec.ServiceSpec) {
        guard active, clientConnections[chanID] == nil else {
            return
        }
        guard let port = NWEndpoint.Port(rawValue: UInt16(spec.rPort)) else {
            eventSink?("\(eventPrefix)_tcp_client_connect_invalid_port", ["chan_id": chanID, "port": spec.rPort])
            return
        }
        let connection = NWConnection(host: NWEndpoint.Host(spec.rHost), port: port, using: .tcp)
        clientConnections[chanID] = connection
        metricSink?("client_dialed")
        connection.stateUpdateHandler = { [weak self] state in
            self?.queue.async {
                self?.handleClientConnectionState(state, chanID: chanID, spec: spec)
            }
        }
        connection.start(queue: queue)
        if !activateClientOnReady {
            activateClientConnection(chanID: chanID, spec: spec)
        }
        receiveFromClientConnection(chanID: chanID)
    }

    private func handleClientConnectionState(_ state: NWConnection.State, chanID: Int, spec: ObstacleBridgeChannelMuxCodec.ServiceSpec) {
        switch state {
        case .ready:
            if activateClientOnReady {
                activateClientConnection(chanID: chanID, spec: spec)
            }
        case .failed(let error):
            eventSink?(
                "\(eventPrefix)_tcp_client_connection_failed",
                [
                    "chan_id": chanID,
                    "host": spec.rHost,
                    "port": spec.rPort,
                    "error": error.localizedDescription,
                ]
            )
            closeClientConnection(chanID: chanID)
        case .cancelled:
            closeClientConnection(chanID: chanID)
        default:
            break
        }
    }

    private func activateClientConnection(chanID: Int, spec: ObstacleBridgeChannelMuxCodec.ServiceSpec) {
        guard !activatedClientChannels.contains(chanID), clientConnections[chanID] != nil else {
            return
        }
        activatedClientChannels.insert(chanID)
        let connectSnapshot = runtime.handleClientConnected(
            chanID: chanID,
            peerAddrHost: spec.rHost,
            peerAddrPort: spec.rPort
        )
        transportEventSink?(.clientConnected(chanID: chanID, localHost: connectSnapshot.localAddrHost, localPort: connectSnapshot.localAddrPort))
        if let connection = clientConnections[chanID] {
            for buffer in connectSnapshot.flushedBuffers {
                sendOnTCPConnection(connection, payload: buffer, chanID: chanID, event: "\(eventPrefix)_tcp_client_flush_failed")
                transportEventSink?(.clientInbound(chanID: chanID, bytes: buffer.count))
            }
        }
    }

    private func receiveFromClientConnection(chanID: Int) {
        guard active, let connection = clientConnections[chanID] else {
            return
        }
        connection.receive(minimumIncompleteLength: 1, maximumLength: maxReadSize) { [weak self] data, _, isComplete, error in
            self?.queue.async {
                guard let self, self.active else { return }
                if let data, !data.isEmpty {
                    do {
                        if let snapshot = try self.runtime.handleLocalClientData(
                            chanID: chanID,
                            payload: data,
                            overlayConnected: self.overlayConnectedProvider()
                        ) {
                            self.muxFrameSink(snapshot.frames)
                            self.transportEventSink?(.clientOutbound(chanID: chanID, bytes: data.count))
                        }
                    } catch {
                        self.eventSink?("\(self.eventPrefix)_tcp_client_data_failed", ["chan_id": chanID, "error": error.localizedDescription])
                    }
                }
                if isComplete || error != nil {
                    self.closeClientConnection(chanID: chanID)
                    return
                }
                self.receiveFromClientConnection(chanID: chanID)
            }
        }
    }

    private func closeClientConnection(chanID: Int) {
        let connection = clientConnections.removeValue(forKey: chanID)
        do {
            let snapshot = try runtime.handleLocalClientEOF(chanID: chanID, overlayConnected: overlayConnectedProvider())
            muxFrameSink(snapshot.frames)
        } catch {
            eventSink?("\(eventPrefix)_tcp_client_close_failed", ["chan_id": chanID, "error": error.localizedDescription])
        }
        if let connection {
            cancelConnection(connection)
        }
        activatedClientChannels.remove(chanID)
        transportEventSink?(.clientClosed(chanID: chanID))
    }

    private func sendOnTCPConnection(_ connection: NWConnection, payload: Data, chanID: Int, event: String) {
        connection.send(content: payload, completion: .contentProcessed { [weak self] error in
            guard let self, let error else { return }
            self.queue.async {
                self.eventSink?(event, ["chan_id": chanID, "error": error.localizedDescription])
            }
        })
    }

    private func cancelConnection(_ connection: NWConnection) {
        connection.stateUpdateHandler = nil
        connection.cancel()
    }
}
