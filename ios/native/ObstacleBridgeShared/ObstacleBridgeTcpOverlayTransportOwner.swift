import Foundation
import Network

final class ObstacleBridgeTcpOverlayTransportOwner {
    typealias EventSink = (String, [String: Any]) -> Void

    private struct ConnectionState {
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
            [
                "protocol": proto,
                "role": role,
                "state": state,
                "chan_id": chanID,
                "svc_id": svcID,
                "service_name": serviceName,
                "source": NSNull(),
                "local": endpoint(host: localHost, port: localPort),
                "local_port": localPort ?? NSNull(),
                "remote_destination": endpoint(host: remoteHost, port: remotePort),
                "stats": stats,
            ]
        }

        private func endpoint(host: String?, port: Int?) -> Any {
            guard let host, let port else {
                return NSNull()
            }
            return ["host": host, "port": port]
        }
    }

    private let peerHost: String
    private let peerPort: Int
    private let bindHost: String
    private let bindPort: Int
    private let overlayRuntime: ObstacleBridgeTcpOverlayRuntime
    private let overlayLayerTransportAdapter: ObstacleBridgeOverlayLayerTransportAdapter?
    private let reconnectRetryDelayMS: Int
    private let queue: DispatchQueue
    private let eventSink: EventSink?
    private let serviceNameByID: [Int: String]

    private var udpRuntime = ObstacleBridgeChannelMuxUdpRuntime(instanceID: 0, connectionSeq: 0)
    private var overlayListener: NWListener?
    private var overlayConnection: NWConnection?
    private var overlayPeerID: Int?
    private var overlayConnected = false
    private var receiveBuffer = Data()
    private var udpServerConnections: [Int: NWConnection] = [:]
    private var udpClientConnections: [Int: NWConnection] = [:]
    private var tcpConnectionStates: [Int: ConnectionState] = [:]
    private var udpConnectionStates: [Int: ConnectionState] = [:]
    private var started = false
    private var reconnectAttempts = 0
    private var reconnectScheduled = false
    private var reconnectWorkItem: DispatchWorkItem?
    private lazy var tcpTransportOwner = ObstacleBridgeChannelMuxTCPTransportOwner(
        queue: queue,
        eventPrefix: "tcp_overlay",
        eventSink: { [weak self] event, fields in
            self?.eventSink?(event, fields)
        },
        muxFrameSink: { [weak self] frames in
            self?.sendMuxFrames(frames)
        },
        transportEventSink: { [weak self] event in
            self?.handleTCPTransportEvent(event)
        },
        overlayConnectedProvider: { [weak self] in
            self?.overlayConnected ?? false
        },
        activateClientOnReady: true
    )

    init(
        peerHost: String,
        peerPort: Int,
        bindHost: String = "0.0.0.0",
        bindPort: Int = 0,
        overlayRuntime: ObstacleBridgeTcpOverlayRuntime,
        reconnectRetryDelayMS: Int = 30000,
        overlayLayerTransportAdapter: ObstacleBridgeOverlayLayerTransportAdapter? = nil,
        queue: DispatchQueue = DispatchQueue(label: "ObstacleBridgeTcpOverlayTransportOwner"),
        serviceNameByID: [Int: String] = [:],
        eventSink: EventSink? = nil
    ) {
        self.peerHost = peerHost
        self.peerPort = peerPort
        self.bindHost = bindHost
        self.bindPort = max(0, bindPort)
        self.overlayRuntime = overlayRuntime
        self.reconnectRetryDelayMS = max(0, reconnectRetryDelayMS)
        self.overlayLayerTransportAdapter = overlayLayerTransportAdapter
        self.queue = queue
        self.serviceNameByID = serviceNameByID
        self.eventSink = eventSink
    }

    func start() {
        guard !started else {
            return
        }
        guard (!peerHost.isEmpty && peerPort > 0) || bindPort > 0 else {
            return
        }
        started = true
        if !peerHost.isEmpty, peerPort > 0 {
            connectOverlay()
            return
        }
        startOverlayListener()
    }

    func stop() {
        guard started else {
            return
        }
        started = false
        overlayConnected = false
        reconnectScheduled = false
        reconnectWorkItem?.cancel()
        reconnectWorkItem = nil
        overlayListener?.cancel()
        overlayListener = nil
        overlayConnection?.cancel()
        overlayConnection = nil
        overlayPeerID = nil
        tcpTransportOwner.stop()
        for connection in udpServerConnections.values {
            connection.cancel()
        }
        for connection in udpClientConnections.values {
            connection.cancel()
        }
        udpServerConnections.removeAll()
        udpClientConnections.removeAll()
        tcpConnectionStates.removeAll()
        udpConnectionStates.removeAll()
        receiveBuffer.removeAll(keepingCapacity: false)
    }

    func connectionRows() -> (tcp: [[String: Any]], udp: [[String: Any]]) {
        let tcpRows = tcpConnectionStates.values.map { $0.snapshot() }.sorted { lhs, rhs in
            (lhs["chan_id"] as? Int ?? -1) < (rhs["chan_id"] as? Int ?? -1)
        }
        let udpRows = udpConnectionStates.values.map { $0.snapshot() }.sorted { lhs, rhs in
            (lhs["chan_id"] as? Int ?? -1) < (rhs["chan_id"] as? Int ?? -1)
        }
        return (tcpRows, udpRows)
    }

    func transportSnapshot() -> [String: Any] {
        [
            "overlay_connected": overlayConnected,
            "overlay_bind_host": bindHost,
            "overlay_bind_port": bindPort,
            "overlay_host": peerHost,
            "overlay_port": peerPort,
            "reconnect_retry_delay_ms": reconnectRetryDelayMS,
            "reconnect_attempts": reconnectAttempts,
            "reconnect_scheduled": reconnectScheduled,
            "server_tcp_channels": tcpTransportOwner.serverConnectionCount,
            "client_tcp_channels": tcpConnectionStates.count,
            "server_udp_channels": udpServerConnections.count,
            "client_udp_channels": udpConnectionStates.count,
        ]
    }

    @discardableResult
    func acceptLocalTCPConnection(
        _ connection: NWConnection,
        spec: ObstacleBridgeChannelMuxCodec.ServiceSpec,
        listenerHost: String,
        listenerPort: Int
    ) -> Bool {
        if let chanID = tcpTransportOwner.acceptLocalConnection(connection, spec: spec) {
            tcpConnectionStates[chanID] = ConnectionState(
                proto: "tcp",
                role: "server",
                chanID: chanID,
                svcID: spec.svcID,
                serviceName: serviceName(spec),
                remoteHost: spec.rHost,
                remotePort: spec.rPort,
                state: "connecting",
                localHost: listenerHost,
                localPort: listenerPort,
                stats: ["rx_msgs": 0, "tx_msgs": 0, "rx_bytes": 0, "tx_bytes": 0]
            )
            return true
        }
        connection.cancel()
        return false
    }

    @discardableResult
    func acceptLocalUDPConnection(
        _ connection: NWConnection,
        spec: ObstacleBridgeChannelMuxCodec.ServiceSpec,
        listenerHost: String,
        listenerPort: Int,
        serviceKey: String
    ) -> Bool {
        connection.stateUpdateHandler = { [weak self] state in
            self?.queue.async {
                self?.handleUDPServerConnectionState(state)
            }
        }
        connection.start(queue: queue)
        receiveFromUDPServerConnection(
            connection: connection,
            spec: spec,
            listenerHost: listenerHost,
            listenerPort: listenerPort,
            serviceKey: serviceKey
        )
        return true
    }

    private func connectOverlay() {
        guard started else {
            return
        }
        guard let port = NWEndpoint.Port(rawValue: UInt16(peerPort)) else {
            eventSink?("tcp_overlay_invalid_peer_port", ["port": peerPort])
            return
        }
        reconnectScheduled = false
        reconnectWorkItem?.cancel()
        reconnectWorkItem = nil
        reconnectAttempts += 1
        let connection = NWConnection(host: NWEndpoint.Host(peerHost), port: port, using: .tcp)
        overlayConnection = connection
        connection.stateUpdateHandler = { [weak self] state in
            self?.queue.async {
                self?.handleOverlayState(state)
            }
        }
        connection.start(queue: queue)
    }

    private func startOverlayListener() {
        guard started, bindPort > 0, let port = NWEndpoint.Port(rawValue: UInt16(bindPort)) else {
            return
        }
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        params.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(bindHost), port: port)
        do {
            let listener = try NWListener(using: params)
            listener.stateUpdateHandler = { [weak self] state in
                self?.queue.async {
                    self?.handleOverlayListenerState(state)
                }
            }
            listener.newConnectionHandler = { [weak self] connection in
                self?.queue.async {
                    self?.acceptOverlayConnection(connection)
                }
            }
            overlayListener = listener
            listener.start(queue: queue)
        } catch {
            eventSink?("tcp_overlay_listener_failed", ["error": error.localizedDescription, "host": bindHost, "port": bindPort])
        }
    }

    private func handleOverlayListenerState(_ state: NWListener.State) {
        if case .failed(let error) = state {
            eventSink?("tcp_overlay_listener_failed", ["error": error.localizedDescription, "host": bindHost, "port": bindPort])
        }
    }

    private func acceptOverlayConnection(_ connection: NWConnection) {
        guard started else {
            connection.cancel()
            return
        }
        if let existing = overlayConnection {
            if let peerID = overlayPeerID {
                let snapshot = overlayRuntime.closeServerPeer(peerID: peerID)
                overlayConnected = snapshot.overlayConnected
                overlayPeerID = nil
            }
            existing.cancel()
        }
        overlayConnection = connection
        connection.stateUpdateHandler = { [weak self, weak connection] state in
            guard let self, let connection else {
                return
            }
            self.queue.async {
                self.handleAcceptedOverlayState(state, connection: connection)
            }
        }
        connection.start(queue: queue)
    }

    private func handleAcceptedOverlayState(_ state: NWConnection.State, connection: NWConnection) {
        guard overlayConnection === connection else {
            return
        }
        switch state {
        case .ready:
            let endpoint = Self.endpointDescription(connection.endpoint)
            let snapshot = overlayRuntime.acceptServerPeer(peerHost: endpoint.host, peerPort: endpoint.port, socketPresent: true)
            overlayPeerID = snapshot.peerID
            overlayConnected = snapshot.overlayConnected
            receiveFromOverlay()
        case .failed(let error):
            eventSink?("tcp_overlay_server_connection_failed", ["error": error.localizedDescription])
            closeAcceptedOverlayConnection(connection)
        case .cancelled:
            closeAcceptedOverlayConnection(connection)
        default:
            break
        }
    }

    private func closeAcceptedOverlayConnection(_ connection: NWConnection) {
        guard overlayConnection === connection else {
            return
        }
        overlayConnection = nil
        connection.cancel()
        if let peerID = overlayPeerID {
            let snapshot = overlayRuntime.closeServerPeer(peerID: peerID)
            overlayConnected = snapshot.overlayConnected
            overlayPeerID = nil
        } else {
            overlayConnected = false
        }
    }

    private func handleOverlayState(_ state: NWConnection.State) {
        switch state {
        case .ready:
            overlayConnected = true
            reconnectScheduled = false
            let snapshot = overlayRuntime.connect(host: peerHost, port: peerPort, socketPresent: true)
            for payload in snapshot.flushedBuffers {
                sendRawOverlayWire(payload)
            }
            receiveFromOverlay()
        case .failed(let error):
            overlayConnected = false
            overlayConnection = nil
            eventSink?("tcp_overlay_connection_failed", ["error": error.localizedDescription])
            scheduleReconnect()
        case .waiting(let error):
            overlayConnected = false
            overlayConnection = nil
            eventSink?("tcp_overlay_connection_waiting", ["error": error.localizedDescription])
            scheduleReconnect()
        case .cancelled:
            overlayConnected = false
            overlayConnection = nil
            scheduleReconnect()
        default:
            break
        }
    }

    private func scheduleReconnect() {
        guard started, !peerHost.isEmpty, peerPort > 0 else {
            return
        }
        reconnectWorkItem?.cancel()
        let workItem = DispatchWorkItem { [weak self] in
            guard let self else {
                return
            }
            self.reconnectScheduled = false
            self.reconnectWorkItem = nil
            self.connectOverlay()
        }
        reconnectWorkItem = workItem
        reconnectScheduled = true
        queue.asyncAfter(deadline: .now() + .milliseconds(reconnectRetryDelayMS), execute: workItem)
    }

    private func receiveFromOverlay() {
        guard started, let connection = overlayConnection else {
            return
        }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            self?.queue.async {
                guard let self, self.started else { return }
                guard self.overlayConnection === connection else { return }
                if let data, !data.isEmpty {
                    self.receiveBuffer.append(data)
                    let snapshot = self.overlayRuntime.handleInboundBytes(self.receiveBuffer)
                    if snapshot.consumedBytes > 0 {
                        self.receiveBuffer.removeSubrange(0..<snapshot.consumedBytes)
                    }
                    for payload in snapshot.completedPayloads {
                        self.handleOverlayTransportPayload(payload)
                    }
                }
                if isComplete || error != nil {
                    if self.peerHost.isEmpty {
                        self.closeAcceptedOverlayConnection(connection)
                    } else {
                        self.overlayConnected = false
                    }
                    return
                }
                self.receiveFromOverlay()
            }
        }
    }

    private func handleOverlayTransportPayload(_ payload: Data) {
        if let adapter = overlayLayerTransportAdapter {
            let snapshot = adapter.handleInboundFrame(payload)
            for frame in snapshot.emittedFrames {
                sendOverlayTransportPayload(frame)
            }
            for delivered in snapshot.deliveredPayloads {
                handleOverlayPayload(delivered)
            }
            return
        }
        handleOverlayPayload(payload)
    }

    private func handleOverlayPayload(_ payload: Data) {
        guard let frame = ObstacleBridgeChannelMuxCodec.unpackMux(payload) else {
            return
        }
        switch frame.proto {
        case .tcp:
            handleInboundTCPMuxFrame(frame)
        case .udp:
            handleInboundUDPMuxFrame(frame)
        default:
            break
        }
    }

    private func handleInboundTCPMuxFrame(_ frame: ObstacleBridgeChannelMuxCodec.MuxFrame) {
        tcpTransportOwner.handleInboundMuxFrame(frame)
    }

    private func handleInboundUDPMuxFrame(_ frame: ObstacleBridgeChannelMuxCodec.MuxFrame) {
        if let connection = udpServerConnections[frame.chanID] {
            switch frame.mtype {
            case .data:
                let snapshot = udpRuntime.handleInboundServerData(chanID: frame.chanID, body: frame.body)
                if let packet = snapshot.packet, snapshot.delivered {
                    sendOnUDPConnection(connection, payload: packet, chanID: frame.chanID)
                    recordInbound(proto: "udp", chanID: frame.chanID, bytes: packet.count)
                }
            case .dataFrag:
                let snapshot = udpRuntime.handleInboundServerFragment(chanID: frame.chanID, payload: frame.body)
                if let packet = snapshot.packet, snapshot.delivered {
                    sendOnUDPConnection(connection, payload: packet, chanID: frame.chanID)
                    recordInbound(proto: "udp", chanID: frame.chanID, bytes: packet.count)
                }
            case .close:
                let snapshot = udpRuntime.handleInboundClose(chanID: frame.chanID)
                if snapshot.closed {
                    udpServerConnections.removeValue(forKey: frame.chanID)
                    connection.cancel()
                    udpConnectionStates.removeValue(forKey: frame.chanID)
                }
            default:
                break
            }
            return
        }
        switch frame.mtype {
        case .open:
            handleInboundUDPClientOpen(chanID: frame.chanID, payload: frame.body)
        case .data:
            let snapshot = udpRuntime.handleInboundClientData(chanID: frame.chanID, body: frame.body)
            if let connection = udpClientConnections[frame.chanID] {
                for packet in snapshot.sentPackets {
                    sendOnUDPConnection(connection, payload: packet, chanID: frame.chanID)
                    recordInbound(proto: "udp", chanID: frame.chanID, bytes: packet.count)
                }
            }
        case .dataFrag:
            let snapshot = udpRuntime.handleInboundClientFragment(chanID: frame.chanID, payload: frame.body)
            if let connection = udpClientConnections[frame.chanID] {
                for packet in snapshot.sentPackets {
                    sendOnUDPConnection(connection, payload: packet, chanID: frame.chanID)
                    recordInbound(proto: "udp", chanID: frame.chanID, bytes: packet.count)
                }
            }
        case .close:
            let snapshot = udpRuntime.handleInboundClientClose(chanID: frame.chanID)
            if snapshot.closed, let connection = udpClientConnections.removeValue(forKey: frame.chanID) {
                connection.cancel()
            }
            udpConnectionStates.removeValue(forKey: frame.chanID)
        default:
            break
        }
    }

    private func handleInboundUDPClientOpen(chanID: Int, payload: Data) {
        guard let parsed = ObstacleBridgeChannelMuxCodec.parseOpenPayload(payload) else {
            return
        }
        let snapshot = udpRuntime.handleInboundClientOpen(chanID: chanID, payload: payload)
        guard snapshot.accepted else {
            return
        }
        udpConnectionStates[chanID] = ConnectionState(
            proto: "udp",
            role: "client",
            chanID: chanID,
            svcID: parsed.spec.svcID,
            serviceName: serviceName(parsed.spec),
            remoteHost: parsed.spec.rHost,
            remotePort: parsed.spec.rPort,
            state: snapshot.connected ? "connected" : "connecting",
            localHost: nil,
            localPort: nil,
            stats: ["rx_msgs": 0, "tx_msgs": 0, "rx_bytes": 0, "tx_bytes": 0]
        )
        if snapshot.connectRequested {
            startOutboundUDPConnection(chanID: chanID, spec: parsed.spec)
        }
    }

    private func startOutboundUDPConnection(chanID: Int, spec: ObstacleBridgeChannelMuxCodec.ServiceSpec) {
        guard udpClientConnections[chanID] == nil,
              let port = NWEndpoint.Port(rawValue: UInt16(spec.rPort))
        else {
            return
        }
        let connection = NWConnection(host: NWEndpoint.Host(spec.rHost), port: port, using: .udp)
        udpClientConnections[chanID] = connection
        connection.stateUpdateHandler = { [weak self] state in
            self?.queue.async {
                self?.handleUDPClientConnectionState(state, chanID: chanID, spec: spec)
            }
        }
        connection.start(queue: queue)
        let snapshot = udpRuntime.handleClientConnected(
            chanID: chanID,
            peerAddrHost: spec.rHost,
            peerAddrPort: spec.rPort
        )
        updateConnectedState(proto: "udp", chanID: chanID, localHost: snapshot.localAddrHost, localPort: snapshot.localAddrPort)
        for packet in snapshot.flushedPackets {
            sendOnUDPConnection(connection, payload: packet, chanID: chanID)
            recordInbound(proto: "udp", chanID: chanID, bytes: packet.count)
        }
        receiveFromUDPClientConnection(chanID: chanID)
    }

    private func handleUDPClientConnectionState(_ state: NWConnection.State, chanID: Int, spec: ObstacleBridgeChannelMuxCodec.ServiceSpec) {
        switch state {
        case .ready:
            updateConnectedState(proto: "udp", chanID: chanID, localHost: nil, localPort: nil)
        case .failed(let error):
            eventSink?("tcp_overlay_udp_client_failed", ["chan_id": chanID, "error": error.localizedDescription, "host": spec.rHost, "port": spec.rPort])
            closeUDPClientConnection(chanID: chanID)
        case .cancelled:
            closeUDPClientConnection(chanID: chanID)
        default:
            break
        }
    }

    private func receiveFromUDPClientConnection(chanID: Int) {
        guard started, let connection = udpClientConnections[chanID] else {
            return
        }
        connection.receiveMessage { [weak self] data, _, _, error in
            self?.queue.async {
                guard let self, self.started else { return }
                if let data, !data.isEmpty,
                   let snapshot = try? self.udpRuntime.handleLocalClientDatagram(chanID: chanID, payload: data) {
                    self.sendMuxFrames(snapshot.frames)
                    self.recordOutbound(proto: "udp", chanID: chanID, bytes: data.count)
                }
                if error != nil {
                    self.closeUDPClientConnection(chanID: chanID)
                    return
                }
                self.receiveFromUDPClientConnection(chanID: chanID)
            }
        }
    }

    private func closeUDPClientConnection(chanID: Int) {
        let connection = udpClientConnections.removeValue(forKey: chanID)
        connection?.cancel()
        udpConnectionStates.removeValue(forKey: chanID)
    }

    private func sendMuxFrames(_ muxFrames: [Data]) {
        for frame in muxFrames {
            if let adapter = overlayLayerTransportAdapter {
                do {
                    let snapshot = try adapter.handleOutboundPayload(frame)
                    for secureFrame in snapshot.emittedFrames {
                        sendOverlayTransportPayload(secureFrame)
                    }
                } catch {
                    eventSink?("tcp_overlay_overlay_layer_send_failed", ["error": error.localizedDescription, "packet_bytes": frame.count])
                }
            } else {
                sendOverlayTransportPayload(frame)
            }
        }
    }

    private func sendOverlayTransportPayload(_ payload: Data) {
        let snapshot = overlayRuntime.sendApp(
            payload: payload,
            writerPresent: overlayConnected && overlayConnection != nil,
            peerConfigured: !peerHost.isEmpty && peerPort > 0,
            now: Date().timeIntervalSince1970
        )
        for wire in snapshot.writtenBuffers {
            sendRawOverlayWire(wire)
        }
    }

    private func sendRawOverlayWire(_ payload: Data) {
        overlayConnection?.send(content: payload, completion: .contentProcessed { _ in })
    }

    private func sendOnUDPConnection(_ connection: NWConnection, payload: Data, chanID: Int) {
        connection.send(content: payload, completion: .contentProcessed { [weak self] error in
            guard let self, let error else { return }
            self.queue.async {
                self.eventSink?("tcp_overlay_udp_client_write_failed", ["chan_id": chanID, "error": error.localizedDescription])
            }
        })
    }

    private func updateConnectedState(proto: String, chanID: Int, localHost: String?, localPort: Int?) {
        switch proto {
        case "tcp":
            guard var state = tcpConnectionStates[chanID] else { return }
            state.state = "connected"
            state.localHost = localHost
            state.localPort = localPort
            tcpConnectionStates[chanID] = state
        case "udp":
            guard var state = udpConnectionStates[chanID] else { return }
            state.state = "connected"
            state.localHost = localHost
            state.localPort = localPort
            udpConnectionStates[chanID] = state
        default:
            break
        }
    }

    private func handleUDPServerConnectionState(_ state: NWConnection.State) {
        if case .failed(let error) = state {
            eventSink?("tcp_overlay_udp_server_connection_failed", ["error": error.localizedDescription])
        }
    }

    private func receiveFromUDPServerConnection(
        connection: NWConnection,
        spec: ObstacleBridgeChannelMuxCodec.ServiceSpec,
        listenerHost: String,
        listenerPort: Int,
        serviceKey: String
    ) {
        guard started else {
            return
        }
        connection.receiveMessage { [weak self] data, _, _, error in
            self?.queue.async {
                guard let self, self.started else { return }
                if let data, !data.isEmpty {
                    let endpoint = Self.endpointDescription(connection.endpoint)
                    if let snapshot = try? self.udpRuntime.handleLocalServerDatagram(
                        spec: spec,
                        serviceKey: serviceKey,
                        payload: data,
                        addrHost: endpoint.host,
                        addrPort: endpoint.port,
                        overlayConnected: self.overlayConnected,
                        acceptingEnabled: true
                    ) {
                        self.udpServerConnections[snapshot.chanID] = connection
                        var state = self.udpConnectionStates[snapshot.chanID] ?? ConnectionState(
                            proto: "udp",
                            role: "server",
                            chanID: snapshot.chanID,
                            svcID: spec.svcID,
                            serviceName: self.serviceName(spec),
                            remoteHost: spec.rHost,
                            remotePort: spec.rPort,
                            state: "connected",
                            localHost: listenerHost,
                            localPort: listenerPort,
                            stats: ["rx_msgs": 0, "tx_msgs": 0, "rx_bytes": 0, "tx_bytes": 0]
                        )
                        state.state = "connected"
                        self.udpConnectionStates[snapshot.chanID] = state
                        self.sendMuxFrames(snapshot.frames)
                        self.recordOutbound(proto: "udp", chanID: snapshot.chanID, bytes: data.count)
                    }
                }
                if error != nil {
                    if let chanID = self.channelID(for: connection) {
                        let snapshot = self.udpRuntime.handleInboundClose(chanID: chanID)
                        if snapshot.closed {
                            self.udpServerConnections.removeValue(forKey: chanID)
                            self.udpConnectionStates.removeValue(forKey: chanID)
                        }
                    }
                    connection.cancel()
                    return
                }
                self.receiveFromUDPServerConnection(
                    connection: connection,
                    spec: spec,
                    listenerHost: listenerHost,
                    listenerPort: listenerPort,
                    serviceKey: serviceKey
                )
            }
        }
    }

    private func channelID(for connection: NWConnection) -> Int? {
        let key = ObjectIdentifier(connection)
        return udpServerConnections.first(where: { ObjectIdentifier($0.value) == key })?.key
    }

    private static func endpointDescription(_ endpoint: NWEndpoint) -> (host: String, port: Int) {
        if case let .hostPort(host, port) = endpoint {
            return (host.debugDescription, Int(port.rawValue))
        }
        return ("127.0.0.1", 0)
    }

    private func recordInbound(proto: String, chanID: Int, bytes: Int) {
        updateStats(proto: proto, chanID: chanID, keyMessages: "rx_msgs", keyBytes: "rx_bytes", bytes: bytes)
    }

    private func recordOutbound(proto: String, chanID: Int, bytes: Int) {
        updateStats(proto: proto, chanID: chanID, keyMessages: "tx_msgs", keyBytes: "tx_bytes", bytes: bytes)
    }

    private func updateStats(proto: String, chanID: Int, keyMessages: String, keyBytes: String, bytes: Int) {
        switch proto {
        case "tcp":
            guard var state = tcpConnectionStates[chanID] else { return }
            state.stats[keyMessages, default: 0] += 1
            state.stats[keyBytes, default: 0] += bytes
            tcpConnectionStates[chanID] = state
        case "udp":
            guard var state = udpConnectionStates[chanID] else { return }
            state.stats[keyMessages, default: 0] += 1
            state.stats[keyBytes, default: 0] += bytes
            udpConnectionStates[chanID] = state
        default:
            break
        }
    }

    private func serviceName(_ spec: ObstacleBridgeChannelMuxCodec.ServiceSpec) -> String {
        if let name = serviceNameByID[spec.svcID], !name.isEmpty {
            return name
        }
        return spec.name ?? ""
    }

    private func handleTCPTransportEvent(_ event: ObstacleBridgeChannelMuxTCPTransportOwner.TransportEvent) {
        switch event {
        case .clientAccepted(let chanID, let spec, let connected):
            tcpConnectionStates[chanID] = ConnectionState(
                proto: "tcp",
                role: "client",
                chanID: chanID,
                svcID: spec.svcID,
                serviceName: serviceName(spec),
                remoteHost: spec.rHost,
                remotePort: spec.rPort,
                state: connected ? "connected" : "connecting",
                localHost: nil,
                localPort: nil,
                stats: ["rx_msgs": 0, "tx_msgs": 0, "rx_bytes": 0, "tx_bytes": 0]
            )
        case .clientConnected(let chanID, let localHost, let localPort):
            updateConnectedState(proto: "tcp", chanID: chanID, localHost: localHost, localPort: localPort)
        case .clientInbound(let chanID, let bytes):
            recordInbound(proto: "tcp", chanID: chanID, bytes: bytes)
        case .clientOutbound(let chanID, let bytes):
            recordOutbound(proto: "tcp", chanID: chanID, bytes: bytes)
        case .clientClosed(let chanID):
            tcpConnectionStates.removeValue(forKey: chanID)
        case .serverConnected(let chanID):
            if var connectionState = tcpConnectionStates[chanID] {
                connectionState.state = "connected"
                tcpConnectionStates[chanID] = connectionState
            }
        case .serverInbound(let chanID, let bytes):
            recordInbound(proto: "tcp", chanID: chanID, bytes: bytes)
        case .serverOutbound(let chanID, let bytes):
            recordOutbound(proto: "tcp", chanID: chanID, bytes: bytes)
        case .serverClosed(let chanID):
            tcpConnectionStates.removeValue(forKey: chanID)
        }
    }
}