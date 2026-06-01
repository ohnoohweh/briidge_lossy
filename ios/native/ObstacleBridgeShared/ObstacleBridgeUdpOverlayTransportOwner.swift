import Foundation
import Network
import Darwin

final class ObstacleBridgeUdpOverlayTransportOwner {
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

    private struct ResolvedAddress {
        let family: Int32
        let storage: Data
        let length: socklen_t
        let host: String
        let port: Int
    }

    private let bindHost: String
    private let bindPort: Int
    private let configuredPeerHost: String?
    private let configuredPeerPort: Int?
    private let overlayLayerTransportAdapter: ObstacleBridgeOverlayLayerTransportAdapter?
    private let startupMuxFrames: [Data]
    private let queue: DispatchQueue
    private let eventSink: EventSink?
    private let serviceNameByID: [Int: String]

    private var udpRuntime = ObstacleBridgeChannelMuxUdpRuntime(instanceID: 0, connectionSeq: 0)
    private let overlayRuntime = ObstacleBridgeUdpOverlayPeerRuntime()
    private lazy var tcpTransportOwner = ObstacleBridgeChannelMuxTCPTransportOwner(
        queue: queue,
        eventPrefix: "udp_overlay",
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

    private var socketFD: Int32 = -1
    private var fixedPeerAddress: ResolvedAddress?
    private var currentPeerAddress: ResolvedAddress?
    private var readSource: DispatchSourceRead?
    private var controlTimer: DispatchSourceTimer?
    private var retransmitTimer: DispatchSourceTimer?
    private var udpServerConnections: [Int: NWConnection] = [:]
    private var udpClientConnections: [Int: NWConnection] = [:]
    private var udpConnectionStates: [Int: ConnectionState] = [:]
    private var tcpConnectionStates: [Int: ConnectionState] = [:]
    private var started = false
    private var secureLinkHandshakePrimed = false
    private var startupMuxFramesSent = false

    init(
        bindHost: String,
        bindPort: Int,
        peerHost: String? = nil,
        peerPort: Int? = nil,
        overlayLayerTransportAdapter: ObstacleBridgeOverlayLayerTransportAdapter? = nil,
        startupMuxFrames: [Data] = [],
        queue: DispatchQueue = DispatchQueue(label: "ObstacleBridgeUdpOverlayTransportOwner"),
        serviceNameByID: [Int: String] = [:],
        eventSink: EventSink? = nil
    ) {
        self.bindHost = bindHost
        self.bindPort = bindPort
        let trimmedPeerHost = peerHost?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.configuredPeerHost = (trimmedPeerHost?.isEmpty == false) ? trimmedPeerHost : nil
        self.configuredPeerPort = peerPort
        self.overlayLayerTransportAdapter = overlayLayerTransportAdapter
        self.startupMuxFrames = startupMuxFrames
        self.queue = queue
        self.serviceNameByID = serviceNameByID
        self.eventSink = eventSink
    }

    var overlayConnected: Bool {
        overlayRuntime.establishedNS != 0 && currentPeerAddress != nil
    }

    func start() throws {
        guard !started else {
            return
        }
        let socket = try Self.makeBoundSocket(
            bindHost: bindHost,
            bindPort: bindPort,
            peerHost: configuredPeerHost,
            peerPort: configuredPeerPort
        )
        socketFD = socket.socketFD
        fixedPeerAddress = socket.peerAddress
        currentPeerAddress = socket.peerAddress
        started = true

        let source = DispatchSource.makeReadSource(fileDescriptor: socketFD, queue: queue)
        source.setEventHandler { [weak self] in
            self?.drainSocket()
        }
        readSource = source
        source.resume()

        startOverlayTimers()
        if currentPeerAddress != nil {
            sendInitialIdleProbe()
        }
    }

    func stop() {
        guard started else {
            return
        }
        started = false
        controlTimer?.cancel()
        controlTimer = nil
        retransmitTimer?.cancel()
        retransmitTimer = nil
        readSource?.cancel()
        readSource = nil
        tcpTransportOwner.stop()
        for connection in udpServerConnections.values {
            cancelConnection(connection)
        }
        for connection in udpClientConnections.values {
            cancelConnection(connection)
        }
        udpServerConnections.removeAll()
        udpClientConnections.removeAll()
        udpConnectionStates.removeAll()
        tcpConnectionStates.removeAll()
        currentPeerAddress = fixedPeerAddress
        secureLinkHandshakePrimed = false
        startupMuxFramesSent = false
        if socketFD >= 0 {
            Darwin.close(socketFD)
            socketFD = -1
        }
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
            "overlay_peer_host": currentPeerAddress?.host ?? NSNull(),
            "overlay_peer_port": currentPeerAddress?.port ?? NSNull(),
            "fixed_peer_host": configuredPeerHost ?? NSNull(),
            "fixed_peer_port": configuredPeerPort ?? NSNull(),
            "server_tcp_channels": tcpTransportOwner.serverConnectionCount,
            "client_tcp_channels": tcpConnectionStates.count,
            "server_udp_channels": udpServerConnections.count,
            "client_udp_channels": udpConnectionStates.count,
            "established_ns": overlayRuntime.establishedNS,
            "last_rx_wall_ns": overlayRuntime.lastRxWallNS,
            "rtt_est_ms": overlayRuntime.rttEstMS,
            "transmit_delay_est_ms": overlayRuntime.transmitDelayEstMS,
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
        cancelConnection(connection)
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

    private func startOverlayTimers() {
        let control = DispatchSource.makeTimerSource(queue: queue)
        control.schedule(deadline: .now() + .milliseconds(25), repeating: .milliseconds(25))
        control.setEventHandler { [weak self] in
            self?.handleOverlayControlTimer()
        }
        control.resume()
        controlTimer = control

        let retransmit = DispatchSource.makeTimerSource(queue: queue)
        retransmit.schedule(deadline: .now() + .milliseconds(25), repeating: .milliseconds(25))
        retransmit.setEventHandler { [weak self] in
            self?.handleOverlayRetransmitTimer()
        }
        retransmit.resume()
        retransmitTimer = retransmit
    }

    private func sendInitialIdleProbe() {
        do {
            let frame = try ObstacleBridgeUdpOverlayCodec.buildProtocolFrame(
                ptype: ObstacleBridgeUdpOverlayCodec.ptypeIdle,
                payload: Data(),
                txNS: monotonicNowNS(),
                echoNS: 0
            )
            sendDatagram(frame)
        } catch {
            eventSink?("udp_overlay_idle_probe_failed", ["error": error.localizedDescription])
        }
    }

    private func handleOverlayControlTimer() {
        guard started else {
            return
        }
        let nowNS = monotonicNowNS()
        let snapshot = overlayRuntime.handleControlTimerTick(nowNS: nowNS, sendPortPresent: currentPeerAddress != nil)
        guard snapshot.controlShouldEmit else {
            return
        }
        do {
            let control = try overlayRuntime.buildOutboundControl(nowNS: nowNS, echoNS: currentEchoNS(nowNS))
            sendDatagram(control.frame)
        } catch {
            eventSink?("udp_overlay_control_timer_failed", ["error": error.localizedDescription])
        }
    }

    private func handleOverlayRetransmitTimer() {
        guard started else {
            return
        }
        do {
            let snapshot = try overlayRuntime.handleRetransmitTimerTick(nowNS: monotonicNowNS(), sendPortPresent: currentPeerAddress != nil)
            for frame in snapshot.emittedFrames {
                sendDatagram(frame)
            }
        } catch {
            eventSink?("udp_overlay_retransmit_timer_failed", ["error": error.localizedDescription])
        }
    }

    private func drainSocket() {
        guard started else {
            return
        }
        var buffer = [UInt8](repeating: 0, count: 65535)
        while started {
            var fromStorage = sockaddr_storage()
            var fromLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let received = withUnsafeMutablePointer(to: &fromStorage) { fromPtr -> Int in
                fromPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                    recvfrom(socketFD, &buffer, buffer.count, 0, sockaddrPtr, &fromLength)
                }
            }
            if received > 0 {
                if let inboundPeer = Self.resolvedAddress(from: fromStorage, length: fromLength) {
                    if fixedPeerAddress == nil {
                        currentPeerAddress = inboundPeer
                    }
                }
                handleOverlayDatagram(Data(buffer[0..<received]))
                continue
            }
            if received == 0 {
                break
            }
            if errno == EAGAIN || errno == EWOULDBLOCK {
                break
            }
            eventSink?("udp_overlay_recv_failed", ["errno": errno])
            break
        }
    }

    private func handleOverlayDatagram(_ datagram: Data) {
        let wasConnected = overlayConnected
        guard let frame = ObstacleBridgeUdpOverlayCodec.parseProtocolFrame(datagram) else {
            return
        }
        let nowNS = monotonicNowNS()
        switch frame.ptype {
        case ObstacleBridgeUdpOverlayCodec.ptypeData:
            guard let snapshot = overlayRuntime.handleInboundDataFrame(
                frame: datagram,
                nowNS: nowNS,
                txNS: frame.txNS,
                echoNS: frame.echoNS,
                sendPortPresent: currentPeerAddress != nil
            ) else {
                return
            }
            if !snapshot.controlReasons.isEmpty {
                do {
                    let control = try overlayRuntime.buildOutboundControl(nowNS: nowNS, echoNS: currentEchoNS(nowNS))
                    sendDatagram(control.frame)
                } catch {
                    eventSink?("udp_overlay_data_control_emit_failed", ["error": error.localizedDescription])
                }
            }
            routeOverlayPayloads(snapshot.completedPayloads)
        case ObstacleBridgeUdpOverlayCodec.ptypeControl:
            guard let control = ObstacleBridgeUdpOverlayCodec.parseControlFrame(datagram) else {
                return
            }
            do {
                let snapshot = try overlayRuntime.handleInboundControlPacket(
                    nowNS: nowNS,
                    packetLastInOrder: control.lastInOrderRX,
                    packetHighest: control.highestRX,
                    packetMissed: control.missed,
                    sendPortPresent: currentPeerAddress != nil
                )
                for emitted in snapshot.emittedFrames {
                    sendDatagram(emitted)
                }
                if snapshot.controlShouldEmit {
                    let outbound = try overlayRuntime.buildOutboundControl(nowNS: nowNS, echoNS: currentEchoNS(nowNS))
                    sendDatagram(outbound.frame)
                }
            } catch {
                eventSink?("udp_overlay_inbound_control_failed", ["error": error.localizedDescription])
            }
        case ObstacleBridgeUdpOverlayCodec.ptypeIdle:
            do {
                let snapshot = try overlayRuntime.handleInboundIdleFrame(
                    nowNS: nowNS,
                    txNS: frame.txNS,
                    echoNS: frame.echoNS,
                    sendPortPresent: currentPeerAddress != nil
                )
                if let reflected = snapshot.reflectedFrame {
                    sendDatagram(reflected)
                }
            } catch {
                eventSink?("udp_overlay_inbound_idle_failed", ["error": error.localizedDescription])
            }
        default:
            break
        }
        if !wasConnected && overlayConnected {
            maybePrimeSecureLinkHandshake()
            maybeSendStartupMuxFrames()
        }
    }

    private func routeOverlayPayloads(_ payloads: [Data]) {
        guard !payloads.isEmpty else {
            return
        }
        for payload in payloads {
            if let adapter = overlayLayerTransportAdapter {
                let snapshot = adapter.handleInboundFrame(payload)
                for emitted in snapshot.emittedFrames {
                    sendOverlayTransportPayload(emitted)
                }
                for delivered in snapshot.deliveredPayloads {
                    handleOverlayPayload(delivered)
                }
                continue
            }
            handleOverlayPayload(payload)
        }
    }

    private func maybePrimeSecureLinkHandshake() {
        guard overlayConnected, !secureLinkHandshakePrimed, let adapter = overlayLayerTransportAdapter else {
            return
        }
        do {
            let snapshot = try adapter.handleTransportConnected()
            secureLinkHandshakePrimed = true
            for frame in snapshot.emittedFrames {
                sendOverlayTransportPayload(frame)
            }
        } catch {
            eventSink?("udp_overlay_secure_link_prime_failed", ["error": error.localizedDescription])
        }
    }

    private func maybeSendStartupMuxFrames() {
        guard overlayConnected, !startupMuxFramesSent, !startupMuxFrames.isEmpty else {
            return
        }
        startupMuxFramesSent = true
        sendMuxFrames(startupMuxFrames)
    }

    private func handleOverlayPayload(_ payload: Data) {
        guard let frame = ObstacleBridgeChannelMuxCodec.unpackMux(payload) else {
            return
        }
        switch frame.proto {
        case .tcp:
            tcpTransportOwner.handleInboundMuxFrame(frame)
        case .udp:
            handleInboundUDPMuxFrame(frame)
        default:
            break
        }
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
            eventSink?("udp_overlay_udp_client_failed", ["chan_id": chanID, "error": error.localizedDescription, "host": spec.rHost, "port": spec.rPort])
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

    private func handleUDPServerConnectionState(_ state: NWConnection.State) {
        if case .failed(let error) = state {
            eventSink?("udp_overlay_udp_server_connection_failed", ["error": error.localizedDescription])
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

    private func sendMuxFrames(_ muxFrames: [Data]) {
        for muxFrame in muxFrames {
            if let adapter = overlayLayerTransportAdapter {
                do {
                    let snapshot = try adapter.handleOutboundPayload(muxFrame)
                    for secureFrame in snapshot.emittedFrames {
                        sendOverlayTransportPayload(secureFrame)
                    }
                } catch {
                    eventSink?("udp_overlay_overlay_layer_send_failed", ["error": error.localizedDescription, "packet_bytes": muxFrame.count])
                }
            } else {
                sendOverlayTransportPayload(muxFrame)
            }
        }
    }

    private func sendOverlayTransportPayload(_ payload: Data) {
        do {
            let snapshot = try overlayRuntime.sendApplicationPayload(payload, nowNS: monotonicNowNS(), echoNS: currentEchoNS(monotonicNowNS()))
            for frame in snapshot.frames {
                sendDatagram(frame)
            }
        } catch {
            eventSink?("udp_overlay_send_payload_failed", ["error": error.localizedDescription, "packet_bytes": payload.count])
        }
    }

    private func sendDatagram(_ packet: Data) {
        guard started, socketFD >= 0, let peerAddress = currentPeerAddress else {
            return
        }
        packet.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else { return }
            peerAddress.storage.withUnsafeBytes { peerBuffer in
                guard let peerBase = peerBuffer.baseAddress else { return }
                let sockaddrPtr = peerBase.assumingMemoryBound(to: sockaddr.self)
                let sent = Darwin.sendto(socketFD, base, rawBuffer.count, 0, sockaddrPtr, peerAddress.length)
                if sent < 0 {
                    eventSink?("udp_overlay_send_failed", ["errno": errno, "packet_bytes": rawBuffer.count])
                }
            }
        }
    }

    private func sendOnUDPConnection(_ connection: NWConnection, payload: Data, chanID: Int) {
        connection.send(content: payload, completion: .contentProcessed { [weak self] error in
            guard let self, let error else { return }
            self.queue.async {
                self.eventSink?("udp_overlay_udp_client_write_failed", ["chan_id": chanID, "error": error.localizedDescription])
            }
        })
    }

    private func cancelConnection(_ connection: NWConnection) {
        connection.stateUpdateHandler = nil
        connection.cancel()
    }

    private func serviceName(_ spec: ObstacleBridgeChannelMuxCodec.ServiceSpec) -> String {
        spec.name ?? serviceNameByID[spec.svcID] ?? ""
    }

    private func updateConnectedState(proto: String, chanID: Int, localHost: String?, localPort: Int?) {
        switch proto {
        case "tcp":
            guard var state = tcpConnectionStates[chanID] else { return }
            state.state = "connected"
            state.localHost = localHost ?? state.localHost
            state.localPort = localPort ?? state.localPort
            tcpConnectionStates[chanID] = state
        case "udp":
            guard var state = udpConnectionStates[chanID] else { return }
            state.state = "connected"
            state.localHost = localHost ?? state.localHost
            state.localPort = localPort ?? state.localPort
            udpConnectionStates[chanID] = state
        default:
            break
        }
    }

    private func recordInbound(proto: String, chanID: Int, bytes: Int) {
        switch proto {
        case "tcp":
            guard var state = tcpConnectionStates[chanID] else { return }
            state.stats["rx_msgs", default: 0] += 1
            state.stats["rx_bytes", default: 0] += bytes
            tcpConnectionStates[chanID] = state
        case "udp":
            guard var state = udpConnectionStates[chanID] else { return }
            state.stats["rx_msgs", default: 0] += 1
            state.stats["rx_bytes", default: 0] += bytes
            udpConnectionStates[chanID] = state
        default:
            break
        }
    }

    private func recordOutbound(proto: String, chanID: Int, bytes: Int) {
        switch proto {
        case "tcp":
            guard var state = tcpConnectionStates[chanID] else { return }
            state.stats["tx_msgs", default: 0] += 1
            state.stats["tx_bytes", default: 0] += bytes
            tcpConnectionStates[chanID] = state
        case "udp":
            guard var state = udpConnectionStates[chanID] else { return }
            state.stats["tx_msgs", default: 0] += 1
            state.stats["tx_bytes", default: 0] += bytes
            udpConnectionStates[chanID] = state
        default:
            break
        }
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
            updateConnectedState(proto: "tcp", chanID: chanID, localHost: nil, localPort: nil)
        case .serverInbound(let chanID, let bytes):
            recordInbound(proto: "tcp", chanID: chanID, bytes: bytes)
        case .serverOutbound(let chanID, let bytes):
            recordOutbound(proto: "tcp", chanID: chanID, bytes: bytes)
        case .serverClosed(let chanID):
            tcpConnectionStates.removeValue(forKey: chanID)
        }
    }

    private func channelID(for connection: NWConnection) -> Int? {
        udpServerConnections.first { $0.value === connection }?.key
    }

    private func currentEchoNS(_ nowNS: UInt64) -> UInt64 {
        guard overlayRuntime.lastRxTxNS != 0,
              overlayRuntime.lastRxWallNS != 0,
              nowNS >= overlayRuntime.lastRxWallNS
        else {
            return 0
        }
        return overlayRuntime.lastRxTxNS + (nowNS - overlayRuntime.lastRxWallNS)
    }

    private func monotonicNowNS() -> UInt64 {
        DispatchTime.now().uptimeNanoseconds
    }

    private static func endpointDescription(_ endpoint: NWEndpoint) -> (host: String, port: Int) {
        if case let .hostPort(host, port) = endpoint {
            return (host.debugDescription, Int(port.rawValue))
        }
        return ("127.0.0.1", 0)
    }

    private static func makeBoundSocket(
        bindHost: String,
        bindPort: Int,
        peerHost: String?,
        peerPort: Int?
    ) throws -> (socketFD: Int32, peerAddress: ResolvedAddress?) {
        let resolvedPeer: ResolvedAddress?
        if let peerHost,
           !peerHost.isEmpty,
           let peerPort,
           peerPort > 0 {
            resolvedPeer = try resolveAddress(host: peerHost, port: peerPort, passive: false, family: AF_UNSPEC)
        } else {
            resolvedPeer = nil
        }
        let bindFamily: Int32
        if let resolvedPeer {
            bindFamily = resolvedPeer.family
        } else {
            bindFamily = bindHost.contains(":") ? AF_INET6 : AF_INET
        }
        let resolvedBindHost: String
        if bindFamily == AF_INET6 && bindHost == "0.0.0.0" {
            resolvedBindHost = "::"
        } else {
            resolvedBindHost = bindHost
        }
        let bindAddr = try resolveAddress(host: resolvedBindHost, port: bindPort, passive: true, family: bindFamily)
        let sock = socket(bindAddr.family, SOCK_DGRAM, IPPROTO_UDP)
        guard sock >= 0 else {
            throw NSError(domain: "ObstacleBridge.UdpOverlayTransportOwner", code: 41, userInfo: [NSLocalizedDescriptionKey: "socket() failed"])
        }
        let flags = fcntl(sock, F_GETFL, 0)
        _ = fcntl(sock, F_SETFL, flags | O_NONBLOCK)
        var noSigPipe: Int32 = 1
        _ = withUnsafePointer(to: &noSigPipe) { ptr in
            setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, ptr, socklen_t(MemoryLayout<Int32>.size))
        }
        let bindResult = bindAddr.storage.withUnsafeBytes { rawBuffer -> Int32 in
            let sockaddrPtr = rawBuffer.baseAddress!.assumingMemoryBound(to: sockaddr.self)
            return Darwin.bind(sock, sockaddrPtr, bindAddr.length)
        }
        guard bindResult == 0 else {
            let err = errno
            Darwin.close(sock)
            throw NSError(domain: "ObstacleBridge.UdpOverlayTransportOwner", code: 42, userInfo: [NSLocalizedDescriptionKey: "bind() failed errno=\(err)"])
        }
        return (sock, resolvedPeer)
    }

    private static func resolvedAddress(from storage: sockaddr_storage, length: socklen_t) -> ResolvedAddress? {
        let family = storage.ss_family
        guard family == sa_family_t(AF_INET) || family == sa_family_t(AF_INET6) else {
            return nil
        }
        var copied = storage
        let hostLength = Int(NI_MAXHOST)
        let serviceLength = Int(NI_MAXSERV)
        var hostBuffer = [CChar](repeating: 0, count: hostLength)
        var serviceBuffer = [CChar](repeating: 0, count: serviceLength)
        let infoResult = withUnsafeMutablePointer(to: &copied) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                getnameinfo(sockaddrPtr, length, &hostBuffer, socklen_t(hostLength), &serviceBuffer, socklen_t(serviceLength), NI_NUMERICHOST | NI_NUMERICSERV)
            }
        }
        guard infoResult == 0 else {
            return nil
        }
        let host = String(cString: hostBuffer)
        let port = Int(String(cString: serviceBuffer)) ?? 0
        let data = withUnsafeBytes(of: copied) { raw in
            Data(raw.prefix(Int(length)))
        }
        return ResolvedAddress(family: Int32(family), storage: data, length: length, host: host, port: port)
    }

    private static func resolveAddress(host: String, port: Int, passive: Bool, family: Int32) throws -> ResolvedAddress {
        var hints = addrinfo(
            ai_flags: passive ? AI_PASSIVE : 0,
            ai_family: family,
            ai_socktype: SOCK_DGRAM,
            ai_protocol: IPPROTO_UDP,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )
        var results: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, String(port), &hints, &results)
        guard status == 0, let info = results else {
            throw NSError(domain: "ObstacleBridge.UdpOverlayTransportOwner", code: 44, userInfo: [NSLocalizedDescriptionKey: "getaddrinfo() failed for \(host):\(port) status=\(status)"])
        }
        defer { freeaddrinfo(results) }
        let addrData = Data(bytes: info.pointee.ai_addr, count: Int(info.pointee.ai_addrlen))
        return ResolvedAddress(
            family: info.pointee.ai_family,
            storage: addrData,
            length: info.pointee.ai_addrlen,
            host: host,
            port: port
        )
    }
}
