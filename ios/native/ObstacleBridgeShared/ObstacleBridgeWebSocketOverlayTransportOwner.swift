import Foundation
import Network

final class ObstacleBridgeWebSocketOverlayTransportOwner: NSObject, URLSessionWebSocketDelegate, URLSessionTaskDelegate {
    typealias EventSink = (String, [String: Any]) -> Void
    typealias TunPacketSink = (Data) -> Void

    private let peerHost: String
    private let peerPort: Int
    private let useTLS: Bool
    private let wsPath: String
    private let wsSubprotocol: String?
    private let overlayRuntime: ObstacleBridgeWebSocketOverlayRuntime
    private let overlayLayerTransportAdapter: ObstacleBridgeOverlayLayerTransportAdapter?
    private let startupMuxFrames: [Data]
    private let reconnectRetryDelayMS: Int
    private let sessionMaxAppPayload: Int
    private let queue: DispatchQueue
    private let eventSink: EventSink?
    private let serviceNameByID: [Int: String]
    private let tunIfname: String?
    private let tunMTU: Int
    private let tunPacketSink: TunPacketSink?
    private let muxInstanceID: UInt64
    private let muxConnectionSeq: UInt32

    private var udpRuntime: ObstacleBridgeChannelMuxUdpRuntime
    private var tunRuntime: ObstacleBridgeChannelMuxTunRuntime?
    private var websocketSession: URLSession?
    private var websocketTask: URLSessionWebSocketTask?
    private var overlayConnected = false
    private var udpServerConnections: [Int: NWConnection] = [:]
    private var udpClientConnections: [Int: NWConnection] = [:]
    private var udpClientDrivers: [Int: ObstacleBridgeUDPClientConnectionDriver] = [:]
    private var tcpConnectionStates: [Int: ObstacleBridgeOverlayConnectionState] = [:]
    private var udpConnectionStates: [Int: ObstacleBridgeOverlayConnectionState] = [:]
    private var activeTunChanIDs: Set<Int> = []
    private var tunStats: [String: Int] = ["rx_msgs": 0, "tx_msgs": 0, "rx_bytes": 0, "tx_bytes": 0]
    private var udpServerDrivers: [ObjectIdentifier: ObstacleBridgeUDPServerConnectionDriver] = [:]
    private var started = false
    private var reconnectAttempts = 0
    private var reconnectScheduled = false
    private var reconnectWorkItem: DispatchWorkItem?
    private var secureLinkHandshakePrimed = false
    private var startupMuxFramesSent = false
    private var connectedURI = ""
    private lazy var tcpTransportOwner = ObstacleBridgeChannelMuxTCPTransportOwner(
        runtime: ObstacleBridgeChannelMuxTcpRuntime(
            instanceID: muxInstanceID,
            connectionSeq: muxConnectionSeq,
            sessionMaxAppPayload: sessionMaxAppPayload
        ),
        sessionMaxAppPayload: sessionMaxAppPayload,
        queue: queue,
        eventPrefix: "ws_overlay",
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
        useTLS: Bool = false,
        wsPath: String = "/",
        wsSubprotocol: String? = nil,
        overlayRuntime: ObstacleBridgeWebSocketOverlayRuntime,
        reconnectRetryDelayMS: Int = 30000,
        sessionMaxAppPayload: Int = 65535,
        overlayLayerTransportAdapter: ObstacleBridgeOverlayLayerTransportAdapter? = nil,
        startupMuxFrames: [Data] = [],
        queue: DispatchQueue = DispatchQueue(label: "ObstacleBridgeWebSocketOverlayTransportOwner"),
        serviceNameByID: [Int: String] = [:],
        tunIfname: String? = nil,
        tunMTU: Int = 0,
        tunPacketSink: TunPacketSink? = nil,
        muxInstanceID: UInt64 = UInt64.random(in: 1...UInt64.max),
        muxConnectionSeq: UInt32 = UInt32.random(in: 1...UInt32.max),
        eventSink: EventSink? = nil
    ) {
        self.peerHost = peerHost
        self.peerPort = peerPort
        self.useTLS = useTLS
        self.wsPath = wsPath.isEmpty ? "/" : wsPath
        self.wsSubprotocol = wsSubprotocol?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.overlayRuntime = overlayRuntime
        self.reconnectRetryDelayMS = max(0, reconnectRetryDelayMS)
        self.sessionMaxAppPayload = max(0, sessionMaxAppPayload)
        self.overlayLayerTransportAdapter = overlayLayerTransportAdapter
        self.startupMuxFrames = startupMuxFrames
        self.queue = queue
        self.serviceNameByID = serviceNameByID
        self.tunIfname = tunIfname?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.tunMTU = max(0, tunMTU)
        self.tunPacketSink = tunPacketSink
        self.muxInstanceID = muxInstanceID
        self.muxConnectionSeq = muxConnectionSeq
        self.eventSink = eventSink
        self.udpRuntime = ObstacleBridgeChannelMuxUdpRuntime(
            instanceID: muxInstanceID,
            connectionSeq: muxConnectionSeq
        )
        if let tunIfname = self.tunIfname, !tunIfname.isEmpty, self.tunMTU > 0 {
            self.tunRuntime = ObstacleBridgeChannelMuxTunRuntime(
                instanceID: muxInstanceID,
                connectionSeq: muxConnectionSeq,
                localSpec: ObstacleBridgeRuntimeConfig.localTunServiceSpec(ifname: tunIfname, mtu: self.tunMTU)
            )
        }
    }

    func start() {
        guard !started else { return }
        guard !peerHost.isEmpty, peerPort > 0 else { return }
        started = true
        connectOverlay()
    }

    func stop() {
        guard started else { return }
        started = false
        overlayConnected = false
        reconnectScheduled = false
        reconnectWorkItem?.cancel()
        reconnectWorkItem = nil
        websocketTask?.cancel(with: .goingAway, reason: nil)
        websocketTask = nil
        websocketSession?.invalidateAndCancel()
        websocketSession = nil
        tcpTransportOwner.stop()
        for connection in udpServerConnections.values { connection.cancel() }
        udpServerDrivers.removeAll()
        for connection in udpClientConnections.values { connection.cancel() }
        udpClientDrivers.removeAll()
        udpServerConnections.removeAll()
        udpClientConnections.removeAll()
        tcpConnectionStates.removeAll()
        udpConnectionStates.removeAll()
        activeTunChanIDs.removeAll()
        tunStats = ["rx_msgs": 0, "tx_msgs": 0, "rx_bytes": 0, "tx_bytes": 0]
        secureLinkHandshakePrimed = false
        startupMuxFramesSent = false
        connectedURI = ""
    }

    func connectionRows() -> (tcp: [[String: Any]], udp: [[String: Any]], tun: [[String: Any]]) {
        let tcpRows = ObstacleBridgeOverlayConnectionSupport.connectionRows(from: tcpConnectionStates)
        let udpRows = ObstacleBridgeOverlayConnectionSupport.connectionRows(from: udpConnectionStates)
        let tunRows: [[String: Any]]
        if activeTunChanIDs.isEmpty, (tunStats["rx_bytes"] ?? 0) == 0, (tunStats["tx_bytes"] ?? 0) == 0 {
            tunRows = []
        } else {
            let ifname = tunIfname ?? "tun"
            let mtu = tunMTU
            let spec = ObstacleBridgeRuntimeConfig.localTunServiceSpec(ifname: ifname, mtu: mtu)
            let stats = tunStats
            tunRows = activeTunChanIDs.sorted().map { chanID in
                ObstacleBridgeNativeConnectionSnapshot.make(
                    proto: "tun",
                    role: "server",
                    state: "connected",
                    chanID: chanID,
                    svcID: spec.svcID,
                    serviceName: "TUN",
                    sourceHost: nil,
                    sourcePort: nil,
                    localHost: ifname,
                    localPort: mtu,
                    remoteHost: spec.rHost,
                    remotePort: spec.rPort,
                    stats: stats
                )
            }
        }
        return (tcpRows, udpRows, tunRows)
    }

    func transportSnapshot() -> [String: Any] {
        [
            "overlay_connected": overlayConnected,
            "overlay_host": peerHost,
            "overlay_port": peerPort,
            "uri": connectedURI,
            "payload_mode": overlayRuntime.configuredPayloadMode,
            "ws_path": wsPath,
            "ws_tls": useTLS,
            "reconnect_retry_delay_ms": reconnectRetryDelayMS,
            "reconnect_attempts": reconnectAttempts,
            "reconnect_scheduled": reconnectScheduled,
            "mux_instance_id": muxInstanceID,
            "mux_connection_seq": muxConnectionSeq,
            "server_tcp_channels": tcpTransportOwner.serverConnectionCount,
            "client_tcp_channels": tcpConnectionStates.count,
            "server_udp_channels": udpServerConnections.count,
            "client_udp_channels": udpConnectionStates.count,
            "tun_channels": activeTunChanIDs.count,
            "tun_stats": tunStats,
        ]
    }

    func sendLocalTunPacket(_ packet: Data) {
        guard started, let tunRuntime, let tunIfname, tunMTU > 0 else { return }
        do {
            guard let localSnapshot = try tunRuntime.handleLocalTunPacket(
                packet: packet,
                mtu: tunMTU,
                spec: ObstacleBridgeRuntimeConfig.localTunServiceSpec(ifname: tunIfname, mtu: tunMTU),
                overlayConnected: overlayConnected,
                acceptingEnabled: true
            ) else {
                return
            }
            activeTunChanIDs.insert(localSnapshot.chanID)
            tunStats["tx_msgs", default: 0] += 1
            tunStats["tx_bytes", default: 0] += packet.count
            sendMuxFrames(localSnapshot.frames)
        } catch {
            eventSink?("ws_overlay_tun_send_failed", [
                "error": error.localizedDescription,
                "packet_bytes": packet.count,
            ])
        }
    }

    @discardableResult
    func acceptLocalTCPConnection(
        _ connection: NWConnection,
        spec: ObstacleBridgeChannelMuxCodec.ServiceSpec,
        listenerHost: String,
        listenerPort: Int
    ) -> Bool {
        if let chanID = tcpTransportOwner.acceptLocalConnection(connection, spec: spec) {
            tcpConnectionStates[chanID] = ObstacleBridgeOverlayConnectionSupport.makeState(
                proto: "tcp",
                role: "server",
                chanID: chanID,
                spec: spec,
                serviceName: serviceName(spec),
                state: "connecting",
                localHost: listenerHost,
                localPort: listenerPort
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
        var driver: ObstacleBridgeUDPServerConnectionDriver!
        connection.stateUpdateHandler = { [weak self] state in
            self?.queue.async {
                self?.handleUDPServerConnectionState(state)
            }
        }
        connection.start(queue: queue)
        driver = ObstacleBridgeUDPServerConnectionDriver(
            connection: connection,
            spec: spec,
            serviceKey: serviceKey,
            queue: queue,
            runtime: udpRuntime,
            startedProvider: { [weak self] in self?.started ?? false },
            overlayConnectedProvider: { [weak self] in self?.overlayConnected ?? false },
            handleSnapshot: { [weak self] event in
                guard let self else { return }
                self.udpServerConnections[event.chanID] = connection
                if self.udpConnectionStates[event.chanID] == nil {
                    self.udpConnectionStates[event.chanID] = ObstacleBridgeOverlayConnectionSupport.makeState(
                        proto: "udp",
                        role: "server",
                        chanID: event.chanID,
                        spec: spec,
                        serviceName: self.serviceName(spec),
                        state: "connected",
                        localHost: listenerHost,
                        localPort: listenerPort
                    )
                } else {
                    ObstacleBridgeOverlayConnectionSupport.updateConnectedState(
                        states: &self.udpConnectionStates,
                        proto: "udp",
                        chanID: event.chanID,
                        localHost: listenerHost,
                        localPort: listenerPort
                    )
                }
                self.sendMuxFrames(event.frames)
                self.recordOutbound(proto: "udp", chanID: event.chanID, bytes: event.bytes)
            },
            handleClosed: { [weak self] chanID in
                guard let self else { return }
                if let chanID {
                    self.udpServerConnections.removeValue(forKey: chanID)
                    self.udpConnectionStates.removeValue(forKey: chanID)
                }
                self.udpServerDrivers.removeValue(forKey: ObjectIdentifier(connection))
            }
        )
        udpServerDrivers[ObjectIdentifier(connection)] = driver
        driver.start()
        return true
    }

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didOpenWithProtocol protocol: String?) {
        queue.async {
            guard self.started, self.websocketTask === webSocketTask else { return }
            self.overlayConnected = true
            self.reconnectScheduled = false
            self.maybePrimeSecureLinkHandshake()
            self.maybeSendStartupMuxFrames()
            self.receiveFromOverlay()
        }
    }

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didCloseWith closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) {
        queue.async {
            guard self.websocketTask === webSocketTask else { return }
            self.overlayConnected = false
            self.websocketTask = nil
            self.websocketSession = nil
            self.secureLinkHandshakePrimed = false
            self.startupMuxFramesSent = false
            self.scheduleReconnect()
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        queue.async {
            guard self.websocketTask === task as? URLSessionWebSocketTask else { return }
            self.overlayConnected = false
            self.websocketTask = nil
            self.websocketSession = nil
            self.secureLinkHandshakePrimed = false
            self.startupMuxFramesSent = false
            if let error {
                self.eventSink?("ws_overlay_connection_failed", ["error": error.localizedDescription])
            }
            self.scheduleReconnect()
        }
    }

    private func connectOverlay() {
        guard started else { return }
        reconnectScheduled = false
        reconnectWorkItem?.cancel()
        reconnectWorkItem = nil
        reconnectAttempts += 1
        do {
            let plan = overlayRuntime.buildConnectPlan(
                host: peerHost,
                port: peerPort,
                peerNameHost: nil,
                peerNamePort: nil,
                useTLS: useTLS,
                wsPath: wsPath,
                wsSubprotocol: wsSubprotocol,
                proxyActive: false
            )
            connectedURI = plan.uri
            guard let url = URL(string: plan.uri) else {
                throw URLError(.badURL)
            }
            var request = URLRequest(url: url)
            for (key, value) in plan.upgradeHeaders {
                request.setValue(value, forHTTPHeaderField: key)
            }
            if let subprotocols = plan.subprotocols, !subprotocols.isEmpty {
                request.setValue(subprotocols.joined(separator: ", "), forHTTPHeaderField: "Sec-WebSocket-Protocol")
            }
            let session = URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)
            let task = session.webSocketTask(with: request)
            websocketSession = session
            websocketTask = task
            task.resume()
        } catch {
            eventSink?("ws_overlay_connect_failed", ["error": error.localizedDescription])
            scheduleReconnect()
        }
    }

    private func scheduleReconnect() {
        guard started, !peerHost.isEmpty, peerPort > 0 else { return }
        reconnectWorkItem?.cancel()
        let workItem = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.reconnectScheduled = false
            self.reconnectWorkItem = nil
            self.connectOverlay()
        }
        reconnectWorkItem = workItem
        reconnectScheduled = true
        queue.asyncAfter(deadline: .now() + .milliseconds(reconnectRetryDelayMS), execute: workItem)
    }

    private func receiveFromOverlay() {
        guard started, let task = websocketTask else { return }
        task.receive { [weak self] result in
            self?.queue.async {
                guard let self, self.started, self.websocketTask === task else { return }
                switch result {
                case .success(let message):
                    do {
                        let payload = try self.overlayRuntime.decodeClientMessage(message)
                        self.handleOverlayTransportPayload(payload)
                        self.receiveFromOverlay()
                    } catch {
                        self.eventSink?("ws_overlay_decode_failed", ["error": error.localizedDescription])
                        self.receiveFromOverlay()
                    }
                case .failure(let error):
                    self.overlayConnected = false
                    self.websocketTask = nil
                    self.websocketSession = nil
                    self.secureLinkHandshakePrimed = false
                    self.startupMuxFramesSent = false
                    self.eventSink?("ws_overlay_receive_failed", ["error": error.localizedDescription])
                    self.scheduleReconnect()
                }
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

    private func maybePrimeSecureLinkHandshake() {
        guard overlayConnected, !secureLinkHandshakePrimed, let adapter = overlayLayerTransportAdapter else { return }
        do {
            let snapshot = try adapter.handleTransportConnected()
            secureLinkHandshakePrimed = true
            for frame in snapshot.emittedFrames {
                sendOverlayTransportPayload(frame)
            }
        } catch {
            eventSink?("ws_overlay_secure_link_prime_failed", ["error": error.localizedDescription])
        }
    }

    private func maybeSendStartupMuxFrames() {
        guard overlayConnected, !startupMuxFramesSent else { return }
        startupMuxFramesSent = true
        sendMuxFrames(startupMuxFrames)
    }

    private func sendMuxFrames(_ frames: [Data]) {
        guard !frames.isEmpty else { return }
        for frame in frames {
            sendOverlayTransportPayload(frame)
        }
    }

    private func sendOverlayTransportPayload(_ payload: Data) {
        if let adapter = overlayLayerTransportAdapter {
            do {
                let snapshot = try adapter.handleOutboundPayload(payload)
                for frame in snapshot.emittedFrames {
                    sendRawOverlayWire(frame)
                }
            } catch {
                eventSink?("ws_overlay_outbound_wrap_failed", ["error": error.localizedDescription])
            }
            return
        }
        sendRawOverlayWire(payload)
    }

    private func sendRawOverlayWire(_ wire: Data) {
        guard started, overlayConnected, let task = websocketTask else { return }
        do {
            let message = try overlayRuntime.encodeClientWire(wire)
            task.send(message) { [weak self] error in
                self?.queue.async {
                    guard let self else { return }
                    if let error {
                        self.eventSink?("ws_overlay_send_failed", ["error": error.localizedDescription])
                    }
                }
            }
        } catch {
            eventSink?("ws_overlay_encode_failed", ["error": error.localizedDescription])
        }
    }

    private func handleOverlayPayload(_ payload: Data) {
        guard let frame = ObstacleBridgeChannelMuxCodec.unpackMux(payload) else {
            return
        }
        switch frame.proto {
        case .tun:
            handleInboundTunMuxFrame(frame)
        case .tcp:
            handleInboundTCPMuxFrame(frame)
        case .udp:
            handleInboundUDPMuxFrame(frame)
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
            if snapshot.closed {
                closeUDPClientConnection(chanID: frame.chanID)
            }
        default:
            break
        }
    }

    private func handleInboundTunMuxFrame(_ frame: ObstacleBridgeChannelMuxCodec.MuxFrame) {
        guard let tunRuntime, tunMTU > 0 else {
            return
        }
        switch frame.mtype {
        case .open:
            let snapshot = tunRuntime.handleInboundTunOpen(chanID: frame.chanID, payload: frame.body)
            if snapshot.accepted { activeTunChanIDs.insert(frame.chanID) }
        case .openChunk:
            let snapshot = tunRuntime.handleInboundTunOpenChunk(chanID: frame.chanID, payload: frame.body)
            if snapshot.accepted { activeTunChanIDs.insert(frame.chanID) }
        case .data:
            let snapshot = tunRuntime.handleInboundTunData(chanID: frame.chanID, body: frame.body, mtu: tunMTU)
            if let packet = snapshot.packet, snapshot.delivered {
                activeTunChanIDs.insert(frame.chanID)
                tunStats["rx_msgs", default: 0] += 1
                tunStats["rx_bytes", default: 0] += packet.count
                tunPacketSink?(packet)
            }
        case .dataFrag:
            let snapshot = tunRuntime.handleInboundTunFragment(chanID: frame.chanID, payload: frame.body, mtu: tunMTU)
            if let packet = snapshot.packet, snapshot.delivered {
                activeTunChanIDs.insert(frame.chanID)
                tunStats["rx_msgs", default: 0] += 1
                tunStats["rx_bytes", default: 0] += packet.count
                tunPacketSink?(packet)
            }
        case .close:
            let snapshot = tunRuntime.handleInboundTunClose(chanID: frame.chanID)
            if snapshot.closed { activeTunChanIDs.remove(frame.chanID) }
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
        udpConnectionStates[chanID] = ObstacleBridgeOverlayConnectionSupport.makeState(
            proto: "udp",
            role: "client",
            chanID: chanID,
            spec: parsed.spec,
            serviceName: serviceName(parsed.spec),
            state: snapshot.connected ? "connected" : "connecting",
            localHost: nil,
            localPort: nil
        )
        if snapshot.connectRequested {
            startOutboundUDPConnection(chanID: chanID, spec: parsed.spec)
        }
    }

    private func startOutboundUDPConnection(chanID: Int, spec: ObstacleBridgeChannelMuxCodec.ServiceSpec) {
        guard udpClientConnections[chanID] == nil else {
            return
        }
        let driver = ObstacleBridgeUDPClientConnectionDriver(
            chanID: chanID,
            spec: spec,
            queue: queue,
            runtime: udpRuntime,
            startedProvider: { [weak self] in self?.started ?? false },
            registerConnection: { [weak self] connection in
                self?.udpClientConnections[chanID] = connection
            },
            updateConnected: { [weak self] localHost, localPort in
                guard let self else { return }
                ObstacleBridgeOverlayConnectionSupport.updateConnectedState(
                    states: &self.udpConnectionStates,
                    proto: "udp",
                    chanID: chanID,
                    localHost: localHost,
                    localPort: localPort
                )
            },
            sendOnUDPConnection: { [weak self] connection, payload, chanID in
                self?.sendOnUDPConnection(connection, payload: payload, chanID: chanID)
            },
            sendMuxFrames: { [weak self] frames in
                self?.sendMuxFrames(frames)
            },
            recordInbound: { [weak self] bytes in
                self?.recordInbound(proto: "udp", chanID: chanID, bytes: bytes)
            },
            recordOutbound: { [weak self] bytes in
                self?.recordOutbound(proto: "udp", chanID: chanID, bytes: bytes)
            },
            eventSink: { [weak self] event, fields in
                self?.eventSink?(event, fields)
            },
            failureEvent: "ws_overlay_udp_client_failed",
            handleClosed: { [weak self] in
                self?.closeUDPClientConnection(chanID: chanID)
            }
        )
        udpClientDrivers[chanID] = driver
        driver.start()
    }

    private func handleTCPTransportEvent(_ event: ObstacleBridgeChannelMuxTCPTransportOwner.TransportEvent) {
        switch event {
        case .clientAccepted(let chanID, let spec, let connected):
            tcpConnectionStates[chanID] = ObstacleBridgeOverlayConnectionSupport.makeState(
                proto: "tcp",
                role: "client",
                chanID: chanID,
                spec: spec,
                serviceName: serviceName(spec),
                state: connected ? "connected" : "connecting",
                localHost: nil,
                localPort: nil
            )
        case .clientConnected(let chanID, let localHost, let localPort):
            ObstacleBridgeOverlayConnectionSupport.updateConnectedState(
                states: &tcpConnectionStates,
                proto: "tcp",
                chanID: chanID,
                localHost: localHost,
                localPort: localPort
            )
        case .clientInbound(let chanID, let bytes), .serverInbound(let chanID, let bytes):
            recordInbound(proto: "tcp", chanID: chanID, bytes: bytes)
        case .clientOutbound(let chanID, let bytes), .serverOutbound(let chanID, let bytes):
            recordOutbound(proto: "tcp", chanID: chanID, bytes: bytes)
        case .clientClosed(let chanID), .serverClosed(let chanID):
            tcpConnectionStates.removeValue(forKey: chanID)
        case .serverConnected(let chanID):
            ObstacleBridgeOverlayConnectionSupport.updateConnectedState(
                states: &tcpConnectionStates,
                proto: "tcp",
                chanID: chanID,
                localHost: nil,
                localPort: nil
            )
        }
    }

    private func handleUDPServerConnectionState(_ state: NWConnection.State) {
        if case .failed(let error) = state {
            eventSink?("ws_overlay_udp_server_connection_failed", ["error": error.localizedDescription])
        }
    }

    private func handleUDPClientConnectionState(_ state: NWConnection.State) {
        if case .failed = state { }
    }

    private func recordInbound(proto: String, chanID: Int, bytes: Int) {
        switch proto {
        case "tcp":
            ObstacleBridgeOverlayConnectionSupport.recordTraffic(states: &tcpConnectionStates, proto: proto, chanID: chanID, direction: "inbound", bytes: bytes)
        case "udp":
            ObstacleBridgeOverlayConnectionSupport.recordTraffic(states: &udpConnectionStates, proto: proto, chanID: chanID, direction: "inbound", bytes: bytes)
        default:
            break
        }
    }

    private func recordOutbound(proto: String, chanID: Int, bytes: Int) {
        switch proto {
        case "tcp":
            ObstacleBridgeOverlayConnectionSupport.recordTraffic(states: &tcpConnectionStates, proto: proto, chanID: chanID, direction: "outbound", bytes: bytes)
        case "udp":
            ObstacleBridgeOverlayConnectionSupport.recordTraffic(states: &udpConnectionStates, proto: proto, chanID: chanID, direction: "outbound", bytes: bytes)
        default:
            break
        }
    }

    private func closeUDPClientConnection(chanID: Int) {
        let driver = udpClientDrivers.removeValue(forKey: chanID)
        driver?.stop()
        let connection = udpClientConnections.removeValue(forKey: chanID)
        connection?.stateUpdateHandler = nil
        connection?.cancel()
        udpConnectionStates.removeValue(forKey: chanID)
    }

    private func sendOnUDPConnection(_ connection: NWConnection, payload: Data, chanID: Int) {
        connection.send(content: payload, completion: .contentProcessed { [weak self] error in
            guard let self, let error else { return }
            self.queue.async {
                self.eventSink?("ws_overlay_udp_client_write_failed", ["chan_id": chanID, "error": error.localizedDescription])
            }
        })
    }

    private func serviceName(_ spec: ObstacleBridgeChannelMuxCodec.ServiceSpec) -> String {
        serviceNameByID[spec.svcID] ?? spec.name ?? spec.lProto.uppercased()
    }
}
