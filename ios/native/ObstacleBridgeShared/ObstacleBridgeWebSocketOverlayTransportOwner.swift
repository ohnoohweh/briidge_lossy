import Foundation
import Network

final class ObstacleBridgeWebSocketOverlayTransportOwner: NSObject, URLSessionWebSocketDelegate, URLSessionTaskDelegate {
    typealias EventSink = (String, [String: Any]) -> Void
    typealias TunPacketSink = (Data) -> Void
    private static let queueSpecificKey = DispatchSpecificKey<Int>()

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
    private let tunServiceSpec: ObstacleBridgeChannelMuxCodec.ServiceSpec?
    private let tunIfname: String?
    private let tunMTU: Int
    private let tunLocalAddress: String?
    private let tunLocalAddress6: String?
    private let sharedTunDisableOutgoingNormalization: Bool
    private let sharedTunDisableInflowFilter: Bool
    private let sharedTunDisableOutflowFilter: Bool
    private let sharedTunDisableScopedThrottle: Bool
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
    private var pendingOutboundMessages: [URLSessionWebSocketTask.Message] = []
    private var outboundSendInFlight = false
    private var overlayEgressWindow = ObstacleBridgeOverlayChannelCore.OverlayEgressWindowState()
    private var lastOverlayRxWallNS: UInt64 = 0
    private var lastPeerPingTxNS: UInt64 = 0
    private var lastRttOkNS: UInt64 = 0
    private var rttEstMS: Double?
    private var tunDebugLocalForwards = 0
    private var tunDebugLocalDrops = 0
    private var tunDebugInboundDelivers = 0
    private var tunDebugInboundDrops = 0
    private var tunDebugInboundRelays = 0
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
        tunServiceSpec: ObstacleBridgeChannelMuxCodec.ServiceSpec? = nil,
        tunIfname: String? = nil,
        tunMTU: Int = 0,
        tunLocalAddress: String? = nil,
        tunLocalAddress6: String? = nil,
        sharedTunDisableOutgoingNormalization: Bool = false,
        sharedTunDisableInflowFilter: Bool = false,
        sharedTunDisableOutflowFilter: Bool = false,
        sharedTunDisableScopedThrottle: Bool = false,
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
        self.tunServiceSpec = tunServiceSpec
        self.tunIfname = tunIfname?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.tunMTU = max(0, tunMTU)
        self.tunLocalAddress = tunLocalAddress
        self.tunLocalAddress6 = tunLocalAddress6
        self.sharedTunDisableOutgoingNormalization = sharedTunDisableOutgoingNormalization
        self.sharedTunDisableInflowFilter = sharedTunDisableInflowFilter
        self.sharedTunDisableOutflowFilter = sharedTunDisableOutflowFilter
        self.sharedTunDisableScopedThrottle = sharedTunDisableScopedThrottle
        self.tunPacketSink = tunPacketSink
        self.muxInstanceID = muxInstanceID
        self.muxConnectionSeq = muxConnectionSeq
        self.eventSink = eventSink
        self.queue.setSpecific(key: Self.queueSpecificKey, value: 1)
        self.udpRuntime = ObstacleBridgeChannelMuxUdpRuntime(
            instanceID: muxInstanceID,
            connectionSeq: muxConnectionSeq
        )
        if let tunIfname = self.tunIfname, !tunIfname.isEmpty, self.tunMTU > 0 {
            let localTunSpec = tunServiceSpec ?? ObstacleBridgeRuntimeConfig.localTunServiceSpec(ifname: tunIfname, mtu: self.tunMTU)
            self.tunRuntime = ObstacleBridgeChannelMuxTunRuntime(
                instanceID: muxInstanceID,
                connectionSeq: muxConnectionSeq,
                localSpec: localTunSpec,
                localTunnelAddress: self.tunLocalAddress,
                localTunnelAddress6: self.tunLocalAddress6,
                sharedTunDisableOutgoingNormalization: self.sharedTunDisableOutgoingNormalization,
                sharedTunDisableInflowFilter: self.sharedTunDisableInflowFilter,
                sharedTunDisableOutflowFilter: self.sharedTunDisableOutflowFilter,
                sharedTunDisableScopedThrottle: self.sharedTunDisableScopedThrottle
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
        tunRuntime?.cleanupSharedTunPeerStateOnDisconnect(peerID: currentTunPeerID())
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
        resetOverlayTransportEpoch()
        connectedURI = ""
        pendingOutboundMessages.removeAll(keepingCapacity: false)
        outboundSendInFlight = false
        overlayEgressWindow = ObstacleBridgeOverlayChannelCore.OverlayEgressWindowState()
        tunDebugLocalForwards = 0
        tunDebugLocalDrops = 0
        tunDebugInboundDelivers = 0
        tunDebugInboundDrops = 0
        tunDebugInboundRelays = 0
    }

    func connectionRows() -> (tcp: [[String: Any]], udp: [[String: Any]], tun: [[String: Any]]) {
        withOwnerQueue {
            let tcpRows = ObstacleBridgeOverlayConnectionSupport.connectionRows(from: tcpConnectionStates)
            let udpRows = ObstacleBridgeOverlayConnectionSupport.connectionRows(from: udpConnectionStates)
            let tunRows = ObstacleBridgeOverlayChannelCore.tunRows(
                activeTunChanIDs: activeTunChanIDs,
                tunStats: tunStats,
                tunRuntime: tunRuntime,
                tunServiceSpec: tunServiceSpec,
                tunIfname: tunIfname,
                tunMTU: tunMTU,
                bufferedFrames: overlayWaitingCount(),
                backpressure: overlayBackpressureSnapshot()
            )
            return (tcpRows, udpRows, tunRows)
        }
    }

    func transportSnapshot() -> [String: Any] {
        withOwnerQueue {
            let protocolStats = overlayProtocolStats()
            return [
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
                "last_rx_wall_ns": lastOverlayRxWallNS,
                "last_rtt_ok_ns": lastRttOkNS,
                "rtt_est_ms": rttEstMS ?? NSNull(),
                "transmit_delay_est_ms": transmitDelayEstMSValue() ?? NSNull(),
                "protocol_stats": protocolStats,
            ]
        }
    }

    private func withOwnerQueue<T>(_ body: () -> T) -> T {
        if DispatchQueue.getSpecific(key: Self.queueSpecificKey) != nil {
            return body()
        }
        return queue.sync(execute: body)
    }

    func sendLocalTunPacket(_ packet: Data) {
        do {
            try ObstacleBridgeOverlayChannelCore.sendLocalTunPacket(
                packet,
                started: started,
                tunRuntime: tunRuntime,
                tunServiceSpec: tunServiceSpec,
                tunIfname: tunIfname,
                tunMTU: tunMTU,
                overlayConnected: overlayConnected,
                bufferedFrames: overlayWaitingCount(),
                backpressure: overlayBackpressureSnapshot(),
                activeTunChanIDs: &activeTunChanIDs,
                tunStats: &tunStats,
                sendMuxFrames: sendMuxFrames,
                onLocalDrop: { [weak self] event in
                    self?.logTunLocalDrop(
                        reason: event.reason,
                        packet: event.packet,
                        sharedRoute: event.sharedRoute,
                        tunRuntime: event.tunRuntime
                    )
                },
                onLocalForward: { [weak self] event in
                    self?.logTunLocalForward(
                        packet: event.packet,
                        chanID: event.chanID,
                        allocatedChannel: event.allocatedChannel,
                        sharedRoute: event.sharedRoute,
                        tunRuntime: event.tunRuntime
                    )
                }
            )
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
        ObstacleBridgeOverlayChannelCore.acceptLocalTCPConnection(
            connection,
            spec: spec,
            listenerHost: listenerHost,
            listenerPort: listenerPort,
            tcpTransportOwner: tcpTransportOwner,
            tcpConnectionStates: &tcpConnectionStates,
            serviceNameByID: serviceNameByID,
            cancelConnection: { $0.cancel() }
        )
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
            },
            eventSink: { [weak self] event, fields in
                self?.eventSink?(event, fields)
            },
            eventPrefix: "ws_overlay"
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
            self.eventSink?("ws_overlay_connected", [
                "peer_host": self.peerHost,
                "peer_port": self.peerPort,
                "uri": self.connectedURI,
            ])
            self.pendingOutboundMessages.removeAll(keepingCapacity: false)
            self.outboundSendInFlight = false
            self.maybePrimeSecureLinkHandshake()
            self.maybeSendStartupMuxFrames()
            self.scheduleNextRTTPing(for: webSocketTask)
            self.receiveFromOverlay()
        }
    }

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didCloseWith closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) {
        queue.async {
            guard self.websocketTask === webSocketTask else { return }
            self.tunRuntime?.cleanupSharedTunPeerStateOnDisconnect(peerID: self.currentTunPeerID())
            self.overlayConnected = false
            self.websocketTask = nil
            self.websocketSession = nil
            self.resetOverlayTransportEpoch()
            self.scheduleReconnect()
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        queue.async {
            guard self.websocketTask === task as? URLSessionWebSocketTask else { return }
            self.tunRuntime?.cleanupSharedTunPeerStateOnDisconnect(peerID: self.currentTunPeerID())
            self.overlayConnected = false
            self.websocketTask = nil
            self.websocketSession = nil
            self.resetOverlayTransportEpoch()
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
                        let frame = try self.overlayRuntime.decodeClientFrame(message)
                        self.handleWebSocketFrame(frame)
                        self.receiveFromOverlay()
                    } catch {
                        self.eventSink?("ws_overlay_decode_failed", ["error": error.localizedDescription])
                        self.receiveFromOverlay()
                    }
                case .failure(let error):
                    self.tunRuntime?.cleanupSharedTunPeerStateOnDisconnect(peerID: self.currentTunPeerID())
                    self.overlayConnected = false
                    self.websocketTask = nil
                    self.websocketSession = nil
                    self.resetOverlayTransportEpoch()
                    self.eventSink?("ws_overlay_receive_failed", ["error": error.localizedDescription])
                    self.scheduleReconnect()
                }
            }
        }
    }

    private func handleWebSocketFrame(_ frame: ObstacleBridgeWebSocketOverlayRuntime.InboundFrame) {
        switch frame {
        case .app(let payload):
            handleOverlayTransportPayload(payload)
        case .ping(let txNS, let echoNS):
            lastPeerPingTxNS = txNS
            eventSink?("ws_overlay_ping_received", [
                "tx_ns": String(txNS),
                "echo_ns": String(echoNS),
            ])
            if echoNS > 0 {
                recordRTTPong(echoTxNS: echoNS)
            }
            sendWebSocketControlPong(echoTxNS: txNS)
        case .pong(let echoTxNS):
            recordRTTPong(echoTxNS: echoTxNS)
            eventSink?("ws_overlay_pong_received", [
                "echo_tx_ns": String(echoTxNS),
            ])
        }
    }

    private func handleOverlayTransportPayload(_ payload: Data) {
        lastOverlayRxWallNS = DispatchTime.now().uptimeNanoseconds
        if let adapter = overlayLayerTransportAdapter {
            let snapshot = adapter.handleInboundFrame(payload)
            for frame in snapshot.emittedFrames {
                sendRawOverlayWire(frame)
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
            eventSink?("ws_overlay_secure_link_prime", [
                "emitted_frames": snapshot.emittedFrames.count,
            ])
            for frame in snapshot.emittedFrames {
                sendRawOverlayWire(frame)
            }
        } catch {
            eventSink?("ws_overlay_secure_link_prime_failed", ["error": error.localizedDescription])
        }
    }

    private func resetOverlayTransportEpoch() {
        overlayLayerTransportAdapter?.handleTransportDisconnected()
        secureLinkHandshakePrimed = false
        startupMuxFramesSent = false
        pendingOutboundMessages.removeAll(keepingCapacity: false)
        outboundSendInFlight = false
        overlayEgressWindow = ObstacleBridgeOverlayChannelCore.OverlayEgressWindowState()
        lastPeerPingTxNS = 0
        lastRttOkNS = 0
        rttEstMS = nil
    }

    private func maybeSendStartupMuxFrames() {
        guard overlayConnected, !startupMuxFramesSent else { return }
        startupMuxFramesSent = true
        sendMuxFrames(startupMuxFrames)
    }

    private func currentTunPeerID() -> Int? {
        1
    }

    private func shouldLogTunDebug(counter: Int) -> Bool {
        counter <= 16 || counter % 100 == 0
    }

    private func logTunLocalForward(
        packet: Data,
        chanID: Int,
        allocatedChannel: Bool,
        sharedRoute: ObstacleBridgeChannelMuxTunRuntime.SharedTunOutboundRouteSnapshot?,
        tunRuntime: ObstacleBridgeChannelMuxTunRuntime
    ) {
        tunDebugLocalForwards += 1
        guard shouldLogTunDebug(counter: tunDebugLocalForwards) else { return }
        var fields = tunRuntime.packetDebugFields(packet: packet)
        fields["chan_id"] = chanID
        fields["allocated_channel"] = allocatedChannel
        fields["sample"] = tunDebugLocalForwards
        if let sharedRoute {
            fields["route_class"] = sharedRoute.routeClass ?? NSNull()
            fields["selected_peer_ids"] = sharedRoute.selectedPeerIDs
            fields["selected_chan_ids"] = sharedRoute.selectedChanIDs
            fields["route_destination_ip"] = sharedRoute.destinationIP ?? NSNull()
        } else {
            fields["route_class"] = "direct"
        }
        eventSink?("ws_overlay_tun_local_forward", fields)
    }

    private func logTunLocalDrop(
        reason: String,
        packet: Data,
        sharedRoute: ObstacleBridgeChannelMuxTunRuntime.SharedTunOutboundRouteSnapshot?,
        tunRuntime: ObstacleBridgeChannelMuxTunRuntime
    ) {
        tunDebugLocalDrops += 1
        guard shouldLogTunDebug(counter: tunDebugLocalDrops) else { return }
        var fields = tunRuntime.packetDebugFields(packet: packet)
        fields["reason"] = reason
        fields["sample"] = tunDebugLocalDrops
        if let sharedRoute {
            fields["route_class"] = sharedRoute.routeClass ?? NSNull()
            fields["selected_peer_ids"] = sharedRoute.selectedPeerIDs
            fields["selected_chan_ids"] = sharedRoute.selectedChanIDs
            fields["route_destination_ip"] = sharedRoute.destinationIP ?? NSNull()
        }
        eventSink?("ws_overlay_tun_local_drop", fields)
    }

    private func logTunInboundDeliver(
        packet: Data,
        chanID: Int,
        tunRuntime: ObstacleBridgeChannelMuxTunRuntime
    ) {
        tunDebugInboundDelivers += 1
        guard shouldLogTunDebug(counter: tunDebugInboundDelivers) else { return }
        var fields = tunRuntime.packetDebugFields(packet: packet)
        fields["chan_id"] = chanID
        fields["sample"] = tunDebugInboundDelivers
        eventSink?("ws_overlay_tun_inbound_deliver", fields)
    }

    private func logTunInboundDrop(
        reason: String,
        peerID: Int?,
        chanID: Int,
        ipVersion: Int?,
        sourceIP: String?,
        destinationIP: String?,
        packetBytes: Int
    ) {
        tunDebugInboundDrops += 1
        guard shouldLogTunDebug(counter: tunDebugInboundDrops) else { return }
        var fields: [String: Any] = [
            "reason": reason,
            "chan_id": chanID,
            "packet_bytes": packetBytes,
            "sample": tunDebugInboundDrops,
        ]
        if let peerID { fields["peer_id"] = peerID }
        if let ipVersion { fields["ip_version"] = ipVersion }
        if let sourceIP { fields["source_ip"] = sourceIP }
        if let destinationIP { fields["destination_ip"] = destinationIP }
        eventSink?("ws_overlay_tun_inbound_drop", fields)
    }

    private func logTunInboundRelay(
        relay: ObstacleBridgeChannelMuxTunRuntime.SharedTunInboundPeerRelaySnapshot,
        sourceChanID: Int,
        packet: Data,
        tunRuntime: ObstacleBridgeChannelMuxTunRuntime
    ) {
        tunDebugInboundRelays += 1
        guard shouldLogTunDebug(counter: tunDebugInboundRelays) else { return }
        var fields = tunRuntime.packetDebugFields(packet: packet)
        fields["source_chan_id"] = sourceChanID
        fields["sample"] = tunDebugInboundRelays
        fields["route_class"] = relay.routeClass ?? NSNull()
        fields["selected_peer_ids"] = relay.selectedPeerIDs
        fields["selected_chan_ids"] = relay.selectedChanIDs
        fields["route_destination_ip"] = relay.destinationIP ?? NSNull()
        eventSink?("ws_overlay_tun_inbound_relay", fields)
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

    private func sendWebSocketControlPong(echoTxNS: UInt64) {
        guard started, overlayConnected, let task = websocketTask else { return }
        do {
            let message = try overlayRuntime.encodeClientPong(echoTxNS: echoTxNS)
            task.send(message) { [weak self] error in
                self?.queue.async {
                    if let error {
                        self?.eventSink?("ws_overlay_pong_send_failed", [
                            "echo_tx_ns": String(echoTxNS),
                            "error": error.localizedDescription,
                        ])
                    } else {
                        self?.eventSink?("ws_overlay_pong_sent", [
                            "echo_tx_ns": String(echoTxNS),
                        ])
                    }
                }
            }
        } catch {
            eventSink?("ws_overlay_control_encode_failed", ["error": error.localizedDescription])
        }
    }

    private func scheduleNextRTTPing(for task: URLSessionWebSocketTask) {
        queue.asyncAfter(deadline: .now() + .seconds(1)) { [weak self, weak task] in
            guard let self, let task else { return }
            self.sendRTTPingAndReschedule(for: task)
        }
    }

    private func sendRTTPingAndReschedule(for task: URLSessionWebSocketTask) {
        guard started, overlayConnected, websocketTask === task else { return }
        let txNS = DispatchTime.now().uptimeNanoseconds
        do {
            let message = try overlayRuntime.encodeClientPing(txNS: txNS, echoNS: lastPeerPingTxNS)
            task.send(message) { [weak self, weak task] error in
                self?.queue.async {
                    guard let self, let task, self.websocketTask === task else { return }
                    if let error {
                        self.eventSink?("ws_overlay_ping_send_failed", [
                            "tx_ns": String(txNS),
                            "error": error.localizedDescription,
                        ])
                    }
                    self.scheduleNextRTTPing(for: task)
                }
            }
        } catch {
            eventSink?("ws_overlay_control_encode_failed", ["error": error.localizedDescription])
            scheduleNextRTTPing(for: task)
        }
    }

    private func recordRTTPong(echoTxNS: UInt64) {
        guard echoTxNS > 0 else { return }
        let nowNS = DispatchTime.now().uptimeNanoseconds
        guard nowNS >= echoTxNS else { return }
        let sampleMS = Double(nowNS - echoTxNS) / 1_000_000.0
        if let current = rttEstMS {
            rttEstMS = (current * 0.875) + (sampleMS * 0.125)
        } else {
            rttEstMS = sampleMS
        }
        lastRttOkNS = nowNS
    }

    private func transmitDelayEstMSValue() -> Double? {
        guard let rttEstMS else { return nil }
        return max(0.0, rttEstMS * 0.5)
    }

    private func sendRawOverlayWire(_ wire: Data) {
        guard started, overlayConnected, let task = websocketTask else { return }
        do {
            let message = try overlayRuntime.encodeClientWire(wire)
            pendingOutboundMessages.append(message)
            ObstacleBridgeOverlayChannelCore.recordOverlayEgress(
                bytes: wire.count,
                state: &overlayEgressWindow
            )
            flushNextOutboundMessageIfNeeded(task: task)
        } catch {
            eventSink?("ws_overlay_encode_failed", ["error": error.localizedDescription])
        }
    }

    private func flushNextOutboundMessageIfNeeded(task: URLSessionWebSocketTask) {
        guard started, overlayConnected, websocketTask === task, !outboundSendInFlight, !pendingOutboundMessages.isEmpty else {
            return
        }
        outboundSendInFlight = true
        let message = pendingOutboundMessages.removeFirst()
        task.send(message) { [weak self] error in
            self?.queue.async {
                guard let self else { return }
                self.outboundSendInFlight = false
                if let error {
                    self.eventSink?("ws_overlay_send_failed", ["error": error.localizedDescription])
                    self.pendingOutboundMessages.removeAll(keepingCapacity: false)
                    return
                }
                self.flushNextOutboundMessageIfNeeded(task: task)
            }
        }
    }

    private func overlayWaitingCount() -> Int {
        pendingOutboundMessages.count + (outboundSendInFlight ? 1 : 0)
    }

    private func overlayBackpressureSnapshot() -> ObstacleBridgeChannelMuxTunRuntime.OverlayBackpressureSnapshot {
        ObstacleBridgeOverlayChannelCore.backpressureSnapshot(
            waitingCount: overlayWaitingCount(),
            inflight: outboundSendInFlight ? 1 : 0,
            maxInflight: 1,
            egressWindow: overlayEgressWindow,
            transmitDelayEstMS: transmitDelayEstMSValue() ?? 0.0
        )
    }

    private func overlayProtocolStats() -> [String: Any] {
        var snapshot = ObstacleBridgeOverlayChannelCore.overlayProtocolStats(
            waitingCount: overlayWaitingCount(),
            inflight: outboundSendInFlight ? 1 : 0,
            maxInflight: 1,
            egressWindow: overlayEgressWindow,
            transmitDelayEstMS: transmitDelayEstMSValue() ?? 0.0
        )
        snapshot["rtt_est_ms"] = rttEstMS ?? NSNull()
        snapshot["last_rtt_ok_ns"] = lastRttOkNS
        return snapshot
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
        ObstacleBridgeOverlayChannelCore.handleInboundTunMuxFrame(
            frame,
            tunRuntime: tunRuntime,
            tunServiceSpec: tunServiceSpec,
            tunIfname: tunIfname,
            tunMTU: tunMTU,
            overlayConnected: overlayConnected,
            bufferedFrames: 0,
            currentTunPeerID: currentTunPeerID(),
            activeTunChanIDs: &activeTunChanIDs,
            tunStats: &tunStats,
            tunPacketSink: tunPacketSink,
            sendMuxFrames: sendMuxFrames,
            onInboundDrop: { [weak self] event in
                self?.logTunInboundDrop(
                    reason: event.reason,
                    peerID: event.peerID,
                    chanID: event.chanID,
                    ipVersion: event.ipVersion,
                    sourceIP: event.sourceIP,
                    destinationIP: event.destinationIP,
                    packetBytes: event.packetBytes
                )
            },
            onInboundRelay: { [weak self] event in
                self?.logTunInboundRelay(
                    relay: event.relay,
                    sourceChanID: event.sourceChanID,
                    packet: event.packet,
                    tunRuntime: event.tunRuntime
                )
            },
            onInboundDeliver: { [weak self] event in
                self?.logTunInboundDeliver(
                    packet: event.packet,
                    chanID: event.chanID,
                    tunRuntime: event.tunRuntime
                )
            }
        )
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
        ObstacleBridgeOverlayChannelCore.handleTCPTransportEvent(
            event,
            tcpConnectionStates: &tcpConnectionStates,
            serviceNameByID: serviceNameByID
        )
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
        ObstacleBridgeOverlayChannelCore.recordTraffic(
            proto: proto,
            chanID: chanID,
            bytes: bytes,
            direction: "inbound",
            tcpConnectionStates: &tcpConnectionStates,
            udpConnectionStates: &udpConnectionStates
        )
    }

    private func recordOutbound(proto: String, chanID: Int, bytes: Int) {
        ObstacleBridgeOverlayChannelCore.recordTraffic(
            proto: proto,
            chanID: chanID,
            bytes: bytes,
            direction: "outbound",
            tcpConnectionStates: &tcpConnectionStates,
            udpConnectionStates: &udpConnectionStates
        )
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
        ObstacleBridgeOverlayChannelCore.serviceName(spec, serviceNameByID: serviceNameByID)
    }
}
