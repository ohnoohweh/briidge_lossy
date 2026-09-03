import Foundation
import Network
import Security
import Darwin

final class ObstacleBridgeWebSocketOverlayTransportOwner: NSObject, URLSessionWebSocketDelegate, URLSessionTaskDelegate {
    typealias EventSink = (String, [String: Any]) -> Void
    typealias TunPacketSink = (Data) -> Void
    private typealias ResolvedAddress = ObstacleBridgeResolvedAddress
    private static let queueSpecificKey = DispatchSpecificKey<Int>()
    private static let lowerLayerUnavailableFallbackNS: UInt64 = UInt64(
        ObstacleBridgeOverlayLayerTransportAdapter.outerReadinessGrace * 1_000_000_000
    )

    private let peerHost: String
    private let peerAddresses: [String]
    private let peerPort: Int
    private let peerResolveFamily: String
    private let useTLS: Bool
    private let wsPath: String
    private let wsSubprotocol: String?
    private let overlayRuntime: ObstacleBridgeWebSocketOverlayRuntime
    private let overlayLayerTransportAdapter: ObstacleBridgeOverlayLayerTransportAdapter?
    private let startupMuxFrames: [Data]
    private let startupMuxFramesProvider: ObstacleBridgeChannelMuxStartupFramesProvider?
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
    private var websocketConnection: NWConnection?
    private var websocketTransportGeneration = 0
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
    private var nextReconnectAttemptDeadlineNS: UInt64?
    private var lowerLayerFallbackWorkItem: DispatchWorkItem?
    private var lowerLayerFallbackDeadlineNS: UInt64?
    private var secureLinkHandshakePrimed = false
    private var startupMuxFramesSent = false
    private var startupMuxFramesReplayedWithTunOpen = false
    private var connectedURI = ""
    private var resolvedPeerHost = ""
    private var resolvedPeerPort = 0
    private var resolvedPeerFamily = ""
    private var resolvedPeerCandidateIndex = 0
    private var resolvedPeerCandidates: [ResolvedAddress] = []
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
            self?.inflowAllowed() ?? false
        },
        activateClientOnReady: true
    )

    init(
        peerHost: String,
        peerAddresses: [String] = [],
        peerPort: Int,
        peerResolveFamily: String = "prefer-ipv6",
        useTLS: Bool = false,
        wsPath: String = "/",
        wsSubprotocol: String? = nil,
        overlayRuntime: ObstacleBridgeWebSocketOverlayRuntime,
        reconnectRetryDelayMS: Int = 30000,
        sessionMaxAppPayload: Int = 65535,
        overlayLayerTransportAdapter: ObstacleBridgeOverlayLayerTransportAdapter? = nil,
        startupMuxFrames: [Data] = [],
        startupMuxFramesProvider: ObstacleBridgeChannelMuxStartupFramesProvider? = nil,
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
        self.peerAddresses = peerAddresses
            .map { ObstacleBridgePeerAddressResolver.stripBrackets($0) }
            .filter { !$0.isEmpty }
        self.peerPort = peerPort
        self.peerResolveFamily = peerResolveFamily
        self.useTLS = useTLS
        self.wsPath = wsPath.isEmpty ? "/" : wsPath
        self.wsSubprotocol = wsSubprotocol?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.overlayRuntime = overlayRuntime
        self.reconnectRetryDelayMS = max(0, reconnectRetryDelayMS)
        self.sessionMaxAppPayload = max(0, sessionMaxAppPayload)
        self.overlayLayerTransportAdapter = overlayLayerTransportAdapter
        self.startupMuxFrames = startupMuxFrames
        self.startupMuxFramesProvider = startupMuxFramesProvider
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
        nextReconnectAttemptDeadlineNS = nil
        reconnectWorkItem?.cancel()
        reconnectWorkItem = nil
        lowerLayerFallbackWorkItem?.cancel()
        lowerLayerFallbackWorkItem = nil
        lowerLayerFallbackDeadlineNS = nil
        websocketTask?.cancel(with: .goingAway, reason: nil)
        websocketTask = nil
        websocketSession?.invalidateAndCancel()
        websocketSession = nil
        websocketConnection?.cancel()
        websocketConnection = nil
        websocketTransportGeneration += 1
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
                serviceNameByID: serviceNameByID,
                bufferedFrames: overlayWaitingCount(),
                backpressure: overlayBackpressureSnapshot()
            )
            return (tcpRows, udpRows, tunRows)
        }
    }

    func transportSnapshot() -> [String: Any] {
        withOwnerQueue {
            let protocolStats = overlayProtocolStats()
            let connectionLayers = connectionLayersSnapshot()
            return [
                "overlay_connected": overlayConnected,
                "app_ready": ObstacleBridgeOverlayLayerTransportAdapter.appReady(from: connectionLayers),
                "connection_layers": connectionLayers,
                "overlay_host": peerHost,
                "overlay_port": peerPort,
                "overlay_peer_host": resolvedPeerHost,
                "overlay_peer_port": resolvedPeerPort,
                "overlay_peer_family": resolvedPeerFamily,
                "overlay_peer_candidate_index": resolvedPeerCandidateIndex,
                "overlay_peer_candidate_count": resolvedPeerCandidates.count,
                "uri": connectedURI,
                "payload_mode": overlayRuntime.configuredPayloadMode,
                "ws_path": wsPath,
                "ws_tls": useTLS,
                "reconnect_retry_delay_ms": reconnectRetryDelayMS,
                "reconnect_attempts": reconnectAttempts,
                "reconnect_scheduled": reconnectScheduled,
                "next_address_attempt_in_seconds": nextAddressAttemptInSeconds() ?? NSNull(),
                "restart_in_seconds": NSNull(),
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

    func requestSecureLinkRekey() -> [String: Any] {
        withOwnerQueue {
            guard started, overlayConnected, let adapter = overlayLayerTransportAdapter else {
                return ["ok": false, "reason": "transport_not_connected"]
            }
            do {
                let snapshot = try adapter.requestSecureLinkRekey()
                for frame in snapshot.emittedFrames {
                    sendOverlayTransportPayload(frame)
                }
                return [
                    "ok": true,
                    "reason": "rekey_started",
                    "emitted_frames": snapshot.emittedFrames.count,
                ]
            } catch {
                return [
                    "ok": false,
                    "reason": "rekey_request_failed",
                    "detail": error.localizedDescription,
                ]
            }
        }
    }

    func connectionLayersSnapshot() -> [[String: Any]] {
        withOwnerQueue {
            if let overlayLayerTransportAdapter {
                return overlayLayerTransportAdapter.connectionLayersSnapshot(
                    transport: "ws",
                    transportConnected: overlayConnected
                )
            }
            return ObstacleBridgeOverlayLayerTransportAdapter.connectionLayersSnapshot(
                transport: "ws",
                transportConnected: overlayConnected,
                compressionEnabled: false,
                secureLinkStatus: nil
            )
        }
    }

    func appReady() -> Bool {
        ObstacleBridgeOverlayLayerTransportAdapter.appReady(from: connectionLayersSnapshot())
    }

    func inflowAllowed() -> Bool {
        ObstacleBridgeOverlayLayerTransportAdapter.inflowAllowed(from: connectionLayersSnapshot())
    }

    func tunConnectivityTestsAllowed() -> Bool {
        withOwnerQueue {
            ObstacleBridgeOverlayChannelCore.tunConnectivityTestsAllowed(
                tunRuntime: tunRuntime,
                backpressure: overlayBackpressureSnapshot()
            )
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
                overlayConnected: inflowAllowed(),
                bufferedFrames: overlayWaitingCount(),
                backpressure: overlayBackpressureSnapshot(),
                activeTunChanIDs: &activeTunChanIDs,
                tunStats: &tunStats,
                sendMuxFrames: sendMuxFrames,
                startupMuxFramesForNewTunOpen: startupMuxFramesForNewTunOpen,
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
            overlayConnectedProvider: { [weak self] in self?.appReady() ?? false },
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
            self.handleWebSocketTransportConnected(generation: self.websocketTransportGeneration)
        }
    }

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didCloseWith closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) {
        queue.async {
            guard self.websocketTask === webSocketTask else { return }
            self.tunRuntime?.cleanupSharedTunPeerStateOnDisconnect(peerID: self.currentTunPeerID())
            self.overlayConnected = false
            self.websocketTask = nil
            self.websocketSession = nil
            self.websocketTransportGeneration += 1
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
            self.websocketTransportGeneration += 1
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
        nextReconnectAttemptDeadlineNS = nil
        reconnectWorkItem?.cancel()
        reconnectWorkItem = nil
        reconnectAttempts += 1

        // A URLSession/NWConnection replacement is a new ChannelMux peer
        // epoch even when the previous WebSocket did not deliver a close or
        // completion callback.  The remote peer has discarded its channel
        // table in that case; retaining the local preferred TUN channel would
        // emit DATA without the OPEN required to bind Shared TUN routing.
        // Reset before allocating the task so the first local packet on this
        // connection necessarily emits a fresh TUN OPEN followed by DATA.
        resetOverlayTransportEpoch()
        websocketTransportGeneration += 1
        let generation = websocketTransportGeneration
        do {
            let resolved = try currentResolvedPeer()
            let usesAddressOverride = !peerAddresses.isEmpty
            let plan = overlayRuntime.buildConnectPlan(
                host: resolved.host,
                port: resolved.port,
                peerNameHost: usesAddressOverride ? peerHost : nil,
                peerNamePort: usesAddressOverride ? peerPort : nil,
                useTLS: useTLS,
                wsPath: wsPath,
                wsSubprotocol: wsSubprotocol,
                proxyActive: false
            )
            resolvedPeerHost = resolved.host
            resolvedPeerPort = resolved.port
            resolvedPeerFamily = ObstacleBridgePeerAddressResolver.familyName(resolved.family)
            connectedURI = plan.uri
            if usesAddressOverride {
                try connectNetworkWebSocket(resolved: resolved, plan: plan, generation: generation)
                return
            }
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

    private func connectNetworkWebSocket(
        resolved: ResolvedAddress,
        plan: ObstacleBridgeWebSocketOverlayRuntime.ConnectPlan,
        generation: Int
    ) throws {
        let physicalHost = resolved.host.contains(":") ? "[\(resolved.host)]" : resolved.host
        let scheme = useTLS ? "wss" : "ws"
        guard let physicalURL = URL(string: "\(scheme)://\(physicalHost):\(resolved.port)\(wsPath)") else {
            throw URLError(.badURL)
        }
        let webSocketOptions = NWProtocolWebSocket.Options(.version13)
        webSocketOptions.autoReplyPing = true
        webSocketOptions.maximumMessageSize = plan.maxSize
        var headers = plan.upgradeHeaders.map { (name: $0.key, value: $0.value) }
        let logicalHost = peerHost.contains(":") ? "[\(peerHost)]" : peerHost
        headers.append((name: "Host", value: "\(logicalHost):\(peerPort)"))
        webSocketOptions.setAdditionalHeaders(headers)
        if let subprotocols = plan.subprotocols {
            webSocketOptions.setSubprotocols(subprotocols)
        }

        let parameters: NWParameters
        if useTLS {
            let tlsOptions = NWProtocolTLS.Options()
            peerHost.withCString { serverName in
                sec_protocol_options_set_tls_server_name(tlsOptions.securityProtocolOptions, serverName)
            }
            parameters = NWParameters(tls: tlsOptions, tcp: NWProtocolTCP.Options())
        } else {
            parameters = NWParameters.tcp
        }
        parameters.defaultProtocolStack.applicationProtocols.insert(webSocketOptions, at: 0)
        let connection = NWConnection(to: .url(physicalURL), using: parameters)
        websocketConnection = connection
        connection.stateUpdateHandler = { [weak self, weak connection] state in
            self?.queue.async {
                guard let self, let connection, self.websocketConnection === connection,
                      self.websocketTransportGeneration == generation else { return }
                switch state {
                case .ready:
                    self.handleWebSocketTransportConnected(generation: generation)
                case .failed(let error):
                    self.handleNetworkWebSocketFailure(error, connection: connection, generation: generation)
                case .waiting(let error):
                    self.handleNetworkWebSocketFailure(error, connection: connection, generation: generation)
                case .cancelled:
                    if self.started, self.overlayConnected {
                        self.handleNetworkWebSocketFailure(
                            NSError(
                                domain: NSPOSIXErrorDomain,
                                code: Int(ECANCELED),
                                userInfo: [NSLocalizedDescriptionKey: "WebSocket connection cancelled"]
                            ),
                            connection: connection,
                            generation: generation
                        )
                    }
                default:
                    break
                }
            }
        }
        connection.start(queue: queue)
    }

    private func handleWebSocketTransportConnected(generation: Int) {
        guard started, websocketTransportGeneration == generation else { return }
        overlayConnected = true
        reconnectScheduled = false
        nextReconnectAttemptDeadlineNS = nil
        eventSink?("ws_overlay_connected", [
            "peer_host": resolvedPeerHost,
            "peer_port": resolvedPeerPort,
            "uri": connectedURI,
        ])
        pendingOutboundMessages.removeAll(keepingCapacity: false)
        outboundSendInFlight = false
        maybePrimeSecureLinkHandshake()
        maybeSendStartupMuxFrames()
        maybeOpenConfiguredTunIfReady()
        scheduleNextRTTPing(generation: generation)
        receiveFromOverlay()
    }

    private func handleNetworkWebSocketFailure(
        _ error: Error,
        connection: NWConnection,
        generation: Int
    ) {
        guard websocketConnection === connection, websocketTransportGeneration == generation else { return }
        tunRuntime?.cleanupSharedTunPeerStateOnDisconnect(peerID: currentTunPeerID())
        overlayConnected = false
        websocketConnection = nil
        websocketTransportGeneration += 1
        connection.cancel()
        resetOverlayTransportEpoch()
        eventSink?("ws_overlay_connection_failed", ["error": error.localizedDescription])
        scheduleReconnect()
    }

    private func scheduleReconnect() {
        guard started, !peerHost.isEmpty, peerPort > 0 else { return }
        advancePeerCandidate()
        reconnectWorkItem?.cancel()
        let workItem = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.reconnectScheduled = false
            self.nextReconnectAttemptDeadlineNS = nil
            self.reconnectWorkItem = nil
            self.connectOverlay()
        }
        reconnectWorkItem = workItem
        reconnectScheduled = true
        nextReconnectAttemptDeadlineNS = DispatchTime.now().uptimeNanoseconds + UInt64(reconnectRetryDelayMS) * 1_000_000
        queue.asyncAfter(deadline: .now() + .milliseconds(reconnectRetryDelayMS), execute: workItem)
    }

    private func nextAddressAttemptInSeconds() -> Double? {
        guard reconnectScheduled, let deadline = nextReconnectAttemptDeadlineNS else {
            return nil
        }
        let now = DispatchTime.now().uptimeNanoseconds
        guard deadline > now else {
            return 0.0
        }
        return Double(deadline - now) / 1_000_000_000.0
    }

    private func resolvePeerCandidates() throws -> [ResolvedAddress] {
        let mode = ObstacleBridgePeerAddressResolver.ResolveMode(rawValue: peerResolveFamily)
        if !peerAddresses.isEmpty {
            var candidates: [ResolvedAddress] = []
            for address in peerAddresses {
                guard ObstacleBridgePeerAddressResolver.hostIPFamily(address) != nil else {
                    throw NSError(
                        domain: "ObstacleBridge.WebSocketOverlay",
                        code: 4,
                        userInfo: [NSLocalizedDescriptionKey: "WebSocket peer address '\(address)' is not an IPv4 or IPv6 literal"]
                    )
                }
                let resolved = try ObstacleBridgePeerAddressResolver.resolvePeerCandidates(
                    host: address,
                    port: peerPort,
                    mode: mode,
                    strictFamily: false,
                    errorDomain: "ObstacleBridge.WebSocketOverlay"
                )
                for candidate in resolved where !candidates.contains(where: {
                    $0.family == candidate.family && $0.host == candidate.host && $0.port == candidate.port
                }) {
                    candidates.append(candidate)
                }
            }
            return candidates.enumerated().sorted { lhs, rhs in
                let lhsRank = mode.rank(for: lhs.element.family)
                let rhsRank = mode.rank(for: rhs.element.family)
                return lhsRank == rhsRank ? lhs.offset < rhs.offset : lhsRank < rhsRank
            }.map(\.element)
        }
        return try ObstacleBridgePeerAddressResolver.resolvePeerCandidates(
            host: peerHost,
            port: peerPort,
            mode: mode,
            strictFamily: false,
            errorDomain: "ObstacleBridge.WebSocketOverlay"
        )
    }

    private func currentResolvedPeer() throws -> ResolvedAddress {
        if resolvedPeerCandidates.isEmpty {
            resolvedPeerCandidates = try resolvePeerCandidates()
            resolvedPeerCandidateIndex = 0
        }
        guard !resolvedPeerCandidates.isEmpty else {
            throw NSError(domain: "ObstacleBridge.WebSocketOverlay", code: 2, userInfo: [
                NSLocalizedDescriptionKey: "failed to resolve WebSocket peer \(peerHost):\(peerPort)"
            ])
        }
        if resolvedPeerCandidateIndex >= resolvedPeerCandidates.count {
            resolvedPeerCandidateIndex = 0
        }
        return resolvedPeerCandidates[resolvedPeerCandidateIndex]
    }

    private func advancePeerCandidate() {
        guard resolvedPeerCandidates.count > 1 else { return }
        resolvedPeerCandidateIndex = (resolvedPeerCandidateIndex + 1) % resolvedPeerCandidates.count
    }

    private func receiveFromOverlay() {
        if let connection = websocketConnection {
            receiveFromNetworkWebSocket(connection: connection, generation: websocketTransportGeneration)
            return
        }
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
                    self.websocketTransportGeneration += 1
                    self.resetOverlayTransportEpoch()
                    self.eventSink?("ws_overlay_receive_failed", ["error": error.localizedDescription])
                    self.scheduleReconnect()
                }
            }
        }
    }

    private func receiveFromNetworkWebSocket(connection: NWConnection, generation: Int) {
        guard started, websocketConnection === connection, websocketTransportGeneration == generation else { return }
        connection.receiveMessage { [weak self, weak connection] content, context, _isComplete, error in
            self?.queue.async {
                guard let self, let connection, self.started,
                      self.websocketConnection === connection,
                      self.websocketTransportGeneration == generation else { return }
                if let error {
                    self.handleNetworkWebSocketFailure(error, connection: connection, generation: generation)
                    return
                }
                guard let content,
                      let metadata = context?.protocolMetadata(definition: NWProtocolWebSocket.definition)
                        as? NWProtocolWebSocket.Metadata else {
                    self.eventSink?("ws_overlay_decode_failed", ["error": "missing WebSocket message metadata"])
                    self.receiveFromNetworkWebSocket(connection: connection, generation: generation)
                    return
                }
                do {
                    let message: URLSessionWebSocketTask.Message
                    switch metadata.opcode {
                    case .text:
                        guard let text = String(data: content, encoding: .utf8) else {
                            throw NSError(
                                domain: "ObstacleBridge.WebSocketOverlay",
                                code: 3,
                                userInfo: [NSLocalizedDescriptionKey: "invalid UTF-8 WebSocket text message"]
                            )
                        }
                        message = .string(text)
                    case .binary:
                        message = .data(content)
                    default:
                        self.receiveFromNetworkWebSocket(connection: connection, generation: generation)
                        return
                    }
                    let frame = try self.overlayRuntime.decodeClientFrame(message)
                    self.handleWebSocketFrame(frame)
                } catch {
                    self.eventSink?("ws_overlay_decode_failed", ["error": error.localizedDescription])
                }
                self.receiveFromNetworkWebSocket(connection: connection, generation: generation)
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
            let snapshot = adapter.handleInboundFrame(payload, observedPeerHost: resolvedPeerHost)
            for frame in snapshot.emittedFrames {
                sendRawOverlayWire(frame)
            }
            for delivered in snapshot.deliveredPayloads {
                handleOverlayPayload(delivered)
            }
            updateLowerLayerFallback()
            maybeSendStartupMuxFrames()
            maybeOpenConfiguredTunIfReady()
            return
        }
        handleOverlayPayload(payload)
    }

    private func maybePrimeSecureLinkHandshake() {
        guard overlayConnected, !secureLinkHandshakePrimed, let adapter = overlayLayerTransportAdapter else { return }
        do {
            let snapshot = try adapter.handleTransportConnected()
            secureLinkHandshakePrimed = true
            updateLowerLayerFallback()
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
        tunRuntime?.resetTransportEpoch()
        activeTunChanIDs.removeAll()
        secureLinkHandshakePrimed = false
        lowerLayerFallbackWorkItem?.cancel()
        lowerLayerFallbackWorkItem = nil
        lowerLayerFallbackDeadlineNS = nil
        startupMuxFramesSent = false
        startupMuxFramesReplayedWithTunOpen = false
        pendingOutboundMessages.removeAll(keepingCapacity: false)
        outboundSendInFlight = false
        overlayEgressWindow = ObstacleBridgeOverlayChannelCore.OverlayEgressWindowState()
        lastPeerPingTxNS = 0
        lastRttOkNS = 0
        rttEstMS = nil
    }

    private func updateLowerLayerFallback() {
        guard started, overlayConnected, !peerHost.isEmpty, peerPort > 0, let adapter = overlayLayerTransportAdapter else {
            lowerLayerFallbackWorkItem?.cancel()
            lowerLayerFallbackWorkItem = nil
            lowerLayerFallbackDeadlineNS = nil
            return
        }
        let status = adapter.secureLinkStatusSnapshot()
        guard let status, status.clientMode, !status.peerConfirmedAuthenticated else {
            lowerLayerFallbackWorkItem?.cancel()
            lowerLayerFallbackWorkItem = nil
            lowerLayerFallbackDeadlineNS = nil
            return
        }
        let delayNS = Self.lowerLayerUnavailableFallbackNS
        lowerLayerFallbackWorkItem?.cancel()
        lowerLayerFallbackWorkItem = nil
        if delayNS == 0 {
            let reason = status.authFailCode != 0 ? "secure_link_failed" : "app_not_ready"
            eventSink?("ws_overlay_lower_layer_unavailable", ["reason": reason, "auth_fail_code": status.authFailCode])
            forceReconnectForUnavailableChannel()
            return
        }
        lowerLayerFallbackDeadlineNS = DispatchTime.now().uptimeNanoseconds + delayNS
        let workItem = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.lowerLayerFallbackWorkItem = nil
            self.lowerLayerFallbackDeadlineNS = nil
            guard self.started, self.overlayConnected, let currentStatus = self.overlayLayerTransportAdapter?.secureLinkStatusSnapshot(), currentStatus.clientMode, !currentStatus.peerConfirmedAuthenticated else {
                return
            }
            let reason = currentStatus.authFailCode != 0 ? "secure_link_failed" : "app_not_ready"
            self.eventSink?("ws_overlay_lower_layer_unavailable", ["reason": reason, "auth_fail_code": currentStatus.authFailCode])
            self.forceReconnectForUnavailableChannel()
        }
        lowerLayerFallbackWorkItem = workItem
        queue.asyncAfter(deadline: .now() + .nanoseconds(Int(delayNS)), execute: workItem)
    }

    private func forceReconnectForUnavailableChannel() {
        overlayConnected = false
        websocketTask?.cancel(with: .goingAway, reason: nil)
        websocketTask = nil
        websocketSession = nil
        websocketConnection?.cancel()
        websocketConnection = nil
        websocketTransportGeneration += 1
        resetOverlayTransportEpoch()
        scheduleReconnect()
    }

    private func maybeSendStartupMuxFrames() {
        guard appReady(), !startupMuxFramesSent else { return }
        let connectionSeq = tunRuntime?.currentConnectionSeq() ?? muxConnectionSeq
        let frames = startupMuxFramesProvider?(muxInstanceID, connectionSeq) ?? startupMuxFrames
        guard !frames.isEmpty else { return }
        startupMuxFramesSent = true
        sendMuxFrames(frames)
    }

    private func maybeOpenConfiguredTunIfReady() {
        do {
            guard let snapshot = try ObstacleBridgeOverlayChannelCore.openConfiguredLocalTunIfReady(
                started: started,
                tunRuntime: tunRuntime,
                tunServiceSpec: tunServiceSpec,
                tunIfname: tunIfname,
                tunMTU: tunMTU,
                overlayConnected: appReady(),
                activeTunChanIDs: &activeTunChanIDs
            ) else { return }
            let startupFrames = startupMuxFramesForNewTunOpen()
            sendMuxFrames(startupFrames + snapshot.frames)
            eventSink?("ws_overlay_proactive_tun_open", ["chan_id": snapshot.chanID])
        } catch {
            eventSink?("ws_overlay_proactive_tun_open_failed", ["error": error.localizedDescription])
        }
    }

    private func startupMuxFramesForNewTunOpen() -> [Data] {
        guard appReady(), !startupMuxFramesReplayedWithTunOpen else { return [] }
        let connectionSeq = tunRuntime?.currentConnectionSeq() ?? muxConnectionSeq
        let frames = startupMuxFramesProvider?(muxInstanceID, connectionSeq) ?? startupMuxFrames
        guard !frames.isEmpty else { return [] }
        startupMuxFramesReplayedWithTunOpen = true
        eventSink?("ws_overlay_startup_mux_replayed_with_tun_open", [
            "connection_seq": String(connectionSeq),
            "frame_count": frames.count,
        ])
        return frames
    }

    private func currentTunPeerID() -> Int? {
        appReady() ? 1 : nil
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
        guard started, overlayConnected else { return }
        let generation = websocketTransportGeneration
        do {
            let message = try overlayRuntime.encodeClientPong(echoTxNS: echoTxNS)
            sendActiveWebSocketMessage(message, generation: generation) { [weak self] error in
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

    private func scheduleNextRTTPing(generation: Int) {
        queue.asyncAfter(deadline: .now() + .seconds(1)) { [weak self] in
            guard let self else { return }
            self.sendRTTPingAndReschedule(generation: generation)
        }
    }

    private func sendRTTPingAndReschedule(generation: Int) {
        guard started, overlayConnected, websocketTransportGeneration == generation else { return }
        flushDueSecureLinkFramesIfNeeded()
        handleLifecycleRotationIfDue()
        let txNS = DispatchTime.now().uptimeNanoseconds
        do {
            let message = try overlayRuntime.encodeClientPing(txNS: txNS, echoNS: lastPeerPingTxNS)
            sendActiveWebSocketMessage(message, generation: generation) { [weak self] error in
                self?.queue.async {
                    guard let self, self.websocketTransportGeneration == generation else { return }
                    if let error {
                        self.eventSink?("ws_overlay_ping_send_failed", [
                            "tx_ns": String(txNS),
                            "error": error.localizedDescription,
                        ])
                    }
                    self.scheduleNextRTTPing(generation: generation)
                }
            }
        } catch {
            eventSink?("ws_overlay_control_encode_failed", ["error": error.localizedDescription])
            scheduleNextRTTPing(generation: generation)
        }
    }

    private func flushDueSecureLinkFramesIfNeeded() {
        guard let adapter = overlayLayerTransportAdapter else {
            return
        }
        do {
            let snapshot = try adapter.pollSecureLinkDueFrames()
            guard !snapshot.emittedFrames.isEmpty else {
                return
            }
            for frame in snapshot.emittedFrames {
                sendRawOverlayWire(frame)
            }
            updateLowerLayerFallback()
        } catch {
            eventSink?("ws_overlay_secure_link_due_frames_failed", ["error": error.localizedDescription])
        }
    }

    private func handleLifecycleRotationIfDue() {
        guard let adapter = overlayLayerTransportAdapter,
              let result = adapter.connectionRotationDue(candidateCount: resolvedPeerCandidates.count)
        else {
            return
        }
        eventSink?("ws_overlay_lifecycle_rotation", [
            "epoch": result.epoch,
            "candidate_cycle": result.candidateCycle,
            "restart_required": result.restartRequired,
        ])
        guard !result.restartRequired else {
            eventSink?("ws_overlay_lifecycle_restart_required", ["candidate_cycle": result.candidateCycle])
            return
        }
        websocketTask?.cancel(with: .goingAway, reason: nil)
        websocketConnection?.cancel()
        overlayConnected = false
        resetOverlayTransportEpoch()
        scheduleReconnect()
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
        guard started, overlayConnected, websocketTask != nil || websocketConnection != nil else { return }
        do {
            let message = try overlayRuntime.encodeClientWire(wire)
            pendingOutboundMessages.append(message)
            ObstacleBridgeOverlayChannelCore.recordOverlayEgress(
                bytes: wire.count,
                state: &overlayEgressWindow
            )
            flushNextOutboundMessageIfNeeded()
        } catch {
            eventSink?("ws_overlay_encode_failed", ["error": error.localizedDescription])
        }
    }

    private func flushNextOutboundMessageIfNeeded() {
        guard started, overlayConnected, websocketTask != nil || websocketConnection != nil,
              !outboundSendInFlight, !pendingOutboundMessages.isEmpty else {
            return
        }
        let generation = websocketTransportGeneration
        outboundSendInFlight = true
        let message = pendingOutboundMessages.removeFirst()
        sendActiveWebSocketMessage(message, generation: generation) { [weak self] error in
            self?.queue.async {
                guard let self, self.websocketTransportGeneration == generation else { return }
                self.outboundSendInFlight = false
                if let error {
                    self.eventSink?("ws_overlay_send_failed", ["error": error.localizedDescription])
                    self.pendingOutboundMessages.removeAll(keepingCapacity: false)
                    return
                }
                self.flushNextOutboundMessageIfNeeded()
            }
        }
    }

    private func sendActiveWebSocketMessage(
        _ message: URLSessionWebSocketTask.Message,
        generation: Int,
        completion: @escaping (Error?) -> Void
    ) {
        guard websocketTransportGeneration == generation else {
            completion(URLError(.cancelled))
            return
        }
        if let task = websocketTask {
            task.send(message) { error in completion(error) }
            return
        }
        guard let connection = websocketConnection else {
            completion(URLError(.notConnectedToInternet))
            return
        }
        let content: Data
        let opcode: NWProtocolWebSocket.Opcode
        switch message {
        case .data(let data):
            content = data
            opcode = .binary
        case .string(let text):
            content = Data(text.utf8)
            opcode = .text
        @unknown default:
            completion(URLError(.cannotDecodeContentData))
            return
        }
        let metadata = NWProtocolWebSocket.Metadata(opcode: opcode)
        let context = NWConnection.ContentContext(
            identifier: "obstaclebridge.websocket.message",
            metadata: [metadata]
        )
        connection.send(
            content: content,
            contentContext: context,
            isComplete: true,
            completion: .contentProcessed { error in completion(error) }
        )
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
            overlayConnected: appReady(),
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
