import Foundation
import Network

final class ObstacleBridgeTcpOverlayTransportOwner {
    typealias EventSink = (String, [String: Any]) -> Void
    typealias TunPacketSink = (Data) -> Void
    private typealias ResolvedAddress = ObstacleBridgeResolvedAddress
    private static let queueSpecificKey = DispatchSpecificKey<Int>()
    private static let lowerLayerUnavailableFallbackNS: UInt64 = UInt64(
        ObstacleBridgeOverlayLayerTransportAdapter.outerReadinessGrace * 1_000_000_000
    )

    private let peerHost: String
    private let peerPort: Int
    private let peerResolveFamily: String
    private let bindHost: String
    private let bindPort: Int
    private let overlayRuntime: ObstacleBridgeTcpOverlayRuntime
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
    private var overlayListener: NWListener?
    private var overlayConnection: NWConnection?
    private var overlayPeerID: Int?
    private var overlayConnected = false
    private var receiveBuffer = Data()
    private var pendingOutboundWires: [Data] = []
    private var outboundSendInFlight = false
    private var overlayEgressWindow = ObstacleBridgeOverlayChannelCore.OverlayEgressWindowState()
    private var lastOverlayRxWallNS: UInt64 = 0
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
    private var secureLinkDueTimer: DispatchSourceTimer?
    private var lowerLayerFallbackWorkItem: DispatchWorkItem?
    private var lowerLayerFallbackDeadlineNS: UInt64?
    private var peerCandidates: [ResolvedAddress] = []
    private var peerCandidateIndex = 0
    private var resolvedPeerHost = ""
    private var observedPeerHost = ""
    private var observedPeerPort = 0
    private var resolvedPeerPort = 0
    private var resolvedPeerFamily = ""
    private var secureLinkHandshakePrimed = false
    private var startupMuxFramesSent = false
    private var startupMuxFramesReplayedWithTunOpen = false
    private lazy var tcpTransportOwner = ObstacleBridgeChannelMuxTCPTransportOwner(
        runtime: ObstacleBridgeChannelMuxTcpRuntime(
            instanceID: muxInstanceID,
            connectionSeq: muxConnectionSeq,
            sessionMaxAppPayload: sessionMaxAppPayload
        ),
        sessionMaxAppPayload: sessionMaxAppPayload,
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
            self?.inflowAllowed() ?? false
        },
        activateClientOnReady: true
    )

    init(
        peerHost: String,
        peerPort: Int,
        peerResolveFamily: String = "prefer-ipv6",
        bindHost: String = "0.0.0.0",
        bindPort: Int = 0,
        overlayRuntime: ObstacleBridgeTcpOverlayRuntime,
        reconnectRetryDelayMS: Int = 30000,
        sessionMaxAppPayload: Int = 65535,
        overlayLayerTransportAdapter: ObstacleBridgeOverlayLayerTransportAdapter? = nil,
        startupMuxFrames: [Data] = [],
        startupMuxFramesProvider: ObstacleBridgeChannelMuxStartupFramesProvider? = nil,
        queue: DispatchQueue = DispatchQueue(label: "ObstacleBridgeTcpOverlayTransportOwner"),
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
        self.peerResolveFamily = peerResolveFamily
        self.bindHost = bindHost
        self.bindPort = max(0, bindPort)
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
        guard !started else {
            return
        }
        guard (!peerHost.isEmpty && peerPort > 0) || bindPort > 0 else {
            return
        }
        started = true
        startSecureLinkDueTimer()
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
        nextReconnectAttemptDeadlineNS = nil
        reconnectWorkItem?.cancel()
        reconnectWorkItem = nil
        secureLinkDueTimer?.cancel()
        secureLinkDueTimer = nil
        lowerLayerFallbackWorkItem?.cancel()
        lowerLayerFallbackWorkItem = nil
        lowerLayerFallbackDeadlineNS = nil
        overlayListener?.cancel()
        overlayListener = nil
        overlayConnection?.cancel()
        overlayConnection = nil
        overlayPeerID = nil
        tcpTransportOwner.stop()
        for connection in udpServerConnections.values {
            connection.cancel()
        }
        udpServerDrivers.removeAll()
        for connection in udpClientConnections.values {
            connection.cancel()
        }
        udpClientDrivers.removeAll()
        udpServerConnections.removeAll()
        udpClientConnections.removeAll()
        tcpConnectionStates.removeAll()
        udpConnectionStates.removeAll()
        activeTunChanIDs.removeAll()
        tunStats = ["rx_msgs": 0, "tx_msgs": 0, "rx_bytes": 0, "tx_bytes": 0]
        receiveBuffer.removeAll(keepingCapacity: false)
        pendingOutboundWires.removeAll(keepingCapacity: false)
        outboundSendInFlight = false
        overlayEgressWindow = ObstacleBridgeOverlayChannelCore.OverlayEgressWindowState()
        resetOverlayTransportEpoch()
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

    func connectionLayersSnapshot() -> [[String: Any]] {
        withOwnerQueue {
            if let overlayLayerTransportAdapter {
                return overlayLayerTransportAdapter.connectionLayersSnapshot(
                    transport: "tcp",
                    transportConnected: overlayConnected
                )
            }
            return ObstacleBridgeOverlayLayerTransportAdapter.connectionLayersSnapshot(
                transport: "tcp",
                transportConnected: overlayConnected,
                compressionEnabled: false,
                secureLinkStatus: nil
            )
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

    func transportSnapshot() -> [String: Any] {
        withOwnerQueue {
            let protocolStats = overlayProtocolStats()
            let connectionLayers = connectionLayersSnapshot()
            return [
                "overlay_connected": overlayConnected,
                "app_ready": ObstacleBridgeOverlayLayerTransportAdapter.appReady(from: connectionLayers),
                "connection_layers": connectionLayers,
                "overlay_bind_host": bindHost,
                "overlay_bind_port": bindPort,
                "overlay_host": peerHost,
                "overlay_port": peerPort,
                "overlay_peer_host": resolvedPeerHost,
                "overlay_peer_port": resolvedPeerPort,
                "overlay_peer_family": resolvedPeerFamily,
                "overlay_peer_candidate_index": peerCandidateIndex,
                "overlay_peer_candidate_count": peerCandidates.count,
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
                "rtt_est_ms": ObstacleBridgeAdminSnapshotSupport.peerMetric("rtt_est_ms", from: ["protocol_stats": protocolStats]),
                "transmit_delay_est_ms": protocolStats["transmit_delay_est_ms"] ?? 0.0,
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
                overlayConnected: inflowAllowed(),
                bufferedFrames: overlayWaitingCount(),
                backpressure: overlayBackpressureSnapshot(),
                transportDelayThresholdMS: overlayLayerTransportAdapter?.transportDelayRotationThresholdMS ?? ObstacleBridgeOverlayChannelCore.tunPostMuxTransportDelayThresholdMS,
                activeTunChanIDs: &activeTunChanIDs,
                tunStats: &tunStats,
                sendMuxFrames: sendMuxFrames,
                startupMuxFramesForNewTunOpen: startupMuxFramesForNewTunOpen
            )
        } catch {
            eventSink?("tcp_overlay_tun_send_failed", [
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
            eventPrefix: "tcp_overlay"
        )
        udpServerDrivers[ObjectIdentifier(connection)] = driver
        driver.start()
        return true
    }

    private func connectOverlay() {
        guard started else {
            return
        }
        let resolved: ResolvedAddress
        do {
            resolved = try currentResolvedPeer()
        } catch {
            eventSink?("tcp_overlay_connect_failed", ["error": error.localizedDescription])
            scheduleReconnect()
            return
        }
        reconnectScheduled = false
        nextReconnectAttemptDeadlineNS = nil
        reconnectWorkItem?.cancel()
        reconnectWorkItem = nil
        reconnectAttempts += 1
        resolvedPeerHost = resolved.host
        resolvedPeerPort = resolved.port
        resolvedPeerFamily = ObstacleBridgePeerAddressResolver.familyName(resolved.family)
        guard let port = NWEndpoint.Port(rawValue: UInt16(resolved.port)) else {
            eventSink?("tcp_overlay_invalid_peer_port", ["port": resolved.port])
            scheduleReconnect()
            return
        }
        let connection = NWConnection(host: NWEndpoint.Host(resolved.host), port: port, using: .tcp)
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
            let endpoint = ObstacleBridgeOverlayConnectionSupport.endpointDescription(connection.endpoint)
            observedPeerHost = endpoint.host
            observedPeerPort = endpoint.port
            let snapshot = overlayRuntime.acceptServerPeer(peerHost: endpoint.host, peerPort: endpoint.port, socketPresent: true)
            overlayPeerID = snapshot.peerID
            overlayConnected = snapshot.overlayConnected
            maybePrimeSecureLinkHandshake()
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
            tunRuntime?.cleanupSharedTunPeerStateOnDisconnect(peerID: peerID)
            overlayPeerID = nil
        } else {
            overlayConnected = false
        }
        resetOverlayTransportEpoch()
    }

    private func handleOverlayState(_ state: NWConnection.State) {
        switch state {
        case .ready:
            overlayConnected = true
            reconnectScheduled = false
            nextReconnectAttemptDeadlineNS = nil
            eventSink?("tcp_overlay_connected", [
                "peer_host": resolvedPeerHost,
                "peer_port": resolvedPeerPort,
            ])
            let snapshot = overlayRuntime.connect(host: resolvedPeerHost, port: resolvedPeerPort, socketPresent: true)
            for payload in snapshot.flushedBuffers {
                sendRawOverlayWire(payload)
            }
            maybePrimeSecureLinkHandshake()
            maybeSendStartupMuxFrames()
            maybeOpenConfiguredTunIfReady()
            receiveFromOverlay()
        case .failed(let error):
            overlayConnected = false
            overlayConnection = nil
            tunRuntime?.cleanupSharedTunPeerStateOnDisconnect(peerID: overlayPeerID)
            resetOverlayTransportEpoch()
            eventSink?("tcp_overlay_connection_failed", ["error": error.localizedDescription])
            scheduleReconnect()
        case .waiting(let error):
            overlayConnected = false
            overlayConnection = nil
            tunRuntime?.cleanupSharedTunPeerStateOnDisconnect(peerID: overlayPeerID)
            resetOverlayTransportEpoch()
            eventSink?("tcp_overlay_connection_waiting", ["error": error.localizedDescription])
            scheduleReconnect()
        case .cancelled:
            overlayConnected = false
            overlayConnection = nil
            tunRuntime?.cleanupSharedTunPeerStateOnDisconnect(peerID: overlayPeerID)
            resetOverlayTransportEpoch()
            scheduleReconnect()
        default:
            break
        }
    }

    private func scheduleReconnect() {
        guard started, !peerHost.isEmpty, peerPort > 0 else {
            return
        }
        advancePeerCandidate()
        reconnectWorkItem?.cancel()
        let workItem = DispatchWorkItem { [weak self] in
            guard let self else {
                return
            }
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
        let candidates = try ObstacleBridgePeerAddressResolver.resolvePeerCandidates(
            host: peerHost,
            port: peerPort,
            mode: mode,
            strictFamily: false,
            errorDomain: "ObstacleBridge.TcpOverlay"
        )
        let bindConstraint = ObstacleBridgePeerAddressResolver.bindFamilyConstraint(bindHost)
        let filtered = candidates.filter { bindConstraint == nil || $0.family == bindConstraint }
        return filtered.isEmpty ? candidates : filtered
    }

    private func currentResolvedPeer() throws -> ResolvedAddress {
        if peerCandidates.isEmpty {
            peerCandidates = try resolvePeerCandidates()
            peerCandidateIndex = 0
        }
        guard !peerCandidates.isEmpty else {
            throw NSError(domain: "ObstacleBridge.TcpOverlay", code: 2, userInfo: [
                NSLocalizedDescriptionKey: "failed to resolve TCP peer \(peerHost):\(peerPort)"
            ])
        }
        if peerCandidateIndex >= peerCandidates.count {
            peerCandidateIndex = 0
        }
        return peerCandidates[peerCandidateIndex]
    }

    private func advancePeerCandidate() {
        guard peerCandidates.count > 1 else { return }
        peerCandidateIndex = (peerCandidateIndex + 1) % peerCandidates.count
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
        lastOverlayRxWallNS = DispatchTime.now().uptimeNanoseconds
        if let adapter = overlayLayerTransportAdapter {
            let snapshot = adapter.handleInboundFrame(
                payload,
                observedPeerHost: observedPeerHost,
                observedPeerPort: observedPeerPort
            )
            for frame in snapshot.emittedFrames {
                sendOverlayTransportPayload(frame)
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
        guard overlayConnected, !secureLinkHandshakePrimed, let adapter = overlayLayerTransportAdapter else {
            return
        }
        do {
            let snapshot = try adapter.handleTransportConnected()
            secureLinkHandshakePrimed = true
            updateLowerLayerFallback()
            for frame in snapshot.emittedFrames {
                sendOverlayTransportPayload(frame)
            }
        } catch {
            eventSink?("tcp_overlay_secure_link_prime_failed", ["error": error.localizedDescription])
        }
    }

    private func startSecureLinkDueTimer() {
        guard secureLinkDueTimer == nil else {
            return
        }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .seconds(1), repeating: .seconds(1))
        timer.setEventHandler { [weak self] in
            self?.handleSecureLinkDueTimer()
        }
        timer.resume()
        secureLinkDueTimer = timer
    }

    private func handleSecureLinkDueTimer() {
        guard started, overlayConnected else {
            return
        }
        flushDueSecureLinkFramesIfNeeded()
        handleLifecycleRotationIfDue()
    }

    private func handleLifecycleRotationIfDue() {
        guard let adapter = overlayLayerTransportAdapter else {
            return
        }
        let protocolStats = overlayProtocolStats()
        let transmitDelayEstMS = protocolStats["transmit_delay_est_ms"] as? Double ?? 0.0
        guard let result = adapter.transportDelayRotationDue(
            transmitDelayEstMS: transmitDelayEstMS,
            candidateCount: peerCandidates.count
        ) ?? adapter.connectionRotationDue(candidateCount: peerCandidates.count)
        else {
            return
        }
        eventSink?("tcp_overlay_lifecycle_rotation", [
            "epoch": result.epoch,
            "candidate_cycle": result.candidateCycle,
            "restart_required": result.restartRequired,
        ])
        guard !result.restartRequired else {
            eventSink?("tcp_overlay_lifecycle_restart_required", ["candidate_cycle": result.candidateCycle])
            return
        }
        overlayConnection?.cancel()
        overlayConnection = nil
        overlayConnected = false
        resetOverlayTransportEpoch()
        scheduleReconnect()
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
                sendOverlayTransportPayload(frame)
            }
            updateLowerLayerFallback()
        } catch {
            eventSink?("tcp_overlay_secure_link_due_frames_failed", ["error": error.localizedDescription])
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
        pendingOutboundWires.removeAll(keepingCapacity: false)
        outboundSendInFlight = false
        overlayEgressWindow = ObstacleBridgeOverlayChannelCore.OverlayEgressWindowState()
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
            eventSink?("tcp_overlay_lower_layer_unavailable", ["reason": reason, "auth_fail_code": status.authFailCode])
            forceReconnectForUnavailableChannel()
            return
        }
        let deadlineNS = DispatchTime.now().uptimeNanoseconds + delayNS
        lowerLayerFallbackDeadlineNS = deadlineNS
        let workItem = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.lowerLayerFallbackWorkItem = nil
            self.lowerLayerFallbackDeadlineNS = nil
            guard self.started, self.overlayConnected, let currentStatus = self.overlayLayerTransportAdapter?.secureLinkStatusSnapshot(), currentStatus.clientMode, !currentStatus.peerConfirmedAuthenticated else {
                return
            }
            let reason = currentStatus.authFailCode != 0 ? "secure_link_failed" : "app_not_ready"
            self.eventSink?("tcp_overlay_lower_layer_unavailable", ["reason": reason, "auth_fail_code": currentStatus.authFailCode])
            self.forceReconnectForUnavailableChannel()
        }
        lowerLayerFallbackWorkItem = workItem
        queue.asyncAfter(deadline: .now() + .nanoseconds(Int(delayNS)), execute: workItem)
    }

    private func forceReconnectForUnavailableChannel() {
        overlayConnected = false
        overlayConnection?.cancel()
        overlayConnection = nil
        receiveBuffer.removeAll(keepingCapacity: false)
        resetOverlayTransportEpoch()
        scheduleReconnect()
    }

    private func maybeSendStartupMuxFrames() {
        guard appReady(), !startupMuxFramesSent else {
            return
        }
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
            eventSink?("tcp_overlay_proactive_tun_open", ["chan_id": snapshot.chanID])
        } catch {
            eventSink?("tcp_overlay_proactive_tun_open_failed", ["error": error.localizedDescription])
        }
    }

    private func startupMuxFramesForNewTunOpen() -> [Data] {
        guard appReady(), !startupMuxFramesReplayedWithTunOpen else { return [] }
        let connectionSeq = tunRuntime?.currentConnectionSeq() ?? muxConnectionSeq
        let frames = startupMuxFramesProvider?(muxInstanceID, connectionSeq) ?? startupMuxFrames
        guard !frames.isEmpty else { return [] }
        startupMuxFramesReplayedWithTunOpen = true
        eventSink?("tcp_overlay_startup_mux_replayed_with_tun_open", [
            "connection_seq": String(connectionSeq),
            "frame_count": frames.count,
        ])
        return frames
    }

    private func currentTunPeerID() -> Int? {
        if let overlayPeerID {
            return overlayPeerID
        }
        if !peerHost.isEmpty, peerPort > 0, appReady() {
            return 1
        }
        return nil
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
            sendMuxFrames: sendMuxFrames
        )
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
            failureEvent: "tcp_overlay_udp_client_failed",
            handleClosed: { [weak self] in
                self?.closeUDPClientConnection(chanID: chanID)
            }
        )
        udpClientDrivers[chanID] = driver
        driver.start()
    }

    private func closeUDPClientConnection(chanID: Int) {
        let driver = udpClientDrivers.removeValue(forKey: chanID)
        driver?.stop()
        let connection = udpClientConnections.removeValue(forKey: chanID)
        connection?.stateUpdateHandler = nil
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
        guard !payload.isEmpty else { return }
        pendingOutboundWires.append(payload)
        ObstacleBridgeOverlayChannelCore.recordOverlayEgress(
            bytes: payload.count,
            state: &overlayEgressWindow
        )
        flushNextOutboundWireIfNeeded()
    }

    private func flushNextOutboundWireIfNeeded() {
        guard !outboundSendInFlight, let connection = overlayConnection, !pendingOutboundWires.isEmpty else {
            return
        }
        outboundSendInFlight = true
        let payload = pendingOutboundWires.removeFirst()
        connection.send(content: payload, completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            self.queue.async {
                self.outboundSendInFlight = false
                if let error {
                    self.eventSink?("tcp_overlay_send_failed", ["error": error.localizedDescription])
                    self.pendingOutboundWires.removeAll(keepingCapacity: false)
                    return
                }
                self.flushNextOutboundWireIfNeeded()
            }
        })
    }

    private func overlayWaitingCount() -> Int {
        pendingOutboundWires.count + (outboundSendInFlight ? 1 : 0)
    }

    private func overlayBackpressureSnapshot() -> ObstacleBridgeChannelMuxTunRuntime.OverlayBackpressureSnapshot {
        ObstacleBridgeOverlayChannelCore.backpressureSnapshot(
            waitingCount: overlayWaitingCount(),
            inflight: outboundSendInFlight ? 1 : 0,
            maxInflight: 1,
            egressWindow: overlayEgressWindow
        )
    }

    private func overlayProtocolStats() -> [String: Any] {
        ObstacleBridgeOverlayChannelCore.overlayProtocolStats(
            waitingCount: overlayWaitingCount(),
            inflight: outboundSendInFlight ? 1 : 0,
            maxInflight: 1,
            egressWindow: overlayEgressWindow
        )
    }

    private func sendOnUDPConnection(_ connection: NWConnection, payload: Data, chanID: Int) {
        connection.send(content: payload, completion: .contentProcessed { [weak self] error in
            guard let self, let error else { return }
            self.queue.async {
                self.eventSink?("tcp_overlay_udp_client_write_failed", ["chan_id": chanID, "error": error.localizedDescription])
            }
        })
    }

    private func handleUDPServerConnectionState(_ state: NWConnection.State) {
        if case .failed(let error) = state {
            eventSink?("tcp_overlay_udp_server_connection_failed", ["error": error.localizedDescription])
        }
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

    private func serviceName(_ spec: ObstacleBridgeChannelMuxCodec.ServiceSpec) -> String {
        ObstacleBridgeOverlayChannelCore.serviceName(spec, serviceNameByID: serviceNameByID)
    }

    private func handleTCPTransportEvent(_ event: ObstacleBridgeChannelMuxTCPTransportOwner.TransportEvent) {
        ObstacleBridgeOverlayChannelCore.handleTCPTransportEvent(
            event,
            tcpConnectionStates: &tcpConnectionStates,
            serviceNameByID: serviceNameByID
        )
    }
}
