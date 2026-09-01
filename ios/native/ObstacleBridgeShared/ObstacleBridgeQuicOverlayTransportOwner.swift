import Foundation
import Network

@available(iOS 15.0, *)
final class ObstacleBridgeQuicOverlayTransportOwner {
    typealias EventSink = (String, [String: Any]) -> Void
    typealias TunPacketSink = (Data) -> Void
    private typealias ResolvedAddress = ObstacleBridgeResolvedAddress
    private static let queueSpecificKey = DispatchSpecificKey<Int>()
    private static let lowerLayerUnavailableFallbackNS: UInt64 = 5_000_000_000

    // Keep Swift QUIC writes capped at 1024 bytes. Network.framework has been
    // observed to stall larger single stream writes in the mixed Swift/Python
    // service-forwarding path, while 1024-byte chunks are proven by the current
    // QUIC design notes and integration tests. Do not "optimize" this away
    // without updating docs/QUIC_DESIGN.md and re-proving larger writes.
    private static let maxNetworkFrameworkWriteBytes = 1024

    private let peerHost: String
    private let peerPort: Int
    private let bindHost: String
    private let bindPort: Int
    private let peerResolveFamily: String
    private let alpn: String
    private let insecure: Bool
    private let overlayRuntime: ObstacleBridgeQuicOverlayRuntime
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
    private var overlayConnection: NWConnection?
    private var overlayConnected = false
    private var receiveBuffer = Data()
    private var pendingOutboundWires: [Data] = []
    private var outboundSendInFlight = false
    private var overlayEgressWindow = ObstacleBridgeOverlayChannelCore.OverlayEgressWindowState()
    private var lastOverlayRxWallNS: UInt64 = 0
    private let outboundContentContext = NWConnection.ContentContext(
        identifier: "obstaclebridge-quic-overlay-stream",
        metadata: []
    )
    private var started = false
    private var reconnectAttempts = 0
    private var reconnectScheduled = false
    private var reconnectWorkItem: DispatchWorkItem?
    private var nextReconnectAttemptDeadlineNS: UInt64?
    private var secureLinkDueTimer: DispatchSourceTimer?
    private var lowerLayerFallbackWorkItem: DispatchWorkItem?
    private var lowerLayerFallbackDeadlineNS: UInt64?
    private var startupMuxFramesSent = false
    private var startupMuxFramesReplayedWithTunOpen = false
    private var resolvedPeerHost = ""
    private var resolvedPeerPort = 0
    private var resolvedPeerFamily = ""
    private var resolvedPeerCandidateIndex = 0
    private var resolvedPeerCandidateCount = 0
    private var resolvedPeerCandidates: [ResolvedAddress] = []
    private var tcpConnectionStates: [Int: ObstacleBridgeOverlayConnectionState] = [:]
    private var tunRuntime: ObstacleBridgeChannelMuxTunRuntime?
    private var activeTunChanIDs: Set<Int> = []
    private var tunStats: [String: Int] = ["rx_msgs": 0, "tx_msgs": 0, "rx_bytes": 0, "tx_bytes": 0]
    private lazy var tcpTransportOwner = ObstacleBridgeChannelMuxTCPTransportOwner(
        runtime: ObstacleBridgeChannelMuxTcpRuntime(
            instanceID: muxInstanceID,
            connectionSeq: muxConnectionSeq,
            sessionMaxAppPayload: sessionMaxAppPayload
        ),
        sessionMaxAppPayload: sessionMaxAppPayload,
        queue: queue,
        eventPrefix: "quic_overlay",
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
        bindHost: String = "::",
        bindPort: Int = 0,
        peerResolveFamily: String = "prefer-ipv6",
        alpn: String = "hq-29",
        insecure: Bool = false,
        overlayRuntime: ObstacleBridgeQuicOverlayRuntime,
        reconnectRetryDelayMS: Int = 30000,
        sessionMaxAppPayload: Int = 65535,
        overlayLayerTransportAdapter: ObstacleBridgeOverlayLayerTransportAdapter? = nil,
        startupMuxFrames: [Data] = [],
        startupMuxFramesProvider: ObstacleBridgeChannelMuxStartupFramesProvider? = nil,
        queue: DispatchQueue = DispatchQueue(label: "ObstacleBridgeQuicOverlayTransportOwner"),
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
        self.bindHost = bindHost
        self.bindPort = max(0, bindPort)
        self.peerResolveFamily = peerResolveFamily
        self.alpn = alpn
        self.insecure = insecure
        self.overlayRuntime = overlayRuntime
        self.reconnectRetryDelayMS = max(0, reconnectRetryDelayMS)
        self.sessionMaxAppPayload = max(1, sessionMaxAppPayload)
        self.overlayLayerTransportAdapter = overlayLayerTransportAdapter
        self.startupMuxFrames = startupMuxFrames
        self.startupMuxFramesProvider = startupMuxFramesProvider
        self.queue = queue
        self.eventSink = eventSink
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
        self.queue.setSpecific(key: Self.queueSpecificKey, value: 1)
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
        startSecureLinkDueTimer()
        connectOverlay()
    }

    func stop() {
        guard started else { return }
        started = false
        tunRuntime?.cleanupSharedTunPeerStateOnDisconnect(peerID: currentTunPeerID())
        tunRuntime?.resetTransportEpoch()
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
        overlayConnection?.cancel()
        overlayConnection = nil
        tcpTransportOwner.stop()
        tcpConnectionStates.removeAll()
        activeTunChanIDs.removeAll()
        tunStats = ["rx_msgs": 0, "tx_msgs": 0, "rx_bytes": 0, "tx_bytes": 0]
        receiveBuffer.removeAll(keepingCapacity: false)
        pendingOutboundWires.removeAll(keepingCapacity: false)
        outboundSendInFlight = false
        overlayEgressWindow = ObstacleBridgeOverlayChannelCore.OverlayEgressWindowState()
        startupMuxFramesSent = false
        startupMuxFramesReplayedWithTunOpen = false
    }

    func connectionRows() -> (tcp: [[String: Any]], udp: [[String: Any]], tun: [[String: Any]]) {
        withOwnerQueue {
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
            return (ObstacleBridgeOverlayConnectionSupport.connectionRows(from: tcpConnectionStates), [], tunRows)
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
                "overlay_peer_candidate_index": resolvedPeerCandidateIndex,
                "overlay_peer_candidate_count": resolvedPeerCandidateCount,
                "overlay_alpn": alpn,
                "overlay_insecure": insecure,
                "reconnect_retry_delay_ms": reconnectRetryDelayMS,
                "reconnect_attempts": reconnectAttempts,
                "reconnect_scheduled": reconnectScheduled,
                "next_address_attempt_in_seconds": nextAddressAttemptInSeconds() ?? NSNull(),
                "restart_in_seconds": NSNull(),
                "mux_instance_id": muxInstanceID,
                "mux_connection_seq": muxConnectionSeq,
                "server_tcp_channels": tcpTransportOwner.serverConnectionCount,
                "client_tcp_channels": tcpConnectionStates.count,
                "server_udp_channels": 0,
                "client_udp_channels": 0,
                "tun_channels": activeTunChanIDs.count,
                "tun_stats": tunStats,
                "last_rx_wall_ns": lastOverlayRxWallNS,
                "rtt_est_ms": ObstacleBridgeAdminSnapshotSupport.peerMetric("rtt_est_ms", from: ["protocol_stats": protocolStats]),
                "transmit_delay_est_ms": protocolStats["transmit_delay_est_ms"] ?? 0.0,
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
                sendTransportFrames(snapshot.emittedFrames)
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
                    transport: "quic",
                    transportConnected: overlayConnected
                )
            }
            return ObstacleBridgeOverlayLayerTransportAdapter.connectionLayersSnapshot(
                transport: "quic",
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
                startupMuxFramesForNewTunOpen: startupMuxFramesForNewTunOpen
            )
        } catch {
            eventSink?("quic_overlay_tun_send_failed", [
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
        _ = spec
        _ = listenerHost
        _ = listenerPort
        _ = serviceKey
        connection.cancel()
        return false
    }

    private func connectOverlay() {
        guard started else { return }
        guard let endpointPort = NWEndpoint.Port(rawValue: UInt16(peerPort)) else {
            eventSink?("quic_overlay_invalid_peer_port", ["port": peerPort])
            return
        }
        reconnectScheduled = false
        nextReconnectAttemptDeadlineNS = nil
        reconnectWorkItem?.cancel()
        reconnectWorkItem = nil
        reconnectAttempts += 1
        do {
            let resolved = try currentResolvedPeer()
            resolvedPeerHost = resolved.host
            resolvedPeerPort = resolved.port
            resolvedPeerFamily = resolved.family
            resolvedPeerCandidateIndex = resolved.index
            resolvedPeerCandidateCount = resolved.candidateCount

            let params = makeQUICParameters()
            if bindPort > 0, let localPort = NWEndpoint.Port(rawValue: UInt16(bindPort)) {
                params.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(bindHost), port: localPort)
            }
            let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(resolved.host), port: endpointPort)
            let connection = NWConnection(to: endpoint, using: params)
            overlayConnection = connection
            connection.stateUpdateHandler = { [weak self] state in
                self?.queue.async {
                    self?.handleOverlayState(state)
                }
            }
            connection.start(queue: queue)
            receiveOverlayData()
        } catch {
            eventSink?("quic_overlay_connect_failed", ["error": error.localizedDescription])
            scheduleReconnect()
        }
    }

    private func makeQUICParameters() -> NWParameters {
        let quicOptions = NWProtocolQUIC.Options(alpn: [alpn])
        quicOptions.direction = .bidirectional
        if #available(iOS 16.0, *) {
            quicOptions.isDatagram = false
        }
        sec_protocol_options_add_tls_application_protocol(quicOptions.securityProtocolOptions, alpn)
        if insecure {
            sec_protocol_options_set_verify_block(quicOptions.securityProtocolOptions, { _, _, completion in
                completion(true)
            }, queue)
        }
        let params = NWParameters(quic: quicOptions)
        params.allowLocalEndpointReuse = true
        return params
    }

    private func resolvePeerCandidates(host: String, port: Int) throws -> [ResolvedAddress] {
        let mode = ObstacleBridgePeerAddressResolver.ResolveMode(rawValue: peerResolveFamily)
        let candidates = try ObstacleBridgePeerAddressResolver.resolvePeerCandidates(
            host: host,
            port: port,
            mode: mode,
            strictFamily: false,
            errorDomain: "ObstacleBridge.QuicOverlay"
        )
        let bindConstraint = ObstacleBridgePeerAddressResolver.bindFamilyConstraint(bindHost)
        let filtered = candidates.filter { bindConstraint == nil || $0.family == bindConstraint }
        return filtered.isEmpty ? candidates : filtered
    }

    private func currentResolvedPeer() throws -> (host: String, port: Int, family: String, index: Int, candidateCount: Int) {
        if resolvedPeerCandidates.isEmpty {
            resolvedPeerCandidates = try resolvePeerCandidates(host: peerHost, port: peerPort)
            resolvedPeerCandidateIndex = 0
        }
        guard !resolvedPeerCandidates.isEmpty else {
            throw NSError(domain: "ObstacleBridge.QuicOverlay", code: 2, userInfo: [
                NSLocalizedDescriptionKey: "failed to resolve QUIC peer \(peerHost):\(peerPort)"
            ])
        }
        if resolvedPeerCandidateIndex >= resolvedPeerCandidates.count {
            resolvedPeerCandidateIndex = 0
        }
        let selected = resolvedPeerCandidates[resolvedPeerCandidateIndex]
        return (
            selected.host,
            selected.port,
            ObstacleBridgePeerAddressResolver.familyName(selected.family),
            resolvedPeerCandidateIndex,
            resolvedPeerCandidates.count
        )
    }

    private func handleOverlayState(_ state: NWConnection.State) {
        switch state {
        case .ready:
            overlayConnected = true
            nextReconnectAttemptDeadlineNS = nil
            let snapshot = overlayRuntime.connect(
                host: resolvedPeerHost.isEmpty ? peerHost : resolvedPeerHost,
                port: resolvedPeerPort == 0 ? peerPort : resolvedPeerPort,
                socketPresent: true
            )
            eventSink?("quic_overlay_connected", [
                "peer_host": snapshot.peerHost,
                "peer_port": snapshot.peerPort,
                "resolved_peer_family": resolvedPeerFamily,
            ])
            do {
                if let adapter = overlayLayerTransportAdapter {
                    let adapterSnapshot = try adapter.handleTransportConnected()
                    updateLowerLayerFallback()
                    sendTransportFrames(adapterSnapshot.emittedFrames)
                }
                flushStartupMuxFramesIfNeeded()
                maybeOpenConfiguredTunIfReady()
            } catch {
                eventSink?("quic_overlay_transport_adapter_connect_failed", ["error": error.localizedDescription])
            }
        case .failed(let error):
            eventSink?("quic_overlay_failed", ["error": error.localizedDescription])
            handleDisconnected(schedule: true)
        case .cancelled:
            handleDisconnected(schedule: false)
        default:
            break
        }
    }

    private func handleDisconnected(schedule: Bool) {
        tunRuntime?.cleanupSharedTunPeerStateOnDisconnect(peerID: currentTunPeerID())
        tunRuntime?.resetTransportEpoch()
        activeTunChanIDs.removeAll()
        overlayConnected = false
        overlayConnection?.cancel()
        overlayConnection = nil
        receiveBuffer.removeAll(keepingCapacity: false)
        pendingOutboundWires.removeAll(keepingCapacity: false)
        outboundSendInFlight = false
        overlayEgressWindow = ObstacleBridgeOverlayChannelCore.OverlayEgressWindowState()
        startupMuxFramesSent = false
        startupMuxFramesReplayedWithTunOpen = false
        if let adapter = overlayLayerTransportAdapter {
            adapter.handleTransportDisconnected()
        }
        lowerLayerFallbackWorkItem?.cancel()
        lowerLayerFallbackWorkItem = nil
        lowerLayerFallbackDeadlineNS = nil
        if schedule {
            scheduleReconnect()
        }
    }

    private func startSecureLinkDueTimer() {
        guard secureLinkDueTimer == nil else { return }
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
        guard let adapter = overlayLayerTransportAdapter,
              let result = adapter.connectionRotationDue(candidateCount: resolvedPeerCandidates.count)
        else {
            return
        }
        eventSink?("quic_overlay_lifecycle_rotation", [
            "epoch": result.epoch,
            "candidate_cycle": result.candidateCycle,
            "restart_required": result.restartRequired,
        ])
        guard !result.restartRequired else {
            eventSink?("quic_overlay_lifecycle_restart_required", ["candidate_cycle": result.candidateCycle])
            return
        }
        handleDisconnected(schedule: true)
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
            sendTransportFrames(snapshot.emittedFrames)
            updateLowerLayerFallback()
        } catch {
            eventSink?("quic_overlay_secure_link_due_frames_failed", ["error": error.localizedDescription])
        }
    }

    private func scheduleReconnect() {
        guard started, !reconnectScheduled else { return }
        advancePeerCandidate()
        reconnectScheduled = true
        let workItem = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.reconnectScheduled = false
            self.nextReconnectAttemptDeadlineNS = nil
            self.connectOverlay()
        }
        reconnectWorkItem = workItem
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

    private func advancePeerCandidate() {
        guard resolvedPeerCandidates.count > 1 else { return }
        resolvedPeerCandidateIndex = (resolvedPeerCandidateIndex + 1) % resolvedPeerCandidates.count
    }

    private func receiveOverlayData() {
        guard let connection = overlayConnection else { return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: max(1, sessionMaxAppPayload + 1024)) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            self.queue.async {
                if let data, !data.isEmpty {
                    self.handleOverlayPayload(data)
                }
                if let error {
                    self.eventSink?("quic_overlay_receive_failed", ["error": error.localizedDescription])
                    self.handleDisconnected(schedule: true)
                    return
                }
                if isComplete {
                    self.handleDisconnected(schedule: self.started)
                    return
                }
                self.receiveOverlayData()
            }
        }
    }

    private func handleOverlayPayload(_ payload: Data) {
        lastOverlayRxWallNS = DispatchTime.now().uptimeNanoseconds
        receiveBuffer.append(payload)
        drainReceiveBuffer()
    }

    private func drainReceiveBuffer() {
        let snapshot = overlayRuntime.handleInboundBytes(receiveBuffer)
        guard snapshot.consumedBytes > 0 else { return }
        receiveBuffer.removeFirst(snapshot.consumedBytes)
        for payload in snapshot.completedPayloads {
            let inboundPayloads: [Data]
            if let adapter = overlayLayerTransportAdapter {
                let adapterSnapshot = adapter.handleInboundFrame(payload, observedPeerHost: resolvedPeerHost)
                inboundPayloads = adapterSnapshot.deliveredPayloads
                if !adapterSnapshot.emittedFrames.isEmpty {
                    sendTransportFrames(adapterSnapshot.emittedFrames)
                }
                updateLowerLayerFallback()
            } else {
                inboundPayloads = [payload]
            }
            for inboundPayload in inboundPayloads {
                handleInboundMuxPayload(inboundPayload)
            }
            flushStartupMuxFramesIfNeeded()
            maybeOpenConfiguredTunIfReady()
        }
    }

    private func handleInboundMuxPayload(_ payload: Data) {
        guard let frame = ObstacleBridgeChannelMuxCodec.unpackMux(payload) else {
            eventSink?("quic_overlay_invalid_mux_frame", ["bytes": payload.count])
            return
        }
        if frame.proto == .tun {
            handleInboundTunMuxFrame(frame)
        } else if frame.proto == .tcp {
            tcpTransportOwner.handleInboundMuxFrame(frame)
        }
    }

    private func currentTunPeerID() -> Int? {
        appReady() ? 1 : nil
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
            eventSink?("quic_overlay_lower_layer_unavailable", ["reason": reason, "auth_fail_code": status.authFailCode])
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
            self.eventSink?("quic_overlay_lower_layer_unavailable", ["reason": reason, "auth_fail_code": currentStatus.authFailCode])
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
        pendingOutboundWires.removeAll(keepingCapacity: false)
        outboundSendInFlight = false
        overlayEgressWindow = ObstacleBridgeOverlayChannelCore.OverlayEgressWindowState()
        if let adapter = overlayLayerTransportAdapter {
            adapter.handleTransportDisconnected()
        }
        lowerLayerFallbackWorkItem?.cancel()
        lowerLayerFallbackWorkItem = nil
        lowerLayerFallbackDeadlineNS = nil
        scheduleReconnect()
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

    private func handleTCPTransportEvent(_ event: ObstacleBridgeChannelMuxTCPTransportOwner.TransportEvent) {
        ObstacleBridgeOverlayChannelCore.handleTCPTransportEvent(
            event,
            tcpConnectionStates: &tcpConnectionStates,
            serviceNameByID: serviceNameByID
        )
    }

    private func sendMuxFrames(_ frames: [Data]) {
        sendFrames(frames)
    }

    private func sendFrames(_ frames: [Data]) {
        guard !frames.isEmpty else { return }
        for frame in frames {
            sendPayload(frame)
        }
    }

    private func sendTransportFrames(_ frames: [Data]) {
        guard !frames.isEmpty else { return }
        for frame in frames {
            let snapshot = overlayRuntime.sendApp(payload: frame, writerPresent: overlayConnection != nil, peerConfigured: !peerHost.isEmpty)
            for wire in snapshot.writtenBuffers {
                enqueueOutboundWire(wire)
            }
        }
    }

    private func enqueueOutboundWire(_ wire: Data) {
        guard !wire.isEmpty else { return }
        for chunk in Self.networkFrameworkWriteChunks(wire) {
            pendingOutboundWires.append(chunk)
            ObstacleBridgeOverlayChannelCore.recordOverlayEgress(
                bytes: chunk.count,
                state: &overlayEgressWindow
            )
        }
        flushNextOutboundWireIfNeeded()
    }

    private static func networkFrameworkWriteChunks(_ wire: Data) -> [Data] {
        guard wire.count > maxNetworkFrameworkWriteBytes else {
            return [wire]
        }
        var chunks: [Data] = []
        var offset = 0
        while offset < wire.count {
            let end = min(offset + maxNetworkFrameworkWriteBytes, wire.count)
            chunks.append(wire.subdata(in: offset..<end))
            offset = end
        }
        return chunks
    }

    private func flushNextOutboundWireIfNeeded() {
        guard !outboundSendInFlight, let connection = overlayConnection, !pendingOutboundWires.isEmpty else {
            return
        }
        outboundSendInFlight = true
        let wire = pendingOutboundWires.removeFirst()
        connection.send(
            content: wire,
            contentContext: outboundContentContext,
            isComplete: false,
            completion: .contentProcessed { [weak self] error in
                guard let self else { return }
                self.queue.async {
                    self.outboundSendInFlight = false
                    if let error {
                        self.eventSink?("quic_overlay_send_failed", ["error": error.localizedDescription])
                        self.pendingOutboundWires.removeAll(keepingCapacity: false)
                        return
                    }
                    self.flushNextOutboundWireIfNeeded()
                }
            }
        )
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

    private func sendPayload(_ payload: Data) {
        let outboundFrames: [Data]
        if let adapter = overlayLayerTransportAdapter {
            do {
                outboundFrames = try adapter.handleOutboundPayload(payload).emittedFrames
            } catch {
                eventSink?("quic_overlay_transport_adapter_send_failed", ["error": error.localizedDescription])
                return
            }
        } else {
            outboundFrames = [payload]
        }
        sendTransportFrames(outboundFrames)
    }

    private func flushStartupMuxFramesIfNeeded() {
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
            eventSink?("quic_overlay_proactive_tun_open", ["chan_id": snapshot.chanID])
        } catch {
            eventSink?("quic_overlay_proactive_tun_open_failed", ["error": error.localizedDescription])
        }
    }

    private func startupMuxFramesForNewTunOpen() -> [Data] {
        guard appReady(), !startupMuxFramesReplayedWithTunOpen else { return [] }
        let connectionSeq = tunRuntime?.currentConnectionSeq() ?? muxConnectionSeq
        let frames = startupMuxFramesProvider?(muxInstanceID, connectionSeq) ?? startupMuxFrames
        guard !frames.isEmpty else { return [] }
        startupMuxFramesReplayedWithTunOpen = true
        eventSink?("quic_overlay_startup_mux_replayed_with_tun_open", [
            "connection_seq": String(connectionSeq),
            "frame_count": frames.count,
        ])
        return frames
    }

    private func serviceName(_ spec: ObstacleBridgeChannelMuxCodec.ServiceSpec) -> String {
        ObstacleBridgeOverlayChannelCore.serviceName(spec, serviceNameByID: serviceNameByID)
    }
}
