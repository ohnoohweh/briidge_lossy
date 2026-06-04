import Foundation
import Network

@available(iOS 15.0, *)
final class ObstacleBridgeQuicOverlayTransportOwner {
    typealias EventSink = (String, [String: Any]) -> Void
    typealias TunPacketSink = (Data) -> Void

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

    private var overlayConnection: NWConnection?
    private var overlayConnected = false
    private var receiveBuffer = Data()
    private var started = false
    private var reconnectAttempts = 0
    private var reconnectScheduled = false
    private var reconnectWorkItem: DispatchWorkItem?
    private var startupMuxFramesSent = false
    private var resolvedPeerHost = ""
    private var resolvedPeerPort = 0
    private var resolvedPeerFamily = ""
    private var resolvedPeerCandidateIndex = -1
    private var resolvedPeerCandidateCount = 0
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
            self?.overlayConnected ?? false
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
        queue: DispatchQueue = DispatchQueue(label: "ObstacleBridgeQuicOverlayTransportOwner"),
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
        self.queue = queue
        self.eventSink = eventSink
        self.serviceNameByID = serviceNameByID
        self.tunIfname = tunIfname?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.tunMTU = max(0, tunMTU)
        self.tunPacketSink = tunPacketSink
        self.muxInstanceID = muxInstanceID
        self.muxConnectionSeq = muxConnectionSeq
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
        overlayConnection?.cancel()
        overlayConnection = nil
        tcpTransportOwner.stop()
        tcpConnectionStates.removeAll()
        activeTunChanIDs.removeAll()
        tunStats = ["rx_msgs": 0, "tx_msgs": 0, "rx_bytes": 0, "tx_bytes": 0]
        receiveBuffer.removeAll(keepingCapacity: false)
        startupMuxFramesSent = false
    }

    func connectionRows() -> (tcp: [[String: Any]], udp: [[String: Any]], tun: [[String: Any]]) {
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
        return (ObstacleBridgeOverlayConnectionSupport.connectionRows(from: tcpConnectionStates), [], tunRows)
    }

    func transportSnapshot() -> [String: Any] {
        [
            "overlay_connected": overlayConnected,
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
            "mux_instance_id": muxInstanceID,
            "mux_connection_seq": muxConnectionSeq,
            "server_tcp_channels": tcpTransportOwner.serverConnectionCount,
            "client_tcp_channels": tcpConnectionStates.count,
            "server_udp_channels": 0,
            "client_udp_channels": 0,
            "tun_channels": activeTunChanIDs.count,
            "tun_stats": tunStats,
        ]
    }

    func sendLocalTunPacket(_ packet: Data) {
        guard started, let tunRuntime, let tunIfname, tunMTU > 0 else {
            return
        }
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
        reconnectWorkItem?.cancel()
        reconnectWorkItem = nil
        reconnectAttempts += 1
        do {
            let resolved = try resolvePeer(host: peerHost, port: peerPort)
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

    private func resolvePeer(host: String, port: Int) throws -> (host: String, port: Int, family: String, index: Int, candidateCount: Int) {
        let mode = ObstacleBridgePeerAddressResolver.ResolveMode(rawValue: peerResolveFamily)
        let candidates = try ObstacleBridgePeerAddressResolver.resolvePeerCandidates(
            host: host,
            port: port,
            mode: mode,
            strictFamily: false,
            errorDomain: "ObstacleBridge.QuicOverlay"
        )
        let bindConstraint = ObstacleBridgePeerAddressResolver.bindFamilyConstraint(bindHost)
        let filtered = Array(candidates.enumerated().filter { bindConstraint == nil || $0.element.family == bindConstraint })
        let selected = filtered.first ?? Array(candidates.enumerated()).first
        guard let selected else {
            throw NSError(domain: "ObstacleBridge.QuicOverlay", code: 2, userInfo: [
                NSLocalizedDescriptionKey: "failed to resolve QUIC peer \(host):\(port)"
            ])
        }
        return (
            selected.element.host,
            selected.element.port,
            ObstacleBridgePeerAddressResolver.familyName(selected.element.family),
            selected.offset,
            candidates.count
        )
    }

    private func handleOverlayState(_ state: NWConnection.State) {
        switch state {
        case .ready:
            overlayConnected = true
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
                    sendFrames(adapterSnapshot.emittedFrames)
                }
                flushStartupMuxFramesIfNeeded()
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
        overlayConnected = false
        overlayConnection?.cancel()
        overlayConnection = nil
        receiveBuffer.removeAll(keepingCapacity: false)
        if let adapter = overlayLayerTransportAdapter {
            adapter.handleTransportDisconnected()
        }
        if schedule {
            scheduleReconnect()
        }
    }

    private func scheduleReconnect() {
        guard started, !reconnectScheduled else { return }
        reconnectScheduled = true
        let workItem = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.reconnectScheduled = false
            self.connectOverlay()
        }
        reconnectWorkItem = workItem
        queue.asyncAfter(deadline: .now() + .milliseconds(reconnectRetryDelayMS), execute: workItem)
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
        let inboundPayloads: [Data]
        if let adapter = overlayLayerTransportAdapter {
            let snapshot = adapter.handleInboundFrame(payload)
            inboundPayloads = snapshot.deliveredPayloads
            if !snapshot.emittedFrames.isEmpty {
                sendFrames(snapshot.emittedFrames)
            }
        } else {
            inboundPayloads = [payload]
        }
        for item in inboundPayloads {
            receiveBuffer.append(item)
            drainReceiveBuffer()
        }
    }

    private func drainReceiveBuffer() {
        let snapshot = overlayRuntime.handleInboundBytes(receiveBuffer)
        guard snapshot.consumedBytes > 0 else { return }
        receiveBuffer.removeFirst(snapshot.consumedBytes)
        for payload in snapshot.completedPayloads {
            guard let frame = ObstacleBridgeChannelMuxCodec.unpackMux(payload) else {
                eventSink?("quic_overlay_invalid_mux_frame", ["bytes": payload.count])
                continue
            }
            if frame.proto == .tun {
                handleInboundTunMuxFrame(frame)
            } else if frame.proto == .tcp {
                tcpTransportOwner.handleInboundMuxFrame(frame)
            }
        }
    }

    private func handleInboundTunMuxFrame(_ frame: ObstacleBridgeChannelMuxCodec.MuxFrame) {
        guard let tunRuntime, tunMTU > 0 else {
            return
        }
        switch frame.mtype {
        case .open:
            let snapshot = tunRuntime.handleInboundTunOpen(chanID: frame.chanID, payload: frame.body)
            if snapshot.accepted {
                activeTunChanIDs.insert(frame.chanID)
            }
        case .openChunk:
            let snapshot = tunRuntime.handleInboundTunOpenChunk(chanID: frame.chanID, payload: frame.body)
            if snapshot.accepted {
                activeTunChanIDs.insert(frame.chanID)
            }
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
            if snapshot.closed {
                activeTunChanIDs.remove(frame.chanID)
            }
        default:
            break
        }
    }

    private func handleTCPTransportEvent(_ event: ObstacleBridgeChannelMuxTCPTransportOwner.TransportEvent) {
        switch event {
        case .clientAccepted(let chanID, let spec, let connected):
            let state = connected ? "connected" : "connecting"
            tcpConnectionStates[chanID] = ObstacleBridgeOverlayConnectionSupport.makeState(
                proto: "tcp",
                role: "client",
                chanID: chanID,
                spec: spec,
                serviceName: serviceName(spec),
                state: state,
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
            ObstacleBridgeOverlayConnectionSupport.recordTraffic(
                states: &tcpConnectionStates,
                proto: "tcp",
                chanID: chanID,
                direction: "inbound",
                bytes: bytes
            )
        case .clientOutbound(let chanID, let bytes), .serverOutbound(let chanID, let bytes):
            ObstacleBridgeOverlayConnectionSupport.recordTraffic(
                states: &tcpConnectionStates,
                proto: "tcp",
                chanID: chanID,
                direction: "outbound",
                bytes: bytes
            )
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

    private func sendMuxFrames(_ frames: [Data]) {
        sendFrames(frames)
    }

    private func sendFrames(_ frames: [Data]) {
        guard !frames.isEmpty else { return }
        for frame in frames {
            sendPayload(frame)
        }
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
        for frame in outboundFrames {
            let snapshot = overlayRuntime.sendApp(payload: frame, writerPresent: overlayConnection != nil, peerConfigured: !peerHost.isEmpty)
            for wire in snapshot.writtenBuffers {
                overlayConnection?.send(
                    content: wire,
                    contentContext: .defaultStream,
                    isComplete: false,
                    completion: .contentProcessed({ _ in })
                )
            }
        }
    }

    private func flushStartupMuxFramesIfNeeded() {
        guard !startupMuxFramesSent, !startupMuxFrames.isEmpty else { return }
        startupMuxFramesSent = true
        sendMuxFrames(startupMuxFrames)
    }

    private func serviceName(_ spec: ObstacleBridgeChannelMuxCodec.ServiceSpec) -> String {
        if let explicit = spec.name, !explicit.isEmpty {
            return explicit
        }
        return serviceNameByID[spec.svcID] ?? ""
    }
}
