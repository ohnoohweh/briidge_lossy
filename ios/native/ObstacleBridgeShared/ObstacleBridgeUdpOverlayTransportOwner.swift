import Foundation
import Network
import Darwin

final class ObstacleBridgeUdpOverlayTransportOwner {
    typealias EventSink = (String, [String: Any]) -> Void
    typealias TunPacketSink = (Data) -> Void
    private static let queueSpecificKey = DispatchSpecificKey<Int>()

    private typealias ResolvedAddress = ObstacleBridgeResolvedAddress
    private static let peerFallbackIdleNS: UInt64 = 3_000_000_000
    private static let reconnectProbeIntervalNS: UInt64 = 1_000_000_000
    private static let secureLinkHandshakeRetryIntervalNS: UInt64 = 1_000_000_000

    private let bindHost: String
    private let bindPort: Int
    private let configuredPeerHost: String?
    private let configuredPeerPort: Int?
    private let configuredPeerResolveFamily: String
    private let overlayLayerTransportAdapter: ObstacleBridgeOverlayLayerTransportAdapter?
    private let startupMuxFrames: [Data]
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
    private let overlayRuntime = ObstacleBridgeUdpOverlayPeerRuntime()
    private var tunRuntime: ObstacleBridgeChannelMuxTunRuntime?
    private lazy var tcpTransportOwner = ObstacleBridgeChannelMuxTCPTransportOwner(
        runtime: ObstacleBridgeChannelMuxTcpRuntime(
            instanceID: muxInstanceID,
            connectionSeq: muxConnectionSeq,
            sessionMaxAppPayload: sessionMaxAppPayload
        ),
        sessionMaxAppPayload: sessionMaxAppPayload,
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
    private var socketFamily: Int32 = AF_INET
    private var peerCandidates: [ResolvedAddress] = []
    private var peerCandidateIndex = 0
    private var fixedPeerAddress: ResolvedAddress?
    private var currentPeerAddress: ResolvedAddress?
    private var readSource: DispatchSourceRead?
    private var controlTimer: DispatchSourceTimer?
    private var retransmitTimer: DispatchSourceTimer?
    private var peerFallbackTimer: DispatchSourceTimer?
    private var udpServerConnections: [Int: NWConnection] = [:]
    private var udpClientConnections: [Int: NWConnection] = [:]
    private var udpClientDrivers: [Int: ObstacleBridgeUDPClientConnectionDriver] = [:]
    private var udpConnectionStates: [Int: ObstacleBridgeOverlayConnectionState] = [:]
    private var tcpConnectionStates: [Int: ObstacleBridgeOverlayConnectionState] = [:]
    private var activeTunChanIDs: Set<Int> = []
    private var tunStats: [String: Int] = ["rx_msgs": 0, "tx_msgs": 0, "rx_bytes": 0, "tx_bytes": 0]
    private var udpServerDrivers: [ObjectIdentifier: ObstacleBridgeUDPServerConnectionDriver] = [:]
    private var started = false
    private var secureLinkHandshakePrimed = false
    private var lastSecureLinkPrimeNS: UInt64 = 0
    private var startupMuxFramesSent = false
    private var currentPeerSelectedAtNS: UInt64 = 0
    private var lastInboundDatagramNS: UInt64 = 0
    private var lastIdleProbeNS: UInt64 = 0
    private var lastOverlayConnectedState = false

    init(
        bindHost: String,
        bindPort: Int,
        peerHost: String? = nil,
        peerPort: Int? = nil,
        peerResolveFamily: String = "prefer-ipv6",
        sessionMaxAppPayload: Int = 65535,
        overlayLayerTransportAdapter: ObstacleBridgeOverlayLayerTransportAdapter? = nil,
        startupMuxFrames: [Data] = [],
        queue: DispatchQueue = DispatchQueue(label: "ObstacleBridgeUdpOverlayTransportOwner"),
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
        self.bindHost = bindHost
        self.bindPort = bindPort
        self.sessionMaxAppPayload = max(0, sessionMaxAppPayload)
        let trimmedPeerHost = peerHost?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.configuredPeerHost = (trimmedPeerHost?.isEmpty == false) ? trimmedPeerHost : nil
        self.configuredPeerPort = peerPort
        self.configuredPeerResolveFamily = peerResolveFamily
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

    var overlayConnected: Bool {
        overlayRuntime.isConnected() && currentPeerAddress != nil
    }

    func start() throws {
        guard !started else {
            return
        }
        let socket = try Self.makeBoundSocket(
            bindHost: bindHost,
            bindPort: bindPort,
            peerHost: configuredPeerHost,
            peerPort: configuredPeerPort,
            peerResolveFamily: configuredPeerResolveFamily
        )
        socketFD = socket.socketFD
        socketFamily = socket.socketFamily
        peerCandidates = socket.peerCandidates
        peerCandidateIndex = 0
        fixedPeerAddress = configuredPeerHost == nil ? nil : socket.peerAddress
        currentPeerAddress = socket.peerAddress
        started = true
        currentPeerSelectedAtNS = monotonicNowNS()
        lastInboundDatagramNS = 0
        lastIdleProbeNS = 0
        lastOverlayConnectedState = false

        let source = DispatchSource.makeReadSource(fileDescriptor: socketFD, queue: queue)
        source.setEventHandler { [weak self] in
            self?.drainSocket()
        }
        readSource = source
        source.resume()

        startOverlayTimers()
        startPeerFallbackTimer()
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
        peerFallbackTimer?.cancel()
        peerFallbackTimer = nil
        readSource?.cancel()
        readSource = nil
        tcpTransportOwner.stop()
        for connection in udpServerConnections.values {
            cancelConnection(connection)
        }
        udpServerDrivers.removeAll()
        for connection in udpClientConnections.values {
            cancelConnection(connection)
        }
        udpClientDrivers.removeAll()
        udpServerConnections.removeAll()
        udpClientConnections.removeAll()
        udpConnectionStates.removeAll()
        tcpConnectionStates.removeAll()
        activeTunChanIDs.removeAll()
        tunStats = ["rx_msgs": 0, "tx_msgs": 0, "rx_bytes": 0, "tx_bytes": 0]
        currentPeerAddress = fixedPeerAddress
        peerCandidates.removeAll()
        peerCandidateIndex = 0
        secureLinkHandshakePrimed = false
        lastSecureLinkPrimeNS = 0
        startupMuxFramesSent = false
        currentPeerSelectedAtNS = 0
        lastInboundDatagramNS = 0
        lastIdleProbeNS = 0
        lastOverlayConnectedState = false
        tunRuntime?.cleanupSharedTunPeerStateOnDisconnect(peerID: currentTunPeerID())
        if socketFD >= 0 {
            Darwin.close(socketFD)
            socketFD = -1
        }
    }

    func connectionRows() -> (tcp: [[String: Any]], udp: [[String: Any]], tun: [[String: Any]]) {
        withOwnerQueue {
            let tcpRows = ObstacleBridgeOverlayConnectionSupport.connectionRows(from: tcpConnectionStates)
            let udpRows = ObstacleBridgeOverlayConnectionSupport.connectionRows(from: udpConnectionStates)
            let tunRows: [[String: Any]]
            if activeTunChanIDs.isEmpty, (tunStats["rx_bytes"] ?? 0) == 0, (tunStats["tx_bytes"] ?? 0) == 0 {
                tunRows = []
            } else {
                let ifname = tunIfname ?? "tun"
                let mtu = tunMTU
                let spec = tunServiceSpec ?? ObstacleBridgeRuntimeConfig.localTunServiceSpec(ifname: ifname, mtu: mtu)
                let stats = tunStats
                tunRows = activeTunChanIDs.sorted().map { chanID in
                    var row = ObstacleBridgeNativeConnectionSnapshot.make(
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
                    row["shared_tun_ownership"] = tunRuntime?.sharedTunRuntimeSnapshot() ?? NSNull()
                    return row
                }
            }
            return (tcpRows, udpRows, tunRows)
        }
    }

    func transportSnapshot() -> [String: Any] {
        withOwnerQueue {
            [
                "overlay_connected": overlayConnected,
                "overlay_bind_host": bindHost,
                "overlay_bind_port": bindPort,
                "overlay_peer_host": currentPeerAddress?.host ?? NSNull(),
                "overlay_peer_port": currentPeerAddress?.port ?? NSNull(),
                "overlay_peer_family": currentPeerAddress.map { ObstacleBridgePeerAddressResolver.familyName($0.family) } ?? NSNull(),
                "overlay_peer_candidate_index": peerCandidateIndex,
                "overlay_peer_candidate_count": peerCandidates.count,
                "fixed_peer_host": configuredPeerHost ?? NSNull(),
                "fixed_peer_port": configuredPeerPort as Any,
                "mux_instance_id": muxInstanceID,
                "mux_connection_seq": muxConnectionSeq,
                "server_tcp_channels": tcpTransportOwner.serverConnectionCount,
                "client_tcp_channels": tcpConnectionStates.count,
                "server_udp_channels": udpServerConnections.count,
                "client_udp_channels": udpConnectionStates.count,
                "tun_channels": activeTunChanIDs.count,
                "tun_stats": tunStats,
                "established_ns": overlayRuntime.establishedNS,
                "last_rx_wall_ns": overlayRuntime.lastRxWallNS,
                "last_rtt_ok_ns": overlayRuntime.lastRttOkNS,
                "rtt_est_ms": overlayRuntime.rttEstMS,
                "transmit_delay_est_ms": overlayRuntime.transmitDelayEstMS,
                "protocol_stats": overlayRuntime.protocolStatsSnapshot(),
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
        guard started, let tunRuntime, let tunIfname, tunMTU > 0 else {
            return
        }
        let localTunSpec = tunServiceSpec ?? ObstacleBridgeRuntimeConfig.localTunServiceSpec(ifname: tunIfname, mtu: tunMTU)
        let bufferedFrames = Int(overlayRuntime.protocolStatsSnapshot()["buffered_frames"] as? Int ?? 0)
        let nowNS = DispatchTime.now().uptimeNanoseconds
        do {
            let sharedRoute = tunRuntime.planSharedTunOutboundRoute(packet: packet)
            let throttle = tunRuntime.scopedTunThrottle(
                packetBytes: packet.count,
                bufferedFrames: bufferedFrames,
                nowNS: nowNS,
                route: sharedRoute
            )
            guard throttle.allowed else {
                tunRuntime.recordSharedTunDrop(
                    reason: "throttled_local_tun",
                    direction: "local_to_peer",
                    destinationIP: sharedRoute?.destinationIP,
                    routeClass: sharedRoute?.routeClass,
                    packetBytes: packet.count
                )
                return
            }
            if let sharedRoute {
                guard sharedRoute.routed else {
                    tunRuntime.recordSharedTunDrop(
                        reason: sharedRoute.dropReason ?? "shared_route_drop",
                        direction: "local_to_peer",
                        ipVersion: sharedRoute.ipVersion,
                        destinationIP: sharedRoute.destinationIP,
                        routeClass: sharedRoute.routeClass,
                        packetBytes: packet.count
                    )
                    return
                }
                let scopeID = tunRuntime.scopeID(for: sharedRoute)
                for chanID in sharedRoute.selectedChanIDs {
                    guard let localSnapshot = try tunRuntime.handleLocalTunPacket(
                        packet: packet,
                        mtu: tunMTU,
                        existingChanID: chanID,
                        spec: localTunSpec,
                        overlayConnected: overlayConnected,
                        acceptingEnabled: true,
                        bufferedFrames: bufferedFrames,
                        nowNS: nowNS,
                        recordInflow: false,
                        scopeID: scopeID
                    ) else {
                        continue
                    }
                    activeTunChanIDs.insert(localSnapshot.chanID)
                    sendMuxFrames(localSnapshot.frames)
                }
                tunRuntime.recordLocalTunForward(packetBytes: packet.count, nowNS: nowNS, route: sharedRoute)
                tunStats["tx_msgs", default: 0] += 1
                tunStats["tx_bytes", default: 0] += packet.count
                return
            }
            guard let localSnapshot = try tunRuntime.handleLocalTunPacket(
                packet: packet,
                mtu: tunMTU,
                spec: localTunSpec,
                overlayConnected: overlayConnected,
                acceptingEnabled: true,
                bufferedFrames: bufferedFrames,
                nowNS: nowNS
            ) else { return }
            activeTunChanIDs.insert(localSnapshot.chanID)
            tunStats["tx_msgs", default: 0] += 1
            tunStats["tx_bytes", default: 0] += packet.count
            sendMuxFrames(localSnapshot.frames)
        } catch {
            eventSink?("udp_overlay_tun_send_failed", [
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

    private func startPeerFallbackTimer() {
        guard peerCandidates.count > 1 else {
            return
        }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .seconds(1), repeating: .seconds(1))
        timer.setEventHandler { [weak self] in
            self?.handlePeerFallbackTimer()
        }
        timer.resume()
        peerFallbackTimer = timer
    }

    private func sendInitialIdleProbe() {
        let nowNS = monotonicNowNS()
        do {
            let frame = try ObstacleBridgeUdpOverlayCodec.buildProtocolFrame(
                ptype: ObstacleBridgeUdpOverlayCodec.ptypeIdle,
                payload: Data(),
                txNS: nowNS,
                echoNS: 0
            )
            lastIdleProbeNS = nowNS
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
        handleTransportLiveness(nowNS: nowNS)
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
                lastInboundDatagramNS = monotonicNowNS()
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

    private func handlePeerFallbackTimer() {
        guard started, peerCandidateIndex + 1 < peerCandidates.count else {
            return
        }
        let nowNS = monotonicNowNS()
        guard lastInboundDatagramNS == 0 || lastInboundDatagramNS < currentPeerSelectedAtNS else {
            return
        }
        if nowNS <= currentPeerSelectedAtNS {
            return
        }
        if nowNS - currentPeerSelectedAtNS < Self.peerFallbackIdleNS {
            return
        }
        rotateToNextPeerCandidate(nowNS: nowNS, reason: "idle")
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
                    txNS: frame.txNS,
                    echoNS: frame.echoNS,
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
        lastOverlayConnectedState = overlayConnected
    }

    private func handleTransportLiveness(nowNS: UInt64) {
        let connected = overlayConnected
        if lastOverlayConnectedState && !connected {
            tunRuntime?.cleanupSharedTunPeerStateOnDisconnect(peerID: currentTunPeerID())
            secureLinkHandshakePrimed = false
            lastSecureLinkPrimeNS = 0
            startupMuxFramesSent = false
            overlayLayerTransportAdapter?.handleTransportDisconnected()
        }
        lastOverlayConnectedState = connected
        if connected {
            maybePrimeSecureLinkHandshake(nowNS: nowNS)
            maybeSendStartupMuxFrames()
        }
        guard !connected, started, currentPeerAddress != nil else {
            return
        }
        if lastIdleProbeNS != 0, nowNS > lastIdleProbeNS, (nowNS - lastIdleProbeNS) < Self.reconnectProbeIntervalNS {
            return
        }
        sendInitialIdleProbe()
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

    private func maybePrimeSecureLinkHandshake(nowNS: UInt64? = nil) {
        guard overlayConnected, let adapter = overlayLayerTransportAdapter else {
            return
        }
        let currentNS = nowNS ?? monotonicNowNS()
        if let status = adapter.secureLinkStatusSnapshot(), status.authenticated {
            secureLinkHandshakePrimed = true
            return
        }
        if secureLinkHandshakePrimed,
           lastSecureLinkPrimeNS != 0,
           currentNS > lastSecureLinkPrimeNS,
           (currentNS - lastSecureLinkPrimeNS) < Self.secureLinkHandshakeRetryIntervalNS {
            return
        }
        do {
            let snapshot = try adapter.handleTransportConnected()
            secureLinkHandshakePrimed = true
            lastSecureLinkPrimeNS = currentNS
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
        case .tun:
            handleInboundTunMuxFrame(frame)
        case .tcp:
            tcpTransportOwner.handleInboundMuxFrame(frame)
        case .udp:
            handleInboundUDPMuxFrame(frame)
        }
    }

    private func currentTunPeerID() -> Int? {
        1
    }

    private func handleInboundTunMuxFrame(_ frame: ObstacleBridgeChannelMuxCodec.MuxFrame) {
        guard let tunRuntime, tunMTU > 0 else {
            return
        }
        let localTunSpec = tunServiceSpec ?? ObstacleBridgeRuntimeConfig.localTunServiceSpec(ifname: tunIfname ?? "tun", mtu: tunMTU)
        let bufferedFrames = Int(overlayRuntime.protocolStatsSnapshot()["buffered_frames"] as? Int ?? 0)
        switch frame.mtype {
        case .open:
            let snapshot = tunRuntime.handleInboundTunOpen(chanID: frame.chanID, payload: frame.body)
            if !snapshot.accepted {
                eventSink?("udp_overlay_tun_open_rejected", ["chan_id": frame.chanID])
            } else {
                activeTunChanIDs.insert(frame.chanID)
                tunRuntime.recordSharedTunPeerBinding(peerID: currentTunPeerID(), chanID: frame.chanID)
            }
        case .openChunk:
            let snapshot = tunRuntime.handleInboundTunOpenChunk(chanID: frame.chanID, payload: frame.body)
            if snapshot.assembled && !snapshot.accepted {
                eventSink?("udp_overlay_tun_open_chunk_rejected", ["chan_id": frame.chanID])
            } else if snapshot.accepted {
                activeTunChanIDs.insert(frame.chanID)
                tunRuntime.recordSharedTunPeerBinding(peerID: currentTunPeerID(), chanID: frame.chanID)
            }
        case .data:
            let snapshot = tunRuntime.handleInboundTunDataSharedGuarded(
                peerID: currentTunPeerID(),
                chanID: frame.chanID,
                body: frame.body,
                mtu: tunMTU
            )
            if !snapshot.delivered {
                if let reason = snapshot.dropReason {
                    tunRuntime.recordSharedTunDrop(
                        reason: reason,
                        direction: "peer_to_local",
                        peerID: currentTunPeerID(),
                        chanID: frame.chanID,
                        ipVersion: snapshot.ipVersion,
                        sourceIP: snapshot.sourceIP,
                        destinationIP: snapshot.destinationIP,
                        packetBytes: frame.body.count
                    )
                }
                return
            }
            if let packet = snapshot.packet {
                activeTunChanIDs.insert(frame.chanID)
                if let relay = tunRuntime.planSharedTunInboundPeerRelay(sourcePeerID: currentTunPeerID(), packet: packet),
                   relay.relayToPeer {
                    for chanID in relay.selectedChanIDs where chanID != frame.chanID {
                        if let localSnapshot = try? tunRuntime.handleLocalTunPacket(
                            packet: packet,
                            mtu: tunMTU,
                            existingChanID: chanID,
                            spec: localTunSpec,
                            overlayConnected: overlayConnected,
                            acceptingEnabled: true,
                            bufferedFrames: bufferedFrames,
                            nowNS: DispatchTime.now().uptimeNanoseconds,
                            recordInflow: false
                        ) {
                            sendMuxFrames(localSnapshot.frames)
                        }
                    }
                    return
                }
                tunStats["rx_msgs", default: 0] += 1
                tunStats["rx_bytes", default: 0] += packet.count
                tunPacketSink?(packet)
            }
        case .dataFrag:
            let snapshot = tunRuntime.handleInboundTunFragment(chanID: frame.chanID, payload: frame.body, mtu: tunMTU)
            if let packet = snapshot.packet, snapshot.delivered {
                activeTunChanIDs.insert(frame.chanID)
                let guarded = tunRuntime.handleInboundTunDataSharedGuarded(
                    peerID: currentTunPeerID(),
                    chanID: frame.chanID,
                    body: packet,
                    mtu: tunMTU,
                    boundChanID: frame.chanID
                )
                if !guarded.delivered {
                    if let reason = guarded.dropReason {
                        tunRuntime.recordSharedTunDrop(
                            reason: reason,
                            direction: "peer_to_local",
                            peerID: currentTunPeerID(),
                            chanID: frame.chanID,
                            ipVersion: guarded.ipVersion,
                            sourceIP: guarded.sourceIP,
                            destinationIP: guarded.destinationIP,
                            packetBytes: packet.count
                        )
                    }
                    return
                }
                if let relay = tunRuntime.planSharedTunInboundPeerRelay(sourcePeerID: currentTunPeerID(), packet: packet),
                   relay.relayToPeer {
                    for chanID in relay.selectedChanIDs where chanID != frame.chanID {
                        if let localSnapshot = try? tunRuntime.handleLocalTunPacket(
                            packet: packet,
                            mtu: tunMTU,
                            existingChanID: chanID,
                            spec: localTunSpec,
                            overlayConnected: overlayConnected,
                            acceptingEnabled: true,
                            bufferedFrames: bufferedFrames,
                            nowNS: DispatchTime.now().uptimeNanoseconds,
                            recordInflow: false
                        ) {
                            sendMuxFrames(localSnapshot.frames)
                        }
                    }
                    return
                }
                tunStats["rx_msgs", default: 0] += 1
                tunStats["rx_bytes", default: 0] += packet.count
                tunPacketSink?(packet)
            }
        case .close:
            let snapshot = tunRuntime.handleInboundTunClose(chanID: frame.chanID)
            if snapshot.closed {
                activeTunChanIDs.remove(frame.chanID)
                tunRuntime.dropSharedTunPeerBinding(peerID: currentTunPeerID(), chanID: frame.chanID)
            }
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
            failureEvent: "udp_overlay_udp_client_failed",
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

    private func handleUDPServerConnectionState(_ state: NWConnection.State) {
        if case .failed(let error) = state {
            eventSink?("udp_overlay_udp_server_connection_failed", ["error": error.localizedDescription])
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
                    let err = errno
                    eventSink?("udp_overlay_send_failed", ["errno": err, "packet_bytes": rawBuffer.count])
                    handleImmediatePeerFallback(sendErrno: err)
                }
            }
        }
    }

    private func handleImmediatePeerFallback(sendErrno: Int32) {
        guard started, peerCandidateIndex + 1 < peerCandidates.count else {
            return
        }
        switch sendErrno {
        case ENETUNREACH, EHOSTUNREACH, EADDRNOTAVAIL:
            rotateToNextPeerCandidate(nowNS: monotonicNowNS(), reason: "send_error")
        default:
            break
        }
    }

    private func rotateToNextPeerCandidate(nowNS: UInt64, reason: String) {
        guard peerCandidateIndex + 1 < peerCandidates.count else {
            return
        }
        peerCandidateIndex += 1
        currentPeerAddress = peerCandidates[peerCandidateIndex]
        currentPeerSelectedAtNS = nowNS
        lastInboundDatagramNS = 0
        secureLinkHandshakePrimed = false
        startupMuxFramesSent = false
        eventSink?("udp_overlay_peer_candidate_rotated", [
            "reason": reason,
            "candidate_index": peerCandidateIndex,
            "peer_host": currentPeerAddress?.host ?? NSNull(),
            "peer_port": currentPeerAddress?.port ?? NSNull(),
            "peer_family": currentPeerAddress.map { ObstacleBridgePeerAddressResolver.familyName($0.family) } ?? NSNull(),
        ])
        sendInitialIdleProbe()
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

    private func recordInbound(proto: String, chanID: Int, bytes: Int) {
        switch proto {
        case "tcp":
            ObstacleBridgeOverlayConnectionSupport.recordTraffic(states: &tcpConnectionStates, proto: proto, chanID: chanID, direction: "inbound", bytes: bytes)
        case "udp":
            ObstacleBridgeOverlayConnectionSupport.recordTraffic(states: &udpConnectionStates, proto: proto, chanID: chanID, direction: "inbound", bytes: bytes)
        case "tun":
            tunStats["rx_msgs", default: 0] += 1
            tunStats["rx_bytes", default: 0] += bytes
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
        case "tun":
            tunStats["tx_msgs", default: 0] += 1
            tunStats["tx_bytes", default: 0] += bytes
        default:
            break
        }
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
            ObstacleBridgeOverlayConnectionSupport.updateConnectedState(states: &tcpConnectionStates, proto: "tcp", chanID: chanID, localHost: localHost, localPort: localPort)
        case .clientInbound(let chanID, let bytes):
            recordInbound(proto: "tcp", chanID: chanID, bytes: bytes)
        case .clientOutbound(let chanID, let bytes):
            recordOutbound(proto: "tcp", chanID: chanID, bytes: bytes)
        case .clientClosed(let chanID):
            tcpConnectionStates.removeValue(forKey: chanID)
        case .serverConnected(let chanID):
            ObstacleBridgeOverlayConnectionSupport.updateConnectedState(states: &tcpConnectionStates, proto: "tcp", chanID: chanID, localHost: nil, localPort: nil)
        case .serverInbound(let chanID, let bytes):
            recordInbound(proto: "tcp", chanID: chanID, bytes: bytes)
        case .serverOutbound(let chanID, let bytes):
            recordOutbound(proto: "tcp", chanID: chanID, bytes: bytes)
        case .serverClosed(let chanID):
            tcpConnectionStates.removeValue(forKey: chanID)
        }
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

    private static func makeBoundSocket(
        bindHost: String,
        bindPort: Int,
        peerHost: String?,
        peerPort: Int?,
        peerResolveFamily: String
    ) throws -> (socketFD: Int32, socketFamily: Int32, peerCandidates: [ResolvedAddress], peerAddress: ResolvedAddress?) {
        let resolvedPeers: [ResolvedAddress]
        if let peerHost,
           !peerHost.isEmpty,
           let peerPort,
           peerPort > 0 {
            resolvedPeers = try ObstacleBridgePeerAddressResolver.resolvePeerAddresses(
                host: peerHost,
                port: peerPort,
                resolveFamily: peerResolveFamily,
                bindHost: bindHost,
                errorDomain: "ObstacleBridge.UdpOverlayTransportOwner"
            )
        } else {
            resolvedPeers = []
        }
        let bindFamily: Int32
        if let explicitBindFamily = ObstacleBridgePeerAddressResolver.bindFamilyConstraint(bindHost) {
            bindFamily = explicitBindFamily
        } else if let resolvedPeer = resolvedPeers.first {
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
        let bindAddr = try ObstacleBridgePeerAddressResolver.resolveAddress(
            host: resolvedBindHost,
            port: bindPort,
            passive: true,
            family: bindFamily,
            errorDomain: "ObstacleBridge.UdpOverlayTransportOwner"
        )
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
        var normalizedPeers: [ResolvedAddress] = []
        for candidate in resolvedPeers {
            let normalized = try ObstacleBridgePeerAddressResolver.normalizePeerCandidate(
                candidate,
                socketFamily: bindFamily,
                errorDomain: "ObstacleBridge.UdpOverlayTransportOwner"
            )
            if !normalizedPeers.contains(where: {
                $0.family == normalized.family && $0.host == normalized.host && $0.port == normalized.port
            }) {
                normalizedPeers.append(normalized)
            }
        }
        return (sock, bindFamily, normalizedPeers, normalizedPeers.first)
    }

    private static func resolvedAddress(from storage: sockaddr_storage, length: socklen_t) -> ResolvedAddress? {
        ObstacleBridgePeerAddressResolver.resolvedAddress(from: storage, length: length)
    }
}
