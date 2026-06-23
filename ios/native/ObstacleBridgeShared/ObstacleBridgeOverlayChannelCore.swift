import Foundation
import Network

enum ObstacleBridgeOverlayChannelCore {
    struct OverlayEgressWindowState {
        var windowStartNS: UInt64?
        var previousBytes: Int = 0
        var currentBytes: Int = 0
    }

    static func simpleBackpressureSnapshot(
        bufferedFrames: Int,
        inflight: Int? = nil,
        maxInflight: Int = 0,
        transmitDelayEstMS: Double = 0.0,
        transportPrevWindowBytes: Int = 0,
        stalled: Bool = false
    ) -> ObstacleBridgeChannelMuxTunRuntime.OverlayBackpressureSnapshot {
        let buffered = max(0, bufferedFrames)
        return ObstacleBridgeChannelMuxTunRuntime.OverlayBackpressureSnapshot(
            waitingCount: buffered,
            inflight: max(0, inflight ?? buffered),
            maxInflight: max(0, maxInflight),
            transmitDelayEstMS: max(0.0, transmitDelayEstMS),
            transportPrevWindowBytes: max(0, transportPrevWindowBytes),
            stalled: stalled
        )
    }

    static func recordOverlayEgress(
        bytes: Int,
        state: inout OverlayEgressWindowState,
        nowNS: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) {
        guard bytes > 0 else { return }
        let windowNS: UInt64 = 1_000_000_000
        if state.windowStartNS == nil {
            state.windowStartNS = nowNS
        } else if let start = state.windowStartNS, nowNS >= start + windowNS {
            state.previousBytes = state.currentBytes
            state.currentBytes = 0
            state.windowStartNS = nowNS
        }
        state.currentBytes += bytes
    }

    static func overlayProtocolStats(
        waitingCount: Int,
        inflight: Int,
        maxInflight: Int,
        egressWindow: OverlayEgressWindowState,
        transmitDelayEstMS: Double = 0.0,
        stalled: Bool = false
    ) -> [String: Any] {
        [
            "waiting_count": max(0, waitingCount),
            "inflight": max(0, inflight),
            "max_inflight": max(0, maxInflight),
            "egress_prev_window_bytes": max(0, egressWindow.previousBytes),
            "egress_curr_window_bytes": max(0, egressWindow.currentBytes),
            "transmit_delay_est_ms": max(0.0, transmitDelayEstMS),
            "stalled": stalled,
        ]
    }

    static func backpressureSnapshot(
        waitingCount: Int,
        inflight: Int,
        maxInflight: Int,
        egressWindow: OverlayEgressWindowState,
        transmitDelayEstMS: Double = 0.0,
        stalled: Bool = false
    ) -> ObstacleBridgeChannelMuxTunRuntime.OverlayBackpressureSnapshot {
        simpleBackpressureSnapshot(
            bufferedFrames: waitingCount,
            inflight: inflight,
            maxInflight: maxInflight,
            transmitDelayEstMS: transmitDelayEstMS,
            transportPrevWindowBytes: egressWindow.previousBytes,
            stalled: stalled
        )
    }

    struct TunLocalDropEvent {
        let reason: String
        let packet: Data
        let sharedRoute: ObstacleBridgeChannelMuxTunRuntime.SharedTunOutboundRouteSnapshot?
        let tunRuntime: ObstacleBridgeChannelMuxTunRuntime
    }

    struct TunLocalForwardEvent {
        let packet: Data
        let chanID: Int
        let allocatedChannel: Bool
        let sharedRoute: ObstacleBridgeChannelMuxTunRuntime.SharedTunOutboundRouteSnapshot?
        let tunRuntime: ObstacleBridgeChannelMuxTunRuntime
    }

    struct TunInboundDropEvent {
        let reason: String
        let peerID: Int?
        let chanID: Int
        let ipVersion: Int?
        let sourceIP: String?
        let destinationIP: String?
        let packetBytes: Int
    }

    struct TunInboundRelayEvent {
        let relay: ObstacleBridgeChannelMuxTunRuntime.SharedTunInboundPeerRelaySnapshot
        let sourceChanID: Int
        let packet: Data
        let tunRuntime: ObstacleBridgeChannelMuxTunRuntime
    }

    struct TunInboundDeliverEvent {
        let packet: Data
        let chanID: Int
        let tunRuntime: ObstacleBridgeChannelMuxTunRuntime
    }

    static func serviceName(
        _ spec: ObstacleBridgeChannelMuxCodec.ServiceSpec,
        serviceNameByID: [Int: String]
    ) -> String {
        serviceNameByID[spec.svcID] ?? spec.name ?? spec.lProto.uppercased()
    }

    static func recordTraffic(
        proto: String,
        chanID: Int,
        bytes: Int,
        direction: String,
        tcpConnectionStates: inout [Int: ObstacleBridgeOverlayConnectionState],
        udpConnectionStates: inout [Int: ObstacleBridgeOverlayConnectionState]
    ) {
        switch proto {
        case "tcp":
            ObstacleBridgeOverlayConnectionSupport.recordTraffic(
                states: &tcpConnectionStates,
                proto: proto,
                chanID: chanID,
                direction: direction,
                bytes: bytes
            )
        case "udp":
            ObstacleBridgeOverlayConnectionSupport.recordTraffic(
                states: &udpConnectionStates,
                proto: proto,
                chanID: chanID,
                direction: direction,
                bytes: bytes
            )
        default:
            break
        }
    }

    static func handleTCPTransportEvent(
        _ event: ObstacleBridgeChannelMuxTCPTransportOwner.TransportEvent,
        tcpConnectionStates: inout [Int: ObstacleBridgeOverlayConnectionState],
        serviceNameByID: [Int: String]
    ) {
        switch event {
        case .clientAccepted(let chanID, let spec, let connected):
            tcpConnectionStates[chanID] = ObstacleBridgeOverlayConnectionSupport.makeState(
                proto: "tcp",
                role: "client",
                chanID: chanID,
                spec: spec,
                serviceName: serviceName(spec, serviceNameByID: serviceNameByID),
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

    @discardableResult
    static func acceptLocalTCPConnection(
        _ connection: NWConnection,
        spec: ObstacleBridgeChannelMuxCodec.ServiceSpec,
        listenerHost: String,
        listenerPort: Int,
        tcpTransportOwner: ObstacleBridgeChannelMuxTCPTransportOwner,
        tcpConnectionStates: inout [Int: ObstacleBridgeOverlayConnectionState],
        serviceNameByID: [Int: String],
        cancelConnection: (NWConnection) -> Void
    ) -> Bool {
        if let chanID = tcpTransportOwner.acceptLocalConnection(connection, spec: spec) {
            tcpConnectionStates[chanID] = ObstacleBridgeOverlayConnectionSupport.makeState(
                proto: "tcp",
                role: "server",
                chanID: chanID,
                spec: spec,
                serviceName: serviceName(spec, serviceNameByID: serviceNameByID),
                state: "connecting",
                localHost: listenerHost,
                localPort: listenerPort
            )
            return true
        }
        cancelConnection(connection)
        return false
    }

    static func tunRows(
        activeTunChanIDs: Set<Int>,
        tunStats: [String: Int],
        tunRuntime: ObstacleBridgeChannelMuxTunRuntime?,
        tunServiceSpec: ObstacleBridgeChannelMuxCodec.ServiceSpec?,
        tunIfname: String?,
        tunMTU: Int,
        bufferedFrames: Int = 0,
        backpressure: ObstacleBridgeChannelMuxTunRuntime.OverlayBackpressureSnapshot? = nil,
        transmitDelayEstMS: Double = 0.0,
        transportPrevWindowBytes: Int = 0,
        stalled: Bool = false
    ) -> [[String: Any]] {
        if activeTunChanIDs.isEmpty, (tunStats["rx_bytes"] ?? 0) == 0, (tunStats["tx_bytes"] ?? 0) == 0 {
            return []
        }
        let ifname = tunIfname ?? "tun"
        let mtu = tunMTU
        let spec = tunServiceSpec ?? ObstacleBridgeRuntimeConfig.localTunServiceSpec(ifname: ifname, mtu: mtu)
        let nowNS = DispatchTime.now().uptimeNanoseconds
        let sharedOwnership = tunRuntime?.sharedTunRuntimeSnapshot()
        let backpressure = backpressure ?? simpleBackpressureSnapshot(
            bufferedFrames: bufferedFrames,
            transmitDelayEstMS: transmitDelayEstMS,
            transportPrevWindowBytes: transportPrevWindowBytes,
            stalled: stalled
        )
        let throttle = {
            guard let tunRuntime else {
                return ["applicable": false, "active": false, "reason": "no_local_ingress"] as [String: Any]
            }
            if sharedOwnership != nil {
                return tunRuntime.sharedTunThrottleSnapshot(snapshot: backpressure, nowNS: nowNS)
            }
            return tunRuntime.directTunThrottleSnapshot(snapshot: backpressure, nowNS: nowNS)
        }()
        return activeTunChanIDs.sorted().map { chanID in
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
                stats: tunStats
            )
            row["shared_tun_ownership"] = sharedOwnership ?? NSNull()
            row["throttle"] = throttle
            return row
        }
    }

    static func sendLocalTunPacket(
        _ packet: Data,
        started: Bool,
        tunRuntime: ObstacleBridgeChannelMuxTunRuntime?,
        tunServiceSpec: ObstacleBridgeChannelMuxCodec.ServiceSpec?,
        tunIfname: String?,
        tunMTU: Int,
        overlayConnected: Bool,
        bufferedFrames: Int,
        backpressure: ObstacleBridgeChannelMuxTunRuntime.OverlayBackpressureSnapshot? = nil,
        activeTunChanIDs: inout Set<Int>,
        tunStats: inout [String: Int],
        sendMuxFrames: ([Data]) -> Void,
        onLocalDrop: ((TunLocalDropEvent) -> Void)? = nil,
        onLocalForward: ((TunLocalForwardEvent) -> Void)? = nil
    ) throws {
        guard started, let tunRuntime, let tunIfname, tunMTU > 0 else {
            return
        }
        let localTunSpec = tunServiceSpec ?? ObstacleBridgeRuntimeConfig.localTunServiceSpec(ifname: tunIfname, mtu: tunMTU)
        let nowNS = DispatchTime.now().uptimeNanoseconds
        let backpressure = backpressure ?? simpleBackpressureSnapshot(bufferedFrames: bufferedFrames)
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
            onLocalDrop?(TunLocalDropEvent(
                reason: "throttled_local_tun",
                packet: packet,
                sharedRoute: sharedRoute,
                tunRuntime: tunRuntime
            ))
            return
        }
        if let sharedRoute {
            guard sharedRoute.routed else {
                let reason = sharedRoute.dropReason ?? "shared_route_drop"
                tunRuntime.recordSharedTunDrop(
                    reason: reason,
                    direction: "local_to_peer",
                    ipVersion: sharedRoute.ipVersion,
                    destinationIP: sharedRoute.destinationIP,
                    routeClass: sharedRoute.routeClass,
                    packetBytes: packet.count
                )
                onLocalDrop?(TunLocalDropEvent(
                    reason: reason,
                    packet: packet,
                    sharedRoute: sharedRoute,
                    tunRuntime: tunRuntime
                ))
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
                    backpressure: backpressure,
                    nowNS: nowNS,
                    recordInflow: false,
                    scopeID: scopeID
                ) else {
                    continue
                }
                activeTunChanIDs.insert(localSnapshot.chanID)
                onLocalForward?(TunLocalForwardEvent(
                    packet: packet,
                    chanID: localSnapshot.chanID,
                    allocatedChannel: localSnapshot.allocatedChannel,
                    sharedRoute: sharedRoute,
                    tunRuntime: tunRuntime
                ))
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
            backpressure: backpressure,
            nowNS: nowNS
        ) else {
            return
        }
        activeTunChanIDs.insert(localSnapshot.chanID)
        tunStats["tx_msgs", default: 0] += 1
        tunStats["tx_bytes", default: 0] += packet.count
        onLocalForward?(TunLocalForwardEvent(
            packet: packet,
            chanID: localSnapshot.chanID,
            allocatedChannel: localSnapshot.allocatedChannel,
            sharedRoute: nil,
            tunRuntime: tunRuntime
        ))
        sendMuxFrames(localSnapshot.frames)
    }

    static func handleInboundTunMuxFrame(
        _ frame: ObstacleBridgeChannelMuxCodec.MuxFrame,
        tunRuntime: ObstacleBridgeChannelMuxTunRuntime?,
        tunServiceSpec: ObstacleBridgeChannelMuxCodec.ServiceSpec?,
        tunIfname: String?,
        tunMTU: Int,
        overlayConnected: Bool,
        bufferedFrames: Int,
        currentTunPeerID: Int?,
        activeTunChanIDs: inout Set<Int>,
        tunStats: inout [String: Int],
        tunPacketSink: ((Data) -> Void)?,
        sendMuxFrames: ([Data]) -> Void,
        onInboundDrop: ((TunInboundDropEvent) -> Void)? = nil,
        onInboundRelay: ((TunInboundRelayEvent) -> Void)? = nil,
        onInboundDeliver: ((TunInboundDeliverEvent) -> Void)? = nil,
        onOpenRejected: ((Int) -> Void)? = nil,
        onOpenChunkRejected: ((Int) -> Void)? = nil
    ) {
        guard let tunRuntime, tunMTU > 0 else {
            return
        }
        let localTunSpec = tunServiceSpec ?? ObstacleBridgeRuntimeConfig.localTunServiceSpec(ifname: tunIfname ?? "tun", mtu: tunMTU)

        func recordDrop(reason: String, chanID: Int, ipVersion: Int?, sourceIP: String?, destinationIP: String?, packetBytes: Int) {
            tunRuntime.recordSharedTunDrop(
                reason: reason,
                direction: "peer_to_local",
                peerID: currentTunPeerID,
                chanID: chanID,
                ipVersion: ipVersion,
                sourceIP: sourceIP,
                destinationIP: destinationIP,
                packetBytes: packetBytes
            )
            onInboundDrop?(TunInboundDropEvent(
                reason: reason,
                peerID: currentTunPeerID,
                chanID: chanID,
                ipVersion: ipVersion,
                sourceIP: sourceIP,
                destinationIP: destinationIP,
                packetBytes: packetBytes
            ))
        }

        func handleDeliveredPacket(_ packet: Data, chanID: Int) {
            activeTunChanIDs.insert(chanID)
            if let relay = tunRuntime.planSharedTunInboundPeerRelay(sourcePeerID: currentTunPeerID, packet: packet),
               relay.relayToPeer {
                onInboundRelay?(TunInboundRelayEvent(
                    relay: relay,
                    sourceChanID: chanID,
                    packet: packet,
                    tunRuntime: tunRuntime
                ))
                for selectedChanID in relay.selectedChanIDs where selectedChanID != chanID {
                    if let localSnapshot = try? tunRuntime.handleLocalTunPacket(
                        packet: packet,
                        mtu: tunMTU,
                        existingChanID: selectedChanID,
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
            onInboundDeliver?(TunInboundDeliverEvent(
                packet: packet,
                chanID: chanID,
                tunRuntime: tunRuntime
            ))
            tunPacketSink?(packet)
        }

        switch frame.mtype {
        case .open:
            let snapshot = tunRuntime.handleInboundTunOpen(chanID: frame.chanID, payload: frame.body)
            if snapshot.accepted {
                activeTunChanIDs.insert(frame.chanID)
                tunRuntime.recordSharedTunPeerBinding(peerID: currentTunPeerID, chanID: frame.chanID)
            } else {
                onOpenRejected?(frame.chanID)
            }
        case .openChunk:
            let snapshot = tunRuntime.handleInboundTunOpenChunk(chanID: frame.chanID, payload: frame.body)
            if snapshot.accepted {
                activeTunChanIDs.insert(frame.chanID)
                tunRuntime.recordSharedTunPeerBinding(peerID: currentTunPeerID, chanID: frame.chanID)
            } else if snapshot.assembled {
                onOpenChunkRejected?(frame.chanID)
            }
        case .data:
            let snapshot = tunRuntime.handleInboundTunDataSharedGuarded(
                peerID: currentTunPeerID,
                chanID: frame.chanID,
                body: frame.body,
                mtu: tunMTU
            )
            if !snapshot.delivered {
                if let reason = snapshot.dropReason {
                    recordDrop(
                        reason: reason,
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
                handleDeliveredPacket(packet, chanID: frame.chanID)
            }
        case .dataFrag:
            let snapshot = tunRuntime.handleInboundTunFragment(chanID: frame.chanID, payload: frame.body, mtu: tunMTU)
            if let packet = snapshot.packet, snapshot.delivered {
                activeTunChanIDs.insert(frame.chanID)
                let guarded = tunRuntime.handleInboundTunDataSharedGuarded(
                    peerID: currentTunPeerID,
                    chanID: frame.chanID,
                    body: packet,
                    mtu: tunMTU,
                    boundChanID: frame.chanID
                )
                if !guarded.delivered {
                    if let reason = guarded.dropReason {
                        recordDrop(
                            reason: reason,
                            chanID: frame.chanID,
                            ipVersion: guarded.ipVersion,
                            sourceIP: guarded.sourceIP,
                            destinationIP: guarded.destinationIP,
                            packetBytes: packet.count
                        )
                    }
                    return
                }
                handleDeliveredPacket(packet, chanID: frame.chanID)
            }
        case .close:
            let snapshot = tunRuntime.handleInboundTunClose(chanID: frame.chanID)
            if snapshot.closed {
                activeTunChanIDs.remove(frame.chanID)
                tunRuntime.dropSharedTunPeerBinding(peerID: currentTunPeerID, chanID: frame.chanID)
            }
        default:
            break
        }
    }
}
