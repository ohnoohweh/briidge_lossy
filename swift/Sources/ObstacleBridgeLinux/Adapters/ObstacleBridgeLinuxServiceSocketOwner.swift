import Dispatch
import Foundation
#if os(Linux)
import Glibc
#endif
import ObstacleBridgeCore

public enum ObstacleBridgeLinuxServiceSocketOwnerError: Error, Equatable, LocalizedError {
    case unsupportedProtocol
    case socketFailure(Int32)
    case bindFailure(Int32)
    case listenFailure(Int32)
    case targetConnectFailure(Int32)

    public var errorDescription: String? {
        switch self {
        case .unsupportedProtocol:
            return "service socket uses an unsupported protocol pairing"
        case .socketFailure(let code):
            return "service socket creation failed (errno=\(code): \(String(cString: strerror(code)))"
        case .bindFailure(let code):
            return "service listener bind failed (errno=\(code): \(String(cString: strerror(code)))"
        case .listenFailure(let code):
            return "service listener listen failed (errno=\(code): \(String(cString: strerror(code)))"
        case .targetConnectFailure(let code):
            return "service target connect failed (errno=\(code): \(String(cString: strerror(code)))"
        }
    }
}

/// The Linux resource-owner result of replacing an overlay transport epoch.
/// Core determines the portable channels that are withdrawn; the owner closes
/// only the descriptors and endpoint routing retained for those channels.
public struct ObstacleBridgeLinuxServiceSocketOwnerEpochReset: Equatable, Sendable {
    public let withdrawnTCPChannels: [UInt16]
    public let withdrawnUDPChannels: [UInt16]
}

/// POSIX descriptor owner for one configured TCP or UDP service. All socket
/// callbacks and data-plane mutation run on one serial queue; no descriptor or
/// channel state is touched by the overlay thread directly.
public final class ObstacleBridgeLinuxServiceSocketOwner: @unchecked Sendable {
    public typealias FrameSink = (ObstacleBridgeLinuxServiceSocketOwner, [ObstacleBridgeChannelMuxFrame]) -> Void

    private struct ChannelTraffic {
        var rxBytes = 0
        var txBytes = 0
        var rxMessages = 0
        var txMessages = 0
    }

    private var spec: ObstacleBridgeLinuxServiceSpec
    private let frameSink: FrameSink
    private let debugEnabled: Bool
    private let debugSink: ((String, [String: String]) -> Void)?
    private let queue: DispatchQueue
    private let tcpRuntime: ObstacleBridgeChannelMuxTcpRuntime
    private let udpRuntime: ObstacleBridgeChannelMuxUdpRuntime
    private var listener: Int32 = -1
    private var listenerSource: DispatchSourceRead?
    private var connectionSources: [UInt16: DispatchSourceRead] = [:]
    private var descriptors: [UInt16: Int32] = [:]
    private var udpPeers: [UInt16: (Data, socklen_t)] = [:]
    private var udpChannels: [Data: UInt16] = [:]
    private var coreTCPChannels: Set<UInt16> = []
    private var coreUDPChannels: Set<UInt16> = []
    private var coreTCPClientChannels: Set<UInt16> = []
    private var coreUDPClientChannels: Set<UInt16> = []
    private var channelTraffic: [UInt16: ChannelTraffic] = [:]
    private var completedTraffic = ChannelTraffic()
    private var openedTCPChannels = 0
    private var openedUDPChannels = 0
    private var malformedFrames = 0
    private var serviceFailures = 0
    private var stopped = false

    public var specification: ObstacleBridgeLinuxServiceSpec { spec }

    /// The O5 payload places the stable configured service id after its
    /// instance and connection identifiers. Routing this before handing the
    /// frame to a socket owner prevents an unrelated installed service from
    /// claiming an inbound channel.
    public func acceptsInboundOpen(_ frame: ObstacleBridgeChannelMuxFrame) -> Bool {
        guard frame.messageType == .open, frame.protocolType == spec.listenProtocol,
              frame.body.count >= 16, frame.body.prefix(2) == Data("O5".utf8) else { return false }
        let serviceID = (UInt16(frame.body[14]) << 8) | UInt16(frame.body[15])
        return serviceID == spec.serviceID
    }

    public var port: Int {
        queue.sync {
            listener >= 0 ? boundPort(listener) : 0
        }
    }

    public init(spec: ObstacleBridgeLinuxServiceSpec, maximumQueuedFrames: Int = 128, maximumApplicationPayload: Int = 65_535, instanceID: UInt64 = 0, connectionSequence: UInt32 = 0, channelIDAllocation: ObstacleBridgeChannelMuxChannelIDAllocation = .peerClient(), debugEnabled: Bool = false, debugSink: ((String, [String: String]) -> Void)? = nil, frameSink: @escaping FrameSink) {
        self.spec = spec
        self.frameSink = frameSink
        self.debugEnabled = debugEnabled
        self.debugSink = debugSink
        self.queue = DispatchQueue(label: "org.obstaclebridge.linux.service.\(spec.serviceID)")
        self.tcpRuntime = ObstacleBridgeChannelMuxTcpRuntime(instanceID: instanceID, connectionSeq: connectionSequence, allocation: channelIDAllocation, sessionMaxAppPayload: maximumApplicationPayload)
        self.udpRuntime = ObstacleBridgeChannelMuxUdpRuntime(instanceID: instanceID, connectionSeq: connectionSequence, sessionMaxAppPayload: maximumApplicationPayload)
    }

    public func start() throws {
        guard spec.listenProtocol == .tcp || spec.listenProtocol == .udp,
              spec.listenProtocol == spec.targetProtocol else { throw ObstacleBridgeLinuxServiceSocketOwnerError.unsupportedProtocol }
        let fd = try bindSocket(host: spec.listenHost, port: spec.listenPort, type: spec.listenProtocol == .tcp ? SOCK_STREAM : SOCK_DGRAM)
        if spec.listenProtocol == .tcp, listen(fd, 64) != 0 { let code = errno; _ = close(fd); throw ObstacleBridgeLinuxServiceSocketOwnerError.listenFailure(code) }
        if spec.listenProtocol == .tcp {
            let flags = fcntl(fd, F_GETFL)
            guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else {
                let code = errno; _ = close(fd); throw ObstacleBridgeLinuxServiceSocketOwnerError.socketFailure(code)
            }
        }
        spec = .init(serviceID: spec.serviceID, name: spec.name, listenProtocol: spec.listenProtocol, listenHost: spec.listenHost, listenPort: boundPort(fd), targetProtocol: spec.targetProtocol, targetHost: spec.targetHost, targetPort: spec.targetPort)
        listener = fd
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        listenerSource = source
        source.setEventHandler { [weak self] in self?.listenerReadable() }
        // Descriptor ownership remains synchronous.  A cancellation handler
        // can run after a replacement catalog has rebound the same numeric
        // descriptor, so closing from it could tear down the new listener.
        source.setCancelHandler {}
        source.resume()
    }

    public func stop() {
        queue.sync {
            guard !stopped else { return }
            stopped = true
            let activeListener = listener
            listener = -1
            listenerSource?.cancel(); listenerSource = nil
            for source in connectionSources.values { source.cancel() }
            connectionSources.removeAll()
            if activeListener >= 0 { _ = close(activeListener) }
            for fd in descriptors.values { _ = close(fd) }
            descriptors.removeAll(); udpPeers.removeAll(); udpChannels.removeAll()
        }
    }

    public func handleInbound(_ frame: ObstacleBridgeChannelMuxFrame) {
        queue.async { [weak self] in self?.handleInboundOnQueue(frame) }
    }

    /// Withdraws resource ownership for channels bound to the prior overlay
    /// epoch. This is synchronous so a replacement transport cannot route a
    /// frame through a descriptor or UDP peer mapping from the old epoch.
    @discardableResult
    public func resetTransportEpoch(instanceID: UInt64, connectionSequence: UInt32) -> ObstacleBridgeLinuxServiceSocketOwnerEpochReset {
        queue.sync {
            let tcp = tcpRuntime.resetTransportEpoch(instanceID: instanceID, connectionSeq: connectionSequence)
            let udp = udpRuntime.resetTransportEpoch(instanceID: instanceID, connectionSeq: connectionSequence)
            let tcpChannels = Set(tcp.withdrawnServerChannels + tcp.withdrawnClientChannels)
                .compactMap(UInt16.init(exactly:)).sorted()
            let udpChannels = Set(udp.withdrawnServerChannels + udp.withdrawnClientChannels)
                .compactMap(UInt16.init(exactly:)).sorted()
            for channelID in Set(tcpChannels + udpChannels) { closeChannel(channelID) }
            return .init(withdrawnTCPChannels: tcpChannels, withdrawnUDPChannels: udpChannels)
        }
    }

    public func snapshot() -> ObstacleBridgeLinuxServiceDataPlaneSnapshot {
        queue.sync {
            .init(
                activeTCPChannels: coreTCPChannels.count + coreTCPClientChannels.count,
                activeUDPChannels: coreUDPChannels.count + coreUDPClientChannels.count,
                queuedFrames: 0, droppedFrames: 0, malformedFrames: malformedFrames,
                serviceFailures: serviceFailures, openedTCPChannels: openedTCPChannels,
                openedUDPChannels: openedUDPChannels
            )
        }
    }

    /// Admin-Web projection of this listener and its currently active mux
    /// channels.  The descriptor owner is the only Linux layer that can
    /// distinguish a configured listener from a connection accepted through
    /// that listener; exposing both makes the shared onboarding policy behave
    /// like Python's connection snapshot.
    public func adminConnectionRows(peerID: String, catalog: String = "own_servers") -> [[String: Any]] {
        queue.sync {
            let boundListenerPort = listener >= 0 ? boundPort(listener) : 0
            let base: [String: Any] = [
                "peer_id": peerID,
                "svc_id": Int(spec.serviceID),
                "service_name": spec.name ?? "",
                "role": ObstacleBridgeAdminSnapshotSupport.serviceConnectionRole(catalog: catalog),
                "source": spec.listenHost,
                "local": ["host": spec.listenHost, "port": boundListenerPort],
                "local_port": boundListenerPort,
                "remote_destination": ["host": spec.targetHost, "port": spec.targetPort],
                "catalog": catalog,
                "stats": [
                    "rx_bytes": completedTraffic.rxBytes,
                    "tx_bytes": completedTraffic.txBytes,
                    "rx_msgs": completedTraffic.rxMessages,
                    "tx_msgs": completedTraffic.txMessages,
                ],
                "throttle": ["active": false],
            ]
            var listenerRow = base
            listenerRow["chan_id"] = NSNull()
            listenerRow["state"] = "listening"
            var rows = [listenerRow]
            let channels = (spec.listenProtocol == .tcp ? coreTCPChannels.union(coreTCPClientChannels) : coreUDPChannels.union(coreUDPClientChannels)).sorted()
            for channelID in channels {
                var row = base
                row["chan_id"] = Int(channelID)
                row["state"] = "connected"
                let traffic = channelTraffic[channelID] ?? .init()
                row["stats"] = [
                    "rx_bytes": traffic.rxBytes,
                    "tx_bytes": traffic.txBytes,
                    "rx_msgs": traffic.rxMessages,
                    "tx_msgs": traffic.txMessages,
                ]
                rows.append(row)
            }
            return rows
        }
    }

    private func listenerReadable() {
        guard !stopped else { return }
        if spec.listenProtocol == .tcp {
            while acceptTCP() {}
        } else {
            while receiveUDP() {}
        }
    }

    /// Drains one pending stream client after the listener's readiness source
    /// fires. The listener is nonblocking, so a stale readiness notification
    /// cannot hold the service-owner queue while a peer is between TCP
    /// handshake and application data.
    @discardableResult
    private func acceptTCP() -> Bool {
        let fd = accept(listener, nil, nil)
        guard fd >= 0 else { return false }
        guard let snapshot = try? tcpRuntime.acceptLocalServerConnection(service: nativeSpec(), overlayConnected: true, acceptingEnabled: true),
              let channelID = UInt16(exactly: snapshot.chanID) else { _ = close(fd); return true }
        descriptors[channelID] = fd
        coreTCPChannels.insert(channelID)
        channelTraffic[channelID] = .init()
        openedTCPChannels += 1
        installReadSource(fd: fd, channelID: channelID, isUDP: false)
        emitCoreWires(snapshot.frames)
        return true
    }

    /// Drains one queued datagram without ever blocking the serial owner
    /// queue. `MSG_DONTWAIT` is intentional even though Dispatch reported
    /// readability: another consumer or a transient readiness state may have
    /// emptied the socket before this callback runs.
    @discardableResult
    private func receiveUDP() -> Bool {
        var bytes = [UInt8](repeating: 0, count: 65_535)
        var address = sockaddr_storage(); var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let count = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(listener, &bytes, bytes.count, Int32(MSG_DONTWAIT), $0, &length) }
        }
        guard count > 0 else { return false }
        let addressData = Data(bytes: &address, count: Int(length))
        guard let snapshot = try? udpRuntime.handleLocalServerDatagram(
            service: nativeSpec(), serviceKey: addressData.base64EncodedString(), payload: Data(bytes.prefix(Int(count))),
            addrHost: addressData.base64EncodedString(), addrPort: 0, overlayConnected: true, acceptingEnabled: true
        ), let channelID = UInt16(exactly: snapshot.chanID) else { return true }
        udpChannels[addressData] = channelID
        udpPeers[channelID] = (addressData, length)
        coreUDPChannels.insert(channelID)
        // A UDP peer reuses its Core channel for subsequent datagrams.  Do
        // not reset its accumulated accounting on each readable event.
        if channelTraffic[channelID] == nil { channelTraffic[channelID] = .init() }
        recordLocalRead(channelID: channelID, bytes: Int(count))
        if snapshot.allocatedChannel { openedUDPChannels += 1 }
        debug("service.udp.local_datagram", ["channel": String(channelID), "bytes": String(count), "allocated": snapshot.allocatedChannel ? "true" : "false", "peer": addressData.base64EncodedString()])
        emitCoreWires(snapshot.frames)
        return true
    }

    private func installReadSource(fd: Int32, channelID: UInt16, isUDP: Bool) {
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        connectionSources[channelID] = source
        source.setEventHandler { [weak self] in self?.connectionReadable(channelID: channelID, isUDP: isUDP) }
        // See the listener source above: close while this owner still holds
        // the descriptor rather than asynchronously after cancellation.
        source.setCancelHandler {}
        source.resume()
    }

    private func connectionReadable(channelID: UInt16, isUDP: Bool) {
        guard let fd = descriptors[channelID], !stopped else { return }
        while true {
            var bytes = [UInt8](repeating: 0, count: 65_535)
            let count = recv(fd, &bytes, bytes.count, Int32(MSG_DONTWAIT))
            if count > 0 {
                let payload = Data(bytes.prefix(Int(count)))
                recordLocalRead(channelID: channelID, bytes: Int(count))
                if coreTCPChannels.contains(channelID), let snapshot = try? tcpRuntime.handleLocalServerData(chanID: Int(channelID), payload: payload, overlayConnected: true) {
                    emitCoreWires(snapshot.frames)
                } else if coreTCPClientChannels.contains(channelID), let snapshot = try? tcpRuntime.handleLocalClientData(chanID: Int(channelID), payload: payload, overlayConnected: true) {
                    emitCoreWires(snapshot.frames)
                } else if coreUDPClientChannels.contains(channelID), let snapshot = try? udpRuntime.handleLocalClientDatagram(chanID: Int(channelID), payload: payload) {
                    emitCoreWires(snapshot.frames)
                } else {
                    malformedFrames += 1
                }
                continue
            }
            if count < 0, (errno == EAGAIN || errno == EWOULDBLOCK) { return }
            if count < 0, errno == EINTR { continue }
            if count == 0 || !isUDP {
                if coreTCPChannels.contains(channelID), let snapshot = try? tcpRuntime.handleLocalServerEOF(chanID: Int(channelID), overlayConnected: true) {
                    emitCoreWires(snapshot.frames)
                } else if coreTCPClientChannels.contains(channelID), let snapshot = try? tcpRuntime.handleLocalClientEOF(chanID: Int(channelID), overlayConnected: true) {
                    emitCoreWires(snapshot.frames)
                } else { malformedFrames += 1 }
                closeChannel(channelID)
            }
            return
        }
    }

    private func handleInboundOnQueue(_ frame: ObstacleBridgeChannelMuxFrame) {
        guard !stopped else { return }
        if frame.messageType == .open, frame.protocolType == .tcp {
            let effect = tcpRuntime.handleInboundClientOpen(chanID: Int(frame.channelID), payload: frame.body, counter: Int(frame.counter))
            if effect.accepted, effect.connectRequested,
               let service = tcpRuntime.admittedClientService(chanID: Int(frame.channelID)),
               let target = try? ObstacleBridgeLinuxServiceSpec(nativeSpec: service) {
                do {
                    try connectTarget(channelID: frame.channelID, spec: target)
                    coreTCPClientChannels.insert(frame.channelID)
                    channelTraffic[frame.channelID] = .init()
                    openedTCPChannels += 1
                    _ = tcpRuntime.handleClientConnected(chanID: Int(frame.channelID))
                } catch {
                    serviceFailures += 1
                    _ = tcpRuntime.handleInboundClientClose(chanID: Int(frame.channelID), counter: Int(frame.counter) + 1)
                }
            }
            if !effect.accepted { malformedFrames += 1 }
            return
        }
        if frame.messageType == .open, frame.protocolType == .udp {
            let effect = udpRuntime.handleInboundClientOpen(chanID: Int(frame.channelID), payload: frame.body, counter: Int(frame.counter))
            if effect.accepted, effect.connectRequested,
               let service = udpRuntime.admittedClientService(chanID: Int(frame.channelID)),
               let target = try? ObstacleBridgeLinuxServiceSpec(nativeSpec: service) {
                do {
                    try connectTarget(channelID: frame.channelID, spec: target)
                    coreUDPClientChannels.insert(frame.channelID)
                    channelTraffic[frame.channelID] = .init()
                    openedUDPChannels += 1
                    _ = udpRuntime.handleClientConnected(chanID: Int(frame.channelID))
                } catch {
                    serviceFailures += 1
                    _ = udpRuntime.handleInboundClientClose(chanID: Int(frame.channelID), counter: Int(frame.counter) + 1)
                }
            }
            if !effect.accepted { malformedFrames += 1 }
            return
        }
        if coreTCPClientChannels.contains(frame.channelID) {
            if frame.messageType == .data {
                let effect = tcpRuntime.handleInboundClientData(chanID: Int(frame.channelID), body: frame.body, counter: Int(frame.counter))
                for payload in effect.writtenBuffers { writeLocal(channelID: frame.channelID, payload: payload) }
                return
            }
            if frame.messageType == .close {
                let effect = tcpRuntime.handleInboundClientClose(chanID: Int(frame.channelID), counter: Int(frame.counter))
                if effect.closed { closeChannel(frame.channelID) }
                return
            }
        }
        if coreUDPClientChannels.contains(frame.channelID) {
            if frame.messageType == .data {
                let effect = udpRuntime.handleInboundClientData(chanID: Int(frame.channelID), body: frame.body, counter: Int(frame.counter))
                for payload in effect.sentPackets { writeLocal(channelID: frame.channelID, payload: payload) }
                return
            }
            if frame.messageType == .dataFragment {
                let effect = udpRuntime.handleInboundClientFragment(chanID: Int(frame.channelID), payload: frame.body, counter: Int(frame.counter))
                for payload in effect.sentPackets { writeLocal(channelID: frame.channelID, payload: payload) }
                return
            }
            if frame.messageType == .close {
                let effect = udpRuntime.handleInboundClientClose(chanID: Int(frame.channelID), counter: Int(frame.counter))
                if effect.closed { closeChannel(frame.channelID) }
                return
            }
        }
        if coreTCPChannels.contains(frame.channelID) {
            if frame.messageType == .data {
                let effect = tcpRuntime.handleInboundServerData(chanID: Int(frame.channelID), body: frame.body, counter: Int(frame.counter))
                for payload in effect.writtenBuffers { writeLocal(channelID: frame.channelID, payload: payload) }
                return
            }
            if frame.messageType == .close {
                let effect = tcpRuntime.handleInboundServerClose(chanID: Int(frame.channelID), counter: Int(frame.counter))
                if effect.localConnectionClosed { closeChannel(frame.channelID) }
                return
            }
        }
        if coreUDPChannels.contains(frame.channelID) {
            if frame.messageType == .data {
                let effect = udpRuntime.handleInboundServerData(chanID: Int(frame.channelID), body: frame.body, counter: Int(frame.counter))
                if effect.delivered, let packet = effect.packet { writeLocal(channelID: frame.channelID, payload: packet) }
                return
            }
            if frame.messageType == .dataFragment {
                let effect = udpRuntime.handleInboundServerFragment(chanID: Int(frame.channelID), payload: frame.body, counter: Int(frame.counter))
                if effect.delivered, let packet = effect.packet { writeLocal(channelID: frame.channelID, payload: packet) }
                return
            }
            if frame.messageType == .close {
                _ = udpRuntime.handleInboundClose(chanID: Int(frame.channelID), counter: Int(frame.counter))
                closeChannel(frame.channelID)
                return
            }
        }
        // Every production service frame is admitted by one of the Core
        // runtimes above. Unknown or lifecycle-invalid frames are contained at
        // this resource boundary and never reach a second session owner.
        malformedFrames += 1
    }

    private func connectTarget(channelID: UInt16, spec remoteSpec: ObstacleBridgeLinuxServiceSpec) throws {
        let fd = try connectSocket(host: remoteSpec.targetHost, port: remoteSpec.targetPort, type: remoteSpec.targetProtocol == .tcp ? SOCK_STREAM : SOCK_DGRAM)
        descriptors[channelID] = fd
        installReadSource(fd: fd, channelID: channelID, isUDP: remoteSpec.targetProtocol == .udp)
    }

    private func writeLocal(channelID: UInt16, payload: Data) {
        guard !payload.isEmpty else { return }
        if let (address, length) = udpPeers[channelID] {
            let written = address.withUnsafeBytes { bytes in
                bytes.baseAddress!.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(listener, payload.withUnsafeBytes { $0.baseAddress }, payload.count, 0, $0, length) }
            }
            if written > 0 { recordLocalWrite(channelID: channelID, bytes: Int(written)) }
            debug("service.udp.local_write", ["channel": String(channelID), "bytes": String(written)])
        } else if let fd = descriptors[channelID] {
            let written = payload.withUnsafeBytes { write(fd, $0.baseAddress, payload.count) }
            if written > 0 { recordLocalWrite(channelID: channelID, bytes: Int(written)) }
        }
    }

    private func closeChannel(_ channelID: UInt16) {
        if let traffic = channelTraffic[channelID] {
            completedTraffic.rxBytes += traffic.rxBytes
            completedTraffic.txBytes += traffic.txBytes
            completedTraffic.rxMessages += traffic.rxMessages
            completedTraffic.txMessages += traffic.txMessages
        }
        connectionSources.removeValue(forKey: channelID)?.cancel()
        if let fd = descriptors.removeValue(forKey: channelID) { _ = close(fd) }
        udpPeers.removeValue(forKey: channelID)
        udpChannels = udpChannels.filter { $0.value != channelID }
        coreTCPChannels.remove(channelID)
        coreUDPChannels.remove(channelID)
        coreTCPClientChannels.remove(channelID)
        coreUDPClientChannels.remove(channelID)
        channelTraffic.removeValue(forKey: channelID)
    }

    private func recordLocalRead(channelID: UInt16, bytes: Int) {
        guard bytes > 0 else { return }
        var traffic = channelTraffic[channelID] ?? .init()
        traffic.rxBytes += bytes
        traffic.rxMessages += 1
        channelTraffic[channelID] = traffic
    }

    private func recordLocalWrite(channelID: UInt16, bytes: Int) {
        guard bytes > 0 else { return }
        var traffic = channelTraffic[channelID] ?? .init()
        traffic.txBytes += bytes
        traffic.txMessages += 1
        channelTraffic[channelID] = traffic
    }

    private func nativeSpec() -> ObstacleBridgeNativeServiceSpec {
        .init(svcID: Int(spec.serviceID), name: spec.name, listenProtocol: spec.listenProtocol == .tcp ? "tcp" : "udp", listenBind: spec.listenHost, listenPort: spec.listenPort, targetProtocol: spec.targetProtocol == .tcp ? "tcp" : "udp", targetHost: spec.targetHost, targetPort: spec.targetPort)
    }

    private func emitCoreWires(_ wires: [Data]) {
        let frames = wires.compactMap { wire -> ObstacleBridgeChannelMuxFrame? in
            guard let decoded = try? ObstacleBridgeChannelMuxFrameCodec.decode(wire),
                  let protocolType = ObstacleBridgeChannelMuxProtocol(rawValue: decoded.protocolType),
                  let messageType = ObstacleBridgeChannelMuxMessageType(rawValue: decoded.messageType) else { return nil }
            return .init(channelID: decoded.channelID, protocolType: protocolType, counter: decoded.counter, messageType: messageType, body: decoded.body)
        }
        if !frames.isEmpty { frameSink(self, frames) }
    }

    private func debug(_ event: String, _ fields: @autoclosure () -> [String: String]) {
        guard debugEnabled else { return }
        debugSink?(event, fields())
    }

    private func bindSocket(host: String, port: Int, type: __socket_type) throws -> Int32 {
        let family = addressFamily(for: host)
        let fd = socket(family, Int32(type.rawValue), 0); guard fd >= 0 else { throw ObstacleBridgeLinuxServiceSocketOwnerError.socketFailure(errno) }
        var reuse: Int32 = 1; _ = withUnsafePointer(to: &reuse) { setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, $0, socklen_t(MemoryLayout<Int32>.size)) }
        let result: Int32
        if family == AF_INET6 {
            var address = sockaddr_in6(); address.sin6_family = sa_family_t(AF_INET6); address.sin6_port = in_port_t(UInt16(port).bigEndian)
            guard host.withCString({ inet_pton(AF_INET6, $0, &address.sin6_addr) }) == 1 else { _ = close(fd); throw ObstacleBridgeLinuxServiceSocketOwnerError.bindFailure(EINVAL) }
            result = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) } }
        } else {
            var address = sockaddr_in(); address.sin_family = sa_family_t(AF_INET); address.sin_port = in_port_t(UInt16(port).bigEndian)
            guard host.withCString({ inet_pton(AF_INET, $0, &address.sin_addr) }) == 1 else { _ = close(fd); throw ObstacleBridgeLinuxServiceSocketOwnerError.bindFailure(EINVAL) }
            result = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        }
        guard result == 0 else { let code = errno; _ = close(fd); throw ObstacleBridgeLinuxServiceSocketOwnerError.bindFailure(code) }
        return fd
    }

    private func boundPort(_ fd: Int32) -> Int {
        var address = sockaddr_storage(); var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        guard withUnsafeMutablePointer(to: &address, { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }) == 0 else { return 0 }
        if Int32(address.ss_family) == AF_INET6 {
            return withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { Int(UInt16(bigEndian: $0.pointee.sin6_port)) }
            }
        }
        return withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { Int(UInt16(bigEndian: $0.pointee.sin_port)) }
        }
    }

    private func connectSocket(host: String, port: Int, type: __socket_type) throws -> Int32 {
        let family = addressFamily(for: host)
        let fd = socket(family, Int32(type.rawValue), 0); guard fd >= 0 else { throw ObstacleBridgeLinuxServiceSocketOwnerError.socketFailure(errno) }
        let result: Int32
        if family == AF_INET6 {
            var address = sockaddr_in6(); address.sin6_family = sa_family_t(AF_INET6); address.sin6_port = in_port_t(UInt16(port).bigEndian)
            guard host.withCString({ inet_pton(AF_INET6, $0, &address.sin6_addr) }) == 1 else { _ = close(fd); throw ObstacleBridgeLinuxServiceSocketOwnerError.targetConnectFailure(EINVAL) }
            result = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) } }
        } else {
            var address = sockaddr_in(); address.sin_family = sa_family_t(AF_INET); address.sin_port = in_port_t(UInt16(port).bigEndian)
            guard host.withCString({ inet_pton(AF_INET, $0, &address.sin_addr) }) == 1 else { _ = close(fd); throw ObstacleBridgeLinuxServiceSocketOwnerError.targetConnectFailure(EINVAL) }
            result = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        }
        guard result == 0 else { let code = errno; _ = close(fd); throw ObstacleBridgeLinuxServiceSocketOwnerError.targetConnectFailure(code) }
        return fd
    }

    private func addressFamily(for host: String) -> Int32 { host.contains(":") ? AF_INET6 : AF_INET }

    deinit { stop() }
}
