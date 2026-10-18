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

    private var spec: ObstacleBridgeLinuxServiceSpec
    private let frameSink: FrameSink
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
            guard listener >= 0 else { return 0 }
            var address = sockaddr_in(); var length = socklen_t(MemoryLayout<sockaddr_in>.size)
            _ = withUnsafeMutablePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(listener, $0, &length) }
            }
            return Int(UInt16(bigEndian: address.sin_port))
        }
    }

    public init(spec: ObstacleBridgeLinuxServiceSpec, maximumQueuedFrames: Int = 128, maximumApplicationPayload: Int = 65_535, instanceID: UInt64 = 0, connectionSequence: UInt32 = 0, channelIDAllocation: ObstacleBridgeChannelMuxChannelIDAllocation = .peerClient(), frameSink: @escaping FrameSink) {
        self.spec = spec
        self.frameSink = frameSink
        self.queue = DispatchQueue(label: "org.obstaclebridge.linux.service.\(spec.serviceID)")
        self.tcpRuntime = ObstacleBridgeChannelMuxTcpRuntime(instanceID: instanceID, connectionSeq: connectionSequence, allocation: channelIDAllocation, sessionMaxAppPayload: maximumApplicationPayload)
        self.udpRuntime = ObstacleBridgeChannelMuxUdpRuntime(instanceID: instanceID, connectionSeq: connectionSequence, sessionMaxAppPayload: maximumApplicationPayload)
    }

    public func start() throws {
        guard spec.listenProtocol == .tcp || spec.listenProtocol == .udp,
              spec.listenProtocol == spec.targetProtocol else { throw ObstacleBridgeLinuxServiceSocketOwnerError.unsupportedProtocol }
        let fd = try bindSocket(host: spec.listenHost, port: spec.listenPort, type: spec.listenProtocol == .tcp ? SOCK_STREAM : SOCK_DGRAM)
        if spec.listenProtocol == .tcp, listen(fd, 64) != 0 { let code = errno; _ = close(fd); throw ObstacleBridgeLinuxServiceSocketOwnerError.listenFailure(code) }
        spec = .init(serviceID: spec.serviceID, name: spec.name, listenProtocol: spec.listenProtocol, listenHost: spec.listenHost, listenPort: boundPort(fd), targetProtocol: spec.targetProtocol, targetHost: spec.targetHost, targetPort: spec.targetPort)
        listener = fd
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        listenerSource = source
        source.setEventHandler { [weak self] in self?.listenerReadable() }
        source.setCancelHandler { _ = close(fd) }
        source.resume()
    }

    public func stop() {
        queue.sync {
            guard !stopped else { return }
            stopped = true
            listenerSource?.cancel(); listenerSource = nil; listener = -1
            for source in connectionSources.values { source.cancel() }
            connectionSources.removeAll()
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
                "role": "client",
                "source": spec.listenHost,
                "local": ["host": spec.listenHost, "port": boundListenerPort],
                "local_port": boundListenerPort,
                "remote_destination": ["host": spec.targetHost, "port": spec.targetPort],
                "catalog": catalog,
                "stats": ["rx_bytes": 0, "tx_bytes": 0, "rx_msgs": 0, "tx_msgs": 0],
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
                rows.append(row)
            }
            return rows
        }
    }

    private func listenerReadable() {
        guard !stopped else { return }
        if spec.listenProtocol == .tcp { acceptTCP() } else { receiveUDP() }
    }

    private func acceptTCP() {
        let fd = accept(listener, nil, nil)
        guard fd >= 0,
              let snapshot = try? tcpRuntime.acceptLocalServerConnection(service: nativeSpec(), overlayConnected: true, acceptingEnabled: true),
              let channelID = UInt16(exactly: snapshot.chanID) else { if fd >= 0 { _ = close(fd) }; return }
        descriptors[channelID] = fd
        coreTCPChannels.insert(channelID)
        openedTCPChannels += 1
        installReadSource(fd: fd, channelID: channelID, isUDP: false)
        emitCoreWires(snapshot.frames)
    }

    private func receiveUDP() {
        var bytes = [UInt8](repeating: 0, count: 65_535)
        var address = sockaddr_storage(); var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let count = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(listener, &bytes, bytes.count, 0, $0, &length) }
        }
        guard count > 0 else { return }
        let addressData = Data(bytes: &address, count: Int(length))
        guard let snapshot = try? udpRuntime.handleLocalServerDatagram(
            service: nativeSpec(), serviceKey: addressData.base64EncodedString(), payload: Data(bytes.prefix(Int(count))),
            addrHost: addressData.base64EncodedString(), addrPort: 0, overlayConnected: true, acceptingEnabled: true
        ), let channelID = UInt16(exactly: snapshot.chanID) else { return }
        udpChannels[addressData] = channelID
        udpPeers[channelID] = (addressData, length)
        coreUDPChannels.insert(channelID)
        if snapshot.allocatedChannel { openedUDPChannels += 1 }
        emitCoreWires(snapshot.frames)
    }

    private func installReadSource(fd: Int32, channelID: UInt16, isUDP: Bool) {
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        connectionSources[channelID] = source
        source.setEventHandler { [weak self] in self?.connectionReadable(channelID: channelID, isUDP: isUDP) }
        source.setCancelHandler { _ = close(fd) }
        source.resume()
    }

    private func connectionReadable(channelID: UInt16, isUDP: Bool) {
        guard let fd = descriptors[channelID], !stopped else { return }
        var bytes = [UInt8](repeating: 0, count: 65_535)
        let count = read(fd, &bytes, bytes.count)
        if count > 0 {
            let payload = Data(bytes.prefix(Int(count)))
            if coreTCPChannels.contains(channelID), let snapshot = try? tcpRuntime.handleLocalServerData(chanID: Int(channelID), payload: payload, overlayConnected: true) {
                emitCoreWires(snapshot.frames)
            } else if coreTCPClientChannels.contains(channelID), let snapshot = try? tcpRuntime.handleLocalClientData(chanID: Int(channelID), payload: payload, overlayConnected: true) {
                emitCoreWires(snapshot.frames)
            } else if coreUDPClientChannels.contains(channelID), let snapshot = try? udpRuntime.handleLocalClientDatagram(chanID: Int(channelID), payload: payload) {
                emitCoreWires(snapshot.frames)
            } else {
                malformedFrames += 1
            }
        } else if count == 0 || !isUDP {
            if coreTCPChannels.contains(channelID), let snapshot = try? tcpRuntime.handleLocalServerEOF(chanID: Int(channelID), overlayConnected: true) {
                emitCoreWires(snapshot.frames)
            } else if coreTCPClientChannels.contains(channelID), let snapshot = try? tcpRuntime.handleLocalClientEOF(chanID: Int(channelID), overlayConnected: true) {
                emitCoreWires(snapshot.frames)
            } else { malformedFrames += 1 }
            closeChannel(channelID)
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
            _ = address.withUnsafeBytes { bytes in
                bytes.baseAddress!.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(listener, payload.withUnsafeBytes { $0.baseAddress }, payload.count, 0, $0, length) }
            }
        } else if let fd = descriptors[channelID] {
            _ = payload.withUnsafeBytes { write(fd, $0.baseAddress, payload.count) }
        }
    }

    private func closeChannel(_ channelID: UInt16) {
        connectionSources.removeValue(forKey: channelID)?.cancel()
        descriptors.removeValue(forKey: channelID)
        udpPeers.removeValue(forKey: channelID)
        udpChannels = udpChannels.filter { $0.value != channelID }
        coreTCPChannels.remove(channelID)
        coreUDPChannels.remove(channelID)
        coreTCPClientChannels.remove(channelID)
        coreUDPClientChannels.remove(channelID)
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

    private func bindSocket(host: String, port: Int, type: __socket_type) throws -> Int32 {
        let fd = socket(AF_INET, Int32(type.rawValue), 0); guard fd >= 0 else { throw ObstacleBridgeLinuxServiceSocketOwnerError.socketFailure(errno) }
        var reuse: Int32 = 1; _ = withUnsafePointer(to: &reuse) { setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, $0, socklen_t(MemoryLayout<Int32>.size)) }
        var address = sockaddr_in(); address.sin_family = sa_family_t(AF_INET); address.sin_port = in_port_t(UInt16(port).bigEndian)
        guard host.withCString({ inet_pton(AF_INET, $0, &address.sin_addr) }) == 1 else { _ = close(fd); throw ObstacleBridgeLinuxServiceSocketOwnerError.bindFailure(EINVAL) }
        let result = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard result == 0 else { let code = errno; _ = close(fd); throw ObstacleBridgeLinuxServiceSocketOwnerError.bindFailure(code) }
        return fd
    }

    private func boundPort(_ fd: Int32) -> Int {
        var address = sockaddr_in(); var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        guard withUnsafeMutablePointer(to: &address, { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }) == 0 else { return 0 }
        return Int(UInt16(bigEndian: address.sin_port))
    }

    private func connectSocket(host: String, port: Int, type: __socket_type) throws -> Int32 {
        let fd = socket(AF_INET, Int32(type.rawValue), 0); guard fd >= 0 else { throw ObstacleBridgeLinuxServiceSocketOwnerError.socketFailure(errno) }
        var address = sockaddr_in(); address.sin_family = sa_family_t(AF_INET); address.sin_port = in_port_t(UInt16(port).bigEndian)
        guard host.withCString({ inet_pton(AF_INET, $0, &address.sin_addr) }) == 1 else { _ = close(fd); throw ObstacleBridgeLinuxServiceSocketOwnerError.targetConnectFailure(EINVAL) }
        let result = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard result == 0 else { let code = errno; _ = close(fd); throw ObstacleBridgeLinuxServiceSocketOwnerError.targetConnectFailure(code) }
        return fd
    }

    deinit { stop() }
}
