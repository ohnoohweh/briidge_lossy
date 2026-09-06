import Dispatch
import Foundation
#if os(Linux)
import Glibc
#endif
import ObstacleBridgePortable

public enum ObstacleBridgeLinuxServiceSocketOwnerError: Error, Equatable {
    case unsupportedProtocol
    case socketFailure(Int32)
    case bindFailure(Int32)
    case listenFailure(Int32)
    case targetConnectFailure(Int32)
}

/// POSIX descriptor owner for one configured TCP or UDP service. All socket
/// callbacks and data-plane mutation run on one serial queue; no descriptor or
/// channel state is touched by the overlay thread directly.
public final class ObstacleBridgeLinuxServiceSocketOwner: @unchecked Sendable {
    public typealias FrameSink = (ObstacleBridgeLinuxServiceSocketOwner, [ObstacleBridgeChannelMuxFrame]) -> Void

    private let spec: ObstacleBridgeLinuxServiceSpec
    private let frameSink: FrameSink
    private let queue: DispatchQueue
    private let plane: ObstacleBridgeLinuxServiceDataPlane
    private var listener: Int32 = -1
    private var listenerSource: DispatchSourceRead?
    private var connectionSources: [UInt16: DispatchSourceRead] = [:]
    private var descriptors: [UInt16: Int32] = [:]
    private var udpPeers: [UInt16: (Data, socklen_t)] = [:]
    private var udpChannels: [Data: UInt16] = [:]
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

    public init(spec: ObstacleBridgeLinuxServiceSpec, maximumQueuedFrames: Int = 128, instanceID: UInt64 = 0, connectionSequence: UInt32 = 0, frameSink: @escaping FrameSink) {
        self.spec = spec
        self.frameSink = frameSink
        self.queue = DispatchQueue(label: "org.obstaclebridge.linux.service.\(spec.serviceID)")
        self.plane = ObstacleBridgeLinuxServiceDataPlane(maximumQueuedFrames: maximumQueuedFrames, instanceID: instanceID, connectionSequence: connectionSequence)
    }

    public func start() throws {
        guard spec.listenProtocol == .tcp || spec.listenProtocol == .udp,
              spec.listenProtocol == spec.targetProtocol else { throw ObstacleBridgeLinuxServiceSocketOwnerError.unsupportedProtocol }
        let fd = try bindSocket(host: spec.listenHost, port: spec.listenPort, type: spec.listenProtocol == .tcp ? SOCK_STREAM : SOCK_DGRAM)
        if spec.listenProtocol == .tcp, listen(fd, 64) != 0 { let code = errno; _ = close(fd); throw ObstacleBridgeLinuxServiceSocketOwnerError.listenFailure(code) }
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

    public func snapshot() -> ObstacleBridgeLinuxServiceDataPlaneSnapshot { queue.sync { plane.snapshot() } }

    private func listenerReadable() {
        guard !stopped else { return }
        if spec.listenProtocol == .tcp { acceptTCP() } else { receiveUDP() }
    }

    private func acceptTCP() {
        let fd = accept(listener, nil, nil)
        guard fd >= 0, let channelID = try? plane.acceptLocalService(spec) else { return }
        descriptors[channelID] = fd
        installReadSource(fd: fd, channelID: channelID, isUDP: false)
        flushFrames()
    }

    private func receiveUDP() {
        var bytes = [UInt8](repeating: 0, count: 65_535)
        var address = sockaddr_storage(); var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let count = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(listener, &bytes, bytes.count, 0, $0, &length) }
        }
        guard count > 0 else { return }
        let addressData = Data(bytes: &address, count: Int(length))
        let channelID: UInt16
        if let existing = udpChannels[addressData] { channelID = existing }
        else {
            guard let created = try? plane.acceptLocalService(spec) else { return }
            channelID = created; udpChannels[addressData] = created; udpPeers[created] = (addressData, length); flushFrames()
        }
        guard (try? plane.localData(channelID: channelID, payload: Data(bytes.prefix(Int(count))))) != nil else { return }
        flushFrames()
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
            _ = try? plane.localData(channelID: channelID, payload: Data(bytes.prefix(Int(count))))
            flushFrames()
        } else if count == 0 || !isUDP {
            _ = try? plane.localEOF(channelID: channelID)
            flushFrames()
            closeChannel(channelID)
        }
    }

    private func handleInboundOnQueue(_ frame: ObstacleBridgeChannelMuxFrame) {
        guard !stopped else { return }
        do {
            switch try plane.receive(frame) {
            case .connectRequested(let channelID, let remoteSpec):
                try connectTarget(channelID: channelID, spec: remoteSpec)
            case .deliverLocal(let channelID, let payload):
                writeLocal(channelID: channelID, payload: payload)
            case .closeLocal(let channelID):
                if let fd = descriptors[channelID] { _ = shutdown(fd, Int32(SHUT_WR)) }
            case nil:
                break
            }
        } catch {
            // The data plane owns bounded malformed/drop counters; keeping the
            // socket owner alive isolates one invalid peer frame.
        }
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
    }

    private func flushFrames() { let frames = plane.drainOutbound(); if !frames.isEmpty { frameSink(self, frames) } }

    private func bindSocket(host: String, port: Int, type: __socket_type) throws -> Int32 {
        let fd = socket(AF_INET, Int32(type.rawValue), 0); guard fd >= 0 else { throw ObstacleBridgeLinuxServiceSocketOwnerError.socketFailure(errno) }
        var reuse: Int32 = 1; _ = withUnsafePointer(to: &reuse) { setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, $0, socklen_t(MemoryLayout<Int32>.size)) }
        var address = sockaddr_in(); address.sin_family = sa_family_t(AF_INET); address.sin_port = in_port_t(UInt16(port).bigEndian)
        guard host.withCString({ inet_pton(AF_INET, $0, &address.sin_addr) }) == 1 else { _ = close(fd); throw ObstacleBridgeLinuxServiceSocketOwnerError.bindFailure(EINVAL) }
        let result = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard result == 0 else { let code = errno; _ = close(fd); throw ObstacleBridgeLinuxServiceSocketOwnerError.bindFailure(code) }
        return fd
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
