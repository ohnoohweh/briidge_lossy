import Dispatch
import Foundation
import ObstacleBridgeCore
#if os(Linux)
import Glibc
#endif

/// Socket owner for a shared-datagram myUDP listener. Reliable peer state is
/// kept exclusively by `ObstacleBridgeMyUDPPeerRegistry` in Core.
public final class ObstacleBridgeLinuxMyUDPListener {
    private struct Endpoint {
        var address: sockaddr_storage
        let length: socklen_t
    }

    public struct ReceivedRecord: Sendable {
        public let peerIdentity: String
        public let payload: Data
    }

    private var descriptor: Int32
    private let descriptorLock = NSLock()
    private let registry = ObstacleBridgeMyUDPPeerRegistry()
    private var endpoints: [ObstacleBridgeMyUDPPeerRegistry.PeerKey: Endpoint] = [:]
    public let port: Int

    public init(port: Int, bindHost: String = "0.0.0.0") throws {
        guard (0...65_535).contains(port) else { throw ObstacleBridgeLinuxMyUDPError.resolutionFailed }
        let fd = socket(AF_INET, Int32(SOCK_DGRAM.rawValue), Int32(IPPROTO_UDP))
        guard fd >= 0 else { throw ObstacleBridgeLinuxMyUDPError.socketFailure(errno) }
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(UInt16(port).bigEndian)
        guard inet_pton(AF_INET, bindHost, &address.sin_addr) == 1 else { _ = Glibc.close(fd); throw ObstacleBridgeLinuxMyUDPError.resolutionFailed }
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bound == 0 else { let code = errno; _ = Glibc.close(fd); throw ObstacleBridgeLinuxMyUDPError.socketFailure(code) }
        descriptor = fd
        var actual = sockaddr_in(); var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        guard withUnsafeMutablePointer(to: &actual, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) } }) == 0 else { _ = Glibc.close(fd); throw ObstacleBridgeLinuxMyUDPError.socketFailure(errno) }
        self.port = Int(UInt16(bigEndian: actual.sin_port))
    }

    deinit { close() }

    public func close() {
        descriptorLock.lock()
        let fd = descriptor
        descriptor = -1
        descriptorLock.unlock()
        if fd >= 0 { _ = Glibc.close(fd) }
    }

    public var activePeerCount: Int { registry.activeKeys.count }

    /// Applies Core's idle-expiry policy and returns endpoint identities that
    /// the adapter/event loop should withdraw from external bookkeeping.
    @discardableResult public func expireIdlePeers(
        nowNanoseconds: UInt64 = DispatchTime.now().uptimeNanoseconds,
        idleTimeoutNanoseconds: UInt64
    ) -> [String] {
        let expired = registry.expire(
            nowNanoseconds: nowNanoseconds,
            idleTimeoutNanoseconds: idleTimeoutNanoseconds
        )
        expired.forEach { endpoints.removeValue(forKey: $0) }
        return expired.map(\.identity)
    }

    /// Executes Core timer effects for every admitted peer and routes each
    /// datagram to the endpoint retained by this socket adapter.
    @discardableResult public func serviceTimers(
        nowNanoseconds: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) throws -> Int {
        descriptorLock.lock()
        let fd = descriptor
        descriptorLock.unlock()
        guard fd >= 0 else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(EBADF) }
        var emitted = 0
        for key in registry.activeKeys {
            guard let endpoint = endpoints[key], let effect = try registry.tick(key, nowNanoseconds: nowNanoseconds) else { continue }
            try execute(effect, endpoint: endpoint, descriptor: fd)
            emitted += effect.outboundDatagrams.count
        }
        return emitted
    }

    /// Processes one datagram. The caller supplies the epoch selected by its
    /// admission/authentication layer; endpoint identity alone never resets
    /// an established reliable peer.
    public func receive(epoch: UInt64 = 1) throws -> ReceivedRecord? {
        descriptorLock.lock()
        let fd = descriptor
        descriptorLock.unlock()
        guard fd >= 0 else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(EBADF) }
        var bytes = [UInt8](repeating: 0, count: 1_452)
        var address = sockaddr_storage()
        var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let count = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(fd, &bytes, bytes.count, 0, $0, &length) }
        }
        guard count > 0 else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(errno) }
        let identity = peerIdentity(address, length: length)
        let key = ObstacleBridgeMyUDPPeerRegistry.PeerKey(identity: identity, epoch: epoch)
        guard registry.selectEpoch(identity: identity, epoch: epoch) else {
            throw ObstacleBridgeLinuxMyUDPError.invalidReply
        }
        endpoints = endpoints.filter { existing, _ in
            existing.identity != identity || existing.epoch == epoch
        }
        let endpoint = Endpoint(address: address, length: length)
        endpoints[key] = endpoint
        let effect: ObstacleBridgeMyUDPPeerEngine.Effect
        do { effect = try registry.receiveWire(Data(bytes.prefix(Int(count))), from: key, nowNanoseconds: DispatchTime.now().uptimeNanoseconds) }
        catch { throw ObstacleBridgeLinuxMyUDPError.invalidReply }
        try execute(effect, endpoint: endpoint, descriptor: fd)
        guard let payload = registry.admit(key).takeDeliveredRecord() else { return nil }
        return .init(peerIdentity: identity, payload: payload)
    }

    private func execute(_ effect: ObstacleBridgeMyUDPPeerEngine.Effect, endpoint: Endpoint, descriptor: Int32) throws {
        var address = endpoint.address
        for datagram in effect.outboundDatagrams {
            let sent = datagram.withUnsafeBytes { payload in
                withUnsafePointer(to: &address) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(descriptor, payload.baseAddress, datagram.count, 0, $0, endpoint.length) }
                }
            }
            guard sent == datagram.count else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(errno) }
        }
    }

    private func peerIdentity(_ address: sockaddr_storage, length: socklen_t) -> String {
        var copy = address
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        var service = [CChar](repeating: 0, count: Int(NI_MAXSERV))
        let status = withUnsafePointer(to: &copy) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getnameinfo($0, length, &host, socklen_t(host.count), &service, socklen_t(service.count), NI_NUMERICHOST | NI_NUMERICSERV) }
        }
        guard status == 0 else { return "unknown" }
        let hostText = String(decoding: host.prefix { $0 != 0 }.map(UInt8.init(bitPattern:)), as: UTF8.self)
        let serviceText = String(decoding: service.prefix { $0 != 0 }.map(UInt8.init(bitPattern:)), as: UTF8.self)
        return "\(hostText):\(serviceText)"
    }
}
