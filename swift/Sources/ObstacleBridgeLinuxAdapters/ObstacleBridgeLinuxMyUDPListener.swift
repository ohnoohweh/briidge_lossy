import Dispatch
import Foundation
import ObstacleBridgeCore
#if os(Linux)
import Glibc
#endif

/// Socket owner for a shared-datagram myUDP listener. Reliable peer state is
/// kept exclusively by `ObstacleBridgeMyUDPPeerRegistry` in Core.
public final class ObstacleBridgeLinuxMyUDPListener {
    public struct ReceivedRecord: Sendable {
        public let peerIdentity: String
        public let payload: Data
    }

    private let descriptor: Int32
    private let registry = ObstacleBridgeMyUDPPeerRegistry()
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

    deinit { _ = Glibc.close(descriptor) }

    /// Processes one datagram. The caller supplies the epoch selected by its
    /// admission/authentication layer; endpoint identity alone never resets
    /// an established reliable peer.
    public func receive(epoch: UInt64 = 1) throws -> ReceivedRecord? {
        var bytes = [UInt8](repeating: 0, count: 1_452)
        var address = sockaddr_storage()
        var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let count = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(descriptor, &bytes, bytes.count, 0, $0, &length) }
        }
        guard count > 0 else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(errno) }
        let identity = peerIdentity(address, length: length)
        let key = ObstacleBridgeMyUDPPeerRegistry.PeerKey(identity: identity, epoch: epoch)
        let effect: ObstacleBridgeMyUDPPeerEngine.Effect
        do { effect = try registry.receiveWire(Data(bytes.prefix(Int(count))), from: key, nowNanoseconds: DispatchTime.now().uptimeNanoseconds) }
        catch { throw ObstacleBridgeLinuxMyUDPError.invalidReply }
        for datagram in effect.outboundDatagrams {
            let sent = datagram.withUnsafeBytes { payload in
                withUnsafePointer(to: &address) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(descriptor, payload.baseAddress, datagram.count, 0, $0, length) }
                }
            }
            guard sent == datagram.count else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(errno) }
        }
        guard let payload = registry.admit(key).takeDeliveredRecord() else { return nil }
        return .init(peerIdentity: identity, payload: payload)
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
