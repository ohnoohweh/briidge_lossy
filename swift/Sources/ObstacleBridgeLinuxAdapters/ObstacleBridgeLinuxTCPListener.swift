import Foundation
#if os(Linux)
import Glibc
#endif
import ObstacleBridgePortable

/// One-connection TCP SecureLink server used by the Linux listener admission
/// path. ChannelMux/runtime ownership is intentionally kept above this raw
/// transport boundary.
public final class ObstacleBridgeLinuxTCPPSKListener: @unchecked Sendable {
    private var descriptor: Int32
    public let port: Int

    public init(port: Int) throws {
        guard (0...65535).contains(port) else { throw ObstacleBridgeLinuxOverlayTransportError.invalidEndpoint }
        let fd = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        guard fd >= 0 else { throw ObstacleBridgeLinuxOverlayTransportError.socketFailure(errno) }
        var reuse: Int32 = 1
        _ = withUnsafePointer(to: &reuse) { setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, $0, socklen_t(MemoryLayout<Int32>.size)) }
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = UInt16(port).bigEndian
        address.sin_addr = in_addr(s_addr: INADDR_LOOPBACK.bigEndian)
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bound == 0 else { let code = errno; _ = Glibc.close(fd); throw ObstacleBridgeLinuxOverlayTransportError.ioFailure(code) }
        guard listen(fd, 8) == 0 else { let code = errno; _ = Glibc.close(fd); throw ObstacleBridgeLinuxOverlayTransportError.ioFailure(code) }
        var actual = sockaddr_in(); var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        guard withUnsafeMutablePointer(to: &actual, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) } }) == 0 else { let code = errno; _ = Glibc.close(fd); throw ObstacleBridgeLinuxOverlayTransportError.ioFailure(code) }
        descriptor = fd
        self.port = Int(UInt16(bigEndian: actual.sin_port))
    }

    /// Authenticates one Python-compatible TCP client then echoes each
    /// protected application record until the peer closes it.
    public func serveOne(psk: Data, serverNonce: Data) throws {
        let clientFD = accept(descriptor, nil, nil)
        guard clientFD >= 0 else { throw ObstacleBridgeLinuxOverlayTransportError.ioFailure(errno) }
        defer { _ = Glibc.close(clientFD) }
        let server = try ObstacleBridgeSecureLinkPSKServer(psk: psk)
        try writeFrame(try server.handleClientHello(readFrame(clientFD), serverNonce: serverNonce), fd: clientFD)
        try writeFrame(try server.handleClientProof(readFrame(clientFD)), fd: clientFD)
        while true {
            do { try writeFrame(try server.protect(server.unprotect(readFrame(clientFD))), fd: clientFD) }
            catch ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF { return }
        }
    }

    public func close() { if descriptor >= 0 { _ = Glibc.close(descriptor); descriptor = -1 } }
    deinit { close() }

    private func readFrame(_ fd: Int32) throws -> Data {
        let header = try readExactly(fd, count: 4)
        let length = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard length >= 1, length <= 65_536 else { throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame }
        let body = try readExactly(fd, count: Int(length))
        guard body.first == 0 else { throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame }
        return Data(body.dropFirst())
    }
    private func writeFrame(_ payload: Data, fd: Int32) throws {
        guard payload.count < 65_536 else { throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame }
        var wire = Data(); var length = UInt32(payload.count + 1).bigEndian
        wire.append(Data(bytes: &length, count: 4)); wire.append(0); wire.append(payload)
        var offset = 0
        while offset < wire.count {
            let count = wire.withUnsafeBytes { Glibc.send(fd, $0.baseAddress!.advanced(by: offset), wire.count - offset, 0) }
            if count > 0 { offset += count; continue }
            if count == 0 { throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF }
            if errno == EINTR { continue }
            throw ObstacleBridgeLinuxOverlayTransportError.ioFailure(errno)
        }
    }
    private func readExactly(_ fd: Int32, count: Int) throws -> Data {
        var result = Data(count: count); var offset = 0
        while offset < count {
            let received = result.withUnsafeMutableBytes { Glibc.recv(fd, $0.baseAddress!.advanced(by: offset), count - offset, 0) }
            if received > 0 { offset += received; continue }
            if received == 0 { throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF }
            if errno == EINTR { continue }
            throw ObstacleBridgeLinuxOverlayTransportError.ioFailure(errno)
        }
        return result
    }
}
