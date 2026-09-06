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
        let accepted = try acceptConfiguredSession(psk: psk, serverNonce: serverNonce)
        defer { accepted.close() }
        while true {
            do { _ = try accepted.send(try accepted.receiveInbound()) }
            catch ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF { return }
        }
    }

    /// Accept and authenticate an inbound TCP epoch so the live runtime can
    /// adopt the same configured-session boundary used by outgoing clients.
    public func acceptConfiguredSession(psk: Data, serverNonce: Data) throws -> ObstacleBridgeLinuxConfiguredSession {
        var peerAddress = sockaddr_in()
        var peerAddressLength = socklen_t(MemoryLayout<sockaddr_in>.size)
        let clientFD = withUnsafeMutablePointer(to: &peerAddress) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                accept(descriptor, $0, &peerAddressLength)
            }
        }
        guard clientFD >= 0 else { throw ObstacleBridgeLinuxOverlayTransportError.ioFailure(errno) }
        let peerPort = Int(UInt16(bigEndian: peerAddress.sin_port))
        let server = try ObstacleBridgeSecureLinkPSKServer(psk: psk)
        try writeFrame(try server.handleClientHello(readFrame(clientFD, observedPeerPort: peerPort), serverNonce: serverNonce), fd: clientFD)
        try writeFrame(try server.handleClientProof(readFrame(clientFD, observedPeerPort: peerPort)), fd: clientFD)
        let lock = NSLock()
        var open = true
        let receive: () throws -> Data = { [weak self] in
            guard let self else { throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF }
            return try self.readFrame(clientFD, observedPeerPort: peerPort)
        }
        let send: (Data) throws -> Void = { [weak self] payload in
            guard let self else { throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF }
            try self.writeFrame(payload, fd: clientFD)
        }
        let raw = ObstacleBridgeLinuxOverlayTransportSession(exchange: { payload in try send(payload); return try receive() }, send: send, receive: receive, close: {
            lock.lock(); let shouldClose = open; open = false; lock.unlock()
            if shouldClose { _ = Glibc.close(clientFD) }
        })
        let lower = try ObstacleBridgeLinuxOverlayTransportClient(host: "127.0.0.1", port: port, transport: .tcp)
        return ObstacleBridgeLinuxConfiguredSession(lower: lower, lowerSession: raw, secureLink: nil, secureLinkServer: server, transport: .tcp)
    }

    public func close() { if descriptor >= 0 { _ = Glibc.close(descriptor); descriptor = -1 } }
    deinit { close() }

    private func readFrame(_ fd: Int32, observedPeerPort: Int? = nil) throws -> Data {
        while true {
            let header = try readExactly(fd, count: 4)
            let length = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            guard length >= 1, length <= 65_536 else { throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame }
            let body = try readExactly(fd, count: Int(length))
            guard let kind = body.first else { throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame }
            let payload = Data(body.dropFirst())
            switch kind {
            case 0 where payload == Data("OBPA\u{02}\u{01}\u{00}".utf8):
                guard let observedPeerPort, (1...65535).contains(observedPeerPort) else {
                    throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame
                }
                var reply = Data("OBPA\u{02}\u{02}\u{04}\u{7f}\u{00}\u{00}\u{01}".utf8)
                var port = UInt16(observedPeerPort).bigEndian
                reply.append(Data(bytes: &port, count: MemoryLayout<UInt16>.size))
                try writeWire(kind: 0, payload: reply, fd: fd)
            case 0: return payload
            case 1:
                guard payload.count >= 8 else { throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame }
                try writeWire(kind: 2, payload: Data(payload.prefix(8)), fd: fd)
            case 2: continue
            default: throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame
            }
        }
    }
    private func writeFrame(_ payload: Data, fd: Int32) throws {
        try writeWire(kind: 0, payload: payload, fd: fd)
    }
    private func writeWire(kind: UInt8, payload: Data, fd: Int32) throws {
        guard payload.count < 65_536 else { throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame }
        var wire = Data(); var length = UInt32(payload.count + 1).bigEndian
        wire.append(Data(bytes: &length, count: 4)); wire.append(kind); wire.append(payload)
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
