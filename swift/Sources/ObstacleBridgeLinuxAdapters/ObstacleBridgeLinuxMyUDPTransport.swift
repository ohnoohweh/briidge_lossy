import Dispatch
import Foundation
#if os(Linux)
import Glibc
#endif
import ObstacleBridgePortable

public enum ObstacleBridgeLinuxMyUDPError: Error, Equatable, LocalizedError {
    case resolutionFailed
    case socketFailure(Int32)
    case connectFailure(Int32)
    case ioFailure(Int32)
    case invalidReply

    public var errorDescription: String? {
        switch self {
        case .resolutionFailed: return "myudp peer resolution failed"
        case .socketFailure(let code), .connectFailure(let code), .ioFailure(let code): return "myudp POSIX failure errno=\(code)"
        case .invalidReply: return "invalid myudp reply"
        }
    }
}

/// Connected POSIX datagram owner for one myudp peer. Reliability/liveness is
/// deliberately layered above this strict DATA-frame exchange primitive.
public final class ObstacleBridgeLinuxMyUDPTransportSession {
    private var descriptor: Int32
    private var nextCounter: UInt16 = 1

    public init(host: String, port: Int, timeoutMilliseconds: Int = 1_000) throws {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = Int32(SOCK_DGRAM.rawValue)
        hints.ai_protocol = Int32(IPPROTO_UDP)
        var addresses: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &addresses) == 0, let first = addresses else { throw ObstacleBridgeLinuxMyUDPError.resolutionFailed }
        defer { freeaddrinfo(first) }
        var candidate: UnsafeMutablePointer<addrinfo>? = first
        var failure: Error = ObstacleBridgeLinuxMyUDPError.resolutionFailed
        var opened: Int32 = -1
        while let row = candidate {
            let fd = socket(row.pointee.ai_family, row.pointee.ai_socktype, row.pointee.ai_protocol)
            if fd >= 0 {
                if connect(fd, row.pointee.ai_addr, row.pointee.ai_addrlen) == 0 {
                    var timeout = timeval(tv_sec: timeoutMilliseconds / 1_000, tv_usec: (timeoutMilliseconds % 1_000) * 1_000)
                    _ = withUnsafePointer(to: &timeout) { setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, $0, socklen_t(MemoryLayout<timeval>.size)) }
                    opened = fd
                    break
                }
                failure = ObstacleBridgeLinuxMyUDPError.connectFailure(errno)
                _ = Glibc.close(fd)
            } else {
                failure = ObstacleBridgeLinuxMyUDPError.socketFailure(errno)
            }
            candidate = row.pointee.ai_next
        }
        guard opened >= 0 else { throw failure }
        descriptor = opened
    }

    public func exchange(_ payload: Data) throws -> Data {
        guard descriptor >= 0 else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(EBADF) }
        let counter = nextCounter
        nextCounter = counter == UInt16.max ? 1 : counter &+ 1
        let wire = try ObstacleBridgeMyUDPCodec.encodeData(payload: payload, counter: counter, transmittedNanoseconds: DispatchTime.now().uptimeNanoseconds)
        let sent = wire.withUnsafeBytes { send(descriptor, $0.baseAddress, wire.count, 0) }
        guard sent == wire.count else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(errno) }
        var buffer = [UInt8](repeating: 0, count: 1_452)
        let received = recv(descriptor, &buffer, buffer.count, 0)
        guard received > 0 else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(errno) }
        guard let decoded = try? ObstacleBridgeMyUDPCodec.decodeData(Data(buffer.prefix(Int(received)))), decoded.counter == counter else { throw ObstacleBridgeLinuxMyUDPError.invalidReply }
        return decoded.payload
    }

    public func close() {
        if descriptor >= 0 { _ = Glibc.close(descriptor); descriptor = -1 }
    }
    deinit { close() }
}
