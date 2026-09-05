import Crypto
import Foundation
#if os(Linux)
import Glibc
#endif

public enum ObstacleBridgeLinuxTransport: String, CaseIterable, Sendable {
    case tcp
    case ws
    case myudp
    case quic

    public var isAvailable: Bool {
        switch self {
        case .tcp, .ws, .myudp:
            true
        case .quic:
            false
        }
    }

    public var unavailableReason: String? {
        switch self {
        case .tcp, .ws, .myudp:
            nil
        case .quic:
            "Linux QUIC is unavailable: the Network.framework owner has no qualified Linux backend"
        }
    }
}

public enum ObstacleBridgeLinuxOverlayTransportError: Error, Equatable, LocalizedError {
    case unavailableTransport(String)
    case invalidEndpoint
    case dnsFailure(String)
    case socketFailure(Int32)
    case connectFailure(Int32)
    case ioFailure(Int32)
    case unexpectedEOF
    case invalidFrame
    case unsupportedWebSocketTLS
    case webSocketHandshakeFailed
    case webSocketProtocolError

    public var errorDescription: String? {
        switch self {
        case .unavailableTransport(let reason), .dnsFailure(let reason): return reason
        case .invalidEndpoint: return "invalid overlay endpoint"
        case .socketFailure(let code), .connectFailure(let code), .ioFailure(let code): return "POSIX socket failure errno=\(code)"
        case .unexpectedEOF: return "overlay peer closed the connection"
        case .invalidFrame: return "invalid overlay frame"
        case .unsupportedWebSocketTLS: return "wss is not admitted until a Linux TLS backend is qualified"
        case .webSocketHandshakeFailed: return "WebSocket upgrade was rejected"
        case .webSocketProtocolError: return "invalid WebSocket frame"
        }
    }
}

public struct ObstacleBridgeLinuxOverlaySnapshot: Equatable, Sendable {
    public let transport: String
    public let state: String
    public let attempts: Int
    public let failureReason: String?
}

/// Linux POSIX lower-transport probes. They intentionally own only the raw
/// transport framing: config, SecureLink session state, ChannelMux, TUN, and
/// Admin integration remain in their respective runtime work packages.
public final class ObstacleBridgeLinuxOverlayTransportClient {
    private let host: String
    private let port: Int
    private let transport: ObstacleBridgeLinuxTransport
    private let wsPath: String
    private(set) public var snapshot: ObstacleBridgeLinuxOverlaySnapshot

    public init(host: String, port: Int, transport: ObstacleBridgeLinuxTransport, wsPath: String = "/") throws {
        guard !host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, (1...65535).contains(port) else {
            throw ObstacleBridgeLinuxOverlayTransportError.invalidEndpoint
        }
        guard transport.isAvailable else {
            throw ObstacleBridgeLinuxOverlayTransportError.unavailableTransport(transport.unavailableReason ?? "transport unavailable")
        }
        self.host = host
        self.port = port
        self.transport = transport
        self.wsPath = wsPath.hasPrefix("/") ? wsPath : "/\(wsPath)"
        self.snapshot = .init(transport: transport.rawValue, state: "disconnected", attempts: 0, failureReason: nil)
    }

    /// Sends one lower-layer application payload and returns one peer payload.
    /// A retry opens a fresh socket, so no stale transport epoch is retained.
    public func roundTrip(_ payload: Data, attempts: Int = 2) throws -> Data {
        let totalAttempts = max(1, attempts)
        var lastError: Error?
        for attempt in 1...totalAttempts {
            snapshot = .init(transport: transport.rawValue, state: "connecting", attempts: attempt, failureReason: nil)
            do {
                let result: Data
                switch transport {
                case .tcp:
                    let connection = try POSIXStreamConnection(host: host, port: port)
                    defer { connection.close() }
                    try connection.write(tcpWire(payload))
                    result = try readTCPApplicationFrame(connection)
                case .ws:
                    let connection = try POSIXStreamConnection(host: host, port: port)
                    defer { connection.close() }
                    try performWebSocketUpgrade(connection)
                    try connection.write(webSocketClientFrame(opcode: 0x2, payload: payload))
                    result = try readWebSocketApplicationFrame(connection)
                case .myudp:
                    let connection = try ObstacleBridgeLinuxMyUDPTransportSession(host: host, port: port)
                    defer { connection.close() }
                    result = try connection.exchange(payload)
                case .quic:
                    throw ObstacleBridgeLinuxOverlayTransportError.unavailableTransport(transport.unavailableReason ?? "transport unavailable")
                }
                snapshot = .init(transport: transport.rawValue, state: "connected", attempts: attempt, failureReason: nil)
                return result
            } catch {
                lastError = error
                snapshot = .init(transport: transport.rawValue, state: "failed", attempts: attempt, failureReason: error.localizedDescription)
            }
        }
        throw lastError ?? ObstacleBridgeLinuxOverlayTransportError.invalidFrame
    }

    public func openSession() throws -> ObstacleBridgeLinuxOverlayTransportSession {
        snapshot = .init(transport: transport.rawValue, state: "connecting", attempts: 1, failureReason: nil)
        do {
            if transport == .myudp {
                let datagram = try ObstacleBridgeLinuxMyUDPTransportSession(host: host, port: port)
                snapshot = .init(transport: transport.rawValue, state: "connected", attempts: 1, failureReason: nil)
                return ObstacleBridgeLinuxOverlayTransportSession { payload in try datagram.exchange(payload) } close: { datagram.close() }
            }
            let connection = try POSIXStreamConnection(host: host, port: port)
            if transport == .ws { try performWebSocketUpgrade(connection) }
            snapshot = .init(transport: transport.rawValue, state: "connected", attempts: 1, failureReason: nil)
            return ObstacleBridgeLinuxOverlayTransportSession { [weak self] payload in
                guard let self else { throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF }
                switch self.transport {
                case .tcp:
                    try connection.write(self.tcpWire(payload))
                    return try self.readTCPApplicationFrame(connection)
                case .ws:
                    try connection.write(self.webSocketClientFrame(opcode: 0x2, payload: payload))
                    return try self.readWebSocketApplicationFrame(connection)
                case .myudp:
                    throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame
                case .quic:
                    throw ObstacleBridgeLinuxOverlayTransportError.unavailableTransport(self.transport.unavailableReason ?? "transport unavailable")
                }
            } close: {
                connection.close()
            }
        } catch {
            snapshot = .init(transport: transport.rawValue, state: "failed", attempts: 1, failureReason: error.localizedDescription)
            throw error
        }
    }

    private func tcpWire(_ payload: Data) -> Data {
        var length = UInt32(payload.count + 1).bigEndian
        var wire = Data(bytes: &length, count: MemoryLayout<UInt32>.size)
        wire.append(0)
        wire.append(payload)
        return wire
    }

    private func readTCPApplicationFrame(_ connection: POSIXStreamConnection) throws -> Data {
        let header = try connection.readExactly(4)
        let length = header.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        guard length > 0, length <= 1_048_576 else { throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame }
        let body = try connection.readExactly(Int(length))
        guard body.first == 0 else { throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame }
        return Data(body.dropFirst())
    }

    private func performWebSocketUpgrade(_ connection: POSIXStreamConnection) throws {
        var rng = SystemRandomNumberGenerator()
        let key = Data((0..<16).map { _ in UInt8.random(in: .min ... .max, using: &rng) }).base64EncodedString()
        let request = "GET \(wsPath) HTTP/1.1\r\nHost: \(host):\(port)\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: \(key)\r\n\r\n"
        try connection.write(Data(request.utf8))
        let response = try connection.readUntil(Data("\r\n\r\n".utf8), maximum: 16 * 1024)
        guard let responseText = String(data: response, encoding: .utf8), responseText.hasPrefix("HTTP/1.1 101") else {
            throw ObstacleBridgeLinuxOverlayTransportError.webSocketHandshakeFailed
        }
        let expected = Data(Insecure.SHA1.hash(data: Data("\(key)258EAFA5-E914-47DA-95CA-C5AB0DC85B11".utf8))).base64EncodedString()
        guard responseText.lowercased().contains("sec-websocket-accept: \(expected.lowercased())") else {
            throw ObstacleBridgeLinuxOverlayTransportError.webSocketHandshakeFailed
        }
    }

    private func webSocketClientFrame(opcode: UInt8, payload: Data) -> Data {
        var frame = Data([0x80 | opcode])
        let maskBit: UInt8 = 0x80
        if payload.count < 126 {
            frame.append(maskBit | UInt8(payload.count))
        } else if payload.count <= Int(UInt16.max) {
            frame.append(maskBit | 126)
            var length = UInt16(payload.count).bigEndian
            frame.append(Data(bytes: &length, count: MemoryLayout<UInt16>.size))
        } else {
            frame.append(maskBit | 127)
            var length = UInt64(payload.count).bigEndian
            frame.append(Data(bytes: &length, count: MemoryLayout<UInt64>.size))
        }
        var rng = SystemRandomNumberGenerator()
        let mask = (0..<4).map { _ in UInt8.random(in: .min ... .max, using: &rng) }
        frame.append(contentsOf: mask)
        for (index, byte) in payload.enumerated() { frame.append(byte ^ mask[index % mask.count]) }
        return frame
    }

    private func readWebSocketApplicationFrame(_ connection: POSIXStreamConnection) throws -> Data {
        while true {
            let header = try connection.readExactly(2)
            guard header[0] & 0x80 != 0 else { throw ObstacleBridgeLinuxOverlayTransportError.webSocketProtocolError }
            let opcode = header[0] & 0x0f
            guard header[1] & 0x80 == 0 else { throw ObstacleBridgeLinuxOverlayTransportError.webSocketProtocolError }
            var length = Int(header[1] & 0x7f)
            if length == 126 {
                let extended = try connection.readExactly(2)
                length = Int(extended.withUnsafeBytes { $0.load(as: UInt16.self).bigEndian })
            } else if length == 127 {
                let extended = try connection.readExactly(8)
                let value = extended.withUnsafeBytes { $0.load(as: UInt64.self).bigEndian }
                guard value <= 1_048_576 else { throw ObstacleBridgeLinuxOverlayTransportError.webSocketProtocolError }
                length = Int(value)
            }
            let payload = try connection.readExactly(length)
            switch opcode {
            case 0x2: return payload
            case 0x9:
                try connection.write(webSocketClientFrame(opcode: 0xA, payload: payload))
            case 0x8: throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF
            default: throw ObstacleBridgeLinuxOverlayTransportError.webSocketProtocolError
            }
        }
    }
}

public final class ObstacleBridgeLinuxOverlayTransportSession {
    private let exchangeImpl: (Data) throws -> Data
    private let closeImpl: () -> Void
    private var closed = false

    fileprivate init(exchange: @escaping (Data) throws -> Data, close: @escaping () -> Void) {
        self.exchangeImpl = exchange
        self.closeImpl = close
    }

    deinit { close() }

    public func exchange(_ payload: Data) throws -> Data {
        guard !closed else { throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF }
        return try exchangeImpl(payload)
    }

    public func close() {
        guard !closed else { return }
        closed = true
        closeImpl()
    }
}

private final class POSIXStreamConnection {
    private var fd: Int32

    init(host: String, port: Int) throws {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
        hints.ai_protocol = Int32(IPPROTO_TCP)
        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, String(port), &hints, &result)
        guard status == 0, let first = result else {
            throw ObstacleBridgeLinuxOverlayTransportError.dnsFailure(String(cString: gai_strerror(status)))
        }
        defer { freeaddrinfo(first) }
        var candidate: UnsafeMutablePointer<addrinfo>? = first
        var openedFD: Int32 = -1
        var lastErrno: Int32 = 0
        while let address = candidate {
            let socketFD = socket(address.pointee.ai_family, address.pointee.ai_socktype, address.pointee.ai_protocol)
            if socketFD >= 0 {
                Self.configureTimeouts(socketFD)
                if connect(socketFD, address.pointee.ai_addr, address.pointee.ai_addrlen) == 0 {
                    openedFD = socketFD
                    break
                }
                lastErrno = errno
                _ = Glibc.close(socketFD)
            } else {
                lastErrno = errno
            }
            candidate = address.pointee.ai_next
        }
        guard openedFD >= 0 else { throw ObstacleBridgeLinuxOverlayTransportError.connectFailure(lastErrno) }
        fd = openedFD
    }

    deinit { close() }

    func close() {
        if fd >= 0 {
            _ = Glibc.close(fd)
            fd = -1
        }
    }

    func write(_ data: Data) throws {
        var offset = 0
        while offset < data.count {
            let sent = data.withUnsafeBytes { bytes in
                Glibc.send(fd, bytes.baseAddress!.advanced(by: offset), data.count - offset, 0)
            }
            if sent > 0 { offset += sent; continue }
            if sent == 0 { throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF }
            if errno == EINTR { continue }
            throw ObstacleBridgeLinuxOverlayTransportError.ioFailure(errno)
        }
    }

    func readExactly(_ count: Int) throws -> Data {
        var output = Data(count: count)
        var offset = 0
        while offset < count {
            let received = output.withUnsafeMutableBytes { bytes in
                Glibc.recv(fd, bytes.baseAddress!.advanced(by: offset), count - offset, 0)
            }
            if received > 0 { offset += received; continue }
            if received == 0 { throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF }
            if errno == EINTR { continue }
            throw ObstacleBridgeLinuxOverlayTransportError.ioFailure(errno)
        }
        return output
    }

    func readUntil(_ delimiter: Data, maximum: Int) throws -> Data {
        var output = Data()
        while output.count < maximum {
            output.append(try readExactly(1))
            if output.suffix(delimiter.count) == delimiter { return output }
        }
        throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame
    }

    private static func configureTimeouts(_ fd: Int32) {
        var timeout = timeval(tv_sec: 5, tv_usec: 0)
        _ = withUnsafePointer(to: &timeout) {
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, $0, socklen_t(MemoryLayout<timeval>.size))
        }
        _ = withUnsafePointer(to: &timeout) {
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, $0, socklen_t(MemoryLayout<timeval>.size))
        }
    }
}
