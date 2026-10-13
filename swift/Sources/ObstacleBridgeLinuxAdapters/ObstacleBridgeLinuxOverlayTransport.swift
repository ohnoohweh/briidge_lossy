import Crypto
import Foundation
import ObstacleBridgeCore
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
        case .tcp, .ws, .myudp, .quic:
            true
        }
    }

    public var unavailableReason: String? {
        switch self {
        case .tcp, .ws, .myudp, .quic:
            nil
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
    case webSocketHandshakeFailed
    case proxyNegotiationFailed(String)
    case webSocketProtocolError
    case cancelled

    public var errorDescription: String? {
        switch self {
        case .unavailableTransport(let reason), .dnsFailure(let reason): return reason
        case .invalidEndpoint: return "invalid overlay endpoint"
        case .socketFailure(let code), .connectFailure(let code), .ioFailure(let code): return "POSIX socket failure errno=\(code)"
        case .unexpectedEOF: return "overlay peer closed the connection"
        case .invalidFrame: return "invalid overlay frame"
        case .webSocketHandshakeFailed: return "WebSocket upgrade was rejected"
        case .proxyNegotiationFailed(let detail): return "HTTP proxy negotiation failed: \(detail)"
        case .webSocketProtocolError: return "invalid WebSocket frame"
        case .cancelled: return "overlay connection was cancelled"
        }
    }
}

public struct ObstacleBridgeLinuxOverlaySnapshot: Equatable, Sendable {
    public let transport: String
    public let state: String
    public let attempts: Int
    public let failureReason: String?
}

/// Common byte-stream boundary for cleartext and TLS WebSocket connections.
/// WebSocket framing stays transport-agnostic above this boundary.
protocol ObstacleBridgeLinuxWebSocketByteConnection: AnyObject {
    func write(_ data: Data) throws
    func readExactly(_ count: Int) throws -> Data
    func readUntil(_ delimiter: Data, maximum: Int) throws -> Data
}

/// Linux POSIX lower-transport probes. They intentionally own only the raw
/// transport framing: config, SecureLink session state, ChannelMux, TUN, and
/// Admin integration remain in their respective runtime work packages.
public final class ObstacleBridgeLinuxOverlayTransportClient {
    private let host: String
    private let port: Int
    private let transport: ObstacleBridgeLinuxTransport
    private let wsPath: String
    private let wsPayloadMode: ObstacleBridgeWebSocketPayloadMode
    private let wsTLS: Bool
    private let wsTrustRootsPath: String?
    private let wsProxy: ObstacleBridgeLinuxHTTPProxy
    private let quicALPN: String
    private let quicInsecure: Bool
    private let quicTrustRootsPath: String?
    private let receiveTimeoutMilliseconds: Int
    /// Core owns application-frame construction and early-send state. Linux
    /// owns the concrete POSIX/NIO connection below this boundary.
    private let tcpOverlayRuntime = ObstacleBridgeTcpOverlayRuntime()
    /// Core owns QUIC application-frame construction; Linux owns NIO-QUIC I/O.
    private let quicOverlayRuntime = ObstacleBridgeQuicOverlayRuntime()
    /// Core owns HTTP CONNECT request policy; Linux owns the proxy socket.
    private let webSocketOverlayRuntime: ObstacleBridgeWebSocketOverlayRuntime
    private(set) public var snapshot: ObstacleBridgeLinuxOverlaySnapshot

    public init(host: String, port: Int, transport: ObstacleBridgeLinuxTransport, wsPath: String = "/", wsPayloadMode: String = "binary", wsTLS: Bool = false, wsTrustRootsPath: String? = nil, wsProxy: ObstacleBridgeLinuxHTTPProxy = .init(), quicALPN: String = "hq-29", quicInsecure: Bool = false, quicTrustRootsPath: String? = nil, receiveTimeoutMilliseconds: Int = 5_000) throws {
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
        self.wsPayloadMode = try ObstacleBridgeWebSocketPayloadCodec.mode(wsPayloadMode)
        self.webSocketOverlayRuntime = try ObstacleBridgeWebSocketOverlayRuntime(payloadMode: wsPayloadMode)
        self.wsTLS = wsTLS
        let normalizedWebSocketTrustRoots = wsTrustRootsPath?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.wsTrustRootsPath = normalizedWebSocketTrustRoots?.isEmpty == false ? normalizedWebSocketTrustRoots : nil
        self.wsProxy = wsProxy
        let normalizedALPN = quicALPN.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalizedALPN.isEmpty else { throw ObstacleBridgeLinuxOverlayTransportError.invalidEndpoint }
        self.quicALPN = normalizedALPN
        self.quicInsecure = quicInsecure
        let normalizedTrustRoots = quicTrustRootsPath?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.quicTrustRootsPath = normalizedTrustRoots?.isEmpty == false ? normalizedTrustRoots : nil
        self.receiveTimeoutMilliseconds = max(1, receiveTimeoutMilliseconds)
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
                    let connection = try POSIXStreamConnection(host: host, port: port, timeoutMilliseconds: receiveTimeoutMilliseconds)
                    defer { connection.close() }
                    for pending in tcpOverlayRuntime.connectionOpened(host: host, port: port, socketPresent: true) {
                        try connection.write(pending)
                    }
                    try connection.write(tcpWire(payload))
                    result = try readTCPApplicationFrame(connection)
                case .ws:
                    if wsTLS {
                        let connection = try ObstacleBridgeLinuxTLSWebSocketConnection(host: host, port: port, trustRootsPath: wsTrustRootsPath, proxy: try wsProxy.endpoint(targetHost: host, secure: true), proxyAuthorization: wsProxy.basicAuthorization(targetHost: host, secure: true), timeoutMilliseconds: receiveTimeoutMilliseconds)
                        defer { connection.close() }
                        try performWebSocketUpgrade(connection)
                        webSocketOverlayRuntime.connectionOpened()
                        let message = try webSocketMessage(payload); try connection.write(webSocketClientFrame(opcode: message.0, payload: message.1))
                        result = try readWebSocketApplicationPayload(connection)
                    } else {
                        let connection = try openWebSocketConnection()
                        defer { connection.close() }
                        try performWebSocketUpgrade(connection)
                        webSocketOverlayRuntime.connectionOpened()
                        let message = try webSocketMessage(payload); try connection.write(webSocketClientFrame(opcode: message.0, payload: message.1))
                        result = try readWebSocketApplicationPayload(connection)
                    }
                case .myudp:
                    let connection = try ObstacleBridgeLinuxMyUDPTransportSession(host: host, port: port, timeoutMilliseconds: receiveTimeoutMilliseconds)
                    defer { connection.close() }
                    result = try connection.exchange(payload)
                case .quic:
                    let connection = try ObstacleBridgeLinuxQUICSession(host: host, port: port, alpn: quicALPN, insecure: quicInsecure, trustRootsPath: quicTrustRootsPath, receiveTimeoutMilliseconds: receiveTimeoutMilliseconds)
                    defer { connection.close() }
                    for pending in quicOverlayRuntime.connectionOpened(host: host, port: port, socketPresent: true) {
                        try connection.write(pending)
                    }
                    try connection.write(try quicWire(payload))
                    result = try readTCPApplicationFrame(connection)
                }
                snapshot = .init(transport: transport.rawValue, state: "connected", attempts: attempt, failureReason: nil)
                return result
            } catch {
                switch transport {
                case .tcp:
                    _ = tcpOverlayRuntime.connectionLost(runFlag: true, peerConfigured: true, writerPresent: false, initiallyConnected: snapshot.state == "connected")
                case .quic:
                    _ = quicOverlayRuntime.connectionLost(runFlag: true, peerConfigured: true, writerPresent: false, initiallyConnected: snapshot.state == "connected")
                case .ws, .myudp:
                    if transport == .ws {
                        _ = webSocketOverlayRuntime.connectionLost(runFlag: true, initiallyConnected: snapshot.state == "connected")
                    }
                    break
                }
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
                let datagram = try ObstacleBridgeLinuxMyUDPTransportSession(host: host, port: port, timeoutMilliseconds: receiveTimeoutMilliseconds)
                snapshot = .init(transport: transport.rawValue, state: "connected", attempts: 1, failureReason: nil)
                return ObstacleBridgeLinuxOverlayTransportSession(
                    exchange: { payload in try datagram.exchange(payload) },
                    send: { payload in _ = try datagram.send(payload) },
                    receive: { try datagram.receive().payload },
                    close: { datagram.close() }
                )
            }
            if transport == .quic {
                let quic = try ObstacleBridgeLinuxQUICSession(host: host, port: port, alpn: quicALPN, insecure: quicInsecure, trustRootsPath: quicTrustRootsPath, receiveTimeoutMilliseconds: receiveTimeoutMilliseconds)
                for pending in quicOverlayRuntime.connectionOpened(host: host, port: port, socketPresent: true) {
                    try quic.write(pending)
                }
                snapshot = .init(transport: transport.rawValue, state: "connected", attempts: 1, failureReason: nil)
                let send: (Data) throws -> Void = { [weak self] payload in
                    guard let self else { throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF }
                    try quic.write(try self.quicWire(payload))
                }
                let receive: () throws -> Data = { [weak self] in
                    guard let self else { throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF }
                    return try self.readTCPApplicationFrame(quic)
                }
                return ObstacleBridgeLinuxOverlayTransportSession(exchange: { payload in try send(payload); return try receive() }, send: send, receive: receive, close: {
                    quic.close()
                })
            }
            if transport == .ws, wsTLS {
                let connection = try ObstacleBridgeLinuxTLSWebSocketConnection(host: host, port: port, trustRootsPath: wsTrustRootsPath, proxy: try wsProxy.endpoint(targetHost: host, secure: true), proxyAuthorization: wsProxy.basicAuthorization(targetHost: host, secure: true), timeoutMilliseconds: receiveTimeoutMilliseconds)
                try performWebSocketUpgrade(connection)
                webSocketOverlayRuntime.connectionOpened()
                snapshot = .init(transport: transport.rawValue, state: "connected", attempts: 1, failureReason: nil)
                let send: (Data) throws -> Void = { [weak self] payload in
                    guard let self else { throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF }
                    let message = try self.webSocketMessage(payload)
                    try connection.write(self.webSocketClientFrame(opcode: message.0, payload: message.1))
                }
                let receive: () throws -> Data = { [weak self] in
                    guard let self else { throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF }
                    return try self.readWebSocketApplicationPayload(connection)
                }
                return ObstacleBridgeLinuxOverlayTransportSession(exchange: { payload in try send(payload); return try receive() }, send: send, receive: receive, close: { connection.close() })
            }
            let connection = transport == .ws ? try openWebSocketConnection() : try POSIXStreamConnection(host: host, port: port, timeoutMilliseconds: receiveTimeoutMilliseconds)
            if transport == .tcp {
                for pending in tcpOverlayRuntime.connectionOpened(host: host, port: port, socketPresent: true) {
                    try connection.write(pending)
                }
            }
            if transport == .ws {
                try performWebSocketUpgrade(connection)
                webSocketOverlayRuntime.connectionOpened()
            }
            snapshot = .init(transport: transport.rawValue, state: "connected", attempts: 1, failureReason: nil)
            let send: (Data) throws -> Void = { [weak self] payload in
                guard let self else { throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF }
                switch self.transport {
                case .tcp:
                    try connection.write(self.tcpWire(payload))
                case .ws:
                    let message = try self.webSocketMessage(payload); try connection.write(self.webSocketClientFrame(opcode: message.0, payload: message.1))
                case .myudp:
                    throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame
                case .quic:
                    throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame
                }
            }
            let receive: () throws -> Data = { [weak self] in
                guard let self else { throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF }
                switch self.transport {
                case .tcp: return try self.readTCPApplicationFrame(connection)
                case .ws: return try self.readWebSocketApplicationPayload(connection)
                case .myudp, .quic: throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame
                }
            }
            return ObstacleBridgeLinuxOverlayTransportSession(exchange: { payload in try send(payload); return try receive() }, send: send, receive: receive, close: {
                connection.close()
            })
        } catch {
            snapshot = .init(transport: transport.rawValue, state: "failed", attempts: 1, failureReason: error.localizedDescription)
            throw error
        }
    }

    private func tcpWire(_ payload: Data) throws -> Data {
        let effect = tcpOverlayRuntime.sendApp(
            payload: payload,
            writerPresent: true,
            peerConfigured: true
        )
        guard let wire = effect.writtenBuffers.first else {
            throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame
        }
        return wire
    }

    private func quicWire(_ payload: Data) throws -> Data {
        let effect = quicOverlayRuntime.sendApp(
            payload: payload,
            writerPresent: true,
            peerConfigured: true
        )
        guard let wire = effect.writtenBuffers.first else {
            throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame
        }
        return wire
    }

    private func openWebSocketConnection() throws -> POSIXStreamConnection {
        guard let proxy = try wsProxy.endpoint(targetHost: host, secure: false) else {
            return try POSIXStreamConnection(host: host, port: port, timeoutMilliseconds: receiveTimeoutMilliseconds)
        }
        let connection = try POSIXStreamConnection(host: proxy.0, port: proxy.1, timeoutMilliseconds: receiveTimeoutMilliseconds)
        do {
            let request = webSocketOverlayRuntime.buildProxyConnectRequest(
                targetHost: host,
                targetPort: port,
                authHeader: wsProxy.basicAuthorization(targetHost: host, secure: false)
            )
            try connection.write(Data(request.utf8))
            let response = try connection.readUntil(Data("\r\n\r\n".utf8), maximum: 16_384)
            guard let status = String(data: response, encoding: .utf8)?.split(separator: "\r\n").first, status.hasPrefix("HTTP/1.1 200") else { throw ObstacleBridgeLinuxOverlayTransportError.proxyNegotiationFailed("CONNECT did not return HTTP 200") }
            return connection
        } catch { connection.close(); throw error }
    }

    private func readTCPApplicationFrame(_ connection: POSIXStreamConnection) throws -> Data {
        // Python's TCP lower transport multiplexes RTT controls with APP
        // frames. Those controls may arrive before the SecureLink server hello,
        // so consume PINGs here and immediately return a compatible PONG rather
        // than exposing the control byte to the SecureLink decoder.
        while true {
            let header = try connection.readExactly(4)
            var headerReader = ObstacleBridgeBinaryReader(header)
            let length = try headerReader.readUInt32()
            guard length > 0, length <= ObstacleBridgeOverlayFrameCodec.maximumBodyLength else { throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame }
            let body = try connection.readExactly(Int(length))
            switch try ObstacleBridgeOverlayEnvelope.decodeTCP(header + body) {
            case .application:
                guard let admitted = tcpOverlayRuntime.receiveApplicationBytes(header + body).first else {
                    throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame
                }
                return admitted
            case .reply(let frame):
                try connection.write(try ObstacleBridgeOverlayEnvelope.encodeTCP(frame))
            case .ignore:
                // A PONG completes a lower-layer liveness exchange and carries
                // no application payload for this client.
                break
            }
        }
    }

    private func readTCPApplicationFrame(_ connection: ObstacleBridgeLinuxQUICSession) throws -> Data {
        while true {
            let header = try connection.readExactly(4)
            var headerReader = ObstacleBridgeBinaryReader(header)
            let length = try headerReader.readUInt32()
            guard length > 0, length <= ObstacleBridgeOverlayFrameCodec.maximumBodyLength else { throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame }
            let body = try connection.readExactly(Int(length))
            switch try ObstacleBridgeOverlayEnvelope.decodeTCP(header + body) {
            case .application:
                guard let admitted = quicOverlayRuntime.receiveApplicationBytes(header + body).first else {
                    throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame
                }
                return admitted
            case .reply(let frame):
                try connection.write(try ObstacleBridgeOverlayEnvelope.encodeTCP(frame))
            case .ignore:
                break
            }
        }
    }

    private func performWebSocketUpgrade(_ connection: some ObstacleBridgeLinuxWebSocketByteConnection) throws {
        var rng = SystemRandomNumberGenerator()
        let key = Data((0..<16).map { _ in UInt8.random(in: .min ... .max, using: &rng) }).base64EncodedString()
        let request = "GET \(wsPath) HTTP/1.1\r\nHost: \(host):\(port)\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: \(key)\r\nX-ObstacleBridge-WS-Payload-Mode: \(wsPayloadMode.rawValue)\r\n\r\n"
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

    /// Python's WebSocket transport carries the same APP/PING/PONG subframe
    /// as its TCP transport inside each binary WebSocket message.
    private func webSocketMessage(_ payload: Data) throws -> (UInt8, Data) {
        let wire = try webSocketWire(payload)
        switch try webSocketOverlayRuntime.encodeClientPayload(wire) { case .binary(let data): return (0x2, data); case .text(let text): return (0x1, Data(text.utf8)) }
    }
    private func webSocketWire(_ payload: Data) throws -> Data {
        try ObstacleBridgeOverlayFrameCodec.encodeBody(.init(kind: .application, payload: payload))
    }

    private func readWebSocketApplicationPayload(_ connection: some ObstacleBridgeLinuxWebSocketByteConnection) throws -> Data {
        while true {
            switch try webSocketOverlayRuntime.receiveClientPayload(readWebSocketApplicationFrame(connection)) {
            case .application(let payload):
                return payload
            case .pong(let txNS, let echoNS):
                let pongWire = try ObstacleBridgeOverlayFrameCodec.encodeBody(.init(kind: .pong, payload: ObstacleBridgeOverlayFrameCodec.pongPayload(echoTxNS: txNS)))
                switch try webSocketOverlayRuntime.encodeClientPayload(pongWire) {
                case .binary(let data): try connection.write(webSocketClientFrame(opcode: 0x2, payload: data))
                case .text(let text): try connection.write(webSocketClientFrame(opcode: 0x1, payload: Data(text.utf8)))
                }
                _ = echoNS
            case .ignore:
                continue
            }
        }
    }

    private func readWebSocketApplicationFrame(_ connection: some ObstacleBridgeLinuxWebSocketByteConnection) throws -> ObstacleBridgeWebSocketPayload {
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
            case 0x2: return .binary(payload)
            case 0x1: guard let text = String(data: payload, encoding: .utf8) else { throw ObstacleBridgeLinuxOverlayTransportError.webSocketProtocolError }; return .text(text)
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
    private let sendImpl: ((Data) throws -> Void)?
    private let receiveImpl: (() throws -> Data)?
    private let closeImpl: () -> Void
    private let lock = NSLock()
    private var closed = false

    init(exchange: @escaping (Data) throws -> Data, send: ((Data) throws -> Void)? = nil, receive: (() throws -> Data)? = nil, close: @escaping () -> Void) {
        self.exchangeImpl = exchange
        self.sendImpl = send
        self.receiveImpl = receive
        self.closeImpl = close
    }

    deinit { close() }

    public func exchange(_ payload: Data) throws -> Data {
        lock.lock(); let isClosed = closed; lock.unlock()
        guard !isClosed else { throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF }
        return try exchangeImpl(payload)
    }

    public func send(_ payload: Data) throws {
        lock.lock(); let isClosed = closed; lock.unlock()
        guard !isClosed, let sendImpl else { throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame }
        try sendImpl(payload)
    }

    public func receive() throws -> Data {
        lock.lock(); let isClosed = closed; lock.unlock()
        guard !isClosed, let receiveImpl else { throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame }
        return try receiveImpl()
    }

    public func close() {
        lock.lock()
        guard !closed else { lock.unlock(); return }
        closed = true
        lock.unlock()
        closeImpl()
    }
}

private final class POSIXStreamConnection: ObstacleBridgeLinuxWebSocketByteConnection {
    private var fd: Int32
    private let descriptorLock = NSLock()

    init(host: String, port: Int, timeoutMilliseconds: Int = 5_000) throws {
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
                Self.configureTimeouts(socketFD, timeoutMilliseconds: timeoutMilliseconds)
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
        descriptorLock.lock()
        let descriptor = fd
        fd = -1
        descriptorLock.unlock()
        guard descriptor >= 0 else { return }
        _ = shutdown(descriptor, Int32(SHUT_RDWR))
        _ = Glibc.close(descriptor)
    }

    func write(_ data: Data) throws {
        let descriptor = try activeDescriptor()
        var offset = 0
        while offset < data.count {
            let sent = data.withUnsafeBytes { bytes in
                Glibc.send(descriptor, bytes.baseAddress!.advanced(by: offset), data.count - offset, 0)
            }
            if sent > 0 { offset += sent; continue }
            if sent == 0 { throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF }
            if errno == EINTR { continue }
            throw ObstacleBridgeLinuxOverlayTransportError.ioFailure(errno)
        }
    }

    func readExactly(_ count: Int) throws -> Data {
        let descriptor = try activeDescriptor()
        var output = Data(count: count)
        var offset = 0
        while offset < count {
            let received = output.withUnsafeMutableBytes { bytes in
                Glibc.recv(descriptor, bytes.baseAddress!.advanced(by: offset), count - offset, 0)
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

    private static func configureTimeouts(_ fd: Int32, timeoutMilliseconds: Int) {
        let bounded = max(1, timeoutMilliseconds)
        var timeout = timeval(tv_sec: bounded / 1_000, tv_usec: (bounded % 1_000) * 1_000)
        _ = withUnsafePointer(to: &timeout) {
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, $0, socklen_t(MemoryLayout<timeval>.size))
        }
        _ = withUnsafePointer(to: &timeout) {
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, $0, socklen_t(MemoryLayout<timeval>.size))
        }
    }

    private func activeDescriptor() throws -> Int32 {
        descriptorLock.lock()
        let descriptor = fd
        descriptorLock.unlock()
        guard descriptor >= 0 else { throw ObstacleBridgeLinuxOverlayTransportError.cancelled }
        return descriptor
    }
}
