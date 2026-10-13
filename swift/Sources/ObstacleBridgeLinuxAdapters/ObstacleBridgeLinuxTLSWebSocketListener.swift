import Foundation
import Crypto
import NIOCore
import NIOPosix
import NIOSSL
import ObstacleBridgeCore

/// TLS-terminating WebSocket listener.  NIO owns the accepted TLS channels;
/// SecureLink is admitted only after the HTTP upgrade has completed.
public final class ObstacleBridgeLinuxTLSWebSocketPSKListener: @unchecked Sendable {
    private final class Inbound: ChannelInboundHandler, @unchecked Sendable {
        typealias InboundIn = ByteBuffer
        let condition = NSCondition(); var bytes = Data(); var inactive = false
        func channelRead(context: ChannelHandlerContext, data: NIOAny) { var b = unwrapInboundIn(data); if let v = b.readBytes(length: b.readableBytes) { condition.lock(); bytes.append(contentsOf: v); condition.broadcast(); condition.unlock() } }
        func channelInactive(context: ChannelHandlerContext) { condition.lock(); inactive = true; condition.broadcast(); condition.unlock(); context.fireChannelInactive() }
        func read(_ count: Int, timeout: Int) throws -> Data { let deadline = Date().addingTimeInterval(Double(timeout) / 1_000); condition.lock(); defer { condition.unlock() }; while bytes.count < count && !inactive { guard condition.wait(until: deadline) else { throw ObstacleBridgeLinuxOverlayTransportError.ioFailure(ETIMEDOUT) } }; guard bytes.count >= count else { throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF }; let result = Data(bytes.prefix(count)); bytes.removeFirst(count); return result }
    }
    private final class Connection: ObstacleBridgeLinuxWebSocketByteConnection, @unchecked Sendable {
        let channel: any Channel; let inbound: Inbound; let timeout: Int
        init(_ channel: any Channel, _ inbound: Inbound, _ timeout: Int) { self.channel = channel; self.inbound = inbound; self.timeout = timeout }
        func write(_ data: Data) throws { var b = channel.allocator.buffer(capacity: data.count); b.writeBytes(data); try channel.writeAndFlush(b).wait() }
        func readExactly(_ count: Int) throws -> Data { try inbound.read(count, timeout: timeout) }
        func readUntil(_ delimiter: Data, maximum: Int) throws -> Data { var r = Data(); while r.count < maximum { r.append(try readExactly(1)); if r.suffix(delimiter.count) == delimiter { return r } }; throw ObstacleBridgeLinuxOverlayTransportError.webSocketHandshakeFailed }
        func close() { channel.close(promise: nil) }
    }
    private final class Acceptor: ChannelInboundHandler, @unchecked Sendable {
        typealias InboundIn = ByteBuffer
        unowned let owner: ObstacleBridgeLinuxTLSWebSocketPSKListener
        let timeout: Int
        init(owner: ObstacleBridgeLinuxTLSWebSocketPSKListener, timeout: Int) { self.owner = owner; self.timeout = timeout }
        func handlerAdded(context: ChannelHandlerContext) { let inbound = Inbound(); context.pipeline.addHandler(inbound).whenSuccess { _ in self.owner.enqueue(Connection(context.channel, inbound, self.timeout)) } }
    }
    private let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private let overlayRuntime: ObstacleBridgeWebSocketOverlayRuntime
    private let condition = NSCondition(); private var pending: [Connection] = []; private var closed = false
    private var channel: (any Channel)?; public private(set) var port: Int = 0; private let webSocketPath: String; private let timeoutMilliseconds: Int
    public init(port: Int, certificatePath: String, privateKeyPath: String, webSocketPath: String = "/", timeoutMilliseconds: Int = 5_000) throws {
        guard (0...65535).contains(port) else { throw ObstacleBridgeLinuxOverlayTransportError.invalidEndpoint }
        self.overlayRuntime = try .init(payloadMode: "binary")
        self.webSocketPath = webSocketPath.hasPrefix("/") ? webSocketPath : "/\(webSocketPath)"; self.timeoutMilliseconds = max(1, timeoutMilliseconds)
        let tls = TLSConfiguration.makeServerConfiguration(certificateChain: [.file(certificatePath)], privateKey: .file(privateKeyPath))
        let context = try NIOSSLContext(configuration: tls)
        let server = try ServerBootstrap(group: group).childChannelInitializer { channel in
            do { return channel.pipeline.addHandlers([try NIOSSLServerHandler(context: context), Acceptor(owner: self, timeout: self.timeoutMilliseconds)]) } catch { return channel.eventLoop.makeFailedFuture(error) }
        }.bind(host: "127.0.0.1", port: port).wait()
        self.channel = server; self.port = Int(server.localAddress?.port ?? 0)
    }
    deinit { close() }
    public var isOpen: Bool { condition.lock(); defer { condition.unlock() }; return !closed }
    public func close() { condition.lock(); guard !closed else { condition.unlock(); return }; closed = true; let server = channel; channel = nil; let pending = pending; self.pending = []; condition.broadcast(); condition.unlock(); pending.forEach { $0.close() }; server?.close(promise: nil); group.shutdownGracefully { _ in } }
    private func enqueue(_ connection: Connection) { condition.lock(); if closed { condition.unlock(); connection.close(); return }; pending.append(connection); condition.broadcast(); condition.unlock() }
    private func next() throws -> Connection { condition.lock(); defer { condition.unlock() }; while pending.isEmpty && !closed { condition.wait() }; guard !pending.isEmpty else { throw ObstacleBridgeLinuxOverlayTransportError.cancelled }; return pending.removeFirst() }
    public func acceptConfiguredSession(psk: Data, serverNonce: Data) throws -> ObstacleBridgeLinuxConfiguredSession {
        while true { let connection = try next(); do { if try upgrade(connection) { return try configured(connection, psk: psk, serverNonce: serverNonce) }; connection.close() } catch { connection.close() } }
    }
    public func serveOne(psk: Data, serverNonce: Data) throws { let session = try acceptConfiguredSession(psk: psk, serverNonce: serverNonce); defer { session.close() }; while true { do { _ = try session.send(try session.receiveInbound()) } catch ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF { return } } }
    private func configured(_ c: Connection, psk: Data, serverNonce: Data) throws -> ObstacleBridgeLinuxConfiguredSession {
        let server = try ObstacleBridgeSecureLinkPSKServer(psk: psk); try writeWire(try server.handleClientHello(readFrame(c), serverNonce: serverNonce), c); try writeWire(try server.handleClientProof(readFrame(c)), c)
        let peerID = overlayRuntime.listenerPeerAccepted()
        let raw = ObstacleBridgeLinuxOverlayTransportSession(exchange: { value in try self.writeWire(value, c); return try self.readFrame(c) }, send: { try self.writeWire($0, c) }, receive: { try self.readFrame(c) }, close: { [weak self] in self?.overlayRuntime.listenerPeerClosed(peerID); c.close() })
        return ObstacleBridgeLinuxConfiguredSession(lowerSession: raw, secureLink: nil, secureLinkServer: server, transport: .ws)
    }
    private func upgrade(_ c: Connection) throws -> Bool { let request = try c.readUntil(Data("\r\n\r\n".utf8), maximum: 16_384); guard let text = String(data: request, encoding: .utf8) else { throw ObstacleBridgeLinuxOverlayTransportError.webSocketHandshakeFailed }; let lines = text.components(separatedBy: "\r\n"); guard let first = lines.first, first.hasPrefix("GET ") else { throw ObstacleBridgeLinuxOverlayTransportError.webSocketHandshakeFailed }; guard lines.contains(where: { $0.lowercased().hasPrefix("upgrade: websocket") }) else { try c.write(Data("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK".utf8)); return false }; guard first.split(separator: " ").dropFirst().first == Substring(webSocketPath), let keyLine = lines.first(where: { $0.lowercased().hasPrefix("sec-websocket-key:") }) else { throw ObstacleBridgeLinuxOverlayTransportError.webSocketHandshakeFailed }; let key = keyLine.split(separator: ":", maxSplits: 1)[1].trimmingCharacters(in: .whitespaces); let accept = Data(Insecure.SHA1.hash(data: Data("\(key)258EAFA5-E914-47DA-95CA-C5AB0DC85B11".utf8))).base64EncodedString(); try c.write(Data("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: \(accept)\r\n\r\n".utf8)); return true }
    private func readFrame(_ c: Connection) throws -> Data { while true { let h = try c.readExactly(2); guard h[0] & 0x80 != 0, h[1] & 0x80 != 0 else { throw ObstacleBridgeLinuxOverlayTransportError.webSocketProtocolError }; let opcode = h[0] & 0x0f; var n = Int(h[1] & 0x7f); if n == 126 { n = Int(try c.readExactly(2).reduce(UInt16(0)) { $0 << 8 | UInt16($1) }) }; let mask = try c.readExactly(4); let encoded = try c.readExactly(n); let data = Data(encoded.enumerated().map { $0.element ^ mask[$0.offset % 4] }); if opcode == 2 { guard let kind = data.first else { throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame }; if kind == 0 { return Data(data.dropFirst()) }; if kind == 1 { try writeControl(2, Data(data.dropFirst().prefix(8)), c); continue } }; if opcode == 8 { throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF }; throw ObstacleBridgeLinuxOverlayTransportError.webSocketProtocolError } }
    private func writeWire(_ payload: Data, _ c: Connection) throws { try writeControl(0, payload, c) }
    private func writeControl(_ kind: UInt8, _ payload: Data, _ c: Connection) throws { var body = Data([kind]); body.append(payload); var frame = Data([0x82]); if body.count < 126 { frame.append(UInt8(body.count)) } else { frame.append(126); var n = UInt16(body.count).bigEndian; frame.append(Data(bytes: &n, count: 2)) }; frame.append(body); try c.write(frame) }
}
