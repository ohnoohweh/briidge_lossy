import Foundation
import NIOCore
import NIOPosix
import NIOSSL
import NIOTLS

/// Synchronous adapter facade over one verified NIO SSL client channel.  It is
/// kept below the existing WebSocket framing boundary so TLS never changes
/// overlay, SecureLink, or ChannelMux byte ownership.
final class ObstacleBridgeLinuxTLSWebSocketConnection: ObstacleBridgeLinuxWebSocketByteConnection, @unchecked Sendable {
    private final class TLSHandlerBox: @unchecked Sendable {
        let handler: NIOSSLClientHandler
        init(_ handler: NIOSSLClientHandler) { self.handler = handler }
    }

    private final class InboundBytes: ChannelInboundHandler, @unchecked Sendable {
        typealias InboundIn = ByteBuffer
        private let condition = NSCondition()
        private var bytes = Data()
        private var inactive = false
        private var failure: Error?
        private var handshakeComplete = false

        func channelRead(context: ChannelHandlerContext, data: NIOAny) {
            var buffer = unwrapInboundIn(data)
            if let received = buffer.readBytes(length: buffer.readableBytes), !received.isEmpty {
                condition.lock(); bytes.append(contentsOf: received); condition.broadcast(); condition.unlock()
            }
        }
        func errorCaught(context: ChannelHandlerContext, error: Error) {
            condition.lock(); failure = error; inactive = true; condition.broadcast(); condition.unlock()
            context.close(promise: nil)
        }
        func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
            if case TLSUserEvent.handshakeCompleted = event {
                condition.lock(); handshakeComplete = true; condition.broadcast(); condition.unlock()
            }
            context.fireUserInboundEventTriggered(event)
        }
        func channelInactive(context: ChannelHandlerContext) {
            condition.lock(); inactive = true; condition.broadcast(); condition.unlock()
            context.fireChannelInactive()
        }
        func close() { condition.lock(); inactive = true; condition.broadcast(); condition.unlock() }
        func readExactly(_ count: Int, timeoutMilliseconds: Int) throws -> Data {
            let deadline = Date().addingTimeInterval(Double(max(1, timeoutMilliseconds)) / 1_000)
            condition.lock(); defer { condition.unlock() }
            while bytes.count < count && !inactive {
                guard condition.wait(until: deadline) else { throw ObstacleBridgeLinuxOverlayTransportError.ioFailure(ETIMEDOUT) }
            }
            if let failure { throw failure }
            guard bytes.count >= count else { throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF }
            // `Data.prefix` preserves the source indices.  Callers decode
            // WebSocket headers with zero-based subscripts, so detach the
            // consumed slice before advancing the shared buffer.
            let result = Data(bytes.prefix(count))
            bytes.removeFirst(count)
            return result
        }
        func waitForHandshake(timeoutMilliseconds: Int) throws {
            let deadline = Date().addingTimeInterval(Double(max(1, timeoutMilliseconds)) / 1_000)
            condition.lock(); defer { condition.unlock() }
            while !handshakeComplete && !inactive && failure == nil {
                guard condition.wait(until: deadline) else { throw ObstacleBridgeLinuxOverlayTransportError.ioFailure(ETIMEDOUT) }
            }
            if let failure { throw failure }
            guard handshakeComplete else { throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF }
        }
    }

    private final class HandshakeObserver: ChannelInboundHandler, @unchecked Sendable {
        typealias InboundIn = ByteBuffer
        private let condition = NSCondition()
        private var complete = false
        private var failure: Error?

        func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
            if case TLSUserEvent.handshakeCompleted = event {
                condition.lock(); complete = true; condition.broadcast(); condition.unlock()
            }
            context.fireUserInboundEventTriggered(event)
        }
        func errorCaught(context: ChannelHandlerContext, error: Error) {
            condition.lock(); failure = error; condition.broadcast(); condition.unlock()
            context.close(promise: nil)
        }
        func channelInactive(context: ChannelHandlerContext) {
            condition.lock(); condition.broadcast(); condition.unlock()
            context.fireChannelInactive()
        }
        func wait(timeoutMilliseconds: Int) throws {
            let deadline = Date().addingTimeInterval(Double(max(1, timeoutMilliseconds)) / 1_000)
            condition.lock(); defer { condition.unlock() }
            while !complete && failure == nil {
                guard condition.wait(until: deadline) else { throw ObstacleBridgeLinuxOverlayTransportError.ioFailure(ETIMEDOUT) }
            }
            if let failure { throw failure }
        }
    }

    private let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private let inbound = InboundBytes()
    private let timeoutMilliseconds: Int
    private let lock = NSLock()
    private var channel: (any Channel)?
    private var closed = false

    init(host: String, port: Int, trustRootsPath: String?, proxy: (String, Int)? = nil, proxyAuthorization: String? = nil, timeoutMilliseconds: Int) throws {
        self.timeoutMilliseconds = max(1, timeoutMilliseconds)
        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.certificateVerification = .fullVerification
        // Keep the platform roots active and add an operator bundle for
        // private deployments; neither path disables verification.
        if let trustRootsPath { configuration.additionalTrustRoots = [.file(trustRootsPath)] }
        let context = try NIOSSLContext(configuration: configuration)
        do {
            let connected = try ClientBootstrap(group: eventLoopGroup).channelInitializer { channel in
                if proxy == nil {
                    do {
                        try channel.pipeline.syncOperations.addHandlers(
                            try NIOSSLClientHandler(context: context, serverHostname: host),
                            self.inbound
                        )
                        return channel.eventLoop.makeSucceededFuture(())
                    }
                    catch { return channel.eventLoop.makeFailedFuture(error) }
                }
                return channel.pipeline.addHandler(self.inbound)
            }.connect(host: proxy?.0 ?? host, port: proxy?.1 ?? port).wait()
            lock.lock(); channel = connected; lock.unlock()
            if proxy != nil {
                let authority = host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
                let authorization = proxyAuthorization.map { "Proxy-Authorization: \($0)\r\n" } ?? ""
                try write(Data("CONNECT \(authority) HTTP/1.1\r\nHost: \(authority)\r\nProxy-Connection: Keep-Alive\r\n\(authorization)\r\n".utf8))
                let response = try readUntil(Data("\r\n\r\n".utf8), maximum: 16_384)
                guard let status = String(data: response, encoding: .utf8)?.split(separator: "\r\n").first, status.hasPrefix("HTTP/1.1 200") else { throw ObstacleBridgeLinuxOverlayTransportError.proxyNegotiationFailed("CONNECT did not return HTTP 200") }
                let handler = TLSHandlerBox(try NIOSSLClientHandler(context: context, serverHostname: host))
                let pipeline = connected.pipeline
                try connected.eventLoop.submit {
                    try pipeline.syncOperations.addHandler(handler.handler, position: .first)
                }.wait()
            }
            try inbound.waitForHandshake(timeoutMilliseconds: self.timeoutMilliseconds)
        } catch {
            close(); throw error
        }
    }

    deinit { close() }

    func write(_ bytes: Data) throws {
        lock.lock(); let channel = channel; let isClosed = closed; lock.unlock()
        guard !isClosed, let channel else { throw ObstacleBridgeLinuxOverlayTransportError.cancelled }
        var buffer = channel.allocator.buffer(capacity: bytes.count); buffer.writeBytes(bytes)
        try channel.writeAndFlush(buffer).wait()
    }
    func readExactly(_ count: Int) throws -> Data {
        try inbound.readExactly(count, timeoutMilliseconds: timeoutMilliseconds)
    }
    func readUntil(_ delimiter: Data, maximum: Int) throws -> Data {
        var result = Data()
        while result.count < maximum {
            result.append(try readExactly(1))
            if result.suffix(delimiter.count) == delimiter { return result }
        }
        throw ObstacleBridgeLinuxOverlayTransportError.webSocketHandshakeFailed
    }
    func close() {
        lock.lock(); guard !closed else { lock.unlock(); return }; closed = true
        let channel = channel; self.channel = nil; lock.unlock()
        inbound.close()
        if let channel {
            channel.closeFuture.whenComplete { [eventLoopGroup] _ in eventLoopGroup.shutdownGracefully { _ in } }
            channel.close(promise: nil)
        } else { eventLoopGroup.shutdownGracefully { _ in } }
    }
}
