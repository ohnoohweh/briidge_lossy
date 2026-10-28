import Foundation
import Logging
import NIOCore
import NIOPosix
import NIOQUIC
#if os(Linux)
import Glibc
#endif

/// Owns one Linux client QUIC connection and its single reliable
/// bidirectional overlay stream.  The upper Linux transport facade remains
/// synchronous, so this class bridges that boundary without making Core or
/// configured-runtime ownership depend on NIO types.
final class ObstacleBridgeLinuxQUICSession: @unchecked Sendable {
    private final class InboundBytes: ChannelInboundHandler, @unchecked Sendable {
        typealias InboundIn = ByteBuffer

        private let condition = NSCondition()
        private var bytes = Data()
        private var inactive = false
        private var asyncHandler: ((Result<Data, Error>) -> Void)?

        func channelRead(context: ChannelHandlerContext, data: NIOAny) {
            var buffer = unwrapInboundIn(data)
            if let received = buffer.readBytes(length: buffer.readableBytes), !received.isEmpty {
                let data = Data(received)
                condition.lock()
                let handler = asyncHandler
                if handler == nil { bytes.append(data) }
                condition.broadcast()
                condition.unlock()
                handler?(.success(data))
            }
        }

        func channelInactive(context: ChannelHandlerContext) {
            condition.lock()
            inactive = true
            let handler = asyncHandler
            condition.broadcast()
            condition.unlock()
            handler?(.failure(ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF))
            context.fireChannelInactive()
        }

        func close() {
            condition.lock()
            inactive = true
            condition.broadcast()
            condition.unlock()
        }

        func readExactly(_ count: Int, timeoutMilliseconds: Int) throws -> Data {
            let deadline = Date().addingTimeInterval(Double(max(1, timeoutMilliseconds)) / 1_000)
            condition.lock()
            defer { condition.unlock() }
            while bytes.count < count && !inactive {
                guard condition.wait(until: deadline) else {
                    throw ObstacleBridgeLinuxOverlayTransportError.ioFailure(EAGAIN)
                }
            }
            guard bytes.count >= count else {
                throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF
            }
            let result = bytes.prefix(count)
            bytes.removeFirst(count)
            return result
        }
        func startAsyncRead(_ handler: @escaping (Result<Data, Error>) -> Void) {
            condition.lock()
            guard asyncHandler == nil else { condition.unlock(); return }
            asyncHandler = handler
            let pending = Data(bytes)
            bytes = Data()
            let terminal = inactive
            condition.unlock()
            if !pending.isEmpty { handler(.success(pending)) }
            if terminal { handler(.failure(ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF)) }
        }
    }

    private let eventLoopGroup: MultiThreadedEventLoopGroup
    private let inbound = InboundBytes()
    private let receiveTimeoutMilliseconds: Int
    private let lock = NSLock()
    private var datagramChannel: (any Channel)?
    private var streamChannel: (any Channel)?
    private var setupResult: Result<Void, Error>?
    private var setupTask: Task<Void, Never>?
    private var closed = false

    init(host: String, port: Int, alpn: String, insecure: Bool, trustRootsPath: String?, receiveTimeoutMilliseconds: Int) throws {
        self.eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.receiveTimeoutMilliseconds = max(1, receiveTimeoutMilliseconds)
        let setupFinished = DispatchSemaphore(value: 0)
        // Construction is called from the synchronous configured-runtime
        // queue.  Do not inherit that executor: it is blocked below while the
        // NIO setup task establishes the stream.
        self.setupTask = Task.detached { [weak self] in
            guard let self else { return }
            do {
                try await self.open(host: host, port: port, alpn: alpn, insecure: insecure, trustRootsPath: trustRootsPath)
                self.recordSetup(.success(()))
            } catch {
                self.recordSetup(.failure(error))
            }
            setupFinished.signal()
        }
        guard setupFinished.wait(timeout: .now() + .milliseconds(self.receiveTimeoutMilliseconds)) == .success else {
            close()
            throw ObstacleBridgeLinuxOverlayTransportError.ioFailure(ETIMEDOUT)
        }
        lock.lock()
        let result = setupResult
        lock.unlock()
        guard let result else {
            close()
            throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame
        }
        do {
            try result.get()
        } catch {
            close()
            throw error
        }
    }

    deinit { close() }

    func write(_ bytes: Data) throws {
        lock.lock()
        let stream = streamChannel
        let isClosed = closed
        lock.unlock()
        guard !isClosed, let stream else { throw ObstacleBridgeLinuxOverlayTransportError.cancelled }
        var buffer = stream.allocator.buffer(capacity: bytes.count)
        buffer.writeBytes(bytes)
        try stream.writeAndFlush(buffer).wait()
    }

    func readExactly(_ count: Int) throws -> Data {
        try inbound.readExactly(count, timeoutMilliseconds: receiveTimeoutMilliseconds)
    }
    func startAsyncRead(_ handler: @escaping (Result<Data, Error>) -> Void) { inbound.startAsyncRead(handler) }

    func close() {
        lock.lock()
        guard !closed else { lock.unlock(); return }
        closed = true
        let task = setupTask
        let stream = streamChannel
        let datagram = datagramChannel
        streamChannel = nil
        datagramChannel = nil
        lock.unlock()
        task?.cancel()
        inbound.close()
        stream?.close(promise: nil)
        if let datagram {
            // Closing the group before the datagram close has executed can
            // strand a pending handshake on the event loop.  Release the
            // group only after its owner channel has completed its close.
            datagram.closeFuture.whenComplete { [eventLoopGroup] _ in
                eventLoopGroup.shutdownGracefully { _ in }
            }
            datagram.close(promise: nil)
        } else {
            eventLoopGroup.shutdownGracefully { _ in }
        }
    }

    private func recordSetup(_ result: Result<Void, Error>) {
        lock.lock()
        setupResult = result
        lock.unlock()
    }

    private func open(host: String, port: Int, alpn: String, insecure: Bool, trustRootsPath: String?) async throws {
        let remoteAddress = try SocketAddress.makeAddressResolvingHost(host, port: port)
        let logger = Logger(label: "obstaclebridge.linux.quic")
        let (datagram, multiplexer) = try await DatagramBootstrap(group: eventLoopGroup)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .bind(host: remoteAddress.protocol == .inet6 ? "::" : "0.0.0.0", port: 0) { channel in
                channel.eventLoop.makeCompletedFuture {
                    let verification: VerificationConfiguration = .x509Certificates(trustRootsFilePath: trustRootsPath)
                    let configuration = QUICConfiguration.client(
                        verificationConfiguration: verification,
                        applicationProtocols: [alpn],
                        peerCertificateVerification: insecure ? .noVerification : .fullVerification
                    )
                    let inboundStreamInitializer: @Sendable (any Channel) -> EventLoopFuture<Never> = { stream in
                        stream.eventLoop.makeFailedFuture(ObstacleBridgeLinuxOverlayTransportError.invalidFrame)
                    }
                    let pair: (
                        QUICHandler<QUICStreamChannels>,
                        QUICHandler<QUICStreamChannels>.ConnectionMultiplexer<Never>
                    ) = try QUICHandler.makeHandlerAndConnectionMultiplexer(
                        channel: channel,
                        quicConfiguration: configuration,
                        logger: logger,
                        inboundStreamChannelInitializer: inboundStreamInitializer
                    )
                    try channel.pipeline.syncOperations.addHandler(pair.0)
                    return (channel, pair.1)
                }
            }
        let datagramWasCancelled = lock.withLock { () -> Bool in
            guard !closed else { return true }
            datagramChannel = datagram
            return false
        }
        if datagramWasCancelled {
            try? await datagram.close()
            throw ObstacleBridgeLinuxOverlayTransportError.cancelled
        }

        let connection: QUICConnection<Never> = try await multiplexer.createNewConnection(
            serverName: host,
            remoteAddress: remoteAddress
        ) { stream in
            stream.eventLoop.makeFailedFuture(ObstacleBridgeLinuxOverlayTransportError.invalidFrame)
        }
        let stream: any Channel = try await connection.createBidirectionalStream { initializer in
            initializer.channel.pipeline.addHandler(self.inbound).map { initializer.channel }
        }
        let streamWasCancelled = lock.withLock { () -> Bool in
            guard !closed else { return true }
            streamChannel = stream
            return false
        }
        if streamWasCancelled {
            try? await stream.close()
            throw ObstacleBridgeLinuxOverlayTransportError.cancelled
        }
    }
}
