import Dispatch
import Foundation
#if os(Linux)
import Glibc
#endif
import ObstacleBridgeCore

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

/// Connected POSIX datagram owner for one Python-compatible myudp peer. DATA
/// records form an ordered stream; CONTROL and IDLE frames are transport
/// traffic, never application replies.
public final class ObstacleBridgeLinuxMyUDPTransportSession {
    private var descriptor: Int32
    private let peerRuntime: ObstacleBridgeUdpOverlayPeerRuntime
    private var deliveredPayloads: [Data] = []
    private let stateLock = NSLock()
    private let receiveLock = NSLock()

    /// `nextDataCounter` is an injectable Core seed for deterministic
    /// rollover qualification; normal runtime construction uses `1`.
    public init(host: String, port: Int, timeoutMilliseconds: Int = 1_000, nextDataCounter: UInt16 = 1) throws {
        peerRuntime = .init(nextCounter: Int(nextDataCounter))
        // Configured IPv6 literals commonly retain URI brackets. `getaddrinfo`
        // accepts the literal itself, not its URI presentation.
        let resolvedHost: String
        if host.hasPrefix("[") && host.hasSuffix("]") {
            resolvedHost = String(host.dropFirst().dropLast())
        } else {
            resolvedHost = host
        }
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = Int32(SOCK_DGRAM.rawValue)
        hints.ai_protocol = Int32(IPPROTO_UDP)
        var addresses: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(resolvedHost, String(port), &hints, &addresses) == 0, let first = addresses else { throw ObstacleBridgeLinuxMyUDPError.resolutionFailed }
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
        _ = try send(payload)
        // A synchronous caller has no event loop to drive Core timer effects.
        // Retry a bounded number of receive timeouts after ticking the shared
        // peer engine, so a dropped DATA datagram exercises the same recovery
        // policy as a long-lived adapter instead of failing the transaction.
        var timeoutTicks = 0
        while true {
            do { return try receive().payload }
            catch ObstacleBridgeLinuxMyUDPError.ioFailure(let code)
                where (code == EAGAIN || code == EWOULDBLOCK) && timeoutTicks < 2 {
                timeoutTicks += 1
                try serviceTimers()
            }
            catch { throw error }
        }
    }

    /// Emits one DATA batch and returns its transport counter. A duplex owner
    /// may receive peer batches independently through `receive()`.
    @discardableResult public func send(_ payload: Data) throws -> UInt16 {
        guard descriptor >= 0 else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(EBADF) }
        guard payload.count <= 65_535 else { throw ObstacleBridgeLinuxMyUDPError.invalidReply }
        stateLock.lock()
        defer { stateLock.unlock() }
        let now = DispatchTime.now().uptimeNanoseconds
        try peerRuntime.enqueueApplicationPayload(payload, nowNS: now)
        var firstCounter: UInt16?
        while true {
            let effect = try peerRuntime.flushSendQueue(nowNS: now)
            guard !effect.frames.isEmpty else { break }
            if firstCounter == nil,
               let counter = effect.counters.first,
               let portableCounter = UInt16(exactly: counter) {
                firstCounter = portableCounter
            }
            try execute(effect.frames)
        }
        guard let firstCounter else { throw ObstacleBridgeLinuxMyUDPError.invalidReply }
        return firstCounter
    }

    public func receive() throws -> (counter: UInt16, payload: Data) {
        guard descriptor >= 0 else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(EBADF) }
        receiveLock.lock()
        defer { receiveLock.unlock() }
        while true {
            stateLock.lock()
            if !deliveredPayloads.isEmpty {
                let payload = deliveredPayloads.removeFirst()
                stateLock.unlock()
                return (0, payload)
            }
            stateLock.unlock()
            var buffer = [UInt8](repeating: 0, count: 1_452)
            let received = recv(descriptor, &buffer, buffer.count, 0)
            guard received > 0 else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(errno) }
            let wire = Data(buffer.prefix(Int(received)))
            stateLock.lock()
            let now = DispatchTime.now().uptimeNanoseconds
            let effect: ObstacleBridgeUdpOverlayPeerRuntime.InboundWireSnapshot
            do { effect = try peerRuntime.receiveWire(wire, nowNS: now) }
            catch {
                stateLock.unlock()
                throw ObstacleBridgeLinuxMyUDPError.invalidReply
            }
            deliveredPayloads.append(contentsOf: effect.deliveredPayloads)
            let payload = deliveredPayloads.isEmpty ? nil : deliveredPayloads.removeFirst()
            stateLock.unlock()
            try execute(effect.emittedFrames)
            if let payload { return (0, payload) }
        }
    }

    public func close() {
        if descriptor >= 0 {
            let active = descriptor
            descriptor = -1
            _ = shutdown(active, Int32(SHUT_RDWR))
            _ = Glibc.close(active)
        }
    }
    deinit { close() }

    /// Executes due Core retransmission, CONTROL, and IDLE effects. A caller
    /// with its own event loop may call this at its selected timer cadence.
    public func serviceTimers() throws {
        guard descriptor >= 0 else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(EBADF) }
        stateLock.lock()
        defer { stateLock.unlock() }
        try execute(peerRuntime.tick(nowNS: DispatchTime.now().uptimeNanoseconds))
    }

    private func sendWire(_ wire: Data) throws {
        // The POSIX owner sends only records accepted by the portable facade.
        // The peer engine remains the state owner; this boundary prevents a
        // Linux-local wire interpretation from drifting from Core constants.
        guard ObstacleBridgeUdpOverlayCodec.parseProtocolFrame(wire) != nil else {
            throw ObstacleBridgeLinuxMyUDPError.invalidReply
        }
        let sent = wire.withUnsafeBytes { Glibc.send(descriptor, $0.baseAddress, wire.count, 0) }
        guard sent == wire.count else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(errno) }
    }
    private func execute(_ datagrams: [Data]) throws {
        for datagram in datagrams { try sendWire(datagram) }
    }
}
