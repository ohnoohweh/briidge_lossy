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
    private let peerEngine = ObstacleBridgeMyUDPPeerEngine()
    private let stateLock = NSLock()
    private let receiveLock = NSLock()

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
        _ = try send(payload)
        return try receive().payload
    }

    /// Emits one DATA batch and returns its transport counter. A duplex owner
    /// may receive peer batches independently through `receive()`.
    @discardableResult public func send(_ payload: Data) throws -> UInt16 {
        guard descriptor >= 0 else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(EBADF) }
        guard payload.count <= 65_535 else { throw ObstacleBridgeLinuxMyUDPError.invalidReply }
        stateLock.lock()
        defer { stateLock.unlock() }
        let now = DispatchTime.now().uptimeNanoseconds
        try peerEngine.enqueueApplicationRecord(payload, nowNanoseconds: now)
        var firstCounter: UInt16?
        while true {
            let effect = try peerEngine.flush(nowNanoseconds: now)
            guard !effect.outboundDatagrams.isEmpty else { break }
            if firstCounter == nil { firstCounter = effect.outboundDataCounters.first }
            try execute(effect)
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
            if let payload = peerEngine.takeDeliveredRecord() {
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
            let effect: ObstacleBridgeMyUDPPeerEngine.Effect
            do { effect = try peerEngine.receiveWire(wire, nowNanoseconds: now) }
            catch {
                stateLock.unlock()
                throw ObstacleBridgeLinuxMyUDPError.invalidReply
            }
            let payload = peerEngine.takeDeliveredRecord()
            stateLock.unlock()
            try execute(effect)
            if let payload { return (0, payload) }
        }
    }

    public func close() {
        if descriptor >= 0 { _ = Glibc.close(descriptor); descriptor = -1 }
    }
    deinit { close() }

    /// Executes due Core retransmission, CONTROL, and IDLE effects. A caller
    /// with its own event loop may call this at its selected timer cadence.
    public func serviceTimers() throws {
        guard descriptor >= 0 else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(EBADF) }
        stateLock.lock()
        defer { stateLock.unlock() }
        try execute(peerEngine.tick(nowNanoseconds: DispatchTime.now().uptimeNanoseconds))
    }

    private func sendWire(_ wire: Data) throws {
        let sent = wire.withUnsafeBytes { Glibc.send(descriptor, $0.baseAddress, wire.count, 0) }
        guard sent == wire.count else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(errno) }
    }
    private func execute(_ effect: ObstacleBridgeMyUDPPeerEngine.Effect) throws {
        for datagram in effect.outboundDatagrams { try sendWire(datagram) }
    }
}
