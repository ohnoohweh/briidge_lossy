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
    private var nextCounter: UInt16 = 1
    private var expectedCounter: UInt16 = 1
    private var pendingChunks: [UInt16: Data] = [:]
    private var completedPayloads: [Data] = []
    private var streamBytes = Data()
    private var expectedRecordLength: Int?
    private var highestReceived: UInt16 = 0
    private var latestPeerTransmitNanoseconds: UInt64 = 0
    private var latestPeerReceiveNanoseconds: UInt64 = 0
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
        var record = Data()
        append(UInt32(payload.count), to: &record)
        record.append(payload)
        var offset = 0
        var firstCounter: UInt16 = 0
        while offset < record.count {
            let length = min(ObstacleBridgeMyUDPCodec.maximumPayloadSize, record.count - offset)
            stateLock.lock()
            let counter = nextCounter
            nextCounter = increment(counter)
            let echo = currentEchoLocked(now: DispatchTime.now().uptimeNanoseconds)
            stateLock.unlock()
            if firstCounter == 0 { firstCounter = counter }
            let chunk = ObstacleBridgeMyUDPStreamChunk(counter: counter, payload: Data(record[offset..<(offset + length)]))
            let wire = try ObstacleBridgeMyUDPCodec.encodeData(chunks: [chunk], transmittedNanoseconds: DispatchTime.now().uptimeNanoseconds, echoedNanoseconds: echo)
            try sendWire(wire)
            offset += length
        }
        return firstCounter
    }

    public func receive() throws -> (counter: UInt16, payload: Data) {
        guard descriptor >= 0 else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(EBADF) }
        receiveLock.lock()
        defer { receiveLock.unlock() }
        while true {
            stateLock.lock()
            if !completedPayloads.isEmpty {
                let payload = completedPayloads.removeFirst()
                stateLock.unlock()
                return (0, payload)
            }
            stateLock.unlock()
            var buffer = [UInt8](repeating: 0, count: 1_452)
            let received = recv(descriptor, &buffer, buffer.count, 0)
            guard received > 0 else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(errno) }
            let wire = Data(buffer.prefix(Int(received)))
            let frame: ObstacleBridgeMyUDPWireFrame
            do { frame = try ObstacleBridgeMyUDPCodec.decodeWire(wire) }
            catch { throw ObstacleBridgeLinuxMyUDPError.invalidReply }
            guard frame.type == ObstacleBridgeMyUDPCodec.dataType else {
                if frame.type == ObstacleBridgeMyUDPCodec.controlType || frame.type == ObstacleBridgeMyUDPCodec.idleType { continue }
                throw ObstacleBridgeLinuxMyUDPError.invalidReply
            }
            let decoded: (chunks: [ObstacleBridgeMyUDPStreamChunk], transmittedNanoseconds: UInt64, echoedNanoseconds: UInt64)
            do { decoded = try ObstacleBridgeMyUDPCodec.decodeDataChunks(wire) }
            catch { throw ObstacleBridgeLinuxMyUDPError.invalidReply }
            var acknowledge: (lastInOrder: UInt16, highest: UInt16, missing: [UInt16]) = (0, 0, [])
            stateLock.lock()
            latestPeerTransmitNanoseconds = decoded.transmittedNanoseconds
            latestPeerReceiveNanoseconds = DispatchTime.now().uptimeNanoseconds
            for chunk in decoded.chunks { accept(chunk) }
            acknowledge = controlStateLocked()
            stateLock.unlock()
            let now = DispatchTime.now().uptimeNanoseconds
            let control = try ObstacleBridgeMyUDPCodec.encodeControl(lastInOrder: acknowledge.lastInOrder, highestReceived: acknowledge.highest, missing: acknowledge.missing, transmittedNanoseconds: now, echoedNanoseconds: echoForPeer(now: now))
            try sendWire(control)
        }
    }

    public func close() {
        if descriptor >= 0 { _ = Glibc.close(descriptor); descriptor = -1 }
    }
    deinit { close() }

    private func accept(_ chunk: ObstacleBridgeMyUDPStreamChunk) {
        if chunk.counter == expectedCounter {
            consume(chunk.payload)
            expectedCounter = increment(expectedCounter)
            while let pending = pendingChunks.removeValue(forKey: expectedCounter) {
                consume(pending)
                expectedCounter = increment(expectedCounter)
            }
        } else if isAhead(chunk.counter, of: expectedCounter), pendingChunks[chunk.counter] == nil {
            pendingChunks[chunk.counter] = chunk.payload
        }
        if highestReceived == 0 || isAhead(chunk.counter, of: highestReceived) { highestReceived = chunk.counter }
    }

    private func consume(_ bytes: Data) {
        streamBytes.append(bytes)
        while true {
            if expectedRecordLength == nil {
                guard streamBytes.count >= 4 else { return }
                let header = Array(streamBytes.prefix(4))
                let length = Int((UInt32(header[0]) << 24) | (UInt32(header[1]) << 16) | (UInt32(header[2]) << 8) | UInt32(header[3]))
                streamBytes.removeFirst(4)
                guard length <= 65_535 else { streamBytes.removeAll(); expectedRecordLength = nil; return }
                expectedRecordLength = length
            }
            guard let length = expectedRecordLength, streamBytes.count >= length else { return }
            completedPayloads.append(Data(streamBytes.prefix(length)))
            streamBytes.removeFirst(length)
            expectedRecordLength = nil
        }
    }

    private func controlStateLocked() -> (lastInOrder: UInt16, highest: UInt16, missing: [UInt16]) {
        let last = expectedCounter == 1 ? 0 : expectedCounter &- 1
        var missing: [UInt16] = []
        var current = expectedCounter
        while current != increment(highestReceived), missing.count < 64 {
            if pendingChunks[current] == nil { missing.append(current) }
            current = increment(current)
        }
        return (last, highestReceived, missing)
    }

    private func echoForPeer(now: UInt64) -> UInt64 {
        stateLock.lock(); defer { stateLock.unlock() }
        return currentEchoLocked(now: now)
    }
    private func currentEchoLocked(now: UInt64) -> UInt64 {
        guard latestPeerTransmitNanoseconds > 0, now >= latestPeerReceiveNanoseconds else { return 0 }
        return latestPeerTransmitNanoseconds &+ (now - latestPeerReceiveNanoseconds)
    }
    private func sendWire(_ wire: Data) throws {
        let sent = wire.withUnsafeBytes { Glibc.send(descriptor, $0.baseAddress, wire.count, 0) }
        guard sent == wire.count else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(errno) }
    }
    private func increment(_ counter: UInt16) -> UInt16 { counter == UInt16.max ? 1 : counter &+ 1 }
    private func isAhead(_ candidate: UInt16, of reference: UInt16) -> Bool {
        let distance = (Int(candidate) - Int(reference) + 65_535) % 65_535
        return distance > 0 && distance < 32_767
    }
    private func append(_ value: UInt32, to data: inout Data) {
        data.append(UInt8((value >> 24) & 0xff)); data.append(UInt8((value >> 16) & 0xff)); data.append(UInt8((value >> 8) & 0xff)); data.append(UInt8(value & 0xff))
    }
}
