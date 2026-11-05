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
    private let synchronousReceiveWaitMS: Int32
    /// This is deliberately metadata-only.  myUDP payloads can contain
    /// protected application traffic and must never be copied into a log.
    private let diagnosticSink: ((ObstacleBridgeRuntimeDiagnosticLevel, String, [String: String]) -> Void)?
    private let readinessQueue = DispatchQueue(label: "org.obstaclebridge.linux.myudp.readiness")
    private var readSource: DispatchSourceRead?
    private var timerSource: DispatchSourceTimer?

    /// `nextDataCounter` is an injectable Core seed for deterministic
    /// rollover qualification; normal runtime construction uses `1`.
    public init(
        host: String,
        port: Int,
        timeoutMilliseconds: Int = 1_000,
        nextDataCounter: UInt16 = 1,
        diagnosticSink: ((ObstacleBridgeRuntimeDiagnosticLevel, String, [String: String]) -> Void)? = nil
    ) throws {
        peerRuntime = .init(nextCounter: Int(nextDataCounter))
        synchronousReceiveWaitMS = Int32(max(1, min(Int(Int32.max), timeoutMilliseconds)))
        self.diagnosticSink = diagnosticSink
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
        guard getaddrinfo(resolvedHost, String(port), &hints, &addresses) == 0, let first = addresses else {
            diagnosticSink?(.warning, "myudp.socket_error_detected", ["operation": "resolve", "reason": "resolution_failed"])
            throw ObstacleBridgeLinuxMyUDPError.resolutionFailed
        }
        defer { freeaddrinfo(first) }
        var candidate: UnsafeMutablePointer<addrinfo>? = first
        var failure: Error = ObstacleBridgeLinuxMyUDPError.resolutionFailed
        var opened: Int32 = -1
        while let row = candidate {
            let fd = socket(row.pointee.ai_family, row.pointee.ai_socktype, row.pointee.ai_protocol)
            if fd >= 0 {
                if connect(fd, row.pointee.ai_addr, row.pointee.ai_addrlen) == 0 {
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
        guard opened >= 0 else {
            diagnosticSink?(.warning, "myudp.socket_error_detected", [
                "operation": "connect", "reason": failure.localizedDescription,
            ])
            throw failure
        }
        descriptor = opened
        diagnosticSink?(.info, "myudp.session_opened", ["address_family": String(first.pointee.ai_family)])
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
        guard payload.count <= 65_535 else {
            // This guard is outside Core's record chunking path.  Preserve the
            // legacy error for now, but make the local rejection observable so
            // a reconnect cannot be mistaken for an inbound parser or rekey
            // failure.  Payload bytes are deliberately never logged.
            diagnostic(.warning, "myudp.local_payload_rejected", diagnosticFields([
                "operation": "send_application",
                "reason": "payload_exceeds_transport_entry_limit",
                "payload_bytes": String(payload.count),
                "payload_limit_bytes": "65535",
            ]))
            throw ObstacleBridgeLinuxMyUDPError.invalidReply
        }
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
        // A full send window means the record is now owned by Core's bounded
        // queue; it is not an I/O failure.  A later CONTROL acknowledgement
        // causes `receive()` / `serviceTimers()` to flush it.  Counter zero
        // is outside the wire-valid DATA range and therefore unambiguously
        // represents an accepted-but-not-yet-emitted record to synchronous
        // callers.  The duplex ChannelMux path deliberately ignores it.
        return firstCounter ?? 0
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
            let received = recv(descriptor, &buffer, buffer.count, Int32(MSG_DONTWAIT))
            guard received > 0 else {
                let code = errno
                // A receive timeout is the owner’s timer cadence, not a
                // disconnected UDP peer.  Keep the duplex reader alive and
                // let Core emit due CONTROL, retransmission, or IDLE frames.
                // Treating EAGAIN as fatal caused an otherwise healthy quiet
                // myUDP epoch to reconnect before its first local service
                // connection could be accepted.
                if code == EAGAIN || code == EWOULDBLOCK {
                    if try waitForSynchronousReceive() { continue }
                    diagnostic(.info, "myudp.receive_idle_timer_service", ["operation": "synchronous_receive"])
                    try serviceTimers()
                    continue
                }
                throw socketError(code, operation: "receive")
            }
            let wire = Data(buffer.prefix(Int(received)))
            stateLock.lock()
            let now = DispatchTime.now().uptimeNanoseconds
            let effect: ObstacleBridgeUdpOverlayPeerRuntime.InboundWireSnapshot
            do { effect = try peerRuntime.receiveWire(wire, nowNS: now) }
            catch {
                stateLock.unlock()
                protocolError(error, wire: wire, operation: "receive")
                // A UDP peer can send a malformed or unrelated datagram at
                // any time.  Python counts and drops it, then keeps the
                // established myUDP session alive; do the same here.
                continue
            }
            deliveredPayloads.append(contentsOf: effect.deliveredPayloads)
            let payload = deliveredPayloads.isEmpty ? nil : deliveredPayloads.removeFirst()
            stateLock.unlock()
            receivedWire(wire, effect: effect, operation: "receive")
            try execute(effect.emittedFrames)
            if let payload { return (0, payload) }
        }
    }

    /// Compatibility path for `exchange()` callers that have no event-loop
    /// owner. The runtime never uses it after `startAsyncReceive()` installs
    /// its Dispatch read source. Frame reads remain MSG_DONTWAIT even here.
    private func waitForSynchronousReceive() throws -> Bool {
        var pollDescriptor = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
        while true {
            let result = poll(&pollDescriptor, 1, synchronousReceiveWaitMS) // OBSTACLEBRIDGE-ASYNC-IO-EXCEPTION: bounded synchronous myUDP bootstrap fallback without an event loop
            if result < 0 && errno == EINTR { continue }
            if result == 0 { return false }
            guard result > 0 else { throw socketError(errno, operation: "poll") }
            if pollDescriptor.revents & Int16(POLLIN) != 0 { return true }
            if pollDescriptor.revents & Int16(POLLERR | POLLHUP | POLLNVAL) != 0 {
                throw ObstacleBridgeLinuxMyUDPError.ioFailure(ECONNRESET)
            }
        }
    }

    /// Switches the established session from bootstrap reads to readiness-driven
    /// operation. The source and timer share one queue, preserving datagram and
    /// timer-effect order without leaving a thread blocked in `recv`.
    public func startAsyncReceive(_ handler: @escaping (Result<Data, Error>) -> Void) throws {
        receiveLock.lock()
        defer { receiveLock.unlock() }
        guard descriptor >= 0 else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(EBADF) }
        guard readSource == nil else { return }
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
            throw ObstacleBridgeLinuxMyUDPError.ioFailure(errno)
        }
        let source = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: readinessQueue)
        source.setEventHandler { [weak self] in self?.drainReadyDatagrams(handler) }
        let timer = DispatchSource.makeTimerSource(queue: readinessQueue)
        timer.schedule(deadline: .now() + .milliseconds(100), repeating: .milliseconds(100), leeway: .milliseconds(10))
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            do { try self.serviceTimers() }
            catch { handler(.failure(error)) }
        }
        readSource = source; timerSource = timer
        source.resume(); timer.resume()
    }

    private func drainReadyDatagrams(_ handler: @escaping (Result<Data, Error>) -> Void) {
        while true {
            var buffer = [UInt8](repeating: 0, count: 1_452)
            // Dispatch readiness can be stale after close or an adjacent
            // drain.  The asynchronous owner must never enter a blocking
            // datagram read from this callback.
            let received = recv(descriptor, &buffer, buffer.count, Int32(MSG_DONTWAIT))
            if received <= 0 {
                let code = errno
                if code == EAGAIN || code == EWOULDBLOCK { return }
                handler(.failure(socketError(code, operation: "async_receive")))
                return
            }
            do {
                for payload in try acceptInboundWire(Data(buffer.prefix(Int(received)))) {
                    handler(.success(payload))
                }
            } catch {
                handler(.failure(error))
                return
            }
        }
    }

    private func acceptInboundWire(_ wire: Data) throws -> [Data] {
        stateLock.lock()
        let now = DispatchTime.now().uptimeNanoseconds
        let effect: ObstacleBridgeUdpOverlayPeerRuntime.InboundWireSnapshot
        do { effect = try peerRuntime.receiveWire(wire, nowNS: now) }
        catch {
            stateLock.unlock()
            protocolError(error, wire: wire, operation: "async_receive")
            // Protocol-invalid datagrams are not a socket failure and must
            // not tear down an authenticated overlay epoch.
            return []
        }
        deliveredPayloads.append(contentsOf: effect.deliveredPayloads)
        let payloads = deliveredPayloads
        deliveredPayloads.removeAll(keepingCapacity: true)
        stateLock.unlock()
        receivedWire(wire, effect: effect, operation: "async_receive")
        try execute(effect.emittedFrames)
        return payloads
    }

    public func close() {
        readSource?.cancel(); readSource = nil
        timerSource?.cancel(); timerSource = nil
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
        let effects = try peerRuntime.tick(nowNS: DispatchTime.now().uptimeNanoseconds)
        if !effects.isEmpty {
            diagnostic(.debug, "myudp.timer_emitted_frames", diagnosticFields([
                "emitted_frame_count": String(effects.count),
            ]))
        }
        try execute(effects)
    }

    public func protocolStatsSnapshot() -> [String: UInt64] {
        stateLock.lock(); defer { stateLock.unlock() }
        return peerRuntime.protocolStatsSnapshot().reduce(into: [:]) { result, entry in
            if let value = entry.value as? Int { result[entry.key] = UInt64(max(0, value)) }
            else if let value = entry.value as? UInt64 { result[entry.key] = value }
            else if let value = entry.value as? Double { result[entry.key] = UInt64(max(0, value.rounded())) }
        }
    }

    /// Counts the frame at the myUDP/SecureLink boundary, rather than at an
    /// application worker. This includes handshake, rekey, and protected
    /// application frames just as the Apple transport owner does.
    func recordSecureLinkBoundaryFrame(direction: String) {
        stateLock.lock()
        defer { stateLock.unlock() }
        peerRuntime.recordSecureLinkBoundaryFrame(direction: direction)
    }

    private func sendWire(_ wire: Data) throws {
        // The POSIX owner sends only records accepted by the portable facade.
        // The peer engine remains the state owner; this boundary prevents a
        // Linux-local wire interpretation from drifting from Core constants.
        guard ObstacleBridgeUdpOverlayCodec.parseProtocolFrame(wire) != nil else {
            diagnostic(.warning, "myudp.protocol_error_detected", diagnosticFields([
                "operation": "send", "reason": "local_egress_frame_rejected", "wire_bytes": String(wire.count),
            ]))
            throw ObstacleBridgeLinuxMyUDPError.invalidReply
        }
        diagnostic(.debug, "myudp.datagram_sent", diagnosticFields(["wire_bytes": String(wire.count)]))
        let sent = wire.withUnsafeBytes { Glibc.send(descriptor, $0.baseAddress, wire.count, 0) }
        guard sent == wire.count else {
            throw socketError(errno, operation: "send", wireBytes: wire.count, sentBytes: max(0, sent))
        }
    }
    private func execute(_ datagrams: [Data]) throws {
        for datagram in datagrams { try sendWire(datagram) }
    }

    private func protocolError(_ error: Error, wire: Data, operation: String) {
        let fields = diagnosticFields([
            "operation": operation,
            "reason": String(describing: error),
            "wire_bytes": String(wire.count),
        ])
        // The WARNING survives ordinary production logging; DEBUG preserves
        // the same causal metadata beside the surrounding packet timeline.
        diagnostic(.warning, "myudp.protocol_error_detected", fields)
        diagnostic(.debug, "myudp.protocol_datagram_rejected", fields)
    }

    private func receivedWire(
        _ wire: Data,
        effect: ObstacleBridgeUdpOverlayPeerRuntime.InboundWireSnapshot,
        operation: String
    ) {
        diagnostic(.debug, "myudp.datagram_received", diagnosticFields([
            "operation": operation,
            "wire_bytes": String(wire.count),
            "delivered_payload_count": String(effect.deliveredPayloads.count),
            "delivered_payload_bytes": String(effect.deliveredPayloads.reduce(0) { $0 + $1.count }),
            "emitted_frame_count": String(effect.emittedFrames.count),
        ]))
    }

    private func socketError(
        _ code: Int32,
        operation: String,
        wireBytes: Int? = nil,
        sentBytes: Int? = nil
    ) -> ObstacleBridgeLinuxMyUDPError {
        var fields = [
            "operation": operation,
            "errno": String(code),
        ]
        if let wireBytes { fields["wire_bytes"] = String(wireBytes) }
        if let sentBytes { fields["sent_bytes"] = String(sentBytes) }
        if operation == "send", code == EAGAIN || code == EWOULDBLOCK {
            // `startAsyncReceive` sets O_NONBLOCK on this same connected UDP
            // descriptor. Record only socket metadata so the next incident
            // can distinguish send-buffer pressure from protocol rejection.
            let flags = fcntl(descriptor, F_GETFL)
            var sendBufferBytes: Int32 = 0
            var length = socklen_t(MemoryLayout<Int32>.size)
            let gotSendBuffer = getsockopt(descriptor, SOL_SOCKET, SO_SNDBUF, &sendBufferBytes, &length) == 0
            fields["would_block"] = "true"
            fields["socket_nonblocking"] = flags >= 0 && (flags & O_NONBLOCK) != 0 ? "true" : "false"
            if gotSendBuffer { fields["socket_send_buffer_bytes"] = String(sendBufferBytes) }
        }
        let safeFields = diagnosticFields(fields)
        diagnostic(.warning, "myudp.socket_error_detected", safeFields)
        diagnostic(.debug, "myudp.socket_error_detail", safeFields)
        return .ioFailure(code)
    }

    private func diagnosticFields(_ fields: [String: String]) -> [String: String] {
        // Most callers hold `stateLock` while Core mutates its peer engine.
        // Do not acquire it recursively merely to enrich a log line.  The
        // Admin snapshot supplies the matching transport counters, while each
        // diagnostic retains the causal operation and bounded frame metadata.
        fields
    }

    private func diagnostic(_ level: ObstacleBridgeRuntimeDiagnosticLevel, _ event: String, _ fields: @autoclosure () -> [String: String]) {
        diagnosticSink?(level, event, fields())
    }
}
