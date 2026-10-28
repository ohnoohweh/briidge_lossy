import Foundation
import Dispatch
import ObstacleBridgeCore
import ObstacleBridgeDesktopShared
#if os(Linux)
import Glibc
#endif

fileprivate typealias ObstacleBridgeLinuxTunHelperFrameKind = ObstacleBridgeWorkerIPC.Kind

/// Failure boundary for the Linux-only helper IPC owner. This adapter never
/// opens `/dev/net/tun`, applies routes, or executes hooks; those privileged
/// actions remain behind the explicitly selected local helper endpoint.
public enum ObstacleBridgeLinuxTunHelperAdapterError: Error, Equatable, LocalizedError {
    case unavailable(String)
    case connectFailed(Int32)
    case timeout
    case disconnected
    case malformedReply(String)
    case frameTooLarge

    public var errorDescription: String? {
        switch self {
        case .unavailable(let detail), .malformedReply(let detail): return detail
        case .connectFailed(let code): return "Linux TUN helper connection failed errno=\(code)"
        case .timeout: return "Linux TUN helper timed out"
        case .disconnected: return "Linux TUN helper disconnected"
        case .frameTooLarge: return "Linux TUN helper frame exceeds the bounded IPC limit"
        }
    }
}

/// Long-lived authenticated packet endpoint for a helper-owned TUN device.
/// Control requests intentionally remain on bounded independent exchanges;
/// this connection only carries packet and EVENT fan-out.
public final class ObstacleBridgeLinuxTunHelperPacketDevice: ObstacleBridgeLinuxPacketDevice, @unchecked Sendable {
    private let adapter: ObstacleBridgeLinuxTunHelperAdapter
    private let packetSink: (Data) -> Void
    private let eventSink: (String) -> Void
    private let lock = NSLock()
    private let receiveQueue = DispatchQueue(label: "org.obstaclebridge.linux.tun-helper-packet-readiness")
    private var fd: Int32 = -1
    private var running = false
    private var generation: UInt64 = 0
    private var readSource: DispatchSourceRead?
    private var receiveBuffer = Data()
    private var receiveBufferGeneration: UInt64 = 0

    public init(adapter: ObstacleBridgeLinuxTunHelperAdapter, packetSink: @escaping (Data) -> Void, eventSink: @escaping (String) -> Void = { _ in }) {
        self.adapter = adapter; self.packetSink = packetSink; self.eventSink = eventSink
    }

    public func start() throws {
        lock.lock(); defer { lock.unlock() }
        guard !running else { return }
        let connected = try adapter.connectSocket()
        let selectedGeneration = UInt64.random(in: 1...UInt64.max)
        do { try adapter.authenticate(on: connected, generation: selectedGeneration) } catch { _ = close(connected); throw error }
        generation = selectedGeneration; fd = connected; running = true
        let source = DispatchSource.makeReadSource(fileDescriptor: connected, queue: receiveQueue)
        readSource = source
        source.setEventHandler { [weak self] in self?.drainReadable() }
        source.resume()
    }

    public func writePacket(_ packet: Data) throws {
        lock.lock(); let active = running ? fd : -1; let activeGeneration = generation; lock.unlock()
        guard active >= 0 else { throw ObstacleBridgeLinuxTunHelperAdapterError.disconnected }
        try adapter.writeFrame(kind: .data, generation: activeGeneration, body: packet, to: active)
    }

    public func stop() {
        lock.lock()
        let active = fd
        let source = readSource
        fd = -1; generation = 0; running = false; readSource = nil
        lock.unlock()
        source?.cancel()
        if active >= 0 { _ = shutdown(active, Int32(SHUT_RDWR)); _ = close(active) }
    }

    /// The packet endpoint stays active for the TUN lifetime. It must never
    /// hold a worker thread inside a stream read: Dispatch reports readiness,
    /// `MSG_DONTWAIT` drains what is already present, and this owner retains
    /// incomplete OBIP records until their remaining bytes arrive.
    private func drainReadable() {
        while true {
            lock.lock(); let active = running ? fd : -1; let activeGeneration = generation; lock.unlock()
            guard active >= 0 else { return }
            var bytes = [UInt8](repeating: 0, count: 16_384)
            let received = recv(active, &bytes, bytes.count, Int32(MSG_DONTWAIT))
            if received > 0 {
                if receiveBufferGeneration != activeGeneration {
                    receiveBuffer.removeAll(keepingCapacity: false)
                    receiveBufferGeneration = activeGeneration
                }
                receiveBuffer.append(bytes, count: Int(received))
                guard consumeBufferedFrames(expectedGeneration: activeGeneration) else { stop(); return }
                continue
            }
            if received < 0, (errno == EAGAIN || errno == EWOULDBLOCK) { return }
            if received < 0, errno == EINTR { continue }
            stop()
            return
        }
    }

    private func consumeBufferedFrames(expectedGeneration: UInt64) -> Bool {
        while receiveBuffer.count >= ObstacleBridgeWorkerIPC.headerBytes {
            let header = Data(receiveBuffer.prefix(ObstacleBridgeWorkerIPC.headerBytes))
            let bodyLength: Int
            do {
                guard let parsedLength = try ObstacleBridgeWorkerIPC.frameSize(header),
                      parsedLength <= ObstacleBridgeLinuxTunHelperAdapter.maximumFrameBytes else { return false }
                bodyLength = parsedLength
            } catch {
                return false
            }
            guard receiveBuffer.count >= ObstacleBridgeWorkerIPC.headerBytes + bodyLength else { return true }
            let length = ObstacleBridgeWorkerIPC.headerBytes + bodyLength
            let wire = Data(receiveBuffer.prefix(length))
            receiveBuffer.removeFirst(length)
            guard let decoded = try? ObstacleBridgeWorkerIPC.decode(wire), let frame = decoded.0,
                  decoded.1.isEmpty, frame.generation == expectedGeneration else { return false }
            switch frame.kind {
            case .data:
                packetSink(frame.payload)
            case .event:
                if let value = try? ObstacleBridgeWorkerIPC.decodeControl(frame),
                   let payload = value["payload"] as? [String: Any], let detail = payload["detail"] as? String {
                    eventSink(detail)
                }
            default:
                continue
            }
            }
        return true
        }
}

/// Unix-domain-socket client for the common OBIP helper protocol. Every bounded
/// exchange negotiates HELLO/READY, then authenticates its one-time token
/// before issuing one control operation.
public final class ObstacleBridgeLinuxTunHelperAdapter: @unchecked Sendable {
    public static let maximumFrameBytes = ObstacleBridgeWorkerIPC.maximumFrameBytes
    private static let helperCapabilities: Set<String> = ["tun.control", "tun.packet", "tun.event"]

    public let socketPath: String
    public let sessionToken: String
    public let timeoutMilliseconds: Int
    private let lock = NSLock()

    public init(socketPath: String, sessionToken: String, timeoutMilliseconds: Int = 2_000) throws {
        guard !socketPath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("Linux TUN helper socket path is required")
        }
        guard !sessionToken.isEmpty else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("Linux TUN helper session token is required")
        }
        guard (1...60_000).contains(timeoutMilliseconds) else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("Linux TUN helper timeout must be between 1 and 60000 ms")
        }
        self.socketPath = socketPath
        self.sessionToken = sessionToken
        self.timeoutMilliseconds = timeoutMilliseconds
    }

    public func send(command: ObstacleBridgeTunHelperCommand, payload: [String: Any]) throws -> [String: Any] {
        guard command != .writePacket else {
            guard let packet = payload["packet"] as? Data else {
                throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("WRITE_PACKET requires a binary packet")
            }
            return try sendPacketToHelper(packet)
        }
        lock.lock(); defer { lock.unlock() }
        return try exchangeControl(operation: command.rawValue, payload: payload)
    }

    /// The helper protocol deliberately has no packet-write acknowledgement;
    /// successful framing and write only prove local handoff to the helper.
    public func sendPacketToHelper(_ packet: Data) throws -> [String: Any] {
        guard packet.count <= Self.maximumFrameBytes else { throw ObstacleBridgeLinuxTunHelperAdapterError.frameTooLarge }
        lock.lock(); defer { lock.unlock() }
        let fd = try connectSocket()
        defer { _ = close(fd) }
        let generation = nextGeneration()
        try authenticate(on: fd, generation: generation)
        try writeFrame(kind: .data, generation: generation, body: packet, to: fd)
        return ["ok": true, "op": ObstacleBridgeTunHelperCommand.writePacket.rawValue]
    }

    /// Delegates a Core-derived network plan to the explicitly configured
    /// privileged helper. The Linux process never applies routes or DNS itself.
    public func apply(packetTunnelPlan plan: ObstacleBridgeRuntimeConfigPort.PacketTunnelPlan, interfaceName: String) throws -> [String: Any] {
        guard plan.enabledOnStartup else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("disabled packet-tunnel plan cannot be applied")
        }
        return try send(command: .applyNetwork, payload: Self.planPayload(plan, interfaceName: interfaceName))
    }

    /// If an apply reply is lost after helper-side partial work, request the
    /// paired removal on a fresh authenticated IPC exchange before surfacing failure.
    public func applyWithRollback(packetTunnelPlan plan: ObstacleBridgeRuntimeConfigPort.PacketTunnelPlan, interfaceName: String) throws -> [String: Any] {
        do { return try apply(packetTunnelPlan: plan, interfaceName: interfaceName) }
        catch { _ = try? rollback(packetTunnelPlan: plan, interfaceName: interfaceName); throw error }
    }

    public func rollback(packetTunnelPlan plan: ObstacleBridgeRuntimeConfigPort.PacketTunnelPlan, interfaceName: String) throws -> [String: Any] {
        try send(command: .removeNetwork, payload: Self.planPayload(plan, interfaceName: interfaceName))
    }

    /// Matches the Python Linux-native helper contract. The helper derives its
    /// hook environment, captures underlay routes, and owns apply/remove.
    private static func planPayload(_ plan: ObstacleBridgeRuntimeConfigPort.PacketTunnelPlan, interfaceName: String) -> [String: Any] {
        ["ifname": interfaceName, "tun_routing": [
            "enabled_on_startup": plan.enabledOnStartup,
            "tunnel_address": plan.tunnelAddress, "tunnel_prefix": plan.tunnelPrefix,
            "tunnel_address6": plan.tunnelAddress6, "tunnel_prefix6": plan.tunnelPrefix6,
            "included_routes": plan.includedRoutes, "excluded_routes": plan.excludedRoutes,
            "included_routes6": plan.includedRoutes6, "excluded_routes6": plan.excludedRoutes6,
            "dns_servers": plan.dnsServers, "mtu": plan.mtu,
        ]]
    }

    private func exchangeControl(operation: String, payload: [String: Any]) throws -> [String: Any] {
        let fd = try connectSocket()
        defer { _ = close(fd) }
        let generation = nextGeneration()
        try authenticate(on: fd, generation: generation)
        try writeControl(operation: operation, payload: payload, generation: generation, to: fd)
        return try readControlResponse(expectedOperation: "\(operation)_OK", generation: generation, from: fd)
    }

    fileprivate func authenticate(on fd: Int32, generation: UInt64) throws {
        try writeAll(try ObstacleBridgeWorkerIPC.hello(generation: generation, role: "tun-helper-client", capabilities: Array(Self.helperCapabilities)), to: fd)
        let peerHello = try readFrame(from: fd)
        let accepted = try ObstacleBridgeWorkerIPC.negotiatedCapabilities(peerHello, supported: Self.helperCapabilities)
        guard peerHello.kind == .hello, peerHello.generation == generation, accepted.role == "tun-helper", Set(accepted.capabilities) == Self.helperCapabilities else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.malformedReply("Linux TUN helper rejected common IPC capability negotiation")
        }
        let ready = try readFrame(from: fd)
        guard ready.kind == .ready, ready.generation == generation,
              let readyValue = try? ObstacleBridgeWorkerIPC.decodeControl(ready), readyValue["op"] as? String == "READY" else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.malformedReply("Linux TUN helper did not confirm common IPC readiness")
        }
        try writeControl(operation: "HELLO", payload: ["token": sessionToken], generation: generation, to: fd)
        _ = try readControlResponse(expectedOperation: "HELLO_OK", generation: generation, from: fd)
    }

    private func writeControl(operation: String, payload: [String: Any], generation: UInt64, to fd: Int32) throws {
        let frame: Data
        do { frame = try ObstacleBridgeWorkerIPC.encodeControl(kind: .request, generation: generation, value: ["op": operation, "payload": payload]) }
        catch { throw ObstacleBridgeLinuxTunHelperAdapterError.malformedReply("unable to encode Linux TUN helper request") }
        try writeAll(frame, to: fd)
    }

    private func readControlResponse(expectedOperation: String, generation: UInt64, from fd: Int32) throws -> [String: Any] {
        // The helper broadcasts packet and EVENT frames to every authenticated
        // client. A bounded control exchange can therefore observe an
        // unsolicited frame before its own response when TUN traffic begins.
        // Those frames belong to the long-lived packet endpoint, so discard
        // them here and keep reading within the socket's bounded timeout.
        while true {
            let frame = try readFrame(from: fd)
            guard frame.generation == generation else { throw ObstacleBridgeLinuxTunHelperAdapterError.malformedReply("Linux TUN helper returned a stale generation") }
            switch frame.kind {
            case .data, .event:
                continue
            case .response:
                let control: (operation: String, payload: [String: Any])
                do { control = try decodeControl(frame) }
                catch { throw ObstacleBridgeLinuxTunHelperAdapterError.malformedReply("Linux TUN helper returned an invalid common IPC control response") }
                let operation = control.operation
                let payload = control.payload
                if operation == "ERROR" {
                    throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("Linux TUN helper rejected \(expectedOperation): \(payload["detail"] as? String ?? "unspecified error")")
                }
                guard operation == expectedOperation else {
                    throw ObstacleBridgeLinuxTunHelperAdapterError.malformedReply("Linux TUN helper returned \(operation), expected \(expectedOperation)")
                }
                return payload.merging(["ok": true, "op": expectedOperation]) { _, response in response }
            default:
                throw ObstacleBridgeLinuxTunHelperAdapterError.malformedReply("Linux TUN helper returned unexpected \(frame.kind.rawValue) frame while awaiting \(expectedOperation)")
            }
        }
    }

    fileprivate func connectSocket() throws -> Int32 {
        let fd = socket(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0)
        guard fd >= 0 else { throw ObstacleBridgeLinuxTunHelperAdapterError.connectFailed(errno) }
        var timeout = timeval(tv_sec: timeoutMilliseconds / 1000, tv_usec: (timeoutMilliseconds % 1000) * 1_000)
        _ = withUnsafePointer(to: &timeout) { setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, $0, socklen_t(MemoryLayout<timeval>.size)) }
        _ = withUnsafePointer(to: &timeout) { setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, $0, socklen_t(MemoryLayout<timeval>.size)) }
        var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(socketPath.utf8) + [0]
        let capacity = MemoryLayout.size(ofValue: address.sun_path)
        guard bytes.count <= capacity else { _ = close(fd); throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("Linux TUN helper socket path is too long") }
        withUnsafeMutableBytes(of: &address.sun_path) { destination in
            destination.initializeMemory(as: UInt8.self, repeating: 0)
            destination.baseAddress!.assumingMemoryBound(to: UInt8.self).update(from: bytes, count: bytes.count)
        }
        let result = withUnsafePointer(to: &address) { pointer in pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        guard result == 0 else {
            let code = errno
            _ = close(fd)
            if code == EAGAIN || code == EWOULDBLOCK { throw ObstacleBridgeLinuxTunHelperAdapterError.timeout }
            throw ObstacleBridgeLinuxTunHelperAdapterError.connectFailed(code)
        }
        return fd
    }

    fileprivate func writeFrame(kind: ObstacleBridgeLinuxTunHelperFrameKind, generation: UInt64, body: Data, to fd: Int32) throws {
        do { try writeAll(try ObstacleBridgeWorkerIPC.encode(kind: kind, generation: generation, payload: body), to: fd) }
        catch ObstacleBridgeWorkerIPC.Failure.frameTooLarge { throw ObstacleBridgeLinuxTunHelperAdapterError.frameTooLarge }
    }

    fileprivate func readFrame(from fd: Int32) throws -> ObstacleBridgeWorkerIPC.Frame {
        let wireHeader = try readExactly(ObstacleBridgeWorkerIPC.headerBytes, from: fd)
        let bodyLength: Int
        do { bodyLength = try ObstacleBridgeWorkerIPC.frameSize(wireHeader) ?? 0 }
        catch ObstacleBridgeWorkerIPC.Failure.frameTooLarge { throw ObstacleBridgeLinuxTunHelperAdapterError.frameTooLarge }
        catch { throw ObstacleBridgeLinuxTunHelperAdapterError.malformedReply("Linux TUN helper returned unknown frame kind") }
        let decoded = try? ObstacleBridgeWorkerIPC.decode(wireHeader + (try readExactly(bodyLength, from: fd)))
        guard let frame = decoded?.0, decoded?.1.isEmpty == true else { throw ObstacleBridgeLinuxTunHelperAdapterError.malformedReply("Linux TUN helper returned an incomplete frame") }
        return frame
    }

    private func decodeControl(_ frame: ObstacleBridgeWorkerIPC.Frame) throws -> (operation: String, payload: [String: Any]) {
        let value = try ObstacleBridgeWorkerIPC.decodeControl(frame)
        guard let operation = value["op"] as? String, !operation.isEmpty, operation.count <= 64,
              let payload = value["payload"] as? [String: Any] else { throw ObstacleBridgeLinuxTunHelperAdapterError.malformedReply("Linux TUN helper returned invalid control") }
        return (operation, payload)
    }

    private func nextGeneration() -> UInt64 { UInt64.random(in: 1...UInt64.max) }

    private func writeAll(_ data: Data, to fd: Int32) throws {
        var offset = 0
        while offset < data.count {
            let written = data.withUnsafeBytes { write(fd, $0.baseAddress!.advanced(by: offset), data.count - offset) }
            guard written > 0 else { if errno == EAGAIN || errno == EWOULDBLOCK { throw ObstacleBridgeLinuxTunHelperAdapterError.timeout }; throw ObstacleBridgeLinuxTunHelperAdapterError.disconnected }
            offset += Int(written)
        }
    }

    private func readExactly(_ count: Int, from fd: Int32) throws -> Data {
        var output = Data(); output.reserveCapacity(count)
        var buffer = [UInt8](repeating: 0, count: min(8192, max(1, count)))
        let deadline = DispatchTime.now().uptimeNanoseconds + UInt64(timeoutMilliseconds) * 1_000_000
        while output.count < count {
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else { throw ObstacleBridgeLinuxTunHelperAdapterError.timeout }
            var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let remaining = Int32(min(UInt64(Int32.max), max(1, (deadline - now) / 1_000_000)))
            let ready = poll(&descriptor, 1, remaining)
            if ready < 0, errno == EINTR { continue }
            guard ready > 0, descriptor.revents & Int16(POLLIN) != 0 else {
                if ready == 0 { throw ObstacleBridgeLinuxTunHelperAdapterError.timeout }
                throw ObstacleBridgeLinuxTunHelperAdapterError.disconnected
            }
            // A readiness event may be stale after a helper teardown.  Never
            // enter a blocking stream read on the control-exchange thread.
            let received = recv(fd, &buffer, min(buffer.count, count - output.count), Int32(MSG_DONTWAIT))
            if received < 0, errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK { continue }
            guard received > 0 else { throw ObstacleBridgeLinuxTunHelperAdapterError.disconnected }
            output.append(buffer, count: Int(received))
        }
        return output
    }
}
