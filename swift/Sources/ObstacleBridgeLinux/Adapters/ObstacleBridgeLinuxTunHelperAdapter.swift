import Foundation
import ObstacleBridgeCore
#if os(Linux)
import Glibc
#endif

/// Failure boundary for the Linux-only helper IPC owner.  This adapter never
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

/// Unix-domain-socket owner for the portable Core helper envelope contract.
/// Each operation uses a bounded length-prefixed JSON request/reply exchange.
/// Sequence generation and reply sequence/op validation remain in
/// `ObstacleBridgeXPCShapedTunHelperCommandTransport` in Core.
public final class ObstacleBridgeLinuxTunHelperAdapter: @unchecked Sendable {
    public static let maximumFrameBytes = 1_048_576

    public let socketPath: String
    public let timeoutMilliseconds: Int
    private let lock = NSLock()
    private var coreTransport: ObstacleBridgeXPCShapedTunHelperCommandTransport!

    public init(socketPath: String, timeoutMilliseconds: Int = 2_000) throws {
        guard !socketPath.isEmpty else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("Linux TUN helper socket path is required")
        }
        guard (1...60_000).contains(timeoutMilliseconds) else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("Linux TUN helper timeout must be between 1 and 60000 ms")
        }
        self.socketPath = socketPath
        self.timeoutMilliseconds = timeoutMilliseconds
        self.coreTransport = ObstacleBridgeXPCShapedTunHelperCommandTransport(
            sendEnvelope: { [weak self] envelope in
                guard let self else { throw ObstacleBridgeLinuxTunHelperAdapterError.disconnected }
                return try self.exchange(kind: "control", envelope: envelope)
            },
            sendPacketEnvelope: { [weak self] envelope in
                guard let self else { throw ObstacleBridgeLinuxTunHelperAdapterError.disconnected }
                return try self.exchange(kind: "packet", envelope: envelope)
            }
        )
    }

    public func send(command: ObstacleBridgeTunHelperCommand, payload: [String: Any]) throws -> [String: Any] {
        lock.lock(); defer { lock.unlock() }
        return try coreTransport.send(command: command, payload: payload)
    }

    public func sendPacketToHelper(_ packet: Data) throws -> [String: Any] {
        lock.lock(); defer { lock.unlock() }
        return try coreTransport.sendPacketToHelper(packet)
    }

    /// Delegates a Core-derived network plan to the explicitly configured
    /// privileged helper. The Linux process never applies routes or DNS itself.
    public func apply(packetTunnelPlan plan: ObstacleBridgeRuntimeConfigPort.PacketTunnelPlan, interfaceName: String) throws -> [String: Any] {
        guard plan.enabledOnStartup else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("disabled packet-tunnel plan cannot be applied")
        }
        return try send(command: .applyNetwork, payload: [
            "action": "up", "argv": [], "env": Self.planEnvironment(plan, interfaceName: interfaceName),
        ])
    }

    /// If an apply reply is lost after helper-side partial work, request the
    /// paired removal on a fresh bounded IPC exchange before surfacing failure.
    public func applyWithRollback(packetTunnelPlan plan: ObstacleBridgeRuntimeConfigPort.PacketTunnelPlan, interfaceName: String) throws -> [String: Any] {
        do {
            return try apply(packetTunnelPlan: plan, interfaceName: interfaceName)
        } catch {
            _ = try? rollback(packetTunnelPlan: plan, interfaceName: interfaceName)
            throw error
        }
    }

    public func rollback(packetTunnelPlan plan: ObstacleBridgeRuntimeConfigPort.PacketTunnelPlan, interfaceName: String) throws -> [String: Any] {
        try send(command: .removeNetwork, payload: [
            "action": "down", "argv": [], "env": Self.planEnvironment(plan, interfaceName: interfaceName),
        ])
    }

    private static func planEnvironment(_ plan: ObstacleBridgeRuntimeConfigPort.PacketTunnelPlan, interfaceName: String) -> [String: String] {
        ["TUN_IFNAME": interfaceName, "TUN_ADDR": "\(plan.tunnelAddress)/\(plan.tunnelPrefix)", "TUN_ADDR6": "\(plan.tunnelAddress6)/\(plan.tunnelPrefix6)", "TUN_MTU": "\(plan.mtu)", "TUN_INCLUDED_ROUTES": plan.includedRoutes.joined(separator: ","), "TUN_EXCLUDED_ROUTES": plan.excludedRoutes.joined(separator: ","), "TUN_INCLUDED_ROUTES6": plan.includedRoutes6.joined(separator: ","), "TUN_EXCLUDED_ROUTES6": plan.excludedRoutes6.joined(separator: ","), "TUN_DNS_SERVERS": plan.dnsServers.joined(separator: ",")]
    }

    private func exchange(kind: String, envelope: [String: Any]) throws -> [String: Any] {
        let request: [String: Any] = ["kind": kind, "envelope": Self.jsonSafe(envelope)]
        let body: Data
        do { body = try JSONSerialization.data(withJSONObject: request, options: [.sortedKeys]) }
        catch { throw ObstacleBridgeLinuxTunHelperAdapterError.malformedReply("unable to encode Linux TUN helper request") }
        guard body.count <= Self.maximumFrameBytes else { throw ObstacleBridgeLinuxTunHelperAdapterError.frameTooLarge }
        let fd = try connectSocket()
        defer { _ = close(fd) }
        try writeFrame(body, to: fd)
        let reply = try readFrame(from: fd)
        guard let raw = try? JSONSerialization.jsonObject(with: reply),
              let dictionary = raw as? [String: Any],
              let response = dictionary["response"] as? [String: Any]
        else { throw ObstacleBridgeLinuxTunHelperAdapterError.malformedReply("Linux TUN helper returned malformed reply") }
        return try Self.restoreData(response)
    }

    private func connectSocket() throws -> Int32 {
        let fd = socket(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0)
        guard fd >= 0 else { throw ObstacleBridgeLinuxTunHelperAdapterError.connectFailed(errno) }
        var timeout = timeval(tv_sec: timeoutMilliseconds / 1000, tv_usec: (timeoutMilliseconds % 1000) * 1_000)
        _ = withUnsafePointer(to: &timeout) { setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, $0, socklen_t(MemoryLayout<timeval>.size)) }
        _ = withUnsafePointer(to: &timeout) { setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, $0, socklen_t(MemoryLayout<timeval>.size)) }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(socketPath.utf8) + [0]
        let capacity = MemoryLayout.size(ofValue: address.sun_path)
        guard bytes.count <= capacity else { _ = close(fd); throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("Linux TUN helper socket path is too long") }
        withUnsafeMutableBytes(of: &address.sun_path) { destination in
            destination.initializeMemory(as: UInt8.self, repeating: 0)
            destination.baseAddress!.assumingMemoryBound(to: UInt8.self).update(from: bytes, count: bytes.count)
        }
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard result == 0 else { let code = errno; _ = close(fd); throw code == EAGAIN || code == EWOULDBLOCK ? ObstacleBridgeLinuxTunHelperAdapterError.timeout : .connectFailed(code) }
        return fd
    }

    private func writeFrame(_ body: Data, to fd: Int32) throws {
        var length = UInt32(body.count).bigEndian
        var wire = Data(bytes: &length, count: MemoryLayout<UInt32>.size)
        wire.append(body)
        try writeAll(wire, to: fd)
    }

    private func readFrame(from fd: Int32) throws -> Data {
        let lengthData = try readExactly(MemoryLayout<UInt32>.size, from: fd)
        let length = lengthData.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        guard length <= UInt32(Self.maximumFrameBytes) else { throw ObstacleBridgeLinuxTunHelperAdapterError.frameTooLarge }
        return try readExactly(Int(length), from: fd)
    }

    private func writeAll(_ data: Data, to fd: Int32) throws {
        var offset = 0
        while offset < data.count {
            let written = data.withUnsafeBytes { write(fd, $0.baseAddress!.advanced(by: offset), data.count - offset) }
            guard written > 0 else {
                if errno == EAGAIN || errno == EWOULDBLOCK { throw ObstacleBridgeLinuxTunHelperAdapterError.timeout }
                throw ObstacleBridgeLinuxTunHelperAdapterError.disconnected
            }
            offset += Int(written)
        }
    }

    private func readExactly(_ count: Int, from fd: Int32) throws -> Data {
        var output = Data(); output.reserveCapacity(count)
        var buffer = [UInt8](repeating: 0, count: min(8192, max(1, count)))
        while output.count < count {
            let received = read(fd, &buffer, min(buffer.count, count - output.count))
            guard received > 0 else {
                if errno == EAGAIN || errno == EWOULDBLOCK { throw ObstacleBridgeLinuxTunHelperAdapterError.timeout }
                throw ObstacleBridgeLinuxTunHelperAdapterError.disconnected
            }
            output.append(buffer, count: Int(received))
        }
        return output
    }

    private static func jsonSafe(_ value: Any) -> Any {
        if let data = value as? Data { return ["__ob_data_base64": data.base64EncodedString()] }
        if let dictionary = value as? [String: Any] { return dictionary.mapValues(jsonSafe) }
        if let array = value as? [Any] { return array.map(jsonSafe) }
        return value
    }

    private static func restoreData(_ value: [String: Any]) throws -> [String: Any] {
        guard let restored = restoreJSON(value) as? [String: Any] else { throw ObstacleBridgeLinuxTunHelperAdapterError.malformedReply("Linux TUN helper response is not an object") }
        return restored
    }

    private static func restoreJSON(_ value: Any) -> Any {
        if let dictionary = value as? [String: Any] {
            if dictionary.count == 1, let encoded = dictionary["__ob_data_base64"] as? String, let data = Data(base64Encoded: encoded) { return data }
            return dictionary.mapValues(restoreJSON)
        }
        if let array = value as? [Any] { return array.map(restoreJSON) }
        return value
    }
}
