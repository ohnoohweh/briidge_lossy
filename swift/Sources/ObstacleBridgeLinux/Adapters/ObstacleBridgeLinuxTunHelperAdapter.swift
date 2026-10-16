import Foundation
import ObstacleBridgeCore
#if os(Linux)
import Glibc
#endif

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

/// Unix-domain-socket client for the Python helper protocol v1. Every bounded
/// exchange authenticates with HELLO before issuing one control operation.
/// This deliberately matches `bridge_tun_helper_protocol.py`; it is not the
/// XPC-shaped Core helper envelope, which is a separate in-process contract.
public final class ObstacleBridgeLinuxTunHelperAdapter: @unchecked Sendable {
    public static let maximumFrameBytes = 1_048_576
    private static let protocolVersion = 1
    private enum FrameKind: UInt8 { case controlRequest = 1, controlResponse = 2, packetFromHelper = 3, packetToHelper = 4, event = 5 }

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
        try authenticate(on: fd)
        try writeFrame(kind: .packetToHelper, body: packet, to: fd)
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
        try authenticate(on: fd)
        try writeControl(operation: operation, payload: payload, to: fd)
        return try readControlResponse(expectedOperation: "\(operation)_OK", from: fd)
    }

    private func authenticate(on fd: Int32) throws {
        try writeControl(operation: "HELLO", payload: ["token": sessionToken], to: fd)
        _ = try readControlResponse(expectedOperation: "HELLO_OK", from: fd)
    }

    private func writeControl(operation: String, payload: [String: Any], to fd: Int32) throws {
        let request: [String: Any] = ["version": Self.protocolVersion, "op": operation, "payload": payload]
        let body: Data
        do { body = try JSONSerialization.data(withJSONObject: request, options: [.sortedKeys]) }
        catch { throw ObstacleBridgeLinuxTunHelperAdapterError.malformedReply("unable to encode Linux TUN helper request") }
        try writeFrame(kind: .controlRequest, body: body, to: fd)
    }

    private func readControlResponse(expectedOperation: String, from fd: Int32) throws -> [String: Any] {
        let (kind, body) = try readFrame(from: fd)
        guard kind == .controlResponse,
              let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              object["version"] as? Int == Self.protocolVersion,
              let operation = object["op"] as? String,
              let payload = object["payload"] as? [String: Any]
        else { throw ObstacleBridgeLinuxTunHelperAdapterError.malformedReply("Linux TUN helper returned malformed protocol-v1 response") }
        if operation == "ERROR" {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("Linux TUN helper rejected \(expectedOperation): \(payload["detail"] as? String ?? "unspecified error")")
        }
        guard operation == expectedOperation else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.malformedReply("Linux TUN helper returned \(operation), expected \(expectedOperation)")
        }
        return payload.merging(["ok": true, "op": expectedOperation]) { _, response in response }
    }

    private func connectSocket() throws -> Int32 {
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

    private func writeFrame(kind: FrameKind, body: Data, to fd: Int32) throws {
        guard body.count <= Self.maximumFrameBytes else { throw ObstacleBridgeLinuxTunHelperAdapterError.frameTooLarge }
        var length = UInt32(body.count).bigEndian
        var wire = Data([kind.rawValue]); wire.append(Data(bytes: &length, count: MemoryLayout<UInt32>.size)); wire.append(body)
        try writeAll(wire, to: fd)
    }

    private func readFrame(from fd: Int32) throws -> (FrameKind, Data) {
        let header = try readExactly(5, from: fd)
        guard let kind = FrameKind(rawValue: header[header.startIndex]) else { throw ObstacleBridgeLinuxTunHelperAdapterError.malformedReply("Linux TUN helper returned unknown frame kind") }
        let length = header.dropFirst().reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard length <= UInt32(Self.maximumFrameBytes) else { throw ObstacleBridgeLinuxTunHelperAdapterError.frameTooLarge }
        return (kind, try readExactly(Int(length), from: fd))
    }

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
        while output.count < count {
            let received = read(fd, &buffer, min(buffer.count, count - output.count))
            guard received > 0 else { if errno == EAGAIN || errno == EWOULDBLOCK { throw ObstacleBridgeLinuxTunHelperAdapterError.timeout }; throw ObstacleBridgeLinuxTunHelperAdapterError.disconnected }
            output.append(buffer, count: Int(received))
        }
        return output
    }
}
