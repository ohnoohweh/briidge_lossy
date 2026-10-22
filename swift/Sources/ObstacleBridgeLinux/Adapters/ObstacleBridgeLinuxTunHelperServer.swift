import Foundation
import ObstacleBridgeCore
#if os(Linux)
import Glibc
#endif

/// Backend boundary for the Swift implementation of the local TUN helper.
/// Privileged ownership deliberately lives behind this protocol rather than in
/// the Unix-socket parser.
public protocol ObstacleBridgeLinuxTunHelperServerBackend: AnyObject {
    func setPacketSink(_ sink: @escaping (Data) -> Void)
    func setEventSink(_ sink: @escaping (String) -> Void)
    func openTun(_ payload: [String: Any]) throws -> [String: Any]
    func applyNetwork(_ payload: [String: Any]) throws -> [String: Any]
    func removeNetwork(_ payload: [String: Any]) throws -> [String: Any]
    func setTunEnabled(_ payload: [String: Any]) throws -> [String: Any]
    func writePacket(_ packet: Data) throws
    func snapshot() throws -> [String: Any]
    func recordFailure(stage: String, error: String)
    func stop()
}

public extension ObstacleBridgeLinuxTunHelperServerBackend {
    func setPacketSink(_ sink: @escaping (Data) -> Void) { _ = sink }
    func setEventSink(_ sink: @escaping (String) -> Void) { _ = sink }
    func recordFailure(stage: String, error: String) { _ = (stage, error) }
}

/// Partial Swift replacement for the Python local TUN helper server. It
/// implements the version-1 authenticated control and packet wire boundary,
/// including helper-originated packet and event fan-out. Network-policy
/// lifecycle remains deliberately incomplete, so callers cannot mistake it
/// for full replacement parity yet.
public final class ObstacleBridgeLinuxTunHelperServer: @unchecked Sendable {
    private typealias FrameKind = ObstacleBridgeTunHelperProtocolV1.FrameKind
    private static let version = ObstacleBridgeTunHelperProtocolV1.version
    private static let maximumFrameBytes = ObstacleBridgeLinuxTunHelperAdapter.maximumFrameBytes

    public let socketPath: String
    private let sessionToken: String
    private let authenticatedClientIdleTimeout: TimeInterval
    private let unauthenticatedClientIdleTimeout: TimeInterval
    private let backend: ObstacleBridgeLinuxTunHelperServerBackend
    private let onStop: (() -> Void)?
    private let queue = DispatchQueue(label: "org.obstaclebridge.linux.tun-helper-server", attributes: .concurrent)
    private let lock = NSLock()
    private let writerLock = NSLock()
    private var listener: Int32 = -1
    private var running = false
    private var authenticatedClients: Set<Int32> = []
    private var lastAuthenticatedActivity = Date()
    private var watchdog: DispatchSourceTimer?

    public init(socketPath: String, sessionToken: String, backend: ObstacleBridgeLinuxTunHelperServerBackend, authenticatedClientIdleTimeout: TimeInterval = 5, unauthenticatedClientIdleTimeout: TimeInterval = 5, onStop: (() -> Void)? = nil) throws {
        guard !socketPath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, !sessionToken.isEmpty else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("Linux TUN helper server requires socket path and session token")
        }
        self.socketPath = socketPath
        self.sessionToken = sessionToken
        self.authenticatedClientIdleTimeout = max(authenticatedClientIdleTimeout, 0.5)
        self.unauthenticatedClientIdleTimeout = max(unauthenticatedClientIdleTimeout, 0.1)
        self.backend = backend
        self.onStop = onStop
        backend.setPacketSink { [weak self] packet in self?.emitPacket(packet) }
        backend.setEventSink { [weak self] detail in self?.emitEvent(detail) }
    }

    public func start() throws {
        lock.lock(); defer { lock.unlock() }
        guard !running else { return }
        let fd = socket(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0)
        guard fd >= 0 else { throw ObstacleBridgeLinuxTunHelperAdapterError.connectFailed(errno) }
        var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(socketPath.utf8) + [0]
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { _ = close(fd); throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("Linux TUN helper socket path is too long") }
        _ = unlink(socketPath)
        withUnsafeMutableBytes(of: &address.sun_path) { output in
            output.initializeMemory(as: UInt8.self, repeating: 0)
            output.baseAddress!.assumingMemoryBound(to: UInt8.self).update(from: bytes, count: bytes.count)
        }
        let bound = withUnsafePointer(to: &address) { pointer in pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        guard bound == 0, listen(fd, 16) == 0 else { let code = errno; _ = close(fd); throw ObstacleBridgeLinuxTunHelperAdapterError.connectFailed(code) }
        applySocketOwnership()
        listener = fd; running = true; lastAuthenticatedActivity = Date()
        let watchdog = DispatchSource.makeTimerSource(queue: queue)
        watchdog.schedule(deadline: .now() + authenticatedClientIdleTimeout, repeating: min(authenticatedClientIdleTimeout, 1))
        watchdog.setEventHandler { [weak self] in self?.expireIdleHelperIfNeeded() }
        self.watchdog = watchdog; watchdog.resume()
        queue.async { [weak self] in self?.acceptLoop() }
    }

    public func stop() {
        lock.lock()
        let fd = listener
        listener = -1; running = false
        let watchdog = self.watchdog
        self.watchdog = nil
        lock.unlock()
        watchdog?.cancel()
        if fd >= 0 { _ = shutdown(fd, Int32(SHUT_RDWR)); _ = close(fd) }
        lock.lock(); authenticatedClients.removeAll(); lock.unlock()
        _ = unlink(socketPath)
        backend.stop()
        onStop?()
    }

    private func acceptLoop() {
        while true {
            lock.lock(); let active = running; let fd = listener; lock.unlock()
            guard active, fd >= 0 else { return }
            let client = accept(fd, nil, nil)
            guard client >= 0 else { continue }
            queue.async { [weak self] in self?.handle(client: client) }
        }
    }

    /// Mirrors Python's SUDO_UID/SUDO_GID handoff: a privileged helper keeps
    /// its endpoint private to the invoking user, while a directly launched
    /// helper is owner-only for the current account.
    private func applySocketOwnership() {
        let uid = ProcessInfo.processInfo.environment["SUDO_UID"].flatMap { UInt32($0) }.map { uid_t($0) }
        let gid = ProcessInfo.processInfo.environment["SUDO_GID"].flatMap { UInt32($0) }.map { gid_t($0) }
        if uid != nil || gid != nil { _ = chown(socketPath, uid ?? uid_t.max, gid ?? gid_t.max) }
        _ = chmod(socketPath, uid == nil ? 0o600 : 0o660)
    }

    private func handle(client: Int32) {
        defer { lock.lock(); authenticatedClients.remove(client); lock.unlock(); _ = close(client) }
        var authenticated = false
        while true {
            let timeoutMS = authenticated ? nil : Int32(min(30_000, max(100, unauthenticatedClientIdleTimeout * 1_000)))
            guard let (kind, body) = try? readFrame(from: client, timeoutMS: timeoutMS) else { return }
            switch kind {
            case .controlRequest:
                guard let message = decodeControl(body) else { try? sendError("bad_control_payload", "invalid protocol-v1 control message", to: client); continue }
                let operation = message.operation.uppercased()
                if operation == "HELLO" {
                    guard message.payload["token"] as? String == sessionToken else { try? sendError("auth_failed", "invalid session token", to: client); continue }
                    authenticated = true
                    lock.lock(); authenticatedClients.insert(client); lastAuthenticatedActivity = Date(); lock.unlock()
                    try? sendControl("HELLO_OK", ["authenticated": true], to: client)
                    continue
                }
                guard authenticated else { try? sendError("not_authenticated", "HELLO required before helper commands", to: client); continue }
                markAuthenticatedActivity()
                handleControl(operation: operation, payload: message.payload, client: client)
            case .packetToHelper:
                guard authenticated else { try? sendError("not_authenticated", "HELLO required before helper packet writes", to: client); continue }
                markAuthenticatedActivity()
                do { try backend.writePacket(body) } catch { try? sendError("write_packet_failed", error.localizedDescription, to: client) }
            default:
                try? sendError("unexpected_frame_kind", "\(kind.rawValue)", to: client)
            }
        }
    }

    private func handleControl(operation: String, payload: [String: Any], client: Int32) {
        do {
            let reply: [String: Any]
            switch operation {
            case "OPEN_TUN": reply = try backend.openTun(payload)
            case "APPLY_NETWORK": reply = try backend.applyNetwork(payload)
            case "REMOVE_NETWORK": reply = try backend.removeNetwork(payload)
            case "SET_TUN_ENABLED": reply = try backend.setTunEnabled(payload)
            case "SNAPSHOT": reply = try backend.snapshot()
            case "STOP":
                try sendControl("STOP_OK", ["stopping": true], to: client)
                emitEvent("helper stopping")
                // Match the Python server: acknowledge first, then stop on a
                // separate task so the client can receive STOP_OK.
                queue.async { [weak self] in self?.stop() }
                return
            default: try sendError("unsupported_op", operation, to: client); return
            }
            try sendControl("\(operation)_OK", reply, to: client)
        } catch {
            backend.recordFailure(stage: operation.lowercased(), error: error.localizedDescription)
            try? sendError("\(operation.lowercased())_failed", error.localizedDescription, to: client)
        }
    }
    private func markAuthenticatedActivity() { lock.lock(); lastAuthenticatedActivity = Date(); lock.unlock() }
    private func expireIdleHelperIfNeeded() {
        lock.lock()
        let expired = running && authenticatedClients.isEmpty && Date().timeIntervalSince(lastAuthenticatedActivity) >= authenticatedClientIdleTimeout
        lock.unlock()
        if expired { emitEvent("helper authenticated-client idle timeout"); stop() }
    }

    private func decodeControl(_ body: Data) -> (operation: String, payload: [String: Any])? {
        try? ObstacleBridgeTunHelperProtocolV1.decodeControl(body)
    }
    private func sendError(_ code: String, _ detail: String, to fd: Int32) throws { try sendControl("ERROR", ["code": code, "detail": detail], to: fd) }
    private func sendControl(_ operation: String, _ payload: [String: Any], to fd: Int32) throws {
        let body = try ObstacleBridgeTunHelperProtocolV1.control(operation: operation, payload: payload)
        try writeFrame(kind: .controlResponse, body: body, to: fd)
    }
    /// Packet and event producers use this fan-out path; only clients that
    /// completed HELLO receive helper-originated traffic.
    public func emitPacket(_ packet: Data) {
        lock.lock(); let clients = authenticatedClients; lock.unlock()
        for client in clients { try? writeFrame(kind: .packetFromHelper, body: packet, to: client) }
    }
    /// Emits the same compact JSON EVENT shape as the Python helper. Event
    /// delivery is best-effort and only reaches authenticated local clients.
    public func emitEvent(_ detail: String) {
        guard let body = try? JSONSerialization.data(withJSONObject: ["detail": detail], options: [.sortedKeys]) else { return }
        lock.lock(); let clients = authenticatedClients; lock.unlock()
        for client in clients { try? writeFrame(kind: .event, body: body, to: client) }
    }
    private func writeFrame(kind: FrameKind, body: Data, to fd: Int32) throws {
        let frame: Data
        do { frame = try ObstacleBridgeTunHelperProtocolV1.frame(kind: kind, body: body) }
        catch ObstacleBridgeTunHelperProtocolV1.Error.frameTooLarge { throw ObstacleBridgeLinuxTunHelperAdapterError.frameTooLarge }
        writerLock.lock(); defer { writerLock.unlock() }
        var offset = 0
        while offset < frame.count {
            let count = frame.withUnsafeBytes {
                #if os(Linux)
                send(fd, $0.baseAddress!.advanced(by: offset), frame.count - offset, Int32(MSG_NOSIGNAL))
                #else
                write(fd, $0.baseAddress!.advanced(by: offset), frame.count - offset)
                #endif
            }
            guard count > 0 else { throw ObstacleBridgeLinuxTunHelperAdapterError.disconnected }
            offset += Int(count)
        }
    }
    private func readFrame(from fd: Int32, timeoutMS: Int32? = nil) throws -> (FrameKind, Data) {
        if let timeoutMS {
            var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            guard poll(&descriptor, 1, timeoutMS) > 0, descriptor.revents & Int16(POLLIN) != 0 else {
                throw ObstacleBridgeLinuxTunHelperAdapterError.disconnected
            }
        }
        let wireHeader = try readExactly(ObstacleBridgeTunHelperProtocolV1.headerBytes, from: fd)
        let parsed: (kind: FrameKind, bodyLength: Int)
        do { parsed = try ObstacleBridgeTunHelperProtocolV1.header(wireHeader) }
        catch ObstacleBridgeTunHelperProtocolV1.Error.frameTooLarge { throw ObstacleBridgeLinuxTunHelperAdapterError.frameTooLarge }
        catch { throw ObstacleBridgeLinuxTunHelperAdapterError.malformedReply("unknown frame kind") }
        return (parsed.kind, try readExactly(parsed.bodyLength, from: fd))
    }
    private func readExactly(_ count: Int, from fd: Int32) throws -> Data {
        var result = Data(); var buffer = [UInt8](repeating: 0, count: min(8192, max(1, count)))
        while result.count < count { let received = read(fd, &buffer, min(buffer.count, count - result.count)); guard received > 0 else { throw ObstacleBridgeLinuxTunHelperAdapterError.disconnected }; result.append(buffer, count: Int(received)) }
        return result
    }
}
