import Foundation
import ObstacleBridgeCore
import ObstacleBridgeDesktopShared
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
/// implements the common OBIP authenticated control and packet wire boundary,
/// including helper-originated packet and event fan-out. Network-policy
/// lifecycle remains deliberately incomplete, so callers cannot mistake it
/// for full replacement parity yet.
public final class ObstacleBridgeLinuxTunHelperServer: @unchecked Sendable {
    private typealias FrameKind = ObstacleBridgeWorkerIPC.Kind
    private static let helperCapabilities: Set<String> = ["tun.control", "tun.packet", "tun.event"]
    private static let maximumFrameBytes = ObstacleBridgeLinuxTunHelperAdapter.maximumFrameBytes

    public let socketPath: String
    private let sessionToken: String
    private let authenticatedClientIdleTimeout: TimeInterval
    private let unauthenticatedClientIdleTimeout: TimeInterval
    private let backend: ObstacleBridgeLinuxTunHelperServerBackend
    private let onStop: (() -> Void)?
    // OBSTACLEBRIDGE-CONCURRENCY: serial; test=ObstacleBridgeLinuxTunHelperAdapterTests
    // One callback owner serializes connection framing and state transitions.
    private let queue = DispatchQueue(label: "org.obstaclebridge.linux.tun-helper-server")
    private let watchdogQueue = DispatchQueue(label: "org.obstaclebridge.linux.tun-helper-server.watchdog")
    private let lock = NSLock()
    private let writerLock = NSLock()
    private var listener: Int32 = -1
    private var listenerSource: DispatchSourceRead?
    private var clientSources: [Int32: DispatchSourceRead] = [:]
    private var running = false
    private var authenticatedClients: Set<Int32> = []
    private var clientGenerations: [Int32: UInt64] = [:]
    private var hasAuthenticatedClient = false
    private var lastAuthenticatedActivityNanoseconds = DispatchTime.now().uptimeNanoseconds
    private var watchdog: DispatchSourceTimer?

    public init(socketPath: String, sessionToken: String, backend: ObstacleBridgeLinuxTunHelperServerBackend, authenticatedClientIdleTimeout: TimeInterval = 5, unauthenticatedClientIdleTimeout: TimeInterval = 5, onStop: (() -> Void)? = nil) throws {
        guard !socketPath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, !sessionToken.isEmpty else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("Linux TUN helper server requires socket path and session token")
        }
        self.socketPath = socketPath
        self.sessionToken = sessionToken
        // Zero explicitly disables expiry for a foreground-managed helper.
        self.authenticatedClientIdleTimeout = max(authenticatedClientIdleTimeout, 0)
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
        try setNonblocking(fd)
        listener = fd; running = true; hasAuthenticatedClient = false
        lastAuthenticatedActivityNanoseconds = DispatchTime.now().uptimeNanoseconds
        if authenticatedClientIdleTimeout > 0 {
            let watchdogInterval = min(authenticatedClientIdleTimeout, unauthenticatedClientIdleTimeout, 1)
            let watchdog = DispatchSource.makeTimerSource(queue: watchdogQueue)
            watchdog.schedule(deadline: .now() + watchdogInterval, repeating: watchdogInterval)
            watchdog.setEventHandler { [weak self] in self?.expireIdleHelperIfNeeded() }
            self.watchdog = watchdog; watchdog.resume()
        }
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        source.setEventHandler { [weak self] in self?.acceptReadyClients() }
        source.setCancelHandler { _ = close(fd) }
        listenerSource = source
        source.resume()
    }

    public func stop() {
        lock.lock()
        let fd = listener
        listener = -1; running = false
        let watchdog = self.watchdog
        self.watchdog = nil
        let listenerSource = self.listenerSource
        self.listenerSource = nil
        let clientSources = Array(self.clientSources.values)
        self.clientSources.removeAll()
        self.clientStates.removeAll()
        lock.unlock()
        watchdog?.cancel()
        if fd >= 0 { _ = shutdown(fd, Int32(SHUT_RDWR)) }
        listenerSource?.cancel()
        clientSources.forEach { $0.cancel() }
        lock.lock(); authenticatedClients.removeAll(); clientGenerations.removeAll(); lock.unlock()
        _ = unlink(socketPath)
        backend.stop()
        onStop?()
    }

    private func acceptReadyClients() {
        while true {
            lock.lock(); let active = running; let fd = listener; lock.unlock()
            guard active, fd >= 0 else { return }
            let client = accept(fd, nil, nil)
            guard client >= 0 else {
                if errno == EAGAIN || errno == EWOULDBLOCK { return }
                return
            }
            do { try setNonblocking(client) }
            catch { _ = close(client); continue }
            register(client: client)
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

    private final class ClientState {
        let fd: Int32
        var decoder = ObstacleBridgeWorkerIPCStreamDecoder()
        var authenticated = false
        var generation: UInt64 = 0
        init(fd: Int32) { self.fd = fd }
    }

    private var clientStates: [Int32: ClientState] = [:]

    private func register(client: Int32) {
        let state = ClientState(fd: client)
        let source = DispatchSource.makeReadSource(fileDescriptor: client, queue: queue)
        source.setEventHandler { [weak self, weak state] in
            guard let self, let state else { return }
            self.receiveReadyBytes(state)
        }
        source.setCancelHandler { _ = close(client) }
        lock.lock(); clientStates[client] = state; clientSources[client] = source; lock.unlock()
        source.resume()
    }

    private func receiveReadyBytes(_ state: ClientState) {
        var buffer = [UInt8](repeating: 0, count: 8192)
        while true {
            // MSG_DONTWAIT keeps a stale readiness notification harmless even
            // if another owner changes the descriptor's status flags.
            let received = recv(state.fd, &buffer, buffer.count, Int32(MSG_DONTWAIT))
            if received > 0 {
                do {
                    for frame in try state.decoder.append(Data(buffer[0..<Int(received)])) {
                        try handle(frame: frame, state: state)
                    }
                } catch { closeClient(state.fd); return }
                continue
            }
            if received == 0 { closeClient(state.fd); return }
            if errno == EAGAIN || errno == EWOULDBLOCK { return }
            closeClient(state.fd); return
        }
    }

    private func handle(frame: ObstacleBridgeWorkerIPC.Frame, state: ClientState) throws {
        let client = state.fd
        if state.generation == 0 {
                guard frame.kind == .hello,
                      let negotiated = try? ObstacleBridgeWorkerIPC.negotiatedCapabilities(frame, supported: Self.helperCapabilities),
                      negotiated.role == "tun-helper-client", Set(negotiated.capabilities) == Self.helperCapabilities else { throw ObstacleBridgeWorkerIPC.Failure.invalidFrame }
                state.generation = frame.generation
                lock.lock(); clientGenerations[client] = state.generation; lock.unlock()
                do {
                    try writeAll(try ObstacleBridgeWorkerIPC.hello(generation: state.generation, role: "tun-helper", capabilities: Array(Self.helperCapabilities)), to: client)
                    try sendControl("READY", ["capabilities": Self.helperCapabilities.sorted()], kind: .ready, generation: state.generation, to: client)
                } catch { throw error }
                return
        }
        guard frame.generation == state.generation else { throw ObstacleBridgeWorkerIPC.Failure.invalidFrame }
        switch frame.kind {
            case .request:
                guard let message = decodeControl(frame) else { try? sendError("bad_control_payload", "invalid common IPC control message", generation: state.generation, to: client); return }
                let operation = message.operation.uppercased()
                if operation == "HELLO" {
                    guard !state.authenticated else { try? sendError("already_authenticated", "HELLO is accepted only once", generation: state.generation, to: client); return }
                    guard message.payload["token"] as? String == sessionToken else { try? sendError("auth_failed", "invalid session token", generation: state.generation, to: client); return }
                    state.authenticated = true
                    lock.lock(); authenticatedClients.insert(client); hasAuthenticatedClient = true; lastAuthenticatedActivityNanoseconds = DispatchTime.now().uptimeNanoseconds; lock.unlock()
                    try? sendControl("HELLO_OK", ["authenticated": true], generation: state.generation, to: client)
                    return
                }
                guard state.authenticated else { try? sendError("not_authenticated", "HELLO required before helper commands", generation: state.generation, to: client); return }
                markAuthenticatedActivity()
                handleControl(operation: operation, payload: message.payload, generation: state.generation, client: client)
            case .data:
                guard state.authenticated else { try? sendError("not_authenticated", "HELLO required before helper packet writes", generation: state.generation, to: client); return }
                markAuthenticatedActivity()
                do { try backend.writePacket(frame.payload) } catch { try? sendError("write_packet_failed", error.localizedDescription, generation: state.generation, to: client) }
            default:
                try? sendError("unexpected_frame_kind", "\(frame.kind.rawValue)", generation: state.generation, to: client)
        }
    }

    private func closeClient(_ fd: Int32) {
        lock.lock()
        authenticatedClients.remove(fd)
        clientGenerations.removeValue(forKey: fd)
        clientStates.removeValue(forKey: fd)
        let source = clientSources.removeValue(forKey: fd)
        lock.unlock()
        _ = shutdown(fd, Int32(SHUT_RDWR))
        source?.cancel()
    }

    private func setNonblocking(_ fd: Int32) throws {
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.connectFailed(errno)
        }
    }

    private func handleControl(operation: String, payload: [String: Any], generation: UInt64, client: Int32) {
        do {
            let reply: [String: Any]
            switch operation {
            case "OPEN_TUN": reply = try backend.openTun(payload)
            case "APPLY_NETWORK": reply = try backend.applyNetwork(payload)
            case "REMOVE_NETWORK": reply = try backend.removeNetwork(payload)
            case "SET_TUN_ENABLED": reply = try backend.setTunEnabled(payload)
            case "SNAPSHOT": reply = try backend.snapshot()
            case "STOP":
                try sendControl("STOP_OK", ["stopping": true], generation: generation, to: client)
                emitEvent("helper stopping")
                // Match the Python server: acknowledge first, then stop on a
                // separate task so the client can receive STOP_OK.
                queue.async { [weak self] in self?.stop() }
                return
            default: try sendError("unsupported_op", operation, generation: generation, to: client); return
            }
            try sendControl("\(operation)_OK", reply, generation: generation, to: client)
        } catch {
            backend.recordFailure(stage: operation.lowercased(), error: error.localizedDescription)
            try? sendError("\(operation.lowercased())_failed", error.localizedDescription, generation: generation, to: client)
        }
    }
    private func markAuthenticatedActivity() {
        lock.lock(); lastAuthenticatedActivityNanoseconds = DispatchTime.now().uptimeNanoseconds; lock.unlock()
    }
    private func expireIdleHelperIfNeeded() {
        guard authenticatedClientIdleTimeout > 0 else { return }
        lock.lock()
        let idleTimeout = hasAuthenticatedClient ? authenticatedClientIdleTimeout : unauthenticatedClientIdleTimeout
        let timeoutNanoseconds = UInt64(idleTimeout * 1_000_000_000)
        let elapsedNanoseconds = DispatchTime.now().uptimeNanoseconds &- lastAuthenticatedActivityNanoseconds
        let expired = running && authenticatedClients.isEmpty && elapsedNanoseconds >= timeoutNanoseconds
        lock.unlock()
        if expired { emitEvent("helper authenticated-client idle timeout"); stop() }
    }

    private func decodeControl(_ frame: ObstacleBridgeWorkerIPC.Frame) -> (operation: String, payload: [String: Any])? {
        guard let value = try? ObstacleBridgeWorkerIPC.decodeControl(frame),
              let operation = value["op"] as? String, !operation.isEmpty, operation.count <= 64,
              let payload = value["payload"] as? [String: Any] else { return nil }
        return (operation, payload)
    }
    private func sendError(_ code: String, _ detail: String, generation: UInt64, to fd: Int32) throws { try sendControl("ERROR", ["code": code, "detail": detail], generation: generation, to: fd) }
    private func sendControl(_ operation: String, _ payload: [String: Any], kind: FrameKind = .response, generation: UInt64, to fd: Int32) throws {
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: kind, generation: generation, value: ["op": operation, "payload": payload]), to: fd)
    }
    /// Packet and event producers use this fan-out path; only clients that
    /// completed HELLO receive helper-originated traffic.
    public func emitPacket(_ packet: Data) {
        lock.lock(); let clients = authenticatedClients; let generations = clientGenerations; lock.unlock()
        for client in clients { if let generation = generations[client] { try? writeFrame(kind: .data, generation: generation, body: packet, to: client) } }
    }
    /// Emits the same compact JSON EVENT shape as the Python helper. Event
    /// delivery is best-effort and only reaches authenticated local clients.
    public func emitEvent(_ detail: String) {
        lock.lock(); let clients = authenticatedClients; let generations = clientGenerations; lock.unlock()
        for client in clients { if let generation = generations[client] { try? sendControl("EVENT", ["detail": detail], kind: .event, generation: generation, to: client) } }
    }
    private func writeFrame(kind: FrameKind, generation: UInt64, body: Data, to fd: Int32) throws {
        let frame: Data
        do { frame = try ObstacleBridgeWorkerIPC.encode(kind: kind, generation: generation, payload: body) }
        catch ObstacleBridgeWorkerIPC.Failure.frameTooLarge { throw ObstacleBridgeLinuxTunHelperAdapterError.frameTooLarge }
        try writeAll(frame, to: fd)
    }
    private func writeAll(_ frame: Data, to fd: Int32) throws {
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
}
