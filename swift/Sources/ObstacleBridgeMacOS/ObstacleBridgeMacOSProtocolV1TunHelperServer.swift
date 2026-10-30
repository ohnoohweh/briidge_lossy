import Foundation

#if os(macOS)
import Darwin

/// macOS Unix-socket resource owner for the shared authenticated OBIP helper ABI.
/// The historical filename is retained for packaged-helper compatibility; it no
/// longer accepts the protocol-v1 five-byte wire header.
final class ObstacleBridgeMacOSProtocolV1TunHelperServer {
    private static let capabilities: Set<String> = ["tun.control", "tun.packet", "tun.event"]
    private let socketPath: String; private let token: String
    private let idleTimeout: TimeInterval
    private let backend: ObstacleBridgeInProcessMacOSTunHelperClient
    private let queue = DispatchQueue(label: "org.obstaclebridge.macos.tun-helper-ipc")
    private let lock = NSLock()
    private let writerLock = NSLock()
    private var listener: Int32 = -1
    // OBSTACLEBRIDGE-CONCURRENCY: serial; test=test_macos_tun_helper_package_skeleton_sources_exist
    private var clientSources: [Int32: DispatchSourceRead] = [:]
    private var clientStates: [Int32: ClientState] = [:]
    private var authenticatedClients: Set<Int32> = []
    private var clientGenerations: [Int32: UInt64] = [:]
    private var lastAuthenticatedActivity = Date()
    private var watchdog: DispatchSourceTimer?

    init(socketPath: String, token: String, idleTimeout: TimeInterval = 5) throws {
        guard !socketPath.isEmpty, !token.isEmpty else { throw ObstacleBridgeWorkerIPC.Failure.invalidControl }
        self.socketPath = socketPath; self.token = token; self.idleTimeout = max(idleTimeout, 0.5)
        self.backend = ObstacleBridgeInProcessMacOSTunHelperClient(queue: queue, packetSink: { _ in })
        backend.setPacketSink { [weak self] packet in self?.emitPacket(packet) }
        backend.setEventSink { [weak self] event, payload in self?.emitEvent(event: event, payload: payload) }
    }

    func run() throws {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0); guard fd >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        defer {
            lock.lock()
            listener = -1; clientGenerations.removeAll()
            let sources = Array(clientSources.values)
            clientSources.removeAll(); clientStates.removeAll()
            let watchdog = self.watchdog; self.watchdog = nil
            lock.unlock()
            sources.forEach { $0.cancel() }
            watchdog?.cancel(); _ = close(fd); _ = unlink(socketPath); backend.stop()
        }
        var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX)
        guard let path = obstacleBridgeUnixSocketPathBytes(socketPath, capacity: MemoryLayout.size(ofValue: address.sun_path)) else { throw ObstacleBridgeWorkerIPC.Failure.invalidFrame }
        _ = unlink(socketPath)
        withUnsafeMutableBytes(of: &address.sun_path) { bytes in
            let destination = bytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
            destination.initialize(repeating: 0, count: bytes.count)
            destination.update(from: path, count: path.count)
        }
        let bound = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        guard bound == 0, listen(fd, 16) == 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        _ = chmod(socketPath, 0o600)
        try setNonblocking(fd)
        lock.lock(); listener = fd; lastAuthenticatedActivity = Date(); lock.unlock()
        let watchdog = DispatchSource.makeTimerSource(queue: queue)
        watchdog.schedule(deadline: .now() + idleTimeout, repeating: min(idleTimeout, 1))
        watchdog.setEventHandler { [weak self] in self?.expireIfIdle() }
        self.watchdog = watchdog; watchdog.resume()
        while true {
            lock.lock(); let active = listener == fd; lock.unlock()
            guard active else { return }
            var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            guard poll(&descriptor, 1, ObstacleBridgeMacOSTunHelperService.ownerLossAcceptPollMilliseconds) >= 0 else { throw ObstacleBridgeWorkerIPC.Failure.invalidFrame }
            guard descriptor.revents & Int16(POLLIN) != 0 else { continue }
            let client = accept(fd, nil, nil)
            if client >= 0 {
                if (try? setNonblocking(client)) != nil { register(client) }
                else { _ = close(client) }
            }
        }
    }

    private final class ClientState {
        let fd: Int32
        var decoder = ObstacleBridgeWorkerIPCStreamDecoder()
        var authenticated = false
        var generation: UInt64 = 0
        init(fd: Int32) { self.fd = fd }
    }

    private func register(_ fd: Int32) {
        let state = ClientState(fd: fd)
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        source.setEventHandler { [weak self, weak state] in
            guard let self, let state else { return }
            self.receiveReadyBytes(state)
        }
        source.setCancelHandler { _ = close(fd) }
        lock.lock(); clientStates[fd] = state; clientSources[fd] = source; lock.unlock()
        source.resume()
    }

    private func receiveReadyBytes(_ state: ClientState) {
        var buffer = [UInt8](repeating: 0, count: 8192)
        while true {
            let count = recv(state.fd, &buffer, buffer.count, MSG_DONTWAIT)
            if count > 0 {
                do {
                    for frame in try state.decoder.append(Data(buffer[0..<Int(count)])) {
                        try handle(frame, state: state)
                    }
                } catch { closeClient(state.fd); return }
                continue
            }
            if count == 0 { closeClient(state.fd); return }
            if errno == EAGAIN || errno == EWOULDBLOCK { return }
            closeClient(state.fd); return
        }
    }

    private func handle(_ frame: ObstacleBridgeWorkerIPC.Frame, state: ClientState) throws {
        let fd = state.fd
        if state.generation == 0 {
                guard frame.kind == .hello,
                      let negotiated = try? ObstacleBridgeWorkerIPC.negotiatedCapabilities(frame, supported: Self.capabilities),
                      negotiated.role == "tun-helper-client", Set(negotiated.capabilities) == Self.capabilities else { throw ObstacleBridgeWorkerIPC.Failure.invalidFrame }
                state.generation = frame.generation
                lock.lock(); clientGenerations[fd] = state.generation; lock.unlock()
                do {
                    try writeAll(ObstacleBridgeWorkerIPC.hello(generation: state.generation, role: "tun-helper", capabilities: Array(Self.capabilities)), fd)
                    try send("READY", ["capabilities": Self.capabilities.sorted()], kind: .ready, generation: state.generation, fd)
                } catch { throw error }
                return
        }
        guard frame.generation == state.generation else { throw ObstacleBridgeWorkerIPC.Failure.invalidFrame }
        if frame.kind == .data, state.authenticated { try? backend.writePacket(frame.payload); return }
        guard frame.kind == .request, let control = decodeControl(frame) else { throw ObstacleBridgeWorkerIPC.Failure.invalidFrame }
            if control.operation == "HELLO" {
                guard !state.authenticated else { try? send("ERROR", ["detail": "HELLO is accepted only once"], generation: state.generation, fd); return }
                guard control.payload["token"] as? String == token else { try? send("ERROR", ["detail": "invalid session token"], generation: state.generation, fd); return }
                state.authenticated = true
                lock.lock(); authenticatedClients.insert(fd); lastAuthenticatedActivity = Date(); lock.unlock()
                try? send("HELLO_OK", ["authenticated": true], generation: state.generation, fd)
                return
            }
            guard state.authenticated else { try? send("ERROR", ["detail": "HELLO required"], generation: state.generation, fd); return }
            do {
                let reply: [String: Any]
                switch control.operation {
                case "OPEN_TUN": reply = try backend.openTun(.init(requestedIfname: control.payload["ifname"] as? String ?? "", mtu: control.payload["mtu"] as? Int ?? 1500))
                case "APPLY_NETWORK": reply = try backend.applyPythonNetwork(control.payload, removing: false)
                case "REMOVE_NETWORK": reply = try backend.applyPythonNetwork(control.payload, removing: true)
                case "SNAPSHOT": reply = backend.runtimeSnapshot.payload()
                case "STOP": try? send("STOP_OK", ["stopping": true], generation: state.generation, fd); backend.stop(); closeClient(fd); return
                default: throw ObstacleBridgeWorkerIPC.Failure.invalidControl
                }
                try send("\(control.operation)_OK", reply, generation: state.generation, fd)
            } catch { try? send("ERROR", ["detail": error.localizedDescription], generation: state.generation, fd) }
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
            throw ObstacleBridgeWorkerIPC.Failure.invalidFrame
        }
    }

    private func expireIfIdle() {
        lock.lock()
        let expired = authenticatedClients.isEmpty && Date().timeIntervalSince(lastAuthenticatedActivity) >= idleTimeout
        let fd = expired ? listener : -1
        if expired { listener = -1 }
        lock.unlock()
        if fd >= 0 { _ = shutdown(fd, Int32(SHUT_RDWR)) }
    }

    private func emitPacket(_ packet: Data) {
        lock.lock(); let clients = authenticatedClients; let generations = clientGenerations; lock.unlock()
        for client in clients { if let generation = generations[client] { try? writeFrame(kind: .data, generation: generation, body: packet, fd: client) } }
    }
    private func emitEvent(event: String, payload: [String: Any]) {
        let detail = payload.isEmpty ? event : "\(event): \(payload)"
        lock.lock(); let clients = authenticatedClients; let generations = clientGenerations; lock.unlock()
        for client in clients { if let generation = generations[client] { try? send("EVENT", ["detail": detail], kind: .event, generation: generation, client) } }
    }
    private func decodeControl(_ frame: ObstacleBridgeWorkerIPC.Frame) -> (operation: String, payload: [String: Any])? {
        guard let value = try? ObstacleBridgeWorkerIPC.decodeControl(frame),
              let operation = value["op"] as? String, !operation.isEmpty, operation.count <= 64,
              let payload = value["payload"] as? [String: Any] else { return nil }
        return (operation, payload)
    }
    private func send(_ op: String, _ payload: [String: Any], kind: ObstacleBridgeWorkerIPC.Kind = .response, generation: UInt64, _ fd: Int32) throws { try writeAll(ObstacleBridgeWorkerIPC.encodeControl(kind: kind, generation: generation, value: ["op": op, "payload": payload]), fd) }
    private func writeFrame(kind: ObstacleBridgeWorkerIPC.Kind, generation: UInt64, body: Data, fd: Int32) throws { try writeAll(ObstacleBridgeWorkerIPC.encode(kind: kind, generation: generation, payload: body), fd) }
    private func writeAll(_ data: Data, _ fd: Int32) throws {
        writerLock.lock(); defer { writerLock.unlock() }
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { write(fd, $0.baseAddress!.advanced(by: offset), data.count-offset) }
            guard count > 0 else { throw ObstacleBridgeWorkerIPC.Failure.invalidFrame }
            offset += count
        }
    }
}
#endif
