import Foundation

#if os(macOS)
import Darwin

/// macOS Unix-socket resource owner for the Python-compatible helper ABI.
final class ObstacleBridgeMacOSProtocolV1TunHelperServer {
    private let socketPath: String; private let token: String
    private let idleTimeout: TimeInterval
    private let backend: ObstacleBridgeInProcessMacOSTunHelperClient
    private let queue = DispatchQueue(label: "org.obstaclebridge.macos.tun-helper-v1", attributes: .concurrent)
    private let lock = NSLock()
    private let writerLock = NSLock()
    private var listener: Int32 = -1
    private var authenticatedClients: Set<Int32> = []
    private var lastAuthenticatedActivity = Date()
    private var watchdog: DispatchSourceTimer?

    init(socketPath: String, token: String, idleTimeout: TimeInterval = 5) throws {
        guard !socketPath.isEmpty, !token.isEmpty else { throw ObstacleBridgeTunHelperProtocolV1.Error.malformedControl }
        self.socketPath = socketPath; self.token = token; self.idleTimeout = max(idleTimeout, 0.5)
        self.backend = ObstacleBridgeInProcessMacOSTunHelperClient(queue: queue, packetSink: { _ in })
        backend.setPacketSink { [weak self] packet in self?.emitPacket(packet) }
        backend.setEventSink { [weak self] event, payload in self?.emitEvent(event: event, payload: payload) }
    }

    func run() throws {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0); guard fd >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        defer { lock.lock(); listener = -1; let watchdog = self.watchdog; self.watchdog = nil; lock.unlock(); watchdog?.cancel(); _ = close(fd); _ = unlink(socketPath); backend.stop() }
        var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX)
        let path = Array(socketPath.utf8) + [0]
        guard path.count <= MemoryLayout.size(ofValue: address.sun_path) else { throw ObstacleBridgeTunHelperProtocolV1.Error.malformedFrame }
        _ = unlink(socketPath)
        withUnsafeMutableBytes(of: &address.sun_path) { $0.baseAddress!.assumingMemoryBound(to: UInt8.self).initialize(repeating: 0); $0.baseAddress!.assumingMemoryBound(to: UInt8.self).update(from: path, count: path.count) }
        let bound = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        guard bound == 0, listen(fd, 16) == 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        _ = chmod(socketPath, 0o600)
        lock.lock(); listener = fd; lastAuthenticatedActivity = Date(); lock.unlock()
        let watchdog = DispatchSource.makeTimerSource(queue: queue)
        watchdog.schedule(deadline: .now() + idleTimeout, repeating: min(idleTimeout, 1))
        watchdog.setEventHandler { [weak self] in self?.expireIfIdle() }
        self.watchdog = watchdog; watchdog.resume()
        while true {
            lock.lock(); let active = listener == fd; lock.unlock()
            guard active else { return }
            let client = accept(fd, nil, nil)
            if client >= 0 { queue.async { [weak self] in self?.serve(client) } }
        }
    }

    private func serve(_ fd: Int32) {
        defer { lock.lock(); authenticatedClients.remove(fd); lock.unlock(); _ = close(fd) }; var authenticated = false
        while let frame = try? readFrame(fd) {
            if frame.0 == .packetToHelper, authenticated { try? backend.writePacket(frame.1); continue }
            guard frame.0 == .controlRequest, let control = try? ObstacleBridgeTunHelperProtocolV1.decodeControl(frame.1) else { return }
            if control.operation == "HELLO" {
                authenticated = control.payload["token"] as? String == token
                if authenticated { lock.lock(); authenticatedClients.insert(fd); lastAuthenticatedActivity = Date(); lock.unlock() }
                try? send("HELLO_OK", ["authenticated": authenticated], fd)
                continue
            }
            guard authenticated else { try? send("ERROR", ["detail": "HELLO required"], fd); continue }
            do {
                let reply: [String: Any]
                switch control.operation {
                case "OPEN_TUN": reply = try backend.openTun(.init(requestedIfname: control.payload["ifname"] as? String ?? "", mtu: control.payload["mtu"] as? Int ?? 1500))
                case "APPLY_NETWORK": reply = try backend.applyPythonNetwork(control.payload, removing: false)
                case "REMOVE_NETWORK": reply = try backend.applyPythonNetwork(control.payload, removing: true)
                case "SNAPSHOT": reply = backend.runtimeSnapshot.payload()
                case "STOP": try? send("STOP_OK", ["stopping": true], fd); backend.stop(); return
                default: throw ObstacleBridgeTunHelperProtocolV1.Error.malformedControl
                }
                try send("\(control.operation)_OK", reply, fd)
            } catch { try? send("ERROR", ["detail": error.localizedDescription], fd) }
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
    /// Python clients receive raw packet frames and UTF-8 event frames after
    /// HELLO; serialize writes so callbacks cannot interleave with replies.
    private func emitPacket(_ packet: Data) {
        lock.lock(); let clients = authenticatedClients; lock.unlock()
        for client in clients { try? writeFrame(kind: .packetFromHelper, body: packet, fd: client) }
    }
    private func emitEvent(event: String, payload: [String: Any]) {
        let detail = payload.isEmpty ? event : "\(event): \(payload)"
        guard let data = detail.data(using: .utf8) else { return }
        lock.lock(); let clients = authenticatedClients; lock.unlock()
        for client in clients { try? writeFrame(kind: .event, body: data, fd: client) }
    }
    private func send(_ op: String, _ payload: [String: Any], _ fd: Int32) throws { try writeAll(ObstacleBridgeTunHelperProtocolV1.frame(kind: .controlResponse, body: try ObstacleBridgeTunHelperProtocolV1.control(operation: op, payload: payload)), fd) }
    private func readFrame(_ fd: Int32) throws -> (ObstacleBridgeTunHelperProtocolV1.FrameKind, Data) { let head = try readExactly(ObstacleBridgeTunHelperProtocolV1.headerBytes, fd); let parsed = try ObstacleBridgeTunHelperProtocolV1.header(head); return (parsed.kind, try readExactly(parsed.bodyLength, fd)) }
    private func readExactly(_ count: Int, _ fd: Int32) throws -> Data { var result = Data(); var b = [UInt8](repeating: 0, count: max(1, min(count, 8192))); while result.count < count { let got = read(fd, &b, min(b.count, count-result.count)); guard got > 0 else { throw ObstacleBridgeTunHelperProtocolV1.Error.malformedFrame }; result.append(b, count: got) }; return result }
    private func writeFrame(kind: ObstacleBridgeTunHelperProtocolV1.FrameKind, body: Data, fd: Int32) throws { try writeAll(ObstacleBridgeTunHelperProtocolV1.frame(kind: kind, body: body), fd) }
    private func writeAll(_ data: Data, _ fd: Int32) throws {
        writerLock.lock(); defer { writerLock.unlock() }
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { write(fd, $0.baseAddress!.advanced(by: offset), data.count-offset) }
            guard count > 0 else { throw ObstacleBridgeTunHelperProtocolV1.Error.malformedFrame }
            offset += count
        }
    }
}
#endif
