import Foundation
import Testing
@testable import ObstacleBridgeLinuxAdapters
@testable import ObstacleBridgeCore
#if os(Linux)
import Glibc
#endif

struct ObstacleBridgeLinuxTunHelperAdapterTests {
    @Test func unavailableEndpointFailsClosedWithoutPrivilegedFallback() throws {
        let adapter = try ObstacleBridgeLinuxTunHelperAdapter(socketPath: "/tmp/obstaclebridge-no-helper-\(UUID().uuidString).sock", sessionToken: "test-token", timeoutMilliseconds: 50)
        #expect(throws: (any Error).self) { try adapter.send(command: .snapshot, payload: [:]) }
    }

    @Test func rejectsMissingEndpointTokenAndInvalidTimeoutBeforeAnyTransportAttempt() {
        #expect(throws: (any Error).self) { _ = try ObstacleBridgeLinuxTunHelperAdapter(socketPath: "", sessionToken: "token") }
        #expect(throws: (any Error).self) { _ = try ObstacleBridgeLinuxTunHelperAdapter(socketPath: "/tmp/helper.sock", sessionToken: "") }
        #expect(throws: (any Error).self) { _ = try ObstacleBridgeLinuxTunHelperAdapter(socketPath: "/tmp/helper.sock", sessionToken: "token", timeoutMilliseconds: 0) }
    }

    @Test func unixHelperUsesAuthenticatedProtocolV1ControlAndPacketFrames() throws {
        let peer = try UnixHelperPeer(connectionCount: 6); defer { peer.stop() }
        let adapter = try ObstacleBridgeLinuxTunHelperAdapter(socketPath: peer.path, sessionToken: peer.token)
        for command in [ObstacleBridgeTunHelperCommand.openTun, .applyNetwork, .removeNetwork, .snapshot, .stop] {
            let response = try adapter.send(command: command, payload: command == .openTun ? ["ifname": "obtest0", "mtu": 1400] : [:])
            #expect(response["op"] as? String == "\(command.rawValue)_OK")
        }
        _ = try adapter.sendPacketToHelper(Data([0x45, 0x00, 0x12, 0x34]))
        #expect(peer.waitForExpectedConnections())
        #expect(peer.operations == ["OPEN_TUN", "APPLY_NETWORK", "REMOVE_NETWORK", "SNAPSHOT", "STOP", "WRITE_PACKET"])
        #expect(peer.packets == [Data([0x45, 0x00, 0x12, 0x34])])
    }

    @Test func helperAppliesAndRollsBackCorePacketTunnelPlan() throws {
        let peer = try UnixHelperPeer(connectionCount: 2); defer { peer.stop() }
        let adapter = try ObstacleBridgeLinuxTunHelperAdapter(socketPath: peer.path, sessionToken: peer.token)
        let plan = try #require(ObstacleBridgeRuntimeConfigPort.packetTunnelPlan(from: ["TUN_routing": ["enabled_on_startup": true, "mtu": 1400]]))
        _ = try adapter.apply(packetTunnelPlan: plan, interfaceName: "obtest0")
        _ = try adapter.rollback(packetTunnelPlan: plan, interfaceName: "obtest0")
        #expect(peer.operations == ["APPLY_NETWORK", "REMOVE_NETWORK"])
        let apply = try #require(peer.payloads.first)
        #expect(apply["ifname"] as? String == "obtest0")
        let routing = try #require(apply["tun_routing"] as? [String: Any])
        #expect(routing["mtu"] as? Int == 1400)
        #expect(routing["included_routes"] as? [String] == ["0.0.0.0/0"])
        #expect(routing["dns_servers"] as? [String] == ["1.1.1.1"])
    }

    @Test func realPythonHelperAcceptsAuthenticatedSwiftApplyAndRemove() throws {
        let helper = try PythonTunHelperPeer(); defer { helper.stop() }
        let adapter = try ObstacleBridgeLinuxTunHelperAdapter(socketPath: helper.path, sessionToken: helper.token)
        let plan = try #require(ObstacleBridgeRuntimeConfigPort.packetTunnelPlan(from: ["TUN_routing": ["enabled_on_startup": true, "mtu": 1400]]))
        let applied = try adapter.apply(packetTunnelPlan: plan, interfaceName: "obtest0")
        #expect(applied["applied"] as? Bool == true)
        #expect(applied["backend"] as? String == "linux-python-memory")
        let removed = try adapter.rollback(packetTunnelPlan: plan, interfaceName: "obtest0")
        #expect(removed["removed"] as? Bool == true)
        #expect(removed["backend"] as? String == "linux-python-memory")
    }

    @Test func helperApplyFailureRequestsRollbackOnFreshAuthenticatedExchange() throws {
        let peer = try UnixHelperPeer(connectionCount: 2, disconnectFirstCommandReply: true); defer { peer.stop() }
        let adapter = try ObstacleBridgeLinuxTunHelperAdapter(socketPath: peer.path, sessionToken: peer.token)
        let plan = try #require(ObstacleBridgeRuntimeConfigPort.packetTunnelPlan(from: ["TUN_routing": ["enabled_on_startup": true]]))
        #expect(throws: (any Error).self) { try adapter.applyWithRollback(packetTunnelPlan: plan, interfaceName: "obtest0") }
        #expect(peer.operations == ["APPLY_NETWORK", "REMOVE_NETWORK"])
    }

    @Test func helperRejectsWrongSessionTokenBeforeOperation() throws {
        let peer = try UnixHelperPeer(connectionCount: 1); defer { peer.stop() }
        let adapter = try ObstacleBridgeLinuxTunHelperAdapter(socketPath: peer.path, sessionToken: "wrong-token")
        #expect(throws: (any Error).self) { try adapter.send(command: .snapshot, payload: [:]) }
        #expect(peer.operations.isEmpty)
    }
}

private final class PythonTunHelperPeer {
    let path = "/tmp/obstaclebridge-python-helper-\(UUID().uuidString).sock"
    let token = "swift-linux-helper-token"
    private let process = Process()

    init() throws {
        let workingDirectory = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let projectRoot = FileManager.default.fileExists(atPath: workingDirectory.appendingPathComponent("src").path) ? workingDirectory : workingDirectory.deletingLastPathComponent()
        let python = [projectRoot.appendingPathComponent(".venv/bin/python").path, "/usr/bin/python3"].first(where: FileManager.default.isExecutableFile(atPath:))!
        process.executableURL = URL(fileURLWithPath: python)
        process.arguments = ["-m", "obstacle_bridge.bridge_tun_helper_server", "--socket-path", path, "--session-token", token, "--backend", "linux-python"]
        var environment = ProcessInfo.processInfo.environment
        environment["PYTHONPATH"] = projectRoot.appendingPathComponent("src").path
        process.environment = environment
        process.standardOutput = Pipe(); process.standardError = Pipe()
        try process.run()
        let deadline = Date().addingTimeInterval(2)
        while !FileManager.default.fileExists(atPath: path), process.isRunning, Date() < deadline { Thread.sleep(forTimeInterval: 0.02) }
        guard FileManager.default.fileExists(atPath: path) else { stop(); throw PeerError.didNotStart }
    }

    func stop() {
        // The helper CLI waits for a process signal after listener shutdown.
        // This test owns the child, so terminate it deterministically.
        if process.isRunning { _ = kill(process.processIdentifier, SIGKILL) }
        process.waitUntilExit()
        try? FileManager.default.removeItem(atPath: path)
    }

    private enum PeerError: Error { case didNotStart }
}

private final class UnixHelperPeer: @unchecked Sendable {
    let path: String
    let token = "test-helper-token"
    private let listener: Int32
    private let expectedConnections: Int
    private let disconnectFirstCommandReply: Bool
    private let completed = DispatchGroup()
    private let lock = NSLock()
    private var capturedOperations: [String] = []
    private var capturedPackets: [Data] = []
    private var capturedPayloads: [[String: Any]] = []
    var operations: [String] { lock.lock(); defer { lock.unlock() }; return capturedOperations }
    var packets: [Data] { lock.lock(); defer { lock.unlock() }; return capturedPackets }
    var payloads: [[String: Any]] { lock.lock(); defer { lock.unlock() }; return capturedPayloads }

    init(connectionCount: Int, disconnectFirstCommandReply: Bool = false) throws {
        self.expectedConnections = connectionCount; self.disconnectFirstCommandReply = disconnectFirstCommandReply
        self.path = "/tmp/obstaclebridge-helper-\(UUID().uuidString).sock"
        self.listener = socket(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0)
        guard listener >= 0 else { throw PeerError.socket }
        var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX); let bytes = Array(path.utf8) + [0]
        withUnsafeMutableBytes(of: &address.sun_path) { destination in destination.initializeMemory(as: UInt8.self, repeating: 0); destination.baseAddress!.assumingMemoryBound(to: UInt8.self).update(from: bytes, count: bytes.count) }
        let result = withUnsafePointer(to: &address) { pointer in pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        guard result == 0, listen(listener, 8) == 0 else { _ = close(listener); throw PeerError.socket }
        for _ in 0..<connectionCount { completed.enter() }
        DispatchQueue.global().async { [weak self] in self?.serve() }
    }

    func stop() { _ = shutdown(listener, Int32(SHUT_RDWR)); _ = close(listener); try? FileManager.default.removeItem(atPath: path) }
    func waitForExpectedConnections() -> Bool { completed.wait(timeout: .now() + 1) == .success }

    private func serve() {
        for index in 0..<expectedConnections {
            let fd = accept(listener, nil, nil); guard fd >= 0 else { return }
            do {
                defer { _ = close(fd); completed.leave() }
                guard let hello = try? readControl(fd), hello.op == "HELLO" else { return }
                guard hello.payload["token"] as? String == token else { try? writeControl("ERROR", ["detail": "invalid session token"], fd); continue }
                try? writeControl("HELLO_OK", ["authenticated": true], fd)
                guard let (kind, body) = try? readFrame(fd) else { return }
                if kind == 4 { lock.lock(); capturedOperations.append("WRITE_PACKET"); capturedPackets.append(body); lock.unlock(); continue }
                guard kind == 1, let request = try? decodeControl(body) else { return }
                lock.lock(); capturedOperations.append(request.op); capturedPayloads.append(request.payload); lock.unlock()
                if disconnectFirstCommandReply && index == 0 { continue }
                try? writeControl("\(request.op)_OK", ["handled": true], fd)
            }
        }
    }

    private func decodeControl(_ data: Data) throws -> (op: String, payload: [String: Any]) {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], object["version"] as? Int == 1, let op = object["op"] as? String, let payload = object["payload"] as? [String: Any] else { throw PeerError.socket }
        return (op, payload)
    }
    private func readControl(_ fd: Int32) throws -> (op: String, payload: [String: Any]) { let (kind, body) = try readFrame(fd); guard kind == 1 else { throw PeerError.socket }; return try decodeControl(body) }
    private func writeControl(_ op: String, _ payload: [String: Any], _ fd: Int32) throws { let body = try JSONSerialization.data(withJSONObject: ["version": 1, "op": op, "payload": payload], options: [.sortedKeys]); try writeFrame(2, body, fd) }
    private func readFrame(_ fd: Int32) throws -> (UInt8, Data) { let header: Data = try readExactly(5, fd); let length = header.dropFirst().reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }; return (header[header.startIndex], try readExactly(Int(length), fd)) }
    private func writeFrame(_ kind: UInt8, _ body: Data, _ fd: Int32) throws { var length = UInt32(body.count).bigEndian; var wire = Data([kind]); wire.append(Data(bytes: &length, count: 4)); wire.append(body); try writeAll(wire, fd) }
    private func readExactly(_ count: Int, _ fd: Int32) throws -> Data { var data = Data(); var buffer = [UInt8](repeating: 0, count: max(1, count)); while data.count < count { let amount = read(fd, &buffer, count - data.count); guard amount > 0 else { throw PeerError.socket }; data.append(buffer, count: Int(amount)) }; return data }
    private func writeAll(_ data: Data, _ fd: Int32) throws { var offset = 0; while offset < data.count { let amount = data.withUnsafeBytes { write(fd, $0.baseAddress!.advanced(by: offset), data.count - offset) }; guard amount > 0 else { throw PeerError.socket }; offset += Int(amount) } }
    private enum PeerError: Error { case socket }
}
