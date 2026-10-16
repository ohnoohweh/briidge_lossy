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

    @Test func swiftHelperServerAcceptsProtocolV1AuthenticatedControl() throws {
        let backend = SwiftHelperBackend()
        let path = "/tmp/obstaclebridge-swift-helper-\(UUID().uuidString).sock"
        let server = try ObstacleBridgeLinuxTunHelperServer(socketPath: path, sessionToken: "swift-server-token", backend: backend)
        try server.start(); defer { server.stop() }
        let adapter = try ObstacleBridgeLinuxTunHelperAdapter(socketPath: path, sessionToken: "swift-server-token")
        let plan = try #require(ObstacleBridgeRuntimeConfigPort.packetTunnelPlan(from: ["TUN_routing": ["enabled_on_startup": true]]))
        #expect(try adapter.apply(packetTunnelPlan: plan, interfaceName: "obtest0")["applied"] as? Bool == true)
        #expect(try adapter.rollback(packetTunnelPlan: plan, interfaceName: "obtest0")["removed"] as? Bool == true)
        #expect(try adapter.send(command: .snapshot, payload: [:])["backend"] as? String == "swift-test")
        _ = try adapter.sendPacketToHelper(Data([0x45, 0x00]))
        #expect(backend.waitForPacket())
        #expect(backend.packets == [Data([0x45, 0x00])])
        #expect(try adapter.send(command: .stop, payload: [:])["stopping"] as? Bool == true)
    }

    @Test func swiftHelperServerStopsAfterAuthenticatedClientIdleWindow() throws {
        let backend = SwiftHelperBackend()
        let path = "/tmp/obstaclebridge-swift-helper-idle-\(UUID().uuidString).sock"
        let server = try ObstacleBridgeLinuxTunHelperServer(socketPath: path, sessionToken: "swift-server-token", backend: backend, authenticatedClientIdleTimeout: 0.5)
        try server.start(); defer { server.stop() }
        let deadline = Date().addingTimeInterval(1.5)
        while FileManager.default.fileExists(atPath: path), Date() < deadline { Thread.sleep(forTimeInterval: 0.02) }
        #expect(!FileManager.default.fileExists(atPath: path))
    }

    @Test func nativeSwiftHelperAppliesAndRollsBackAddressesAndRoutesThroughArgvOnlyCommands() throws {
        let lock = NSLock(); var commands: [[String]] = []
        let backend = ObstacleBridgeLinuxNativeTunHelperBackend(commandRunner: { arguments, _ in
            lock.lock(); commands.append(arguments); lock.unlock(); return ""
        })
        let payload: [String: Any] = ["ifname": "obtest0", "tun_routing": [
            "mtu": 1400, "tunnel_address": "198.18.0.1", "tunnel_prefix": 24,
            "included_routes": ["10.0.0.0/8"],
        ]]
        #expect(try backend.applyNetwork(payload)["applied"] as? Bool == true)
        #expect(try backend.removeNetwork(payload)["removed"] as? Bool == true)
        lock.lock(); let recorded = commands; lock.unlock()
        #expect(recorded.contains(["ip", "-4", "addr", "replace", "198.18.0.1/24", "dev", "obtest0"]))
        #expect(recorded.contains(["ip", "-4", "route", "replace", "10.0.0.0/8", "dev", "obtest0"]))
        #expect(recorded.contains(["ip", "-4", "route", "del", "10.0.0.0/8", "dev", "obtest0"]))
    }

    @Test func nativeSwiftHelperSuspendsAndResumesInstalledRoutes() throws {
        var commands: [[String]] = []
        let backend = ObstacleBridgeLinuxNativeTunHelperBackend(commandRunner: { arguments, _ in commands.append(arguments); return "" })
        let payload: [String: Any] = ["ifname": "obtest0", "tun_routing": ["included_routes": ["10.0.0.0/8"]]]
        _ = try backend.applyNetwork(payload)
        _ = try backend.setTunEnabled(["enabled": false])
        _ = try backend.setTunEnabled(["enabled": true])
        #expect(commands.filter { $0 == ["ip", "-4", "route", "replace", "10.0.0.0/8", "dev", "obtest0"] }.count == 2)
        #expect(commands.contains(["ip", "-4", "route", "del", "10.0.0.0/8", "dev", "obtest0"]))
    }

    @Test func nativeSwiftHelperPinsExcludedRoutesToTheCapturedUnderlay() throws {
        var commands: [[String]] = []
        let backend = ObstacleBridgeLinuxNativeTunHelperBackend(commandRunner: { arguments, _ in
            commands.append(arguments)
            return arguments == ["ip", "-j", "-4", "route", "show", "default"] ? "[{\"gateway\":\"192.0.2.1\",\"dev\":\"eth0\",\"prefsrc\":\"192.0.2.2\"}]" : "[]"
        })
        _ = try backend.applyNetwork(["ifname": "obtest0", "tun_routing": ["excluded_routes": ["203.0.113.9/32"]]])
        #expect(commands.contains(["ip", "-4", "route", "replace", "203.0.113.9/32", "via", "192.0.2.1", "dev", "eth0", "src", "192.0.2.2"]))
        _ = try backend.removeNetwork([:])
        #expect(commands.contains(["ip", "-4", "route", "del", "203.0.113.9/32"]))
    }

    @Test func nativeSwiftHelperRestoresPriorExcludedRouteInsteadOfDeletingIt() throws {
        var commands: [[String]] = []
        let backend = ObstacleBridgeLinuxNativeTunHelperBackend(commandRunner: { arguments, _ in
            commands.append(arguments)
            if arguments == ["ip", "-j", "-4", "route", "show", "default"] { return "[{\"gateway\":\"192.0.2.1\",\"dev\":\"eth0\"}]" }
            if arguments == ["ip", "-j", "-4", "route", "show", "203.0.113.9/32"] { return "[{\"dst\":\"203.0.113.9/32\",\"gateway\":\"192.0.2.9\",\"dev\":\"eth1\"}]" }
            return "[]"
        })
        _ = try backend.applyNetwork(["ifname": "obtest0", "tun_routing": ["excluded_routes": ["203.0.113.9/32"]]])
        _ = try backend.removeNetwork([:])
        #expect(commands.contains(["ip", "-4", "route", "replace", "203.0.113.9/32", "via", "192.0.2.9", "dev", "eth1"]))
    }

    @Test func nativeSwiftHelperEmitsLifecycleEvents() throws {
        var events: [String] = []
        let backend = ObstacleBridgeLinuxNativeTunHelperBackend(commandRunner: { arguments, _ in arguments.contains("-j") ? "[]" : "" })
        backend.setEventSink { events.append($0) }
        _ = try backend.applyNetwork(["ifname": "obtest0", "tun_routing": [:]])
        _ = try backend.setTunEnabled(["enabled": false])
        _ = try backend.removeNetwork([:])
        #expect(events == ["network applied interface=obtest0", "tun enabled=false", "network removed interface=obtest0"])
    }

    @Test func nativeSwiftHelperAppliesAndRevertsResolvedDNS() throws {
        var commands: [[String]] = []
        let backend = ObstacleBridgeLinuxNativeTunHelperBackend(commandRunner: { arguments, _ in
            commands.append(arguments); return arguments.contains("-j") ? "[]" : ""
        })
        _ = try backend.applyNetwork(["ifname": "obtest0", "tun_routing": ["dns_servers": ["1.1.1.1", "2606:4700:4700::1111"]]])
        _ = try backend.removeNetwork([:])
        #expect(commands.contains(["resolvectl", "dns", "obtest0", "1.1.1.1", "2606:4700:4700::1111"]))
        #expect(commands.contains(["resolvectl", "domain", "obtest0", "~."]))
        #expect(commands.contains(["resolvectl", "default-route", "obtest0", "yes"]))
        #expect(commands.contains(["resolvectl", "revert", "obtest0"]))
    }

    @Test func nativeSwiftHelperSnapshotDescribesAppliedPolicyWithoutSecrets() throws {
        let backend = ObstacleBridgeLinuxNativeTunHelperBackend(commandRunner: { arguments, _ in
            arguments.contains("-j") ? "[{\"gateway\":\"192.0.2.1\",\"dev\":\"eth0\"}]" : ""
        })
        _ = try backend.applyNetwork(["ifname": "obtest0", "tun_routing": ["included_routes": ["10.0.0.0/8"], "dns_servers": ["1.1.1.1"]]])
        let snapshot = try backend.snapshot()
        #expect(snapshot["network_applied"] as? Bool == true)
        #expect(snapshot["dns_servers"] as? [String] == ["1.1.1.1"])
        #expect(snapshot["applied_routes"] as? [String] == ["-4 10.0.0.0/8"])
    }

    @Test func nativeSwiftHelperAppliesAndRemovesExplicitFirewallRules() throws {
        var commands: [[String]] = []
        let backend = ObstacleBridgeLinuxNativeTunHelperBackend(commandRunner: { arguments, _ in commands.append(arguments); return arguments.contains("-j") ? "[]" : "" })
        _ = try backend.applyNetwork(["ifname": "obtest0", "listener_hook_env": ["WAN_IF": "eth0"], "tun_routing": ["tunnel_address": "198.18.0.1", "tunnel_prefix": 24]])
        _ = try backend.removeNetwork([:])
        #expect(commands.contains(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "198.18.0.1/24", "-o", "eth0", "-j", "MASQUERADE"]))
        #expect(commands.contains(["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "198.18.0.1/24", "-o", "eth0", "-j", "MASQUERADE"]))
    }

    @Test func nativeSwiftHelperPersistsRedactedPolicySnapshot() throws {
        let path = URL(fileURLWithPath: "/tmp/obstaclebridge-native-state-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: path) }
        let backend = ObstacleBridgeLinuxNativeTunHelperBackend(stateURL: path, commandRunner: { arguments, _ in arguments.contains("-j") ? "[]" : "" })
        _ = try backend.applyNetwork(["ifname": "obtest0", "tun_routing": ["dns_servers": ["1.1.1.1"]]])
        let snapshot = try JSONSerialization.jsonObject(with: Data(contentsOf: path)) as? [String: Any]
        #expect(snapshot?["network_applied"] as? Bool == true)
        #expect(snapshot?["dns_servers"] as? [String] == ["1.1.1.1"])
    }

    @Test func nativeSwiftHelperRecoversPersistedPolicyBeforeNewOwnership() throws {
        let path = URL(fileURLWithPath: "/tmp/obstaclebridge-native-recovery-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: path) }
        let writer = ObstacleBridgeLinuxNativeTunHelperBackend(stateURL: path, commandRunner: { arguments, _ in arguments.contains("-j") ? "[]" : "" })
        _ = try writer.applyNetwork(["ifname": "obtest0", "tun_routing": ["included_routes": ["10.0.0.0/8"]]])
        var commands: [[String]] = []
        let recovery = ObstacleBridgeLinuxNativeTunHelperBackend(stateURL: path, commandRunner: { arguments, _ in commands.append(arguments); return "" })
        try recovery.recoverPersistedPolicy()
        #expect(commands.contains(["ip", "-4", "route", "del", "10.0.0.0/8", "dev", "obtest0"]))
        #expect(!FileManager.default.fileExists(atPath: path.path))
    }

    @Test func nativeSwiftHelperRunsConfiguredHookAroundPolicyLifecycle() throws {
        var commands: [[String]] = []
        let backend = ObstacleBridgeLinuxNativeTunHelperBackend(commandRunner: { arguments, _ in commands.append(arguments); return arguments.contains("-j") ? "[]" : "" })
        _ = try backend.applyNetwork(["ifname": "obtest0", "hook_path": "/opt/obstaclebridge/tun-hook", "tun_routing": [:]])
        _ = try backend.removeNetwork([:])
        #expect(commands.contains(["/opt/obstaclebridge/tun-hook", "up", "obtest0"]))
        #expect(commands.contains(["/opt/obstaclebridge/tun-hook", "down", "obtest0"]))
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["OBSTACLEBRIDGE_PRIVILEGED_TUN"] == "1"))
    func privilegedNativeSwiftHelperAppliesAndRemovesKernelTunPolicy() throws {
        #if os(Linux)
        let name = "obq\(getpid() % 100_000)"
        let backend = ObstacleBridgeLinuxNativeTunHelperBackend()
        defer { backend.stop() }
        _ = try backend.openTun(["ifname": name, "mtu": 1400])
        _ = try backend.applyNetwork(["ifname": name, "tun_routing": [
            "tunnel_address": "198.18.0.1", "tunnel_prefix": 24,
            "included_routes": ["198.19.0.0/16"],
        ]])
        let snapshot = try backend.snapshot()
        #expect(snapshot["network_applied"] as? Bool == true)
        _ = try backend.removeNetwork([:])
        #expect(try backend.snapshot()["network_applied"] as? Bool == false)
        #endif
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["OBSTACLEBRIDGE_PRIVILEGED_TUN"] == "1"))
    func privilegedNativeSwiftHelperQualifiesTunRouteDNSAndHookLifecycle() throws {
        #if os(Linux)
        let name = "obq\(getpid() % 100_000)"
        let directory = URL(fileURLWithPath: "/tmp/obstaclebridge-swift-hook-\(UUID().uuidString)", isDirectory: true)
        let hook = directory.appendingPathComponent("hook.sh")
        let marker = directory.appendingPathComponent("events")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Data("#!/bin/sh\nprintf '%s:%s\\n' \"$1\" \"$2\" >> '\(marker.path)'\n".utf8).write(to: hook)
        guard chmod(hook.path, 0o700) == 0 else { throw POSIXError(.EPERM) }
        defer { try? FileManager.default.removeItem(at: directory) }

        let backend = ObstacleBridgeLinuxNativeTunHelperBackend()
        defer { backend.stop() }
        _ = try backend.openTun(["ifname": name, "mtu": 1400])
        let interface = try #require(backend.snapshot()["ifname"] as? String)
        let route = "198.19.0.0/16"
        let address = "198.18.0.1"
        _ = try backend.applyNetwork(["ifname": interface, "hook_path": hook.path, "tun_routing": [
            "tunnel_address": address, "tunnel_prefix": 24,
            "included_routes": [route], "dns_servers": ["192.0.2.53"],
        ]])
        #expect(try ObstacleBridgeLinuxNativeTunHelperBackend.runProcess(["ip", "-j", "-4", "addr", "show", "dev", interface], false).contains(address))
        #expect(try ObstacleBridgeLinuxNativeTunHelperBackend.runProcess(["ip", "-j", "-4", "route", "show", route], false).contains(interface))
        #expect(try ObstacleBridgeLinuxNativeTunHelperBackend.runProcess(["resolvectl", "dns", interface], false).contains("192.0.2.53"))
        _ = try backend.removeNetwork([:])
        let addressesAfterRemoval = try ObstacleBridgeLinuxNativeTunHelperBackend.runProcess(["ip", "-j", "-4", "addr", "show", "dev", interface], false)
        let routesAfterRemoval = try ObstacleBridgeLinuxNativeTunHelperBackend.runProcess(["ip", "-j", "-4", "route", "show", route], false)
        let dnsAfterRemoval = try ObstacleBridgeLinuxNativeTunHelperBackend.runProcess(["resolvectl", "dns", interface], false)
        #expect(!addressesAfterRemoval.contains(address))
        #expect(!routesAfterRemoval.contains(interface))
        #expect(!dnsAfterRemoval.contains("192.0.2.53"))
        #expect(String(decoding: try Data(contentsOf: marker), as: UTF8.self) == "up:\(interface)\ndown:\(interface)\n")
        #endif
    }
}

private final class SwiftHelperBackend: ObstacleBridgeLinuxTunHelperServerBackend, @unchecked Sendable {
    private let lock = NSLock(); private var receivedPackets: [Data] = []
    private let receivedPacket = DispatchSemaphore(value: 0)
    var packets: [Data] { lock.lock(); defer { lock.unlock() }; return receivedPackets }
    func openTun(_ payload: [String: Any]) throws -> [String: Any] { ["opened": true] }
    func applyNetwork(_ payload: [String: Any]) throws -> [String: Any] { ["applied": true] }
    func removeNetwork(_ payload: [String: Any]) throws -> [String: Any] { ["removed": true] }
    func setTunEnabled(_ payload: [String: Any]) throws -> [String: Any] { ["enabled": true] }
    func writePacket(_ packet: Data) throws { lock.lock(); receivedPackets.append(packet); lock.unlock(); receivedPacket.signal() }
    func waitForPacket() -> Bool { receivedPacket.wait(timeout: .now() + 1) == .success }
    func snapshot() throws -> [String: Any] { ["backend": "swift-test"] }
    func stop() {}
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
