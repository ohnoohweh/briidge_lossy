import Foundation
import Testing
@testable import ObstacleBridgeLinuxAdapters
@testable import ObstacleBridgeCore
import ObstacleBridgeDesktopShared
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

    @Test func unixHelperUsesAuthenticatedCommonIPCControlAndPacketFrames() throws {
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

    @Test func swiftHelperServerAcceptsCommonIPCAuthenticatedControl() throws {
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

    @Test func controlExchangeIgnoresHelperEventBeforeItsResponse() throws {
        let backend = SwiftHelperBackend(emitEventBeforeReply: true)
        let path = "/tmp/obstaclebridge-swift-helper-event-\(UUID().uuidString).sock"
        let server = try ObstacleBridgeLinuxTunHelperServer(socketPath: path, sessionToken: "swift-server-token", backend: backend)
        try server.start(); defer { server.stop() }
        let adapter = try ObstacleBridgeLinuxTunHelperAdapter(socketPath: path, sessionToken: "swift-server-token")
        #expect(try adapter.send(command: .applyNetwork, payload: [:])["applied"] as? Bool == true)
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

    @Test func nativeSwiftHelperAppliesIPv6ExclusionsWithoutAnIPv6UnderlayDefaultRoute() throws {
        var commands: [[String]] = []
        let backend = ObstacleBridgeLinuxNativeTunHelperBackend(commandRunner: { arguments, _ in
            commands.append(arguments)
            // This host has an IPv4 Internet default only.  IPv6 loopback and
            // link-local routes are still valid main-table exclusions.
            if arguments == ["ip", "-j", "-4", "route", "show", "default"] {
                return "[{\"gateway\":\"192.0.2.1\",\"dev\":\"eth0\"}]"
            }
            return arguments.contains("-j") ? "[]" : ""
        })
        #expect(try backend.applyNetwork(["ifname": "obtest0", "tun_routing": [
            "tunnel_address6": "fd20:106::2", "tunnel_prefix6": 64,
            "tunnel_gateway6": "fd20:106::1", "included_routes6": ["::/0"],
            "excluded_routes6": ["::1/128", "fe80::/10"],
        ]])["applied"] as? Bool == true)
        #expect(commands.contains(["ip", "-6", "rule", "add", "pref", "11000", "to", "::1/128", "lookup", "main"]))
        #expect(commands.contains(["ip", "-6", "route", "replace", "table", "21205", "default", "via", "fd20:106::1", "dev", "obtest0", "metric", "1", "onlink"]))
    }

    @Test func nativeSwiftHelperFullTunnelRetainsEveryKernelConnectedLocalLAN() throws {
        var commands: [[String]] = []
        let backend = ObstacleBridgeLinuxNativeTunHelperBackend(commandRunner: { arguments, _ in
            commands.append(arguments)
            if arguments == ["ip", "-j", "-4", "route", "show", "proto", "kernel", "scope", "link"] {
                return "[{\"dst\":\"10.0.0.0/24\"},{\"dst\":\"192.168.122.0/24\"},{\"dst\":\"192.168.179.0/24\"}]"
            }
            if arguments == ["ip", "-j", "-4", "route", "show", "default"] {
                return "[{\"gateway\":\"10.0.0.1\",\"dev\":\"eth0\"}]"
            }
            return arguments.contains("-j") ? "[]" : ""
        })
        _ = try backend.applyNetwork(["ifname": "obtest0", "tun_routing": [
            "tunnel_address": "198.18.70.2", "tunnel_prefix": 24, "tunnel_gateway": "198.18.70.1",
            "included_routes": ["0.0.0.0/0"],
            "excluded_routes": ["192.168.179.0/24"],
        ]])
        let snapshot = try backend.snapshot()
        #expect(commands.contains(["ip", "-4", "rule", "add", "pref", "10001", "to", "192.168.122.0/24", "lookup", "main"]))
        #expect(commands.contains(["ip", "-4", "rule", "add", "pref", "10002", "to", "192.168.179.0/24", "lookup", "main"]))
        #expect(!commands.contains(["ip", "-4", "route", "replace", "192.168.179.0/24", "via", "198.18.70.1", "dev", "obtest0"]))
        #expect(commands.contains(["ip", "-4", "route", "replace", "table", "20205", "default", "via", "198.18.70.1", "dev", "obtest0", "onlink"]))
        let policyRules = snapshot["policy_rules"] as? [String] ?? []
        #expect(policyRules.contains(where: { $0.contains("192.168.179.0/24 lookup main") }))
        _ = try backend.removeNetwork([:])
        #expect(commands.contains(["ip", "-4", "route", "flush", "table", "20205"]))
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
        let writer = ObstacleBridgeLinuxNativeTunHelperBackend(stateURL: path, commandRunner: { arguments, _ in
            if arguments == ["ip", "-j", "-4", "route", "show", "default"] { return "[{\"gateway\":\"192.0.2.1\",\"dev\":\"eth0\"}]" }
            if arguments == ["ip", "-j", "-4", "route", "show", "203.0.113.9/32"] { return "[{\"dst\":\"203.0.113.9/32\",\"gateway\":\"192.0.2.9\",\"dev\":\"eth1\"}]" }
            return arguments.contains("-j") ? "[]" : ""
        })
        _ = try writer.applyNetwork([
            "ifname": "obtest0", "hook_path": "/opt/obstaclebridge/tun-hook",
            "listener_hook_env": ["WAN_IF": "eth0"],
            "tun_routing": [
                "tunnel_address": "198.18.0.1", "tunnel_prefix": 24,
                "included_routes": ["10.0.0.0/8"], "excluded_routes": ["203.0.113.9/32"],
                "dns_servers": ["1.1.1.1"],
            ],
        ])
        var commands: [[String]] = []
        let recovery = ObstacleBridgeLinuxNativeTunHelperBackend(stateURL: path, commandRunner: { arguments, _ in commands.append(arguments); return "" })
        try recovery.recoverPersistedPolicy()
        #expect(commands.contains(["ip", "-4", "route", "del", "10.0.0.0/8", "dev", "obtest0"]))
        #expect(commands.contains(["ip", "-4", "route", "replace", "203.0.113.9/32", "via", "192.0.2.9", "dev", "eth1"]))
        #expect(commands.contains(["resolvectl", "revert", "obtest0"]))
        #expect(commands.contains(["iptables", "-D", "FORWARD", "-i", "obtest0", "-o", "eth0", "-j", "ACCEPT"]))
        #expect(commands.contains(["/opt/obstaclebridge/tun-hook", "down", "obtest0"]))
        #expect(commands.contains(["ip", "-4", "addr", "del", "198.18.0.1/24", "dev", "obtest0"]))
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
        let name = "obqr\(getpid() % 10_000)"
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
        let name = "obqh\(getpid() % 10_000)"
        let directory = URL(fileURLWithPath: "/tmp/obstaclebridge-swift-hook-\(UUID().uuidString)", isDirectory: true)
        let hook = directory.appendingPathComponent("hook.sh")
        let marker = directory.appendingPathComponent("events")
        let socket = directory.appendingPathComponent("helper.sock")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Data("#!/bin/sh\nprintf '%s:%s\\n' \"$1\" \"$2\" >> '\(marker.path)'\n".utf8).write(to: hook)
        guard chmod(hook.path, 0o700) == 0 else { throw POSIXError(.EPERM) }
        defer { try? FileManager.default.removeItem(at: directory) }

        let backend = ObstacleBridgeLinuxNativeTunHelperBackend()
        let server = try ObstacleBridgeLinuxTunHelperServer(socketPath: socket.path, sessionToken: "privileged-swift-helper-token", backend: backend)
        try server.start()
        defer { server.stop() }
        let adapter = try ObstacleBridgeLinuxTunHelperAdapter(socketPath: socket.path, sessionToken: "privileged-swift-helper-token")
        let opened = try adapter.send(command: .openTun, payload: ["ifname": name, "mtu": 1400])
        let interface = try #require(opened["ifname"] as? String)
        // This opt-in test runs concurrently with the basic privileged
        // route test, so its host policy must not compete for that route.
        let route = "198.21.0.0/16"
        let route6 = "fd21:106::/64"
        let peerExclusion = "203.0.113.254/32"
        let address = "198.20.0.1"
        let address6 = "fd20:106::1"
        _ = try adapter.send(command: .applyNetwork, payload: ["ifname": interface, "hook_path": hook.path, "tun_routing": [
            "tunnel_address": address, "tunnel_prefix": 24,
            "tunnel_address6": address6, "tunnel_prefix6": 64,
            "included_routes": [route], "included_routes6": [route6],
            "excluded_routes": [peerExclusion], "dns_servers": ["192.0.2.53"],
        ]])
        // This is the packet path used by the unprivileged foreground after
        // it authenticates to the helper.  The helper counter proves the
        // packet reached the real TUN owner rather than merely a test socket.
        _ = try adapter.sendPacketToHelper(Data([0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 198, 20, 0, 1, 198, 21, 0, 1]))
        let deadline = Date().addingTimeInterval(1)
        var packetSnapshot: [String: Any] = [:]
        while Date() < deadline {
            packetSnapshot = try adapter.send(command: .snapshot, payload: [:])
            if (packetSnapshot["packets_from_runtime"] as? Int ?? 0) == 1 { break }
            Thread.sleep(forTimeInterval: 0.02)
        }
        #expect(packetSnapshot["packets_from_runtime"] as? Int == 1)
        #expect(try ObstacleBridgeLinuxNativeTunHelperBackend.runProcess(["ip", "-j", "-4", "addr", "show", "dev", interface], false).contains(address))
        #expect(try ObstacleBridgeLinuxNativeTunHelperBackend.runProcess(["ip", "-j", "-4", "route", "show", route], false).contains(interface))
        #expect(try ObstacleBridgeLinuxNativeTunHelperBackend.runProcess(["ip", "-j", "-6", "addr", "show", "dev", interface], false).contains(address6))
        #expect(try ObstacleBridgeLinuxNativeTunHelperBackend.runProcess(["ip", "-j", "-6", "route", "show", route6], false).contains(interface))
        #expect(!(try ObstacleBridgeLinuxNativeTunHelperBackend.runProcess(["ip", "-j", "-4", "route", "show", peerExclusion], false)).contains(interface))
        #expect(try ObstacleBridgeLinuxNativeTunHelperBackend.runProcess(["resolvectl", "dns", interface], false).contains("192.0.2.53"))
        _ = try adapter.send(command: .removeNetwork, payload: [:])
        let addressesAfterRemoval = try ObstacleBridgeLinuxNativeTunHelperBackend.runProcess(["ip", "-j", "-4", "addr", "show", "dev", interface], false)
        let routesAfterRemoval = try ObstacleBridgeLinuxNativeTunHelperBackend.runProcess(["ip", "-j", "-4", "route", "show", route], false)
        let addresses6AfterRemoval = try ObstacleBridgeLinuxNativeTunHelperBackend.runProcess(["ip", "-j", "-6", "addr", "show", "dev", interface], false)
        let routes6AfterRemoval = try ObstacleBridgeLinuxNativeTunHelperBackend.runProcess(["ip", "-j", "-6", "route", "show", route6], false)
        let peerExclusionAfterRemoval = try ObstacleBridgeLinuxNativeTunHelperBackend.runProcess(["ip", "-j", "-4", "route", "show", peerExclusion], false)
        let dnsAfterRemoval = try ObstacleBridgeLinuxNativeTunHelperBackend.runProcess(["resolvectl", "dns", interface], false)
        #expect(!addressesAfterRemoval.contains(address))
        #expect(!routesAfterRemoval.contains(interface))
        #expect(!addresses6AfterRemoval.contains(address6))
        #expect(!routes6AfterRemoval.contains(interface))
        #expect(!peerExclusionAfterRemoval.contains(interface))
        #expect(!dnsAfterRemoval.contains("192.0.2.53"))
        #expect(String(decoding: try Data(contentsOf: marker), as: UTF8.self) == "up:\(interface)\ndown:\(interface)\n")
        #endif
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["OBSTACLEBRIDGE_PRIVILEGED_TUN"] == "1" && ProcessInfo.processInfo.environment["OBSTACLEBRIDGE_LINUX_TEST_HELPER_EXECUTABLE"] != nil))
    func privilegedNativeSwiftHelperRecoversPolicyAfterHelperProcessLoss() throws {
        #if os(Linux)
        let executable = try #require(ProcessInfo.processInfo.environment["OBSTACLEBRIDGE_LINUX_TEST_HELPER_EXECUTABLE"])
        #expect(FileManager.default.isExecutableFile(atPath: executable))
        let directory = URL(fileURLWithPath: "/tmp/obstaclebridge-swift-recovery-\(UUID().uuidString)", isDirectory: true)
        let socket = directory.appendingPathComponent("helper.sock")
        let state = URL(fileURLWithPath: socket.path + ".state.json")
        let hook = directory.appendingPathComponent("hook.sh")
        let marker = directory.appendingPathComponent("events")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Data("#!/bin/sh\nprintf '%s:%s\\n' \"$1\" \"$2\" >> '\(marker.path)'\n".utf8).write(to: hook)
        guard chmod(hook.path, 0o700) == 0 else { throw POSIXError(.EPERM) }
        defer { try? FileManager.default.removeItem(at: directory) }

        let wanInterface = try #require(try defaultIPv4Interface())
        let token = "privileged-recovery-token"
        let first = try launchNativeHelper(executable: executable, socketPath: socket.path, token: token)
        defer { terminate(first) }
        let firstAdapter = try waitForNativeHelper(socketPath: socket.path, token: token, process: first)
        let opened = try firstAdapter.send(command: .openTun, payload: ["ifname": "obkr\(getpid() % 10_000)", "mtu": 1400])
        let interface = try #require(opened["ifname"] as? String)
        let address = "198.20.1.1"
        _ = try firstAdapter.send(command: .applyNetwork, payload: [
            "ifname": interface, "hook_path": hook.path,
            "listener_hook_env": ["WAN_IF": wanInterface],
            "tun_routing": [
                "tunnel_address": address, "tunnel_prefix": 24,
                "included_routes": ["198.22.0.0/16"], "dns_servers": ["192.0.2.53"],
            ],
        ])
        #expect(FileManager.default.fileExists(atPath: state.path))
        let forwardBeforeLoss = try ObstacleBridgeLinuxNativeTunHelperBackend.runProcess(["iptables", "-S", "FORWARD"], false)
        #expect(forwardBeforeLoss.contains("-i \(interface) -o \(wanInterface) -j ACCEPT"))

        // SIGKILL models an interrupted helper: no in-process STOP/rollback is
        // allowed to run, so the successor must consume the persisted policy.
        _ = kill(first.processIdentifier, SIGKILL)
        first.waitUntilExit()
        #expect(FileManager.default.fileExists(atPath: state.path))

        let replacement = try launchNativeHelper(executable: executable, socketPath: socket.path, token: token)
        defer { terminate(replacement) }
        let replacementAdapter = try waitForNativeHelper(socketPath: socket.path, token: token, process: replacement)
        #expect(!FileManager.default.fileExists(atPath: state.path))
        #expect(try replacementAdapter.send(command: .snapshot, payload: [:])["network_applied"] as? Bool == false)
        let forwardAfterRecovery = try ObstacleBridgeLinuxNativeTunHelperBackend.runProcess(["iptables", "-S", "FORWARD"], false)
        #expect(!forwardAfterRecovery.contains("-i \(interface) -o \(wanInterface) -j ACCEPT"))
        #expect(String(decoding: try Data(contentsOf: marker), as: UTF8.self) == "up:\(interface)\ndown:\(interface)\n")

        _ = try replacementAdapter.send(command: .stop, payload: [:])
        let stoppedDeadline = Date().addingTimeInterval(2)
        while replacement.isRunning && Date() < stoppedDeadline { Thread.sleep(forTimeInterval: 0.02) }
        #expect(!replacement.isRunning)
        #endif
    }

    private func defaultIPv4Interface() throws -> String? {
        let text = try ObstacleBridgeLinuxNativeTunHelperBackend.runProcess(["ip", "-j", "-4", "route", "show", "default"], false)
        guard let routes = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [[String: Any]] else { return nil }
        return routes.first?["dev"] as? String
    }

    private func launchNativeHelper(executable: String, socketPath: String, token: String) throws -> Process {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = ["--tun-helper-server", socketPath, token, "--idle-sec", "30"]
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        try process.run()
        return process
    }

    private func waitForNativeHelper(socketPath: String, token: String, process: Process) throws -> ObstacleBridgeLinuxTunHelperAdapter {
        let adapter = try ObstacleBridgeLinuxTunHelperAdapter(socketPath: socketPath, sessionToken: token, timeoutMilliseconds: 100)
        let deadline = Date().addingTimeInterval(3)
        while process.isRunning && Date() < deadline {
            if (try? adapter.send(command: .snapshot, payload: [:])) != nil { return adapter }
            Thread.sleep(forTimeInterval: 0.02)
        }
        throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("native Swift helper did not become available")
    }

    private func terminate(_ process: Process) {
        if process.isRunning { _ = kill(process.processIdentifier, SIGKILL) }
        process.waitUntilExit()
    }
}

private final class SwiftHelperBackend: ObstacleBridgeLinuxTunHelperServerBackend, @unchecked Sendable {
    private let lock = NSLock(); private var receivedPackets: [Data] = []
    private let receivedPacket = DispatchSemaphore(value: 0)
    private let emitEventBeforeReply: Bool
    private var eventSink: (String) -> Void = { _ in }
    init(emitEventBeforeReply: Bool = false) { self.emitEventBeforeReply = emitEventBeforeReply }
    var packets: [Data] { lock.lock(); defer { lock.unlock() }; return receivedPackets }
    func openTun(_ payload: [String: Any]) throws -> [String: Any] { ["opened": true] }
    func setEventSink(_ sink: @escaping (String) -> Void) { eventSink = sink }
    func applyNetwork(_ payload: [String: Any]) throws -> [String: Any] {
        if emitEventBeforeReply { eventSink("network apply started") }
        return ["applied": true]
    }
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
                let hello = try readFrame(fd)
                let negotiated = try ObstacleBridgeWorkerIPC.negotiatedCapabilities(hello, supported: ["tun.control", "tun.packet", "tun.event"])
                guard hello.kind == .hello, negotiated.role == "tun-helper-client", Set(negotiated.capabilities) == Set(["tun.control", "tun.packet", "tun.event"]) else { return }
                try writeAll(try ObstacleBridgeWorkerIPC.hello(generation: hello.generation, role: "tun-helper", capabilities: ["tun.control", "tun.packet", "tun.event"]), fd)
                try writeControl("READY", ["capabilities": ["tun.control", "tun.event", "tun.packet"]], kind: .ready, generation: hello.generation, fd)
                guard let tokenHello = try? readControl(fd), tokenHello.op == "HELLO" else { return }
                guard tokenHello.payload["token"] as? String == token else { try? writeControl("ERROR", ["detail": "invalid session token"], generation: hello.generation, fd); continue }
                try? writeControl("HELLO_OK", ["authenticated": true], generation: hello.generation, fd)
                let frame = try readFrame(fd)
                guard frame.generation == hello.generation else { return }
                if frame.kind == .data { lock.lock(); capturedOperations.append("WRITE_PACKET"); capturedPackets.append(frame.payload); lock.unlock(); continue }
                guard frame.kind == .request, let request = try? decodeControl(frame) else { return }
                lock.lock(); capturedOperations.append(request.op); capturedPayloads.append(request.payload); lock.unlock()
                if disconnectFirstCommandReply && index == 0 { continue }
                try? writeControl("\(request.op)_OK", ["handled": true], generation: hello.generation, fd)
            }
        }
    }

    private func decodeControl(_ frame: ObstacleBridgeWorkerIPC.Frame) throws -> (op: String, payload: [String: Any]) {
        guard let object = try? ObstacleBridgeWorkerIPC.decodeControl(frame), let op = object["op"] as? String, let payload = object["payload"] as? [String: Any] else { throw PeerError.socket }
        return (op, payload)
    }
    private func readControl(_ fd: Int32) throws -> (op: String, payload: [String: Any]) { let frame = try readFrame(fd); guard frame.kind == .request else { throw PeerError.socket }; return try decodeControl(frame) }
    private func writeControl(_ op: String, _ payload: [String: Any], kind: ObstacleBridgeWorkerIPC.Kind = .response, generation: UInt64, _ fd: Int32) throws { try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: kind, generation: generation, value: ["op": op, "payload": payload]), fd) }
    private func readFrame(_ fd: Int32) throws -> ObstacleBridgeWorkerIPC.Frame { let header = try readExactly(ObstacleBridgeWorkerIPC.headerBytes, fd); guard let size = try ObstacleBridgeWorkerIPC.frameSize(header), let decoded = try ObstacleBridgeWorkerIPC.decode(header + (try readExactly(size, fd))).0 else { throw PeerError.socket }; return decoded }
    private func readExactly(_ count: Int, _ fd: Int32) throws -> Data { var data = Data(); var buffer = [UInt8](repeating: 0, count: max(1, count)); while data.count < count { let amount = read(fd, &buffer, count - data.count); guard amount > 0 else { throw PeerError.socket }; data.append(buffer, count: Int(amount)) }; return data }
    private func writeAll(_ data: Data, _ fd: Int32) throws { var offset = 0; while offset < data.count { let amount = data.withUnsafeBytes { write(fd, $0.baseAddress!.advanced(by: offset), data.count - offset) }; guard amount > 0 else { throw PeerError.socket }; offset += Int(amount) } }
    private enum PeerError: Error { case socket }
}
