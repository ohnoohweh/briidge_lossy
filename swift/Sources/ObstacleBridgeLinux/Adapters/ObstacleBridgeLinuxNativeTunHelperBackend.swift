import Foundation

/// Native device owner for the Swift TUN helper server. This is intentionally
/// narrower than the Python `linux-native` backend: it owns `/dev/net/tun`
/// and packet I/O now, but fails closed for network policy until the complete
/// route/DNS/firewall/hook lifecycle can be implemented equivalently.
public final class ObstacleBridgeLinuxNativeTunHelperBackend: ObstacleBridgeLinuxTunHelperServerBackend, @unchecked Sendable {
    public typealias PacketSink = (Data) -> Void
    /// Injectable command boundary keeps privileged host mutation out of unit
    /// tests while production uses argv-only Process execution.
    public typealias CommandRunner = (_ arguments: [String], _ allowFailure: Bool) throws -> String
    private let lock = NSLock()
    private var packetSink: PacketSink
    private var eventSink: (String) -> Void = { _ in }
    private var device: ObstacleBridgeLinuxTunDevice?
    private var packetsFromRuntime = 0
    private var packetsToRuntime = 0
    private var lastFailure: [String: Any] = [:]
    private var tunEnabled = true
    private let commandRunner: CommandRunner
    private var appliedInterface = ""
    private var appliedAddresses: [(String, String)] = []
    private var appliedRoutes: [(String, String)] = []
    private var configuredRoutes: [(String, String)] = []
    private var excludedRoutes: [(String, String)] = []
    private var underlay: [String: [String: String]] = [:]
    private var appliedDNSServers: [String] = []
    private var appliedFirewallRules: [[String]] = []
    private var appliedHookPath = ""
    private var previousExcludedRoutes: [String: [String: Any]] = [:]
    /// Full-tunnel defaults live in dedicated tables. Destination-specific
    /// rules retain every kernel-connected LAN in main, including vmnet/libvirt.
    private var policyTables: [String: Int] = [:]
    private var policyRules: [(family: String, preference: Int, destination: String, table: String)] = []
    private var policyGateways: [String: String] = [:]
    private let stateURL: URL?

    public init(packetSink: @escaping PacketSink = { _ in }, stateURL: URL? = nil, commandRunner: @escaping CommandRunner = ObstacleBridgeLinuxNativeTunHelperBackend.runProcess) {
        self.packetSink = packetSink; self.stateURL = stateURL; self.commandRunner = commandRunner
    }

    public func setPacketSink(_ sink: @escaping PacketSink) { lock.lock(); packetSink = sink; lock.unlock() }
    public func setEventSink(_ sink: @escaping (String) -> Void) { lock.lock(); eventSink = sink; lock.unlock() }

    /// Clears state left by a terminated prior helper before this helper takes
    /// ownership.  The persisted record is redacted and only contains argv
    /// fragments that this backend originally created.
    public func recoverPersistedPolicy() throws {
        guard let stateURL, FileManager.default.fileExists(atPath: stateURL.path),
              let data = try? Data(contentsOf: stateURL),
              let snapshot = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              snapshot["network_applied"] as? Bool == true else { return }
        let ifname = snapshot["policy_interface"] as? String ?? ""
        guard ObstacleBridgeLinuxTunDevice.isValidInterfaceName(ifname) else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("persisted helper policy has no safe interface name")
        }
        for entry in (snapshot["applied_routes"] as? [String] ?? []).reversed() { try removePersistedIP(entry, kind: "route", interfaceName: ifname) }
        for entry in (snapshot["excluded_routes"] as? [String] ?? []).reversed() { try removePersistedIP(entry, kind: "route", interfaceName: nil) }
        for record in (snapshot["policy_rule_records"] as? [[String: Any]] ?? []).reversed() {
            guard let family = record["family"] as? String, family == "-4" || family == "-6",
                  let preference = record["preference"] as? Int, preference > 0,
                  let destination = record["destination"] as? String, !destination.isEmpty,
                  let table = record["table"] as? String, !table.isEmpty else { continue }
            _ = try commandRunner(["ip", family, "rule", "del", "pref", String(preference), "to", destination, "lookup", table], true)
        }
        for (family, table) in (snapshot["policy_tables"] as? [String: Int] ?? [:]) where family == "-4" || family == "-6" {
            _ = try commandRunner(["ip", family, "route", "flush", "table", String(table)], true)
        }
        if !(snapshot["dns_servers"] as? [String] ?? []).isEmpty { _ = try commandRunner(["resolvectl", "revert", ifname], true) }
        for rule in (snapshot["firewall_rules"] as? [[String]] ?? []).reversed() { _ = try commandRunner(Self.removeFirewallRule(rule), true) }
        for entry in (snapshot["applied_addresses"] as? [String] ?? []).reversed() { try removePersistedIP(entry, kind: "addr", interfaceName: ifname) }
        try FileManager.default.removeItem(at: stateURL)
        emitEvent("recovered prior helper policy interface=\(ifname)")
    }

    public func openTun(_ payload: [String: Any]) throws -> [String: Any] {
        guard let requested = payload["ifname"] as? String, !requested.isEmpty else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("OPEN_TUN requires ifname")
        }
        let mtu = (payload["mtu"] as? Int) ?? 1_500
        lock.lock()
        if let device { let reply = snapshotLocked(device: device); lock.unlock(); return reply }
        lock.unlock()
        let device = try ObstacleBridgeLinuxTunDevice(interfaceName: requested, mtu: mtu, packetSink: { [weak self] packet in
            self?.lock.lock(); self?.packetsToRuntime += 1; self?.lock.unlock()
            self?.lock.lock(); let sink = self?.packetSink; self?.lock.unlock()
            sink?(packet)
        })
        try device.start()
        lock.lock(); self.device = device; let reply = snapshotLocked(device: device); lock.unlock()
        return reply
    }

    public func applyNetwork(_ payload: [String: Any]) throws -> [String: Any] {
        guard let ifname = payload["ifname"] as? String, ObstacleBridgeLinuxTunDevice.isValidInterfaceName(ifname),
              let routing = payload["tun_routing"] as? [String: Any] else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("APPLY_NETWORK requires a valid interface and tunnel-routing plan")
        }
        guard appliedInterface.isEmpty || appliedInterface == ifname else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("Swift native helper refuses to replace another helper-owned interface")
        }
        let mtu = (routing["mtu"] as? Int) ?? 1_500
        var addresses: [(String, String)] = []
        var routes: [(String, String)] = []
        var excluded: [(String, String)] = []
        let dnsServers = (routing["dns_servers"] as? [String] ?? []).filter { !$0.isEmpty }
        let hookEnvironment = payload["listener_hook_env"] as? [String: Any] ?? [:]
        let wanInterface = (hookEnvironment["WAN_IF"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let hookPath = (payload["hook_path"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if !hookPath.isEmpty && !hookPath.hasPrefix("/") { throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("hook_path must be an absolute executable path") }
        var firewallRules: [[String]] = []
        var savedUnderlay: [String: [String: String]] = [:]
        var previousExcluded: [String: [String: Any]] = [:]
        var fullTunnelGateways: [String: String] = [:]
        func cidr(_ addressKey: String, _ prefixKey: String, _ family: String) throws -> String? {
            guard let address = routing[addressKey] as? String, !address.isEmpty else { return nil }
            guard let prefix = routing[prefixKey] as? Int, prefix > 0 else { throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("APPLY_NETWORK has an invalid \(addressKey) prefix") }
            return "\(address)/\(prefix)"
        }
        if let cidr = try cidr("tunnel_address", "tunnel_prefix", "-4") { addresses.append(("-4", cidr)) }
        if let cidr = try cidr("tunnel_address6", "tunnel_prefix6", "-6") { addresses.append(("-6", cidr)) }
        if !wanInterface.isEmpty && wanInterface.lowercased() != "auto" {
            for (family, cidr) in addresses {
                let binary = family == "-4" ? "iptables" : "ip6tables"
                firewallRules += [
                    [binary, "-A", "FORWARD", "-i", ifname, "-o", wanInterface, "-j", "ACCEPT"],
                    [binary, "-A", "FORWARD", "-i", wanInterface, "-o", ifname, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
                    [binary, "-t", "nat", "-A", "POSTROUTING", "-s", cidr, "-o", wanInterface, "-j", "MASQUERADE"],
                ]
            }
        }
        for (family, key, gatewayKey) in [("-4", "included_routes", "tunnel_gateway"), ("-6", "included_routes6", "tunnel_gateway6")] {
            for route in (routing[key] as? [String] ?? []) where !route.isEmpty {
                if Self.isDefaultRoute(route) { fullTunnelGateways[family] = (routing[gatewayKey] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines) }
                else { routes.append((family, route)) }
            }
        }
        for (family, key) in [("-4", "excluded_routes"), ("-6", "excluded_routes6")] {
            for route in (routing[key] as? [String] ?? []) where !route.isEmpty { excluded.append((family, route)) }
        }
        do {
            for family in ["-4", "-6"] {
                let text = try commandRunner(["ip", "-j", family, "route", "show", "default"], false)
                if let value = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [[String: Any]], let route = value.first,
                   let dev = route["dev"] as? String, !dev.isEmpty {
                    var record = ["dev": dev]
                    if let via = route["gateway"] as? String { record["via"] = via }
                    if let source = route["prefsrc"] as? String { record["src"] = source }
                    savedUnderlay[family] = record
                }
            }
            if !excluded.isEmpty && (savedUnderlay["-4"] == nil && excluded.contains { $0.0 == "-4" } || savedUnderlay["-6"] == nil && excluded.contains { $0.0 == "-6" }) {
                throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("APPLY_NETWORK cannot preserve excluded routes without an underlay default route")
            }
            _ = try commandRunner(["ip", "link", "set", "dev", ifname, "up", "mtu", String(mtu)], false)
            for (family, cidr) in addresses { _ = try commandRunner(["ip", family, "addr", "replace", cidr, "dev", ifname], false) }
            for (family, route) in excluded {
                let priorText = try commandRunner(["ip", "-j", family, "route", "show", route], false)
                if let values = try? JSONSerialization.jsonObject(with: Data(priorText.utf8)) as? [[String: Any]], let prior = values.first {
                    previousExcluded["\(family) \(route)"] = prior
                }
                guard let saved = savedUnderlay[family], let dev = saved["dev"] else { continue }
                var command = ["ip", family, "route", "replace", route]
                if let via = saved["via"] { command += ["via", via] }
                command += ["dev", dev]
                if let source = saved["src"] { command += ["src", source] }
                _ = try commandRunner(command, false)
            }
            if tunEnabled { for (family, route) in routes { _ = try commandRunner(["ip", family, "route", "replace", route, "dev", ifname], false) } }
            if tunEnabled {
                for family in ["-4", "-6"] where fullTunnelGateways[family] != nil {
                    try installFullTunnelPolicy(family: family, gateway: fullTunnelGateways[family] ?? "", ifname: ifname, excluded: excluded)
                }
            }
            if !dnsServers.isEmpty {
                _ = try commandRunner(["resolvectl", "dns", ifname] + dnsServers, false)
                _ = try commandRunner(["resolvectl", "domain", ifname, "~."], false)
                _ = try commandRunner(["resolvectl", "default-route", ifname, "yes"], false)
            }
            for rule in firewallRules { _ = try commandRunner(rule, false) }
            if !hookPath.isEmpty { _ = try commandRunner([hookPath, "up", ifname], false) }
        } catch {
            if !hookPath.isEmpty { _ = try? commandRunner([hookPath, "down", ifname], true) }
            _ = try? commandRunner(["resolvectl", "revert", ifname], true)
            for (family, route) in routes.reversed() { _ = try? commandRunner(["ip", family, "route", "del", route, "dev", ifname], true) }
            removeFullTunnelPolicy(allowFailure: true)
            for (family, route) in excluded.reversed() { _ = try? commandRunner(["ip", family, "route", "del", route], true) }
            for (family, cidr) in addresses.reversed() { _ = try? commandRunner(["ip", family, "addr", "del", cidr, "dev", ifname], true) }
            for rule in firewallRules.reversed() { _ = try? commandRunner(Self.removeFirewallRule(rule), true) }
            recordFailure(stage: "apply_network", error: error.localizedDescription)
            throw error
        }
        lock.lock(); appliedInterface = ifname; appliedAddresses = addresses; configuredRoutes = routes; appliedRoutes = tunEnabled ? routes : []; excludedRoutes = excluded; underlay = savedUnderlay; appliedDNSServers = dnsServers; appliedFirewallRules = firewallRules; appliedHookPath = hookPath; previousExcludedRoutes = previousExcluded; policyGateways = fullTunnelGateways; lock.unlock()
        emitEvent("network applied interface=\(ifname)")
        persistState()
        return ["applied": true, "backend": "linux-swift-native", "ifname": ifname, "routes_active": tunEnabled]
    }

    public func removeNetwork(_ payload: [String: Any]) throws -> [String: Any] {
        lock.lock(); let ifname = appliedInterface; let routes = appliedRoutes; let addresses = appliedAddresses; let excluded = excludedRoutes; let dnsServers = appliedDNSServers; let firewall = appliedFirewallRules; let hookPath = appliedHookPath; let previousExcluded = previousExcludedRoutes; lock.unlock()
        guard !ifname.isEmpty else { return ["removed": true, "backend": "linux-swift-native"] }
        for (family, route) in routes.reversed() { _ = try commandRunner(["ip", family, "route", "del", route, "dev", ifname], true) }
        removeFullTunnelPolicy(allowFailure: true)
        for (family, route) in excluded.reversed() {
            let key = "\(family) \(route)"
            if let previous = previousExcluded[key] { _ = try commandRunner(Self.restoreRoute(family: family, fallback: route, record: previous), true) }
            else { _ = try commandRunner(["ip", family, "route", "del", route], true) }
        }
        if !dnsServers.isEmpty { _ = try commandRunner(["resolvectl", "revert", ifname], true) }
        for rule in firewall.reversed() { _ = try commandRunner(Self.removeFirewallRule(rule), true) }
        if !hookPath.isEmpty { _ = try commandRunner([hookPath, "down", ifname], true) }
        for (family, cidr) in addresses.reversed() { _ = try commandRunner(["ip", family, "addr", "del", cidr, "dev", ifname], true) }
        lock.lock(); appliedInterface = ""; appliedAddresses = []; appliedRoutes = []; configuredRoutes = []; excludedRoutes = []; underlay = [:]; appliedDNSServers = []; appliedFirewallRules = []; appliedHookPath = ""; previousExcludedRoutes = [:]; policyGateways = [:]; lock.unlock()
        emitEvent("network removed interface=\(ifname)")
        persistState()
        return ["removed": true, "backend": "linux-swift-native", "ifname": ifname]
    }

    public func setTunEnabled(_ payload: [String: Any]) throws -> [String: Any] {
        let value = payload["enabled"]
        let enabled: Bool
        if let boolean = value as? Bool { enabled = boolean }
        else if let number = value as? NSNumber { enabled = number.boolValue }
        else if let text = value as? String {
            switch text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
            case "1", "true", "yes", "on": enabled = true
            case "0", "false", "no", "off": enabled = false
            default: throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("SET_TUN_ENABLED requires a boolean enabled value")
            }
        } else { throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("SET_TUN_ENABLED requires a boolean enabled value") }
        lock.lock()
        let ifname = appliedInterface
        let routes = configuredRoutes
        let activeRoutes = appliedRoutes
        let gateways = policyGateways
        let excluded = excludedRoutes
        let hasPolicy = !policyTables.isEmpty
        lock.unlock()
        if !ifname.isEmpty {
            if enabled && activeRoutes.isEmpty && !hasPolicy {
                for (family, route) in routes { _ = try commandRunner(["ip", family, "route", "replace", route, "dev", ifname], false) }
                for family in ["-4", "-6"] where gateways[family] != nil { try installFullTunnelPolicy(family: family, gateway: gateways[family] ?? "", ifname: ifname, excluded: excluded) }
                lock.lock(); appliedRoutes = routes; lock.unlock()
            } else if !enabled && (!activeRoutes.isEmpty || hasPolicy) {
                for (family, route) in activeRoutes.reversed() { _ = try commandRunner(["ip", family, "route", "del", route, "dev", ifname], true) }
                removeFullTunnelPolicy(allowFailure: true)
                lock.lock(); appliedRoutes = []; lock.unlock()
            }
        }
        lock.lock(); tunEnabled = enabled; let snapshot = self.device.map(snapshotLocked) ?? closedSnapshotLocked(); lock.unlock()
        emitEvent("tun enabled=\(enabled)")
        persistState()
        return snapshot.merging(["tun_enabled": enabled]) { _, new in new }
    }

    public func writePacket(_ packet: Data) throws {
        lock.lock(); let device = self.device; lock.unlock()
        guard let device else { throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("TUN device is not open") }
        try device.writePacket(packet)
        lock.lock(); packetsFromRuntime += 1; lock.unlock()
    }

    public func snapshot() throws -> [String: Any] {
        lock.lock(); defer { lock.unlock() }
        guard let device else {
            return closedSnapshotLocked()
        }
        return snapshotLocked(device: device)
    }

    public func stop() {
        _ = try? removeNetwork([:])
        lock.lock(); let device = self.device; self.device = nil; lock.unlock()
        device?.stop()
    }

    public func recordFailure(stage: String, error: String) {
        lock.lock(); lastFailure = ["stage": stage, "error": error]; lock.unlock()
        emitEvent("failure stage=\(stage)")
        persistState()
    }

    private func emitEvent(_ detail: String) { lock.lock(); let sink = eventSink; lock.unlock(); sink(detail) }
    private func removePersistedIP(_ entry: String, kind: String, interfaceName: String?) throws {
        let parts = entry.split(separator: " ", maxSplits: 1).map(String.init)
        guard parts.count == 2, parts[0] == "-4" || parts[0] == "-6" else { throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("persisted helper policy has invalid IP entry") }
        var command = ["ip", parts[0], kind, "del", parts[1]]
        if let interfaceName { command += ["dev", interfaceName] }
        _ = try commandRunner(command, true)
    }
    private func persistState() {
        guard let stateURL else { return }
        lock.lock(); let value = snapshotFields(["backend": "linux-swift-native", "opened": device != nil]); lock.unlock()
        guard JSONSerialization.isValidJSONObject(value), let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) else { return }
        try? data.write(to: stateURL, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: stateURL.path)
    }

    private func snapshotLocked(device: ObstacleBridgeLinuxTunDevice) -> [String: Any] {
        snapshotFields(["backend": "linux-swift-native", "opened": true, "ifname": device.actualInterfaceName, "mtu": device.mtu])
    }
    private func closedSnapshotLocked() -> [String: Any] { snapshotFields(["backend": "linux-swift-native", "opened": false]) }
    private func snapshotFields(_ base: [String: Any]) -> [String: Any] {
        base.merging([
            "packets_from_runtime": packetsFromRuntime, "packets_to_runtime": packetsToRuntime,
            "last_failure": lastFailure, "tun_enabled": tunEnabled, "network_applied": !appliedInterface.isEmpty,
            "policy_interface": appliedInterface,
            "applied_addresses": appliedAddresses.map { "\($0.0) \($0.1)" },
            "applied_routes": appliedRoutes.map { "\($0.0) \($0.1)" },
            "excluded_routes": excludedRoutes.map { "\($0.0) \($0.1)" },
            "underlay": underlay, "dns_servers": appliedDNSServers,
            "firewall_rules": appliedFirewallRules,
            "hook_path": appliedHookPath,
            "previous_excluded_routes": previousExcludedRoutes,
            "policy_tables": policyTables, "policy_rules": policyRules.map { "\($0.family) pref \($0.preference) to \($0.destination) lookup \($0.table)" },
            "policy_rule_records": policyRules.map { ["family": $0.family, "preference": $0.preference, "destination": $0.destination, "table": $0.table] },
        ]) { _, new in new }
    }

    private static func isDefaultRoute(_ route: String) -> Bool {
        let value = route.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return value == "default" || value == "0.0.0.0/0" || value == "::/0" || value == "::0/0"
    }

    private static func policyTableID(ifname: String, family: String) -> Int {
        let base = family == "-4" ? 20_000 : 21_000
        return base + ifname.utf8.reduce(0) { ($0 + Int($1)) % 500 }
    }

    private func connectedMainRoutes(family: String) throws -> [String] {
        let text = try commandRunner(["ip", "-j", family, "route", "show", "proto", "kernel", "scope", "link"], true)
        guard let rows = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [[String: Any]] else { return [] }
        var result: [String] = []
        for row in rows {
            let route = (row["dst"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            if !route.isEmpty, !Self.isDefaultRoute(route), !result.contains(route) { result.append(route) }
        }
        return result
    }

    private func installFullTunnelPolicy(family: String, gateway: String, ifname: String, excluded: [(String, String)]) throws {
        let table = String(Self.policyTableID(ifname: ifname, family: family))
        var destinations = try connectedMainRoutes(family: family)
        for (_, route) in excluded.filter({ $0.0 == family }) where !destinations.contains(route) { destinations.append(route) }
        let preferenceBase = family == "-4" ? 10_000 : 11_000
        var installed: [(family: String, preference: Int, destination: String, table: String)] = []
        for (index, destination) in destinations.enumerated() {
            let preference = preferenceBase + index
            // A recovered helper can encounter an already-present rule. The
            // desired policy is still represented by this idempotent argv.
            _ = try commandRunner(["ip", family, "rule", "add", "pref", String(preference), "to", destination, "lookup", "main"], true)
            installed.append((family, preference, destination, "main"))
        }
        let defaultDestination = family == "-4" ? "0.0.0.0/0" : "::/0"
        let defaultPreference = preferenceBase + destinations.count
        _ = try commandRunner(["ip", family, "rule", "add", "pref", String(defaultPreference), "to", defaultDestination, "lookup", table], true)
        installed.append((family, defaultPreference, defaultDestination, table))
        var routeCommand = ["ip", family, "route", "replace", "table", table, "default"]
        if !gateway.isEmpty { routeCommand += ["via", gateway] }
        routeCommand += ["dev", ifname]
        if !gateway.isEmpty && family == "-4" { routeCommand.append("onlink") }
        if !gateway.isEmpty && family == "-6" { routeCommand += ["metric", "1", "onlink"] }
        _ = try commandRunner(routeCommand, false)
        lock.lock(); policyTables[family] = Int(table); policyRules += installed; lock.unlock()
    }

    private func removeFullTunnelPolicy(allowFailure: Bool) {
        lock.lock(); let rules = policyRules; let tables = policyTables; policyRules = []; policyTables = [:]; lock.unlock()
        for rule in rules.reversed() {
            _ = try? commandRunner(["ip", rule.family, "rule", "del", "pref", String(rule.preference), "to", rule.destination, "lookup", rule.table], allowFailure)
        }
        for (family, table) in tables { _ = try? commandRunner(["ip", family, "route", "flush", "table", String(table)], allowFailure) }
    }

    public static func runProcess(_ arguments: [String], _ allowFailure: Bool) throws -> String {
        guard let command = arguments.first else { throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("Linux helper command is empty") }
        let paths: [String]
        switch command {
        case "ip": paths = ["/usr/sbin/ip", "/sbin/ip"]
        case "resolvectl": paths = ["/usr/bin/resolvectl", "/bin/resolvectl"]
        case "iptables": paths = ["/usr/sbin/iptables", "/sbin/iptables"]
        case "ip6tables": paths = ["/usr/sbin/ip6tables", "/sbin/ip6tables"]
        default: paths = []
        }
        let selectedPaths = command.hasPrefix("/") ? [command] : paths
        guard let executable = selectedPaths.first(where: FileManager.default.isExecutableFile(atPath:)) else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("Linux helper command is unavailable: \(command)")
        }
        let process = Process(); process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = Array(arguments.dropFirst())
        let stdout = Pipe(); let stderr = Pipe(); process.standardOutput = stdout; process.standardError = stderr
        try process.run(); process.waitUntilExit()
        let output = String(data: stdout.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        if process.terminationStatus != 0 && !allowFailure { throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("Linux helper command failed: \(arguments.joined(separator: " "))") }
        return output
    }
    private static func removeFirewallRule(_ rule: [String]) -> [String] {
        guard let index = rule.firstIndex(of: "-A") else { return rule }
        var result = rule; result[index] = "-D"; return result
    }
    private static func restoreRoute(family: String, fallback: String, record: [String: Any]) -> [String] {
        var command = ["ip", family, "route", "replace", (record["dst"] as? String) ?? fallback]
        if let gateway = record["gateway"] as? String { command += ["via", gateway] }
        if let dev = record["dev"] as? String { command += ["dev", dev] }
        if let source = record["prefsrc"] as? String { command += ["src", source] }
        return command
    }
}
