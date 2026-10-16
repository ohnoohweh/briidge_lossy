import Foundation
#if os(macOS)
import Darwin
#endif

/// macOS resource owner for the portable TUN-helper contract. It owns utun
/// descriptor lifecycle and hook-process execution; Core owns all envelopes,
/// command validation, state snapshots, and loopback transport semantics.
final class ObstacleBridgeInProcessMacOSTunHelperClient: ObstacleBridgeTunHelperClienting {
    private let queue: DispatchQueue
    private var packetSink: (Data) -> Void
    private var eventSink: ((String, [String: Any]) -> Void)?
    private var adapter: ObstacleBridgeMacOSTunAdapter?
    private(set) var runtimeSnapshot = ObstacleBridgeTunHelperRuntimeSnapshot()

    init(queue: DispatchQueue, packetSink: @escaping (Data) -> Void, eventSink: ((String, [String: Any]) -> Void)? = nil) {
        self.queue = queue
        self.packetSink = packetSink
        self.eventSink = eventSink
    }

    /// The standalone Unix server attaches these sinks after its stored
    /// properties are initialized; app/XPC callers provide them at creation.
    func setPacketSink(_ sink: @escaping (Data) -> Void) { packetSink = sink }
    func setEventSink(_ sink: ((String, [String: Any]) -> Void)?) { eventSink = sink }

    var requestedIfname: String { adapter?.requestedIfname ?? runtimeSnapshot.requestedIfname }
    var actualIfname: String { adapter?.actualIfname ?? runtimeSnapshot.ifname }
    var mtu: Int { adapter?.mtu ?? runtimeSnapshot.mtu }
    var isOpen: Bool { runtimeSnapshot.opened && adapter != nil }
    var transportKind: String { "in_process" }

    @discardableResult
    func openTun(_ request: ObstacleBridgeTunHelperOpenRequest) throws -> [String: Any] {
        if isOpen, requestedIfname == request.requestedIfname, mtu == request.mtu { return runtimeSnapshot.payload() }
        stop()
        let tunAdapter = ObstacleBridgeMacOSTunAdapter(
            ifname: request.requestedIfname, mtu: request.mtu, queue: queue,
            packetSink: { [weak self] packet in self?.emitPacketFromHelper(packet) },
            eventSink: { [weak self] event, payload in self?.emitEventFromHelper(event: event, payload: payload) }
        )
        try tunAdapter.start()
        adapter = tunAdapter
        runtimeSnapshot.markOpened(requestedIfname: request.requestedIfname, actualIfname: tunAdapter.actualIfname, mtu: request.mtu)
        return runtimeSnapshot.payload()
    }

    private func emitPacketFromHelper(_ packet: Data) {
        do {
            let envelope = ObstacleBridgeTunHelperPacketEnvelope.packetFromHelper(packet)
            let runtimePacket = try ObstacleBridgeTunHelperPacketEnvelope.packetFromHelperPacket(from: envelope.xpcPayload())
            runtimeSnapshot.recordPacketToRuntime()
            packetSink(runtimePacket)
        } catch { recordFailure(stage: "packet_from_helper", error: error.localizedDescription) }
    }

    private func emitEventFromHelper(event: String, payload: [String: Any]) {
        guard let eventSink else { return }
        do {
            let decoded = try ObstacleBridgeTunHelperEventEnvelope.decode(ObstacleBridgeTunHelperEventEnvelope(event: event, payload: payload).xpcPayload())
            eventSink(decoded.event, decoded.payload)
        } catch { recordFailure(stage: "event_from_helper", error: error.localizedDescription) }
    }

    func applyNetwork(action: String, argv: [String], env: [String: String]) { runHook(action: action, argv: argv, env: env, removing: false) }
    func removeNetwork(action: String, argv: [String], env: [String: String]) { runHook(action: action, argv: argv, env: env, removing: true) }

    /// Translates the Python protocol-v1 network payload into the same bundled
    /// Darwin hook contract used by the packaged Swift helper.
    func applyPythonNetwork(_ payload: [String: Any], removing: Bool) throws -> [String: Any] {
        guard let routing = payload["tun_routing"] as? [String: Any] else {
            throw ObstacleBridgeTunHelperCommandError.invalidPayload("APPLY_NETWORK requires tun_routing")
        }
        let ifname = (payload["ifname"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? actualIfname
        guard !ifname.isEmpty else { throw ObstacleBridgeTunHelperCommandError.invalidPayload("APPLY_NETWORK requires an open TUN interface") }
        func text(_ key: String) -> String { String(describing: routing[key] ?? "").trimmingCharacters(in: .whitespacesAndNewlines) }
        func routes(_ key: String) -> String { (routing[key] as? [Any] ?? []).map { String(describing: $0) }.filter { !$0.isEmpty }.joined(separator: ",") }
        var env: [String: String] = [
            "MTU": text("mtu").isEmpty ? String(mtu) : text("mtu"),
            "INCLUDED_ROUTES": routes("included_routes"), "EXCLUDED_ROUTES": routes("excluded_routes"),
            "INCLUDED_ROUTES6": routes("included_routes6"), "EXCLUDED_ROUTES6": routes("excluded_routes6"),
        ]
        let address = text("tunnel_address"), prefix = text("tunnel_prefix"), gateway = text("tunnel_gateway")
        let resolvedGateway = gateway.isEmpty ? defaultGateway(address: address, prefix: prefix, ipv6: false) : gateway
        if !address.isEmpty, !prefix.isEmpty { env["TUN_ADDR"] = "\(address)/\(prefix)" }
        if !resolvedGateway.isEmpty { env["TUN_GW"] = resolvedGateway; env["PEER_ADDR"] = resolvedGateway }
        let address6 = text("tunnel_address6"), prefix6 = text("tunnel_prefix6"), gateway6 = text("tunnel_gateway6")
        let resolvedGateway6 = gateway6.isEmpty ? defaultGateway(address: address6, prefix: prefix6, ipv6: true) : gateway6
        if !address6.isEmpty, !prefix6.isEmpty { env["TUN_ADDR6"] = "\(address6)/\(prefix6)" }
        if !resolvedGateway6.isEmpty { env["TUN_GW6"] = resolvedGateway6; env["PEER_ADDR6"] = resolvedGateway6 }
        let dns = routing["dns_servers"] as? [Any] ?? []
        if dns.indices.contains(0) { env["DNS1"] = String(describing: dns[0]) }
        if dns.indices.contains(1) { env["DNS2"] = String(describing: dns[1]) }
        for (key, value) in payload["listener_hook_env"] as? [String: Any] ?? [:] { env[key] = String(describing: value) }
        let serverSide = String(describing: payload["service_catalog"] ?? "").lowercased() == "remote_servers"
        let hookName = serverSide ? "server-tun-hook-macos.sh" : "client-tun-hook-macos.sh"
        let hook = Bundle.main.bundleURL.appendingPathComponent("Contents/Resources/scripts/\(hookName)").path
        runHook(action: removing ? "down" : "up", argv: [hook, removing ? "down" : "up", ifname], env: env, removing: removing)
        if !runtimeSnapshot.lastFailure.isEmpty { throw ObstacleBridgeTunHelperCommandError.invalidResponse("Darwin TUN hook failed") }
        return runtimeSnapshot.payload()
    }

    func writePacket(_ packet: Data) throws {
        guard let adapter else { return }
        try adapter.write(packet: packet)
        runtimeSnapshot.recordPacketFromRuntime()
    }

    func recordFailure(stage: String, error: String) { runtimeSnapshot.markFailure(stage: stage, error: error) }

    /// Matches Python's ip_interface(...).network.hosts() choice: use the
    /// first usable subnet peer unless it is the local address, then use the
    /// next. This is only relevant when configuration omits an explicit peer.
    private func defaultGateway(address: String, prefix: String, ipv6: Bool) -> String {
#if os(macOS)
        let width = ipv6 ? 16 : 4
        guard let length = Int(prefix), (ipv6 ? 0...128 : 0...32).contains(length), length < width * 8 else { return "" }
        let family: Int32 = ipv6 ? AF_INET6 : AF_INET
        var input = in6_addr()
        guard inet_pton(family, address, &input) == 1 else { return "" }
        var local = withUnsafeBytes(of: input) { Array($0.prefix(width)) }
        var candidate = local
        for index in 0..<width {
            let bitsBefore = index * 8
            if length <= bitsBefore { candidate[index] = 0 }
            else if length < bitsBefore + 8 { candidate[index] &= UInt8(0xff << (8 - (length - bitsBefore))) }
        }
        func increment(_ bytes: inout [UInt8]) -> Bool {
            for index in bytes.indices.reversed() { if bytes[index] < 255 { bytes[index] += 1; return true }; bytes[index] = 0 }
            return false
        }
        guard increment(&candidate) else { return "" }
        if candidate == local { guard increment(&candidate) else { return "" } }
        var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let rendered: UnsafePointer<CChar>? = candidate.withUnsafeBytes { bytes in inet_ntop(family, bytes.baseAddress, &output, socklen_t(output.count)) }
        return rendered.map { String(cString: $0) } ?? ""
#else
        return ""
#endif
    }

    private func runHook(action: String, argv: [String], env: [String: String], removing: Bool) {
        guard let executable = argv.first, !executable.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            runtimeSnapshot.markNetworkApplied(action: action, argv: argv, env: env)
            if removing { runtimeSnapshot.networkApplied = false }
            return
        }
#if os(macOS)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = Array(argv.dropFirst())
        var processEnv = ProcessInfo.processInfo.environment
        for (key, value) in env { processEnv[key] = value }
        process.environment = processEnv
        let outputPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = outputPipe
        do {
            try process.run()
            process.waitUntilExit()
            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            emitEventFromHelper(event: "macos_tun_hook_completed", payload: ["action": action, "argv": argv, "status": Int(process.terminationStatus), "output": output])
            if process.terminationStatus == 0 {
                runtimeSnapshot.markNetworkApplied(action: action, argv: argv, env: env)
                if removing { runtimeSnapshot.networkApplied = false }
            } else {
                runtimeSnapshot.markFailure(stage: "macos_tun_hook_\(action)", error: "exit_status=\(process.terminationStatus)")
            }
        } catch { runtimeSnapshot.markFailure(stage: "macos_tun_hook_\(action)", error: error.localizedDescription) }
#else
        runtimeSnapshot.markFailure(stage: "macos_tun_hook_\(action)", error: "macOS TUN hook execution is not available on iOS")
#endif
    }

    func stop() {
        adapter?.stop()
        adapter = nil
        runtimeSnapshot.opened = false
        runtimeSnapshot.networkApplied = false
        runtimeSnapshot.stopped = true
        runtimeSnapshot.cleanupAttempted = true
        runtimeSnapshot.cleanupOK = true
    }
}
