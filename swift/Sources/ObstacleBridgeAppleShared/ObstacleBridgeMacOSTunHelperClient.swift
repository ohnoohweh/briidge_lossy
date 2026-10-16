import Foundation

/// macOS resource owner for the portable TUN-helper contract. It owns utun
/// descriptor lifecycle and hook-process execution; Core owns all envelopes,
/// command validation, state snapshots, and loopback transport semantics.
final class ObstacleBridgeInProcessMacOSTunHelperClient: ObstacleBridgeTunHelperClienting {
    private let queue: DispatchQueue
    private let packetSink: (Data) -> Void
    private let eventSink: ((String, [String: Any]) -> Void)?
    private var adapter: ObstacleBridgeMacOSTunAdapter?
    private(set) var runtimeSnapshot = ObstacleBridgeTunHelperRuntimeSnapshot()

    init(queue: DispatchQueue, packetSink: @escaping (Data) -> Void, eventSink: ((String, [String: Any]) -> Void)? = nil) {
        self.queue = queue
        self.packetSink = packetSink
        self.eventSink = eventSink
    }

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
        if !address.isEmpty, !prefix.isEmpty { env["TUN_ADDR"] = "\(address)/\(prefix)" }
        if !gateway.isEmpty { env["TUN_GW"] = gateway; env["PEER_ADDR"] = gateway }
        let address6 = text("tunnel_address6"), prefix6 = text("tunnel_prefix6"), gateway6 = text("tunnel_gateway6")
        if !address6.isEmpty, !prefix6.isEmpty { env["TUN_ADDR6"] = "\(address6)/\(prefix6)" }
        if !gateway6.isEmpty { env["TUN_GW6"] = gateway6; env["PEER_ADDR6"] = gateway6 }
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
