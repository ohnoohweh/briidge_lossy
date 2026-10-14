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
