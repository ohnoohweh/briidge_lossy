import Foundation

enum ObstacleBridgeTunHelperCommand: String, CaseIterable {
    case openTun = "OPEN_TUN"
    case applyNetwork = "APPLY_NETWORK"
    case removeNetwork = "REMOVE_NETWORK"
    case writePacket = "WRITE_PACKET"
    case snapshot = "SNAPSHOT"
    case stop = "STOP"
}

enum ObstacleBridgeTunHelperFrameKind: String, CaseIterable {
    case controlRequest = "CONTROL_REQUEST"
    case controlResponse = "CONTROL_RESPONSE"
    case packetFromHelper = "PACKET_FROM_HELPER"
    case packetToHelper = "PACKET_TO_HELPER"
    case event = "EVENT"
}

enum ObstacleBridgeTunHelperPlatformScope {
    static let macOSBackend = "darwin-native"
    static let desktopHelperMode = "helper"
    static let iOSUsesNetworkExtensionBoundary = true
}

enum ObstacleBridgeTunHelperCommandError: Error, LocalizedError {
    case invalidPayload(String)
    case invalidResponse(String)
    case unsupportedCommand(String)
    case unsupportedFrame(String)

    var errorDescription: String? {
        switch self {
        case .invalidPayload(let detail):
            return detail
        case .invalidResponse(let detail):
            return detail
        case .unsupportedCommand(let detail):
            return detail
        case .unsupportedFrame(let detail):
            return detail
        }
    }
}

struct ObstacleBridgeTunHelperCommandEnvelope {
    let command: ObstacleBridgeTunHelperCommand
    let payload: [String: Any]
    let sequence: Int

    init(command: ObstacleBridgeTunHelperCommand, payload: [String: Any], sequence: Int = 0) {
        self.command = command
        self.payload = payload
        self.sequence = max(0, sequence)
    }

    func xpcPayload() -> [String: Any] {
        [
            "command": command.rawValue,
            "seq": sequence,
            "payload": payload,
        ]
    }

    static func decode(_ message: [String: Any]) throws -> ObstacleBridgeTunHelperCommandEnvelope {
        guard let commandName = message["command"] as? String,
              let command = ObstacleBridgeTunHelperCommand(rawValue: commandName) else {
            throw ObstacleBridgeTunHelperCommandError.unsupportedCommand("unsupported helper command")
        }
        let payload = message["payload"] as? [String: Any] ?? [:]
        let sequence = Self.intValue(from: message["seq"], defaultValue: 0)
        return ObstacleBridgeTunHelperCommandEnvelope(command: command, payload: payload, sequence: sequence)
    }

    private static func intValue(from value: Any?, defaultValue: Int) -> Int {
        if let value = value as? Int {
            return value
        }
        if let value = value as? NSNumber {
            return value.intValue
        }
        if let value = value as? String, let parsed = Int(value) {
            return parsed
        }
        return defaultValue
    }
}

struct ObstacleBridgeTunHelperPacketEnvelope {
    let frameKind: ObstacleBridgeTunHelperFrameKind
    let payload: [String: Any]
    let sequence: Int

    init(frameKind: ObstacleBridgeTunHelperFrameKind, payload: [String: Any], sequence: Int = 0) {
        self.frameKind = frameKind
        self.payload = payload
        self.sequence = max(0, sequence)
    }

    static func packetFromHelper(_ packet: Data, sequence: Int = 0) -> ObstacleBridgeTunHelperPacketEnvelope {
        ObstacleBridgeTunHelperPacketEnvelope(
            frameKind: .packetFromHelper,
            payload: [
                "packet": packet,
                "len": packet.count,
            ],
            sequence: sequence
        )
    }

    static func packetToHelper(_ packet: Data, sequence: Int = 0) -> ObstacleBridgeTunHelperPacketEnvelope {
        ObstacleBridgeTunHelperPacketEnvelope(
            frameKind: .packetToHelper,
            payload: [
                "packet": packet,
                "len": packet.count,
            ],
            sequence: sequence
        )
    }

    func xpcPayload() -> [String: Any] {
        [
            "frame_kind": frameKind.rawValue,
            "seq": sequence,
            "payload": payload,
        ]
    }

    static func decode(_ message: [String: Any]) throws -> ObstacleBridgeTunHelperPacketEnvelope {
        guard let kindName = message["frame_kind"] as? String,
              let frameKind = ObstacleBridgeTunHelperFrameKind(rawValue: kindName) else {
            throw ObstacleBridgeTunHelperCommandError.unsupportedFrame("unsupported helper frame")
        }
        let payload = message["payload"] as? [String: Any] ?? [:]
        let sequence = Self.intValue(from: message["seq"], defaultValue: 0)
        return ObstacleBridgeTunHelperPacketEnvelope(frameKind: frameKind, payload: payload, sequence: sequence)
    }

    static func packetFromHelperPacket(from message: [String: Any]) throws -> Data {
        let envelope = try decode(message)
        guard envelope.frameKind == .packetFromHelper else {
            throw ObstacleBridgeTunHelperCommandError.unsupportedFrame("expected PACKET_FROM_HELPER")
        }
        guard let packet = envelope.payload["packet"] as? Data else {
            throw ObstacleBridgeTunHelperCommandError.invalidPayload("PACKET_FROM_HELPER requires Data packet")
        }
        return packet
    }

    static func packetToHelperPacket(from message: [String: Any]) throws -> Data {
        let envelope = try decode(message)
        guard envelope.frameKind == .packetToHelper else {
            throw ObstacleBridgeTunHelperCommandError.unsupportedFrame("expected PACKET_TO_HELPER")
        }
        guard let packet = envelope.payload["packet"] as? Data else {
            throw ObstacleBridgeTunHelperCommandError.invalidPayload("PACKET_TO_HELPER requires Data packet")
        }
        return packet
    }

    private static func intValue(from value: Any?, defaultValue: Int) -> Int {
        if let value = value as? Int {
            return value
        }
        if let value = value as? NSNumber {
            return value.intValue
        }
        if let value = value as? String, let parsed = Int(value) {
            return parsed
        }
        return defaultValue
    }
}

struct ObstacleBridgeTunHelperEventEnvelope {
    let event: String
    let payload: [String: Any]
    let sequence: Int

    init(event: String, payload: [String: Any], sequence: Int = 0) {
        self.event = event
        self.payload = payload
        self.sequence = max(0, sequence)
    }

    func xpcPayload() -> [String: Any] {
        [
            "frame_kind": ObstacleBridgeTunHelperFrameKind.event.rawValue,
            "seq": sequence,
            "payload": [
                "event": event,
                "payload": payload,
            ],
        ]
    }

    static func decode(_ message: [String: Any]) throws -> ObstacleBridgeTunHelperEventEnvelope {
        guard let kindName = message["frame_kind"] as? String,
              let frameKind = ObstacleBridgeTunHelperFrameKind(rawValue: kindName) else {
            throw ObstacleBridgeTunHelperCommandError.unsupportedFrame("unsupported helper frame")
        }
        guard frameKind == .event else {
            throw ObstacleBridgeTunHelperCommandError.unsupportedFrame("expected EVENT")
        }
        guard let body = message["payload"] as? [String: Any],
              let event = body["event"] as? String,
              !event.isEmpty else {
            throw ObstacleBridgeTunHelperCommandError.invalidPayload("EVENT requires event")
        }
        let payload = body["payload"] as? [String: Any] ?? [:]
        let sequence = Self.intValue(from: message["seq"], defaultValue: 0)
        return ObstacleBridgeTunHelperEventEnvelope(event: event, payload: payload, sequence: sequence)
    }

    private static func intValue(from value: Any?, defaultValue: Int) -> Int {
        if let value = value as? Int {
            return value
        }
        if let value = value as? NSNumber {
            return value.intValue
        }
        if let value = value as? String, let parsed = Int(value) {
            return parsed
        }
        return defaultValue
    }
}

struct ObstacleBridgeTunHelperOpenRequest {
    let requestedIfname: String
    let mtu: Int

    func payload() -> [String: Any] {
        [
            "ifname": requestedIfname,
            "mtu": mtu,
        ]
    }
}

struct ObstacleBridgeTunHelperNetworkRequest {
    let ifname: String
    let mtu: Int
    let tunRouting: [String: Any]
    let listenerHookEnv: [String: String]

    func payload() -> [String: Any] {
        [
            "ifname": ifname,
            "mtu": mtu,
            "tun_routing": tunRouting,
            "listener_hook_env": listenerHookEnv,
        ]
    }
}

struct ObstacleBridgeTunHelperRuntimeSnapshot {
    var backend: String = ObstacleBridgeTunHelperPlatformScope.macOSBackend
    var requestedIfname: String = ""
    var ifname: String = ""
    var mtu: Int = 0
    var opened = false
    var networkApplied = false
    var packetsFromRuntime = 0
    var packetsToRuntime = 0
    var applyCalls = 0
    var removeCalls = 0
    var lastApplyPayload: [String: Any] = [:]
    var lastRemovePayload: [String: Any] = [:]
    var lastHookAction = ""
    var lastHookArgv: [String] = []
    var lastHookEnv: [String: String] = [:]
    var lastFailure: [String: Any] = [:]
    var stopped = false
    var cleanupAttempted = false
    var cleanupOK = false

    mutating func markOpened(requestedIfname: String, actualIfname: String, mtu: Int) {
        self.requestedIfname = requestedIfname
        self.ifname = actualIfname
        self.mtu = mtu
        self.opened = true
        self.stopped = false
        self.cleanupAttempted = false
        self.cleanupOK = false
    }

    mutating func markNetworkApplied(action: String, argv: [String], env: [String: String]) {
        self.networkApplied = action == "up" || action == "on_created" || action == "on_channel_connected"
        self.lastHookAction = action
        self.lastHookArgv = argv
        self.lastHookEnv = env
        if self.networkApplied {
            self.applyCalls += 1
            self.lastApplyPayload = ["action": action, "argv": argv, "env": env]
        } else {
            self.removeCalls += 1
            self.lastRemovePayload = ["action": action, "argv": argv, "env": env]
        }
        self.lastFailure = [:]
    }

    mutating func markFailure(stage: String, error: String) {
        self.lastFailure = [
            "stage": stage,
            "error": error,
        ]
    }

    mutating func recordPacketFromRuntime() {
        packetsFromRuntime += 1
    }

    mutating func recordPacketToRuntime() {
        packetsToRuntime += 1
    }

    func payload() -> [String: Any] {
        [
            "backend": backend,
            "requested_ifname": requestedIfname,
            "ifname": ifname,
            "mtu": mtu,
            "opened": opened,
            "network_applied": networkApplied,
            "apply_calls": applyCalls,
            "remove_calls": removeCalls,
            "last_apply_payload": lastApplyPayload,
            "last_remove_payload": lastRemovePayload,
            "packets_from_runtime": packetsFromRuntime,
            "packets_to_runtime": packetsToRuntime,
            "last_hook_action": lastHookAction,
            "last_hook_argv": lastHookArgv,
            "last_hook_env": lastHookEnv,
            "last_failure": lastFailure,
            "stopped": stopped,
            "cleanup_attempted": cleanupAttempted,
            "cleanup_ok": cleanupOK,
        ]
    }
}

protocol ObstacleBridgeTunHelperClienting: AnyObject {
    var requestedIfname: String { get }
    var actualIfname: String { get }
    var mtu: Int { get }
    var isOpen: Bool { get }
    var runtimeSnapshot: ObstacleBridgeTunHelperRuntimeSnapshot { get }
    var transportKind: String { get }

    @discardableResult
    func openTun(_ request: ObstacleBridgeTunHelperOpenRequest) throws -> [String: Any]
    func applyNetwork(action: String, argv: [String], env: [String: String])
    func removeNetwork(action: String, argv: [String], env: [String: String])
    func writePacket(_ packet: Data) throws
    func recordFailure(stage: String, error: String)
    func stop()
}

final class ObstacleBridgeInProcessMacOSTunHelperClient: ObstacleBridgeTunHelperClienting {
    private let queue: DispatchQueue
    private let packetSink: (Data) -> Void
    private let eventSink: ((String, [String: Any]) -> Void)?
    private var adapter: ObstacleBridgeMacOSTunAdapter?
    private(set) var runtimeSnapshot = ObstacleBridgeTunHelperRuntimeSnapshot()

    init(
        queue: DispatchQueue,
        packetSink: @escaping (Data) -> Void,
        eventSink: ((String, [String: Any]) -> Void)? = nil
    ) {
        self.queue = queue
        self.packetSink = packetSink
        self.eventSink = eventSink
    }

    var requestedIfname: String {
        adapter?.requestedIfname ?? runtimeSnapshot.requestedIfname
    }

    var actualIfname: String {
        adapter?.actualIfname ?? runtimeSnapshot.ifname
    }

    var mtu: Int {
        adapter?.mtu ?? runtimeSnapshot.mtu
    }

    var isOpen: Bool {
        runtimeSnapshot.opened && adapter != nil
    }

    var transportKind: String {
        "in_process"
    }

    @discardableResult
    func openTun(_ request: ObstacleBridgeTunHelperOpenRequest) throws -> [String: Any] {
        if isOpen,
           requestedIfname == request.requestedIfname,
           mtu == request.mtu {
            return runtimeSnapshot.payload()
        }
        stop()
        let tunAdapter = ObstacleBridgeMacOSTunAdapter(
            ifname: request.requestedIfname,
            mtu: request.mtu,
            queue: queue,
            packetSink: { [weak self] packet in
                guard let self else { return }
                self.emitPacketFromHelper(packet)
            },
            eventSink: { [weak self] event, payload in
                self?.emitEventFromHelper(event: event, payload: payload)
            }
        )
        try tunAdapter.start()
        adapter = tunAdapter
        runtimeSnapshot.markOpened(
            requestedIfname: request.requestedIfname,
            actualIfname: tunAdapter.actualIfname,
            mtu: request.mtu
        )
        return runtimeSnapshot.payload()
    }

    private func emitPacketFromHelper(_ packet: Data) {
        do {
            let envelope = ObstacleBridgeTunHelperPacketEnvelope.packetFromHelper(packet)
            let runtimePacket = try ObstacleBridgeTunHelperPacketEnvelope.packetFromHelperPacket(
                from: envelope.xpcPayload()
            )
            runtimeSnapshot.recordPacketToRuntime()
            packetSink(runtimePacket)
        } catch {
            recordFailure(stage: "packet_from_helper", error: error.localizedDescription)
        }
    }

    private func emitEventFromHelper(event: String, payload: [String: Any]) {
        guard let eventSink else { return }
        do {
            let envelope = ObstacleBridgeTunHelperEventEnvelope(event: event, payload: payload)
            let decoded = try ObstacleBridgeTunHelperEventEnvelope.decode(envelope.xpcPayload())
            eventSink(decoded.event, decoded.payload)
        } catch {
            recordFailure(stage: "event_from_helper", error: error.localizedDescription)
        }
    }

    func applyNetwork(action: String, argv: [String], env: [String: String]) {
        runHook(action: action, argv: argv, env: env, removing: false)
    }

    func removeNetwork(action: String, argv: [String], env: [String: String]) {
        runHook(action: action, argv: argv, env: env, removing: true)
    }

    func writePacket(_ packet: Data) throws {
        guard let adapter else { return }
        try adapter.write(packet: packet)
        runtimeSnapshot.recordPacketFromRuntime()
    }

    func recordFailure(stage: String, error: String) {
        runtimeSnapshot.markFailure(stage: stage, error: error)
    }

    private func runHook(action: String, argv: [String], env: [String: String], removing: Bool) {
        guard let executable = argv.first, !executable.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            runtimeSnapshot.markNetworkApplied(action: action, argv: argv, env: env)
            if removing {
                runtimeSnapshot.networkApplied = false
            }
            return
        }
#if os(macOS)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = Array(argv.dropFirst())
        var processEnv = ProcessInfo.processInfo.environment
        for (key, value) in env {
            processEnv[key] = value
        }
        process.environment = processEnv
        let outputPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = outputPipe
        do {
            try process.run()
            process.waitUntilExit()
            let data = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            emitEventFromHelper(event: "macos_tun_hook_completed", payload: [
                "action": action,
                "argv": argv,
                "status": Int(process.terminationStatus),
                "output": output,
            ])
            if process.terminationStatus == 0 {
                runtimeSnapshot.markNetworkApplied(action: action, argv: argv, env: env)
                if removing {
                    runtimeSnapshot.networkApplied = false
                }
            } else {
                runtimeSnapshot.markFailure(
                    stage: "macos_tun_hook_\(action)",
                    error: "exit_status=\(process.terminationStatus)"
                )
            }
        } catch {
            runtimeSnapshot.markFailure(stage: "macos_tun_hook_\(action)", error: error.localizedDescription)
        }
#else
        runtimeSnapshot.markFailure(
            stage: "macos_tun_hook_\(action)",
            error: "macOS TUN hook execution is not available on iOS"
        )
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

final class ObstacleBridgeTunHelperCommandServer {
    private let backend: ObstacleBridgeTunHelperClienting

    init(backend: ObstacleBridgeTunHelperClienting) {
        self.backend = backend
    }

    func handle(command: ObstacleBridgeTunHelperCommand, payload: [String: Any]) throws -> [String: Any] {
        let body: [String: Any]
        switch command {
        case .openTun:
            let request = try openRequest(from: payload)
            body = try backend.openTun(request)
        case .applyNetwork:
            let action = Self.stringValue(from: payload["action"], defaultValue: "up")
            backend.applyNetwork(
                action: action,
                argv: Self.stringArray(from: payload["argv"]),
                env: Self.stringMap(from: payload["env"])
            )
            body = backend.runtimeSnapshot.payload()
        case .removeNetwork:
            let action = Self.stringValue(from: payload["action"], defaultValue: "down")
            backend.removeNetwork(
                action: action,
                argv: Self.stringArray(from: payload["argv"]),
                env: Self.stringMap(from: payload["env"])
            )
            body = backend.runtimeSnapshot.payload()
        case .writePacket:
            guard let packet = payload["packet"] as? Data else {
                throw ObstacleBridgeTunHelperCommandError.invalidPayload("WRITE_PACKET requires Data packet")
            }
            try backend.writePacket(packet)
            body = backend.runtimeSnapshot.payload()
        case .snapshot:
            body = backend.runtimeSnapshot.payload()
        case .stop:
            backend.stop()
            body = backend.runtimeSnapshot.payload()
        }
        return [
            "ok": true,
            "op": command.rawValue,
            "payload": body,
        ]
    }

    func handleXPCPayload(_ message: [String: Any]) throws -> [String: Any] {
        let envelope = try ObstacleBridgeTunHelperCommandEnvelope.decode(message)
        var response = try handle(command: envelope.command, payload: envelope.payload)
        response["seq"] = envelope.sequence
        return response
    }

    func handleXPCPacketPayload(_ message: [String: Any]) throws -> [String: Any] {
        let envelope = try ObstacleBridgeTunHelperPacketEnvelope.decode(message)
        guard envelope.frameKind == .packetToHelper else {
            throw ObstacleBridgeTunHelperCommandError.unsupportedFrame("expected PACKET_TO_HELPER")
        }
        guard let packet = envelope.payload["packet"] as? Data else {
            throw ObstacleBridgeTunHelperCommandError.invalidPayload("PACKET_TO_HELPER requires Data packet")
        }
        var response = try handle(command: .writePacket, payload: ["packet": packet])
        response["seq"] = envelope.sequence
        return response
    }

    private func openRequest(from payload: [String: Any]) throws -> ObstacleBridgeTunHelperOpenRequest {
        let ifname = Self.stringValue(from: payload["ifname"], defaultValue: "")
        guard !ifname.isEmpty else {
            throw ObstacleBridgeTunHelperCommandError.invalidPayload("OPEN_TUN requires ifname")
        }
        let mtu = Self.intValue(from: payload["mtu"], defaultValue: 0)
        guard mtu > 0 else {
            throw ObstacleBridgeTunHelperCommandError.invalidPayload("OPEN_TUN requires positive mtu")
        }
        return ObstacleBridgeTunHelperOpenRequest(requestedIfname: ifname, mtu: mtu)
    }

    private static func stringValue(from value: Any?, defaultValue: String) -> String {
        if let value = value as? String {
            return value
        }
        if let value {
            return String(describing: value)
        }
        return defaultValue
    }

    private static func intValue(from value: Any?, defaultValue: Int) -> Int {
        if let value = value as? Int {
            return value
        }
        if let value = value as? NSNumber {
            return value.intValue
        }
        if let value = value as? String, let parsed = Int(value) {
            return parsed
        }
        return defaultValue
    }

    private static func stringArray(from value: Any?) -> [String] {
        guard let values = value as? [Any] else {
            return []
        }
        return values.map { String(describing: $0) }
    }

    private static func stringMap(from value: Any?) -> [String: String] {
        guard let values = value as? [String: Any] else {
            return [:]
        }
        var result: [String: String] = [:]
        for (key, value) in values {
            result[key] = String(describing: value)
        }
        return result
    }
}

protocol ObstacleBridgeTunHelperCommandTransport {
    func send(command: ObstacleBridgeTunHelperCommand, payload: [String: Any]) throws -> [String: Any]
    func sendPacketToHelper(_ packet: Data) throws -> [String: Any]
}

final class ObstacleBridgeLoopbackTunHelperCommandTransport: ObstacleBridgeTunHelperCommandTransport {
    private let server: ObstacleBridgeTunHelperCommandServer

    init(server: ObstacleBridgeTunHelperCommandServer) {
        self.server = server
    }

    func send(command: ObstacleBridgeTunHelperCommand, payload: [String: Any]) throws -> [String: Any] {
        try server.handle(command: command, payload: payload)
    }

    func sendPacketToHelper(_ packet: Data) throws -> [String: Any] {
        let envelope = ObstacleBridgeTunHelperPacketEnvelope.packetToHelper(packet)
        return try server.handleXPCPacketPayload(envelope.xpcPayload())
    }
}

final class ObstacleBridgeXPCShapedTunHelperCommandTransport: ObstacleBridgeTunHelperCommandTransport {
    private let sendEnvelope: ([String: Any]) throws -> [String: Any]
    private let sendPacketEnvelope: ([String: Any]) throws -> [String: Any]
    private var nextSequence = 0

    init(
        sendEnvelope: @escaping ([String: Any]) throws -> [String: Any],
        sendPacketEnvelope: @escaping ([String: Any]) throws -> [String: Any]
    ) {
        self.sendEnvelope = sendEnvelope
        self.sendPacketEnvelope = sendPacketEnvelope
    }

    convenience init(server: ObstacleBridgeTunHelperCommandServer) {
        self.init(
            sendEnvelope: { message in
                try server.handleXPCPayload(message)
            },
            sendPacketEnvelope: { message in
                try server.handleXPCPacketPayload(message)
            }
        )
    }

    func send(command: ObstacleBridgeTunHelperCommand, payload: [String: Any]) throws -> [String: Any] {
        let sequence = nextOperationSequence()
        let envelope = ObstacleBridgeTunHelperCommandEnvelope(command: command, payload: payload, sequence: sequence)
        let response = try sendEnvelope(envelope.xpcPayload())
        guard (response["ok"] as? Bool) == true else {
            throw ObstacleBridgeTunHelperCommandError.invalidResponse("helper command failed")
        }
        guard response["op"] as? String == command.rawValue else {
            throw ObstacleBridgeTunHelperCommandError.invalidResponse("helper response command mismatch")
        }
        guard Self.intValue(from: response["seq"], defaultValue: -1) == sequence else {
            throw ObstacleBridgeTunHelperCommandError.invalidResponse("helper response sequence mismatch")
        }
        guard response["payload"] is [String: Any] else {
            throw ObstacleBridgeTunHelperCommandError.invalidResponse("helper response missing payload")
        }
        return response
    }

    func sendPacketToHelper(_ packet: Data) throws -> [String: Any] {
        let sequence = nextOperationSequence()
        let envelope = ObstacleBridgeTunHelperPacketEnvelope.packetToHelper(packet, sequence: sequence)
        let response = try sendPacketEnvelope(envelope.xpcPayload())
        guard (response["ok"] as? Bool) == true else {
            throw ObstacleBridgeTunHelperCommandError.invalidResponse("helper packet write failed")
        }
        guard response["op"] as? String == ObstacleBridgeTunHelperCommand.writePacket.rawValue else {
            throw ObstacleBridgeTunHelperCommandError.invalidResponse("helper packet response command mismatch")
        }
        guard Self.intValue(from: response["seq"], defaultValue: -1) == sequence else {
            throw ObstacleBridgeTunHelperCommandError.invalidResponse("helper packet response sequence mismatch")
        }
        guard response["payload"] is [String: Any] else {
            throw ObstacleBridgeTunHelperCommandError.invalidResponse("helper packet response missing payload")
        }
        return response
    }

    private func nextOperationSequence() -> Int {
        nextSequence += 1
        return nextSequence
    }

    private static func intValue(from value: Any?, defaultValue: Int) -> Int {
        if let value = value as? Int {
            return value
        }
        if let value = value as? NSNumber {
            return value.intValue
        }
        if let value = value as? String, let parsed = Int(value) {
            return parsed
        }
        return defaultValue
    }
}

final class ObstacleBridgeLoopbackTunHelperClient: ObstacleBridgeTunHelperClienting {
    private let transport: ObstacleBridgeTunHelperCommandTransport
    private let operationQueue = DispatchQueue(label: "ObstacleBridgeTunHelperClient.Operations")
    let transportKind: String
    private(set) var runtimeSnapshot = ObstacleBridgeTunHelperRuntimeSnapshot()

    init(transport: ObstacleBridgeTunHelperCommandTransport, transportKind: String = "loopback") {
        self.transport = transport
        self.transportKind = transportKind
    }

    var requestedIfname: String {
        runtimeSnapshot.requestedIfname
    }

    var actualIfname: String {
        runtimeSnapshot.ifname
    }

    var mtu: Int {
        runtimeSnapshot.mtu
    }

    var isOpen: Bool {
        runtimeSnapshot.opened
    }

    @discardableResult
    func openTun(_ request: ObstacleBridgeTunHelperOpenRequest) throws -> [String: Any] {
        try serialized {
            try applyResponse(transport.send(command: .openTun, payload: request.payload()))
        }
    }

    func applyNetwork(action: String, argv: [String], env: [String: String]) {
        serialized {
            guard runtimeSnapshot.opened, !runtimeSnapshot.ifname.isEmpty else {
                recordFailureUnlocked(stage: "apply_network", error: "TUN helper is not open")
                return
            }
            do {
                _ = try applyResponse(transport.send(
                    command: .applyNetwork,
                    payload: ["action": action, "argv": argv, "env": env]
                ))
            } catch {
                recordFailureUnlocked(stage: "apply_network", error: error.localizedDescription)
            }
        }
    }

    func removeNetwork(action: String, argv: [String], env: [String: String]) {
        serialized {
            do {
                _ = try applyResponse(transport.send(
                    command: .removeNetwork,
                    payload: ["action": action, "argv": argv, "env": env]
                ))
            } catch {
                recordFailureUnlocked(stage: "remove_network", error: error.localizedDescription)
            }
        }
    }

    func writePacket(_ packet: Data) throws {
        try serialized {
            guard runtimeSnapshot.opened, !runtimeSnapshot.ifname.isEmpty else {
                recordFailureUnlocked(stage: "write_packet", error: "TUN helper is not open")
                throw ObstacleBridgeTunHelperCommandError.invalidResponse("TUN helper is not open")
            }
            try applyResponse(transport.sendPacketToHelper(packet))
        }
    }

    func recordFailure(stage: String, error: String) {
        serialized {
            recordFailureUnlocked(stage: stage, error: error)
        }
    }

    func stop() {
        serialized {
            do {
                _ = try applyResponse(transport.send(command: .stop, payload: [:]))
            } catch {
                recordFailureUnlocked(stage: "stop", error: error.localizedDescription)
            }
        }
    }

    @discardableResult
    private func serialized<T>(_ body: () throws -> T) rethrows -> T {
        try operationQueue.sync(execute: body)
    }

    private func serialized(_ body: () -> Void) {
        operationQueue.sync(execute: body)
    }

    private func recordFailureUnlocked(stage: String, error: String) {
        runtimeSnapshot.markFailure(stage: stage, error: error)
    }

    @discardableResult
    private func applyResponse(_ response: [String: Any]) throws -> [String: Any] {
        guard (response["ok"] as? Bool) == true,
              let payload = response["payload"] as? [String: Any] else {
            throw ObstacleBridgeTunHelperCommandError.invalidPayload("invalid helper response")
        }
        runtimeSnapshot = Self.snapshot(from: payload, fallback: runtimeSnapshot)
        return payload
    }

    private static func snapshot(
        from payload: [String: Any],
        fallback: ObstacleBridgeTunHelperRuntimeSnapshot
    ) -> ObstacleBridgeTunHelperRuntimeSnapshot {
        var snapshot = fallback
        snapshot.backend = payload["backend"] as? String ?? snapshot.backend
        snapshot.requestedIfname = payload["requested_ifname"] as? String ?? snapshot.requestedIfname
        snapshot.ifname = payload["ifname"] as? String ?? snapshot.ifname
        snapshot.mtu = payload["mtu"] as? Int ?? snapshot.mtu
        snapshot.opened = payload["opened"] as? Bool ?? snapshot.opened
        snapshot.networkApplied = payload["network_applied"] as? Bool ?? snapshot.networkApplied
        snapshot.applyCalls = payload["apply_calls"] as? Int ?? snapshot.applyCalls
        snapshot.removeCalls = payload["remove_calls"] as? Int ?? snapshot.removeCalls
        snapshot.lastApplyPayload = payload["last_apply_payload"] as? [String: Any] ?? snapshot.lastApplyPayload
        snapshot.lastRemovePayload = payload["last_remove_payload"] as? [String: Any] ?? snapshot.lastRemovePayload
        snapshot.packetsFromRuntime = payload["packets_from_runtime"] as? Int ?? snapshot.packetsFromRuntime
        snapshot.packetsToRuntime = payload["packets_to_runtime"] as? Int ?? snapshot.packetsToRuntime
        snapshot.lastHookAction = payload["last_hook_action"] as? String ?? snapshot.lastHookAction
        snapshot.lastHookArgv = payload["last_hook_argv"] as? [String] ?? snapshot.lastHookArgv
        snapshot.lastHookEnv = payload["last_hook_env"] as? [String: String] ?? snapshot.lastHookEnv
        snapshot.lastFailure = payload["last_failure"] as? [String: Any] ?? snapshot.lastFailure
        snapshot.stopped = payload["stopped"] as? Bool ?? snapshot.stopped
        snapshot.cleanupAttempted = payload["cleanup_attempted"] as? Bool ?? snapshot.cleanupAttempted
        snapshot.cleanupOK = payload["cleanup_ok"] as? Bool ?? snapshot.cleanupOK
        return snapshot
    }
}
