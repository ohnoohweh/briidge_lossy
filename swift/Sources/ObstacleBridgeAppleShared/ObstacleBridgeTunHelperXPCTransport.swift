import Foundation

#if os(macOS)
@objc protocol ObstacleBridgeTunHelperXPCServicing {
    func ping(_ reply: @escaping (NSDictionary) -> Void)
    func handleCommand(_ message: NSDictionary, withReply reply: @escaping (NSDictionary) -> Void)
    func handlePacketToHelper(_ message: NSDictionary, withReply reply: @escaping (NSDictionary) -> Void)
}

@objc protocol ObstacleBridgeTunHelperXPCClientCallbacks {
    func handlePacketFromHelper(_ message: NSDictionary)
    func handleEventFromHelper(_ message: NSDictionary)
}

enum ObstacleBridgeTunHelperXPC {
    static let requestTimeoutSeconds: TimeInterval = 15.0
    private static let reachabilityLock = NSLock()
    private static var cachedReachability: [String: Any] = [
        "ok": false,
        "error": "helper XPC reachability check pending",
    ]

    static func interface() -> NSXPCInterface {
        NSXPCInterface(with: ObstacleBridgeTunHelperXPCServicing.self)
    }

    static func callbackInterface() -> NSXPCInterface {
        NSXPCInterface(with: ObstacleBridgeTunHelperXPCClientCallbacks.self)
    }

    static func ping(
        machServiceName: String = ObstacleBridgeMacOSTunHelperService.xpcMachServiceName,
        timeout: TimeInterval = 0.25
    ) -> [String: Any] {
        ping(machServiceName: machServiceName, timeout: timeout) { _ in }
        reachabilityLock.lock()
        defer { reachabilityLock.unlock() }
        return cachedReachability
    }

    static func ping(
        machServiceName: String = ObstacleBridgeMacOSTunHelperService.xpcMachServiceName,
        timeout: TimeInterval = 0.25,
        completion: @escaping ([String: Any]) -> Void
    ) {
        let connection = NSXPCConnection(machServiceName: machServiceName, options: [.privileged])
        connection.remoteObjectInterface = interface()
        let finishLock = NSLock()
        var finished = false
        func finish(_ result: [String: Any]) {
            finishLock.lock()
            defer { finishLock.unlock() }
            guard !finished else { return }
            finished = true
            reachabilityLock.lock()
            cachedReachability = result
            reachabilityLock.unlock()
            connection.invalidate()
            completion(result)
        }
        connection.resume()
        let proxy = connection.remoteObjectProxyWithErrorHandler { error in
            finish(["ok": false, "error": error.localizedDescription])
        } as? ObstacleBridgeTunHelperXPCServicing
        guard let proxy else {
            finish(["ok": false, "error": "helper XPC proxy unavailable"])
            return
        }
        proxy.ping { payload in
            finish(payload as? [String: Any] ?? ["ok": false, "error": "helper XPC ping returned invalid payload"])
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
            finish(["ok": false, "error": "helper XPC ping timed out"])
        }
    }
}

final class ObstacleBridgeNSXPCTunHelperCommandTransport: ObstacleBridgeTunHelperCommandTransport {
    private let connection: NSXPCConnection
    private let callbackHandler: ObstacleBridgeTunHelperXPCClientCallbackHandler?
    private let timeout: TimeInterval
    private var nextSequence = 0

    init(
        machServiceName: String = ObstacleBridgeMacOSTunHelperService.xpcMachServiceName,
        timeout: TimeInterval = ObstacleBridgeTunHelperXPC.requestTimeoutSeconds,
        packetSink: ((Data) -> Void)? = nil,
        eventSink: ((String, [String: Any]) -> Void)? = nil
    ) {
        self.connection = NSXPCConnection(machServiceName: machServiceName, options: [.privileged])
        self.connection.remoteObjectInterface = ObstacleBridgeTunHelperXPC.interface()
        if packetSink != nil || eventSink != nil {
            let handler = ObstacleBridgeTunHelperXPCClientCallbackHandler(
                packetSink: packetSink,
                eventSink: eventSink
            )
            self.callbackHandler = handler
            self.connection.exportedInterface = ObstacleBridgeTunHelperXPC.callbackInterface()
            self.connection.exportedObject = handler
        } else {
            self.callbackHandler = nil
        }
        self.timeout = timeout
        self.connection.resume()
    }

    deinit {
        connection.invalidate()
    }

    func send(command: ObstacleBridgeTunHelperCommand, payload: [String: Any]) throws -> [String: Any] {
        throw ObstacleBridgeTunHelperCommandError.invalidResponse("XPC commands require completion-based lifecycle ownership")
    }

    func sendPacketToHelper(_ packet: Data) throws -> [String: Any] {
        throw ObstacleBridgeTunHelperCommandError.invalidResponse("XPC packet writes require completion-based lifecycle ownership")
    }

    func send(command: ObstacleBridgeTunHelperCommand, payload: [String: Any], completion: @escaping (Result<[String: Any], Error>) -> Void) {
        let sequence = nextOperationSequence()
        let envelope = ObstacleBridgeTunHelperCommandEnvelope(
            command: command,
            payload: payload,
            sequence: sequence
        )
        sendRequest({ proxy, reply in
            proxy.handleCommand(envelope.xpcPayload() as NSDictionary, withReply: reply)
        }, expectedOperation: command.rawValue, expectedSequence: sequence, packetResponse: false, completion: completion)
    }

    func sendPacketToHelper(_ packet: Data, completion: @escaping (Result<[String: Any], Error>) -> Void) {
        let sequence = nextOperationSequence()
        let envelope = ObstacleBridgeTunHelperPacketEnvelope.packetToHelper(packet, sequence: sequence)
        sendRequest({ proxy, reply in
            proxy.handlePacketToHelper(envelope.xpcPayload() as NSDictionary, withReply: reply)
        }, expectedOperation: ObstacleBridgeTunHelperCommand.writePacket.rawValue, expectedSequence: sequence, packetResponse: true, completion: completion)
    }

    private func sendRequest(
        _ sender: (ObstacleBridgeTunHelperXPCServicing, @escaping (NSDictionary) -> Void) -> Void,
        expectedOperation: String,
        expectedSequence: Int,
        packetResponse: Bool,
        completion: @escaping (Result<[String: Any], Error>) -> Void
    ) {
        let completionLock = NSLock()
        var completed = false
        func finish(_ result: Result<[String: Any], Error>) {
            completionLock.lock()
            defer { completionLock.unlock() }
            guard !completed else { return }
            completed = true
            completion(result)
        }
        let proxy = connection.remoteObjectProxyWithErrorHandler { error in
            finish(.failure(ObstacleBridgeTunHelperCommandError.invalidResponse(error.localizedDescription)))
        } as? ObstacleBridgeTunHelperXPCServicing
        guard let proxy else {
            finish(.failure(ObstacleBridgeTunHelperCommandError.invalidResponse("helper XPC proxy unavailable")))
            return
        }
        sender(proxy) { payload in
            let response = payload as? [String: Any] ?? [:]
            do {
                try self.validateResponse(response, expectedOperation: expectedOperation, expectedSequence: expectedSequence, packetResponse: packetResponse)
                finish(.success(response))
            } catch { finish(.failure(error)) }
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
            finish(.failure(ObstacleBridgeTunHelperCommandError.invalidResponse("helper XPC request timed out")))
        }
    }

    private func validateResponse(
        _ response: [String: Any],
        expectedOperation: String,
        expectedSequence: Int,
        packetResponse: Bool
    ) throws {
        guard (response["ok"] as? Bool) == true else {
            let message = Self.responseErrorMessage(
                response,
                defaultMessage: packetResponse ? "helper packet write failed" : "helper command failed"
            )
            throw ObstacleBridgeTunHelperCommandError.invalidResponse(
                message
            )
        }
        guard response["op"] as? String == expectedOperation else {
            throw ObstacleBridgeTunHelperCommandError.invalidResponse(
                packetResponse ? "helper packet response command mismatch" : "helper response command mismatch"
            )
        }
        guard Self.intValue(from: response["seq"], defaultValue: -1) == expectedSequence else {
            throw ObstacleBridgeTunHelperCommandError.invalidResponse(
                packetResponse ? "helper packet response sequence mismatch" : "helper response sequence mismatch"
            )
        }
        guard response["payload"] is [String: Any] else {
            throw ObstacleBridgeTunHelperCommandError.invalidResponse(
                packetResponse ? "helper packet response missing payload" : "helper response missing payload"
            )
        }
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

    private static func responseErrorMessage(_ response: [String: Any], defaultMessage: String) -> String {
        if let error = response["error"] as? String, !error.isEmpty {
            return error
        }
        if let payload = response["payload"] as? [String: Any],
           let error = payload["error"] as? String,
           !error.isEmpty {
            return error
        }
        return defaultMessage
    }
}

/// Completion-owned client for the privileged helper.  `ObstacleBridgeHostRunner`
/// uses the completion methods below on its service-state queue; the inherited
/// synchronous witnesses reject use so XPC replies can never block that queue.
final class ObstacleBridgeAsyncXPCTunHelperClient: ObstacleBridgeTunHelperClienting {
    let transportKind: String
    private let transport: ObstacleBridgeNSXPCTunHelperCommandTransport
    private let stateLock = NSLock()
    private var snapshot = ObstacleBridgeTunHelperRuntimeSnapshot()

    init(transport: ObstacleBridgeNSXPCTunHelperCommandTransport, transportKind: String = "xpc") {
        self.transport = transport
        self.transportKind = transportKind
    }

    var requestedIfname: String { stateLock.withLock { snapshot.requestedIfname } }
    var actualIfname: String { stateLock.withLock { snapshot.ifname } }
    var mtu: Int { stateLock.withLock { snapshot.mtu } }
    var isOpen: Bool { stateLock.withLock { snapshot.opened } }
    var runtimeSnapshot: ObstacleBridgeTunHelperRuntimeSnapshot { stateLock.withLock { snapshot } }

    func openTun(_ request: ObstacleBridgeTunHelperOpenRequest, completion: @escaping (Result<[String: Any], Error>) -> Void) {
        send(command: .openTun, payload: request.payload(), completion: completion)
    }

    func applyNetwork(action: String, argv: [String], env: [String: String], completion: @escaping (Result<[String: Any], Error>) -> Void) {
        send(command: .applyNetwork, payload: ["action": action, "argv": argv, "env": env], completion: completion)
    }

    func removeNetwork(action: String, argv: [String], env: [String: String], completion: @escaping (Result<[String: Any], Error>) -> Void) {
        send(command: .removeNetwork, payload: ["action": action, "argv": argv, "env": env], completion: completion)
    }

    func writePacket(_ packet: Data, completion: @escaping (Result<[String: Any], Error>) -> Void) {
        transport.sendPacketToHelper(packet) { [weak self] result in
            completion(self?.apply(result) ?? .failure(ObstacleBridgeTunHelperCommandError.invalidResponse("XPC helper client released")))
        }
    }

    func stop(completion: @escaping (Result<[String: Any], Error>) -> Void) {
        send(command: .stop, payload: [:], completion: completion)
    }

    func recordFailure(stage: String, error: String) {
        stateLock.withLock { snapshot.markFailure(stage: stage, error: error) }
    }

    func openTun(_ request: ObstacleBridgeTunHelperOpenRequest) throws -> [String: Any] { throw synchronousUseError() }
    func applyNetwork(action: String, argv: [String], env: [String: String]) { recordFailure(stage: "apply_network", error: synchronousUseError().localizedDescription) }
    func removeNetwork(action: String, argv: [String], env: [String: String]) { recordFailure(stage: "remove_network", error: synchronousUseError().localizedDescription) }
    func writePacket(_ packet: Data) throws { throw synchronousUseError() }
    func stop() { recordFailure(stage: "stop", error: synchronousUseError().localizedDescription) }

    private func send(command: ObstacleBridgeTunHelperCommand, payload: [String: Any], completion: @escaping (Result<[String: Any], Error>) -> Void) {
        transport.send(command: command, payload: payload) { [weak self] result in
            completion(self?.apply(result) ?? .failure(ObstacleBridgeTunHelperCommandError.invalidResponse("XPC helper client released")))
        }
    }

    private func apply(_ result: Result<[String: Any], Error>) -> Result<[String: Any], Error> {
        switch result {
        case .failure(let error): return .failure(error)
        case .success(let response):
            guard let payload = response["payload"] as? [String: Any] else {
                return .failure(ObstacleBridgeTunHelperCommandError.invalidResponse("helper response missing payload"))
            }
            stateLock.withLock { snapshot = Self.snapshot(from: payload, fallback: snapshot) }
            return .success(payload)
        }
    }

    private func synchronousUseError() -> ObstacleBridgeTunHelperCommandError {
        .invalidResponse("XPC helper commands require completion-based lifecycle ownership")
    }

    private static func snapshot(from payload: [String: Any], fallback: ObstacleBridgeTunHelperRuntimeSnapshot) -> ObstacleBridgeTunHelperRuntimeSnapshot {
        var value = fallback
        value.backend = payload["backend"] as? String ?? value.backend
        value.requestedIfname = payload["requested_ifname"] as? String ?? value.requestedIfname
        value.ifname = payload["ifname"] as? String ?? value.ifname
        value.mtu = payload["mtu"] as? Int ?? value.mtu
        value.opened = payload["opened"] as? Bool ?? value.opened
        value.networkApplied = payload["network_applied"] as? Bool ?? value.networkApplied
        value.applyCalls = payload["apply_calls"] as? Int ?? value.applyCalls
        return value
    }
}

final class ObstacleBridgeTunHelperXPCClientCallbackHandler: NSObject, ObstacleBridgeTunHelperXPCClientCallbacks {
    private let packetSink: ((Data) -> Void)?
    private let eventSink: ((String, [String: Any]) -> Void)?

    init(packetSink: ((Data) -> Void)?, eventSink: ((String, [String: Any]) -> Void)?) {
        self.packetSink = packetSink
        self.eventSink = eventSink
    }

    func handlePacketFromHelper(_ message: NSDictionary) {
        guard let packetSink else { return }
        do {
            let packet = try ObstacleBridgeTunHelperPacketEnvelope.packetFromHelperPacket(
                from: message as? [String: Any] ?? [:]
            )
            packetSink(packet)
        } catch {
            eventSink?("macos_tun_helper_xpc_packet_callback_failed", [
                "error": error.localizedDescription,
            ])
        }
    }

    func handleEventFromHelper(_ message: NSDictionary) {
        guard let eventSink else { return }
        do {
            let envelope = try ObstacleBridgeTunHelperEventEnvelope.decode(message as? [String: Any] ?? [:])
            eventSink(envelope.event, envelope.payload)
        } catch {
            eventSink("macos_tun_helper_xpc_event_callback_failed", [
                "error": error.localizedDescription,
            ])
        }
    }
}

final class ObstacleBridgeTunHelperXPCService: NSObject, ObstacleBridgeTunHelperXPCServicing {
    private var server: ObstacleBridgeTunHelperCommandServer!
    private var backend: ObstacleBridgeTunHelperClienting!
    private weak var connection: NSXPCConnection?

    override init() {
        super.init()
        configureBackend(connection: nil)
    }

    init(connection: NSXPCConnection?) {
        self.connection = connection
        super.init()
        configureBackend(connection: connection)
    }

    private func configureBackend(connection: NSXPCConnection?) {
        self.connection = connection
        let backend = ObstacleBridgeInProcessMacOSTunHelperClient(
            queue: DispatchQueue(label: "ObstacleBridgeTunHelperXPCService.Backend"),
            packetSink: { [weak self] packet in
                self?.sendPacketFromHelper(packet)
            },
            eventSink: { [weak self] event, payload in
                self?.sendEventFromHelper(event: event, payload: payload)
            }
        )
        self.backend = backend
        self.server = ObstacleBridgeTunHelperCommandServer(backend: backend)
    }

    init(backend: ObstacleBridgeTunHelperClienting) {
        super.init()
        self.backend = backend
        self.server = ObstacleBridgeTunHelperCommandServer(backend: backend)
    }

    init(server: ObstacleBridgeTunHelperCommandServer, backend: ObstacleBridgeTunHelperClienting) {
        super.init()
        self.server = server
        self.backend = backend
    }

    func ping(_ reply: @escaping (NSDictionary) -> Void) {
        reply([
            "ok": true,
            "implemented": true,
            "bundle_identifier": ObstacleBridgeMacOSTunHelperService.helperBundleIdentifier,
            "helper_version": ObstacleBridgeMacOSTunHelperService.expectedHelperVersion,
            "python_helper_protocol_version": ObstacleBridgeMacOSTunHelperService.pythonHelperProtocolVersion,
            "helper_pid": ProcessInfo.processInfo.processIdentifier,
            "backend": backend.runtimeSnapshot.backend,
            "runtime": backend.runtimeSnapshot.payload(),
            "supported_commands": ObstacleBridgeTunHelperCommand.allCases.map { $0.rawValue },
            "supported_frame_kinds": ObstacleBridgeTunHelperFrameKind.allCases.map { $0.rawValue },
        ])
    }

    func handleCommand(_ message: NSDictionary, withReply reply: @escaping (NSDictionary) -> Void) {
        let raw = message as? [String: Any] ?? [:]
        do {
            reply(try server.handleXPCPayload(raw) as NSDictionary)
        } catch {
            reply(errorResponse(op: "UNKNOWN", sequence: sequence(from: raw), error: error.localizedDescription))
        }
    }

    func handlePacketToHelper(_ message: NSDictionary, withReply reply: @escaping (NSDictionary) -> Void) {
        let raw = message as? [String: Any] ?? [:]
        do {
            reply(try server.handleXPCPacketPayload(raw) as NSDictionary)
        } catch {
            reply(errorResponse(
                op: ObstacleBridgeTunHelperCommand.writePacket.rawValue,
                sequence: sequence(from: raw),
                error: error.localizedDescription
            ))
        }
    }

    private func sendPacketFromHelper(_ packet: Data) {
        let envelope = ObstacleBridgeTunHelperPacketEnvelope.packetFromHelper(packet)
        clientCallbackProxy()?.handlePacketFromHelper(envelope.xpcPayload() as NSDictionary)
    }

    private func sendEventFromHelper(event: String, payload: [String: Any]) {
        let envelope = ObstacleBridgeTunHelperEventEnvelope(event: event, payload: payload)
        clientCallbackProxy()?.handleEventFromHelper(envelope.xpcPayload() as NSDictionary)
    }

    private func clientCallbackProxy() -> ObstacleBridgeTunHelperXPCClientCallbacks? {
        connection?.remoteObjectProxyWithErrorHandler { error in
            NSLog("[ObstacleBridgeTunHelper][xpc_callback_failed] %@", error.localizedDescription)
        } as? ObstacleBridgeTunHelperXPCClientCallbacks
    }

    private func errorResponse(op: String, sequence: Int, error: String) -> NSDictionary {
        [
            "ok": false,
            "op": op,
            "seq": sequence,
            "payload": [
                "error": error,
            ],
        ] as NSDictionary
    }

    private func sequence(from raw: [String: Any]) -> Int {
        if let value = raw["seq"] as? Int {
            return value
        }
        if let value = raw["seq"] as? NSNumber {
            return value.intValue
        }
        if let value = raw["seq"] as? String, let parsed = Int(value) {
            return parsed
        }
        return 0
    }
}

final class ObstacleBridgeTunHelperXPCListenerDelegate: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        let service = ObstacleBridgeTunHelperXPCService(connection: newConnection)
        newConnection.exportedInterface = ObstacleBridgeTunHelperXPC.interface()
        newConnection.exportedObject = service
        newConnection.remoteObjectInterface = ObstacleBridgeTunHelperXPC.callbackInterface()
        newConnection.resume()
        return true
    }
}
#endif
