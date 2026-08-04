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
        let connection = NSXPCConnection(machServiceName: machServiceName, options: [])
        connection.remoteObjectInterface = interface()
        defer {
            connection.invalidate()
        }
        connection.resume()
        let semaphore = DispatchSemaphore(value: 0)
        var response: [String: Any] = [:]
        var lastError = ""
        let proxy = connection.remoteObjectProxyWithErrorHandler { error in
            lastError = error.localizedDescription
            semaphore.signal()
        } as? ObstacleBridgeTunHelperXPCServicing
        guard let proxy else {
            return [
                "ok": false,
                "error": "helper XPC proxy unavailable",
            ]
        }
        proxy.ping { payload in
            response = payload as? [String: Any] ?? [:]
            semaphore.signal()
        }
        if semaphore.wait(timeout: .now() + timeout) == .timedOut {
            return [
                "ok": false,
                "error": "helper XPC ping timed out",
            ]
        }
        if !lastError.isEmpty {
            return [
                "ok": false,
                "error": lastError,
            ]
        }
        return response
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
        self.connection = NSXPCConnection(machServiceName: machServiceName, options: [])
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
        let sequence = nextOperationSequence()
        let envelope = ObstacleBridgeTunHelperCommandEnvelope(
            command: command,
            payload: payload,
            sequence: sequence
        )
        let response = try sendRequest { proxy, reply in
            proxy.handleCommand(envelope.xpcPayload() as NSDictionary, withReply: reply)
        }
        try validateResponse(
            response,
            expectedOperation: command.rawValue,
            expectedSequence: sequence,
            packetResponse: false
        )
        return response
    }

    func sendPacketToHelper(_ packet: Data) throws -> [String: Any] {
        let sequence = nextOperationSequence()
        let envelope = ObstacleBridgeTunHelperPacketEnvelope.packetToHelper(packet, sequence: sequence)
        let response = try sendRequest { proxy, reply in
            proxy.handlePacketToHelper(envelope.xpcPayload() as NSDictionary, withReply: reply)
        }
        try validateResponse(
            response,
            expectedOperation: ObstacleBridgeTunHelperCommand.writePacket.rawValue,
            expectedSequence: sequence,
            packetResponse: true
        )
        return response
    }

    private func sendRequest(
        _ sender: (ObstacleBridgeTunHelperXPCServicing, @escaping (NSDictionary) -> Void) -> Void
    ) throws -> [String: Any] {
        let semaphore = DispatchSemaphore(value: 0)
        var response: [String: Any] = [:]
        var failure = ""
        let proxy = connection.remoteObjectProxyWithErrorHandler { error in
            failure = error.localizedDescription
            semaphore.signal()
        } as? ObstacleBridgeTunHelperXPCServicing
        guard let proxy else {
            throw ObstacleBridgeTunHelperCommandError.invalidResponse("helper XPC proxy unavailable")
        }
        sender(proxy) { payload in
            response = payload as? [String: Any] ?? [:]
            semaphore.signal()
        }
        if semaphore.wait(timeout: .now() + timeout) == .timedOut {
            throw ObstacleBridgeTunHelperCommandError.invalidResponse("helper XPC request timed out")
        }
        if !failure.isEmpty {
            throw ObstacleBridgeTunHelperCommandError.invalidResponse(failure)
        }
        return response
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
