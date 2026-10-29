import CoreFoundation
import Foundation
import Darwin

/// Protocol-v1 native peer child. The inherited connected descriptor is both
/// configuration capability and owner-lifetime signal; no config path, secret
/// environment variable, or loopback listener is used for startup control.
enum ObstacleBridgeNativePeerWorker {
    private enum WorkerError: LocalizedError {
        case invalidFrame
        case invalidBootstrap
        case invalidDescriptor

        var errorDescription: String? { "invalid native peer worker request" }
    }

    static func run(controlFD: Int32, logFD: Int32? = nil) throws {
        guard controlFD >= 0, logFD != controlFD else { throw WorkerError.invalidDescriptor }
        try makeNonBlocking(controlFD)
        let control = FileHandle(fileDescriptor: controlFD, closeOnDealloc: true)
        var runner: ObstacleBridgeHostRunner?
        defer { runner?.stopPeerWorker() }
        do {
            let hello = try readFrame(control)
            guard kind(hello) == "worker.hello", hello["role"] as? String == "supervisor",
                  hello["capabilities"] as? [String] == ["peer.binary-data", "peer.control"], let helloGeneration = strictPositiveInt(hello["generation"])
            else { throw WorkerError.invalidBootstrap }
            try writeFrame(control, ["v": 1, "kind": "worker.hello", "role": "peer", "capabilities": ["peer.binary-data", "peer.control"], "generation": helloGeneration])
            let start = try readFrame(control)
            guard kind(start) == "peer.start",
                  let peerID = start["peer_id"] as? String, !peerID.isEmpty, peerID.count <= 128,
                  let generation = strictPositiveInt(start["generation"]), generation == helloGeneration,
                  let configuration = start["config"] as? [String: Any]
            else { throw WorkerError.invalidBootstrap }
            let rootLogLevel = ObstacleBridgeRuntimeConfig.privateWorkerLogLevel(from: start["log_root_level"])
            let producer = try logFD.map { try ObstacleBridgeLogProducer(inheritedFD: $0, minimumLevel: rootLogLevel) }
            let native = try ObstacleBridgeHostRunner(peerWorkerConfiguration: configuration, peerWorkerLogProducer: producer)
            try native.startPeerWorker()
            runner = native
            try writeFrame(control, ["v": ObstacleBridgeRuntimeConfig.isolatedWorkerProtocolVersion, "kind": "peer.ready", "peer_id": peerID,
                                     "generation": generation, "implementation": "native"])
            while true {
                let frame = try readIPCFrame(control)
                if frame.kind == .data {
                    guard frame.generation == UInt64(generation) else { throw WorkerError.invalidFrame }
                    try writeData(control, generation: generation, payload: frame.payload)
                    continue
                }
                let request = try controlFrame(frame)
                guard request["peer_id"] as? String == peerID,
                      strictPositiveInt(request["generation"]) == generation,
                      let identifier = request["id"] as? String, !identifier.isEmpty, identifier.count <= 128
                else { throw WorkerError.invalidFrame }
                switch kind(request) {
                case "peer.stop":
                    try writeFrame(control, ["v": 1, "kind": "peer.stopping", "peer_id": peerID,
                                             "generation": generation, "id": identifier])
                    return
                case "peer.snapshot":
                    let bundle = native.peerWorkerSnapshotBundle()
                    try writeFrame(control, ["v": 1, "kind": "peer.snapshot.reply", "peer_id": peerID,
                                             "generation": generation, "id": identifier,
                                             "status": bundle["status"] as Any,
                                             "connections": bundle["connections"] as Any,
                                             "peers": bundle["peers"] as Any])
                case "peer.control":
                    try writeFrame(control, ["v": 1, "kind": "peer.control.reply", "peer_id": peerID,
                                             "generation": generation, "id": identifier,
                                             "result": ["ok": false, "requested": 0,
                                                        "reason": "native_peer_control_not_supported"]])
                default:
                    throw WorkerError.invalidFrame
                }
            }
        } catch {
            // Do not serialize errors: they may include configuration values.
            try? writeFrame(control, ["v": 1, "kind": "peer.error", "error": "peer worker failed"])
        }
    }

    private static func kind(_ frame: [String: Any]) -> String? { frame["kind"] as? String }

    private static func strictPositiveInt(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(), number.intValue > 0,
              number.doubleValue == Double(number.intValue)
        else { return nil }
        return number.intValue
    }

    private static func readFrame(_ handle: FileHandle) throws -> [String: Any] {
        try controlFrame(readIPCFrame(handle))
    }

    private static func readIPCFrame(_ handle: FileHandle) throws -> ObstacleBridgeWorkerIPC.Frame {
        let header = try readExactly(handle, count: ObstacleBridgeWorkerIPC.headerBytes)
        guard let length = try ObstacleBridgeWorkerIPC.frameSize(header) else { throw WorkerError.invalidFrame }
        let payload = header + (try readExactly(handle, count: length))
        let (frame, remainder) = try ObstacleBridgeWorkerIPC.decode(payload)
        guard let frame, remainder.isEmpty else { throw WorkerError.invalidFrame }
        return frame
    }

    private static func controlFrame(_ frame: ObstacleBridgeWorkerIPC.Frame) throws -> [String: Any] {
        let value = try ObstacleBridgeWorkerIPC.decodeControl(frame)
        guard strictPositiveInt(value["v"]) == ObstacleBridgeRuntimeConfig.isolatedWorkerProtocolVersion
        else { throw WorkerError.invalidFrame }
        return value
    }

    private static func readExactly(_ handle: FileHandle, count: Int) throws -> Data {
        var output = Data()
        while output.count < count {
            try waitReadable(handle.fileDescriptor)
            var buffer = [UInt8](repeating: 0, count: count - output.count)
            let received = Darwin.read(handle.fileDescriptor, &buffer, buffer.count) // O_NONBLOCK readiness owner
            if received > 0 { output.append(buffer, count: received); continue }
            if received < 0 && errno == EINTR { continue }
            if received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) { continue }
            throw NSError(domain: "ObstacleBridgeNativePeerWorker", code: 1)
        }
        return output
    }

    private static func makeNonBlocking(_ descriptor: Int32) throws {
        let flags = Darwin.fcntl(descriptor, F_GETFL)
        guard flags >= 0, Darwin.fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0
        else { throw WorkerError.invalidDescriptor }
    }

    /// The private child owns this one synchronous protocol loop.  Reads stay
    /// nonblocking; `poll` is the documented no-event-loop compatibility wait.
    private static func waitReadable(_ descriptor: Int32) throws {
        var pollDescriptor = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
        while true {
            let result = Darwin.poll(&pollDescriptor, 1, -1) // OBSTACLEBRIDGE-ASYNC-IO-EXCEPTION: isolated native peer control owner has no host event loop
            if result < 0 && errno == EINTR { continue }
            guard result > 0, pollDescriptor.revents & Int16(POLLIN) != 0 else { throw WorkerError.invalidFrame }
            return
        }
    }

    private static func writeFrame(_ handle: FileHandle, _ frame: [String: Any]) throws {
        let rawKind = frame["kind"] as? String ?? ""
        let kind: ObstacleBridgeWorkerIPC.Kind = rawKind == "worker.hello" ? .hello : rawKind == "peer.error" ? .error : .response
        let generation = UInt64(strictPositiveInt(frame["generation"]) ?? 1)
        handle.write(try ObstacleBridgeWorkerIPC.encodeControl(kind: kind, generation: generation, value: frame))
    }

    private static func writeData(_ handle: FileHandle, generation: Int, payload: Data) throws {
        handle.write(try ObstacleBridgeWorkerIPC.encode(kind: .data, generation: UInt64(generation), payload: payload))
    }
}
