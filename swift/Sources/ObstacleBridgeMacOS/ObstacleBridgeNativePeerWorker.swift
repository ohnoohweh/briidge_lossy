import CoreFoundation
import Foundation

/// Protocol-v1 native peer child. The inherited connected descriptor is both
/// configuration capability and owner-lifetime signal; no config path, secret
/// environment variable, or loopback listener is used for startup control.
enum ObstacleBridgeNativePeerWorker {
    private static let maximumFrame = 1_048_576

    private enum WorkerError: LocalizedError {
        case invalidFrame
        case invalidBootstrap
        case invalidDescriptor

        var errorDescription: String? { "invalid native peer worker request" }
    }

    static func run(controlFD: Int32, logFD: Int32? = nil) throws {
        guard controlFD >= 0, logFD != controlFD else { throw WorkerError.invalidDescriptor }
        let control = FileHandle(fileDescriptor: controlFD, closeOnDealloc: true)
        var runner: ObstacleBridgeHostRunner?
        defer { runner?.stopPeerWorker() }
        do {
            let start = try readFrame(control)
            guard kind(start) == "peer.start",
                  let peerID = start["peer_id"] as? String, !peerID.isEmpty, peerID.count <= 128,
                  let generation = strictPositiveInt(start["generation"]),
                  let configuration = start["config"] as? [String: Any]
            else { throw WorkerError.invalidBootstrap }
            let rootLogLevel = strictLogLevel(start["log_root_level"]) ?? 30
            let producer = try logFD.map { try ObstacleBridgeLogProducer(inheritedFD: $0, minimumLevel: rootLogLevel) }
            let native = try ObstacleBridgeHostRunner(peerWorkerConfiguration: configuration, peerWorkerLogProducer: producer)
            try native.startPeerWorker()
            runner = native
            try writeFrame(control, ["v": ObstacleBridgeRuntimeConfig.isolatedWorkerProtocolVersion, "kind": "peer.ready", "peer_id": peerID,
                                     "generation": generation, "implementation": "native"])
            while true {
                let request = try readFrame(control)
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

    private static func strictLogLevel(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(), number.intValue >= 0,
              number.doubleValue == Double(number.intValue)
        else { return nil }
        return number.intValue
    }

    private static func readFrame(_ handle: FileHandle) throws -> [String: Any] {
        let header = try readExactly(handle, count: 4)
        let length = header.reduce(0) { ($0 << 8) | Int($1) }
        guard length > 0, length <= maximumFrame else { throw WorkerError.invalidFrame }
        let payload = try readExactly(handle, count: length)
        guard let frame = try JSONSerialization.jsonObject(with: payload) as? [String: Any],
              strictPositiveInt(frame["v"]) == ObstacleBridgeRuntimeConfig.isolatedWorkerProtocolVersion
        else { throw WorkerError.invalidFrame }
        return frame
    }

    private static func readExactly(_ handle: FileHandle, count: Int) throws -> Data {
        var output = Data()
        while output.count < count {
            let chunk = try handle.read(upToCount: count - output.count) ?? Data()
            guard !chunk.isEmpty else { throw NSError(domain: "ObstacleBridgeNativePeerWorker", code: 1) }
            output.append(chunk)
        }
        return output
    }

    private static func writeFrame(_ handle: FileHandle, _ frame: [String: Any]) throws {
        let payload = try JSONSerialization.data(withJSONObject: frame, options: [])
        guard !payload.isEmpty, payload.count <= maximumFrame else { throw WorkerError.invalidFrame }
        var length = UInt32(payload.count).bigEndian
        handle.write(Data(bytes: &length, count: 4))
        handle.write(payload)
    }
}
