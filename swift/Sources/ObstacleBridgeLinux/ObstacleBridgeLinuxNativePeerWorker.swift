import CoreFoundation
import Foundation
import ObstacleBridgeDesktopShared
import ObstacleBridgeLinuxAdapters

/// Linux native peer child. It shares the versioned desktop-worker framing
/// with Python and macOS; its connected inherited descriptor is both the
/// configuration handoff and the owner-lifetime capability.
enum ObstacleBridgeLinuxNativePeerWorker {
    private enum WorkerError: Error { case invalid }

    static func run(controlFD: Int32) throws {
        guard controlFD >= 0 else { throw WorkerError.invalid }
        let handle = FileHandle(fileDescriptor: controlFD, closeOnDealloc: true)
        var runtime: ObstacleBridgeLinuxLiveRuntime?
        defer { runtime?.stop() }
        do {
            let hello = try read(handle)
            guard hello["kind"] as? String == "worker.hello",
                  hello["role"] as? String == "supervisor",
                  hello["capabilities"] as? [String] == ["peer.control"],
                  let helloGeneration = positive(hello["generation"])
            else { throw WorkerError.invalid }
            try write(handle, ["v": 1, "kind": "worker.hello", "role": "peer",
                               "capabilities": ["peer.control"], "generation": helloGeneration])
            let start = try read(handle)
            guard start["kind"] as? String == "peer.start",
                  let peerID = start["peer_id"] as? String, !peerID.isEmpty, peerID.count <= 128,
                  let generation = positive(start["generation"]), generation == helloGeneration,
                  let raw = start["config"] as? [String: Any]
            else { throw WorkerError.invalid }
            let configuration = try ObstacleBridgeLinuxRuntimeConfiguration.parseJSONObject(raw)
            guard !configuration.listenerMode, configuration.transport == .tcp,
                  !configuration.packetTunnelEnabled, !configuration.proxyProvider.enabled else { throw WorkerError.invalid }
            let live = ObstacleBridgeLinuxLiveRuntime(configuration: configuration)
            live.start(); runtime = live
            try write(handle, ["v": 1, "kind": "peer.ready", "peer_id": peerID,
                               "generation": generation, "implementation": "native"])
            while true {
                let request = try read(handle)
                guard request["peer_id"] as? String == peerID, positive(request["generation"]) == generation,
                      let identifier = request["id"] as? String, !identifier.isEmpty, identifier.count <= 128 else { throw WorkerError.invalid }
                switch request["kind"] as? String {
                case "peer.stop":
                    try write(handle, ["v": 1, "kind": "peer.stopping", "peer_id": peerID, "generation": generation, "id": identifier])
                    return
                case "peer.snapshot":
                    let status = try json(live.status())
                    try write(handle, ["v": 1, "kind": "peer.snapshot.reply", "peer_id": peerID,
                                       "generation": generation, "id": identifier, "status": status,
                                       "connections": [:], "peers": ["peers": []]])
                case "peer.control":
                    try write(handle, ["v": 1, "kind": "peer.control.reply", "peer_id": peerID,
                                       "generation": generation, "id": identifier,
                                       "result": ["ok": false, "requested": 0,
                                                  "reason": "native_peer_control_not_supported"]])
                default: throw WorkerError.invalid
                }
            }
        } catch { try? write(handle, ["v": 1, "kind": "peer.error", "error": "peer worker failed"]) }
    }

    private static func positive(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.intValue > 0, number.doubleValue == Double(number.intValue) else { return nil }
        return number.intValue
    }

    private static func json<T: Encodable>(_ value: T) throws -> [String: Any] {
        try JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) as? [String: Any] ?? [:]
    }

    private static func read(_ handle: FileHandle) throws -> [String: Any] {
        let header = try exact(handle, ObstacleBridgeWorkerIPC.headerBytes)
        guard let length = try ObstacleBridgeWorkerIPC.frameSize(header) else { throw WorkerError.invalid }
        let (frame, remainder) = try ObstacleBridgeWorkerIPC.decode(header + (try exact(handle, length)))
        guard let frame, remainder.isEmpty,
              let value = try? ObstacleBridgeWorkerIPC.decodeControl(frame),
              positive(value["v"]) == 1 else { throw WorkerError.invalid }
        return value
    }

    private static func exact(_ handle: FileHandle, _ count: Int) throws -> Data {
        var output = Data()
        while output.count < count {
            let chunk = try handle.read(upToCount: count - output.count) ?? Data()
            guard !chunk.isEmpty else { throw WorkerError.invalid }
            output.append(chunk)
        }
        return output
    }

    private static func write(_ handle: FileHandle, _ value: [String: Any]) throws {
        let rawKind = value["kind"] as? String ?? ""
        let kind: ObstacleBridgeWorkerIPC.Kind = rawKind == "worker.hello" ? .hello : rawKind == "peer.error" ? .error : .response
        handle.write(try ObstacleBridgeWorkerIPC.encodeControl(kind: kind,
                                                                generation: UInt64(positive(value["generation"]) ?? 1),
                                                                value: value))
    }
}
