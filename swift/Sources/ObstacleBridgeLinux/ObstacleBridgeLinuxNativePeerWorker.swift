import CoreFoundation
import Foundation
import ObstacleBridgeLinuxAdapters

/// Linux native peer child, deliberately limited to the existing outbound
/// runtime. Its connected inherited descriptor is configuration handoff and
/// owner-lifetime capability; it never creates an Admin or IPC listener.
enum ObstacleBridgeLinuxNativePeerWorker {
    private static let maximumFrame = 1_048_576

    static func run(controlFD: Int32) throws {
        guard controlFD >= 0 else { throw WorkerError.invalid }
        let handle = FileHandle(fileDescriptor: controlFD, closeOnDealloc: true)
        var runtime: ObstacleBridgeLinuxLiveRuntime?
        defer { runtime?.stop() }
        do {
            let start = try read(handle)
            guard start["kind"] as? String == "peer.start",
                  let peerID = start["peer_id"] as? String, !peerID.isEmpty, peerID.count <= 128,
                  let generation = positive(start["generation"]),
                  let raw = start["config"] as? [String: Any]
            else { throw WorkerError.invalid }
            let configuration = try ObstacleBridgeLinuxRuntimeConfiguration.parseJSONObject(raw)
            guard !configuration.listenerMode, configuration.transport == .tcp,
                  !configuration.packetTunnelEnabled, !configuration.proxyProvider.enabled else { throw WorkerError.invalid }
            let live = ObstacleBridgeLinuxLiveRuntime(configuration: configuration)
            live.start(); runtime = live
            try write(handle, ["v": 1, "kind": "peer.ready", "peer_id": peerID, "generation": generation, "implementation": "native"])
            while true {
                let request = try read(handle)
                guard request["peer_id"] as? String == peerID, positive(request["generation"]) == generation,
                      let identifier = request["id"] as? String, !identifier.isEmpty, identifier.count <= 128 else { throw WorkerError.invalid }
                switch request["kind"] as? String {
                case "peer.stop": try write(handle, ["v": 1, "kind": "peer.stopping", "peer_id": peerID, "generation": generation, "id": identifier]); return
                case "peer.snapshot":
                    let status = try json(live.status())
                    try write(handle, ["v": 1, "kind": "peer.snapshot.reply", "peer_id": peerID, "generation": generation, "id": identifier, "status": status, "connections": [:], "peers": ["peers": []]])
                case "peer.control": try write(handle, ["v": 1, "kind": "peer.control.reply", "peer_id": peerID, "generation": generation, "id": identifier, "result": ["ok": false, "requested": 0, "reason": "native_peer_control_not_supported"]])
                default: throw WorkerError.invalid
                }
            }
        } catch { try? write(handle, ["v": 1, "kind": "peer.error", "error": "peer worker failed"]) }
    }
    private enum WorkerError: Error { case invalid }
    private static func positive(_ value: Any?) -> Int? { guard let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID(), n.intValue > 0, n.doubleValue == Double(n.intValue) else { return nil }; return n.intValue }
    private static func json<T: Encodable>(_ value: T) throws -> [String: Any] { try JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) as? [String: Any] ?? [:] }
    private static func read(_ handle: FileHandle) throws -> [String: Any] { let h = try exact(handle, 4); let n = h.reduce(0) { ($0 << 8) | Int($1) }; guard n > 0, n <= maximumFrame, let result = try JSONSerialization.jsonObject(with: exact(handle, n)) as? [String: Any], positive(result["v"]) == 1 else { throw WorkerError.invalid }; return result }
    private static func exact(_ handle: FileHandle, _ count: Int) throws -> Data { var out = Data(); while out.count < count { let next = try handle.read(upToCount: count - out.count) ?? Data(); guard !next.isEmpty else { throw WorkerError.invalid }; out.append(next) }; return out }
    private static func write(_ handle: FileHandle, _ frame: [String: Any]) throws { let body = try JSONSerialization.data(withJSONObject: frame); guard body.count <= maximumFrame else { throw WorkerError.invalid }; var n = UInt32(body.count).bigEndian; handle.write(Data(bytes: &n, count: 4)); handle.write(body) }
}
