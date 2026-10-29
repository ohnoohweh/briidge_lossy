import CoreFoundation
import Foundation
import ObstacleBridgeDesktopShared
import ObstacleBridgeLinuxAdapters
#if os(Linux)
import Glibc
#endif

/// Linux native peer child. It shares the versioned desktop-worker framing
/// with Python and macOS; its connected inherited descriptor is both the
/// configuration handoff and the owner-lifetime capability.
enum ObstacleBridgeLinuxNativePeerWorker {
    private enum WorkerError: Error { case invalid }

    static func run(controlFD: Int32) throws {
        guard controlFD >= 0 else { throw WorkerError.invalid }
        try makeNonBlocking(controlFD)
        let handle = FileHandle(fileDescriptor: controlFD, closeOnDealloc: true)
        var runtime: ObstacleBridgeLinuxLiveRuntime?
        defer { runtime?.stop() }
        do {
            let hello = try read(handle)
            guard hello["kind"] as? String == "worker.hello",
                  hello["role"] as? String == "supervisor",
                  hello["capabilities"] as? [String] == ["peer.binary-data", "peer.control"],
                  let helloGeneration = positive(hello["generation"])
            else { throw WorkerError.invalid }
            try write(handle, ["v": 1, "kind": "worker.hello", "role": "peer",
                               "capabilities": ["peer.binary-data", "peer.control"], "generation": helloGeneration])
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
                let frame = try readIPCFrame(handle)
                if frame.kind == .data {
                    guard frame.generation == UInt64(generation) else { throw WorkerError.invalid }
                    try writeData(handle, generation: generation, payload: frame.payload)
                    continue
                }
                let request = try control(frame)
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
        try control(readIPCFrame(handle))
    }

    private static func readIPCFrame(_ handle: FileHandle) throws -> ObstacleBridgeWorkerIPC.Frame {
        let header = try exact(handle, ObstacleBridgeWorkerIPC.headerBytes)
        guard let length = try ObstacleBridgeWorkerIPC.frameSize(header) else { throw WorkerError.invalid }
        let (frame, remainder) = try ObstacleBridgeWorkerIPC.decode(header + (try exact(handle, length)))
        guard let frame, remainder.isEmpty else { throw WorkerError.invalid }
        return frame
    }

    private static func control(_ frame: ObstacleBridgeWorkerIPC.Frame) throws -> [String: Any] {
        guard let value = try? ObstacleBridgeWorkerIPC.decodeControl(frame), positive(value["v"]) == 1 else { throw WorkerError.invalid }
        return value
    }

    private static func exact(_ handle: FileHandle, _ count: Int) throws -> Data {
        var output = Data()
        while output.count < count {
            try waitReadable(handle.fileDescriptor)
            var buffer = [UInt8](repeating: 0, count: count - output.count)
            let received = Glibc.read(handle.fileDescriptor, &buffer, buffer.count) // O_NONBLOCK readiness owner
            if received > 0 { output.append(buffer, count: received); continue }
            if received < 0 && errno == EINTR { continue }
            if received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) { continue }
            throw WorkerError.invalid
        }
        return output
    }

    private static func makeNonBlocking(_ descriptor: Int32) throws {
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else { throw WorkerError.invalid }
    }

    /// This is the child process's private control boundary; frame assembly
    /// remains nonblocking and only this owner waits for the next command.
    private static func waitReadable(_ descriptor: Int32) throws {
        var pollDescriptor = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
        while true {
            let result = poll(&pollDescriptor, 1, -1) // OBSTACLEBRIDGE-ASYNC-IO-EXCEPTION: isolated native peer control owner has no host event loop
            if result < 0 && errno == EINTR { continue }
            guard result > 0, pollDescriptor.revents & Int16(POLLIN) != 0 else { throw WorkerError.invalid }
            return
        }
    }

    private static func write(_ handle: FileHandle, _ value: [String: Any]) throws {
        let rawKind = value["kind"] as? String ?? ""
        let kind: ObstacleBridgeWorkerIPC.Kind = rawKind == "worker.hello" ? .hello : rawKind == "peer.error" ? .error : .response
        handle.write(try ObstacleBridgeWorkerIPC.encodeControl(kind: kind,
                                                                generation: UInt64(positive(value["generation"]) ?? 1),
                                                                value: value))
    }

    private static func writeData(_ handle: FileHandle, generation: Int, payload: Data) throws {
        handle.write(try ObstacleBridgeWorkerIPC.encode(kind: .data, generation: UInt64(generation), payload: payload))
    }
}
