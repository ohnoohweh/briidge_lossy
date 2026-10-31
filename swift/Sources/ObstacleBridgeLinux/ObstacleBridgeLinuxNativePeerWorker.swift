import CoreFoundation
import Dispatch
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

    /// Post-bootstrap control ownership stays on one serial readiness queue.
    /// Partial common-OBIP frames remain in the shared decoder until the next
    /// descriptor callback; no long-lived control path waits for a frame.
    private final class ControlOwner: @unchecked Sendable {
        // OBSTACLEBRIDGE-CONCURRENCY: serial; test=test_linux_native_peer_worker_uses_readiness_decoder_after_bootstrap
        private let descriptor: Int32
        private let handle: FileHandle
        private let runtime: ObstacleBridgeLinuxLiveRuntime
        private let peerID: String
        private let generation: Int
        private let queue = DispatchQueue(label: "org.obstaclebridge.linux.native-peer-control")
        private var decoder = ObstacleBridgeWorkerIPCStreamDecoder()
        private var source: DispatchSourceRead?

        init(descriptor: Int32, handle: FileHandle, runtime: ObstacleBridgeLinuxLiveRuntime, peerID: String, generation: Int) {
            self.descriptor = descriptor
            self.handle = handle
            self.runtime = runtime
            self.peerID = peerID
            self.generation = generation
        }

        func start() {
            let source = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: queue)
            source.setEventHandler { [weak self] in self?.drainReadableControl() }
            source.setCancelHandler { _ = close(self.descriptor) }
            self.source = source
            source.resume()
        }

        private func drainReadableControl() {
            while true {
                var bytes = [UInt8](repeating: 0, count: 65_536)
                let received = Glibc.read(descriptor, &bytes, bytes.count) // O_NONBLOCK readiness owner
                if received > 0 {
                    do {
                        let frames = try decoder.append(Data(bytes.prefix(Int(received))))
                        for frame in frames { try handle(frame) }
                    } catch {
                        finish(exitCode: 2, reportFailure: true)
                        return
                    }
                    continue
                }
                if received == 0 {
                    finish(exitCode: 0, reportFailure: false)
                    return
                }
                if errno == EINTR { continue }
                if errno == EAGAIN || errno == EWOULDBLOCK { return }
                finish(exitCode: 2, reportFailure: true)
                return
            }
        }

        private func handle(_ frame: ObstacleBridgeWorkerIPC.Frame) throws {
            if frame.kind == .data {
                guard frame.generation == UInt64(generation) else { throw WorkerError.invalid }
                try ObstacleBridgeLinuxNativePeerWorker.writeData(handle, generation: generation, payload: frame.payload)
                return
            }
            let request = try ObstacleBridgeLinuxNativePeerWorker.control(frame)
            guard request["peer_id"] as? String == peerID,
                  ObstacleBridgeLinuxNativePeerWorker.positive(request["generation"]) == generation,
                  let identifier = request["id"] as? String, !identifier.isEmpty, identifier.count <= 128
            else { throw WorkerError.invalid }
            switch request["kind"] as? String {
            case "peer.stop":
                try ObstacleBridgeLinuxNativePeerWorker.write(handle, ["v": 1, "kind": "peer.stopping", "peer_id": peerID, "generation": generation, "id": identifier])
                finish(exitCode: 0, reportFailure: false)
            case "peer.snapshot":
                let status = try ObstacleBridgeLinuxNativePeerWorker.json(runtime.status())
                try ObstacleBridgeLinuxNativePeerWorker.write(handle, ["v": 1, "kind": "peer.snapshot.reply", "peer_id": peerID,
                                                                          "generation": generation, "id": identifier, "status": status,
                                                                          "connections": [:], "peers": ["peers": []]])
            case "peer.control":
                try ObstacleBridgeLinuxNativePeerWorker.write(handle, ["v": 1, "kind": "peer.control.reply", "peer_id": peerID,
                                                                          "generation": generation, "id": identifier,
                                                                          "result": ["ok": false, "requested": 0,
                                                                                     "reason": "native_peer_control_not_supported"]])
            default:
                throw WorkerError.invalid
            }
        }

        private func finish(exitCode: Int32, reportFailure: Bool) {
            source?.cancel(); source = nil
            if reportFailure {
                try? ObstacleBridgeLinuxNativePeerWorker.write(handle, ["v": 1, "kind": "peer.error", "error": "peer worker failed"])
            }
            runtime.stop()
            exit(exitCode)
        }
    }

    static func run(controlFD: Int32) throws {
        guard controlFD >= 0 else { throw WorkerError.invalid }
        try makeNonBlocking(controlFD)
        let handle = FileHandle(fileDescriptor: controlFD, closeOnDealloc: false)
        var transferred = false
        defer { if !transferred { try? handle.close() } }
        do {
            // The inherited HELLO/start exchange is the one bounded bootstrap
            // exception. It completes before a long-lived readiness owner is
            // installed for the child-control channel.
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
            let runtime = ObstacleBridgeLinuxLiveRuntime(configuration: configuration)
            runtime.start()
            try write(handle, ["v": 1, "kind": "peer.ready", "peer_id": peerID,
                               "generation": generation, "implementation": "native"])
            let owner = ControlOwner(descriptor: controlFD, handle: handle, runtime: runtime, peerID: peerID, generation: generation)
            owner.start()
            transferred = true
            withExtendedLifetime(owner) { dispatchMain() }
        } catch {
            try? write(handle, ["v": 1, "kind": "peer.error", "error": "peer worker failed"])
            throw error
        }
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
            let received = Glibc.read(handle.fileDescriptor, &buffer, buffer.count) // bounded bootstrap with O_NONBLOCK
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

    private static func waitReadable(_ descriptor: Int32) throws {
        var pollDescriptor = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
        while true {
            let result = poll(&pollDescriptor, 1, 5_000) // OBSTACLEBRIDGE-ASYNC-IO-EXCEPTION: bounded inherited-descriptor bootstrap before readiness ownership
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
