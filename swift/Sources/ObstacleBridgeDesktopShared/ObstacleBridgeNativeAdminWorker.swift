import CoreFoundation
import Foundation

/// The native Admin child bootstrap boundary. The parent supplies connected
/// Unix descriptors; this entrypoint neither reads ambient configuration nor
/// opens a listener. HTTP/session ownership is added by IPC-1A2.
public enum ObstacleBridgeNativeAdminWorker {
    private enum Failure: Error { case invalidBootstrap }
    private static let maximumControlPayload = 65_536
    private static let bootstrapStatusRequestID = "bootstrap-status"

    public static func run(controlFD: Int32, lifetimeFD: Int32, logFD: Int32? = nil, generation: Int) throws {
        guard controlFD >= 0, lifetimeFD >= 0, controlFD != lifetimeFD, generation > 0 else { throw Failure.invalidBootstrap }
        let control = FileHandle(fileDescriptor: controlFD, closeOnDealloc: true)
        let lifetime = FileHandle(fileDescriptor: lifetimeFD, closeOnDealloc: true)
        let hello = try readControl(control, generation: generation, expectedKind: .hello)
        guard hello["kind"] as? String == "worker.hello", hello["role"] as? String == "supervisor",
              hello["capabilities"] as? [String] == ["admin.control"], strictPositiveInt(hello["generation"]) == generation
        else { throw Failure.invalidBootstrap }
        try write(control, kind: .hello, generation: generation, value: [
            "v": 1, "kind": "worker.hello", "role": "admin", "capabilities": ["admin.control"], "generation": generation,
        ])
        let bootstrap = try readControl(control, generation: generation, expectedKind: .request)
        guard bootstrap["kind"] as? String == "admin.start", bootstrap["args"] is [String: Any] else { throw Failure.invalidBootstrap }
        let logLevel = strictNonnegativeInt(bootstrap["log_root_level"]) ?? 30
        let logProducer = try logFD.map { try ObstacleBridgeLogProducer(inheritedFD: $0, minimumLevel: logLevel) }
        // This is the first parent-owned datum the child needs.  It pins the
        // common correlated request/reply boundary before IPC-1A2 adds the
        // HTTP/session methods that consume further runner state.
        let deadline = ProcessInfo.processInfo.systemUptime + 1
        try write(control, kind: .request, generation: generation, value: [
            "v": 1, "kind": "admin.call", "id": bootstrapStatusRequestID,
            "method": "get_status_snapshot", "args": [], "kwargs": [:], "deadline": deadline,
        ])
        let reply = try readControl(control, generation: generation, expectedKind: .response)
        guard reply["kind"] as? String == "admin.reply", reply["id"] as? String == bootstrapStatusRequestID,
              reply["ok"] as? Bool == true, reply["result"] is [String: Any]
        else { throw Failure.invalidBootstrap }
        logProducer?.emit(name: "admin.native", level: "INFO", levelNumber: 20, message: "native_admin_ready")
        try write(control, kind: .ready, generation: generation, value: [
            "v": 1, "kind": "admin.ready", "implementation": "native", "port": 0, "generation": generation,
        ])
        // A zero-byte lifetime read is the sole owner-loss signal. Closing it
        // releases both inherited capabilities without an ambient endpoint.
        while !lifetime.availableData.isEmpty { }
    }

    private static func strictPositiveInt(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.intValue > 0, number.doubleValue == Double(number.intValue) else { return nil }
        return number.intValue
    }

    private static func strictNonnegativeInt(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.intValue >= 0, number.doubleValue == Double(number.intValue) else { return nil }
        return number.intValue
    }

    private static func readControl(_ handle: FileHandle, generation: Int, expectedKind: ObstacleBridgeWorkerIPC.Kind) throws -> [String: Any] {
        let header = try readExactly(handle, count: ObstacleBridgeWorkerIPC.headerBytes)
        guard let size = try ObstacleBridgeWorkerIPC.frameSize(header), size <= maximumControlPayload else { throw Failure.invalidBootstrap }
        let (frame, remainder) = try ObstacleBridgeWorkerIPC.decode(header + readExactly(handle, count: size))
        guard let frame, remainder.isEmpty, frame.kind == expectedKind, frame.generation == UInt64(generation) else { throw Failure.invalidBootstrap }
        let value = try ObstacleBridgeWorkerIPC.decodeControl(frame)
        guard strictPositiveInt(value["v"]) == 1 else { throw Failure.invalidBootstrap }
        return value
    }

    private static func write(_ handle: FileHandle, kind: ObstacleBridgeWorkerIPC.Kind, generation: Int, value: [String: Any]) throws {
        let frame = try ObstacleBridgeWorkerIPC.encodeControl(kind: kind, generation: UInt64(generation), value: value)
        guard frame.count - ObstacleBridgeWorkerIPC.headerBytes <= maximumControlPayload else { throw Failure.invalidBootstrap }
        handle.write(frame)
    }

    private static func readExactly(_ handle: FileHandle, count: Int) throws -> Data {
        var output = Data()
        while output.count < count {
            let chunk = try handle.read(upToCount: count - output.count) ?? Data()
            guard !chunk.isEmpty else { throw Failure.invalidBootstrap }
            output.append(chunk)
        }
        return output
    }
}
