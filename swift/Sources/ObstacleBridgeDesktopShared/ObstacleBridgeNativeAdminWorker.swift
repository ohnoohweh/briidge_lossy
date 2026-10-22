import CoreFoundation
import Foundation

/// The native Admin child bootstrap boundary. The parent supplies connected
/// Unix descriptors; this entrypoint neither reads ambient configuration nor
/// opens a listener. HTTP/session ownership is added by IPC-1A2.
public enum ObstacleBridgeNativeAdminWorker {
    private enum Failure: Error { case invalidBootstrap }

    public static func run(controlFD: Int32, lifetimeFD: Int32, generation: Int) throws {
        guard controlFD >= 0, lifetimeFD >= 0, controlFD != lifetimeFD, generation > 0 else { throw Failure.invalidBootstrap }
        let control = FileHandle(fileDescriptor: controlFD, closeOnDealloc: true)
        let lifetime = FileHandle(fileDescriptor: lifetimeFD, closeOnDealloc: true)
        let hello = try readControl(control, generation: generation)
        guard hello["kind"] as? String == "worker.hello", hello["role"] as? String == "supervisor",
              hello["capabilities"] as? [String] == ["admin.control"], strictPositiveInt(hello["generation"]) == generation
        else { throw Failure.invalidBootstrap }
        try write(control, kind: .hello, generation: generation, value: [
            "v": 1, "kind": "worker.hello", "role": "admin", "capabilities": ["admin.control"], "generation": generation,
        ])
        let bootstrap = try readControl(control, generation: generation)
        guard bootstrap["kind"] as? String == "admin.start", bootstrap["args"] is [String: Any] else { throw Failure.invalidBootstrap }
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

    private static func readControl(_ handle: FileHandle, generation: Int) throws -> [String: Any] {
        let header = try readExactly(handle, count: ObstacleBridgeWorkerIPC.headerBytes)
        guard let size = try ObstacleBridgeWorkerIPC.frameSize(header) else { throw Failure.invalidBootstrap }
        let (frame, remainder) = try ObstacleBridgeWorkerIPC.decode(header + readExactly(handle, count: size))
        guard let frame, remainder.isEmpty, frame.generation == UInt64(generation) else { throw Failure.invalidBootstrap }
        let value = try ObstacleBridgeWorkerIPC.decodeControl(frame)
        guard strictPositiveInt(value["v"]) == 1 else { throw Failure.invalidBootstrap }
        return value
    }

    private static func write(_ handle: FileHandle, kind: ObstacleBridgeWorkerIPC.Kind, generation: Int, value: [String: Any]) throws {
        handle.write(try ObstacleBridgeWorkerIPC.encodeControl(kind: kind, generation: UInt64(generation), value: value))
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
