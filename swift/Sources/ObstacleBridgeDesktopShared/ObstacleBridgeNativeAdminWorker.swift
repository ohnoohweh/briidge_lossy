import CoreFoundation
import Dispatch
import Foundation
#if os(macOS) || os(iOS)
import Darwin
#else
import Glibc
#endif

/// The native Admin child bootstrap boundary. The parent supplies connected
/// Unix descriptors; this entrypoint neither reads ambient configuration nor
/// opens a listener. HTTP/session ownership is added by IPC-1A2.
public enum ObstacleBridgeNativeAdminWorker {
    private enum Failure: Error { case invalidBootstrap }
    private static let maximumControlPayload = 65_536
    private static let bootstrapStatusRequestID = "bootstrap-status"

    #if os(Linux)
    private static let unixStreamSocketType = Int32(SOCK_STREAM.rawValue)
    #else
    private static let unixStreamSocketType = SOCK_STREAM
    #endif

    /// Serialized parent-owned state access for a native Admin child. The
    /// inherited control descriptor remains the only RPC transport.
    public final class ParentRPC: @unchecked Sendable {
        private static let methods: Set<String> = [
            "get_status_snapshot", "get_peer_connections_snapshot", "get_connections_snapshot",
            "get_config_snapshot", "get_onboarding_config_snapshot", "get_config_schema_snapshot", "get_debug_logs", "fetch_logs",
            "update_config", "replace_remote_services_catalog", "request_overlay_reconnect",
            "request_secure_link_rekey", "request_secure_link_reload", "request_tun_helper_repair",
            "request_restart", "request_shutdown", "request_tun_enabled",
            "get_telemetry_client_snapshot",
        ]
        private let control: FileHandle
        private let generation: Int
        private let lock = NSLock()
        private var failed = false

        init(control: FileHandle, generation: Int) {
            self.control = control
            self.generation = generation
        }

        public func call(method: String, args: [Any] = [], kwargs: [String: Any] = [:], timeout: TimeInterval = 0.35, requestID: String? = nil) throws -> Any {
            guard Self.methods.contains(method), timeout > 0, timeout <= 4,
                  JSONSerialization.isValidJSONObject(args), JSONSerialization.isValidJSONObject(kwargs)
            else { throw Failure.invalidBootstrap }
            lock.lock(); defer { lock.unlock() }
            guard !failed else { throw Failure.invalidBootstrap }
            let deadline = ProcessInfo.processInfo.systemUptime + timeout
            let identifier = requestID ?? UUID().uuidString.lowercased()
            guard !identifier.isEmpty, identifier.count <= 64 else { throw Failure.invalidBootstrap }
            do {
                try ObstacleBridgeNativeAdminWorker.write(control, kind: .request, generation: generation, value: [
                    "v": 1, "kind": "admin.call", "id": identifier, "method": method,
                    "args": args, "kwargs": kwargs, "deadline": deadline,
                ])
                let reply = try ObstacleBridgeNativeAdminWorker.readControl(control, generation: generation, expectedKind: .response, deadline: deadline)
                guard reply["kind"] as? String == "admin.reply", reply["id"] as? String == identifier,
                      reply["ok"] as? Bool == true
                else { throw Failure.invalidBootstrap }
                return reply["result"] ?? NSNull()
            } catch {
                failed = true
                throw error
            }
        }
    }

    public struct Service {
        public let port: Int
        private let stopHandler: () -> Void

        public init(port: Int, stop: @escaping () -> Void) {
            self.port = port
            self.stopHandler = stop
        }

        fileprivate func stop() { stopHandler() }
    }

    public static func run(controlFD: Int32, lifetimeFD: Int32, logFD: Int32? = nil, generation: Int, serviceFactory: (([String: Any], ParentRPC) throws -> Service)? = nil) throws {
        guard controlFD >= 0, lifetimeFD >= 0, controlFD != lifetimeFD, generation > 0,
              isUnixStreamDescriptor(controlFD), isUnixStreamDescriptor(lifetimeFD)
        else { throw Failure.invalidBootstrap }
        try makeNonBlocking(controlFD)
        let control = FileHandle(fileDescriptor: controlFD, closeOnDealloc: true)
        let hello = try readControl(control, generation: generation, expectedKind: .hello, deadline: ProcessInfo.processInfo.systemUptime + 5)
        guard hello["kind"] as? String == "worker.hello", hello["role"] as? String == "supervisor",
              hello["capabilities"] as? [String] == ["admin.control"], strictPositiveInt(hello["generation"]) == generation
        else { throw Failure.invalidBootstrap }
        try write(control, kind: .hello, generation: generation, value: [
            "v": 1, "kind": "worker.hello", "role": "admin", "capabilities": ["admin.control"], "generation": generation,
        ])
        let bootstrap = try readControl(control, generation: generation, expectedKind: .request, deadline: ProcessInfo.processInfo.systemUptime + 5)
        guard bootstrap["kind"] as? String == "admin.start", bootstrap["args"] is [String: Any] else { throw Failure.invalidBootstrap }
        let logLevel = strictNonnegativeInt(bootstrap["log_root_level"]) ?? 30
        let logProducer = try logFD.map { try ObstacleBridgeLogProducer(inheritedFD: $0, minimumLevel: logLevel) }
        let parentRPC = ParentRPC(control: control, generation: generation)
        let initialStatus = try parentRPC.call(method: "get_status_snapshot", timeout: 1, requestID: bootstrapStatusRequestID)
        guard initialStatus is [String: Any]
        else { throw Failure.invalidBootstrap }
        let service = try serviceFactory?(bootstrap["args"] as! [String: Any], parentRPC)
        defer { service?.stop() }
        logProducer?.emit(name: "admin.native", level: "INFO", levelNumber: 20, message: "native_admin_ready")
        try write(control, kind: .ready, generation: generation, value: [
            "v": 1, "kind": "admin.ready", "implementation": "native", "port": service?.port ?? 0, "generation": generation,
        ])
        // A zero-byte lifetime read is the sole owner-loss signal. Keep it
        // callback-owned: FileHandle.availableData would block this process
        // and can race descriptor teardown on Linux. The descriptor is made
        // nonblocking before the source starts, so a stale readiness event
        // cannot turn this handler into a blocking read.
        let flags = fcntl(lifetimeFD, F_GETFL)
        guard flags >= 0, fcntl(lifetimeFD, F_SETFL, flags | O_NONBLOCK) == 0
        else { throw Failure.invalidBootstrap }
        let lifetimeQueue = DispatchQueue(label: "org.obstaclebridge.native-admin-lifetime")
        let lifetimeEnded = DispatchSemaphore(value: 0)
        let lifetimeSource = DispatchSource.makeReadSource(fileDescriptor: lifetimeFD, queue: lifetimeQueue)
        lifetimeSource.setEventHandler {
            var byte: UInt8 = 0
            while true {
                let received = read(lifetimeFD, &byte, 1) // O_NONBLOCK readiness owner
                if received == 0 {
                    lifetimeEnded.signal()
                    return
                }
                if received > 0 { continue }
                if errno == EINTR { continue }
                if errno == EAGAIN || errno == EWOULDBLOCK { return }
                lifetimeEnded.signal()
                return
            }
        }
        lifetimeSource.setCancelHandler { _ = close(lifetimeFD) }
        lifetimeSource.resume()
        withExtendedLifetime(lifetimeSource) { lifetimeEnded.wait() }
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

    private static func readControl(_ handle: FileHandle, generation: Int, expectedKind: ObstacleBridgeWorkerIPC.Kind, deadline: TimeInterval) throws -> [String: Any] {
        let header = try readExactly(handle, count: ObstacleBridgeWorkerIPC.headerBytes, deadline: deadline)
        guard let size = try ObstacleBridgeWorkerIPC.frameSize(header), size <= maximumControlPayload else { throw Failure.invalidBootstrap }
        let (frame, remainder) = try ObstacleBridgeWorkerIPC.decode(header + readExactly(handle, count: size, deadline: deadline))
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

    private static func readExactly(_ handle: FileHandle, count: Int, deadline: TimeInterval) throws -> Data {
        var output = Data()
        while output.count < count {
            try waitReadable(handle.fileDescriptor, deadline: deadline)
            var buffer = [UInt8](repeating: 0, count: count - output.count)
            let received = read(handle.fileDescriptor, &buffer, buffer.count) // O_NONBLOCK readiness owner
            if received > 0 {
                output.append(buffer, count: received)
                continue
            }
            if received < 0 && errno == EINTR { continue }
            if received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) { continue }
            throw Failure.invalidBootstrap
        }
        return output
    }

    private static func makeNonBlocking(_ descriptor: Int32) throws {
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0
        else { throw Failure.invalidBootstrap }
    }

    private static func waitReadable(_ descriptor: Int32, deadline: TimeInterval) throws {
        while true {
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            guard remaining > 0 else { throw Failure.invalidBootstrap }
            var pollDescriptor = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
            let milliseconds = Int32(min(Double(Int32.max), max(1, ceil(remaining * 1_000))))
            let result = poll(&pollDescriptor, 1, milliseconds)
            if result < 0 && errno == EINTR { continue }
            guard result > 0, pollDescriptor.revents & Int16(POLLIN) != 0 else { throw Failure.invalidBootstrap }
            return
        }
    }

    private static func isUnixStreamDescriptor(_ descriptor: Int32) -> Bool {
        var socketType: Int32 = 0
        var socketTypeLength = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &socketType, &socketTypeLength) == 0,
              socketType == unixStreamSocketType
        else { return false }
        var address = sockaddr_storage()
        var addressLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let result = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(descriptor, $0, &addressLength)
            }
        }
        return result == 0 && address.ss_family == sa_family_t(AF_UNIX)
    }
}
