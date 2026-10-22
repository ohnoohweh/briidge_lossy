#if os(macOS) || os(Linux)
import Dispatch
import Foundation
#if os(macOS)
import Darwin
private let logDatagramSocket = SOCK_DGRAM
private let logStreamSocket = SOCK_STREAM
#else
import Glibc
private let logDatagramSocket = Int32(SOCK_DGRAM.rawValue)
private let logStreamSocket = Int32(SOCK_STREAM.rawValue)
#endif

/// Supervises either private log collector. Records are best effort; callers
/// never wait for the collector, disk, a query, or a restart to complete.
public final class ObstacleBridgeLogWorkerSupervisor: @unchecked Sendable {
    public enum Failure: Error, LocalizedError {
        case invalidConfiguration, unavailable
        public var errorDescription: String? {
            switch self {
            case .invalidConfiguration: return "invalid logging worker configuration"
            case .unavailable: return "logging worker unavailable"
            }
        }
    }

    private static let maxDatagram = 8 * 1024
    private let implementation: String
    private let executable: String
    /// Python's managed log ring uses a DEBUG root and optional component
    /// overrides; keep the same effective threshold for native-host children.
    public let proxyLogLevel: Int
    private let stateLock = NSLock()
    private let lifecycleLock = NSLock()
    private let queryLock = NSLock()
    private let monitorQueue = DispatchQueue(label: "org.obstaclebridge.desktop.logging-worker")
    private var process: Process?
    private var dataFD: Int32 = -1
    private var lifetimeFD: Int32 = -1
    private var stopped = true
    private var timer: DispatchSourceTimer?
    private var generation = 0
    private var restarts = 0
    private var failedStarts = 0
    private var droppedRecords = 0
    private var nextAttempt = Date.distantPast

    public init(implementation: String, executable: String, proxyLogLevel: Int = 0) throws {
        guard ["python", "native"].contains(implementation), !executable.isEmpty else { throw Failure.invalidConfiguration }
        self.implementation = implementation
        self.executable = executable
        self.proxyLogLevel = proxyLogLevel
    }

    /// Desktop configuration intentionally rejects sinks that the private
    /// collectors cannot own yet, rather than silently dropping file/UDP logs.
    public static func configured(from root: [String: Any]) throws -> ObstacleBridgeLogWorkerSupervisor? {
        let section = root["debug_logging"] as? [String: Any] ?? [:]
        func setting(_ key: String) -> Any? { section[key] ?? root[key] }
        let rawMode = setting("log_worker")
        guard rawMode == nil || rawMode is String else { throw Failure.invalidConfiguration }
        let mode = ((rawMode as? String) ?? "off").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard ["off", "python", "native"].contains(mode) else { throw Failure.invalidConfiguration }
        if mode == "off" { return nil }
        for key in ["log_file", "log_udp_target", "log_admin_udp_target"] {
            guard let value = setting(key), !(value is NSNull) else { continue }
            guard let text = value as? String, text.isEmpty else { throw Failure.invalidConfiguration }
        }
        for key in ["log_udp_only", "debug_stderr"] {
            guard let value = setting(key), !(value is NSNull) else { continue }
            guard let flag = value as? Bool, !flag else { throw Failure.invalidConfiguration }
        }
        let executableKey = "log_worker_\(mode)_executable"
        guard setting(executableKey) == nil || setting(executableKey) is String else { throw Failure.invalidConfiguration }
        let configured = (setting(executableKey) as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        let host = Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0])
        let executable = configured.flatMap { $0.isEmpty ? nil : $0 }
            ?? (mode == "python" ? "/usr/bin/python3" : host.deletingLastPathComponent().appendingPathComponent("ObstacleBridgeLogCollector").path)
        let proxy = root["proxy_provider"] as? [String: Any] ?? [:]
        let rawProxyLevel = proxy["log_proxy_provider"] ?? root["log_proxy_provider"]
        let levels = ["NOTSET": 0, "DEBUG": 10, "INFO": 20, "WARNING": 30, "WARN": 30,
                      "ERROR": 40, "CRITICAL": 50, "FATAL": 50]
        let proxyLevel = (rawProxyLevel as? String).flatMap { levels[$0.uppercased()] } ?? 0
        return try .init(implementation: mode, executable: executable, proxyLogLevel: proxyLevel)
    }

    private func socketPair(_ kind: Int32) throws -> (Int32, Int32) {
        var descriptors: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, kind, 0, &descriptors) == 0 else { throw Failure.unavailable }
        // The parent descriptor must not leak into the collector.  The child
        // descriptor is deliberately inherited because Process supplies it as
        // standard input or standard error during exec.
        guard fcntl(descriptors[0], F_SETFD, FD_CLOEXEC) == 0 else {
            close(descriptors[0]); close(descriptors[1]); throw Failure.unavailable
        }
        return (descriptors[0], descriptors[1])
    }

    private func waitReadable(_ fd: Int32, milliseconds: Int32) -> Bool {
        let deadline = DispatchTime.now().uptimeNanoseconds + UInt64(milliseconds) * 1_000_000
        while true {
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else { return false }
            var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let remaining = Int32(max(1, (deadline - now) / 1_000_000))
            let result = poll(&descriptor, 1, remaining)
            if result < 0 && errno == EINTR { continue }
            return result > 0 && descriptor.revents & Int16(POLLIN) != 0
        }
    }

    private func receive(_ fd: Int32, generation: UInt64) -> (kind: ObstacleBridgeWorkerIPC.Kind, payload: [String: Any])? {
        var bytes = [UInt8](repeating: 0, count: Self.maxDatagram + ObstacleBridgeWorkerIPC.headerBytes + 1)
        let count = recv(fd, &bytes, bytes.count, 0)
        guard count > 0, count <= Self.maxDatagram + ObstacleBridgeWorkerIPC.headerBytes,
              let decoded = try? ObstacleBridgeWorkerIPC.decode(Data(bytes.prefix(count))), let frame = decoded.0,
              decoded.1.isEmpty, frame.generation == generation,
              let object = try? JSONSerialization.jsonObject(with: frame.payload) as? [String: Any] else { return nil }
        return (frame.kind, object)
    }

    private func sendDatagram(_ fd: Int32, kind: ObstacleBridgeWorkerIPC.Kind, generation: UInt64, payload: [String: Any]) -> Bool {
        guard let data = try? JSONSerialization.data(withJSONObject: payload), !data.isEmpty, data.count <= Self.maxDatagram else { return false }
        guard let frame = try? ObstacleBridgeWorkerIPC.encode(kind: kind, generation: generation, payload: data),
              frame.count <= Self.maxDatagram + ObstacleBridgeWorkerIPC.headerBytes else { return false }
        #if os(Linux)
        let flags = Int32(MSG_DONTWAIT | MSG_NOSIGNAL)
        #else
        let flags = Int32(MSG_DONTWAIT)
        #endif
        return frame.withUnsafeBytes { send(fd, $0.baseAddress, $0.count, flags) } == frame.count
    }

    /// Call while lifecycleLock is held. The child inherits only the two
    /// private sockets as standard descriptors; stdout cannot stall the ring.
    private func launch() throws {
        let (parentData, childData) = try socketPair(logDatagramSocket)
        let parentLifetime: Int32, childLifetime: Int32
        do { (parentLifetime, childLifetime) = try socketPair(logStreamSocket) }
        catch { close(parentData); close(childData); throw error }
        var adopted = false
        let childInput = FileHandle(fileDescriptor: childData, closeOnDealloc: true)
        let childError = FileHandle(fileDescriptor: childLifetime, closeOnDealloc: true)
        let child = Process()
        defer {
            try? childInput.close(); try? childError.close()
            if !adopted {
                close(parentData); close(parentLifetime)
                if child.isRunning { _ = kill(child.processIdentifier, SIGKILL); child.waitUntilExit() }
            }
        }
        var bufferSize: Int32 = 64 * 1024
        for fd in [parentData, childData] {
            guard setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufferSize, socklen_t(MemoryLayout<Int32>.size)) == 0,
                  setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufferSize, socklen_t(MemoryLayout<Int32>.size)) == 0 else { throw Failure.unavailable }
        }
        #if os(macOS)
        var noSignal: Int32 = 1
        guard setsockopt(parentData, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size)) == 0 else { throw Failure.unavailable }
        #endif
        guard let nullOutput = FileHandle(forWritingAtPath: "/dev/null") else { throw Failure.unavailable }
        child.executableURL = URL(fileURLWithPath: executable)
        let nextGeneration = UInt64(generation + 1)
        child.arguments = (implementation == "python" ? ["-m", "obstacle_bridge.bridge_logging_ipc"] : []) + ["--private-fds", "0", "2", "--generation", String(nextGeneration)]
        child.standardInput = childInput
        child.standardError = childError
        child.standardOutput = nullOutput
        try child.run()
        try childInput.close(); try childError.close(); try nullOutput.close()
        guard waitReadable(parentData, milliseconds: 5_000),
              let ready = receive(parentData, generation: nextGeneration), ready.kind == .ready, ready.payload["v"] as? Int == 1,
              ready.payload["kind"] as? String == "worker.ready", ready.payload["role"] as? String == "logging",
              ready.payload["implementation"] as? String == implementation, child.isRunning else { throw Failure.unavailable }
        stateLock.lock()
        process = child; dataFD = parentData; lifetimeFD = parentLifetime; generation += 1
        stateLock.unlock()
        adopted = true
    }

    public func start() throws {
        lifecycleLock.lock(); defer { lifecycleLock.unlock() }
        stateLock.lock(); let canStart = stopped; stopped = false; stateLock.unlock()
        guard canStart else { throw Failure.invalidConfiguration }
        do { try launch() }
        catch { stateLock.lock(); stopped = true; stateLock.unlock(); throw error }
        let source = DispatchSource.makeTimerSource(queue: monitorQueue)
        source.schedule(deadline: .now() + .milliseconds(250), repeating: .milliseconds(250))
        source.setEventHandler { [weak self] in self?.recoverIfNeeded() }
        timer = source
        source.resume()
    }

    private func retireChild() -> Process? {
        stateLock.lock()
        let child = process, data = dataFD, lifetime = lifetimeFD
        process = nil; dataFD = -1; lifetimeFD = -1
        stateLock.unlock()
        if lifetime >= 0 { close(lifetime) }
        if data >= 0 { close(data) }
        return child
    }

    private func recoverIfNeeded() {
        guard lifecycleLock.try() else { return }
        defer { lifecycleLock.unlock() }
        stateLock.lock()
        let shouldRecover = !stopped && process?.isRunning != true && Date() >= nextAttempt
        stateLock.unlock()
        guard shouldRecover else { return }
        if let old = retireChild() { old.waitUntilExit() }
        do {
            try launch()
            stateLock.lock(); restarts += 1; stateLock.unlock()
        } catch {
            stateLock.lock(); failedStarts += 1; nextAttempt = Date().addingTimeInterval(1); stateLock.unlock()
        }
    }

    /// Messages are bounded and sent without waiting. Callers must not pass
    /// credentials, packet contents, or other sensitive payloads.
    public func emit(name: String, level: String, levelNumber: Int, message: String) {
        guard stateLock.try() else { return }
        defer { stateLock.unlock() }
        guard !stopped, dataFD >= 0, process?.isRunning == true else { droppedRecords += 1; return }
        let record: [String: Any] = ["v": 1, "created": Date().timeIntervalSince1970, "name": String(name.prefix(256)),
                                     "level": String(level.prefix(32)), "levelno": levelNumber,
                                     "message": String(message.prefix(4096)), "process": Int(ProcessInfo.processInfo.processIdentifier), "thread": "native"]
        if !sendDatagram(dataFD, kind: .data, generation: UInt64(generation), payload: record) { droppedRecords += 1 }
    }

    /// A child gets a separate record-only socket, never the Admin query
    /// capability. The relay follows collector replacement automatically.
    public func makeProducerRelay() throws -> ObstacleBridgeLogProducerRelay {
        try ObstacleBridgeLogProducerRelay(supervisor: self)
    }

    public func recordRelayAllocationFailure() {
        stateLock.lock(); droppedRecords += 1; stateLock.unlock()
    }

    fileprivate func forwardRecord(_ data: Data) {
        // This runs on the relay's dedicated queue rather than on a proxy
        // request path.  Wait for a concurrent lifecycle transition instead
        // of silently losing a child record while it holds stateLock.
        stateLock.lock()
        defer { stateLock.unlock() }
        guard !stopped, dataFD >= 0, process?.isRunning == true else { droppedRecords += 1; return }
        #if os(Linux)
        let flags = Int32(MSG_DONTWAIT | MSG_NOSIGNAL)
        #else
        let flags = Int32(MSG_DONTWAIT)
        #endif
        guard let frame = try? ObstacleBridgeWorkerIPC.encode(kind: .data, generation: UInt64(generation), payload: data) else { droppedRecords += 1; return }
        let sent = frame.withUnsafeBytes { send(dataFD, $0.baseAddress, $0.count, flags) }
        if sent != frame.count { droppedRecords += 1 }
    }

    public func fetch(limit: Int) -> [String: Any] {
        let unavailable: [String: Any] = ["available": false, "lines": [String](), "error": "logger unavailable"]
        guard queryLock.try() else { return unavailable }
        defer { queryLock.unlock() }
        stateLock.lock()
        let currentGeneration = generation
        let descriptor = !stopped && process?.isRunning == true && dataFD >= 0 ? fcntl(dataFD, F_DUPFD_CLOEXEC, 3) : -1
        stateLock.unlock()
        guard descriptor >= 0 else { return unavailable }
        defer { close(descriptor) }
        let requestID = UUID().uuidString.lowercased()
        guard sendDatagram(descriptor, kind: .request, generation: UInt64(currentGeneration), payload: ["v": 1, "kind": "logs.query", "limit": max(1, min(limit, 1000)), "request_id": requestID]),
              waitReadable(descriptor, milliseconds: 150), let reply = receive(descriptor, generation: UInt64(currentGeneration)), reply.kind == .response,
              reply.payload["v"] as? Int == 1, reply.payload["kind"] as? String == "logs.reply", reply.payload["ok"] as? Bool == true,
              reply.payload["request_id"] as? String == requestID, let lines = reply.payload["lines"] as? [String] else { return unavailable }
        stateLock.lock(); let current = !stopped && generation == currentGeneration && process?.isRunning == true; stateLock.unlock()
        return current ? ["available": true, "lines": lines, "error": ""] : unavailable
    }

    public func status() -> [String: Any] {
        stateLock.lock(); defer { stateLock.unlock() }
        let running = !stopped && process?.isRunning == true
        return ["implementation": implementation, "state": stopped ? "stopped" : (running ? "running" : "restarting"),
                "pid": Int(process?.processIdentifier ?? 0), "generation": generation, "restarts": restarts,
                "failed_starts": failedStarts, "dropped_records": droppedRecords]
    }

    public func stop() {
        lifecycleLock.lock(); defer { lifecycleLock.unlock() }
        timer?.cancel(); timer = nil
        stateLock.lock(); stopped = true; stateLock.unlock()
        guard let child = retireChild() else { return }
        let deadline = Date().addingTimeInterval(1)
        while child.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.02) }
        if child.isRunning { _ = kill(child.processIdentifier, SIGKILL) }
        child.waitUntilExit()
    }

    deinit { stop() }
}

/// Bounded record-only ingress; malformed records and queries never reach the
/// collector. Cancellation closes the read descriptor on its own queue.
public final class ObstacleBridgeLogProducerRelay: @unchecked Sendable {
    private weak var supervisor: ObstacleBridgeLogWorkerSupervisor?
    private let readFD: Int32
    public let childHandle: FileHandle
    private let source: DispatchSourceRead

    fileprivate init(supervisor: ObstacleBridgeLogWorkerSupervisor) throws {
        var fds: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, logDatagramSocket, 0, &fds) == 0 else { throw ObstacleBridgeLogWorkerSupervisor.Failure.unavailable }
        let readFD = fds[0], childFD = fds[1]
        var adopted = false
        defer { if !adopted { close(readFD); close(childFD) } }
        guard fcntl(readFD, F_SETFD, FD_CLOEXEC) == 0, fcntl(childFD, F_SETFD, FD_CLOEXEC) == 0 else {
            throw ObstacleBridgeLogWorkerSupervisor.Failure.unavailable
        }
        let flags = fcntl(readFD, F_GETFL)
        guard flags >= 0, fcntl(readFD, F_SETFL, flags | O_NONBLOCK) == 0 else { throw ObstacleBridgeLogWorkerSupervisor.Failure.unavailable }
        var bufferSize: Int32 = 64 * 1024
        for fd in [readFD, childFD] {
            guard setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufferSize, socklen_t(MemoryLayout<Int32>.size)) == 0,
                  setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufferSize, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
                throw ObstacleBridgeLogWorkerSupervisor.Failure.unavailable
            }
        }
        #if os(macOS)
        var noSignal: Int32 = 1
        guard setsockopt(childFD, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            throw ObstacleBridgeLogWorkerSupervisor.Failure.unavailable
        }
        #endif
        self.supervisor = supervisor
        self.readFD = readFD
        self.childHandle = FileHandle(fileDescriptor: childFD, closeOnDealloc: true)
        self.source = DispatchSource.makeReadSource(fileDescriptor: readFD, queue: DispatchQueue(label: "org.obstaclebridge.desktop.log-relay"))
        source.setEventHandler { [weak self] in self?.drain() }
        source.setCancelHandler { close(readFD) }
        adopted = true
        source.resume()
    }

    private func drain() {
        for _ in 0..<128 {
            var bytes = [UInt8](repeating: 0, count: 8193)
            let count = recv(readFD, &bytes, bytes.count, Int32(MSG_DONTWAIT))
            guard count > 0 else { return }
            guard count <= 8192 else { continue }
            let data = Data(bytes.prefix(count))
            guard let record = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  record["v"] as? Int == 1, record["kind"] == nil else { continue }
            supervisor?.forwardRecord(data)
        }
    }

    public func releaseChildHandle() { try? childHandle.close() }
    public func stop() { source.cancel(); releaseChildHandle() }
    deinit { stop() }
}

/// A native child-side endpoint for a producer-only inherited logging
/// capability. It has no query or collector-lifecycle operations.
public final class ObstacleBridgeLogProducer: @unchecked Sendable {
    private static let maxDatagram = 8 * 1024
    private let descriptor: Int32
    private let minimumLevel: Int

    public init(inheritedFD: Int32, minimumLevel: Int = 0) throws {
        guard inheritedFD >= 0 else { throw ObstacleBridgeLogWorkerSupervisor.Failure.unavailable }
        var socketType: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(inheritedFD, SOL_SOCKET, SO_TYPE, &socketType, &length) == 0,
              socketType == logDatagramSocket else { throw ObstacleBridgeLogWorkerSupervisor.Failure.unavailable }
        let flags = fcntl(inheritedFD, F_GETFL)
        guard flags >= 0, fcntl(inheritedFD, F_SETFL, flags | O_NONBLOCK) == 0 else {
            throw ObstacleBridgeLogWorkerSupervisor.Failure.unavailable
        }
        self.descriptor = inheritedFD
        self.minimumLevel = minimumLevel
    }

    public func emit(name: String, level: String, levelNumber: Int, message: String) {
        guard levelNumber >= minimumLevel else { return }
        let record: [String: Any] = [
            "v": 1,
            "created": Date().timeIntervalSince1970,
            "name": String(name.prefix(256)),
            "level": String(level.prefix(32)),
            "levelno": levelNumber,
            "message": String(message.prefix(4096)),
            "process": Int(ProcessInfo.processInfo.processIdentifier),
            "thread": "native",
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: record),
              !data.isEmpty, data.count <= Self.maxDatagram else { return }
        #if os(Linux)
        let flags = Int32(MSG_DONTWAIT | MSG_NOSIGNAL)
        #else
        let flags = Int32(MSG_DONTWAIT)
        #endif
        _ = data.withUnsafeBytes { send(descriptor, $0.baseAddress, $0.count, flags) }
    }

    deinit { close(descriptor) }
}
#endif
