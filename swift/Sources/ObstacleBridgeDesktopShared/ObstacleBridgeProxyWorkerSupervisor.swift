#if os(macOS) || os(Linux)
import Foundation
import Dispatch
#if os(macOS)
import Darwin
private let proxySupervisorStreamType = SOCK_STREAM
#else
import Glibc
private let proxySupervisorStreamType = Int32(SOCK_STREAM.rawValue)
#endif

/// Native desktop owner for either proxy implementation. The control channel
/// is an inherited Unix socket, not an externally discoverable endpoint.
public final class ObstacleBridgeProxyWorkerSupervisor: @unchecked Sendable {
    public enum Failure: Error, LocalizedError {
        case invalidConfiguration, invalidFrame, unavailable, timeout
        public var errorDescription: String? {
            switch self {
            case .invalidConfiguration: return "invalid proxy worker configuration"
            case .invalidFrame: return "invalid proxy worker frame"
            case .unavailable: return "proxy worker unavailable"
            case .timeout: return "proxy worker timed out"
            }
        }
    }

    private let implementation: String
    private let executable: String
    private let loggingWorker: ObstacleBridgeLogWorkerSupervisor?
    private let lock = NSLock()
    private let writeLock = NSLock()
    private let readerGroup = DispatchGroup()
    private var child: Process?
    private var control: Int32 = -1
    private var listeners: [String: Any] = [:]
    private var capabilities: [String: Any] = [:]
    private var generation = 0
    private var lastError = ""
    private var stopping = false
    private var logRelay: ObstacleBridgeLogProducerRelay?
    private static let maxFrame = 65_536

    public init(implementation: String, executable: String, loggingWorker: ObstacleBridgeLogWorkerSupervisor? = nil) throws {
        guard ["python", "native"].contains(implementation), !executable.isEmpty else { throw Failure.invalidConfiguration }
        self.implementation = implementation
        self.executable = executable
        self.loggingWorker = loggingWorker
    }

    private static func waitReady(_ fd: Int32, events: Int16, deadline: UInt64) throws {
        while true {
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else { throw Failure.timeout }
            let remaining = max(1, min(UInt64(Int32.max), (deadline - now) / 1_000_000))
            var descriptor = pollfd(fd: fd, events: events, revents: 0)
            let result = poll(&descriptor, 1, Int32(remaining))
            if result < 0 && errno == EINTR { continue }
            if result == 0 { throw Failure.timeout }
            guard result > 0, descriptor.revents & events != 0 else { throw Failure.unavailable }
            return
        }
    }

    private static func readExact(_ fd: Int32, count: Int, deadline: UInt64) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        var offset = 0
        while offset < count {
            try waitReady(fd, events: Int16(POLLIN), deadline: deadline)
            let n = bytes.withUnsafeMutableBytes { recv(fd, $0.baseAddress!.advanced(by: offset), count - offset, 0) }
            if n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) { continue }
            guard n > 0 else { throw Failure.unavailable }
            offset += n
        }
        return Data(bytes)
    }

    private static func readFrame(_ fd: Int32, timeout: UInt64) throws -> [String: Any] {
        let deadline = DispatchTime.now().uptimeNanoseconds + timeout
        let header = try readExact(fd, count: ObstacleBridgeWorkerIPC.headerBytes, deadline: deadline)
        guard let size = try ObstacleBridgeWorkerIPC.frameSize(header), size <= maxFrame else { throw Failure.invalidFrame }
        let (frame, remainder) = try ObstacleBridgeWorkerIPC.decode(header + (try readExact(fd, count: size, deadline: deadline)))
        guard let frame, remainder.isEmpty else { throw Failure.invalidFrame }
        let value = try ObstacleBridgeWorkerIPC.decodeControl(frame)
        guard value["v"] as? Int == 1 else { throw Failure.invalidFrame }
        return value
    }

    private func writeFrame(_ fd: Int32, value: [String: Any]) throws {
        let rawKind = value["kind"] as? String ?? ""
        let kind: ObstacleBridgeWorkerIPC.Kind = rawKind == "proxy.start" || rawKind == "proxy.stop" ? .request : .response
        let generation = UInt64((value["generation"] as? Int) ?? 1)
        let frame = try ObstacleBridgeWorkerIPC.encodeControl(kind: kind, generation: generation, value: value)
        guard frame.count - ObstacleBridgeWorkerIPC.headerBytes <= Self.maxFrame else { throw Failure.invalidFrame }
        let deadline = DispatchTime.now().uptimeNanoseconds + 1_000_000_000
        writeLock.lock(); defer { writeLock.unlock() }
        var offset = 0
        while offset < frame.count {
            try Self.waitReady(fd, events: Int16(POLLOUT), deadline: deadline)
            #if os(Linux)
            let flags = Int32(MSG_NOSIGNAL)
            #else
            let flags: Int32 = 0
            #endif
            let n = frame.withUnsafeBytes { send(fd, $0.baseAddress!.advanced(by: offset), frame.count - offset, flags) }
            if n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) { continue }
            guard n > 0 else { throw Failure.unavailable }
            offset += n
        }
    }

    /// The bootstrap dictionary is sent only on the inherited control socket.
    public func start(config: [String: Any], generation expectedGeneration: Int = 1) throws {
        lock.lock()
        let alreadyStarted = child != nil
        lock.unlock()
        guard !alreadyStarted, expectedGeneration > 0 else { throw Failure.invalidConfiguration }
        var fds: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, proxySupervisorStreamType, 0, &fds) == 0 else { throw Failure.unavailable }
        let parentFD = fds[0], childFD = fds[1]
        // The parent end must not leak into the worker.  The child end is
        // deliberately left inheritable: Foundation's macOS Process adapter
        // installs this descriptor as standard input during exec.  Marking it
        // close-on-exec made that hand-off platform dependent and caused the
        // private proxy worker to exit before its ready frame.
        guard fcntl(parentFD, F_SETFD, FD_CLOEXEC) == 0 else {
            close(parentFD); close(childFD); throw Failure.unavailable
        }
        let flags = fcntl(parentFD, F_GETFL)
        guard flags >= 0, fcntl(parentFD, F_SETFL, flags | O_NONBLOCK) == 0 else {
            close(parentFD); close(childFD); throw Failure.unavailable
        }
        #if os(macOS)
        var noSignal: Int32 = 1
        guard setsockopt(parentFD, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            close(parentFD); close(childFD); throw Failure.unavailable
        }
        #endif
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = (implementation == "python" ? ["-m", "obstacle_bridge.bridge_proxy_worker"] : []) + ["--control-fd", "0"]
        let childInput = FileHandle(fileDescriptor: childFD, closeOnDealloc: true)
        process.standardInput = childInput
        var relay: ObstacleBridgeLogProducerRelay?
        if let loggingWorker {
            do { relay = try loggingWorker.makeProducerRelay() }
            catch { loggingWorker.recordRelayAllocationFailure() }
        }
        if let relay {
            process.arguments?.append(contentsOf: ["--log-fd", "2"])
            process.standardError = relay.childHandle
        }
        do {
            try process.run()
            relay?.releaseChildHandle()
            lock.lock(); child = process; control = parentFD; stopping = false; logRelay = relay; lock.unlock()
            try childInput.close()
            try writeFrame(parentFD, value: ["v": 1, "kind": "proxy.start", "generation": expectedGeneration, "config": config,
                                             "log_root_level": 10, "log_levels": ["proxy_provider": loggingWorker?.proxyLogLevel ?? 0]])
            let response = try Self.readFrame(parentFD, timeout: 5_000_000_000)
            if response["kind"] as? String == "proxy.error",
               let code = response["code"] as? String,
               ["invalid_configuration", "startup_failed"].contains(code) {
                throw code == "invalid_configuration" ? Failure.invalidConfiguration : Failure.unavailable
            }
            guard response["kind"] as? String == "proxy.ready", response["implementation"] as? String == implementation,
                  response["generation"] as? Int == expectedGeneration,
                  let advertised = response["capabilities"] as? [String: Any],
                  let initial = response["listeners"] as? [String: Any] else { throw Failure.invalidFrame }
            lock.lock(); listeners = initial; capabilities = advertised; generation = expectedGeneration; lastError = ""; lock.unlock()
            readerGroup.enter()
            let group = readerGroup
            DispatchQueue.global().async { [weak self] in
                defer { group.leave() }
                do {
                    while true {
                        let event = try Self.readFrame(parentFD, timeout: 3_000_000_000)
                        guard event["kind"] as? String == "proxy.snapshot", event["generation"] as? Int == expectedGeneration,
                              let updated = event["listeners"] as? [String: Any] else { throw Failure.invalidFrame }
                        guard let owner = self else { return }
                        owner.lock.lock()
                        if owner.generation == expectedGeneration { owner.listeners = updated }
                        owner.lock.unlock()
                    }
                } catch {
                    guard let owner = self else { return }
                    owner.lock.lock()
                    if !owner.stopping && owner.generation == expectedGeneration {
                        owner.listeners = [:]; owner.lastError = "unavailable"
                    }
                    owner.lock.unlock()
                }
            }
        } catch {
            try? childInput.close()
            relay?.stop()
            lock.lock()
            let adopted = child != nil
            lock.unlock()
            if adopted { stop() } else { close(parentFD) }
            throw error
        }
    }

    public func snapshot() -> [String: Any] {
        lock.lock(); defer { lock.unlock() }
        let running = child?.isRunning == true && lastError.isEmpty && !stopping
        return ["worker": ["implementation": implementation, "state": running ? "running" : "unavailable",
                            "pid": Int(child?.processIdentifier ?? 0), "generation": generation],
                "capabilities": running ? capabilities : [:], "listeners": running ? listeners : [:], "last_error": lastError]
    }

    public func stop() {
        lock.lock()
        guard let process = child, !stopping else { lock.unlock(); return }
        stopping = true
        let fd = control, relay = logRelay
        logRelay = nil
        lock.unlock()
        try? writeFrame(fd, value: ["v": 1, "kind": "proxy.stop"])
        _ = shutdown(fd, Int32(SHUT_RDWR))
        _ = readerGroup.wait(timeout: .now() + 2)
        close(fd)
        let deadline = Date().addingTimeInterval(2)
        while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.02) }
        if process.isRunning {
            _ = kill(process.processIdentifier, SIGKILL)
        }
        process.waitUntilExit()
        relay?.stop()
        lock.lock(); child = nil; control = -1; listeners = [:]; capabilities = [:]; lock.unlock()
    }

    deinit { stop() }
}

/// Restarts either selected proxy implementation without replacing it with an
/// in-process listener. Each generation receives a fresh control capability.
public final class ObstacleBridgeSupervisedProxyWorker: @unchecked Sendable {
    private let implementation: String
    private let executable: String
    private let loggingWorker: ObstacleBridgeLogWorkerSupervisor?
    private let stateLock = NSLock()
    private let lifecycleLock = NSLock()
    private let monitorQueue = DispatchQueue(label: "org.obstaclebridge.desktop.proxy-supervisor")
    private var active: ObstacleBridgeProxyWorkerSupervisor?
    private var configuration: [String: Any]?
    private var timer: DispatchSourceTimer?
    private var stopped = true
    private var generation = 0
    private var failedStarts = 0
    private var lastError = ""
    private var nextAttempt = Date.distantPast
    private var retryDelay: TimeInterval = 0.25

    public init(implementation: String, executable: String, loggingWorker: ObstacleBridgeLogWorkerSupervisor? = nil) throws {
        guard ["python", "native"].contains(implementation), !executable.isEmpty else {
            throw ObstacleBridgeProxyWorkerSupervisor.Failure.invalidConfiguration
        }
        self.implementation = implementation
        self.executable = executable
        self.loggingWorker = loggingWorker
    }

    /// Lifecycle lock is held. Bootstrap credentials stay on private sockets
    /// and in the owner's in-memory configuration; they are never status data.
    private func launch(_ config: [String: Any]) throws {
        let worker = try ObstacleBridgeProxyWorkerSupervisor(implementation: implementation, executable: executable, loggingWorker: loggingWorker)
        stateLock.lock(); let expectedGeneration = generation + 1; stateLock.unlock()
        try worker.start(config: config, generation: expectedGeneration)
        let snapshot = worker.snapshot()
        var nextConfig = config
        let listeners = snapshot["listeners"] as? [String: Any] ?? [:]
        for name in ["http", "socks5"] {
            let key = "\(name)_port"
            let configuredPort = (config[key] as? NSNumber)?.intValue ?? 0
            if configuredPort == 0, let listener = listeners[name] as? [String: Any],
               let port = listener["bound_port"] as? Int, port > 0 {
                nextConfig[key] = port
            }
        }
        stateLock.lock()
        active = worker; configuration = nextConfig; generation = expectedGeneration; lastError = ""
        stateLock.unlock()
    }

    public func start(config: [String: Any]) throws {
        lifecycleLock.lock(); defer { lifecycleLock.unlock() }
        stateLock.lock(); let canStart = stopped && generation == 0; if canStart { stopped = false }; stateLock.unlock()
        guard canStart else { throw ObstacleBridgeProxyWorkerSupervisor.Failure.invalidConfiguration }
        do { try launch(config) }
        catch { stateLock.lock(); stopped = true; stateLock.unlock(); throw error }
        let source = DispatchSource.makeTimerSource(queue: monitorQueue)
        source.schedule(deadline: .now() + .milliseconds(250), repeating: .milliseconds(250))
        source.setEventHandler { [weak self] in self?.recoverIfNeeded() }
        timer = source
        source.resume()
    }

    private func recoverIfNeeded() {
        guard lifecycleLock.try() else { return }
        defer { lifecycleLock.unlock() }
        stateLock.lock(); let worker = active; let isStopped = stopped; stateLock.unlock()
        guard !isStopped else { return }
        if let worker {
            let snapshot = worker.snapshot()
            let state = (snapshot["worker"] as? [String: Any])?["state"] as? String
            guard state != "running" else { return }
            stateLock.lock(); active = nil; lastError = "unavailable"; nextAttempt = Date().addingTimeInterval(0.25); stateLock.unlock()
            worker.stop()
            return
        }
        stateLock.lock(); let config = configuration; let ready = Date() >= nextAttempt; stateLock.unlock()
        guard ready, let config else { return }
        do {
            try launch(config)
            stateLock.lock(); retryDelay = 0.25; stateLock.unlock()
        } catch {
            stateLock.lock()
            failedStarts += 1
            if let failure = error as? ObstacleBridgeProxyWorkerSupervisor.Failure {
                switch failure {
                case .invalidConfiguration: lastError = "invalid_configuration"
                case .invalidFrame, .unavailable, .timeout: lastError = "startup_failed"
                }
            } else { lastError = "startup_failed" }
            nextAttempt = Date().addingTimeInterval(retryDelay)
            retryDelay = min(retryDelay * 2, 5)
            stateLock.unlock()
        }
    }

    public func snapshot() -> [String: Any] {
        stateLock.lock()
        let worker = active, localGeneration = generation, localRestarts = max(0, generation - 1), localFailures = failedStarts, localError = lastError, isStopped = stopped
        stateLock.unlock()
        let snapshot = worker?.snapshot() ?? [:]
        stateLock.lock(); let current = !stopped && active === worker && generation == localGeneration; stateLock.unlock()
        let inner = snapshot["worker"] as? [String: Any] ?? [:]
        let running = current && inner["state"] as? String == "running"
        return ["worker": ["implementation": implementation, "state": isStopped ? "stopped" : (running ? "running" : "unavailable"),
                           "pid": running ? (inner["pid"] as? Int ?? 0) : 0, "generation": localGeneration,
                           "restarts": localRestarts, "failed_starts": localFailures,
                           "capabilities": running ? (snapshot["capabilities"] ?? [:]) : [:]],
                "listeners": running ? (snapshot["listeners"] ?? [:]) : [:],
                "last_error": running || isStopped ? "" : (localError.isEmpty ? "unavailable" : localError)]
    }

    public func stop() {
        lifecycleLock.lock(); defer { lifecycleLock.unlock() }
        timer?.cancel(); timer = nil
        stateLock.lock(); stopped = true; lastError = ""; let worker = active; active = nil; configuration = nil; stateLock.unlock()
        worker?.stop()
    }

    deinit { stop() }
}
#endif
