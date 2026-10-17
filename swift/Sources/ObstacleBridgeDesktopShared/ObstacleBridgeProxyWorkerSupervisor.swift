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
    private let lock = NSLock()
    private let writeLock = NSLock()
    private let readerGroup = DispatchGroup()
    private var child: Process?
    private var control: Int32 = -1
    private var listeners: [String: Any] = [:]
    private var lastError = ""
    private var stopping = false
    private static let maxFrame = 65_536

    public init(implementation: String, executable: String) throws {
        guard ["python", "native"].contains(implementation), !executable.isEmpty else { throw Failure.invalidConfiguration }
        self.implementation = implementation
        self.executable = executable
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
        let prefix = [UInt8](try readExact(fd, count: 4, deadline: deadline))
        let size = prefix.reduce(0) { ($0 << 8) | Int($1) }
        guard size > 0, size <= maxFrame else { throw Failure.invalidFrame }
        let body = try readExact(fd, count: size, deadline: deadline)
        guard let value = try JSONSerialization.jsonObject(with: body) as? [String: Any], value["v"] as? Int == 1 else {
            throw Failure.invalidFrame
        }
        return value
    }

    private func writeFrame(_ fd: Int32, value: [String: Any]) throws {
        let data = try JSONSerialization.data(withJSONObject: value)
        guard !data.isEmpty, data.count <= Self.maxFrame else { throw Failure.invalidFrame }
        let size = UInt32(data.count)
        var frame = Data([UInt8((size >> 24) & 255), UInt8((size >> 16) & 255), UInt8((size >> 8) & 255), UInt8(size & 255)])
        frame.append(data)
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
    public func start(config: [String: Any]) throws {
        lock.lock()
        let alreadyStarted = child != nil
        lock.unlock()
        guard !alreadyStarted else { throw Failure.invalidConfiguration }
        var fds: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, proxySupervisorStreamType, 0, &fds) == 0 else { throw Failure.unavailable }
        let parentFD = fds[0], childFD = fds[1]
        guard fcntl(parentFD, F_SETFD, FD_CLOEXEC) == 0, fcntl(childFD, F_SETFD, FD_CLOEXEC) == 0 else {
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
        do {
            try process.run()
            lock.lock(); child = process; control = parentFD; stopping = false; lock.unlock()
            try childInput.close()
            try writeFrame(parentFD, value: ["v": 1, "kind": "proxy.start", "config": config])
            let response = try Self.readFrame(parentFD, timeout: 5_000_000_000)
            guard response["kind"] as? String == "proxy.ready", response["implementation"] as? String == implementation,
                  let initial = response["listeners"] as? [String: Any] else { throw Failure.invalidFrame }
            lock.lock(); listeners = initial; lastError = ""; lock.unlock()
            readerGroup.enter()
            let group = readerGroup
            DispatchQueue.global().async { [weak self] in
                defer { group.leave() }
                do {
                    while true {
                        let event = try Self.readFrame(parentFD, timeout: 3_000_000_000)
                        guard event["kind"] as? String == "proxy.snapshot", let updated = event["listeners"] as? [String: Any] else { throw Failure.invalidFrame }
                        guard let owner = self else { return }
                        owner.lock.lock(); owner.listeners = updated; owner.lock.unlock()
                    }
                } catch {
                    guard let owner = self else { return }
                    owner.lock.lock()
                    if !owner.stopping { owner.listeners = [:]; owner.lastError = "proxy worker unavailable" }
                    owner.lock.unlock()
                }
            }
        } catch {
            try? childInput.close()
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
                            "pid": Int(child?.processIdentifier ?? 0)],
                "listeners": running ? listeners : [:], "last_error": lastError]
    }

    public func stop() {
        lock.lock()
        guard let process = child, !stopping else { lock.unlock(); return }
        stopping = true
        let fd = control
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
        lock.lock(); child = nil; control = -1; listeners = [:]; lock.unlock()
    }

    deinit { stop() }
}
#endif
