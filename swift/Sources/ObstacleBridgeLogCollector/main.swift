import Foundation
import Dispatch
#if SWIFT_PACKAGE
import ObstacleBridgeDesktopShared
#endif
#if canImport(Darwin)
import Darwin
private let datagramSocketType = SOCK_DGRAM
private let streamSocketType = SOCK_STREAM
#else
import Glibc
private let datagramSocketType = Int32(SOCK_DGRAM.rawValue)
private let streamSocketType = Int32(SOCK_STREAM.rawValue)
#endif

// Public UDP v1 is unauthenticated and restricted to loopback. Private mode
// receives anonymous sockets inherited from its supervisor instead.
private let maxDatagram = 60 * 1024
// Keep replies below the default Darwin UDP send limit as well as Linux's.
private let maxReplyDatagram = 8 * 1024
private let ringLimit = 1_200
private let ringByteLimit = 1_048_576
private let privateStartupTimeoutMS: Int32 = 5_000

private func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("\(message)\n".utf8))
    exit(1)
}

private func parsePort(_ arguments: [String]) -> UInt16 {
    guard arguments.count == 3, arguments[1] == "--bind",
          arguments[2].hasPrefix("127.0.0.1:"),
          let port = UInt16(arguments[2].dropFirst("127.0.0.1:".count)), port > 0 else {
        fail("usage: ObstacleBridgeLogCollector --bind 127.0.0.1:PORT")
    }
    return port
}

private func render(_ payload: [String: Any]) -> String? {
    guard let name = payload["name"] as? String,
          let level = payload["level"] as? String,
          let message = payload["message"] as? String,
          let created = payload["created"] as? NSNumber,
          created.doubleValue.isFinite,
          (0...253_402_300_799).contains(created.doubleValue) else { return nil }
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.dateFormat = "yyyy-MM-dd HH:mm:ss,SSS"
    let timestamp = formatter.string(from: Date(timeIntervalSince1970: created.doubleValue))
    let exception = (payload["exception"] as? String).map { "\n" + $0 } ?? ""
    return "\(timestamp) \(level) \(name): \(message)\(exception)"
}

private func reply(_ lines: [String], limit: Int, requestID: String?) -> Data? {
    var payload: [String: Any] = ["v": 1, "kind": "logs.reply", "ok": true, "lines": [String]()]
    if let requestID, requestID.utf8.count <= 64 { payload["request_id"] = requestID }
    guard let empty = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]) else { return nil }
    var bytes = empty.count
    var newestFirst: [String] = []
    for line in lines.suffix(max(1, min(limit, 1_000))).reversed() {
        guard let encoded = try? JSONSerialization.data(withJSONObject: [line], options: [.sortedKeys]) else { return nil }
        let extra = encoded.count - 2 + (newestFirst.isEmpty ? 0 : 1)
        if bytes + extra > maxReplyDatagram { break }
        newestFirst.append(line)
        bytes += extra
    }
    payload["lines"] = Array(newestFirst.reversed())
    guard let result = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]), result.count <= maxReplyDatagram else { return nil }
    return result
}

private func socketType(_ fd: Int32) -> Int32? {
    var kind: Int32 = 0
    var size = socklen_t(MemoryLayout<Int32>.size)
    guard getsockopt(fd, SOL_SOCKET, SO_TYPE, &kind, &size) == 0 else { return nil }
    var address = sockaddr_storage()
    var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
    let result = withUnsafeMutablePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
    }
    guard result == 0, Int32(address.ss_family) == AF_UNIX else { return nil }
    return kind
}

let arguments = CommandLine.arguments
let privateMode = arguments.count == 6 && arguments[1] == "--private-fds" && arguments[4] == "--generation"
let socketFD: Int32
let lifetimeFD: Int32
let privateGeneration: UInt64
if privateMode {
    guard let data = Int32(arguments[2]), let lifetime = Int32(arguments[3]),
          let generation = UInt64(arguments[5]), generation > 0,
          data >= 0, lifetime >= 0, data != lifetime,
          socketType(data) == datagramSocketType, socketType(lifetime) == streamSocketType else {
        fail("invalid private logging sockets")
    }
    socketFD = data
    lifetimeFD = lifetime
    privateGeneration = generation
    var startupDescriptors = [pollfd(fd: data, events: Int16(POLLIN), revents: 0), pollfd(fd: lifetime, events: Int16(POLLIN), revents: 0)]
    let startupPoll = poll(&startupDescriptors, nfds_t(startupDescriptors.count), privateStartupTimeoutMS)
    guard startupPoll > 0, startupDescriptors[1].revents == 0,
          startupDescriptors[0].revents & Int16(POLLIN) != 0 else {
        fail("logging worker startup timed out")
    }
    var helloBuffer = [UInt8](repeating: 0, count: maxDatagram + ObstacleBridgeWorkerIPC.headerBytes + 1)
    // The startup poll only grants a bounded opportunity to authenticate the
    // inherited datagram; it must not turn into a blocking read if readiness
    // was consumed while the worker was scheduled.
    let helloCount = recv(data, &helloBuffer, helloBuffer.count, Int32(MSG_DONTWAIT))
    guard helloCount > 0, helloCount <= maxDatagram + ObstacleBridgeWorkerIPC.headerBytes,
          let decoded = try? ObstacleBridgeWorkerIPC.decode(Data(helloBuffer.prefix(helloCount))),
          let hello = decoded.0, decoded.1.isEmpty, hello.kind == .hello, hello.generation == generation,
          let helloPayload = try? ObstacleBridgeWorkerIPC.decodeControl(hello),
          helloPayload["v"] as? Int == 1, helloPayload["kind"] as? String == "worker.hello",
          helloPayload["role"] as? String == "supervisor",
          helloPayload["capabilities"] as? [String] == ["logging.query", "logging.records"] else {
        fail("invalid logging worker capability request")
    }
    let helloReply = try ObstacleBridgeWorkerIPC.encodeControl(kind: .hello, generation: generation, value: [
        "v": 1, "kind": "worker.hello", "role": "logging",
        "capabilities": ["logging.query", "logging.records"],
    ])
    let helloSent = helloReply.withUnsafeBytes { send(data, $0.baseAddress, $0.count, 0) }
    guard helloSent == helloReply.count else { fail("unable to negotiate logging worker") }
    let ready = try ObstacleBridgeWorkerIPC.encodeControl(kind: .ready, generation: generation, value: [
        "v": 1, "kind": "worker.ready", "role": "logging", "implementation": "native",
    ])
    let sent = ready.withUnsafeBytes { send(data, $0.baseAddress, $0.count, 0) }
    guard sent == ready.count else { fail("unable to announce logging worker") }
} else {
    let port = parsePort(arguments)
    socketFD = socket(AF_INET, datagramSocketType, 0)
    lifetimeFD = -1
    privateGeneration = 0
    guard socketFD >= 0 else { fail("unable to create collector socket") }
    var bindAddress = sockaddr_in()
    bindAddress.sin_family = sa_family_t(AF_INET)
    bindAddress.sin_port = port.bigEndian
    bindAddress.sin_addr = in_addr(s_addr: UInt32(0x7f000001).bigEndian)
    let bound = withUnsafePointer(to: &bindAddress) { address in
        address.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            bind(socketFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    guard bound == 0 else { fail("unable to bind collector socket") }
}
defer { close(socketFD) }
defer { if lifetimeFD >= 0 { close(lifetimeFD) } }

final class CollectorState {
    private let socketFD: Int32
    private let privateMode: Bool
    private let generation: UInt64
    private var lines: [String] = []
    private var ringBytes = 0

    init(socketFD: Int32, privateMode: Bool, generation: UInt64) {
        self.socketFD = socketFD
        self.privateMode = privateMode
        self.generation = generation
    }

    func drainReadableDatagrams() {
        while true {
            var buffer = [UInt8](repeating: 0, count: 65_535)
            var peer = sockaddr_storage()
            var peerLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let count = withUnsafeMutablePointer(to: &peer) { address in
                address.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    recvfrom(socketFD, &buffer, buffer.count, Int32(MSG_DONTWAIT), $0, &peerLength)
                }
            }
            if count < 0 {
                if errno == EINTR { continue }
                if errno == EAGAIN || errno == EWOULDBLOCK { return }
                fail("collector socket receive failed")
            }
            guard count <= (privateMode ? maxReplyDatagram + ObstacleBridgeWorkerIPC.headerBytes : maxDatagram) else { continue }
            handle(Data(buffer.prefix(count)), peer: peer, peerLength: peerLength)
        }
    }

    private func handle(_ wire: Data, peer: sockaddr_storage, peerLength: socklen_t) {
        let payloadData: Data
        if privateMode {
            guard let decoded = try? ObstacleBridgeWorkerIPC.decode(wire), let frame = decoded.0,
                  decoded.1.isEmpty, frame.generation == generation,
                  frame.kind == .request || frame.kind == .data else { return }
            payloadData = frame.payload
        } else { payloadData = wire }
        guard let payload = (try? JSONSerialization.jsonObject(with: payloadData)) as? [String: Any],
              payload["v"] as? Int == 1 else { return }
        if payload["kind"] as? String == "logs.query" {
            guard let data = reply(lines, limit: (payload["limit"] as? Int) ?? 400, requestID: payload["request_id"] as? String) else { return }
            if privateMode {
                guard let framed = try? ObstacleBridgeWorkerIPC.encode(kind: .response, generation: generation, payload: data) else { return }
                _ = framed.withUnsafeBytes { send(socketFD, $0.baseAddress, $0.count, Int32(MSG_DONTWAIT)) }
            } else {
                _ = withUnsafePointer(to: peer) { address in
                    address.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
                        data.withUnsafeBytes { sendto(socketFD, $0.baseAddress, $0.count, Int32(MSG_DONTWAIT), socketAddress, peerLength) }
                    }
                }
            }
        } else if let line = render(payload) {
            lines.append(line); ringBytes += line.utf8.count
            while lines.count > ringLimit || ringBytes > ringByteLimit { ringBytes -= lines.removeFirst().utf8.count }
            FileHandle.standardOutput.write(Data((line + "\n").utf8))
        }
    }
}

let flags = fcntl(socketFD, F_GETFL)
guard flags >= 0, fcntl(socketFD, F_SETFL, flags | O_NONBLOCK) == 0 else { fail("unable to make collector socket nonblocking") }
let collector = CollectorState(socketFD: socketFD, privateMode: privateMode, generation: privateGeneration)
let collectorQueue = DispatchQueue(label: "org.obstaclebridge.log-collector")
let dataSource = DispatchSource.makeReadSource(fileDescriptor: socketFD, queue: collectorQueue)
dataSource.setEventHandler { collector.drainReadableDatagrams() }
dataSource.setCancelHandler { close(socketFD) }
dataSource.resume()
let lifetimeSource: DispatchSourceRead?
if lifetimeFD >= 0 {
    let source = DispatchSource.makeReadSource(fileDescriptor: lifetimeFD, queue: collectorQueue)
    source.setEventHandler { exit(0) }
    source.setCancelHandler { close(lifetimeFD) }
    source.resume()
    lifetimeSource = source
} else { lifetimeSource = nil }
dispatchMain()
