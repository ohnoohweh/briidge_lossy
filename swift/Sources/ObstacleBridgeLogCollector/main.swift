import Foundation
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
let privateMode = arguments.count == 4 && arguments[1] == "--private-fds"
let socketFD: Int32
let lifetimeFD: Int32
if privateMode {
    guard let data = Int32(arguments[2]), let lifetime = Int32(arguments[3]),
          data > 2, lifetime > 2, data != lifetime,
          socketType(data) == datagramSocketType, socketType(lifetime) == streamSocketType else {
        fail("invalid private logging sockets")
    }
    socketFD = data
    lifetimeFD = lifetime
    let ready = try JSONSerialization.data(withJSONObject: [
        "v": 1, "kind": "worker.ready", "role": "logging", "implementation": "native",
    ], options: [.sortedKeys])
    let sent = ready.withUnsafeBytes { send(data, $0.baseAddress, $0.count, 0) }
    guard sent == ready.count else { fail("unable to announce logging worker") }
} else {
    let port = parsePort(arguments)
    socketFD = socket(AF_INET, datagramSocketType, 0)
    lifetimeFD = -1
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

var lines: [String] = []
var ringBytes = 0
var buffer = [UInt8](repeating: 0, count: 65_535)
while true {
    if privateMode {
        var descriptors = [pollfd(fd: socketFD, events: Int16(POLLIN), revents: 0), pollfd(fd: lifetimeFD, events: Int16(POLLIN), revents: 0)]
        let observed = poll(&descriptors, nfds_t(descriptors.count), -1)
        if observed < 0 {
            if errno == EINTR { continue }
            fail("collector poll failed")
        }
        if descriptors[1].revents != 0 { break }
        if descriptors[0].revents & Int16(POLLIN) == 0 { break }
    }
    var peer = sockaddr_storage()
    var peerLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
    let count = withUnsafeMutablePointer(to: &peer) { address in
        address.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            recvfrom(socketFD, &buffer, buffer.count, 0, $0, &peerLength)
        }
    }
    if count < 0 {
        if errno == EINTR { continue }
        fail("collector socket receive failed")
    }
    guard count <= (privateMode ? maxReplyDatagram : maxDatagram),
          let payload = (try? JSONSerialization.jsonObject(with: Data(buffer.prefix(count)))) as? [String: Any],
          let version = payload["v"] as? Int, version == 1 else { continue }
    if payload["kind"] as? String == "logs.query" {
        guard let data = reply(lines, limit: (payload["limit"] as? Int) ?? 400, requestID: payload["request_id"] as? String) else { continue }
        if privateMode {
            _ = data.withUnsafeBytes { send(socketFD, $0.baseAddress, $0.count, Int32(MSG_DONTWAIT)) }
        } else {
            _ = withUnsafePointer(to: &peer) { address in
                address.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
                    data.withUnsafeBytes { bytes in
                        sendto(socketFD, bytes.baseAddress, bytes.count, 0, socketAddress, peerLength)
                    }
                }
            }
        }
    } else if let line = render(payload) {
        lines.append(line)
        ringBytes += line.utf8.count
        while lines.count > ringLimit || ringBytes > ringByteLimit {
            ringBytes -= lines.removeFirst().utf8.count
        }
        FileHandle.standardOutput.write(Data((line + "\n").utf8))
    }
}
