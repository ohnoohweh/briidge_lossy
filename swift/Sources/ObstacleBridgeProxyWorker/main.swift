import Dispatch
import Foundation
#if canImport(Darwin)
import Darwin
private let streamType = SOCK_STREAM
#else
import Glibc
private let streamType = Int32(SOCK_STREAM.rawValue)
#endif

private let maximumControlFrame = 65_536
private enum WorkerError: Error { case invalid, io, closed }

private func readExact(_ fd: Int32, _ count: Int) throws -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    var offset = 0
    while offset < count {
        let n = bytes.withUnsafeMutableBytes { recv(fd, $0.baseAddress!.advanced(by: offset), count - offset, 0) }
        if n < 0 && errno == EINTR { continue }
        guard n > 0 else { throw WorkerError.closed }
        offset += n
    }
    return Data(bytes)
}

private func writeAll(_ fd: Int32, _ data: Data) throws {
    var offset = 0
    while offset < data.count {
        let n = data.withUnsafeBytes { send(fd, $0.baseAddress!.advanced(by: offset), data.count - offset, 0) }
        if n < 0 && errno == EINTR { continue }
        guard n > 0 else { throw WorkerError.io }
        offset += n
    }
}

private func readFrame(_ fd: Int32) throws -> [String: Any] {
    let prefix = [UInt8](try readExact(fd, 4))
    let size = prefix.reduce(0) { ($0 << 8) | Int($1) }
    guard size > 0 && size <= maximumControlFrame,
          let message = try JSONSerialization.jsonObject(with: readExact(fd, size)) as? [String: Any],
          message["v"] as? Int == 1 else { throw WorkerError.invalid }
    return message
}

private func writeFrame(_ fd: Int32, _ message: [String: Any]) throws {
    let body = try JSONSerialization.data(withJSONObject: message, options: [.sortedKeys])
    guard body.count > 0 && body.count <= maximumControlFrame else { throw WorkerError.invalid }
    let size = UInt32(body.count)
    var frame = Data([UInt8((size >> 24) & 255), UInt8((size >> 16) & 255), UInt8((size >> 8) & 255), UInt8(size & 255)])
    frame.append(body)
    try writeAll(fd, frame)
}

private func validateControlSocket(_ fd: Int32) -> Bool {
    var kind: Int32 = 0
    var size = socklen_t(MemoryLayout<Int32>.size)
    guard fd > 2, getsockopt(fd, SOL_SOCKET, SO_TYPE, &kind, &size) == 0, kind == streamType else { return false }
    var address = sockaddr_storage()
    var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
    let result = withUnsafeMutablePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
    }
    return result == 0 && Int32(address.ss_family) == AF_UNIX
}

private func setTimeout(_ fd: Int32, seconds: Int) {
    var timeout = timeval(tv_sec: seconds, tv_usec: 0)
    _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
}

private func connectDirect(_ host: String, _ port: Int) throws -> Int32 {
    guard (1...65_535).contains(port) else { throw WorkerError.invalid }
    var hints = addrinfo()
    hints.ai_family = AF_UNSPEC
    hints.ai_socktype = streamType
    var result: UnsafeMutablePointer<addrinfo>?
    guard getaddrinfo(host, String(port), &hints, &result) == 0, let first = result else { throw WorkerError.io }
    defer { freeaddrinfo(first) }
    var cursor: UnsafeMutablePointer<addrinfo>? = first
    while let item = cursor {
        let fd = socket(item.pointee.ai_family, item.pointee.ai_socktype, item.pointee.ai_protocol)
        if fd >= 0 {
            setTimeout(fd, seconds: 30)
            if connect(fd, item.pointee.ai_addr, item.pointee.ai_addrlen) == 0 { return fd }
            close(fd)
        }
        cursor = item.pointee.ai_next
    }
    throw WorkerError.io
}

private struct ProxySettings: Sendable {
    let configuredPort: Int
    let socks: Bool
    let username: String?
    let password: String?
}

private final class ProxyListener: @unchecked Sendable {
    private let settings: ProxySettings
    private let fd: Int32
    private let source: DispatchSourceRead
    private let lock = NSLock()
    private var accepted = 0, active = 0, completed = 0, failed = 0, rx = 0, tx = 0
    private var lastError = ""
    let boundPort: Int

    init(settings: ProxySettings) throws {
        self.settings = settings
        guard (0...65_535).contains(settings.configuredPort) else { throw WorkerError.invalid }
        let listener = socket(AF_INET, streamType, 0)
        guard listener >= 0 else { throw WorkerError.io }
        var yes: Int32 = 1
        _ = setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = UInt16(settings.configuredPort).bigEndian
        address.sin_addr = in_addr(s_addr: UInt32(0x7f000001).bigEndian)
        let bound = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard bound == 0, listen(listener, 64) == 0 else { close(listener); throw WorkerError.io }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        guard withUnsafeMutablePointer(to: &address, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(listener, $0, &length) } }) == 0 else { close(listener); throw WorkerError.io }
        boundPort = Int(UInt16(bigEndian: address.sin_port))
        fd = listener
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
        source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: DispatchQueue(label: "org.obstaclebridge.proxy.accept.\(fd)"))
        source.setEventHandler { [weak self] in self?.acceptClients() }
        source.setCancelHandler { close(listener) }
        source.resume()
    }

    func stop() { source.cancel() }

    func snapshot() -> [String: Any] {
        lock.lock(); defer { lock.unlock() }
        return ["accepted_connections": accepted, "active_connections": active, "completed_connections": completed,
                "failed_connections": failed, "rx_bytes": rx, "tx_bytes": tx, "last_error": lastError,
                "bind_host": "127.0.0.1", "port": settings.configuredPort, "bound_port": boundPort,
                "http_enabled": !settings.socks, "socks5_enabled": settings.socks,
                "auth_required": settings.username != nil, "egress_mode": "direct"]
    }

    private func acceptClients() {
        while true {
            let client = accept(fd, nil, nil)
            if client < 0 { return }
            lock.lock()
            guard active < 128 else { lock.unlock(); close(client); continue }
            accepted += 1; active += 1
            lock.unlock()
            let flags = fcntl(client, F_GETFL)
            guard flags >= 0, fcntl(client, F_SETFL, flags & ~O_NONBLOCK) == 0 else {
                close(client)
                lock.lock(); active -= 1; failed += 1; lastError = "proxy session setup failed"; lock.unlock()
                continue
            }
            setTimeout(client, seconds: 30)
            DispatchQueue.global().async { [self] in
                var success = false
                defer {
                    close(client)
                    lock.lock(); active -= 1
                    if success { completed += 1 } else { failed += 1; lastError = "proxy session failed" }
                    lock.unlock()
                }
                do { try serve(client); success = true } catch { }
            }
        }
    }

    private func serve(_ client: Int32) throws {
        if settings.socks { try serveSOCKS(client) } else { try serveHTTP(client) }
    }

    private func serveHTTP(_ client: Int32) throws {
        var header = Data()
        while header.count < 65_536 {
            header.append(try readExact(client, 1))
            if header.suffix(4) == Data("\r\n\r\n".utf8) { break }
        }
        guard header.suffix(4) == Data("\r\n\r\n".utf8), let text = String(data: header, encoding: .isoLatin1) else { throw WorkerError.invalid }
        let rows = text.components(separatedBy: "\r\n")
        let parts = rows[0].split(separator: " ", maxSplits: 2).map(String.init)
        guard parts.count == 3, parts[2].hasPrefix("HTTP/") else { throw WorkerError.invalid }
        var headers: [String: String] = [:]
        for row in rows.dropFirst() {
            if let colon = row.firstIndex(of: ":") { headers[String(row[..<colon]).lowercased()] = String(row[row.index(after: colon)...]).trimmingCharacters(in: .whitespaces) }
        }
        if let username = settings.username, let password = settings.password {
            let raw = headers["proxy-authorization"] ?? ""
            let expected = Data("\(username):\(password)".utf8).base64EncodedString()
            guard raw.lowercased().hasPrefix("basic "), String(raw.dropFirst(6)).trimmingCharacters(in: .whitespaces) == expected else {
                try writeAll(client, Data("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"ObstacleBridge\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".utf8))
                throw WorkerError.invalid
            }
        }
        let host: String, port: Int
        if parts[0].uppercased() == "CONNECT" {
            guard let url = URL(string: "http://\(parts[1])"), let value = url.host else { throw WorkerError.invalid }
            host = value; port = url.port ?? 443
        } else {
            guard let url = URL(string: parts[1]), let value = url.host, let scheme = url.scheme, !scheme.isEmpty else { throw WorkerError.invalid }
            host = value; port = url.port ?? (scheme.lowercased() == "https" ? 443 : 80)
        }
        let remote = try connectDirect(host, port)
        defer { close(remote) }
        if parts[0].uppercased() == "CONNECT" {
            try writeAll(client, Data("HTTP/1.1 200 Connection Established\r\nProxy-Agent: ObstacleBridge\r\n\r\n".utf8))
        } else {
            guard let components = URLComponents(string: parts[1]) else { throw WorkerError.invalid }
            var target = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
            if let query = components.percentEncodedQuery { target += "?" + query }
            let retained = rows.dropFirst().filter { !$0.isEmpty && !$0.lowercased().hasPrefix("proxy-authorization:") && !$0.lowercased().hasPrefix("proxy-connection:") }
            let rewritten = (["\(parts[0]) \(target) \(parts[2])"] + retained).joined(separator: "\r\n") + "\r\n\r\n"
            try writeAll(remote, Data(rewritten.utf8))
            lock.lock(); rx += rewritten.utf8.count; lock.unlock()
        }
        relay(client, remote)
    }

    private func serveSOCKS(_ client: Int32) throws {
        let greeting = [UInt8](try readExact(client, 2))
        guard greeting[0] == 5 else { throw WorkerError.invalid }
        let methods = [UInt8](try readExact(client, Int(greeting[1])))
        let method: UInt8 = settings.username == nil ? 0 : 2
        guard methods.contains(method) else { try writeAll(client, Data([5, 255])); throw WorkerError.invalid }
        try writeAll(client, Data([5, method]))
        if method == 2 {
            let head = [UInt8](try readExact(client, 2))
            let user = String(data: try readExact(client, Int(head[1])), encoding: .utf8)
            let length = [UInt8](try readExact(client, 1))[0]
            let password = String(data: try readExact(client, Int(length)), encoding: .utf8)
            let ok = head[0] == 1 && user == settings.username && password == settings.password
            try writeAll(client, Data([1, ok ? 0 : 1]))
            guard ok else { throw WorkerError.invalid }
        }
        let head = [UInt8](try readExact(client, 4))
        guard head[0] == 5, head[1] == 1, head[2] == 0 else { throw WorkerError.invalid }
        let host: String
        switch head[3] {
        case 1: host = [UInt8](try readExact(client, 4)).map(String.init).joined(separator: ".")
        case 3:
            let length = [UInt8](try readExact(client, 1))[0]
            guard let value = String(data: try readExact(client, Int(length)), encoding: .utf8), !value.isEmpty else { throw WorkerError.invalid }
            host = value
        case 4:
            let bytes = [UInt8](try readExact(client, 16))
            host = stride(from: 0, to: 16, by: 2).map { String((UInt16(bytes[$0]) << 8) | UInt16(bytes[$0 + 1]), radix: 16) }.joined(separator: ":")
        default: throw WorkerError.invalid
        }
        let port = [UInt8](try readExact(client, 2))
        let remote = try connectDirect(host, Int(port[0]) << 8 | Int(port[1]))
        defer { close(remote) }
        try writeAll(client, Data([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]))
        relay(client, remote)
    }

    private func relay(_ left: Int32, _ right: Int32) {
        let group = DispatchGroup()
        for (from, to, inbound) in [(left, right, true), (right, left, false)] {
            group.enter()
            DispatchQueue.global().async { [self] in
                defer { group.leave() }
                var bytes = [UInt8](repeating: 0, count: 16_384)
                while true {
                    let n = recv(from, &bytes, bytes.count, 0)
                    if n < 0 && errno == EINTR { continue }
                    if n <= 0 { _ = shutdown(to, Int32(SHUT_WR)); return }
                    do { try writeAll(to, Data(bytes.prefix(n))) } catch { _ = shutdown(from, Int32(SHUT_RDWR)); _ = shutdown(to, Int32(SHUT_RDWR)); return }
                    lock.lock(); if inbound { rx += n } else { tx += n }; lock.unlock()
                }
            }
        }
        group.wait()
    }
}

private func run(_ fd: Int32) throws {
    guard validateControlSocket(fd) else { throw WorkerError.invalid }
    setTimeout(fd, seconds: 5)
    let initial = try readFrame(fd)
    guard initial["kind"] as? String == "proxy.start", let config = initial["config"] as? [String: Any],
          let bindHost = config["bind"] as? String, bindHost == "127.0.0.1",
          let policy = config["policy"] as? [String: Any], policy.count == 2,
          policy["allow_private_destinations"] as? Bool == true,
          let blocked = policy["blocked_host_patterns"] as? [String], blocked.isEmpty,
          let egress = config["egress"] as? [String: Any], let mode = egress["mode"] as? String,
          ["direct", "off", "none"].contains(mode.lowercased()),
          Set(egress.keys).isSubset(of: ["mode", "address_families"]),
          (egress["address_families"] == nil || Set(egress["address_families"] as? [String] ?? []) == ["ipv4", "ipv6"]),
          let protocols = config["protocols"] as? [String],
          let httpPort = config["http_port"] as? Int, let socksPort = config["socks5_port"] as? Int else { throw WorkerError.invalid }
    let auth = config["auth"] as? [String: Any] ?? [:]
    let authMode = (auth["mode"] as? String ?? "none").lowercased()
    var username: String?, password: String?
    if !["", "none", "off", "disabled"].contains(authMode) {
        username = (auth["username"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        let token = auth["token"] as? String ?? ""
        password = (token.isEmpty ? auth["password"] as? String : token)?.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let username, let password, !username.isEmpty, !password.isEmpty else { throw WorkerError.invalid }
    }
    var listeners: [String: ProxyListener] = [:]
    defer { listeners.values.forEach { $0.stop() } }
    if !Set(protocols).isDisjoint(with: ["http", "http-connect"]) {
        listeners["http"] = try ProxyListener(settings: .init(configuredPort: httpPort, socks: false, username: username, password: password))
    }
    if !Set(protocols).isDisjoint(with: ["socks5", "socks5-connect"]) {
        listeners["socks5"] = try ProxyListener(settings: .init(configuredPort: socksPort, socks: true, username: username, password: password))
    }
    guard !listeners.isEmpty else { throw WorkerError.invalid }
    func snapshot() -> [String: Any] { listeners.mapValues { $0.snapshot() } }
    try writeFrame(fd, ["v": 1, "kind": "proxy.ready", "implementation": "native", "listeners": snapshot()])
    while true {
        var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        let count = poll(&descriptor, 1, 250)
        if count < 0 && errno == EINTR { continue }
        guard count >= 0 else { throw WorkerError.io }
        if count > 0 {
            if descriptor.revents & Int16(POLLIN) != 0 {
                do {
                    guard try readFrame(fd)["kind"] as? String == "proxy.stop" else { throw WorkerError.invalid }
                } catch WorkerError.closed {
                    break
                }
            }
            break
        }
        try writeFrame(fd, ["v": 1, "kind": "proxy.snapshot", "listeners": snapshot()])
    }
}

signal(SIGPIPE, SIG_IGN)
let args = CommandLine.arguments
guard args.count == 3, args[1] == "--control-fd", let fd = Int32(args[2]) else { exit(1) }
do { try run(fd); close(fd) } catch { close(fd); exit(1) }
