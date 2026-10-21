import Dispatch
import Foundation
#if canImport(Darwin)
import Darwin
private let streamType = SOCK_STREAM
private let datagramType = SOCK_DGRAM
#else
import Glibc
private let streamType = Int32(SOCK_STREAM.rawValue)
private let datagramType = Int32(SOCK_DGRAM.rawValue)
#endif

private let maximumControlFrame = 65_536
private enum WorkerError: Error { case invalid, io, closed, destinationDenied }

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

private func validateSocket(_ fd: Int32, type: Int32) -> Bool {
    var kind: Int32 = 0
    var size = socklen_t(MemoryLayout<Int32>.size)
    // A native supervisor can hand over private sockets as standard descriptors.
    guard fd >= 0, getsockopt(fd, SOL_SOCKET, SO_TYPE, &kind, &size) == 0, kind == type else { return false }
    var address = sockaddr_storage()
    var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
    let result = withUnsafeMutablePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
    }
    return result == 0 && Int32(address.ss_family) == AF_UNIX
}

private final class ChildLogger: @unchecked Sendable {
    private let fd: Int32
    var level: Int = 30

    init(fd: Int32) throws {
        guard validateSocket(fd, type: datagramType) else { throw WorkerError.invalid }
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { throw WorkerError.io }
        self.fd = fd
    }

    func emit(_ level: Int, _ message: String) {
        guard level >= self.level else { return }
        let record: [String: Any] = ["v": 1, "created": Date().timeIntervalSince1970,
                                     "name": "proxy_provider", "level": level >= 30 ? "WARNING" : "INFO",
                                     "levelno": level, "message": message, "process": Int(getpid()), "thread": "native-proxy"]
        guard let data = try? JSONSerialization.data(withJSONObject: record), data.count <= 8192 else { return }
        _ = data.withUnsafeBytes { send(fd, $0.baseAddress, data.count, 0) }
    }
}

private func setTimeout(_ fd: Int32, seconds: Int) {
    var timeout = timeval(tv_sec: seconds, tv_usec: 0)
    _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
}

private struct DestinationPolicy: Sendable {
    let allowPrivateDestinations: Bool
    let blockedHostPatterns: [String]
}

private func policyHost(_ host: String) -> String {
    host.trimmingCharacters(in: .whitespacesAndNewlines)
        .trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        .trimmingCharacters(in: CharacterSet(charactersIn: "."))
        .lowercased()
}

private func patternMatches(_ pattern: String, _ host: String) -> Bool {
    let escaped = NSRegularExpression.escapedPattern(for: pattern)
        .replacingOccurrences(of: "\\*", with: ".*")
        .replacingOccurrences(of: "\\?", with: ".")
    return host.range(of: "^" + escaped + "$", options: [.regularExpression, .caseInsensitive]) != nil
}

private func isNonPublic(_ item: UnsafeMutablePointer<addrinfo>) -> Bool {
    guard let rawAddress = item.pointee.ai_addr else { return true }
    if item.pointee.ai_family == AF_INET {
        let address = rawAddress.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
        let bytes = withUnsafeBytes(of: address.sin_addr) { Array($0) }
        guard bytes.count == 4 else { return true }
        return bytes[0] == 0 || bytes[0] == 10 || bytes[0] == 127 || bytes[0] >= 224
            || (bytes[0] == 169 && bytes[1] == 254)
            || (bytes[0] == 172 && (16...31).contains(bytes[1]))
            || (bytes[0] == 192 && bytes[1] == 168)
            || (bytes[0] == 100 && (64...127).contains(bytes[1]))
    }
    if item.pointee.ai_family == AF_INET6 {
        let address = rawAddress.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
        let bytes = withUnsafeBytes(of: address.sin6_addr) { Array($0) }
        guard bytes.count == 16 else { return true }
        if bytes[0..<10].allSatisfy({ $0 == 0 }) && bytes[10] == 255 && bytes[11] == 255 {
            let ipv4 = Array(bytes[12...15])
            return ipv4[0] == 0 || ipv4[0] == 10 || ipv4[0] == 127 || ipv4[0] >= 224
                || (ipv4[0] == 169 && ipv4[1] == 254)
                || (ipv4[0] == 172 && (16...31).contains(ipv4[1]))
                || (ipv4[0] == 192 && ipv4[1] == 168)
                || (ipv4[0] == 100 && (64...127).contains(ipv4[1]))
        }
        return bytes.allSatisfy({ $0 == 0 }) || (bytes[0..<15].allSatisfy({ $0 == 0 }) && bytes[15] == 1)
            || (bytes[0] & 0xfe) == 0xfc || (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80) || bytes[0] == 0xff
    }
    return true
}

private func connectDirect(_ host: String, _ port: Int, policy: DestinationPolicy) throws -> Int32 {
    guard (1...65_535).contains(port) else { throw WorkerError.invalid }
    let normalizedHost = policyHost(host)
    guard !normalizedHost.isEmpty,
          !policy.blockedHostPatterns.contains(where: { patternMatches($0, normalizedHost) }) else { throw WorkerError.destinationDenied }
    var hints = addrinfo()
    hints.ai_family = AF_UNSPEC
    hints.ai_socktype = streamType
    var result: UnsafeMutablePointer<addrinfo>?
    guard getaddrinfo(host, String(port), &hints, &result) == 0, let first = result else { throw WorkerError.io }
    defer { freeaddrinfo(first) }
    if !policy.allowPrivateDestinations {
        var candidate: UnsafeMutablePointer<addrinfo>? = first
        while let item = candidate {
            if isNonPublic(item) { throw WorkerError.destinationDenied }
            candidate = item.pointee.ai_next
        }
    }
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
    let bindHost: String
    let socks: Bool
    let username: String?
    let password: String?
    let policy: DestinationPolicy
}

private final class ProxyListener: @unchecked Sendable {
    private let settings: ProxySettings
    private let logger: ChildLogger?
    private let fd: Int32
    private let source: DispatchSourceRead
    private let lock = NSLock()
    private var accepted = 0, active = 0, completed = 0, failed = 0, rx = 0, tx = 0
    private var lastError = ""
    let boundPort: Int

    init(settings: ProxySettings, logger: ChildLogger?) throws {
        self.settings = settings
        self.logger = logger
        guard (0...65_535).contains(settings.configuredPort) else { throw WorkerError.invalid }
        let family: Int32 = settings.bindHost == "::1" ? AF_INET6 : AF_INET
        let listener = socket(family, streamType, 0)
        guard listener >= 0 else { throw WorkerError.io }
        var yes: Int32 = 1
        _ = setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        if family == AF_INET {
            var address = sockaddr_in()
            address.sin_family = sa_family_t(AF_INET)
            address.sin_port = UInt16(settings.configuredPort).bigEndian
            address.sin_addr = in_addr(s_addr: UInt32(0x7f000001).bigEndian)
            let bound = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
            guard bound == 0, listen(listener, 64) == 0 else { close(listener); throw WorkerError.io }
            var length = socklen_t(MemoryLayout<sockaddr_in>.size)
            guard withUnsafeMutablePointer(to: &address, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(listener, $0, &length) } }) == 0 else { close(listener); throw WorkerError.io }
            boundPort = Int(UInt16(bigEndian: address.sin_port))
        } else {
            var address = sockaddr_in6()
            address.sin6_family = sa_family_t(AF_INET6)
            address.sin6_port = UInt16(settings.configuredPort).bigEndian
            guard withUnsafeMutablePointer(to: &address.sin6_addr, { inet_pton(AF_INET6, settings.bindHost, $0) }) == 1 else { close(listener); throw WorkerError.invalid }
            let bound = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) } }
            guard bound == 0, listen(listener, 64) == 0 else { close(listener); throw WorkerError.io }
            var length = socklen_t(MemoryLayout<sockaddr_in6>.size)
            guard withUnsafeMutablePointer(to: &address, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(listener, $0, &length) } }) == 0 else { close(listener); throw WorkerError.io }
            boundPort = Int(UInt16(bigEndian: address.sin6_port))
        }
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
                "bind_host": settings.bindHost, "port": settings.configuredPort, "bound_port": boundPort,
                "http_enabled": !settings.socks, "socks5_enabled": settings.socks,
                "auth_required": settings.username != nil, "egress_mode": "direct",
                "destination_policy_enforced": true]
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
            // Session I/O is allowed to wait independently of the shared
            // dispatch pool, whose bounded worker count can otherwise let
            // idle clients starve unrelated accepted connections.
            Thread.detachNewThread { [self] in
                var success = false
                defer {
                    close(client)
                    lock.lock(); active -= 1
                    if success { completed += 1 } else { failed += 1; lastError = "proxy session failed" }
                    lock.unlock()
                }
                do { try serve(client); success = true } catch { logger?.emit(30, "[PROXY] client failed") }
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
        let remote: Int32
        do { remote = try connectDirect(host, port, policy: settings.policy) }
        catch WorkerError.destinationDenied {
            try writeAll(client, Data("HTTP/1.1 403 Forbidden\r\nContent-Length: 30\r\nConnection: close\r\n\r\ndestination blocked by policy\n".utf8))
            throw WorkerError.destinationDenied
        }
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
        let remote: Int32
        do { remote = try connectDirect(host, Int(port[0]) << 8 | Int(port[1]), policy: settings.policy) }
        catch WorkerError.destinationDenied {
            try writeAll(client, Data([5, 2, 0, 1, 0, 0, 0, 0, 0, 0]))
            throw WorkerError.destinationDenied
        }
        defer { close(remote) }
        try writeAll(client, Data([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]))
        relay(client, remote)
    }

    private func relay(_ left: Int32, _ right: Int32) {
        // A session owns one dispatch thread. Waiting on nested dispatch jobs
        // can starve the shared pool under simultaneous proxy connections.
        // Bounded nonblocking buffers preserve independent duplex progress and
        // propagate half-closes only after pending bytes have been delivered.
        for fd in [left, right] {
            let flags = fcntl(fd, F_GETFL)
            guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { return }
        }
        let capacity = 65_536
        var pending = [Data(), Data()] // left -> right, right -> left
        var eof = [false, false]
        var closedWrite = [false, false]
        let fds = [left, right]
        var bytes = [UInt8](repeating: 0, count: 16_384)
        while true {
            for direction in 0..<2 where eof[direction] && pending[direction].isEmpty && !closedWrite[direction] {
                _ = shutdown(fds[1 - direction], Int32(SHUT_WR))
                closedWrite[direction] = true
            }
            if eof[0] && eof[1] && pending[0].isEmpty && pending[1].isEmpty { return }
            var descriptors = (0..<2).map { direction -> pollfd in
                var events: Int16 = 0
                if !eof[direction] && pending[direction].count < capacity { events |= Int16(POLLIN) }
                if !pending[1 - direction].isEmpty { events |= Int16(POLLOUT) }
                return pollfd(fd: events == 0 ? -1 : fds[direction], events: events, revents: 0)
            }
            let count = poll(&descriptors, nfds_t(descriptors.count), 30_000)
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { return }
            for direction in 0..<2 {
                let events = descriptors[direction].revents
                if events & Int16(POLLERR | POLLNVAL) != 0 { return }
                if events & Int16(POLLOUT) != 0 && !pending[1 - direction].isEmpty {
                    let incoming = 1 - direction
                    let sent = pending[incoming].withUnsafeBytes { send(fds[direction], $0.baseAddress, $0.count, 0) }
                    if sent > 0 {
                        pending[incoming].removeFirst(sent)
                        lock.lock(); if incoming == 0 { rx += sent } else { tx += sent }; lock.unlock()
                    } else if sent == 0 || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) { return }
                }
                if !eof[direction] && pending[direction].count < capacity && events & Int16(POLLIN | POLLHUP) != 0 {
                    let received = recv(fds[direction], &bytes, min(bytes.count, capacity - pending[direction].count), 0)
                    if received > 0 { pending[direction].append(contentsOf: bytes.prefix(received)) }
                    else if received == 0 { eof[direction] = true }
                    else if errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK { return }
                }
            }
        }
    }
}

private func run(_ fd: Int32, logFD: Int32?) throws {
    guard validateSocket(fd, type: streamType), logFD != fd else { throw WorkerError.invalid }
    let logger = try logFD.map { try ChildLogger(fd: $0) }
    setTimeout(fd, seconds: 5)
    let initial = try readFrame(fd)
    let rootLevel = initial["log_root_level"] as? Int ?? 30
    let loggerLevel = (initial["log_levels"] as? [String: Int])?["proxy_provider"] ?? 0
    logger?.level = loggerLevel == 0 ? rootLevel : loggerLevel
    guard initial["kind"] as? String == "proxy.start", let config = initial["config"] as? [String: Any],
          let bindHost = config["bind"] as? String, ["127.0.0.1", "::1"].contains(bindHost),
          let policy = config["policy"] as? [String: Any], Set(policy.keys) == ["allow_private_destinations", "blocked_host_patterns"],
          let allowPrivateDestinations = policy["allow_private_destinations"] as? Bool,
          let blocked = policy["blocked_host_patterns"] as? [String], blocked.allSatisfy({ !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }),
          let egress = config["egress"] as? [String: Any], let mode = egress["mode"] as? String,
          mode.lowercased() == "direct", Set(egress.keys).isSubset(of: ["mode", "address_families"]),
          (egress["address_families"] == nil || Set(egress["address_families"] as? [String] ?? []) == ["ipv4", "ipv6"]),
          let protocols = config["protocols"] as? [String],
          !protocols.isEmpty, Set(protocols).isSubset(of: ["http", "http-connect", "socks5", "socks5-connect"]),
          let httpPort = config["http_port"] as? Int, (0...65_535).contains(httpPort),
          let socksPort = config["socks5_port"] as? Int, (0...65_535).contains(socksPort) else { throw WorkerError.invalid }
    guard let auth = config["auth"] as? [String: Any] else { throw WorkerError.invalid }
    let authMode = (auth["mode"] as? String ?? "none").lowercased()
    guard Set(auth.keys).isSubset(of: ["mode", "username", "token", "password"]),
          auth["username"] == nil || auth["username"] is String,
          auth["token"] == nil || auth["token"] is String,
          auth["password"] == nil || auth["password"] is String,
          ["none", "basic", "token", "password"].contains(authMode) else { throw WorkerError.invalid }
    var username: String?, password: String?
    if authMode == "none" {
        guard (auth["username"] as? String ?? "").isEmpty,
              (auth["token"] as? String ?? "").isEmpty,
              (auth["password"] as? String ?? "").isEmpty else { throw WorkerError.invalid }
    } else {
        username = (auth["username"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        let token = auth["token"] as? String ?? ""
        password = (token.isEmpty ? auth["password"] as? String : token)?.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let username, let password, !username.isEmpty, !password.isEmpty else { throw WorkerError.invalid }
    }
    var listeners: [String: ProxyListener] = [:]
    let destinationPolicy = DestinationPolicy(allowPrivateDestinations: allowPrivateDestinations, blockedHostPatterns: blocked.map(policyHost))
    defer { listeners.values.forEach { $0.stop() } }
    if !Set(protocols).isDisjoint(with: ["http", "http-connect"]) {
        listeners["http"] = try ProxyListener(settings: .init(configuredPort: httpPort, bindHost: bindHost, socks: false, username: username, password: password, policy: destinationPolicy), logger: logger)
    }
    if !Set(protocols).isDisjoint(with: ["socks5", "socks5-connect"]) {
        listeners["socks5"] = try ProxyListener(settings: .init(configuredPort: socksPort, bindHost: bindHost, socks: true, username: username, password: password, policy: destinationPolicy), logger: logger)
    }
    guard !listeners.isEmpty else { throw WorkerError.invalid }
    logger?.emit(20, "[PROXY] listener started")
    defer { logger?.emit(20, "[PROXY] listener stopped") }
    func snapshot() -> [String: Any] { listeners.mapValues { $0.snapshot() } }
    let capabilities: [String: Any] = ["contract_version": 1, "bind_families": ["ipv4", "ipv6"],
                                        "protocols": ["http-connect", "socks5-connect"],
                                        "auth_modes": ["none", "basic", "token", "password"],
                                        "egress_modes": ["direct"],
                                        "destination_policy": ["enforced": true, "requires_unrestricted": false]]
    try writeFrame(fd, ["v": 1, "kind": "proxy.ready", "implementation": "native", "capabilities": capabilities, "listeners": snapshot()])
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
var controlFD: Int32?, logFD: Int32?
var index = 1
while index + 1 < args.count {
    guard let value = Int32(args[index + 1]) else { exit(1) }
    switch args[index] {
    case "--control-fd" where controlFD == nil: controlFD = value
    case "--log-fd" where logFD == nil: logFD = value
    default: exit(1)
    }
    index += 2
}
guard index == args.count, let fd = controlFD else { exit(1) }
do {
    try run(fd, logFD: logFD)
    close(fd)
} catch {
    let code: String
    if let workerError = error as? WorkerError {
        switch workerError {
        case .invalid: code = "invalid_configuration"
        case .io, .closed, .destinationDenied: code = "startup_failed"
        }
    } else {
        code = "startup_failed"
    }
    try? writeFrame(fd, ["v": 1, "kind": "proxy.error", "code": code])
    close(fd)
    exit(1)
}
