import Dispatch
import Foundation
#if os(Linux)
import Glibc
#endif

/// Local explicit proxy owner.  It deliberately uses system egress: it must
/// remain usable while the overlay is connecting and never creates a route
/// dependency on the packet tunnel it helps bootstrap.
public final class ObstacleBridgeLinuxProxyProvider: @unchecked Sendable {
    private let configuration: ObstacleBridgeLinuxProxyProviderConfiguration
    private let queue = DispatchQueue(label: "org.obstaclebridge.linux.proxy")
    private var listeners: [(fd: Int32, source: DispatchSourceRead)] = []
    private let lock = NSLock()
    private var accepted = 0
    private var completed = 0
    private var failed = 0
    private var boundHTTPPort = 0
    private var boundSOCKS5Port = 0

    public init(configuration: ObstacleBridgeLinuxProxyProviderConfiguration) { self.configuration = configuration }

    public func start() throws {
        guard configuration.enabled else { return }
        if configuration.httpEnabled { try install(port: configuration.httpPort, socks: false) }
        if configuration.socks5Enabled { try install(port: configuration.socks5Port, socks: true) }
    }

    public func stop() { listeners.forEach { $0.source.cancel() }; listeners.removeAll() }

    public func snapshot() -> [String: Any] {
        lock.lock(); defer { lock.unlock() }
        return ["enabled": configuration.enabled, "bind_host": configuration.bindHost, "http_port": configuration.httpEnabled ? boundHTTPPort : 0, "socks5_port": configuration.socks5Enabled ? boundSOCKS5Port : 0, "accepted_connections": accepted, "completed_connections": completed, "failed_connections": failed]
    }

    private func install(port: Int, socks: Bool) throws {
        let fd = try listener(port: port)
        lock.lock()
        if socks { boundSOCKS5Port = boundPort(fd) } else { boundHTTPPort = boundPort(fd) }
        lock.unlock()
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        source.setEventHandler { [weak self] in self?.accept(listener: fd, socks: socks) }
        source.setCancelHandler { _ = close(fd) }
        listeners.append((fd, source)); source.resume()
    }

    private func accept(listener: Int32, socks: Bool) {
        let client = Glibc.accept(listener, nil, nil); guard client >= 0 else { return }
        lock.lock(); accepted += 1; lock.unlock()
        DispatchQueue.global().async { [weak self] in self?.serve(client: client, socks: socks) }
    }

    private func serve(client: Int32, socks: Bool) {
        defer { _ = close(client) }
        do {
            if socks { try serveSOCKS(client) } else { try serveHTTP(client) }
            lock.lock(); completed += 1; lock.unlock()
        } catch { lock.lock(); failed += 1; lock.unlock() }
    }

    private func serveHTTP(_ client: Int32) throws {
        let data = try readHeader(client)
        guard let text = String(data: data, encoding: .isoLatin1), let line = text.split(separator: "\r\n").first else { throw ProxyError.invalid }
        let bits = line.split(separator: " ", maxSplits: 2).map(String.init); guard bits.count == 3 else { throw ProxyError.invalid }
        let headers = Dictionary(uniqueKeysWithValues: text.split(separator: "\r\n").dropFirst().compactMap { row -> (String, String)? in let p = row.split(separator: ":", maxSplits: 1); return p.count == 2 ? (p[0].lowercased(), p[1].trimmingCharacters(in: .whitespaces)) : nil })
        guard authorized(headers["proxy-authorization"]) else { try write(client, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"ObstacleBridge\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); throw ProxyError.auth }
        let destination: (String, Int)
        if bits[0].uppercased() == "CONNECT" { destination = try authority(bits[1], defaultPort: 443) }
        else { guard let url = URL(string: bits[1]), let host = url.host else { throw ProxyError.invalid }; destination = (host, url.port ?? (url.scheme?.lowercased() == "https" ? 443 : 80)) }
        let remote = try connect(destination.0, destination.1); defer { _ = close(remote) }
        if bits[0].uppercased() == "CONNECT" { try write(client, "HTTP/1.1 200 Connection Established\r\nProxy-Agent: ObstacleBridge\r\n\r\n") }
        else {
            let target = URL(string: bits[1]).flatMap { url -> String? in var r = url.path.isEmpty ? "/" : url.path; if let q = url.query { r += "?" + q }; return r } ?? bits[1]
            let filtered = text.split(separator: "\r\n").dropFirst().filter { !$0.lowercased().hasPrefix("proxy-authorization:") && !$0.lowercased().hasPrefix("proxy-connection:") }
            try write(remote, (["\(bits[0]) \(target) \(bits[2])"] + filtered.map(String.init)).joined(separator: "\r\n") + "\r\n\r\n")
        }
        relay(client, remote)
    }

    private func serveSOCKS(_ client: Int32) throws {
        let greeting = try readExactly(client, 2); guard greeting[0] == 5 else { throw ProxyError.invalid }
        let methods = try readExactly(client, Int(greeting[1])); let required = configuration.credentials != nil
        let method: UInt8 = required ? 2 : 0
        guard methods.contains(method) else { try write(client, Data([5, 255])); throw ProxyError.auth }; try write(client, Data([5, method]))
        if required { let head = try readExactly(client, 2); let u = try readExactly(client, Int(head[1])); let pLen = try readExactly(client, 1); let p = try readExactly(client, Int(pLen[0])); guard String(data: u, encoding: .utf8) == configuration.credentials?.username, String(data: p, encoding: .utf8) == configuration.credentials?.password else { try write(client, Data([1,1])); throw ProxyError.auth }; try write(client, Data([1,0])) }
        let header = try readExactly(client, 4); guard header[0] == 5, header[1] == 1 else { try write(client, Data([5,7,0,1,0,0,0,0,0,0])); throw ProxyError.invalid }
        let host: String
        switch header[3] { case 1: host = try readExactly(client, 4).map(String.init).joined(separator: "."); case 3: host = String(data: try readExactly(client, Int(try readExactly(client, 1)[0])), encoding: .utf8) ?? ""; case 4: host = try readExactly(client, 16).withUnsafeBytes { inet_ntop(AF_INET6, $0.baseAddress, UnsafeMutablePointer<CChar>.allocate(capacity: 46), 46) }.map { String(cString: $0) } ?? ""; default: throw ProxyError.invalid }
        let portData = try readExactly(client, 2); let remote = try connect(host, Int(portData[0]) << 8 | Int(portData[1])); defer { _ = close(remote) }
        try write(client, Data([5,0,0,1,0,0,0,0,0,0])); relay(client, remote)
    }

    private func relay(_ left: Int32, _ right: Int32) { let group = DispatchGroup(); for (from, to) in [(left,right),(right,left)] { group.enter(); DispatchQueue.global().async { var buffer = [UInt8](repeating: 0, count: 16_384); while true { let n = read(from, &buffer, buffer.count); if n <= 0 { _ = shutdown(to, Int32(SHUT_WR)); break }; var offset = 0; while offset < n { let w = Glibc.write(to, buffer.withUnsafeBytes { $0.baseAddress!.advanced(by: offset) }, n - offset); if w <= 0 { break }; offset += w } }; group.leave() } }; group.wait() }
    private func readHeader(_ fd: Int32) throws -> Data { var result = Data(); while result.count < 65_536 { result.append(try readExactly(fd, 1)); if result.suffix(4) == Data("\r\n\r\n".utf8) { return result } }; throw ProxyError.invalid }
    private func readExactly(_ fd: Int32, _ count: Int) throws -> Data { var data = Data(count: count); let n = data.withUnsafeMutableBytes { read(fd, $0.baseAddress, count) }; guard n == count else { throw ProxyError.invalid }; return data }
    private func write(_ fd: Int32, _ text: String) throws { try write(fd, Data(text.utf8)) }
    private func write(_ fd: Int32, _ data: Data) throws { let n = data.withUnsafeBytes { Glibc.write(fd, $0.baseAddress, data.count) }; guard n == data.count else { throw ProxyError.invalid } }
    private func authorized(_ header: String?) -> Bool { guard let credentials = configuration.credentials else { return true }; guard let header, header.lowercased().hasPrefix("basic "), let data = Data(base64Encoded: String(header.dropFirst(6))), let value = String(data: data, encoding: .utf8) else { return false }; return value == "\(credentials.username):\(credentials.password)" }
    private func authority(_ raw: String, defaultPort: Int) throws -> (String, Int) { if raw.hasPrefix("[") { guard let end = raw.firstIndex(of: "]") else { throw ProxyError.invalid }; return (String(raw[raw.index(after: raw.startIndex)..<end]), Int(raw.dropFirst(raw.distance(from: raw.startIndex, to: end) + 2).dropFirst()) ?? defaultPort) }; let parts = raw.split(separator: ":", maxSplits: 1); return (String(parts[0]), parts.count == 2 ? Int(parts[1]) ?? defaultPort : defaultPort) }
    private func listener(port: Int) throws -> Int32 { let fd = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0); guard fd >= 0 else { throw ProxyError.invalid }; var yes: Int32 = 1; _ = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size)); var address = sockaddr_in(); address.sin_family = sa_family_t(AF_INET); address.sin_port = in_port_t(UInt16(port).bigEndian); guard inet_pton(AF_INET, configuration.bindHost, &address.sin_addr) == 1 else { _ = close(fd); throw ProxyError.invalid }; let bound = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }; guard bound == 0, listen(fd, 64) == 0 else { _ = close(fd); throw ProxyError.invalid }; return fd }
    private func boundPort(_ fd: Int32) -> Int { var address = sockaddr_in(); var length = socklen_t(MemoryLayout<sockaddr_in>.size); _ = withUnsafeMutablePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) } }; return Int(UInt16(bigEndian: address.sin_port)) }
    private func connect(_ host: String, _ port: Int) throws -> Int32 { var hints = addrinfo(ai_flags: 0, ai_family: AF_UNSPEC, ai_socktype: Int32(SOCK_STREAM.rawValue), ai_protocol: 0, ai_addrlen: 0, ai_addr: nil, ai_canonname: nil, ai_next: nil); var result: UnsafeMutablePointer<addrinfo>?; guard getaddrinfo(host, String(port), &hints, &result) == 0 else { throw ProxyError.invalid }; defer { freeaddrinfo(result) }; var row = result; while let current = row { if !configuration.allowPrivateDestinations && isPrivate(current.pointee.ai_addr, family: current.pointee.ai_family) { row = current.pointee.ai_next; continue }; let fd = socket(current.pointee.ai_family, current.pointee.ai_socktype, current.pointee.ai_protocol); if fd >= 0 && Glibc.connect(fd, current.pointee.ai_addr, current.pointee.ai_addrlen) == 0 { return fd }; if fd >= 0 { _ = close(fd) }; row = current.pointee.ai_next }; throw ProxyError.invalid }
    private func isPrivate(_ address: UnsafeMutablePointer<sockaddr>?, family: Int32) -> Bool { guard let address else { return true }; if family == AF_INET { let value = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }; return value >> 24 == 10 || value >> 20 == 0xAC1 || value >> 16 == 0xC0A8 || value >> 24 == 127 || value >> 16 == 0xA9FE }; return family == AF_INET6 }
    private enum ProxyError: Error { case invalid, auth }
}
