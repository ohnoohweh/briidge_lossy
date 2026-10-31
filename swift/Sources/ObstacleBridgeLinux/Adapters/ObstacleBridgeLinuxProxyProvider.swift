import Dispatch
import Foundation
#if os(Linux)
import Glibc
#endif

/// Local explicit proxy owner.  It deliberately uses system egress: it must
/// remain usable while the overlay is connecting and never creates a route
/// dependency on the packet tunnel it helps bootstrap.
public final class ObstacleBridgeLinuxProxyProvider: @unchecked Sendable {
    // OBSTACLEBRIDGE-CONCURRENCY: lock; test=ObstacleBridgeLinuxProxyProviderTests
    private let configuration: ObstacleBridgeLinuxProxyProviderConfiguration
    private let queue = DispatchQueue(label: "org.obstaclebridge.linux.proxy")
    private var listeners: [(fd: Int32, source: DispatchSourceRead)] = []
    private let lock = NSLock()
    private var accepted = 0
    private var completed = 0
    private var failed = 0
    private var boundHTTPPort = 0
    private var boundSOCKS5Port = 0
    private var relays: [Int32: Relay] = [:]

    /// Owns both directions of a proxied stream. Each descriptor is drained
    /// only after Dispatch reports readiness; incomplete writes stay queued
    /// behind a write source instead of parking a worker in `poll`.
    private final class Relay: @unchecked Sendable {
        // OBSTACLEBRIDGE-CONCURRENCY: serial; test=ObstacleBridgeLinuxProxyProviderTests
        private let client: Int32
        private let remote: Int32
        private let queue: DispatchQueue
        private let finished: (Int32, Bool) -> Void
        private var clientRead: DispatchSourceRead?
        private var remoteRead: DispatchSourceRead?
        private var clientWrite: DispatchSourceWrite?
        private var remoteWrite: DispatchSourceWrite?
        private var toClient = Data()
        private var toRemote = Data()
        private var clientInputOpen = true
        private var remoteInputOpen = true
        private var stopped = false

        init(client: Int32, remote: Int32, finished: @escaping (Int32, Bool) -> Void) {
            self.client = client
            self.remote = remote
            self.queue = DispatchQueue(label: "org.obstaclebridge.linux.proxy.relay.\(client)")
            self.finished = finished
        }

        func start() {
            queue.async { [weak self] in
                guard let self else { return }
                guard self.makeNonblocking(self.client), self.makeNonblocking(self.remote) else { self.finish(failed: true); return }
                let clientRead = DispatchSource.makeReadSource(fileDescriptor: self.client, queue: self.queue)
                let remoteRead = DispatchSource.makeReadSource(fileDescriptor: self.remote, queue: self.queue)
                self.clientRead = clientRead; self.remoteRead = remoteRead
                clientRead.setEventHandler { [weak self] in self?.drain(fromClient: true) }
                remoteRead.setEventHandler { [weak self] in self?.drain(fromClient: false) }
                clientRead.resume(); remoteRead.resume()
            }
        }

        func stop() { queue.async { [weak self] in self?.finish(failed: false) } }

        private func drain(fromClient: Bool) {
            let source = fromClient ? client : remote
            while true {
                var buffer = [UInt8](repeating: 0, count: 16 * 1024)
                let count = recv(source, &buffer, buffer.count, Int32(MSG_DONTWAIT))
                if count > 0 {
                    if fromClient { toRemote.append(buffer, count: Int(count)); flush(toClient: false) }
                    else { toClient.append(buffer, count: Int(count)); flush(toClient: true) }
                    continue
                }
                if count < 0, errno == EINTR { continue }
                if count < 0, errno == EAGAIN || errno == EWOULDBLOCK { return }
                if count == 0 {
                    if fromClient { clientInputOpen = false; clientRead?.cancel(); clientRead = nil; _ = shutdown(remote, Int32(SHUT_WR)) }
                    else { remoteInputOpen = false; remoteRead?.cancel(); remoteRead = nil; _ = shutdown(client, Int32(SHUT_WR)) }
                    finishIfDrained()
                    return
                }
                finish(failed: true)
                return
            }
        }

        private func flush(toClient: Bool) {
            var pending = toClient ? self.toClient : toRemote
            let destination = toClient ? client : remote
            while !pending.isEmpty {
                let count = pending.withUnsafeBytes { send(destination, $0.baseAddress, pending.count, Int32(MSG_NOSIGNAL | MSG_DONTWAIT)) }
                if count > 0 { pending.removeFirst(Int(count)); continue }
                if count < 0, errno == EINTR { continue }
                if count < 0, errno == EAGAIN || errno == EWOULDBLOCK {
                    if toClient { self.toClient = pending; installWrite(toClient: true) }
                    else { self.toRemote = pending; installWrite(toClient: false) }
                    return
                }
                finish(failed: true)
                return
            }
            if toClient { self.toClient = pending; clientWrite?.cancel(); clientWrite = nil }
            else { self.toRemote = pending; remoteWrite?.cancel(); remoteWrite = nil }
            finishIfDrained()
        }

        private func installWrite(toClient: Bool) {
            if toClient, clientWrite != nil { return }
            if !toClient, remoteWrite != nil { return }
            let source = DispatchSource.makeWriteSource(fileDescriptor: toClient ? client : remote, queue: queue)
            source.setEventHandler { [weak self] in self?.flush(toClient: toClient) }
            if toClient { clientWrite = source } else { remoteWrite = source }
            source.resume()
        }

        private func finishIfDrained() {
            guard !clientInputOpen, !remoteInputOpen, toClient.isEmpty, toRemote.isEmpty else { return }
            finish(failed: false)
        }

        private func finish(failed: Bool) {
            guard !stopped else { return }
            stopped = true
            clientRead?.cancel(); remoteRead?.cancel(); clientWrite?.cancel(); remoteWrite?.cancel()
            clientRead = nil; remoteRead = nil; clientWrite = nil; remoteWrite = nil
            _ = close(client); _ = close(remote)
            finished(client, failed)
        }

        private func makeNonblocking(_ descriptor: Int32) -> Bool {
            let flags = fcntl(descriptor, F_GETFL)
            return flags >= 0 && fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0
        }
    }

    public init(configuration: ObstacleBridgeLinuxProxyProviderConfiguration) { self.configuration = configuration }

    public func start() throws {
        guard configuration.enabled else { return }
        if configuration.httpEnabled { try install(port: configuration.httpPort, socks: false) }
        if configuration.socks5Enabled { try install(port: configuration.socks5Port, socks: true) }
    }

    public func stop() {
        listeners.forEach { $0.source.cancel() }; listeners.removeAll()
        let active = relays.values; relays.removeAll()
        active.forEach { $0.stop() }
    }

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
        // A Dispatch read notification is level-triggered but can be stale.
        // Drain only accepts already queued by the kernel so this callback
        // never enters a blocking accept wait.
        while true {
            let client = Glibc.accept(listener, nil, nil)
            guard client >= 0 else {
                if errno == EAGAIN || errno == EWOULDBLOCK { return }
                return
            }
            guard setNonblocking(client) else { _ = close(client); continue }
            lock.lock(); accepted += 1; lock.unlock()
            DispatchQueue.global().async { [weak self] in self?.serve(client: client, socks: socks) }
        }
    }

    private func serve(client: Int32, socks: Bool) {
        do {
            let remote = try socks ? serveSOCKS(client) : serveHTTP(client)
            let relay = Relay(client: client, remote: remote) { [weak self] descriptor, relayFailed in
                guard let self else { return }
                self.queue.async {
                    self.relays.removeValue(forKey: descriptor)
                    self.lock.lock()
                    if relayFailed { self.failed += 1 } else { self.completed += 1 }
                    self.lock.unlock()
                }
            }
            queue.async { [weak self] in self?.relays[client] = relay; relay.start() }
        } catch {
            _ = close(client)
            lock.lock(); failed += 1; lock.unlock()
        }
    }

    private func serveHTTP(_ client: Int32) throws -> Int32 {
        let data = try readHeader(client)
        guard let text = String(data: data, encoding: .isoLatin1), let line = text.split(separator: "\r\n").first else { throw ProxyError.invalid }
        let bits = line.split(separator: " ", maxSplits: 2).map(String.init); guard bits.count == 3 else { throw ProxyError.invalid }
        let headers = Dictionary(uniqueKeysWithValues: text.split(separator: "\r\n").dropFirst().compactMap { row -> (String, String)? in let p = row.split(separator: ":", maxSplits: 1); return p.count == 2 ? (p[0].lowercased(), p[1].trimmingCharacters(in: .whitespaces)) : nil })
        guard authorized(headers["proxy-authorization"]) else { try write(client, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"ObstacleBridge\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); throw ProxyError.auth }
        let destination: (String, Int)
        if bits[0].uppercased() == "CONNECT" { destination = try authority(bits[1], defaultPort: 443) }
        else { guard let url = URL(string: bits[1]), let host = url.host else { throw ProxyError.invalid }; destination = (host, url.port ?? (url.scheme?.lowercased() == "https" ? 443 : 80)) }
        let remote = try connect(destination.0, destination.1)
        if bits[0].uppercased() == "CONNECT" { try write(client, "HTTP/1.1 200 Connection Established\r\nProxy-Agent: ObstacleBridge\r\n\r\n") }
        else {
            let target = URL(string: bits[1]).flatMap { url -> String? in var r = url.path.isEmpty ? "/" : url.path; if let q = url.query { r += "?" + q }; return r } ?? bits[1]
            let filtered = text.split(separator: "\r\n").dropFirst().filter { !$0.lowercased().hasPrefix("proxy-authorization:") && !$0.lowercased().hasPrefix("proxy-connection:") }
            try write(remote, (["\(bits[0]) \(target) \(bits[2])"] + filtered.map(String.init)).joined(separator: "\r\n") + "\r\n\r\n")
        }
        return remote
    }

    private func serveSOCKS(_ client: Int32) throws -> Int32 {
        let greeting = try readExactly(client, 2); guard greeting[0] == 5 else { throw ProxyError.invalid }
        let methods = try readExactly(client, Int(greeting[1])); let required = configuration.credentials != nil
        let method: UInt8 = required ? 2 : 0
        guard methods.contains(method) else { try write(client, Data([5, 255])); throw ProxyError.auth }; try write(client, Data([5, method]))
        if required { let head = try readExactly(client, 2); let u = try readExactly(client, Int(head[1])); let pLen = try readExactly(client, 1); let p = try readExactly(client, Int(pLen[0])); guard String(data: u, encoding: .utf8) == configuration.credentials?.username, String(data: p, encoding: .utf8) == configuration.credentials?.password else { try write(client, Data([1,1])); throw ProxyError.auth }; try write(client, Data([1,0])) }
        let header = try readExactly(client, 4); guard header[0] == 5, header[1] == 1 else { try write(client, Data([5,7,0,1,0,0,0,0,0,0])); throw ProxyError.invalid }
        let host: String
        switch header[3] { case 1: host = try readExactly(client, 4).map(String.init).joined(separator: "."); case 3: host = String(data: try readExactly(client, Int(try readExactly(client, 1)[0])), encoding: .utf8) ?? ""; case 4: host = try readExactly(client, 16).withUnsafeBytes { inet_ntop(AF_INET6, $0.baseAddress, UnsafeMutablePointer<CChar>.allocate(capacity: 46), 46) }.map { String(cString: $0) } ?? ""; default: throw ProxyError.invalid }
        let portData = try readExactly(client, 2); let remote = try connect(host, Int(portData[0]) << 8 | Int(portData[1]))
        try write(client, Data([5,0,0,1,0,0,0,0,0,0])); return remote
    }
    private func readHeader(_ fd: Int32) throws -> Data { var result = Data(); while result.count < 65_536 { result.append(try readExactly(fd, 1)); if result.suffix(4) == Data("\r\n\r\n".utf8) { return result } }; throw ProxyError.invalid }
    /// Bounded parser compatibility path. The listener never delegates a
    /// blocking `read`: every byte is consumed only after readiness, with the
    /// descriptor remaining nonblocking through the later relay handoff.
    private func readExactly(_ fd: Int32, _ count: Int) throws -> Data {
        var output = Data(); output.reserveCapacity(count)
        var buffer = [UInt8](repeating: 0, count: min(8192, max(1, count)))
        let deadline = DispatchTime.now().uptimeNanoseconds + 10_000_000_000
        while output.count < count {
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else { throw ProxyError.invalid }
            var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let remaining = Int32(min(UInt64(Int32.max), max(1, (deadline - now) / 1_000_000)))
            let ready = poll(&descriptor, 1, remaining) // OBSTACLEBRIDGE-ASYNC-IO-EXCEPTION: bounded compatibility parser pending per-client readiness state machine.
            if ready < 0, errno == EINTR { continue }
            guard ready > 0, descriptor.revents & Int16(POLLIN) != 0 else { throw ProxyError.invalid }
            let received = recv(fd, &buffer, min(buffer.count, count - output.count), Int32(MSG_DONTWAIT))
            if received < 0, errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK { continue }
            guard received > 0 else { throw ProxyError.invalid }
            output.append(buffer, count: Int(received))
        }
        return output
    }
    private func write(_ fd: Int32, _ text: String) throws { try write(fd, Data(text.utf8)) }
    private func write(_ fd: Int32, _ data: Data) throws { let n = data.withUnsafeBytes { Glibc.write(fd, $0.baseAddress, data.count) }; guard n == data.count else { throw ProxyError.invalid } }
    private func authorized(_ header: String?) -> Bool { guard let credentials = configuration.credentials else { return true }; guard let header, header.lowercased().hasPrefix("basic "), let data = Data(base64Encoded: String(header.dropFirst(6))), let value = String(data: data, encoding: .utf8) else { return false }; return value == "\(credentials.username):\(credentials.password)" }
    private func authority(_ raw: String, defaultPort: Int) throws -> (String, Int) { if raw.hasPrefix("[") { guard let end = raw.firstIndex(of: "]") else { throw ProxyError.invalid }; return (String(raw[raw.index(after: raw.startIndex)..<end]), Int(raw.dropFirst(raw.distance(from: raw.startIndex, to: end) + 2).dropFirst()) ?? defaultPort) }; let parts = raw.split(separator: ":", maxSplits: 1); return (String(parts[0]), parts.count == 2 ? Int(parts[1]) ?? defaultPort : defaultPort) }
    private func listener(port: Int) throws -> Int32 {
        let fd = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        guard fd >= 0 else { throw ProxyError.invalid }
        var yes: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(UInt16(port).bigEndian)
        guard inet_pton(AF_INET, configuration.bindHost, &address.sin_addr) == 1 else { _ = close(fd); throw ProxyError.invalid }
        let bound = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard bound == 0, listen(fd, 64) == 0 else { _ = close(fd); throw ProxyError.invalid }
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { _ = close(fd); throw ProxyError.invalid }
        return fd
    }
    private func setNonblocking(_ fd: Int32) -> Bool {
        let flags = fcntl(fd, F_GETFL)
        return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0
    }
    private func boundPort(_ fd: Int32) -> Int { var address = sockaddr_in(); var length = socklen_t(MemoryLayout<sockaddr_in>.size); _ = withUnsafeMutablePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) } }; return Int(UInt16(bigEndian: address.sin_port)) }
    private func connect(_ host: String, _ port: Int) throws -> Int32 { var hints = addrinfo(ai_flags: 0, ai_family: AF_UNSPEC, ai_socktype: Int32(SOCK_STREAM.rawValue), ai_protocol: 0, ai_addrlen: 0, ai_addr: nil, ai_canonname: nil, ai_next: nil); var result: UnsafeMutablePointer<addrinfo>?; guard getaddrinfo(host, String(port), &hints, &result) == 0 else { throw ProxyError.invalid }; defer { freeaddrinfo(result) }; var row = result; while let current = row { if !configuration.allowPrivateDestinations && isPrivate(current.pointee.ai_addr, family: current.pointee.ai_family) { row = current.pointee.ai_next; continue }; let fd = socket(current.pointee.ai_family, current.pointee.ai_socktype, current.pointee.ai_protocol); if fd >= 0 && Glibc.connect(fd, current.pointee.ai_addr, current.pointee.ai_addrlen) == 0 { return fd }; if fd >= 0 { _ = close(fd) }; row = current.pointee.ai_next }; throw ProxyError.invalid }
    private func isPrivate(_ address: UnsafeMutablePointer<sockaddr>?, family: Int32) -> Bool { guard let address else { return true }; if family == AF_INET { let value = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }; return value >> 24 == 10 || value >> 20 == 0xAC1 || value >> 16 == 0xC0A8 || value >> 24 == 127 || value >> 16 == 0xA9FE }; return family == AF_INET6 }
    private enum ProxyError: Error { case invalid, auth }
}
