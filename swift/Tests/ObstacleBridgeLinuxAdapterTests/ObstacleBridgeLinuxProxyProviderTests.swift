import Foundation
import Testing
#if os(Linux)
import Glibc
#endif
@testable import ObstacleBridgeLinuxAdapters

struct ObstacleBridgeLinuxProxyProviderTests {
    @Test func listenerReadinessDrainAdmitsEveryQueuedSOCKSClient() throws {
        let provider = ObstacleBridgeLinuxProxyProvider(configuration: .init(enabled: true, socks5Port: 0, httpEnabled: false, allowPrivateDestinations: true))
        try provider.start(); defer { provider.stop() }
        let port = try #require(provider.snapshot()["socks5_port"] as? Int)
        let first = try connect(port: port); defer { _ = close(first) }
        let second = try connect(port: port); defer { _ = close(second) }
        try send(first, Data([5, 1, 0]))
        try send(second, Data([5, 1, 0]))
        #expect(try receive(first) == Data([5, 0]))
        #expect(try receive(second) == Data([5, 0]))
        #expect((provider.snapshot()["accepted_connections"] as? Int ?? 0) >= 2)
    }

    @Test func listenersServeAuthenticationAndSOCKS5Negotiation() throws {
        let provider = ObstacleBridgeLinuxProxyProvider(configuration: .init(enabled: true, httpPort: 0, socks5Port: 0, credentials: ("operator", "token"), allowPrivateDestinations: true))
        try provider.start(); defer { provider.stop() }
        let snapshot = provider.snapshot()
        let httpPort = try #require(snapshot["http_port"] as? Int)
        let socksPort = try #require(snapshot["socks5_port"] as? Int)
        #expect(httpPort > 0); #expect(socksPort > 0)

        let http = try connect(port: httpPort); defer { _ = close(http) }
        try send(http, Data("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n".utf8))
        #expect(String(data: try receive(http), encoding: .utf8)?.contains("407 Proxy Authentication Required") == true)

        let socks = try connect(port: socksPort); defer { _ = close(socks) }
        try send(socks, Data([5, 1, 2]))
        #expect(try receive(socks) == Data([5, 2]))
    }

    private func connect(port: Int) throws -> Int32 {
        let fd = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0); guard fd >= 0 else { throw SocketError.failure }
        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        _ = withUnsafePointer(to: &timeout) { setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, $0, socklen_t(MemoryLayout<timeval>.size)) }
        var address = sockaddr_in(); address.sin_family = sa_family_t(AF_INET); address.sin_port = in_port_t(UInt16(port).bigEndian)
        _ = "127.0.0.1".withCString { inet_pton(AF_INET, $0, &address.sin_addr) }
        guard withUnsafePointer(to: &address, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Glibc.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }) == 0 else { _ = close(fd); throw SocketError.failure }
        return fd
    }
    private func send(_ fd: Int32, _ data: Data) throws { guard data.withUnsafeBytes({ Glibc.write(fd, $0.baseAddress, data.count) }) == data.count else { throw SocketError.failure } }
    private func receive(_ fd: Int32) throws -> Data { var bytes = [UInt8](repeating: 0, count: 512); let count = read(fd, &bytes, bytes.count); guard count > 0 else { throw SocketError.failure }; return Data(bytes.prefix(Int(count))) }
    private enum SocketError: Error { case failure }
}
