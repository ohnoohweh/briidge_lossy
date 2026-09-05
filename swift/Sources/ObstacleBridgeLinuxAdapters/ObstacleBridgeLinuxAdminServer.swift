import Dispatch
import Foundation
#if os(Linux)
import Glibc
#endif

public enum ObstacleBridgeLinuxAdminServerError: Error, Equatable, LocalizedError {
    case invalidBindHost
    case socketFailure(Int32)
    case bindFailure(Int32)
    case listenFailure(Int32)

    public var errorDescription: String? {
        switch self {
        case .invalidBindHost: return "Linux Admin server currently requires an IPv4 bind address"
        case .socketFailure(let code), .bindFailure(let code), .listenFailure(let code): return "POSIX Admin server failure errno=\(code)"
        }
    }
}

/// Minimal Linux-native Admin HTTP surface. It owns no transport state and
/// reads only the runtime's redacted status projection.
public final class ObstacleBridgeLinuxAdminServer: @unchecked Sendable {
    private let statusProvider: () -> ObstacleBridgeLinuxRuntimeStatus
    private let queue = DispatchQueue(label: "org.obstaclebridge.linux.admin")
    private var listener: Int32 = -1
    private var source: DispatchSourceRead?
    public private(set) var port: Int = 0

    public init(runtime: ObstacleBridgeLinuxConfiguredRuntime) {
        self.statusProvider = { runtime.status() }
    }

    public init(liveRuntime: ObstacleBridgeLinuxLiveRuntime) {
        self.statusProvider = { liveRuntime.status() }
    }

    public func start(bindHost: String = "127.0.0.1", port requestedPort: Int = 0) throws {
        guard listener < 0 else { return }
        guard let address = ipv4Address(bindHost), (0...65535).contains(requestedPort) else { throw ObstacleBridgeLinuxAdminServerError.invalidBindHost }
        let fd = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        guard fd >= 0 else { throw ObstacleBridgeLinuxAdminServerError.socketFailure(errno) }
        var reuse: Int32 = 1
        _ = withUnsafePointer(to: &reuse) { setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, $0, socklen_t(MemoryLayout<Int32>.size)) }
        var socketAddress = sockaddr_in()
        socketAddress.sin_family = sa_family_t(AF_INET)
        socketAddress.sin_port = in_port_t(UInt16(requestedPort).bigEndian)
        socketAddress.sin_addr = address
        let bindResult = withUnsafePointer(to: &socketAddress) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bindResult == 0 else { let code = errno; _ = close(fd); throw ObstacleBridgeLinuxAdminServerError.bindFailure(code) }
        guard listen(fd, 16) == 0 else { let code = errno; _ = close(fd); throw ObstacleBridgeLinuxAdminServerError.listenFailure(code) }
        var actual = sockaddr_in(); var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &actual) { pointer in pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) } }
        self.listener = fd
        self.port = Int(UInt16(bigEndian: actual.sin_port))
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        self.source = source
        source.setEventHandler { [weak self] in self?.acceptReadyClient() }
        source.setCancelHandler { _ = close(fd) }
        source.resume()
    }

    public func stop() {
        source?.cancel()
        source = nil
        listener = -1
        port = 0
    }

    private func acceptReadyClient() {
        guard listener >= 0 else { return }
        let client = accept(listener, nil, nil)
        guard client >= 0 else { return }
        DispatchQueue.global().async { [weak self] in self?.serve(client) }
    }

    private func serve(_ client: Int32) {
        defer { _ = close(client) }
        var request = Data()
        var buffer = [UInt8](repeating: 0, count: 1024)
        while request.count < 16 * 1024 {
            let received = read(client, &buffer, buffer.count)
            guard received > 0 else { return }
            request.append(buffer, count: Int(received))
            if request.range(of: Data("\r\n\r\n".utf8)) != nil { break }
        }
        let requestLine = String(data: request, encoding: .utf8)?.split(separator: "\r\n", maxSplits: 1).first ?? ""
        let path = requestLine.split(separator: " ").dropFirst().first.map(String.init) ?? ""
        let response: (Int, Data)
        switch path {
        case "/api/status": response = (200, statusData())
        case "/api/peers": response = (200, peersData())
        default: response = (404, Data("{\"error\":\"not found\"}".utf8))
        }
        let header = "HTTP/1.1 \(response.0 == 200 ? "200 OK" : "404 Not Found")\r\nContent-Type: application/json\r\nContent-Length: \(response.1.count)\r\nConnection: close\r\n\r\n"
        var wire = Data(header.utf8); wire.append(response.1)
        _ = wire.withUnsafeBytes { write(client, $0.baseAddress, wire.count) }
    }

    private func statusData() -> Data {
        let status = statusProvider()
        let payload: [String: Any] = [
            "platform": "linux-swift",
            "overlay_transport": status.transport,
            "transport_state": status.state,
            "app_ready": status.appReady,
            "failure_reason": status.failureReason as Any,
            "connection_layers": [
                ["name": "transport", "state": status.state, "connected": status.state == "connected"],
                ["name": "secure_link", "state": status.secureLinkState, "authenticated": status.secureLinkState == "authenticated"],
            ],
        ]
        return json(payload)
    }

    private func peersData() -> Data {
        let status = statusProvider()
        return json([["peer_id": "configured-peer", "transport": status.transport, "state": status.state, "app_ready": status.appReady, "configured_candidates": status.configuredCandidates, "active_host": status.activeHost as Any, "port": status.port, "failure_reason": status.failureReason as Any]])
    }

    private func json(_ object: Any) -> Data { (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data("{}".utf8) }

    private func ipv4Address(_ host: String) -> in_addr? {
        var address = in_addr()
        return host.withCString { inet_pton(AF_INET, $0, &address) == 1 ? address : nil }
    }

    deinit { stop() }
}
