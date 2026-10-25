import Dispatch
import Foundation
import ObstacleBridgeDesktopShared
#if os(Linux)
import Glibc
#endif

/// Linux-owned first IPC-1A2 slice. The inherited child owns a loopback
/// listener, but reads its status only through the bounded parent RPC. Full
/// authenticated API, sessions, configuration, and log-query parity remain
/// outside this intentionally narrow surface.
public final class ObstacleBridgeNativeAdminLinuxService: @unchecked Sendable {
    private let parentRPC: ObstacleBridgeNativeAdminWorker.ParentRPC
    private let queue = DispatchQueue(label: "org.obstaclebridge.linux.native-admin")
    private var listener: Int32 = -1
    private var source: DispatchSourceRead?
    public private(set) var port: Int = 0

    public init(arguments: [String: Any], parentRPC: ObstacleBridgeNativeAdminWorker.ParentRPC) throws {
        let bindHost = (arguments["admin_web_bind"] as? String) ?? "127.0.0.1"
        let requestedPort = (arguments["admin_web_port"] as? NSNumber)?.intValue ?? 0
        guard bindHost == "127.0.0.1", (0...65535).contains(requestedPort) else {
            throw ObstacleBridgeLinuxAdminServerError.invalidBindHost
        }
        self.parentRPC = parentRPC
        try start(port: requestedPort)
    }

    deinit { stop() }

    public func stop() {
        source?.cancel()
        source = nil
        listener = -1
        port = 0
    }

    private func start(port requestedPort: Int) throws {
        let fd = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        guard fd >= 0 else { throw ObstacleBridgeLinuxAdminServerError.socketFailure(errno) }
        var reuse: Int32 = 1
        _ = withUnsafePointer(to: &reuse) { setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, $0, socklen_t(MemoryLayout<Int32>.size)) }
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(UInt16(requestedPort).bigEndian)
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bound == 0 else { let code = errno; _ = close(fd); throw ObstacleBridgeLinuxAdminServerError.bindFailure(code) }
        guard listen(fd, 8) == 0 else { let code = errno; _ = close(fd); throw ObstacleBridgeLinuxAdminServerError.listenFailure(code) }
        var actual = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &actual) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }
        listener = fd
        port = Int(UInt16(bigEndian: actual.sin_port))
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        self.source = source
        source.setEventHandler { [weak self] in self?.acceptClient() }
        source.setCancelHandler { _ = close(fd) }
        source.resume()
    }

    private func acceptClient() {
        guard listener >= 0 else { return }
        let client = accept(listener, nil, nil)
        guard client >= 0 else { return }
        DispatchQueue.global().async { [weak self] in self?.serve(client) }
    }

    private func serve(_ client: Int32) {
        defer { _ = close(client) }
        var buffer = [UInt8](repeating: 0, count: 1024)
        let received = read(client, &buffer, buffer.count)
        guard received > 0,
              let request = String(bytes: buffer.prefix(Int(received)), encoding: .utf8),
              let line = request.split(separator: "\r\n", maxSplits: 1).first
        else { return }
        let components = line.split(separator: " ")
        guard components.count >= 2, components[0] == "GET", components[1] == "/api/status" else {
            writeResponse(client, status: "404 Not Found", body: Data("{\"error\":\"not found\"}".utf8))
            return
        }
        let status = (try? parentRPC.call(method: "get_status_snapshot")) as? [String: Any] ?? ["state": "unavailable"]
        guard let body = try? JSONSerialization.data(withJSONObject: status, options: [.sortedKeys]) else { return }
        writeResponse(client, status: "200 OK", body: body)
    }

    private func writeResponse(_ client: Int32, status: String, body: Data) {
        var wire = Data("HTTP/1.1 \(status)\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n".utf8)
        wire.append(body)
        _ = wire.withUnsafeBytes { write(client, $0.baseAddress, wire.count) }
    }
}
