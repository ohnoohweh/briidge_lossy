import Dispatch
import Foundation
import ObstacleBridgeCore
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
    private let security: ObstacleBridgeLinuxAdminSecurity
    private let adminWebDirectory: URL
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
        let authDisabled = (arguments["admin_web_auth_disable"] as? Bool) ?? false
        let username = (arguments["admin_web_username"] as? String) ?? ""
        let password = (arguments["admin_web_password"] as? String) ?? ""
        self.adminWebDirectory = URL(fileURLWithPath: (arguments["admin_web_dir"] as? String) ?? "./admin_web", isDirectory: true).standardizedFileURL
        self.security = ObstacleBridgeLinuxAdminSecurity(
            credentials: { (!authDisabled && !username.isEmpty && !password.isEmpty, username, password) },
            scope: { "\(bindHost)|\(requestedPort)" }
        )
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
        var buffer = [UInt8](repeating: 0, count: 16 * 1024)
        let received = read(client, &buffer, buffer.count)
        guard received > 0,
              let request = String(bytes: buffer.prefix(Int(received)), encoding: .utf8),
              let line = request.split(separator: "\r\n", maxSplits: 1).first
        else { return }
        let components = line.split(separator: " ")
        guard components.count >= 2 else {
            writeResponse(client, status: "404 Not Found", body: Data("{\"error\":\"not found\"}".utf8))
            return
        }
        let method = String(components[0]).uppercased()
        let target = String(components[1])
        let path = target.split(separator: "?", maxSplits: 1).first.map(String.init) ?? ""
        let headerText = request.split(separator: "\r\n\r\n", maxSplits: 1).first.map(String.init) ?? ""
        let headers = headerText.split(separator: "\r\n").dropFirst().reduce(into: [String: String]()) { result, value in
            let pair = value.split(separator: ":", maxSplits: 1)
            guard pair.count == 2 else { return }
            result[pair[0].trimmingCharacters(in: .whitespaces).lowercased()] = pair[1].trimmingCharacters(in: .whitespaces)
        }
        let body = request.components(separatedBy: "\r\n\r\n").dropFirst().joined(separator: "\r\n\r\n").data(using: .utf8)
        if method == "GET", let staticResponse = staticResponse(path: path) {
            writeResponse(client, status: "200 OK", body: staticResponse.body, contentType: staticResponse.contentType)
            return
        }
        switch path {
        case "/api/auth/state" where method == "GET":
            writeResponse(client, response: jsonResponse(security.state(headers: headers)))
            return
        case "/api/auth/challenge" where method == "GET":
            writeResponse(client, response: jsonResponse(security.issueLoginChallenge()))
            return
        case "/api/auth/login" where method == "POST":
            writeResponse(client, response: security.login(body: body))
            return
        case "/api/auth/logout" where method == "POST":
            writeResponse(client, response: security.logout(headers: headers))
            return
        case "/api/config/challenge":
            guard method == "POST" else {
                writeResponse(client, status: "405 Method Not Allowed", body: Data("{\"error\":\"method not allowed\"}".utf8))
                return
            }
            guard security.isAuthenticated(headers: headers) else {
                writeResponse(client, status: "401 Unauthorized", body: Data("{\"ok\":false,\"authenticated\":false,\"error\":\"authentication required\"}".utf8))
                return
            }
            guard let updates = (try? JSONSerialization.jsonObject(with: body ?? Data())) as? [String: Any],
                  let values = updates["updates"] as? [String: Any] else {
                writeResponse(client, status: "400 Bad Request", body: Data("{\"ok\":false,\"error\":\"updates must be an object\"}".utf8))
                return
            }
            writeResponse(client, response: jsonResponse((try? security.issueConfigChallenge(updates: values)) ?? ["ok": false, "error": "updates must be an object"]))
            return
        case "/api/config" where method == "POST":
            guard security.isAuthenticated(headers: headers) else {
                writeResponse(client, status: "401 Unauthorized", body: Data("{\"ok\":false,\"authenticated\":false,\"error\":\"authentication required\"}".utf8))
                return
            }
            guard let payload = (try? JSONSerialization.jsonObject(with: body ?? Data())) as? [String: Any],
                  let updates = payload["updates"] as? [String: Any] else {
                writeResponse(client, status: "400 Bad Request", body: Data("{\"ok\":false,\"error\":\"invalid JSON body or updates must be an object\"}".utf8))
                return
            }
            let authRequired = security.state(headers: headers)["auth_required"] as? Bool ?? false
            guard !authRequired || (!(payload["challenge_id"] as? String ?? "").isEmpty && !(payload["proof"] as? String ?? "").isEmpty) else {
                writeResponse(client, status: "428 Precondition Required", body: Data("{\"ok\":false,\"error\":\"configuration change confirmation required\"}".utf8))
                return
            }
            if authRequired, let error = security.validateConfigChallenge(body: body) {
                let encoded = try? JSONSerialization.data(withJSONObject: ["ok": false, "error": error], options: [.sortedKeys])
                writeResponse(client, status: "403 Forbidden", body: encoded ?? Data("{}".utf8))
                return
            }
            let result = try? parentRPC.call(method: "update_config", args: [updates])
            let values = result as? [Any] ?? []
            let succeeded = (values.first as? Bool) ?? ((values.first as? NSNumber)?.boolValue ?? false)
            if !succeeded {
                let error = values.dropFirst().first as? String ?? "configuration update failed"
                let encoded = try? JSONSerialization.data(withJSONObject: ["ok": false, "error": error], options: [.sortedKeys])
                writeResponse(client, status: "400 Bad Request", body: encoded ?? Data("{}".utf8))
                return
            }
            if updates.keys.contains(where: { ["admin_web_auth_disable", "admin_web_username", "admin_web_password", "secure_link_psk"].contains($0) }) {
                security.reset()
            }
            let config = try? parentRPC.call(method: "get_config_snapshot")
            let response = ["ok": true, "config": config as? [String: Any] ?? [:]] as [String: Any]
            let encoded = try? JSONSerialization.data(withJSONObject: response, options: [.sortedKeys])
            writeResponse(client, status: "200 OK", body: encoded ?? Data("{\"ok\":true}".utf8))
            return
        default: break
        }
        guard method == "GET", ["/api/status", "/api/meta", "/api/config", "/api/logs", "/api/connections", "/api/peers"].contains(path) else {
            writeResponse(client, status: "404 Not Found", body: Data("{\"error\":\"not found\"}".utf8))
            return
        }
        guard security.isAuthenticated(headers: headers) else {
            writeResponse(client, status: "401 Unauthorized", body: Data("{\"ok\":false,\"authenticated\":false,\"error\":\"authentication required\"}".utf8))
            return
        }
        if path == "/api/config" {
            let config = try? parentRPC.call(method: "get_config_snapshot")
            let schema = try? parentRPC.call(method: "get_config_schema_snapshot")
            let payload: [String: Any] = [
                "ok": true,
                "config": config as? [String: Any] ?? [:],
                "schema": schema as? [String: Any] ?? [:],
            ]
            guard let responseBody = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]) else { return }
            writeResponse(client, status: "200 OK", body: responseBody)
            return
        }
        if path == "/api/meta" {
            let status = try? parentRPC.call(method: "get_status_snapshot")
            let snapshot = status as? [String: Any] ?? [:]
            let payload: [String: Any] = [
                "app": "ObstacleBridgeLinux",
                "platform": "linux",
                "build": snapshot["build"] ?? [:],
            ]
            guard let responseBody = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]) else { return }
            writeResponse(client, status: "200 OK", body: responseBody)
            return
        }
        let rpcMethod: String
        switch path {
        case "/api/status": rpcMethod = "get_status_snapshot"
        case "/api/config": rpcMethod = "get_config_snapshot"
        case "/api/connections": rpcMethod = "get_connections_snapshot"
        case "/api/peers": rpcMethod = "get_peer_connections_snapshot"
        default: rpcMethod = "fetch_logs"
        }
        let rpcArgs: [Any] = path == "/api/logs" ? [logLimit(target: target)] : []
        let result = try? parentRPC.call(method: rpcMethod, args: rpcArgs)
        let payload: Any = path == "/api/logs" ? ["logs": result ?? []] : (result as? [String: Any] ?? ["state": "unavailable"])
        guard let body = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]) else { return }
        writeResponse(client, status: "200 OK", body: body)
    }

    private func jsonResponse(_ payload: [String: Any]) -> ObstacleBridgeAdminLinuxResponse {
        ObstacleBridgeAdminAPI.linuxJSONResponse(payload) ?? .init(statusCode: 500, body: Data("{}".utf8))
    }

    private func staticResponse(path: String) -> (body: Data, contentType: String)? {
        let relativePath: String
        switch path {
        case "/", "/index.html": relativePath = "index.html"
        case "/app.js": relativePath = "app.js"
        case "/style.css": relativePath = "style.css"
        default: return nil
        }
        let file = adminWebDirectory.appendingPathComponent(relativePath).standardizedFileURL
        guard file.deletingLastPathComponent() == adminWebDirectory,
              let body = try? Data(contentsOf: file) else { return nil }
        let contentType: String
        switch relativePath {
        case "app.js": contentType = "application/javascript; charset=utf-8"
        case "style.css": contentType = "text/css; charset=utf-8"
        default: contentType = "text/html; charset=utf-8"
        }
        return (body, contentType)
    }

    private func logLimit(target: String) -> Int {
        guard let query = target.split(separator: "?", maxSplits: 1).dropFirst().first else { return 400 }
        for pair in query.split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1)
            if parts.count == 2, parts[0] == "limit", let value = Int(parts[1]) {
                return max(1, min(value, 10_000))
            }
        }
        return 400
    }

    private func writeResponse(_ client: Int32, status: String, body: Data, contentType: String = "application/json; charset=utf-8") {
        var wire = Data("HTTP/1.1 \(status)\r\nContent-Type: \(contentType)\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n".utf8)
        wire.append(body)
        _ = wire.withUnsafeBytes { write(client, $0.baseAddress, wire.count) }
    }

    private func writeResponse(_ client: Int32, response: ObstacleBridgeAdminLinuxResponse) {
        let status: String
        switch response.statusCode {
        case 200: status = "200 OK"
        case 400: status = "400 Bad Request"
        case 401: status = "401 Unauthorized"
        case 403: status = "403 Forbidden"
        default: status = "500 Internal Server Error"
        }
        let extra = response.headers.map { "\($0.0): \($0.1)\r\n" }.joined()
        var wire = Data("HTTP/1.1 \(status)\r\nContent-Type: \(response.contentType)\r\nContent-Length: \(response.body.count)\r\n\(extra)Connection: close\r\n\r\n".utf8)
        wire.append(response.body)
        _ = wire.withUnsafeBytes { write(client, $0.baseAddress, wire.count) }
    }
}
