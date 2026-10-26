import Dispatch
import Foundation
import Crypto
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
    private static let liveTopics = ["status", "connections", "peers"]
    private struct WebSocketFrame {
        let opcode: UInt8
        let payload: Data
        let final: Bool
        let consumed: Int
    }
    private let parentRPC: ObstacleBridgeNativeAdminWorker.ParentRPC
    private let security: ObstacleBridgeLinuxAdminSecurity
    private let controlToken: String
    private let adminWebDirectory: URL
    private let startedAt = ProcessInfo.processInfo.systemUptime
    private let adminWebName: String
    private let overlayTransport: String
    private let dashboardEnabled: Bool?
    private let telemetrySpoolDirectory: String
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
        self.controlToken = (arguments["admin_web_token"] as? String) ?? ""
        self.adminWebName = (arguments["admin_web_name"] as? String) ?? ""
        self.overlayTransport = (arguments["overlay_transport"] as? String) ?? ""
        self.dashboardEnabled = arguments["dashboard"] as? Bool
        self.telemetrySpoolDirectory = (arguments["telemetry_spool_directory"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
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
        if path == "/api/live", method == "GET", headers["upgrade"]?.lowercased() == "websocket" {
            guard security.isAuthenticated(headers: headers) else {
                writeResponse(client, status: "401 Unauthorized", body: Data("{\"ok\":false,\"authenticated\":false,\"error\":\"authentication required\"}".utf8))
                return
            }
            serveLiveWebSocket(client, target: target, key: headers["sec-websocket-key"] ?? "", version: headers["sec-websocket-version"] ?? "")
            return
        }
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
        case "/api/channelmux/remote-services" where method == "POST":
            guard security.isAuthenticated(headers: headers) else {
                writeResponse(client, status: "401 Unauthorized", body: Data("{\"ok\":false,\"authenticated\":false,\"error\":\"authentication required\"}".utf8))
                return
            }
            guard let payload = (try? JSONSerialization.jsonObject(with: body ?? Data())) as? [String: Any],
                  let remoteServers = payload["remote_servers"] as? [Any] else {
                writeResponse(client, status: "400 Bad Request", body: Data("{\"ok\":false,\"error\":\"remote_servers must be an array\"}".utf8))
                return
            }
            let result = try? parentRPC.call(method: "replace_remote_services_catalog", args: [remoteServers])
            let values = result as? [Any] ?? []
            let succeeded = (values.first as? Bool) ?? ((values.first as? NSNumber)?.boolValue ?? false)
            guard succeeded else {
                let error = values.dropFirst().first as? String ?? "remote service update failed"
                let encoded = try? JSONSerialization.data(withJSONObject: ["ok": false, "error": error], options: [.sortedKeys])
                writeResponse(client, status: "400 Bad Request", body: encoded ?? Data("{}".utf8))
                return
            }
            let encoded = try? JSONSerialization.data(withJSONObject: ["ok": true, "remote_servers": remoteServers], options: [.sortedKeys])
            writeResponse(client, status: "200 OK", body: encoded ?? Data("{\"ok\":true}".utf8))
            return
        case "/api/reconnect" where method == "POST":
            guard security.isAuthenticated(headers: headers) else {
                writeResponse(client, status: "401 Unauthorized", body: Data("{\"ok\":false,\"authenticated\":false,\"error\":\"authentication required\"}".utf8))
                return
            }
            guard isControlAuthorized(headers: headers) else {
                writeResponse(client, status: "403 Forbidden", body: Data("{\"ok\":false,\"error\":\"forbidden\"}".utf8))
                return
            }
            guard let payload = (try? JSONSerialization.jsonObject(with: body ?? Data("{}".utf8))) as? [String: Any] else {
                writeResponse(client, status: "400 Bad Request", body: Data("{\"ok\":false,\"error\":\"invalid JSON body\"}".utf8))
                return
            }
            let target = (payload["peer_id"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let result = try? parentRPC.call(method: "request_overlay_reconnect", kwargs: target.isEmpty ? [:] : ["target_peer_id": target])
            let response = result as? [String: Any] ?? ["ok": false, "error": "reconnect unavailable"]
            let status = (response["ok"] as? Bool ?? false) ? "200 OK" : response["reason"] as? String == "unknown_peer_id" ? "404 Not Found" : "409 Conflict"
            let encoded = try? JSONSerialization.data(withJSONObject: response, options: [.sortedKeys])
            writeResponse(client, status: status, body: encoded ?? Data("{\"ok\":false}".utf8))
            return
        case "/api/secure-link/rekey" where method == "POST":
            guard security.isAuthenticated(headers: headers) else {
                writeResponse(client, status: "401 Unauthorized", body: Data("{\"ok\":false,\"authenticated\":false,\"error\":\"authentication required\"}".utf8))
                return
            }
            guard let payload = (try? JSONSerialization.jsonObject(with: body ?? Data())) as? [String: Any],
                  let target = (payload["peer_id"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines), !target.isEmpty else {
                writeResponse(client, status: "400 Bad Request", body: Data("{\"ok\":false,\"error\":\"peer_id is required\"}".utf8))
                return
            }
            let result = try? parentRPC.call(method: "request_secure_link_rekey", kwargs: ["target_peer_id": target])
            let response = result as? [String: Any] ?? ["ok": false, "error": "rekey unavailable"]
            let status = (response["ok"] as? Bool ?? false) ? "200 OK" : "409 Conflict"
            let encoded = try? JSONSerialization.data(withJSONObject: response, options: [.sortedKeys])
            writeResponse(client, status: status, body: encoded ?? Data("{\"ok\":false}".utf8))
            return
        case "/api/secure-link/reload" where method == "POST":
            guard security.isAuthenticated(headers: headers) else {
                writeResponse(client, status: "401 Unauthorized", body: Data("{\"ok\":false,\"authenticated\":false,\"error\":\"authentication required\"}".utf8))
                return
            }
            guard let payload = (try? JSONSerialization.jsonObject(with: body ?? Data())) as? [String: Any],
                  let scope = (payload["scope"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
                  ["revocation", "local_identity", "all"].contains(scope) else {
                writeResponse(client, status: "400 Bad Request", body: Data("{\"ok\":false,\"error\":\"scope must be one of revocation, local_identity, all\"}".utf8))
                return
            }
            let target = (payload["peer_id"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            var kwargs: [String: Any] = ["scope": scope]
            if !target.isEmpty { kwargs["target_peer_id"] = target }
            let result = try? parentRPC.call(method: "request_secure_link_reload", kwargs: kwargs)
            let response = result as? [String: Any] ?? ["ok": false, "error": "reload unavailable"]
            let status = (response["ok"] as? Bool ?? false) ? "200 OK" : "409 Conflict"
            let encoded = try? JSONSerialization.data(withJSONObject: response, options: [.sortedKeys])
            writeResponse(client, status: status, body: encoded ?? Data("{\"ok\":false}".utf8))
            return
        case "/api/tun-helper/repair" where method == "POST":
            guard security.isAuthenticated(headers: headers) else {
                writeResponse(client, status: "401 Unauthorized", body: Data("{\"ok\":false,\"authenticated\":false,\"error\":\"authentication required\"}".utf8))
                return
            }
            guard isControlAuthorized(headers: headers) else {
                writeResponse(client, status: "403 Forbidden", body: Data("{\"ok\":false,\"error\":\"forbidden\"}".utf8))
                return
            }
            let result = try? parentRPC.call(method: "request_tun_helper_repair", timeout: 2)
            let response = result as? [String: Any] ?? ["ok": false, "error": "TUN helper repair unavailable", "retryable": true]
            let status = (response["ok"] as? Bool ?? false) ? "200 OK" : "409 Conflict"
            let encoded = try? JSONSerialization.data(withJSONObject: response, options: [.sortedKeys])
            writeResponse(client, status: status, body: encoded ?? Data("{\"ok\":false}".utf8))
            return
        case "/api/tun-routing/control" where method == "POST":
            guard security.isAuthenticated(headers: headers) else {
                writeResponse(client, status: "401 Unauthorized", body: Data("{\"ok\":false,\"authenticated\":false,\"error\":\"authentication required\"}".utf8))
                return
            }
            guard isControlAuthorized(headers: headers) else {
                writeResponse(client, status: "403 Forbidden", body: Data("{\"ok\":false,\"error\":\"forbidden\"}".utf8))
                return
            }
            guard let payload = (try? JSONSerialization.jsonObject(with: body ?? Data())) as? [String: Any],
                  let enabled = payload["enabled"] as? Bool else {
                writeResponse(client, status: "400 Bad Request", body: Data("{\"ok\":false,\"error\":\"enabled is required\"}".utf8))
                return
            }
            let result = try? parentRPC.call(method: "request_tun_enabled", kwargs: ["enabled": enabled], timeout: 2)
            let response = result as? [String: Any] ?? ["ok": false, "error": "TUN routing control unavailable", "retryable": true]
            let status = (response["ok"] as? Bool ?? false) ? "200 OK" : "409 Conflict"
            let encoded = try? JSONSerialization.data(withJSONObject: response, options: [.sortedKeys])
            writeResponse(client, status: status, body: encoded ?? Data("{\"ok\":false}".utf8))
            return
        case "/api/restart" where method == "POST":
            guard security.isAuthenticated(headers: headers) else {
                writeResponse(client, status: "401 Unauthorized", body: Data("{\"ok\":false,\"authenticated\":false,\"error\":\"authentication required\"}".utf8))
                return
            }
            guard isControlAuthorized(headers: headers) else {
                writeResponse(client, status: "403 Forbidden", body: Data("{\"ok\":false,\"error\":\"forbidden\"}".utf8))
                return
            }
            guard (try? parentRPC.call(method: "request_restart", kwargs: ["reason": "admin_web:/api/restart"])) != nil else {
                writeResponse(client, status: "503 Service Unavailable", body: Data("{\"ok\":false,\"error\":\"restart unavailable\",\"retryable\":true}".utf8))
                return
            }
            writeResponse(client, status: "200 OK", body: Data("{\"ok\":true,\"restarting\":true}".utf8))
            return
        case "/api/shutdown" where method == "POST":
            guard security.isAuthenticated(headers: headers) else {
                writeResponse(client, status: "401 Unauthorized", body: Data("{\"ok\":false,\"authenticated\":false,\"error\":\"authentication required\"}".utf8))
                return
            }
            guard isControlAuthorized(headers: headers) else {
                writeResponse(client, status: "403 Forbidden", body: Data("{\"ok\":false,\"error\":\"forbidden\"}".utf8))
                return
            }
            guard (try? parentRPC.call(method: "request_shutdown", kwargs: ["exit_code": 76, "reason": "admin_web:/api/shutdown"])) != nil else {
                writeResponse(client, status: "503 Service Unavailable", body: Data("{\"ok\":false,\"error\":\"shutdown unavailable\",\"retryable\":true}".utf8))
                return
            }
            writeResponse(client, status: "200 OK", body: Data("{\"ok\":true,\"shutting_down\":true}".utf8))
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
        case "/api/onboarding/blueprints" where method == "GET":
            guard security.isAuthenticated(headers: headers) else {
                writeResponse(client, status: "401 Unauthorized", body: Data("{\"ok\":false,\"authenticated\":false,\"error\":\"authentication required\"}".utf8))
                return
            }
            let connections = try? parentRPC.call(method: "get_connections_snapshot")
            let blueprints = onboardingBlueprints(connections as? [String: Any] ?? [:])
            let payload: [String: Any] = ["ok": true, "count": blueprints.count, "blueprints": blueprints]
            guard let encoded = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]) else {
                writeResponse(client, status: "503 Service Unavailable", body: Data("{\"ok\":false,\"error\":\"blueprints unavailable\",\"retryable\":true}".utf8))
                return
            }
            writeResponse(client, status: "200 OK", body: encoded)
            return
        case "/api/onboarding/connection-profiles" where method == "GET":
            guard security.isAuthenticated(headers: headers) else {
                writeResponse(client, status: "401 Unauthorized", body: Data("{\"ok\":false,\"authenticated\":false,\"error\":\"authentication required\"}".utf8))
                return
            }
            let peers = try? parentRPC.call(method: "get_peer_connections_snapshot")
            let profiles = onboardingConnectionProfiles(peers as? [String: Any] ?? [:])
            let payload: [String: Any] = ["ok": true, "count": profiles.count, "profiles": profiles]
            guard let encoded = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]) else {
                writeResponse(client, status: "503 Service Unavailable", body: Data("{\"ok\":false,\"error\":\"profiles unavailable\",\"retryable\":true}".utf8))
                return
            }
            writeResponse(client, status: "200 OK", body: encoded)
            return
        case "/api/onboarding/invite/generate" where method == "POST":
            guard security.isAuthenticated(headers: headers) else {
                writeResponse(client, status: "401 Unauthorized", body: Data("{\"ok\":false,\"authenticated\":false,\"error\":\"authentication required\"}".utf8))
                return
            }
            guard let config = (try? parentRPC.call(method: "get_onboarding_config_snapshot")) as? [String: Any] else {
                writeResponse(client, status: "503 Service Unavailable", body: Data("{\"ok\":false,\"error\":\"configuration unavailable\",\"retryable\":true}".utf8))
                return
            }
            let peers = (try? parentRPC.call(method: "get_peer_connections_snapshot")) as? [String: Any] ?? [:]
            writeResponse(client, response: ObstacleBridgeAdminOnboardingPort.generate(
                body: body,
                runtimeConfig: config,
                profiles: onboardingConnectionProfiles(peers)
            ))
            return
        case "/api/onboarding/invite/preview" where method == "POST":
            guard security.isAuthenticated(headers: headers) else {
                writeResponse(client, status: "401 Unauthorized", body: Data("{\"ok\":false,\"authenticated\":false,\"error\":\"authentication required\"}".utf8))
                return
            }
            writeResponse(client, response: ObstacleBridgeAdminOnboardingPort.preview(body: body))
            return
        default: break
        }
        guard method == "GET", ["/api/health", "/api/status", "/api/meta", "/api/config", "/api/logs", "/api/connections", "/api/peers", "/api/telemetry", "/api/tun-routing/status", "/api/live"].contains(path) else {
            writeResponse(client, status: "404 Not Found", body: Data("{\"error\":\"not found\"}".utf8))
            return
        }
        guard security.isAuthenticated(headers: headers) else {
            writeResponse(client, status: "401 Unauthorized", body: Data("{\"ok\":false,\"authenticated\":false,\"error\":\"authentication required\"}".utf8))
            return
        }
        if path == "/api/health" {
            writeResponse(client, status: "200 OK", body: Data("{\"ok\":true}".utf8))
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
                "pid": ProcessInfo.processInfo.processIdentifier,
                "uptime_sec": max(0, Int(ProcessInfo.processInfo.systemUptime - startedAt)),
                "admin_web_name": adminWebName,
                "overlay_transport": overlayTransport,
                "dashboard_enabled": dashboardEnabled ?? NSNull(),
                "milestone": "C",
                "build": snapshot["build"] ?? [:],
                "runtime_dependencies": ["ok": true, "missing": [], "install_hint": ""],
            ]
            guard let responseBody = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]) else { return }
            writeResponse(client, status: "200 OK", body: responseBody)
            return
        }
        if path == "/api/telemetry" {
            guard !telemetrySpoolDirectory.isEmpty else {
                writeResponse(client, status: "404 Not Found", body: Data("{\"ok\":false,\"error\":\"telemetry status disabled\"}".utf8))
                return
            }
            let clientSnapshot = try? parentRPC.call(method: "get_telemetry_client_snapshot")
            guard let telemetryClient = clientSnapshot as? [String: Any] else {
                writeResponse(client, status: "503 Service Unavailable", body: Data("{\"ok\":false,\"error\":\"telemetry status unavailable\",\"retryable\":true}".utf8))
                return
            }
            let payload: [String: Any] = ["ok": true, "client": telemetryClient]
            guard let responseBody = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]) else { return }
            writeResponse(client, status: "200 OK", body: responseBody)
            return
        }
        if path == "/api/tun-routing/status" {
            let status = try? parentRPC.call(method: "get_status_snapshot")
            let snapshot = status as? [String: Any] ?? [:]
            let tun = snapshot["tun"] as? [Any] ?? []
            let helper = snapshot["tun_helper"] as? [String: Any] ?? [:]
            let runtime = helper["runtime"] as? [String: Any] ?? [:]
            let control: [String: Any] = [
                "enabled": runtime["included_routes_active"] ?? false,
                "startup_enabled": runtime["included_routes_startup_enabled"] ?? false,
                "supported": runtime["included_routes_toggle_supported"] ?? false,
            ]
            let payload: [String: Any] = [
                "tun": tun,
                "shared_tun": snapshot["shared_tun"] ?? [],
                "tun_helper": helper,
                "tun_control": control,
                "summary": ["tun_total": tun.count],
                "app": "udp-bidirectional-mux",
                "milestone": "C",
            ]
            guard let responseBody = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]) else { return }
            writeResponse(client, status: "200 OK", body: responseBody)
            return
        }
        if path == "/api/live" {
            let topic = liveTopic(target: target)
            let result: Any?
            switch topic {
            case "status": result = try? parentRPC.call(method: "get_status_snapshot")
            case "peers": result = try? parentRPC.call(method: "get_peer_connections_snapshot")
            case "connections": result = try? parentRPC.call(method: "get_connections_snapshot")
            default:
                writeResponse(client, status: "404 Not Found", body: Data("{\"error\":\"not found\"}".utf8))
                return
            }
            guard let payload = result as? [String: Any],
                  let responseBody = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]) else {
                writeResponse(client, status: "503 Service Unavailable", body: Data("{\"error\":\"snapshot unavailable\"}".utf8))
                return
            }
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

    private func onboardingBlueprints(_ snapshot: [String: Any]) -> [[String: Any]] {
        var grouped = [String: [[String: Any]]]()
        for transport in ["udp", "tcp"] {
            guard let rows = snapshot[transport] as? [[String: Any]] else { continue }
            for row in rows {
                guard String(describing: row["state"] ?? "").lowercased() != "listening",
                      let peerID = row["peer_id"].map({ String(describing: $0) }).flatMap({ $0.isEmpty ? nil : $0 }),
                      let localPort = positivePort(row["local_port"]),
                      let destination = endpoint(row["remote_destination"])
                else { continue }
                let blueprint: [String: Any] = [
                    "name": "bp-\(peerID)-\(transport)-\(localPort)",
                    "listen": ["protocol": transport, "bind": "0.0.0.0", "port": localPort],
                    "target": ["protocol": transport, "host": destination.host, "port": destination.port],
                ]
                if !(grouped[peerID] ?? []).contains(where: { ($0["name"] as? String) == blueprint["name"] as? String }) {
                    grouped[peerID, default: []].append(blueprint)
                }
            }
        }
        return grouped.keys.sorted().compactMap { peerID in
            guard let servers = grouped[peerID], !servers.isEmpty else { return nil }
            return ["peer_id": peerID, "own_servers": servers]
        }
    }

    private func onboardingConnectionProfiles(_ snapshot: [String: Any]) -> [[String: Any]] {
        guard let rows = snapshot["peers"] as? [[String: Any]] else { return [] }
        return rows.compactMap { row in
            let transport = String(describing: row["transport"] ?? "").lowercased()
            guard ["udp", "tcp", "quic", "ws", "myudp"].contains(transport) else { return nil }
            let role = String(describing: row["state"] ?? "").lowercased() == "listening" ? "server" : "client"
            let endpoint = endpoint(row[role == "server" ? "listen" : "peer"])
            let identifier = String(describing: row["id"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            var profile: [String: Any] = [
                "id": "live:\(transport):\(identifier)",
                "source": "live",
                "transport": transport == "udp" ? "myudp" : transport,
                "role": role,
                "endpoint_host": endpoint?.host ?? "",
                "endpoint_port": endpoint?.port ?? NSNull(),
                "label": endpoint.map { "\(transport.uppercased()) \(role) \($0.host):\($0.port)" } ?? "\(transport.uppercased()) \(role)",
            ]
            if role == "server" {
                profile["listen_bind"] = endpoint?.host ?? ""
                profile["listen_port"] = endpoint?.port ?? NSNull()
            } else {
                profile["peer_host"] = endpoint?.host ?? ""
                profile["peer_port"] = endpoint?.port ?? NSNull()
            }
            return profile
        }
    }

    private func positivePort(_ value: Any?) -> Int? {
        let port: Int
        if let number = value as? NSNumber { port = number.intValue }
        else if let text = value as? String, let parsed = Int(text) { port = parsed }
        else { return nil }
        return (1...65535).contains(port) ? port : nil
    }

    private func endpoint(_ value: Any?) -> (host: String, port: Int)? {
        let text = String(describing: value ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard let separator = text.lastIndex(of: ":"),
              let port = positivePort(String(text[text.index(after: separator)...]))
        else { return nil }
        let host = String(text[..<separator]).trimmingCharacters(in: CharacterSet(charactersIn: "[] "))
        return host.isEmpty ? nil : (host, port)
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

    private func liveTopic(target: String) -> String {
        guard let query = target.split(separator: "?", maxSplits: 1).dropFirst().first else { return "" }
        for pair in query.split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1)
            if parts.count == 2, parts[0] == "topic" { return String(parts[1]).lowercased() }
        }
        return ""
    }

    private func isControlAuthorized(headers: [String: String]) -> Bool {
        controlToken.isEmpty || headers["authorization"] == "Bearer \(controlToken)"
    }

    private func serveLiveWebSocket(_ client: Int32, target: String, key: String, version: String) {
        guard !key.isEmpty, version == "13" else {
            writeResponse(client, status: "400 Bad Request", body: Data("{\"error\":\"invalid websocket handshake\"}".utf8))
            return
        }
        let accept = Data(Insecure.SHA1.hash(data: Data("\(key)258EAFA5-E914-47DA-95CA-C5AB0DC85B11".utf8))).base64EncodedString()
        let handshake = Data("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: \(accept)\r\n\r\n".utf8)
        guard handshake.withUnsafeBytes({ write(client, $0.baseAddress, handshake.count) == handshake.count }) else { return }
        var topics = Set(Self.liveTopics)
        if let requested = ObstacleBridgeAdminLiveTopicPolicyPort.normalizedTopic(liveTopic(target: target)) {
            topics = Self.liveTopics.contains(requested) ? [requested] : []
        }
        var nextDue: [String: TimeInterval] = [:]
        let intervals = Dictionary(uniqueKeysWithValues: Self.liveTopics.map { ($0, ObstacleBridgeAdminLiveTopicPolicyPort.interval($0)) })
        guard sendLiveJSON(client, value: ["type": "hello", "topics": Array(topics).sorted(), "intervals_sec": intervals]) else { return }
        var receiveBuffer = Data()
        while true {
            let now = ProcessInfo.processInfo.systemUptime
            for topic in topics.sorted() where now >= (nextDue[topic] ?? 0) {
                guard let payload = livePayload(topic: topic),
                      sendLiveJSON(client, value: ["type": topic, "data": payload])
                else { return }
                nextDue[topic] = now + ObstacleBridgeAdminLiveTopicPolicyPort.interval(topic)
            }
            var descriptor = pollfd(fd: client, events: Int16(POLLIN), revents: 0)
            let ready = poll(&descriptor, 1, 250)
            guard ready >= 0 else { return }
            guard ready > 0 else { continue }
            var buffer = [UInt8](repeating: 0, count: 16 * 1024)
            let count = read(client, &buffer, buffer.count)
            guard count > 0 else { return }
            receiveBuffer.append(buffer, count: Int(count))
            while let frame = parseWebSocketFrame(receiveBuffer) {
                receiveBuffer.removeSubrange(0..<frame.consumed)
                guard frame.final else { return }
                switch frame.opcode {
                case 0x1:
                    guard let object = try? JSONSerialization.jsonObject(with: frame.payload) as? [String: Any] else { continue }
                    topics = ObstacleBridgeAdminLiveTopicPolicyPort.topicsForControlMessage(subscribe: object["subscribe"], activeTabs: object["active_tabs"] as? [Any], currentTopics: topics)
                        .intersection(Self.liveTopics)
                    for topic in ObstacleBridgeAdminLiveTopicPolicyPort.parseTopics(object["request"]).sorted() {
                        guard let payload = livePayload(topic: topic),
                              sendLiveJSON(client, value: ["type": topic, "data": payload])
                        else { return }
                        nextDue[topic] = ProcessInfo.processInfo.systemUptime + ObstacleBridgeAdminLiveTopicPolicyPort.interval(topic)
                    }
                case 0x8: _ = sendWebSocketFrame(client, opcode: 0x8, payload: Data()); return
                case 0x9: guard sendWebSocketFrame(client, opcode: 0xA, payload: frame.payload) else { return }
                default: continue
                }
            }
        }
    }

    private func livePayload(topic: String) -> [String: Any]? {
        let method = topic == "status" ? "get_status_snapshot" : topic == "peers" ? "get_peer_connections_snapshot" : topic == "connections" ? "get_connections_snapshot" : ""
        return method.isEmpty ? nil : (try? parentRPC.call(method: method)) as? [String: Any]
    }

    private func sendLiveJSON(_ client: Int32, value: [String: Any]) -> Bool {
        guard let body = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) else { return false }
        return sendWebSocketFrame(client, opcode: 0x1, payload: body)
    }

    private func sendWebSocketFrame(_ client: Int32, opcode: UInt8, payload: Data) -> Bool {
        guard payload.count <= Int(UInt16.max) else { return false }
        var frame = Data([0x80 | opcode])
        if payload.count < 126 { frame.append(UInt8(payload.count)) }
        else { frame.append(126); var length = UInt16(payload.count).bigEndian; frame.append(Data(bytes: &length, count: 2)) }
        frame.append(payload)
        return frame.withUnsafeBytes { write(client, $0.baseAddress, frame.count) == frame.count }
    }

    private func parseWebSocketFrame(_ data: Data) -> WebSocketFrame? {
        guard data.count >= 2 else { return nil }
        let first = data[data.startIndex], second = data[data.startIndex + 1]
        let final = (first & 0x80) != 0, opcode = first & 0x0F
        var index = 2, length = Int(second & 0x7F)
        if length == 126 {
            guard data.count >= index + 2 else { return nil }
            length = (Int(data[data.startIndex + index]) << 8) | Int(data[data.startIndex + index + 1]); index += 2
        } else if length == 127 { return nil }
        guard (second & 0x80) != 0, data.count >= index + 4 else { return nil }
        let mask = Array(data[(data.startIndex + index)..<(data.startIndex + index + 4)]); index += 4
        guard length <= 16 * 1024, data.count >= index + length else { return nil }
        var payload = Array(data[(data.startIndex + index)..<(data.startIndex + index + length)])
        for offset in payload.indices { payload[offset] ^= mask[offset % 4] }
        return .init(opcode: opcode, payload: Data(payload), final: final, consumed: index + length)
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
        case 404: status = "404 Not Found"
        case 405: status = "405 Method Not Allowed"
        case 409: status = "409 Conflict"
        default: status = "500 Internal Server Error"
        }
        let extra = response.headers.map { "\($0.0): \($0.1)\r\n" }.joined()
        var wire = Data("HTTP/1.1 \(status)\r\nContent-Type: \(response.contentType)\r\nContent-Length: \(response.body.count)\r\n\(extra)Connection: close\r\n\r\n".utf8)
        wire.append(response.body)
        _ = wire.withUnsafeBytes { write(client, $0.baseAddress, wire.count) }
    }
}
