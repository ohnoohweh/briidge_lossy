import Dispatch
import Foundation
import Crypto
import ObstacleBridgeCore
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
    private let peersProvider: () -> [(identity: String, snapshot: ObstacleBridgeLinuxPeerSnapshot)]
    private let connectionsProvider: () -> [String: Any]
    private let runtimeHealthProvider: () -> (count: Int, previousClean: Bool?)
    private let runtimeHealthRecordsProvider: () -> [ObstacleBridgeRuntimeHealthRecord]
    private let resourceHealthProvider: () -> [String: Any]
    private let adminConfigurationProvider: () -> [String: Any]
    private let buildInfoProvider: () -> [String: Any]
    private let staticDirectory: URL?
    private let configurationStore: ObstacleBridgeLinuxAdminConfigurationStore?
    private let reconnectHandler: (@Sendable () -> Void)?
    private let secureLinkRekeyHandler: (@Sendable (String) -> [String: Any])?
    private let restartHandler: (@Sendable () -> Void)?
    private let shutdownHandler: (@Sendable () -> Void)?
    private let debugLogsProvider: ((Int) -> [String])?
    private let security: ObstacleBridgeLinuxAdminSecurity
    private let queue = DispatchQueue(label: "org.obstaclebridge.linux.admin")
    private let startedAt = Date()
    private var listener: Int32 = -1
    private var source: DispatchSourceRead?
    public private(set) var port: Int = 0

    public init(runtime: ObstacleBridgeLinuxConfiguredRuntime, adminConfiguration: [String: Any] = [:], configurationStore: ObstacleBridgeLinuxAdminConfigurationStore? = nil, staticDirectory: URL? = nil, reconnectHandler: (@Sendable () -> Void)? = nil, secureLinkRekeyHandler: (@Sendable (String) -> [String: Any])? = nil, restartHandler: (@Sendable () -> Void)? = nil, shutdownHandler: (@Sendable () -> Void)? = nil, debugLogsProvider: ((Int) -> [String])? = nil, buildInfo: [String: Any]? = nil, connectionsProvider: @escaping () -> [String: Any] = { ["tcp": [], "udp": [], "tun": []] }) {
        self.statusProvider = { runtime.status() }
        self.peersProvider = { [("configured-peer", runtime.status().peer)] }
        self.connectionsProvider = connectionsProvider
        self.runtimeHealthProvider = { (0, nil) }
        self.runtimeHealthRecordsProvider = { [] }
        self.resourceHealthProvider = { [:] }
        self.configurationStore = configurationStore; self.adminConfigurationProvider = { configurationStore?.snapshot() ?? adminConfiguration }
        self.security = Self.makeSecurity(adminConfiguration: adminConfiguration, configurationStore: configurationStore)
        self.buildInfoProvider = { buildInfo ?? ["available": false] }
        self.staticDirectory = staticDirectory
        self.reconnectHandler = reconnectHandler
        self.secureLinkRekeyHandler = secureLinkRekeyHandler
        self.restartHandler = restartHandler
        self.shutdownHandler = shutdownHandler
        self.debugLogsProvider = debugLogsProvider
    }

    public init(liveRuntime: ObstacleBridgeLinuxLiveRuntime, adminConfiguration: [String: Any] = [:], configurationStore: ObstacleBridgeLinuxAdminConfigurationStore? = nil, staticDirectory: URL? = nil, reconnectHandler: (@Sendable () -> Void)? = nil, secureLinkRekeyHandler: (@Sendable (String) -> [String: Any])? = nil, restartHandler: (@Sendable () -> Void)? = nil, shutdownHandler: (@Sendable () -> Void)? = nil, debugLogsProvider: ((Int) -> [String])? = nil, buildInfo: [String: Any]? = nil) {
        self.statusProvider = { liveRuntime.status() }
        self.peersProvider = { [("configured-peer", liveRuntime.status().peer)] }
        self.connectionsProvider = { liveRuntime.connectionsForAdmin() }
        self.runtimeHealthProvider = { liveRuntime.runtimeHealthMetadataForAdmin() }
        self.runtimeHealthRecordsProvider = { liveRuntime.runtimeHealthRecentRecordsForAdmin() }
        self.resourceHealthProvider = { liveRuntime.resourceHealthForAdmin() }
        self.configurationStore = configurationStore; self.adminConfigurationProvider = { configurationStore?.snapshot() ?? adminConfiguration }
        self.security = Self.makeSecurity(adminConfiguration: adminConfiguration, configurationStore: configurationStore)
        self.buildInfoProvider = { buildInfo ?? ["available": false] }
        self.staticDirectory = staticDirectory
        self.reconnectHandler = reconnectHandler
        self.secureLinkRekeyHandler = secureLinkRekeyHandler
        self.restartHandler = restartHandler
        self.shutdownHandler = shutdownHandler
        self.debugLogsProvider = debugLogsProvider
    }

    public init(myudpListenerRuntime: ObstacleBridgeLinuxMyUDPListenerRuntime, adminConfiguration: [String: Any] = [:], configurationStore: ObstacleBridgeLinuxAdminConfigurationStore? = nil, staticDirectory: URL? = nil, reconnectHandler: (@Sendable () -> Void)? = nil, secureLinkRekeyHandler: (@Sendable (String) -> [String: Any])? = nil, restartHandler: (@Sendable () -> Void)? = nil, shutdownHandler: (@Sendable () -> Void)? = nil, debugLogsProvider: ((Int) -> [String])? = nil, buildInfo: [String: Any]? = nil) {
        self.statusProvider = { myudpListenerRuntime.status() }
        self.peersProvider = {
            myudpListenerRuntime.peers().map { ($0.identity, $0.snapshot) }
        }
        self.connectionsProvider = { ["tcp": [], "udp": [], "tun": []] }
        self.runtimeHealthProvider = { (0, nil) }
        self.runtimeHealthRecordsProvider = { [] }
        self.resourceHealthProvider = { [:] }
        self.configurationStore = configurationStore; self.adminConfigurationProvider = { configurationStore?.snapshot() ?? adminConfiguration }
        self.security = Self.makeSecurity(adminConfiguration: adminConfiguration, configurationStore: configurationStore)
        self.buildInfoProvider = { buildInfo ?? ["available": false] }
        self.staticDirectory = staticDirectory
        self.reconnectHandler = reconnectHandler
        self.secureLinkRekeyHandler = secureLinkRekeyHandler
        self.restartHandler = restartHandler
        self.shutdownHandler = shutdownHandler
        self.debugLogsProvider = debugLogsProvider
    }

    private static func makeSecurity(
        adminConfiguration: [String: Any],
        configurationStore: ObstacleBridgeLinuxAdminConfigurationStore?
    ) -> ObstacleBridgeLinuxAdminSecurity {
        let runtimeConfiguration: () -> [String: Any] = {
            (try? configurationStore?.runtimeSnapshot()) ?? adminConfiguration
        }
        return ObstacleBridgeLinuxAdminSecurity(
            credentials: {
                let flat = ObstacleBridgeRuntimeConfigPort.flatten(runtimeConfiguration())
                let authDisabled = (flat["admin_web_auth_disable"] as? Bool) ?? false
                let username = flat["admin_web_username"] as? String ?? ""
                let password = flat["admin_web_password"] as? String ?? ""
                return (!authDisabled && !username.isEmpty && !password.isEmpty, username, password)
            },
            scope: {
                let flat = ObstacleBridgeRuntimeConfigPort.flatten(runtimeConfiguration())
                return [
                    flat["admin_web_bind"] as? String ?? "",
                    String(flat["admin_web_port"] as? Int ?? 0),
                    flat["admin_web_path"] as? String ?? "",
                ].joined(separator: "|")
            }
        )
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
        guard let headerEnd = request.range(of: Data("\r\n\r\n".utf8)) else { return }
        let headerData = request[..<headerEnd.lowerBound]
        let headerText = String(data: headerData, encoding: .utf8) ?? ""
        let headers = headerText.split(separator: "\r\n").dropFirst().reduce(into: [String: String]()) { headers, line in
            let parts = line.split(separator: ":", maxSplits: 1)
            guard parts.count == 2 else { return }
            headers[parts[0].trimmingCharacters(in: .whitespaces).lowercased()] = parts[1].trimmingCharacters(in: .whitespaces)
        }
        let contentLength = headers["content-length"].flatMap(Int.init) ?? 0
        guard (0...65_536).contains(contentLength) else { return }
        let bodyStart = headerEnd.upperBound
        while request.count - bodyStart < contentLength {
            let received = read(client, &buffer, buffer.count); guard received > 0 else { return }; request.append(buffer, count: Int(received))
        }
        let body = Data(request[bodyStart..<(bodyStart + contentLength)])
        let requestLine = headerText.split(separator: "\r\n", maxSplits: 1).first ?? ""
        let parts = requestLine.split(separator: " ")
        let method = parts.first.map(String.init) ?? ""
        let target = parts.dropFirst().first.map(String.init) ?? ""
        let path = target.split(separator: "?", maxSplits: 1).first.map(String.init) ?? target
        if path == "/api/live", method == "GET", headerText.lowercased().contains("upgrade: websocket") {
            guard security.isAuthenticated(headers: headers) else {
                writeResponse(client, response: jsonResponse(["ok": false, "authenticated": false, "error": "authentication required"], statusCode: 401))
                return
            }
            serveLiveWebSocket(client, target: target, headerText: headerText)
            return
        }
        let response: ObstacleBridgeAdminLinuxResponse
        var controlAction: (@Sendable () -> Void)?
        let authenticationRoutes: Set<String> = ["/api/auth/state", "/api/auth/challenge", "/api/auth/login", "/api/auth/logout", "/api/config/challenge", "/api/config/secret/secure-link-psk/challenge"]
        if path.hasPrefix("/api/"), !authenticationRoutes.contains(path), !security.isAuthenticated(headers: headers) {
            response = jsonResponse(["ok": false, "authenticated": false, "error": "authentication required"], statusCode: 401)
        } else if method != "GET" && !(method == "POST" && ["/api/auth/login", "/api/auth/logout", "/api/config", "/api/config/challenge", "/api/config/secret/secure-link-psk/challenge", "/api/config/secret/secure-link-psk", "/api/onboarding/invite", "/api/onboarding/preview", "/api/onboarding/invite/generate", "/api/onboarding/invite/preview", "/api/restart", "/api/reconnect", "/api/secure-link/rekey", "/api/secure-link/reload", "/api/shutdown"].contains(path)) {
            response = .init(statusCode: 405, body: Data("{\"error\":\"method not allowed\"}".utf8))
        } else { switch path {
        case "/", "/index.html":
            response = staticResponse(path) ?? .init(statusCode: 200, body: Data(adminDashboard.utf8), contentType: "text/html; charset=utf-8")
        case "/api/status": response = ObstacleBridgeAdminAPI.linuxJSONResponse(statusPayload()) ?? .init(statusCode: 500, body: Data("{}".utf8))
        case "/api/logs":
            let limit = Int(target.split(separator: "?", maxSplits: 1).dropFirst().first?
                .split(separator: "&").first(where: { $0.hasPrefix("limit=") })?
                .dropFirst("limit=".count) ?? "400") ?? 400
            let lines = debugLogsProvider?(max(1, min(limit, 10_000))) ?? []
            response = ObstacleBridgeAdminAPI.linuxJSONResponse(["ok": true, "lines": lines, "count": lines.count, "source": "linux-swift", "logger_available": debugLogsProvider != nil, "logger_error": debugLogsProvider == nil ? "native observability unavailable" : ""]) ?? .init(statusCode: 500, body: Data("{}".utf8))
        case "/api/peers": response = ObstacleBridgeAdminAPI.linuxJSONResponse(["peers": peersPayload()]) ?? .init(statusCode: 500, body: Data("{}".utf8))
        case "/api/connections": response = ObstacleBridgeAdminAPI.linuxJSONResponse(connectionsProvider()) ?? .init(statusCode: 500, body: Data("{}".utf8))
        case "/api/meta": response = ObstacleBridgeAdminAPI.linuxJSONResponse(metaPayload()) ?? .init(statusCode: 500, body: Data("{}".utf8))
        case "/api/live":
            let requestedTopic = target.split(separator: "?", maxSplits: 1).dropFirst().first?
                .split(separator: "&").first(where: { $0.hasPrefix("topic=") })?
                .dropFirst("topic=".count).description ?? ""
            let topic = ObstacleBridgeAdminLiveTopicPolicyPort.normalizedTopic(requestedTopic) ?? ""
            response = ObstacleBridgeAdminLiveTopicPort.payload(topic: topic, status: statusPayload(), peers: peersPayload(), connections: connectionsProvider())
                .flatMap { ObstacleBridgeAdminAPI.linuxJSONResponse($0) } ?? .init(statusCode: 404, body: Data("{}".utf8))
        case "/api/auth/state":
            response = jsonResponse(security.state(headers: headers))
        case "/api/auth/challenge":
            response = method == "GET" ? jsonResponse(security.issueLoginChallenge()) : jsonResponse(["error": "method not allowed"], statusCode: 405)
        case "/api/auth/login":
            response = method == "POST" ? security.login(body: body) : jsonResponse(["error": "method not allowed"], statusCode: 405)
        case "/api/auth/logout":
            response = method == "POST" ? security.logout(headers: headers) : jsonResponse(["error": "method not allowed"], statusCode: 405)
        case "/api/config":
            if method == "GET" {
                response = ObstacleBridgeAdminAPI.linuxJSONResponse(configSnapshotPayload()) ?? .init(statusCode: 500, body: Data("{}".utf8))
            } else if let updates = (try? JSONSerialization.jsonObject(with: body) as? [String: Any])?["updates"] as? [String: Any], let configurationStore {
                let authRequired = security.state(headers: headers)["auth_required"] as? Bool ?? false
                if authRequired, body.isEmpty || ((try? JSONSerialization.jsonObject(with: body) as? [String: Any])?["challenge_id"] as? String ?? "").isEmpty || ((try? JSONSerialization.jsonObject(with: body) as? [String: Any])?["proof"] as? String ?? "").isEmpty {
                    response = jsonResponse(["ok": false, "error": "configuration change confirmation required"], statusCode: 428)
                } else if authRequired, let error = security.validateConfigChallenge(body: body) {
                    response = jsonResponse(["ok": false, "error": error], statusCode: 403)
                } else { do {
                    let saved = try configurationStore.apply(updates: updates)
                    if updates.keys.contains(where: { ["admin_web_auth_disable", "admin_web_username", "admin_web_password", "secure_link_psk"].contains($0) }) { security.reset() }
                    response = ObstacleBridgeAdminAPI.linuxJSONResponse([
                        "ok": true,
                        "updated_keys": saved.normalizedKeys,
                        "config": ObstacleBridgeRuntimeConfigPort.redactedConfiguration(ObstacleBridgeRuntimeConfigPort.flatten(saved.configuration)),
                        "schema": ObstacleBridgeLinuxAdminConfigurationStore.schemaSnapshot(),
                    ]) ?? .init(statusCode: 500, body: Data("{}".utf8))
                }
                catch { response = ObstacleBridgeAdminAPI.linuxJSONResponse(["ok": false, "error": error.localizedDescription], statusCode: 400) ?? .init(statusCode: 500, body: Data("{}".utf8)) } }
            } else { response = ObstacleBridgeAdminAPI.linuxJSONResponse(["ok": false, "error": "invalid JSON body or configuration writes unavailable"], statusCode: 400) ?? .init(statusCode: 500, body: Data("{}".utf8)) }
        case "/api/config/challenge":
            let authRequired = security.state(headers: headers)["auth_required"] as? Bool ?? false
            if method != "POST" { response = jsonResponse(["error": "method not allowed"], statusCode: 405) }
            else if !authRequired { response = jsonResponse(["ok": true, "auth_required": false]) }
            else if !security.isAuthenticated(headers: headers) { response = jsonResponse(["ok": false, "authenticated": false, "error": "authentication required"], statusCode: 401) }
            else if let updates = (try? JSONSerialization.jsonObject(with: body) as? [String: Any])?["updates"] as? [String: Any] {
                do { response = jsonResponse(try security.issueConfigChallenge(updates: updates)) }
                catch { response = jsonResponse(["ok": false, "error": "updates must be an object"], statusCode: 400) }
            } else { response = jsonResponse(["ok": false, "error": "updates must be an object"], statusCode: 400) }
        case "/api/config/secret/secure-link-psk/challenge":
            let authRequired = security.state(headers: headers)["auth_required"] as? Bool ?? false
            if method != "POST" { response = jsonResponse(["error": "method not allowed"], statusCode: 405) }
            else if !authRequired { response = jsonResponse(["ok": false, "error": "admin password authentication is required to reveal secure_link_psk"], statusCode: 403) }
            else if !security.isAuthenticated(headers: headers) { response = jsonResponse(["ok": false, "authenticated": false, "error": "authentication required"], statusCode: 401) }
            else { response = jsonResponse(security.issueSecretRevealChallenge(secretName: "secure_link_psk")) }
        case "/api/config/secret/secure-link-psk":
            if method != "POST" { response = jsonResponse(["error": "method not allowed"], statusCode: 405) }
            else {
                let flat = ObstacleBridgeRuntimeConfigPort.flatten((try? configurationStore?.runtimeSnapshot()) ?? adminConfigurationProvider())
                response = security.revealSecret(body: body, secretName: "secure_link_psk", secretValue: flat["secure_link_psk"] as? String ?? "")
            }
        case "/api/reconnect":
            guard let reconnectHandler else {
                response = ObstacleBridgeAdminAPI.linuxJSONResponse(["ok": false, "error": "reconnect is unavailable for this runtime"], statusCode: 409) ?? .init(statusCode: 500, body: Data("{}".utf8))
                break
            }
            controlAction = reconnectHandler
            response = ObstacleBridgeAdminAPI.linuxJSONResponse(["ok": true, "reconnect_requested": true]) ?? .init(statusCode: 500, body: Data("{}".utf8))
        case "/api/restart":
            guard let restartHandler else {
                response = jsonResponse(["ok": false, "error": "restart is unavailable for this runtime"], statusCode: 409)
                break
            }
            controlAction = restartHandler
            response = jsonResponse(["ok": true, "restarting": true, "restart_embedded": false, "restart_mode": "immediate", "restart_delay_sec": 0])
        case "/api/secure-link/rekey":
            guard let secureLinkRekeyHandler else {
                response = jsonResponse(["ok": false, "reason": "runtime_unavailable"], statusCode: 409)
                break
            }
            guard let payload = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
                response = jsonResponse(["ok": false, "error": "invalid JSON body"], statusCode: 400)
                break
            }
            let peerID = (payload["peer_id"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            guard !peerID.isEmpty else {
                response = jsonResponse(["ok": false, "error": "peer_id is required"], statusCode: 400)
                break
            }
            let result = secureLinkRekeyHandler(peerID)
            response = jsonResponse(result, statusCode: (result["ok"] as? Bool) == true ? 200 : 409)
        case "/api/secure-link/reload":
            guard let payload = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
                response = jsonResponse(["ok": false, "error": "invalid JSON body"], statusCode: 400)
                break
            }
            let scope = (payload["scope"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard ["revocation", "local_identity", "all"].contains(scope) else {
                response = jsonResponse(["ok": false, "error": "scope must be one of revocation, local_identity, all"], statusCode: 400)
                break
            }
            let peerID = (payload["peer_id"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            response = jsonResponse([
                "ok": false, "scope": scope, "target_peer_id": peerID.isEmpty ? NSNull() : peerID,
                "requested": 1, "reloaded": 0, "dropped": 0, "failed": 1,
                "results": [["transport": statusProvider().transport, "peer_ids": ["configured-peer"], "ok": false, "reason": "secure_link_cert_mode_required"]],
            ], statusCode: 409)
        case "/api/shutdown":
            guard let shutdownHandler else {
                response = ObstacleBridgeAdminAPI.linuxJSONResponse(["ok": false, "error": "shutdown is unavailable for this runtime"], statusCode: 409) ?? .init(statusCode: 500, body: Data("{}".utf8))
                break
            }
            controlAction = shutdownHandler
            response = ObstacleBridgeAdminAPI.linuxJSONResponse(["ok": true, "shutdown_requested": true]) ?? .init(statusCode: 500, body: Data("{}".utf8))
        case "/api/onboarding/connection-profiles":
            let profiles = ObstacleBridgeAdminOnboardingPort.connectionProfiles(runtimeConfig: adminConfigurationProvider())
            response = ObstacleBridgeAdminAPI.linuxJSONResponse(["ok": true, "count": profiles.count, "profiles": profiles]) ?? .init(statusCode: 500, body: Data("{}".utf8))
        case "/api/onboarding/blueprints":
            let blueprints = ObstacleBridgeAdminOnboardingPort.blueprints(connections: connectionsProvider())
            response = ObstacleBridgeAdminAPI.linuxJSONResponse(["ok": true, "count": blueprints.count, "blueprints": blueprints]) ?? .init(statusCode: 500, body: Data("{}".utf8))
        case "/api/onboarding/invite", "/api/onboarding/invite/generate":
            do {
                let runtimeConfiguration = try configurationStore?.runtimeSnapshot() ?? adminConfigurationProvider()
                response = ObstacleBridgeAdminOnboardingPort.generate(body: body, runtimeConfig: runtimeConfiguration)
            } catch {
                response = ObstacleBridgeAdminAPI.linuxJSONResponse(["ok": false, "error": error.localizedDescription], statusCode: 400) ?? .init(statusCode: 500, body: Data("{}".utf8))
            }
        case "/api/onboarding/preview", "/api/onboarding/invite/preview":
            response = ObstacleBridgeAdminOnboardingPort.preview(body: body)
        case "/api/admin-ui":
            response = ObstacleBridgeAdminAPI.linuxJSONResponse(ObstacleBridgeAdminWebPort.uiPayload(runtimeConfig: adminConfigurationProvider(), platform: "linux-swift")) ?? .init(statusCode: 500, body: Data("{}".utf8))
        case "/api/security-advisor":
            response = ObstacleBridgeAdminAPI.linuxJSONResponse(ObstacleBridgeAdminWebPort.securityAdvisorPayload(runtimeConfig: adminConfigurationProvider(), bindHostFallback: "127.0.0.1")) ?? .init(statusCode: 500, body: Data("{}".utf8))
        default:
            if method == "GET", let staticAsset = staticResponse(path) { response = staticAsset }
            else { response = ObstacleBridgeAdminAPI.linuxJSONResponse(["error": "not found"], statusCode: 404) ?? .init(statusCode: 404, body: Data("{}".utf8)) }
        } }
        writeResponse(client, response: response)
        if let controlAction { DispatchQueue.global(qos: .userInitiated).async(execute: controlAction) }
    }

    private func jsonResponse(_ payload: [String: Any], statusCode: Int = 200) -> ObstacleBridgeAdminLinuxResponse {
        ObstacleBridgeAdminAPI.linuxJSONResponse(payload, statusCode: statusCode) ?? .init(statusCode: 500, body: Data("{}".utf8))
    }

    private func writeResponse(_ client: Int32, response: ObstacleBridgeAdminLinuxResponse) {
        let statusText: String
        switch response.statusCode {
        case 200: statusText = "200 OK"
        case 400: statusText = "400 Bad Request"
        case 401: statusText = "401 Unauthorized"
        case 403: statusText = "403 Forbidden"
        case 404: statusText = "404 Not Found"
        case 405: statusText = "405 Method Not Allowed"
        case 409: statusText = "409 Conflict"
        case 428: statusText = "428 Precondition Required"
        default: statusText = "500 Internal Server Error"
        }
        let extraHeaders = response.headers.map { "\($0.0): \($0.1)\r\n" }.joined()
        let header = "HTTP/1.1 \(statusText)\r\nContent-Type: \(response.contentType)\r\nContent-Length: \(response.body.count)\r\n\(extraHeaders)Connection: close\r\n\r\n"
        var wire = Data(header.utf8)
        wire.append(response.body)
        _ = wire.withUnsafeBytes { write(client, $0.baseAddress, wire.count) }
    }

    private var adminDashboard: String {
        """
        <!doctype html><html><head><meta charset="utf-8"><title>ObstacleBridge Linux</title><style>body{font-family:system-ui;margin:2rem;max-width:72rem}pre{background:#111;color:#ddd;padding:1rem;overflow:auto}a{margin-right:1rem}</style></head><body><h1>ObstacleBridge Linux</h1><p>Native runtime Admin dashboard.</p><p><a href="/api/status">Status JSON</a><a href="/api/peers">Peers JSON</a><a href="/api/config">Redacted config</a></p><pre id="status">Loading…</pre><script>const view=document.getElementById('status');async function refresh(){try{view.textContent=JSON.stringify(await (await fetch('/api/status')).json(),null,2)}catch(e){view.textContent='Admin status unavailable: '+e}}refresh();setInterval(refresh,1000)</script></body></html>
        """
    }

    private func staticResponse(_ requestPath: String) -> ObstacleBridgeAdminLinuxResponse? {
        guard let base = resolvedStaticDirectory() else { return nil }
        let relative = (requestPath.isEmpty || requestPath == "/") ? "index.html" : String(requestPath.drop(while: { $0 == "/" }))
        guard !relative.contains("..") else { return .init(statusCode: 404, body: Data("not found".utf8), contentType: "text/plain; charset=utf-8") }
        let file = base.appendingPathComponent(relative).standardizedFileURL
        guard file.path.hasPrefix(base.standardizedFileURL.path + "/"), let body = try? Data(contentsOf: file) else { return nil }
        let contentType: String
        switch file.pathExtension.lowercased() {
        case "html": contentType = "text/html; charset=utf-8"
        case "css": contentType = "text/css; charset=utf-8"
        case "js": contentType = "application/javascript; charset=utf-8"
        case "json": contentType = "application/json; charset=utf-8"
        case "svg": contentType = "image/svg+xml"
        case "png": contentType = "image/png"
        default: contentType = "application/octet-stream"
        }
        return .init(statusCode: 200, body: body, contentType: contentType)
    }

    private func resolvedStaticDirectory() -> URL? {
        let manager = FileManager.default
        let candidates = [staticDirectory, URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent("admin_web"), CommandLine.arguments.first.map { URL(fileURLWithPath: $0).deletingLastPathComponent().appendingPathComponent("admin_web") }].compactMap { $0 }
        return candidates.first { manager.fileExists(atPath: $0.appendingPathComponent("index.html").path) }
    }

    private struct LinuxWebSocketFrame {
        let opcode: UInt8
        let payload: Data
        let final: Bool
        let consumed: Int
    }

    /// A reconnectable, snapshot-first WebSocket subscription. The Linux
    /// socket owner intentionally keeps protocol framing local while Core
    /// decides topic admission and payload shape.
    private func serveLiveWebSocket(_ client: Int32, target: String, headerText: String) {
        guard let key = headerText.split(separator: "\r\n").first(where: { $0.lowercased().hasPrefix("sec-websocket-key:") })?
            .split(separator: ":", maxSplits: 1).dropFirst().first?.trimmingCharacters(in: .whitespaces)
        else {
            let wire = Data("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n".utf8)
            _ = wire.withUnsafeBytes { write(client, $0.baseAddress, wire.count) }
            return
        }
        let accept = Data(Insecure.SHA1.hash(data: Data("\(key)258EAFA5-E914-47DA-95CA-C5AB0DC85B11".utf8))).base64EncodedString()
        let handshake = Data("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: \(accept)\r\n\r\n".utf8)
        _ = handshake.withUnsafeBytes { write(client, $0.baseAddress, handshake.count) }
        var topics = Set(ObstacleBridgeAdminLiveTopicPolicyPort.allTopics)
        var nextDue: [String: TimeInterval] = [:]
        var intervals: [String: Any] = [:]
        for topic in ObstacleBridgeAdminLiveTopicPolicyPort.allTopics {
            intervals[topic] = ObstacleBridgeAdminLiveTopicPolicyPort.interval(topic)
        }
        guard sendLiveJSON(client, value: ["type": "hello", "topics": Array(topics).sorted(), "intervals_sec": intervals]) else { return }
        let initialTopic = target.split(separator: "?", maxSplits: 1).dropFirst().first?
            .split(separator: "&").first(where: { $0.hasPrefix("topic=") })?
            .dropFirst("topic=".count).description
        if let initialTopic, let topic = ObstacleBridgeAdminLiveTopicPolicyPort.normalizedTopic(initialTopic) {
            topics = [topic]
        }
        var receiveBuffer = Data()
        while true {
            let now = ProcessInfo.processInfo.systemUptime
            for topic in topics.sorted() where now >= (nextDue[topic] ?? 0) {
                if let payload = ObstacleBridgeAdminLiveTopicPort.payload(topic: topic, status: statusPayload(), peers: peersPayload(), connections: connectionsProvider()) {
                    guard sendLiveJSON(client, value: ["type": topic, "data": payload]) else { return }
                }
                nextDue[topic] = now + ObstacleBridgeAdminLiveTopicPolicyPort.interval(topic)
            }
            var descriptor = pollfd(fd: client, events: Int16(POLLIN), revents: 0)
            let ready = poll(&descriptor, 1, 250)
            guard ready >= 0 else { return }
            guard ready > 0 else { continue }
            var buffer = [UInt8](repeating: 0, count: 16 * 1024)
            let received = read(client, &buffer, buffer.count)
            guard received > 0 else { return }
            receiveBuffer.append(buffer, count: Int(received))
            while let frame = parseLiveWebSocketFrame(receiveBuffer) {
                receiveBuffer.removeSubrange(0..<frame.consumed)
                guard frame.final else { return }
                switch frame.opcode {
                case 0x1:
                    guard let object = try? JSONSerialization.jsonObject(with: frame.payload) as? [String: Any] else { continue }
                    topics = ObstacleBridgeAdminLiveTopicPolicyPort.topicsForControlMessage(
                        subscribe: object["subscribe"], activeTabs: object["active_tabs"] as? [Any], currentTopics: topics
                    )
                    let requested = ObstacleBridgeAdminLiveTopicPolicyPort.parseTopics(object["request"])
                    for topic in requested.sorted() {
                        if let payload = ObstacleBridgeAdminLiveTopicPort.payload(topic: topic, status: statusPayload(), peers: peersPayload(), connections: connectionsProvider()) {
                            guard sendLiveJSON(client, value: ["type": topic, "data": payload]) else { return }
                        }
                        nextDue[topic] = ProcessInfo.processInfo.systemUptime + ObstacleBridgeAdminLiveTopicPolicyPort.interval(topic)
                    }
                case 0x8:
                    _ = sendLiveFrame(client, opcode: 0x8, payload: Data())
                    return
                case 0x9:
                    guard sendLiveFrame(client, opcode: 0xA, payload: frame.payload) else { return }
                default:
                    continue
                }
            }
        }
    }

    private func sendLiveJSON(_ client: Int32, value: [String: Any]) -> Bool {
        guard let body = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) else { return false }
        return sendLiveFrame(client, opcode: 0x1, payload: body)
    }

    private func sendLiveFrame(_ client: Int32, opcode: UInt8, payload: Data) -> Bool {
        guard payload.count <= Int(UInt16.max) else { return false }
        var frame = Data([0x80 | opcode])
        if payload.count < 126 { frame.append(UInt8(payload.count)) }
        else { frame.append(126); var length = UInt16(payload.count).bigEndian; frame.append(Data(bytes: &length, count: 2)) }
        frame.append(payload)
        return frame.withUnsafeBytes { write(client, $0.baseAddress, frame.count) == frame.count }
    }

    private func parseLiveWebSocketFrame(_ data: Data) -> LinuxWebSocketFrame? {
        guard data.count >= 2 else { return nil }
        let first = data[data.startIndex], second = data[data.startIndex + 1]
        let final = (first & 0x80) != 0, opcode = first & 0x0F
        var index = 2, length = Int(second & 0x7F)
        if length == 126 {
            guard data.count >= index + 2 else { return nil }
            length = (Int(data[data.startIndex + index]) << 8) | Int(data[data.startIndex + index + 1]); index += 2
        } else if length == 127 { return nil }
        let masked = (second & 0x80) != 0
        var mask: [UInt8] = []
        if masked {
            guard data.count >= index + 4 else { return nil }
            mask = Array(data[(data.startIndex + index)..<(data.startIndex + index + 4)]); index += 4
        }
        guard length <= 16 * 1024, data.count >= index + length else { return nil }
        var payload = Data(data[(data.startIndex + index)..<(data.startIndex + index + length)])
        if masked {
            var bytes = Array(payload)
            for offset in bytes.indices { bytes[offset] ^= mask[offset % 4] }
            payload = Data(bytes)
        }
        return .init(opcode: opcode, payload: payload, final: final, consumed: index + length)
    }

    /// Matches the Python Admin API: values are flattened for form fields,
    /// while schema retains its section grouping for rendering.
    private func configSnapshotPayload() -> [String: Any] {
        let flattened = ObstacleBridgeRuntimeConfigPort.flatten(adminConfigurationProvider())
        return [
            "ok": true,
            "config": ObstacleBridgeRuntimeConfigPort.redactedConfiguration(flattened),
            "schema": ObstacleBridgeLinuxAdminConfigurationStore.schemaSnapshot(),
        ]
    }

    private func metaPayload() -> [String: Any] {
        let configuration = ObstacleBridgeRuntimeConfigPort.flatten(adminConfigurationProvider())
        return [
            "app": "ObstacleBridgeLinux",
            "pid": ProcessInfo.processInfo.processIdentifier,
            "uptime_sec": max(0, Int(Date().timeIntervalSince(startedAt))),
            "admin_web_name": configuration["admin_web_name"] as? String ?? "",
            "overlay_transport": statusProvider().transport,
            "dashboard_enabled": true,
            "milestone": "C",
            "build": buildInfoProvider(),
            "runtime_dependencies": ["ok": true, "missing": [], "install_hint": ""],
        ]
    }

    private func statusPayload() -> [String: Any] {
        let status = statusProvider()
        let health = runtimeHealthProvider()
        let healthRecords = runtimeHealthRecordsProvider().compactMap { record -> [String: Any]? in
            guard let data = try? JSONEncoder().encode(record) else { return nil }
            return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        }
        let transportRuntime = ObstacleBridgeAdminSnapshotSupport.transportRuntimeEnvelope(
            kind: status.transport,
            status: status.state,
            extra: ["app_ready": status.appReady, "failure_reason": status.failureReason as Any]
        )
        let payload: [String: Any] = [
            "platform": "linux-swift",
            "overlay_transport": status.transport,
            "transport_state": status.state,
            "app_ready": status.appReady,
            "failure_reason": status.failureReason as Any,
            "transport_runtime": transportRuntime,
            "runtime_health_record_count": health.count,
            "previous_runtime_lifetime_ended_cleanly": health.previousClean as Any,
            "runtime_health_recent_records": healthRecords,
            "resource_health": resourceHealthProvider(),
            "operator_capabilities": operatorCapabilities(),
            "connection_layers": [
                ["name": "transport", "state": status.state, "connected": status.state == "connected"],
                ["name": "secure_link", "state": status.secureLinkState, "authenticated": status.secureLinkState == "authenticated"],
            ],
            "channel_mux": [
                "tcp_open": status.activeTCPChannels,
                "udp_open": status.activeUDPChannels,
                "queued_frames": status.queuedServiceFrames,
                "dropped_frames": status.droppedServiceFrames,
                "malformed_frames": status.malformedServiceFrames,
                "service_failures": status.serviceFailures,
                "tcp_opened_total": status.openedTCPChannels,
                "udp_opened_total": status.openedUDPChannels,
            ],
            "receive_loop": [
                "state": status.receiveLoopState,
                "connection_epoch": status.receiveEpoch,
                "received_frames": status.receivedFrames,
                "dropped_frames": status.droppedReceiveFrames,
                "queue_depth": status.receiveQueueDepth,
                "failure_reason": status.receiveFailureReason as Any,
            ],
            "peer": peerPayload(status.peer),
            "build": buildInfoProvider(),
        ]
        return payload
    }

    /// Host facts and actionable guidance for the Linux resource boundaries.
    /// This exposes neither configured endpoints nor credentials.
    private func operatorCapabilities() -> [String: Any] {
        let manager = FileManager.default
        let tunPresent = manager.fileExists(atPath: "/dev/net/tun")
        let effectiveCapabilities = (try? String(contentsOfFile: "/proc/self/status", encoding: .utf8))?
            .split(separator: "\n").first(where: { $0.hasPrefix("CapEff:") })?
            .split(separator: "\t").last.flatMap { UInt64($0, radix: 16) } ?? 0
        let netAdmin = effectiveCapabilities & (UInt64(1) << 12) != 0
        let ipAvailable = ["/usr/sbin/ip", "/sbin/ip"].contains { manager.isExecutableFile(atPath: $0) }
        let resolvectlAvailable = ["/usr/bin/resolvectl", "/bin/resolvectl"].contains { manager.isExecutableFile(atPath: $0) }
        let firewallAvailable = ["/usr/sbin/iptables", "/sbin/iptables"].contains { manager.isExecutableFile(atPath: $0) }
        var guidance: [String] = []
        if !tunPresent { guidance.append("/dev/net/tun is unavailable") }
        if !netAdmin { guidance.append("grant CAP_NET_ADMIN to the helper process or launch it through an authorized supervisor") }
        if !ipAvailable { guidance.append("install iproute2 for address and route policy") }
        if !resolvectlAvailable { guidance.append("install systemd-resolved/resolvectl before configuring helper-owned DNS") }
        return [
            "tun_device_present": tunPresent, "net_admin_effective": netAdmin,
            "ip_available": ipAvailable, "resolvectl_available": resolvectlAvailable,
            "iptables_available": firewallAvailable, "privileged_tun_ready": tunPresent && netAdmin && ipAvailable,
            "guidance": guidance,
        ]
    }

    private func peersPayload() -> [[String: Any]] {
        let status = statusProvider()
        return peersProvider().map { row in
            var peer = peerPayload(row.snapshot, identity: row.identity)
            peer["configured_candidates"] = status.configuredCandidates
            peer["active_host"] = status.activeHost as Any
            peer["port"] = status.port
            peer["failure_reason"] = status.failureReason as Any
            return peer
        }
    }

    /// Serialize the one Core/adapter-derived peer projection. Do not read
    /// configuration secrets or construct protocol counters in this HTTP
    /// adapter: all SecureLink fields arrive through `status.peer`.
    private func peerPayload(_ peer: ObstacleBridgeLinuxPeerSnapshot, identity: String = "configured-peer") -> [String: Any] {
        [
            "peer_id": identity,
            "transport": peer.transport,
            "state": peer.lifecycleState,
            "connection_epoch": peer.connectionEpoch,
            "app_ready": peer.ready,
            "secure_link": [
                "state": peer.secureLinkState,
                "authenticated": peer.authenticated,
                "session_id": peer.sessionID ?? NSNull(),
                "pending_rekey_session_id": peer.pendingRekeySessionID ?? NSNull(),
                "application_sending_blocked": peer.applicationSendingBlocked,
                "attempts": peer.attempts,
                "next_retry_milliseconds": peer.nextRetryMilliseconds ?? NSNull(),
                "protected_tx_counter": peer.protectedTxCounter,
                "protected_rx_counter": peer.protectedRxCounter,
                "protected_frames_sent_total": peer.protectedFramesSentTotal,
                "protected_frames_received_total": peer.protectedFramesReceivedTotal,
                "authenticated_generations_total": peer.authenticatedGenerationsTotal,
                "rekeys_completed_total": peer.rekeysCompletedTotal,
            ],
            "compression_layer": [
                "enabled": peer.compression.enabled,
                "algorithm": peer.compression.algorithm,
                "level": peer.compression.level,
                "min_bytes": peer.compression.minimumBodyBytes,
                "compress_attempts_total": peer.compression.compressAttemptsTotal,
                "compress_applied_total": peer.compression.compressAppliedTotal,
                "compress_skipped_no_gain_total": peer.compression.compressSkippedNoGainTotal,
                "compress_input_bytes_total": peer.compression.compressInputBytesTotal,
                "compress_output_bytes_total": peer.compression.compressOutputBytesTotal,
                "compressed_frames_sent_total": peer.compression.compressedFramesSentTotal,
                "compressed_frames_received_total": peer.compression.compressedFramesReceivedTotal,
                "compressed_input_bytes_sent_total": peer.compression.compressedInputBytesSentTotal,
                "compressed_output_bytes_sent_total": peer.compression.compressedOutputBytesSentTotal,
                "compressed_input_bytes_received_total": peer.compression.compressedInputBytesReceivedTotal,
                "compressed_output_bytes_received_total": peer.compression.compressedOutputBytesReceivedTotal,
                "uncompressed_frames_sent_total": peer.compression.uncompressedFramesSentTotal,
                "uncompressed_frames_received_total": peer.compression.uncompressedFramesReceivedTotal,
                "uncompressed_bytes_sent_total": peer.compression.uncompressedBytesSentTotal,
                "uncompressed_bytes_received_total": peer.compression.uncompressedBytesReceivedTotal,
                "rejected_frames_total": peer.compression.rejectedFramesTotal,
                "rejected_bytes_total": peer.compression.rejectedBytesTotal,
            ],
        ]
    }

    private func json(_ object: Any) -> Data { (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data("{}".utf8) }

    private func ipv4Address(_ host: String) -> in_addr? {
        var address = in_addr()
        return host.withCString { inet_pton(AF_INET, $0, &address) == 1 ? address : nil }
    }

    deinit { stop() }
}
