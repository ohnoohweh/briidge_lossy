import Foundation

/// macOS-owned IPC-1A2 browser bootstrap. It keeps listener, authentication,
/// sessions, static assets, and read-only Admin documents in the native child;
/// every runtime value still crosses the inherited bounded parent RPC.
enum ObstacleBridgeNativeAdminMacOSService {
    static func run(controlFD: Int32, lifetimeFD: Int32, logFD: Int32?, generation: Int) throws {
        try ObstacleBridgeNativeAdminWorker.run(
            controlFD: controlFD,
            lifetimeFD: lifetimeFD,
            logFD: logFD,
            generation: generation,
            serviceFactory: makeService
        )
    }

    private static func makeService(arguments: [String: Any], parentRPC: ObstacleBridgeNativeAdminWorker.ParentRPC) throws -> ObstacleBridgeNativeAdminWorker.Service {
        let bindHost = (arguments["admin_web_bind"] as? String) ?? "127.0.0.1"
        let requestedPort = (arguments["admin_web_port"] as? NSNumber)?.intValue ?? 0
        let username = (arguments["admin_web_username"] as? String) ?? ""
        let password = (arguments["admin_web_password"] as? String) ?? ""
        let authDisabled = (arguments["admin_web_auth_disable"] as? Bool) ?? false
        let authRequired = !authDisabled && !username.isEmpty && !password.isEmpty
        let bearerToken = (arguments["admin_web_token"] as? String) ?? ""
        let assetDirectory = (arguments["admin_web_dir"] as? String) ?? ""
        let cookieScope = [bindHost, String(requestedPort), (arguments["admin_web_path"] as? String) ?? "/"].joined(separator: "|")
        let auth = ObstacleBridgeAdminAuth(
            queueLabel: "ObstacleBridgeNativeAdminMacOS.Auth",
            authRequiredProvider: { authRequired },
            usernameProvider: { username },
            passwordProvider: { password },
            bearerTokenProvider: { bearerToken },
            cookieScopeProvider: { cookieScope }
        )
        let configChallenges = ObstacleBridgeAdminConfigChallenge(
            queueLabel: "ObstacleBridgeNativeAdminMacOS.ConfigChallenge",
            usernameProvider: { username },
            passwordProvider: { password }
        )
        func snapshot(_ method: String) -> [String: Any] {
            (try? parentRPC.call(method: method)) as? [String: Any] ?? ["state": "unavailable"]
        }
        func json(_ payload: Any, statusLine: String = "HTTP/1.1 200 OK") -> ObstacleBridgeAdminAPIResponse {
            .init(statusLine: statusLine, contentType: "application/json; charset=utf-8", body: ObstacleBridgeWebAdminServer.jsonBody(payload), headers: [])
        }
        func logs(path: String) -> ObstacleBridgeAdminAPIResponse {
            let limit = queryLimit(path, fallback: 500)
            let fetched = (try? parentRPC.call(method: "fetch_logs", args: [limit])) as? [String: Any] ?? [:]
            return json(ObstacleBridgeAdminAPI.logsPayload(
                lines: fetched["lines"] as? [String] ?? [],
                available: fetched["available"] as? Bool ?? false,
                source: fetched["source"] as? String ?? "managed",
                error: fetched["error"] as? String ?? "logger unavailable",
                loggingWorker: fetched["worker_status"] as? [String: Any] ?? fetched["worker"] as? [String: Any]
            ))
        }
        func configChallenge(body: Data?) -> ObstacleBridgeAdminAPIResponse {
            guard let body,
                  let payload = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
                  let updates = payload["updates"] as? [String: Any] else {
                return json(["ok": false, "error": "invalid JSON body or updates must be an object"], statusLine: "HTTP/1.1 400 Bad Request")
            }
            guard authRequired else { return json(["ok": true, "auth_required": false]) }
            guard let challenge = try? configChallenges.issueChallenge(updates: updates) else {
                return json(["ok": false, "error": "unable to issue configuration challenge"], statusLine: "HTTP/1.1 400 Bad Request")
            }
            var response = challenge
            response["ok"] = true
            response["auth_required"] = true
            return json(response)
        }
        func updateConfig(body: Data?) -> ObstacleBridgeAdminAPIResponse {
            guard let body,
                  let payload = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
                  let updates = payload["updates"] as? [String: Any] else {
                return json(["ok": false, "error": "invalid JSON body or updates must be an object"], statusLine: "HTTP/1.1 400 Bad Request")
            }
            if authRequired {
                let challengeID = (payload["challenge_id"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
                let proof = (payload["proof"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                guard !challengeID.isEmpty, !proof.isEmpty else {
                    return json(["ok": false, "error": "configuration change confirmation required"], statusLine: "HTTP/1.1 428 Precondition Required")
                }
                if let error = configChallenges.validate(challengeID: challengeID, proof: proof, updates: updates) {
                    return json(["ok": false, "error": error], statusLine: "HTTP/1.1 403 Forbidden")
                }
            }
            let result = try? parentRPC.call(method: "update_config", args: [updates])
            let updateResult = ObstacleBridgeWebAdminServer.normalizedConfigUpdateResult(result)
            guard updateResult.succeeded else {
                return json(["ok": false, "error": updateResult.error], statusLine: "HTTP/1.1 400 Bad Request")
            }
            if updates.keys.contains(where: { ["admin_web_auth_disable", "admin_web_username", "admin_web_password", "secure_link_psk"].contains($0) }) {
                auth.resetState()
                configChallenges.reset()
            }
            return json(["ok": true, "config": snapshot("get_config_snapshot")])
        }
        let server = try ObstacleBridgeWebAdminServer(
            bindHost: bindHost,
            port: requestedPort,
            fallbackIndexTitle: "ObstacleBridge native Admin child",
            fallbackIndexSubtitle: "Native Admin browser reads are served through inherited parent RPC.",
            statusProvider: { snapshot("get_status_snapshot") },
            apiProvider: { method, path, headers, body in
                switch (method.uppercased(), path.split(separator: "?", maxSplits: 1).first.map(String.init) ?? path) {
                case ("GET", "/api/auth/state"): return json(auth.authState(headers: headers))
                case ("GET", "/api/auth/challenge"): return auth.authChallenge(method: method)
                case ("POST", "/api/auth/login"): return auth.authLogin(method: method, body: body)
                case ("POST", "/api/auth/logout"): return auth.authLogout(method: method, headers: headers)
                case ("GET", "/api/health"): return json(["ok": true])
                case ("GET", "/api/status"): return json(snapshot("get_status_snapshot"))
                case ("GET", "/api/meta"):
                    let status = snapshot("get_status_snapshot")
                    return json(["app": "ObstacleBridgeMacOS", "platform": "macos", "admin_web_name": arguments["admin_web_name"] as? String ?? "", "build": status["build"] ?? [:], "runtime_dependencies": ["ok": true, "missing": [], "install_hint": ""]])
                case ("GET", "/api/config"):
                    return json(["ok": true, "config": snapshot("get_config_snapshot"), "schema": snapshot("get_config_schema_snapshot")])
                case ("POST", "/api/config/challenge"): return configChallenge(body: body)
                case ("POST", "/api/config"): return updateConfig(body: body)
                case ("GET", "/api/logs"): return logs(path: path)
                case ("GET", "/api/connections"): return json(snapshot("get_connections_snapshot"))
                case ("GET", "/api/peers"): return json(snapshot("get_peer_connections_snapshot"))
                case ("GET", "/api/onboarding/connection-profiles"):
                    let profiles = ObstacleBridgeWebAdminServer.onboardingConnectionProfiles(snapshot: snapshot("get_peer_connections_snapshot"))
                    return json(["ok": true, "count": profiles.count, "profiles": profiles])
                case ("GET", "/api/tun-routing/status"):
                    let status = snapshot("get_status_snapshot")
                    let tun = status["tun"] as? [Any] ?? []
                    let helper = status["tun_helper"] as? [String: Any] ?? [:]
                    return json(["tun": tun, "shared_tun": status["shared_tun"] ?? [], "tun_helper": helper, "summary": ["tun_total": tun.count], "app": "udp-bidirectional-mux", "milestone": "C"])
                default: return nil
                }
            },
            staticFileProvider: { ObstacleBridgeWebAdminServer.staticAssetResponse(path: $0, assetDirectory: assetDirectory) },
            liveTopicProvider: { topic in
                switch topic {
                case "status": return snapshot("get_status_snapshot")
                case "peers": return snapshot("get_peer_connections_snapshot")
                case "connections": return snapshot("get_connections_snapshot")
                default: return nil
                }
            },
            authRequiredProvider: { authRequired },
            authenticatedProvider: { auth.isAuthenticated(headers: $0) }
        )
        let port = try server.startAndWait()
        return .init(port: port, stop: { server.stop() })
    }

    private static func queryLimit(_ path: String, fallback: Int) -> Int {
        guard let query = path.split(separator: "?", maxSplits: 1).dropFirst().first else { return fallback }
        for pair in query.split(separator: "&") {
            let fields = pair.split(separator: "=", maxSplits: 1)
            if fields.count == 2, fields[0] == "limit", let value = Int(fields[1]) { return max(1, min(value, 10_000)) }
        }
        return fallback
    }

}
