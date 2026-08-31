import Foundation

protocol ObstacleBridgeAdminAPIStateProvider: AnyObject {
    func adminStatusSnapshot() -> [String: Any]
    func adminConnectionsSnapshot() -> [String: Any]
    func adminTunRoutingSnapshot() -> [String: Any]
    func adminTunRoutingControl(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse
    func adminPeersSnapshot() -> [[String: Any]]
    func adminMetaSnapshot() -> [String: Any]
    func adminConfigSnapshot() -> [String: Any]
    func adminConfigChallenge(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse
    func adminUpdateConfig(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse
    func adminTunHelperStatus(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse
    func adminTunHelperAction(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse
    func adminTunHelperRepair(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse
    func adminAuthRequired() -> Bool
    func adminIsAuthenticated(headers: [String: String]) -> Bool
    func adminAuthState(headers: [String: String]) -> [String: Any]
    func adminAuthChallenge(method: String) -> ObstacleBridgeAdminAPIResponse
    func adminAuthLogin(method: String, body: Data?) -> ObstacleBridgeAdminAPIResponse
    func adminAuthLogout(method: String, headers: [String: String]) -> ObstacleBridgeAdminAPIResponse
    func adminRequestRestart(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse
    func adminRequestReconnect(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse
    func adminRequestSecureLinkRekey(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse
    func adminRequestShutdown(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse
    func adminLogLines(limit: Int) -> [String]
    func adminOnboardingConnectionProfiles() -> [[String: Any]]
    func adminOnboardingBlueprints() -> [[String: Any]]
    func adminOnboardingInviteGenerate(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse
    func adminOnboardingInvitePreview(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse
    func adminRequestRestart() -> [String: Any]
    func adminRequestReconnect() -> [String: Any]
    func adminRequestShutdown() -> [String: Any]
}

extension ObstacleBridgeAdminAPIStateProvider {
    func adminConnectionsSnapshot() -> [String: Any] {
        ObstacleBridgeAdminAPI.emptyConnectionsSnapshot()
    }

    func adminTunRoutingSnapshot() -> [String: Any] {
        ObstacleBridgeAdminAPI.tunRoutingSnapshot(fromConnections: adminConnectionsSnapshot())
    }

    func adminTunRoutingControl(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        guard let body = request.body,
              let doc = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              doc["enabled"] is Bool else {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "error": "enabled is required",
            ], statusLine: "HTTP/1.1 400 Bad Request")
        }
        let tunControl = (adminTunRoutingSnapshot()["tun_control"] as? [String: Any]) ?? [:]
        return ObstacleBridgeAdminAPI.jsonResponse([
            "ok": false,
            "enabled": tunControl["enabled"] as? Bool ?? false,
            "startup_enabled": tunControl["startup_enabled"] as? Bool ?? false,
            "supported": false,
            "error": "TUN route control unsupported",
        ], statusLine: "HTTP/1.1 409 Conflict")
    }

    func adminPeersSnapshot() -> [[String: Any]] {
        []
    }

    func adminMetaSnapshot() -> [String: Any] {
        [:]
    }

    func adminConfigSnapshot() -> [String: Any] {
        [
            "config": [:],
            "schema": [:],
        ]
    }

    func adminConfigChallenge(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        _ = request
        return ObstacleBridgeAdminAPI.jsonResponse([
            "ok": true,
            "auth_required": false,
        ])
    }

    func adminUpdateConfig(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        _ = request
        return ObstacleBridgeAdminAPI.jsonResponse([
            "ok": false,
            "error": "config update unsupported",
        ], statusLine: "HTTP/1.1 400 Bad Request")
    }

    func adminTunHelperStatus(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        _ = request
        return ObstacleBridgeAdminAPI.jsonResponse([
            "ok": true,
            "tun_helper": adminStatusSnapshot()["tun_helper"] ?? [:],
        ])
    }

    func adminTunHelperAction(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        _ = request
        return ObstacleBridgeAdminAPI.jsonResponse([
            "ok": false,
            "error": "TUN helper actions unsupported",
        ], statusLine: "HTTP/1.1 400 Bad Request")
    }

    func adminTunHelperRepair(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        _ = request
        return ObstacleBridgeAdminAPI.jsonResponse([
            "ok": false,
            "reason": "repair_supported_only_for_linux_native_helper",
            "repaired": [],
            "failed": [],
        ], statusLine: "HTTP/1.1 400 Bad Request")
    }

    func adminAuthRequired() -> Bool {
        false
    }

    func adminIsAuthenticated(headers: [String: String]) -> Bool {
        _ = headers
        return true
    }

    func adminAuthState(headers: [String: String]) -> [String: Any] {
        [
            "ok": true,
            "auth_required": adminAuthRequired(),
            "authenticated": adminIsAuthenticated(headers: headers),
            "username": "",
        ]
    }

    func adminAuthChallenge(method: String) -> ObstacleBridgeAdminAPIResponse {
        guard method.uppercased() == "GET" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        return ObstacleBridgeAdminAPI.jsonResponse([
            "ok": true,
            "auth_required": false,
        ])
    }

    func adminAuthLogin(method: String, body: Data?) -> ObstacleBridgeAdminAPIResponse {
        _ = body
        guard method.uppercased() == "POST" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        return ObstacleBridgeAdminAPI.jsonResponse([
            "ok": true,
            "auth_required": false,
            "authenticated": true,
        ])
    }

    func adminAuthLogout(method: String, headers: [String: String]) -> ObstacleBridgeAdminAPIResponse {
        _ = headers
        guard method.uppercased() == "POST" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        return ObstacleBridgeAdminAPI.jsonResponse([
            "ok": true,
            "authenticated": false,
        ])
    }

    func adminRequestRestart(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        _ = request
        return ObstacleBridgeAdminAPI.jsonResponse(adminRequestRestart())
    }

    func adminRequestReconnect(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        _ = request
        return ObstacleBridgeAdminAPI.jsonResponse(adminRequestReconnect())
    }

    func adminRequestSecureLinkRekey(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        _ = request
        return ObstacleBridgeAdminAPI.jsonResponse([
            "ok": false,
            "reason": "secure_link_rekey_unsupported",
        ], statusLine: "HTTP/1.1 400 Bad Request")
    }

    func adminRequestShutdown(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        _ = request
        return ObstacleBridgeAdminAPI.jsonResponse(adminRequestShutdown())
    }

    func adminLogLines(limit: Int) -> [String] {
        _ = limit
        return []
    }

    func adminOnboardingConnectionProfiles() -> [[String: Any]] {
        []
    }

    func adminOnboardingBlueprints() -> [[String: Any]] {
        []
    }

    func adminOnboardingInviteGenerate(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        _ = request
        return ObstacleBridgeAdminAPI.jsonResponse([
            "ok": false,
            "error": "invite generation unsupported",
        ], statusLine: "HTTP/1.1 400 Bad Request")
    }

    func adminOnboardingInvitePreview(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        _ = request
        return ObstacleBridgeAdminAPI.jsonResponse([
            "ok": false,
            "error": "invite preview unsupported",
        ], statusLine: "HTTP/1.1 400 Bad Request")
    }

    func adminRequestRestart() -> [String: Any] {
        ["ok": false, "error": "restart unsupported"]
    }

    func adminRequestReconnect() -> [String: Any] {
        ["ok": false, "error": "reconnect unsupported"]
    }

    func adminRequestShutdown() -> [String: Any] {
        ["ok": false, "error": "shutdown unsupported"]
    }
}

struct ObstacleBridgeAdminAPIRequest {
    let method: String
    let path: String
    let headers: [String: String]
    let body: Data?
}

struct ObstacleBridgeAdminAPIResponse {
    let statusLine: String
    let contentType: String
    let body: Data
    let headers: [(String, String)]

    var tupleValue: (statusLine: String, contentType: String, body: Data) {
        (statusLine, contentType, body)
    }
}

enum ObstacleBridgeAdminAPI {
    static func tunControlSnapshot(enabled: Bool, startupEnabled: Bool, supported: Bool) -> [String: Any] {
        [
            "enabled": enabled,
            "startup_enabled": startupEnabled,
            "supported": supported,
        ]
    }

    static func response(
        for request: ObstacleBridgeAdminAPIRequest,
        provider: ObstacleBridgeAdminAPIStateProvider
    ) -> ObstacleBridgeAdminAPIResponse? {
        let normalizedMethod = request.method.uppercased()
        let normalizedPath = request.path.split(separator: "?", maxSplits: 1).first.map(String.init) ?? request.path
        switch (normalizedMethod, normalizedPath) {
        case ("GET", "/api/status"):
            return jsonResponse(statusSnapshot(status: provider.adminStatusSnapshot(), connections: provider.adminConnectionsSnapshot()))
        case ("GET", "/api/bootstrap"):
            return jsonResponse(provider.adminMetaSnapshot()["bootstrap_state"] ?? [:])
        case ("GET", "/api/auth/state"):
            return jsonResponse(provider.adminAuthState(headers: request.headers))
        case ("GET", "/api/meta"):
            return jsonResponse(provider.adminMetaSnapshot())
        case ("GET", "/api/connections"):
            return jsonResponse(provider.adminConnectionsSnapshot())
        case ("GET", "/api/tun-routing/status"):
            return jsonResponse(provider.adminTunRoutingSnapshot())
        case ("POST", "/api/tun-routing/control"):
            return provider.adminTunRoutingControl(request: request)
        case ("GET", "/api/tun-helper/status"):
            return provider.adminTunHelperStatus(request: request)
        case ("POST", "/api/tun-helper/action"):
            return provider.adminTunHelperAction(request: request)
        case ("POST", "/api/tun-helper/repair"):
            return provider.adminTunHelperRepair(request: request)
        case ("GET", "/api/peers"):
            return jsonResponse(["peers": provider.adminPeersSnapshot()])
        case ("GET", "/api/config"):
            return jsonResponse(provider.adminConfigSnapshot())
        case ("GET", "/api/onboarding/connection-profiles"):
            let profiles = provider.adminOnboardingConnectionProfiles()
            return jsonResponse(["ok": true, "count": profiles.count, "profiles": profiles])
        case ("GET", "/api/onboarding/blueprints"):
            let blueprints = provider.adminOnboardingBlueprints()
            return jsonResponse(["ok": true, "count": blueprints.count, "blueprints": blueprints])
        case ("POST", "/api/onboarding/invite/generate"):
            return provider.adminOnboardingInviteGenerate(request: request)
        case ("POST", "/api/onboarding/invite/preview"):
            return provider.adminOnboardingInvitePreview(request: request)
        case ("POST", "/api/config/challenge"):
            return provider.adminConfigChallenge(request: request)
        case ("POST", "/api/config"):
            return provider.adminUpdateConfig(request: request)
        case ("GET", "/api/logs"):
            return jsonResponse(["lines": provider.adminLogLines(limit: queryLimit(from: request.path) ?? 500)])
        case ("POST", "/api/restart"):
            return provider.adminRequestRestart(request: request)
        case ("POST", "/api/reconnect"):
            return provider.adminRequestReconnect(request: request)
        case ("POST", "/api/secure-link/rekey"):
            return provider.adminRequestSecureLinkRekey(request: request)
        case ("POST", "/api/shutdown"):
            return provider.adminRequestShutdown(request: request)
        case ("GET", "/api/auth/challenge"):
            return provider.adminAuthChallenge(method: normalizedMethod)
        case ("POST", "/api/auth/login"):
            return provider.adminAuthLogin(method: normalizedMethod, body: request.body)
        case ("POST", "/api/auth/logout"):
            return provider.adminAuthLogout(method: normalizedMethod, headers: request.headers)
        default:
            return nil
        }
    }

    static func liveTopicPayload(topic: String, provider: ObstacleBridgeAdminAPIStateProvider) -> Any? {
        switch topic {
        case "status":
            return statusSnapshot(status: provider.adminStatusSnapshot(), connections: provider.adminConnectionsSnapshot())
        case "connections":
            return provider.adminConnectionsSnapshot()
        case "tun_routing":
            return provider.adminTunRoutingSnapshot()
        case "peers":
            return ["peers": provider.adminPeersSnapshot()]
        case "meta":
            return provider.adminMetaSnapshot()
        default:
            return nil
        }
    }

    static func request(fromMessagePayload payload: [String: Any]) -> ObstacleBridgeAdminAPIRequest? {
        let source: [String: Any]
        if let nested = payload["api_request"] as? [String: Any] {
            source = nested
        } else if String(describing: payload["command"] ?? "") == "admin_api_request" {
            source = payload
        } else if payload["method"] != nil, payload["path"] != nil {
            source = payload
        } else {
            return nil
        }

        guard let path = source["path"] as? String, !path.isEmpty else {
            return nil
        }
        let method = (source["method"] as? String) ?? "GET"
        let headers = source["headers"] as? [String: String] ?? [:]
        let body: Data?
        if let bodyBase64 = source["body_base64"] as? String {
            body = Data(base64Encoded: bodyBase64)
        } else if let bodyUTF8 = source["body_utf8"] as? String {
            body = Data(bodyUTF8.utf8)
        } else {
            body = nil
        }
        return ObstacleBridgeAdminAPIRequest(method: method, path: path, headers: headers, body: body)
    }

    static func appMessageResponse(
        for request: ObstacleBridgeAdminAPIRequest,
        provider: ObstacleBridgeAdminAPIStateProvider
    ) -> [String: Any] {
        guard let response = response(for: request, provider: provider) else {
            return [
                "ok": false,
                "status_line": "HTTP/1.1 404 Not Found",
                "content_type": "application/json; charset=utf-8",
                "body_json": ["ok": false, "error": "not found", "path": request.path],
            ]
        }

        var payload: [String: Any] = [
            "ok": true,
            "status_line": response.statusLine,
            "content_type": response.contentType,
        ]
        if response.contentType.lowercased().contains("application/json"),
           let json = try? JSONSerialization.jsonObject(with: response.body) {
            payload["body_json"] = json
        } else if let text = String(data: response.body, encoding: .utf8) {
            payload["body_utf8"] = text
        } else {
            payload["body_base64"] = response.body.base64EncodedString()
        }
        return payload
    }

    static func jsonBody(_ value: Any) -> Data {
        if JSONSerialization.isValidJSONObject(value),
           let data = try? JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys]) {
            return data
        }
        let fallback: [String: Any] = [
            "ok": false,
            "error": "snapshot was not a valid JSON object",
        ]
        return (try? JSONSerialization.data(withJSONObject: fallback, options: [.prettyPrinted, .sortedKeys])) ?? Data("{}".utf8)
    }

    static func emptyConnectionsSnapshot() -> [String: Any] {
        [
            "counts": [
                "udp": 0,
                "tcp": 0,
                "tun": 0,
                "udp_listening": 0,
                "tcp_listening": 0,
                "tun_listening": 0,
            ],
            "udp": [],
            "tcp": [],
            "tun": [],
        ]
    }

    static func emptyTunRoutingSnapshot() -> [String: Any] {
        [
            "tun": [],
            "shared_tun": [],
            "tun_helper": [:],
            "summary": [
                "tun_total": 0,
                "tun_open": 0,
                "tun_listening": 0,
                "shared_services": 0,
                "shared_active_peer_bindings": 0,
                "shared_drop_total": 0,
                "shared_drop_by_reason": [:] as [String: Int],
                "icmp_stage_counts": [:] as [String: Int],
                "probe_boundary_counts": [:] as [String: Int],
                "local_reply_stage_counts": [:] as [String: Int],
                "probe_last_timeout_diag": [:] as [String: Any],
                "probe_last_timeout_diag_by_transport": [:] as [String: Any],
            ],
            "app": "udp-bidirectional-mux",
            "milestone": "C",
        ]
    }

    static func tunRoutingSnapshot(fromConnections snapshot: [String: Any]) -> [String: Any] {
        let tunRows = snapshot["tun"] as? [[String: Any]] ?? []
        let sharedRows = deduplicatedSharedTunRows(from: tunRows)
        let icmpStageCounts = snapshot["tun_icmp_stage_counts"] as? [String: Any] ?? [:]
        let probeBoundaryCounts = snapshot["tun_probe_boundary_counts"] as? [String: Any] ?? [:]
        let localReplyStageCounts = snapshot["tun_local_reply_stage_counts"] as? [String: Any] ?? [:]
        let probeLastTimeoutDiag = snapshot["tun_probe_last_timeout_diag"] as? [String: Any] ?? [:]
        let probeLastTimeoutDiagByTransport = snapshot["tun_probe_last_timeout_diag_by_transport"] as? [String: Any] ?? [:]
        let tunOpen = tunRows.reduce(into: 0) { partialResult, row in
            let state = String(describing: row["state"] ?? "connected").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if row["chan_id"] is NSNull {
                return
            }
            if row["chan_id"] == nil {
                return
            }
            if state != "listening" {
                partialResult += 1
            }
        }
        let tunListening = tunRows.reduce(into: 0) { partialResult, row in
            let state = String(describing: row["state"] ?? "connected").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if state == "listening" {
                partialResult += 1
            }
        }
        let activeBindings = sharedRows.reduce(into: 0) { partialResult, row in
            let ownership = row["shared_tun_ownership"] as? [String: Any] ?? [:]
            let bindings = ownership["active_peer_bindings"] as? [Any] ?? []
            partialResult += bindings.count
        }
        let sharedDropTotal = sharedRows.reduce(into: 0) { partialResult, row in
            let ownership = row["shared_tun_ownership"] as? [String: Any] ?? [:]
            let dropCounters = ownership["drop_counters"] as? [String: Any] ?? [:]
            partialResult += (dropCounters["total"] as? Int) ?? (dropCounters["total"] as? NSNumber)?.intValue ?? 0
        }
        let sharedDropByReason = sharedRows.reduce(into: [String: Int]()) { partialResult, row in
            let ownership = row["shared_tun_ownership"] as? [String: Any] ?? [:]
            let dropCounters = ownership["drop_counters"] as? [String: Any] ?? [:]
            let byReason = dropCounters["by_reason"] as? [String: Any] ?? [:]
            for (reason, rawCount) in byReason {
                let count = (rawCount as? Int) ?? (rawCount as? NSNumber)?.intValue ?? 0
                partialResult[reason] = (partialResult[reason] ?? 0) + count
            }
        }
        return [
            "tun": tunRows,
            "shared_tun": sharedRows,
            "tun_helper": [:],
            "summary": [
                "tun_total": tunRows.count,
                "tun_open": tunOpen,
                "tun_listening": tunListening,
                "shared_services": sharedRows.count,
                "shared_active_peer_bindings": activeBindings,
                "shared_drop_total": sharedDropTotal,
                "shared_drop_by_reason": sharedDropByReason,
                "icmp_stage_counts": icmpStageCounts,
                "probe_boundary_counts": probeBoundaryCounts,
                "local_reply_stage_counts": localReplyStageCounts,
                "probe_last_timeout_diag": probeLastTimeoutDiag,
                "probe_last_timeout_diag_by_transport": probeLastTimeoutDiagByTransport,
            ],
            "app": "udp-bidirectional-mux",
            "milestone": "C",
        ]
    }

    static func statusSnapshot(status: [String: Any], connections: [String: Any]) -> [String: Any] {
        var payload = status
        let tunRows = connections["tun"] as? [[String: Any]] ?? []
        let helper = status["tun_helper"] as? [String: Any] ?? [:]
        let helperRuntime = helper["runtime"] as? [String: Any] ?? [:]
        let tunConnected = tunRows.contains { row in
            let state = String(describing: row["state"] ?? "connected").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard let chan = row["chan_id"], !(chan is NSNull) else { return false }
            return state != "listening"
        }
        let selectedIfname: String = {
            for row in tunRows {
                let local = row["local"] as? [String: Any] ?? [:]
                let candidate = String(describing: local["ifname"] ?? row["local_bind"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
                if !candidate.isEmpty { return candidate }
            }
            return String(describing: helperRuntime["ifname"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        }()
        payload["tun_ifname"] = selectedIfname
        payload["tun_connected"] = tunConnected
        payload["tun_helper_runtime_ifname"] = String(describing: helperRuntime["ifname"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        payload["tun_icmp_stage_counts"] = connections["tun_icmp_stage_counts"] ?? [:]
        payload["tun_probe_boundary_counts"] = connections["tun_probe_boundary_counts"] ?? [:]
        payload["tun_local_reply_stage_counts"] = connections["tun_local_reply_stage_counts"] ?? [:]
        payload["tun_probe_last_timeout_diag"] = connections["tun_probe_last_timeout_diag"] ?? [:]
        payload["tun_probe_last_timeout_diag_by_transport"] = connections["tun_probe_last_timeout_diag_by_transport"] ?? [:]
        return payload
    }

    private static func deduplicatedSharedTunRows(from tunRows: [[String: Any]]) -> [[String: Any]] {
        var rowsByKey: [String: [String: Any]] = [:]
        var order: [String] = []
        for row in tunRows {
            guard row["shared_tun_ownership"] is [String: Any] else {
                continue
            }
            let local = row["local"] as? [String: Any] ?? [:]
            let key = [
                String(describing: row["svc_owner_peer_id"] ?? ""),
                String(describing: row["svc_id"] ?? ""),
                String(describing: local["ifname"] ?? row["local_bind"] ?? ""),
                String(describing: local["mtu"] ?? row["local_port"] ?? ""),
            ].joined(separator: "|")
            if rowsByKey[key] == nil {
                order.append(key)
                rowsByKey[key] = row
                continue
            }
            let existingState = String(describing: rowsByKey[key]?["state"] ?? "")
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .lowercased()
            let rowState = String(describing: row["state"] ?? "")
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .lowercased()
            if existingState == "listening" && rowState != "listening" {
                rowsByKey[key] = row
            }
        }
        return order.compactMap { rowsByKey[$0] }
    }

    static func jsonResponse(_ payload: Any, statusLine: String = "HTTP/1.1 200 OK", headers: [(String, String)] = []) -> ObstacleBridgeAdminAPIResponse {
        ObstacleBridgeAdminAPIResponse(
            statusLine: statusLine,
            contentType: "application/json; charset=utf-8",
            body: jsonBody(payload),
            headers: headers
        )
    }

    static func plainTextResponse(statusLine: String, body: String, headers: [(String, String)] = []) -> ObstacleBridgeAdminAPIResponse {
        ObstacleBridgeAdminAPIResponse(
            statusLine: statusLine,
            contentType: "text/plain; charset=utf-8",
            body: Data(body.utf8),
            headers: headers
        )
    }

    private static func queryLimit(from path: String) -> Int? {
        guard let components = URLComponents(string: "http://localhost\(path)") else {
            return nil
        }
        return components.queryItems?.first(where: { $0.name == "limit" }).flatMap { Int($0.value ?? "") }
    }
}
