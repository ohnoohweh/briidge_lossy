import Foundation

/// Public adapter port for a platform-owned configuration store. The platform
/// declares its supported schema; Core retains grouped-field and type checks.
public enum ObstacleBridgeAdminConfigUpdatePort {
    public static func validatedNextConfiguration(
        currentRawConfig: [String: Any],
        currentRuntimeConfig: [String: Any],
        updates: [String: Any],
        schema: [String: [String: Any]],
        sections: [String: String]
    ) throws -> (configuration: [String: Any], normalizedKeys: [String]) {
        let result = try ObstacleBridgeAdminConfigSupport.validatedNextRawConfig(
            currentRawConfig: currentRawConfig,
            currentRuntimeConfig: currentRuntimeConfig,
            updates: updates,
            configurationPolicy: .init(
                normalizedUpdates: { updates, _ in updates },
                looksGrouped: { raw in raw.values.contains { $0 is [String: Any] } },
                schemaRow: { schema[$0] },
                sectionName: { sections[$0] }
            )
        )
        return (result.nextRawConfig, result.normalizedKeys)
    }
}

/// Public onboarding HTTP-effect port. Linux owns routing; Core owns token
/// shape, validation, and preview redaction.
public enum ObstacleBridgeAdminOnboardingPort {
    public static func generate(body: Data?, runtimeConfig: [String: Any]) -> ObstacleBridgeAdminLinuxResponse {
        linuxResponse(ObstacleBridgeAdminConfigSupport.inviteGenerateResponse(
            method: "POST", body: body, runtimeConfig: runtimeConfig, profiles: [],
            encryptSecrets: { payload in
                guard !containsSecret(payload) else { throw NSError(domain: "ObstacleBridgeLinux", code: 1, userInfo: [NSLocalizedDescriptionKey: "Linux onboarding secrets are unavailable"]) }
                return payload
            }
        ))
    }
    public static func preview(body: Data?) -> ObstacleBridgeAdminLinuxResponse {
        linuxResponse(ObstacleBridgeAdminConfigSupport.invitePreviewResponse(method: "POST", body: body, decryptSecrets: { $0 }))
    }
    private static func linuxResponse(_ response: ObstacleBridgeAdminAPIResponse) -> ObstacleBridgeAdminLinuxResponse {
        let code = Int(response.statusLine.split(separator: " ").dropFirst().first ?? "500") ?? 500
        return .init(statusCode: code, body: response.body)
    }
    private static func containsSecret(_ value: Any) -> Bool {
        if let object = value as? [String: Any] { return object.contains { $0.key.lowercased().contains("psk") || $0.key.lowercased().contains("password") || containsSecret($0.value) } }
        if let values = value as? [Any] { return values.contains(where: containsSecret) }
        return false
    }
}

enum ObstacleBridgeAdminConfigSupport {
    struct ConfigurationPolicy {
        let normalizedUpdates: ([String: Any], [String: Any]) -> [String: Any]
        let looksGrouped: ([String: Any]) -> Bool
        let schemaRow: (String) -> [String: Any]?
        let sectionName: (String) -> String?
    }

    enum ParsedBody {
        case payload([String: Any])
        case response(ObstacleBridgeAdminAPIResponse)
    }

    static func jsonObjectBody(
        method: String,
        expectedMethod: String,
        body: Data?
    ) -> ParsedBody {
        guard method.uppercased() == expectedMethod.uppercased() else {
            return .response(
                ObstacleBridgeAdminAPI.plainTextResponse(
                    statusLine: "HTTP/1.1 405 Method Not Allowed",
                    body: "Method Not Allowed"
                )
            )
        }
        guard let body,
              let object = try? JSONSerialization.jsonObject(with: body),
              let payload = object as? [String: Any] else {
            return .response(
                ObstacleBridgeAdminAPI.jsonResponse(
                    [
                        "ok": false,
                        "error": "invalid JSON body",
                    ],
                    statusLine: "HTTP/1.1 400 Bad Request"
                )
            )
        }
        return .payload(payload)
    }

    static func updatesObject(from payload: [String: Any]) -> ParsedBody {
        guard let updates = payload["updates"] as? [String: Any] else {
            return .response(
                ObstacleBridgeAdminAPI.jsonResponse(
                    [
                        "ok": false,
                        "error": "updates must be an object",
                    ],
                    statusLine: "HTTP/1.1 400 Bad Request"
                )
            )
        }
        return .payload(updates)
    }

    static func inviteGenerateResponse(
        method: String,
        body: Data?,
        runtimeConfig: [String: Any],
        profiles: [[String: Any]],
        encryptSecrets: ([String: Any]) throws -> [String: Any]
    ) -> ObstacleBridgeAdminAPIResponse {
        switch jsonObjectBody(method: method, expectedMethod: "POST", body: body) {
        case .response(let response):
            return response
        case .payload(let payload):
            let connectionID = (payload["connection_id"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            let selectedConnection: [String: Any]?
            if profiles.count > 1 && connectionID.isEmpty {
                return ObstacleBridgeAdminAPI.jsonResponse([
                    "ok": false,
                    "error": "multiple connection profiles available; select connection_id",
                    "profiles": profiles,
                ], statusLine: "HTTP/1.1 409 Conflict")
            }
            if !connectionID.isEmpty {
                selectedConnection = profiles.first { String(describing: $0["id"] ?? "") == connectionID }
                if selectedConnection == nil {
                    return ObstacleBridgeAdminAPI.jsonResponse([
                        "ok": false,
                        "error": "unknown connection_id: \(connectionID)",
                    ], statusLine: "HTTP/1.1 400 Bad Request")
                }
            } else {
                selectedConnection = profiles.first
            }
            let effectiveRuntimeConfig = ObstacleBridgeOnboarding.tokenRuntimeConfig(
                runtimeConfig: runtimeConfig,
                requestPayload: payload
            )
            let own = ObstacleBridgeOnboarding.sanitizeServices(payload["own_servers"] ?? effectiveRuntimeConfig["own_servers"])
            let remote = ObstacleBridgeOnboarding.sanitizeServices(payload["remote_servers"] ?? effectiveRuntimeConfig["remote_servers"])
            let preview = ObstacleBridgeOnboarding.tokenPayload(
                runtimeConfig: effectiveRuntimeConfig,
                connection: selectedConnection ?? [:],
                ownServices: own,
                remoteServices: remote,
                encryptSecrets: encryptSecrets
            )
            do {
                let token = try ObstacleBridgeOnboarding.encodeToken(preview)
                return ObstacleBridgeAdminAPI.jsonResponse([
                    "ok": true,
                    "invite_token": token,
                    "preview": preview,
                ])
            } catch {
                return ObstacleBridgeAdminAPI.jsonResponse([
                    "ok": false,
                    "error": "failed to encode invite token",
                ], statusLine: "HTTP/1.1 400 Bad Request")
            }
        }
    }

    static func invitePreviewResponse(
        method: String,
        body: Data?,
        decryptSecrets: ([String: Any]) throws -> [String: Any]
    ) -> ObstacleBridgeAdminAPIResponse {
        switch jsonObjectBody(method: method, expectedMethod: "POST", body: body) {
        case .response(let response):
            return response
        case .payload(let payload):
            let token = (payload["invite_token"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            guard !token.isEmpty else {
                return ObstacleBridgeAdminAPI.jsonResponse([
                    "ok": false,
                    "error": "invite_token is required",
                ], statusLine: "HTTP/1.1 400 Bad Request")
            }
            do {
                let decoded = try ObstacleBridgeOnboarding.decodeToken(token)
                var preview = decoded
                if let psk = preview["secure_link_psk"] as? String, !psk.isEmpty {
                    preview["secure_link_psk"] = "***hidden***"
                    preview["secure_link_psk_present"] = true
                }
                return ObstacleBridgeAdminAPI.jsonResponse([
                    "ok": true,
                    "preview": preview,
                    "suggested_updates": try ObstacleBridgeOnboarding.updates(
                        from: decoded,
                        decryptSecrets: decryptSecrets
                    ),
                ])
            } catch {
                return ObstacleBridgeAdminAPI.jsonResponse([
                    "ok": false,
                    "error": error.localizedDescription,
                ], statusLine: "HTTP/1.1 400 Bad Request")
            }
        }
    }

    static func validatedNextRawConfig(
        currentRawConfig: [String: Any],
        currentRuntimeConfig: [String: Any],
        updates: [String: Any],
        configurationPolicy: ConfigurationPolicy
    ) throws -> (nextRawConfig: [String: Any], normalizedKeys: [String]) {
        let normalized = configurationPolicy.normalizedUpdates(updates, currentRuntimeConfig)
        let grouped = configurationPolicy.looksGrouped(currentRawConfig)
        var nextRawConfig = currentRawConfig
        for (key, rawValue) in normalized {
            guard let schemaRow = configurationPolicy.schemaRow(key) else {
                throw NSError(domain: "ObstacleBridgeAdminConfigSupport", code: 20, userInfo: [NSLocalizedDescriptionKey: "unknown config key: \(key)"])
            }
            let value = try validatedConfigValue(key: key, rawValue: rawValue, schemaRow: schemaRow)
            if grouped, let section = configurationPolicy.sectionName(key) {
                var block = (nextRawConfig[section] as? [String: Any]) ?? [:]
                block[key] = value
                nextRawConfig[section] = block
                if key != section {
                    nextRawConfig.removeValue(forKey: key)
                }
            } else {
                nextRawConfig[key] = value
            }
        }
        return (nextRawConfig, Array(normalized.keys).sorted())
    }

    static func validatedConfigValue(key: String, rawValue: Any, schemaRow: [String: Any]) throws -> Any {
        let defaultValue = schemaRow["default"]
        switch defaultValue {
        case is Bool:
            guard let boolValue = rawValue as? Bool else {
                throw NSError(domain: "ObstacleBridgeAdminConfigSupport", code: 21, userInfo: [NSLocalizedDescriptionKey: "\(key) expects boolean"])
            }
            return boolValue
        case is Int:
            guard let intValue = rawValue as? Int else {
                throw NSError(domain: "ObstacleBridgeAdminConfigSupport", code: 22, userInfo: [NSLocalizedDescriptionKey: "\(key) expects integer"])
            }
            return intValue
        case is Double:
            if let doubleValue = rawValue as? Double {
                return doubleValue
            }
            if let intValue = rawValue as? Int {
                return Double(intValue)
            }
            throw NSError(domain: "ObstacleBridgeAdminConfigSupport", code: 23, userInfo: [NSLocalizedDescriptionKey: "\(key) expects number"])
        case is String:
            guard let stringValue = rawValue as? String else {
                throw NSError(domain: "ObstacleBridgeAdminConfigSupport", code: 24, userInfo: [NSLocalizedDescriptionKey: "\(key) expects string"])
            }
            return stringValue
        case is [Any]:
            guard let listValue = rawValue as? [Any] else {
                throw NSError(domain: "ObstacleBridgeAdminConfigSupport", code: 25, userInfo: [NSLocalizedDescriptionKey: "\(key) expects list"])
            }
            return listValue
        default:
            return rawValue
        }
    }

    static func configChallengeResponse(
        request: ObstacleBridgeAdminAPIRequest,
        authRequired: Bool,
        authenticated: Bool,
        challengeIssuer: ([String: Any]) throws -> [String: Any]
    ) -> ObstacleBridgeAdminAPIResponse {
        let payload: [String: Any]
        switch jsonObjectBody(method: request.method, expectedMethod: "POST", body: request.body) {
        case .response(let response):
            return response
        case .payload(let value):
            payload = value
        }
        let updates = payload["updates"] as? [String: Any] ?? [:]
        guard authRequired else {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": true,
                "auth_required": false,
            ])
        }
        guard authenticated else {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "authenticated": false,
                "error": "authentication required",
            ], statusLine: "HTTP/1.1 401 Unauthorized")
        }
        do {
            let challenge = try challengeIssuer(updates)
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": true,
                "auth_required": true,
                "challenge_id": challenge["challenge_id"] as? String ?? "",
                "seed": challenge["seed"] as? String ?? "",
                "updates_digest": challenge["updates_digest"] as? String ?? "",
            ])
        } catch {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "error": "failed to issue configuration change challenge",
            ], statusLine: "HTTP/1.1 400 Bad Request")
        }
    }

    static func validateConfigChallengePayload(
        payload: [String: Any],
        updates: [String: Any],
        authRequired: Bool,
        challengeValidator: (String, String, [String: Any]) -> String?
    ) -> ObstacleBridgeAdminAPIResponse? {
        guard authRequired else {
            return nil
        }
        let challengeID = (payload["challenge_id"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let proof = (payload["proof"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !challengeID.isEmpty, !proof.isEmpty else {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "error": "configuration change confirmation required",
            ], statusLine: "HTTP/1.1 428 Precondition Required")
        }
        if let error = challengeValidator(challengeID, proof, updates) {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "error": error,
            ], statusLine: "HTTP/1.1 403 Forbidden")
        }
        return nil
    }

    static func configUpdateSuccessResponse(
        maskedConfig: [String: Any],
        restartAfterSave: Bool,
        restartEmbedded: Bool
    ) -> ObstacleBridgeAdminAPIResponse {
        ObstacleBridgeAdminAPI.jsonResponse([
            "ok": true,
            "config": maskedConfig,
            "restart_requested": restartAfterSave,
            "restart_supported": true,
            "restart_mode": restartAfterSave ? "immediate" : "",
            "restart_delay_sec": 0,
            "restart_embedded": restartEmbedded,
        ])
    }
}
