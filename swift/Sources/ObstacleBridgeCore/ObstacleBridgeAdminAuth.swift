import Crypto
import Foundation

final class ObstacleBridgeAdminAuth {
    private static let authChallengeTTL: TimeInterval = 300
    private static let authSessionTTL: TimeInterval = 12 * 60 * 60

    private let queue: DispatchQueue
    private let authRequiredProvider: () -> Bool
    private let usernameProvider: () -> String
    private let passwordProvider: () -> String
    private let bearerTokenProvider: () -> String
    private let cookieScopeProvider: () -> String

    private var state = ObstacleBridgeAdminAuthPolicy.State()
    private var revealChallenges: [String: ObstacleBridgeAdminSecretRevealPolicy.Challenge] = [:]

    init(
        queueLabel: String,
        authRequiredProvider: @escaping () -> Bool,
        usernameProvider: @escaping () -> String,
        passwordProvider: @escaping () -> String,
        bearerTokenProvider: @escaping () -> String,
        cookieScopeProvider: @escaping () -> String
    ) {
        self.queue = DispatchQueue(label: queueLabel)
        self.authRequiredProvider = authRequiredProvider
        self.usernameProvider = usernameProvider
        self.passwordProvider = passwordProvider
        self.bearerTokenProvider = bearerTokenProvider
        self.cookieScopeProvider = cookieScopeProvider
    }

    func resetState() {
        queue.sync {
            state.reset()
            revealChallenges.removeAll()
        }
    }

    func issueSecretRevealChallenge(secretName: String) -> ObstacleBridgeAdminAPIResponse {
        guard authRequiredProvider() else {
            return ObstacleBridgeAdminAPI.jsonResponse(["ok": false, "error": "admin password authentication is required to reveal \(secretName)"], statusLine: "HTTP/1.1 403 Forbidden")
        }
        return queue.sync {
            let identifier = UUID().uuidString.lowercased()
            let seed = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased() + identifier
            let now = Date().timeIntervalSince1970
            revealChallenges = revealChallenges.filter { $0.value.expiresAt > now }
            revealChallenges[identifier] = ObstacleBridgeAdminSecretRevealPolicy.issue(identifier: identifier, seed: seed, secretName: secretName, now: now, ttl: 60)
            return ObstacleBridgeAdminAPI.jsonResponse(["ok": true, "auth_required": true, "challenge_id": identifier, "seed": seed, "secret_name": secretName])
        }
    }

    func revealSecret(body: Data?, secretName: String, secretValue: String) -> ObstacleBridgeAdminAPIResponse {
        guard authRequiredProvider() else {
            return ObstacleBridgeAdminAPI.jsonResponse(["ok": false, "error": "admin password authentication is required to reveal \(secretName)"], statusLine: "HTTP/1.1 403 Forbidden")
        }
        guard let body, let payload = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            return ObstacleBridgeAdminAPI.jsonResponse(["ok": false, "error": "invalid JSON body"], statusLine: "HTTP/1.1 400 Bad Request")
        }
        let identifier = (payload["challenge_id"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let proof = (payload["proof"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !identifier.isEmpty, !proof.isEmpty else {
            return ObstacleBridgeAdminAPI.jsonResponse(["ok": false, "error": "\(secretName) reveal confirmation required"], statusLine: "HTTP/1.1 428 Precondition Required")
        }
        let validation = queue.sync { () -> ObstacleBridgeAdminSecretRevealPolicy.ValidationResult? in
            guard let challenge = revealChallenges.removeValue(forKey: identifier) else { return nil }
            return ObstacleBridgeAdminSecretRevealPolicy.validate(challenge, proof: proof, secretName: secretName, username: usernameProvider(), password: passwordProvider(), now: Date().timeIntervalSince1970, digest: Self.sha256Hex)
        }
        guard let validation else {
            return ObstacleBridgeAdminAPI.jsonResponse(["ok": false, "error": "invalid or expired \(secretName) reveal challenge"], statusLine: "HTTP/1.1 403 Forbidden")
        }
        guard validation == .valid else {
            let error = validation == .proofMismatch ? "\(secretName) reveal confirmation failed" : "invalid or expired \(secretName) reveal challenge"
            return ObstacleBridgeAdminAPI.jsonResponse(["ok": false, "error": error], statusLine: "HTTP/1.1 403 Forbidden")
        }
        var generator = SystemRandomNumberGenerator()
        let salt = Data((0..<16).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
        let nonce = Data((0..<12).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
        guard let encrypted = try? ObstacleBridgeAdminSecretRevealPolicy.encryptedEnvelope(secretName: secretName, secretValue: secretValue, password: passwordProvider(), salt: salt, nonce: nonce) else {
            return ObstacleBridgeAdminAPI.jsonResponse(["ok": false, "error": "secret reveal encryption failed"], statusLine: "HTTP/1.1 500 Internal Server Error")
        }
        return ObstacleBridgeAdminAPI.jsonResponse(["ok": true, "secret_name": secretName, "encrypted": encrypted])
    }

    func isAuthenticated(headers: [String: String]) -> Bool {
        if !authRequiredProvider() {
            return true
        }
        return queue.sync {
            state.isAuthenticated(headers: headers, cookieName: sessionCookieName(), now: Date().timeIntervalSince1970)
        }
    }

    func authState(headers: [String: String]) -> [String: Any] {
        let required = authRequiredProvider()
        return [
            "ok": true,
            "auth_required": required,
            "authenticated": isAuthenticated(headers: headers),
            "username": required ? usernameProvider() : "",
        ]
    }

    func authChallenge(method: String) -> ObstacleBridgeAdminAPIResponse {
        guard method.uppercased() == "GET" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        guard authRequiredProvider() else {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": true,
                "auth_required": false,
            ])
        }
        return queue.sync {
            let challengeID = UUID().uuidString.lowercased()
            let seed = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased() + challengeID
            _ = state.issueChallenge(identifier: challengeID, seed: seed, now: Date().timeIntervalSince1970, ttl: Self.authChallengeTTL)
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": true,
                "auth_required": true,
                "challenge_id": challengeID,
                "seed": seed,
                "algorithm": "sha256(seed:username:password)",
            ])
        }
    }

    func authLogin(method: String, body: Data?) -> ObstacleBridgeAdminAPIResponse {
        guard method.uppercased() == "POST" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        guard authRequiredProvider() else {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": true,
                "auth_required": false,
                "authenticated": true,
            ], headers: issueSessionHeaders())
        }
        guard let body,
              let object = try? JSONSerialization.jsonObject(with: body),
              let payload = object as? [String: Any] else {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "error": "invalid JSON body",
            ], statusLine: "HTTP/1.1 400 Bad Request")
        }
        let challengeID = (payload["challenge_id"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let proof = (payload["proof"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let result = queue.sync {
            state.consumeChallenge(
                identifier: challengeID,
                proof: proof,
                username: usernameProvider(),
                password: passwordProvider(),
                now: Date().timeIntervalSince1970,
                digest: Self.sha256Hex
            )
        }
        switch result {
        case .invalidOrExpiredChallenge:
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "authenticated": false,
                "error": "invalid or expired challenge",
            ], statusLine: "HTTP/1.1 403 Forbidden")
        case .invalidProof:
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "authenticated": false,
                "error": "authentication failed",
            ], statusLine: "HTTP/1.1 403 Forbidden")
        case .authenticated:
            break
        }
        return ObstacleBridgeAdminAPI.jsonResponse([
            "ok": true,
            "authenticated": true,
        ], headers: issueSessionHeaders())
    }

    func authLogout(method: String, headers: [String: String]) -> ObstacleBridgeAdminAPIResponse {
        guard method.uppercased() == "POST" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        queue.sync { state.revokeSession(headers: headers, cookieName: sessionCookieName()) }
        return ObstacleBridgeAdminAPI.jsonResponse([
            "ok": true,
            "authenticated": false,
        ], headers: [expiredSessionHeader()])
    }

    func validateBearer(headers: [String: String]) -> ObstacleBridgeAdminAPIResponse? {
        let token = bearerTokenProvider().trimmingCharacters(in: .whitespacesAndNewlines)
        if token.isEmpty {
            return nil
        }
        if (headers["authorization"] ?? "") == "Bearer \(token)" {
            return nil
        }
        return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 403 Forbidden", body: "Forbidden")
    }

    private func issueSessionHeaders() -> [(String, String)] {
        let token = UUID().uuidString.replacingOccurrences(of: "-", with: "") + UUID().uuidString.replacingOccurrences(of: "-", with: "")
        queue.sync {
            state.issueSession(token: token, now: Date().timeIntervalSince1970, ttl: Self.authSessionTTL)
        }
        return [sessionHeader(token: token)]
    }

    private func sessionHeader(token: String) -> (String, String) {
        ObstacleBridgeAdminAuthPolicy.sessionHeader(cookieName: sessionCookieName(), token: token)
    }

    private func expiredSessionHeader() -> (String, String) {
        ObstacleBridgeAdminAuthPolicy.expiredSessionHeader(cookieName: sessionCookieName())
    }

    private func sessionCookieName() -> String {
        ObstacleBridgeAdminAuthPolicy.sessionCookieName(scope: cookieScopeProvider(), digest: Self.sha256Hex)
    }

    private static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
