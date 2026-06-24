import CryptoKit
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

    private var authChallenges: [String: [String: Any]] = [:]
    private var authSessions: [String: TimeInterval] = [:]

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
            authChallenges.removeAll()
            authSessions.removeAll()
        }
    }

    func isAuthenticated(headers: [String: String]) -> Bool {
        if !authRequiredProvider() {
            return true
        }
        return queue.sync {
            pruneStateLocked()
            let token = Self.parseCookieHeader(headers)[sessionCookieName()] ?? ""
            return !token.isEmpty && authSessions[token] != nil
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
            pruneStateLocked()
            let challengeID = UUID().uuidString.lowercased()
            let seed = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased() + challengeID
            authChallenges[challengeID] = [
                "seed": seed,
                "expires_at": Date().timeIntervalSince1970 + Self.authChallengeTTL,
            ]
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
        let seed: String? = queue.sync {
            pruneStateLocked()
            let item = authChallenges.removeValue(forKey: challengeID)
            return item?["seed"] as? String
        }
        guard let seed else {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "authenticated": false,
                "error": "invalid or expired challenge",
            ], statusLine: "HTTP/1.1 403 Forbidden")
        }
        let expected = Self.buildAuthProof(seed: seed, username: usernameProvider(), password: passwordProvider())
        guard proof == expected else {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "authenticated": false,
                "error": "authentication failed",
            ], statusLine: "HTTP/1.1 403 Forbidden")
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
        let token = Self.parseCookieHeader(headers)[sessionCookieName()] ?? ""
        if !token.isEmpty {
            _ = queue.sync {
                authSessions.removeValue(forKey: token)
            }
        }
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
            pruneStateLocked()
            authSessions[token] = Date().timeIntervalSince1970 + Self.authSessionTTL
        }
        return [sessionHeader(token: token)]
    }

    private func sessionHeader(token: String) -> (String, String) {
        ("Set-Cookie", "\(sessionCookieName())=\(token); Path=/; HttpOnly; SameSite=Strict")
    }

    private func expiredSessionHeader() -> (String, String) {
        ("Set-Cookie", "\(sessionCookieName())=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
    }

    private func sessionCookieName() -> String {
        let digest = SHA256.hash(data: Data(cookieScopeProvider().utf8)).map { String(format: "%02x", $0) }.joined()
        return "admin_web_session_\(digest.prefix(12))"
    }

    private func pruneStateLocked() {
        let now = Date().timeIntervalSince1970
        authChallenges = authChallenges.filter { _, item in
            (item["expires_at"] as? TimeInterval ?? 0) > now
        }
        authSessions = authSessions.filter { _, expiresAt in
            expiresAt > now
        }
    }

    private static func parseCookieHeader(_ headers: [String: String]) -> [String: String] {
        let raw = headers["cookie"] ?? ""
        var cookies: [String: String] = [:]
        for part in raw.split(separator: ";") {
            let item = String(part).trimmingCharacters(in: .whitespacesAndNewlines)
            guard !item.isEmpty, let equals = item.firstIndex(of: "=") else {
                continue
            }
            let key = String(item[..<equals]).trimmingCharacters(in: .whitespacesAndNewlines)
            let value = String(item[item.index(after: equals)...]).trimmingCharacters(in: .whitespacesAndNewlines)
            cookies[key] = value
        }
        return cookies
    }

    private static func buildAuthProof(seed: String, username: String, password: String) -> String {
        SHA256.hash(data: Data("\(seed):\(username):\(password)".utf8)).map { String(format: "%02x", $0) }.joined()
    }
}
