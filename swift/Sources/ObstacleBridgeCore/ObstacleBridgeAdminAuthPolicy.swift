import Foundation

/// Portable Admin-authentication state and policy. Adapters supply random
/// values, time, and the cryptographic digest implementation.
public enum ObstacleBridgeAdminAuthPolicy {
    public struct Challenge: Equatable {
        public let identifier: String
        public let seed: String
        public let expiresAt: TimeInterval
    }

    public enum LoginResult: Equatable {
        case authenticated
        case invalidOrExpiredChallenge
        case invalidProof
    }

    public struct State {
        private var challenges: [String: Challenge] = [:]
        private var sessions: [String: TimeInterval] = [:]

        public init() {}

        public mutating func reset() {
            challenges.removeAll()
            sessions.removeAll()
        }

        public mutating func issueChallenge(identifier: String, seed: String, now: TimeInterval, ttl: TimeInterval) -> Challenge {
            prune(now: now)
            let challenge = Challenge(identifier: identifier, seed: seed, expiresAt: now + max(0, ttl))
            challenges[identifier] = challenge
            return challenge
        }

        public mutating func consumeChallenge(
            identifier: String,
            proof: String,
            username: String,
            password: String,
            now: TimeInterval,
            digest: (Data) -> String
        ) -> LoginResult {
            prune(now: now)
            guard let challenge = challenges.removeValue(forKey: identifier), challenge.expiresAt > now else {
                return .invalidOrExpiredChallenge
            }
            let expected = digest(Data("\(challenge.seed):\(username):\(password)".utf8))
            return proof == expected ? .authenticated : .invalidProof
        }

        public mutating func issueSession(token: String, now: TimeInterval, ttl: TimeInterval) {
            prune(now: now)
            sessions[token] = now + max(0, ttl)
        }

        public mutating func isAuthenticated(headers: [String: String], cookieName: String, now: TimeInterval) -> Bool {
            prune(now: now)
            guard let token = parseCookieHeader(headers)[cookieName], !token.isEmpty else { return false }
            return sessions[token] != nil
        }

        public mutating func revokeSession(headers: [String: String], cookieName: String) {
            guard let token = parseCookieHeader(headers)[cookieName], !token.isEmpty else { return }
            sessions.removeValue(forKey: token)
        }

        public mutating func prune(now: TimeInterval) {
            challenges = challenges.filter { $0.value.expiresAt > now }
            sessions = sessions.filter { $0.value > now }
        }
    }

    public static func parseCookieHeader(_ headers: [String: String]) -> [String: String] {
        let raw = headers["cookie"] ?? ""
        var cookies: [String: String] = [:]
        for part in raw.split(separator: ";") {
            let item = String(part).trimmingCharacters(in: .whitespacesAndNewlines)
            guard !item.isEmpty, let equals = item.firstIndex(of: "=") else { continue }
            let key = String(item[..<equals]).trimmingCharacters(in: .whitespacesAndNewlines)
            let value = String(item[item.index(after: equals)...]).trimmingCharacters(in: .whitespacesAndNewlines)
            cookies[key] = value
        }
        return cookies
    }

    public static func sessionCookieName(scope: String, digest: (Data) -> String) -> String {
        "admin_web_session_\(digest(Data(scope.utf8)).prefix(12))"
    }

    public static func sessionHeader(cookieName: String, token: String) -> (String, String) {
        ("Set-Cookie", "\(cookieName)=\(token); Path=/; HttpOnly; SameSite=Strict")
    }

    public static func expiredSessionHeader(cookieName: String) -> (String, String) {
        ("Set-Cookie", "\(cookieName)=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
    }
}
