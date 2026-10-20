import Foundation
import ObstacleBridgeCore

/// Core-auth policy owner for the Linux HTTP adapter. It provides only the
/// platform inputs (time, randomness, cookies); proof and update binding stay
/// in the portable Core policies.
final class ObstacleBridgeLinuxAdminSecurity: @unchecked Sendable {
    private let lock = NSLock()
    private var authState = ObstacleBridgeAdminAuthPolicy.State()
    private var configChallenges: [String: ObstacleBridgeAdminConfigChallengePolicy.Challenge] = [:]
    private var revealChallenges: [String: ObstacleBridgeAdminSecretRevealPolicy.Challenge] = [:]
    private let credentials: () -> (required: Bool, username: String, password: String)
    private let scope: () -> String

    init(credentials: @escaping () -> (required: Bool, username: String, password: String), scope: @escaping () -> String) {
        self.credentials = credentials; self.scope = scope
    }

    func isAuthenticated(headers: [String: String]) -> Bool {
        let settings = credentials(); guard settings.required else { return true }
        lock.lock(); defer { lock.unlock() }
        return authState.isAuthenticated(headers: headers, cookieName: cookieName(), now: Date().timeIntervalSince1970)
    }

    func state(headers: [String: String]) -> [String: Any] {
        let settings = credentials()
        return ["ok": true, "auth_required": settings.required, "authenticated": isAuthenticated(headers: headers)]
    }

    func issueLoginChallenge() -> [String: Any] {
        let settings = credentials(); guard settings.required else { return ["ok": true, "auth_required": false] }
        let identifier = UUID().uuidString.lowercased()
        let seed = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased() + identifier
        lock.lock(); defer { lock.unlock() }
        _ = authState.issueChallenge(identifier: identifier, seed: seed, now: Date().timeIntervalSince1970, ttl: 300)
        return ["ok": true, "auth_required": true, "challenge_id": identifier, "seed": seed, "algorithm": "sha256(seed:username:password)"]
    }

    func login(body: Data?) -> ObstacleBridgeAdminLinuxResponse {
        let settings = credentials()
        guard settings.required else { return json(["ok": true, "auth_required": false, "authenticated": true], headers: sessionHeaders()) }
        guard let body, let payload = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else { return json(["ok": false, "error": "invalid JSON body"], status: 400) }
        let identifier = (payload["challenge_id"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let proof = (payload["proof"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        lock.lock(); let result = authState.consumeChallenge(identifier: identifier, proof: proof, username: settings.username, password: settings.password, now: Date().timeIntervalSince1970, digest: Self.sha256Hex); lock.unlock()
        switch result {
        case .authenticated: return json(["ok": true, "authenticated": true], headers: sessionHeaders())
        case .invalidOrExpiredChallenge: return json(["ok": false, "authenticated": false, "error": "invalid or expired challenge"], status: 403)
        case .invalidProof: return json(["ok": false, "authenticated": false, "error": "authentication failed"], status: 403)
        }
    }

    func logout(headers: [String: String]) -> ObstacleBridgeAdminLinuxResponse {
        lock.lock(); authState.revokeSession(headers: headers, cookieName: cookieName()); lock.unlock()
        return json(["ok": true, "authenticated": false], headers: [ObstacleBridgeAdminAuthPolicy.expiredSessionHeader(cookieName: cookieName())])
    }

    func reset() {
        lock.lock()
        defer { lock.unlock() }
        authState.reset()
        configChallenges.removeAll()
        revealChallenges.removeAll()
    }

    func issueSecretRevealChallenge(secretName: String) -> [String: Any] {
        let identifier = UUID().uuidString.lowercased()
        let seed = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased() + identifier
        let challenge = ObstacleBridgeAdminSecretRevealPolicy.issue(
            identifier: identifier, seed: seed, secretName: secretName,
            now: Date().timeIntervalSince1970, ttl: 60
        )
        lock.lock()
        defer { lock.unlock() }
        revealChallenges = revealChallenges.filter { $0.value.expiresAt > Date().timeIntervalSince1970 }
        revealChallenges[identifier] = challenge
        return ["ok": true, "auth_required": true, "challenge_id": identifier, "seed": seed, "secret_name": secretName]
    }

    func revealSecret(body: Data?, secretName: String, secretValue: String) -> ObstacleBridgeAdminLinuxResponse {
        let settings = credentials()
        guard settings.required else {
            return json(["ok": false, "error": "admin password authentication is required to reveal \(secretName)"], status: 403)
        }
        guard let body, let payload = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            return json(["ok": false, "error": "invalid JSON body"], status: 400)
        }
        let identifier = (payload["challenge_id"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let proof = (payload["proof"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !identifier.isEmpty, !proof.isEmpty else {
            return json(["ok": false, "error": "\(secretName) reveal confirmation required"], status: 428)
        }
        lock.lock()
        let challenge = revealChallenges.removeValue(forKey: identifier)
        lock.unlock()
        guard let challenge else {
            return json(["ok": false, "error": "invalid or expired \(secretName) reveal challenge"], status: 403)
        }
        let result = ObstacleBridgeAdminSecretRevealPolicy.validate(
            challenge, proof: proof, secretName: secretName, username: settings.username,
            password: settings.password, now: Date().timeIntervalSince1970, digest: Self.sha256Hex
        )
        switch result {
        case .expired:
            return json(["ok": false, "error": "invalid or expired \(secretName) reveal challenge"], status: 403)
        case .secretMismatch:
            return json(["ok": false, "error": "secret reveal payload mismatch"], status: 403)
        case .proofMismatch:
            return json(["ok": false, "error": "\(secretName) reveal confirmation failed"], status: 403)
        case .valid:
            break
        }
        var generator = SystemRandomNumberGenerator()
        let salt = Data((0..<16).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
        let nonce = Data((0..<12).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
        do {
            let envelope = try ObstacleBridgeAdminSecretRevealPolicy.encryptedEnvelope(
                secretName: secretName, secretValue: secretValue, password: settings.password,
                salt: salt, nonce: nonce
            )
            return json(["ok": true, "secret_name": secretName, "encrypted": envelope])
        } catch {
            return json(["ok": false, "error": "secret reveal encryption failed"], status: 500)
        }
    }

    func issueConfigChallenge(updates: [String: Any]) throws -> [String: Any] {
        let identifier = UUID().uuidString.lowercased(), seed = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased() + identifier
        let challenge = try ObstacleBridgeAdminConfigChallengePolicy.issue(identifier: identifier, seed: seed, updates: updates, now: Date().timeIntervalSince1970, ttl: 60, digest: Self.sha256Hex)
        lock.lock(); defer { lock.unlock() }
        configChallenges = configChallenges.filter { $0.value.expiresAt > Date().timeIntervalSince1970 }; configChallenges[identifier] = challenge
        return ["ok": true, "auth_required": true, "challenge_id": identifier, "seed": seed, "updates_digest": challenge.updatesDigest]
    }

    func validateConfigChallenge(body: Data?) -> String? {
        guard let body, let payload = try? JSONSerialization.jsonObject(with: body) as? [String: Any], let updates = payload["updates"] as? [String: Any] else { return "invalid JSON body or updates must be an object" }
        let identifier = (payload["challenge_id"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines), proof = (payload["proof"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased(), settings = credentials()
        lock.lock(); defer { lock.unlock() }
        guard let challenge = configChallenges.removeValue(forKey: identifier) else { return "invalid or expired configuration change challenge" }
        guard let outcome = try? ObstacleBridgeAdminConfigChallengePolicy.validate(challenge, proof: proof, updates: updates, username: settings.username, password: settings.password, now: Date().timeIntervalSince1970, digest: Self.sha256Hex) else { return "failed to digest configuration updates" }
        switch outcome { case .valid: return nil; case .expired: return "invalid or expired configuration change challenge"; case .updatesMismatch: return "configuration update payload mismatch"; case .proofMismatch: return "configuration change confirmation failed" }
    }

    private func sessionHeaders() -> [(String, String)] {
        let token = UUID().uuidString.replacingOccurrences(of: "-", with: "") + UUID().uuidString.replacingOccurrences(of: "-", with: "")
        lock.lock(); authState.issueSession(token: token, now: Date().timeIntervalSince1970, ttl: 12 * 60 * 60); lock.unlock()
        return [ObstacleBridgeAdminAuthPolicy.sessionHeader(cookieName: cookieName(), token: token)]
    }
    private func cookieName() -> String { ObstacleBridgeAdminAuthPolicy.sessionCookieName(scope: scope(), digest: Self.sha256Hex) }
    private static func sha256Hex(_ data: Data) -> String { ObstacleBridgeCrypto.sha256(data).map { String(format: "%02x", $0) }.joined() }
    private func json(_ payload: [String: Any], status: Int = 200, headers: [(String, String)] = []) -> ObstacleBridgeAdminLinuxResponse { guard let response = ObstacleBridgeAdminAPI.linuxJSONResponse(payload, statusCode: status) else { return .init(statusCode: 500, body: Data("{}".utf8)) }; return .init(statusCode: response.statusCode, body: response.body, contentType: response.contentType, headers: headers) }
}
