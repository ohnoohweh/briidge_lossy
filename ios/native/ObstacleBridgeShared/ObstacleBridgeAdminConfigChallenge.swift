import CryptoKit
import Foundation

final class ObstacleBridgeAdminConfigChallenge {
    private static let defaultTTL: TimeInterval = 60

    private let queue: DispatchQueue
    private let usernameProvider: () -> String
    private let passwordProvider: () -> String
    private let ttl: TimeInterval
    private var challenges: [String: [String: Any]] = [:]

    init(
        queueLabel: String,
        ttl: TimeInterval = ObstacleBridgeAdminConfigChallenge.defaultTTL,
        usernameProvider: @escaping () -> String,
        passwordProvider: @escaping () -> String
    ) {
        self.queue = DispatchQueue(label: queueLabel)
        self.ttl = ttl
        self.usernameProvider = usernameProvider
        self.passwordProvider = passwordProvider
    }

    func reset() {
        queue.sync {
            challenges.removeAll()
        }
    }

    func issueChallenge(updates: [String: Any]) throws -> [String: Any] {
        let challengeID = UUID().uuidString.lowercased()
        let seed = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased() + challengeID
        let updatesDigest = try Self.configUpdateDigest(updates)
        queue.sync {
            pruneLocked()
            challenges[challengeID] = [
                "seed": seed,
                "updates_digest": updatesDigest,
                "expires_at": Date().timeIntervalSince1970 + ttl,
            ]
        }
        return [
            "challenge_id": challengeID,
            "seed": seed,
            "updates_digest": updatesDigest,
        ]
    }

    func validate(challengeID: String, proof: String, updates: [String: Any]) -> String? {
        queue.sync {
            pruneLocked()
            guard let challenge = challenges.removeValue(forKey: challengeID) else {
                return "invalid or expired configuration change challenge"
            }
            let updatesDigest: String
            do {
                updatesDigest = try Self.configUpdateDigest(updates)
            } catch {
                return "failed to digest configuration updates"
            }
            guard updatesDigest == String(describing: challenge["updates_digest"] ?? "") else {
                return "configuration update payload mismatch"
            }
            let expected = Self.buildProof(
                seed: String(describing: challenge["seed"] ?? ""),
                username: usernameProvider(),
                password: passwordProvider(),
                updatesDigest: updatesDigest
            )
            return proof == expected ? nil : "configuration change confirmation failed"
        }
    }

    private func pruneLocked() {
        let now = Date().timeIntervalSince1970
        challenges = challenges.filter { _, item in
            (item["expires_at"] as? TimeInterval ?? 0) > now
        }
    }

    private static func canonicalConfigUpdateData(_ updates: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: updates, options: [.sortedKeys])
    }

    private static func configUpdateDigest(_ updates: [String: Any]) throws -> String {
        let data = try canonicalConfigUpdateData(updates)
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func buildProof(seed: String, username: String, password: String, updatesDigest: String) -> String {
        SHA256.hash(data: Data("\(seed):\(username):\(password):\(updatesDigest)".utf8)).map { String(format: "%02x", $0) }.joined()
    }
}
