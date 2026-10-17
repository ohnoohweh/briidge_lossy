import Crypto
import Foundation

final class ObstacleBridgeAdminConfigChallenge {
    private static let defaultTTL: TimeInterval = 60

    private let queue: DispatchQueue
    private let usernameProvider: () -> String
    private let passwordProvider: () -> String
    private let ttl: TimeInterval
    private var challenges: [String: ObstacleBridgeAdminConfigChallengePolicy.Challenge] = [:]

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
        let now = Date().timeIntervalSince1970
        let challenge = try ObstacleBridgeAdminConfigChallengePolicy.issue(
            identifier: challengeID,
            seed: seed,
            updates: updates,
            now: now,
            ttl: ttl,
            digest: Self.sha256Hex
        )
        queue.sync {
            pruneLocked()
            challenges[challengeID] = challenge
        }
        return [
            "challenge_id": challengeID,
            "seed": seed,
            "updates_digest": challenge.updatesDigest,
        ]
    }

    func validate(challengeID: String, proof: String, updates: [String: Any]) -> String? {
        queue.sync {
            pruneLocked()
            guard let challenge = challenges.removeValue(forKey: challengeID) else {
                return "invalid or expired configuration change challenge"
            }
            do {
                let result = try ObstacleBridgeAdminConfigChallengePolicy.validate(
                    challenge,
                    proof: proof,
                    updates: updates,
                    username: usernameProvider(),
                    password: passwordProvider(),
                    now: Date().timeIntervalSince1970,
                    digest: Self.sha256Hex
                )
                switch result {
                case .valid:
                    return nil
                case .updatesMismatch:
                    return "configuration update payload mismatch"
                case .expired:
                    return "invalid or expired configuration change challenge"
                case .proofMismatch:
                    return "configuration change confirmation failed"
                }
            } catch {
                return "failed to digest configuration updates"
            }
        }
    }

    private func pruneLocked() {
        let now = Date().timeIntervalSince1970
        challenges = challenges.filter { _, item in
            item.expiresAt > now
        }
    }

    private static func sha256Hex(_ data: Data) -> String {
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
