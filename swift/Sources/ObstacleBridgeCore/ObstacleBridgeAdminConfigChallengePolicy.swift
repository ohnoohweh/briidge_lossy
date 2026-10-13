import Foundation

/// Portable configuration-change challenge policy. Platform adapters provide
/// random identifiers, time, and the cryptographic digest implementation.
public enum ObstacleBridgeAdminConfigChallengePolicy {
    public enum ValidationResult: Equatable {
        case valid
        case expired
        case updatesMismatch
        case proofMismatch
    }

    public struct Challenge: Equatable {
        public let identifier: String
        public let seed: String
        public let updatesDigest: String
        public let expiresAt: TimeInterval

        public init(identifier: String, seed: String, updatesDigest: String, expiresAt: TimeInterval) {
            self.identifier = identifier
            self.seed = seed
            self.updatesDigest = updatesDigest
            self.expiresAt = expiresAt
        }
    }

    public static func issue(
        identifier: String,
        seed: String,
        updates: [String: Any],
        now: TimeInterval,
        ttl: TimeInterval,
        digest: (Data) -> String
    ) throws -> Challenge {
        Challenge(
            identifier: identifier,
            seed: seed,
            updatesDigest: digest(try canonicalUpdateData(updates)),
            expiresAt: now + max(0, ttl)
        )
    }

    public static func validate(
        _ challenge: Challenge,
        proof: String,
        updates: [String: Any],
        username: String,
        password: String,
        now: TimeInterval,
        digest: (Data) -> String
    ) throws -> ValidationResult {
        guard challenge.expiresAt > now else { return .expired }
        let updatesDigest = digest(try canonicalUpdateData(updates))
        guard updatesDigest == challenge.updatesDigest else { return .updatesMismatch }
        let expected = digest(Data("\(challenge.seed):\(username):\(password):\(updatesDigest)".utf8))
        return proof == expected ? .valid : .proofMismatch
    }

    public static func canonicalUpdateData(_ updates: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: updates, options: [.sortedKeys])
    }
}
