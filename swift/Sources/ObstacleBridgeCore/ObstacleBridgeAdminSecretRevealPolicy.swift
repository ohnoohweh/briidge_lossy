import Foundation

/// Portable password-confirmed secret-reveal protocol. Adapters supply fresh
/// challenge and encryption material; proof validation and envelope format
/// remain identical across Admin server implementations.
public enum ObstacleBridgeAdminSecretRevealPolicy {
    public static let iterations = 200_000
    public static let aadPrefix = Data("ObstacleBridge WebAdmin secret reveal v1".utf8)

    public struct Challenge: Equatable {
        public let identifier: String
        public let seed: String
        public let secretName: String
        public let expiresAt: TimeInterval

        public init(identifier: String, seed: String, secretName: String, expiresAt: TimeInterval) {
            self.identifier = identifier
            self.seed = seed
            self.secretName = secretName
            self.expiresAt = expiresAt
        }
    }

    public enum ValidationResult: Equatable {
        case valid
        case expired
        case secretMismatch
        case proofMismatch
    }

    public static func issue(identifier: String, seed: String, secretName: String, now: TimeInterval, ttl: TimeInterval) -> Challenge {
        .init(identifier: identifier, seed: seed, secretName: secretName, expiresAt: now + max(0, ttl))
    }

    public static func validate(
        _ challenge: Challenge,
        proof: String,
        secretName: String,
        username: String,
        password: String,
        now: TimeInterval,
        digest: (Data) -> String
    ) -> ValidationResult {
        guard challenge.expiresAt > now else { return .expired }
        guard challenge.secretName == secretName else { return .secretMismatch }
        let expected = digest(Data("\(challenge.seed):\(username):\(password):\(secretName)".utf8))
        return proof == expected ? .valid : .proofMismatch
    }

    public static func encryptedEnvelope(
        secretName: String,
        secretValue: String,
        password: String,
        salt: Data,
        nonce: Data
    ) throws -> [String: Any] {
        let key = try ObstacleBridgeCrypto.pbkdf2SHA256(
            password: Data(password.utf8), salt: salt, iterations: iterations, outputByteCount: 32
        )
        let aad = aadPrefix + Data(":".utf8) + Data(secretName.utf8)
        let ciphertext = try ObstacleBridgeCrypto.aesGCMSeal(
            plaintext: Data(secretValue.utf8), key: key, nonce: nonce, authenticatedData: aad
        )
        return [
            "algorithm": "AES-GCM",
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": iterations,
            "salt": salt.base64EncodedString(),
            "nonce": nonce.base64EncodedString(),
            "aad": aad.base64EncodedString(),
            "ciphertext": ciphertext.base64EncodedString(),
        ]
    }
}
