import CryptoKit
import Darwin
import Foundation

enum ObstacleBridgeConfigSecretCodec {
    private static let salt = Data("ObstacleBridge config secret v1".utf8)
    private static let info = Data("ObstacleBridge config field encryption".utf8)
    private static let aad = Data("ObstacleBridge cfg secret".utf8)

    static func decryptPayload(_ payload: [String: Any]) throws -> [String: Any] {
        try ObstacleBridgeConfigSecretPolicy.decryptPayload(payload, decrypt: decryptSecret)
    }

    static func encryptPayload(_ payload: [String: Any]) throws -> [String: Any] {
        try ObstacleBridgeConfigSecretPolicy.encryptPayload(payload, encrypt: encryptSecret)
    }

    private static func encryptSecret(_ value: String) throws -> String {
        let key = derivedKey()
        let nonceData = Data((0..<12).map { _ in UInt8.random(in: 0...255) })
        let nonce = try ChaChaPoly.Nonce(data: nonceData)
        let sealed = try ChaChaPoly.seal(Data(value.utf8), using: key, nonce: nonce, authenticating: aad)
        return ObstacleBridgeConfigSecretPolicy.prefix + ObstacleBridgeConfigSecretPolicy.urlSafeBase64Encode(sealed.combined)
    }

    private static func decryptSecret(_ value: String) throws -> String {
        guard value.hasPrefix(ObstacleBridgeConfigSecretPolicy.prefix) else {
            return value
        }
        let encoded = String(value.dropFirst(ObstacleBridgeConfigSecretPolicy.prefix.count))
        let combined = try ObstacleBridgeConfigSecretPolicy.urlSafeBase64Decode(encoded)
        let sealed = try ChaChaPoly.SealedBox(combined: combined)
        let plaintext = try ChaChaPoly.open(sealed, using: derivedKey(), authenticating: aad)
        guard let stringValue = String(data: plaintext, encoding: .utf8) else {
            throw NSError(
                domain: "ObstacleBridge.ConfigSecretCodec",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "failed to decode config secret"]
            )
        }
        return stringValue
    }

    private static func derivedKey() -> SymmetricKey {
        let seed = configSecretSeed()
        guard let derived = ObstacleBridgeNativeCrypto.hkdfSHA256Salt(
            salt as NSData,
            info: info as NSData,
            keyMaterial: seed as NSData,
            lengthValue: 32
        ) as Data? else {
            return SymmetricKey(data: seed)
        }
        return SymmetricKey(data: derived)
    }

    private static func configSecretSeed() -> Data {
        var hostname = [CChar](repeating: 0, count: Int(MAXHOSTNAMELEN) + 1)
        if gethostname(&hostname, hostname.count) == 0,
           let text = String(validatingUTF8: hostname),
           !text.isEmpty {
            return Data(text.utf8)
        }
        let fallback = ProcessInfo.processInfo.hostName
        if !fallback.isEmpty {
            return Data(fallback.utf8)
        }
        return Data("obstacle-bridge".utf8)
    }

}
