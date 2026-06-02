import CryptoKit
import Darwin
import Foundation

enum ObstacleBridgeConfigSecretCodec {
    private static let secretFields: Set<String> = ["admin_web_password", "secure_link_psk"]
    private static let prefix = "enc:v1:"
    private static let salt = Data("ObstacleBridge config secret v1".utf8)
    private static let info = Data("ObstacleBridge config field encryption".utf8)
    private static let aad = Data("ObstacleBridge cfg secret".utf8)

    static func decryptPayload(_ payload: [String: Any]) throws -> [String: Any] {
        guard let decoded = try transformSecrets(in: payload, transform: decryptSecret) as? [String: Any] else {
            return payload
        }
        return decoded
    }

    static func encryptPayload(_ payload: [String: Any]) throws -> [String: Any] {
        guard let encoded = try transformSecrets(in: payload, transform: encryptSecret) as? [String: Any] else {
            return payload
        }
        return encoded
    }

    private static func transformSecrets(in object: Any, transform: (String) throws -> String) throws -> Any {
        if let dict = object as? [String: Any] {
            var out: [String: Any] = [:]
            out.reserveCapacity(dict.count)
            for (key, value) in dict {
                if secretFields.contains(key), let stringValue = value as? String {
                    out[key] = stringValue.isEmpty ? "" : try transform(stringValue)
                } else {
                    out[key] = try transformSecrets(in: value, transform: transform)
                }
            }
            return out
        }
        if let list = object as? [Any] {
            return try list.map { try transformSecrets(in: $0, transform: transform) }
        }
        return object
    }

    private static func encryptSecret(_ value: String) throws -> String {
        let key = derivedKey()
        let nonceData = Data((0..<12).map { _ in UInt8.random(in: 0...255) })
        let nonce = try ChaChaPoly.Nonce(data: nonceData)
        let sealed = try ChaChaPoly.seal(Data(value.utf8), using: key, nonce: nonce, authenticating: aad)
        return prefix + urlSafeBase64Encode(sealed.combined)
    }

    private static func decryptSecret(_ value: String) throws -> String {
        guard value.hasPrefix(prefix) else {
            return value
        }
        let encoded = String(value.dropFirst(prefix.count))
        let combined = try urlSafeBase64Decode(encoded)
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

    private static func urlSafeBase64Encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
    }

    private static func urlSafeBase64Decode(_ text: String) throws -> Data {
        var normalized = text
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = normalized.count % 4
        if remainder != 0 {
            normalized += String(repeating: "=", count: 4 - remainder)
        }
        guard let data = Data(base64Encoded: normalized) else {
            throw NSError(
                domain: "ObstacleBridge.ConfigSecretCodec",
                code: 2,
                userInfo: [NSLocalizedDescriptionKey: "invalid base64 config secret"]
            )
        }
        return data
    }
}
