import Foundation

/// Portable configuration-secret envelope policy. Platform adapters provide
/// the actual cryptographic sealing and opening operations.
enum ObstacleBridgeConfigSecretPolicy {
    static let prefix = "enc:v1:"
    private static let secretFields: Set<String> = ["admin_web_password", "secure_link_psk"]

    static func encryptPayload(
        _ payload: [String: Any],
        encrypt: (String) throws -> String
    ) throws -> [String: Any] {
        guard let encoded = try transformSecrets(in: payload, transform: encrypt) as? [String: Any] else {
            return payload
        }
        return encoded
    }

    static func decryptPayload(
        _ payload: [String: Any],
        decrypt: (String) throws -> String
    ) throws -> [String: Any] {
        guard let decoded = try transformSecrets(in: payload, transform: decrypt) as? [String: Any] else {
            return payload
        }
        return decoded
    }

    static func urlSafeBase64Encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
    }

    static func urlSafeBase64Decode(_ text: String) throws -> Data {
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
}
