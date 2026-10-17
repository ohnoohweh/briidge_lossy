import Foundation

/// Public redaction boundary for platform-owned configuration exports.
public enum ObstacleBridgeAdminConfigProjectionPort {
    public static func redacted(_ payload: [String: Any]) -> [String: Any] {
        redact(payload) as? [String: Any] ?? [:]
    }

    private static func redact(_ value: Any) -> Any {
        if let object = value as? [String: Any] {
            var output: [String: Any] = [:]
            for (key, nested) in object {
                if isSecret(key) {
                    let present = (nested as? String)?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false
                    output[key] = "***hidden***"
                    output["\(key)_present"] = present
                } else {
                    output[key] = redact(nested)
                }
            }
            return output
        }
        if let values = value as? [Any] { return values.map(redact) }
        return value
    }

    private static func isSecret(_ key: String) -> Bool {
        let normalized = key.lowercased()
        return normalized.contains("password") || normalized.contains("psk") || normalized.contains("private_key") || normalized.contains("cert_sig")
    }
}

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
