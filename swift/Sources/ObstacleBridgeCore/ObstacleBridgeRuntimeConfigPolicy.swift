import Foundation

/// Portable scalar and overlay-limit policy shared by platform configuration adapters.
enum ObstacleBridgeRuntimeConfigPolicy {
    static func defaultTelemetryConfig() -> [String: Any] {
        [
            "telemetry_enabled": false,
            "telemetry_endpoint": "https://127.0.0.1:18443/v1/telemetry/batches",
            "telemetry_spool_directory": "/var/lib/obstaclebridge/telemetry-client",
        ]
    }

    static func intValue(from value: Any?) -> Int? {
        if let number = value as? NSNumber { return number.intValue }
        if let value = value as? Int { return value }
        if let value = value as? String { return Int(value) }
        return nil
    }

    static func doubleValue(from value: Any?) -> Double? {
        if let number = value as? NSNumber { return number.doubleValue }
        if let value = value as? Double { return value }
        if let value = value as? Int { return Double(value) }
        if let value = value as? String { return Double(value) }
        return nil
    }

    static func boolValue(from value: Any?) -> Bool? {
        if let value = value as? Bool { return value }
        if let number = value as? NSNumber { return number.boolValue }
        guard let value = value as? String else { return nil }
        switch value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "1", "true", "yes", "on": return true
        case "0", "false", "no", "off": return false
        default: return nil
        }
    }

    static func stringValue(from value: Any?) -> String? {
        guard let value else { return nil }
        if let string = value as? String {
            let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? nil : trimmed
        }
        return (value as? NSNumber)?.stringValue
    }

    static func overlaySessionMaxAppPayload(from payload: [String: Any]) -> Int {
        let transport = (stringValue(from: payload["overlay_transport"]) ?? "myudp").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        var limit = transport == "ws" ? max(1, intValue(from: payload["ws_max_size"]) ?? 65535) : 65535
        let secureLinkEnabled = boolValue(from: payload["secure_link"]) ?? false
        let secureLinkMode = (stringValue(from: payload["secure_link_mode"]) ?? "off").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if secureLinkEnabled, secureLinkMode != "off" { limit = max(0, limit - 20 - 16) }
        return max(0, limit)
    }

    static func overlayMaxInflight(from payload: [String: Any]) -> Int {
        min(32767, max(1, intValue(from: payload["max_inflight"]) ?? 200))
    }

    static func peerResolveFamilyValue(from value: Any?) -> String? {
        guard let raw = stringValue(from: value)?.lowercased() else { return nil }
        return ["prefer-ipv6", "ipv4", "ipv6"].contains(raw) ? raw : nil
    }
}
