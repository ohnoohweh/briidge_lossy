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

    static func wsPeerAddresses(from value: Any?) -> [String] {
        let values = (value as? [Any]) ?? (value.map { [$0] } ?? [])
        var addresses: [String] = []
        for value in values {
            guard let rendered = stringValue(from: value) else { continue }
            for token in rendered.replacingOccurrences(of: ";", with: ",").split(separator: ",", omittingEmptySubsequences: false) {
                let trimmed = String(token).trimmingCharacters(in: .whitespacesAndNewlines)
                let address = trimmed.hasPrefix("[") && trimmed.hasSuffix("]") ? String(trimmed.dropFirst().dropLast()) : trimmed
                if !address.isEmpty, !addresses.contains(address) { addresses.append(address) }
            }
        }
        return addresses
    }

    static func peerHost(for transport: String, payload: [String: Any]) -> String? {
        let keys = ["myudp": "udp_peer", "tcp": "tcp_peer", "quic": "quic_peer", "ws": "ws_peer"]
        return keys[transport].flatMap { stringValue(from: payload[$0]) }
    }

    static func peerPort(for transport: String, payload: [String: Any]) -> Int? {
        let keys = ["myudp": "udp_peer_port", "tcp": "tcp_peer_port", "quic": "quic_peer_port", "ws": "ws_peer_port"]
        return keys[transport].flatMap { intValue(from: payload[$0]) }
    }

    static func overlayPeerExcludedRoutes(from flatPayload: [String: Any]) -> (ipv4: [String], ipv6: [String]) {
        let transport = (stringValue(from: flatPayload["overlay_transport"]) ?? "myudp")
            .split(separator: ",").map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
            .first(where: { !$0.isEmpty }) ?? "myudp"
        guard let host = peerHost(for: transport, payload: flatPayload),
              let port = peerPort(for: transport, payload: flatPayload), port > 0 else { return ([], []) }
        let resolveFamily = resolveFamily(for: transport, payload: flatPayload)
        let bindHost = bindHost(for: transport, payload: flatPayload)
        let wsAddresses = transport == "ws" ? wsPeerAddresses(from: flatPayload["ws_peer_addresses"]) : []
        let candidates = wsAddresses.isEmpty ? splitConfiguredPeerHosts(host) : wsAddresses
        var ipv4: [String] = []; var ipv6: [String] = []
        for host in candidates {
            guard let route = ObstacleBridgePacketTunnelRoutePolicy.hostRouteCIDR(host) else { continue }
            if route.isIPv6 {
                if resolveFamily != "ipv4" { ipv6.append(route.route) }
            } else if resolveFamily != "ipv6" {
                ipv4.append(route.route)
                if resolveFamily != "ipv4", bindHost == "::", let mapped = ObstacleBridgePacketTunnelRoutePolicy.ipv4MappedIPv6RouteCIDR(host) { ipv6.append(mapped) }
            }
        }
        return (dedupeRoutes(ipv4), dedupeRoutes(ipv6))
    }

    static func effectiveExcludedRoutes(from flatPayload: [String: Any], baseIPv4: [String], baseIPv6: [String]) -> (ipv4: [String], ipv6: [String]) {
        let peerRoutes = overlayPeerExcludedRoutes(from: flatPayload)
        return (dedupeRoutes(baseIPv4 + peerRoutes.ipv4), dedupeRoutes(baseIPv6 + peerRoutes.ipv6))
    }

    private static func bindHost(for transport: String, payload: [String: Any]) -> String {
        let keys = ["myudp": "udp_bind", "tcp": "tcp_bind", "quic": "quic_bind", "ws": "ws_bind"]
        return keys[transport].flatMap { stringValue(from: payload[$0]) } ?? "::"
    }

    private static func resolveFamily(for transport: String, payload: [String: Any]) -> String {
        let keys = ["myudp": "udp_peer_resolve_family", "tcp": "tcp_peer_resolve_family", "quic": "quic_peer_resolve_family", "ws": "ws_peer_resolve_family"]
        return keys[transport].flatMap { peerResolveFamilyValue(from: payload[$0]) } ?? "prefer-ipv6"
    }

    private static func splitConfiguredPeerHosts(_ host: String) -> [String] {
        host.replacingOccurrences(of: ";", with: ",").split(separator: ",")
            .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
    }

    private static func dedupeRoutes(_ values: [String]) -> [String] {
        var seen: Set<String> = []
        return values.compactMap { value in
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            return !trimmed.isEmpty && seen.insert(trimmed).inserted ? trimmed : nil
        }
    }
}
