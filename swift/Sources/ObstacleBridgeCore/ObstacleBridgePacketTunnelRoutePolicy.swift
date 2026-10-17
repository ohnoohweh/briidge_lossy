import Foundation

struct ObstacleBridgePacketTunnelIPv4RouteSpec {
    let destinationAddress: String
    let subnetMask: String
}

struct ObstacleBridgePacketTunnelIPv6RouteSpec {
    let destinationAddress: String
    let networkPrefixLength: Int
}

enum ObstacleBridgePacketTunnelRoutePolicy {
    static func routes(_ values: [String]) throws -> [ObstacleBridgePacketTunnelIPv4RouteSpec] {
        try values.map { cidr in
            let parts = cidr.split(separator: "/", maxSplits: 1).map(String.init)
            guard parts.count == 2, let prefix = Int(parts[1]), (0...32).contains(prefix) else {
                throw ObstacleBridgePacketTunnelConfigurationError.invalidRoute(cidr)
            }
            return .init(destinationAddress: parts[0], subnetMask: subnetMask(prefix))
        }
    }

    static func routes6(_ values: [String]) throws -> [ObstacleBridgePacketTunnelIPv6RouteSpec] {
        try values.map { cidr in
            let parts = cidr.split(separator: "/", maxSplits: 1).map(String.init)
            guard parts.count == 2, let prefix = Int(parts[1]), (0...128).contains(prefix) else {
                throw ObstacleBridgePacketTunnelConfigurationError.invalidRoute(cidr)
            }
            return .init(destinationAddress: parts[0], networkPrefixLength: prefix)
        }
    }

    static func subnetMask(_ prefix: Int) -> String {
        let mask = prefix == 0 ? 0 : UInt32.max << UInt32(32 - prefix)
        return [(mask >> 24) & 0xff, (mask >> 16) & 0xff, (mask >> 8) & 0xff, mask & 0xff]
            .map(String.init).joined(separator: ".")
    }

    static func ipv4RouteContains(host: String, network: String, prefix: Int) -> Bool {
        guard (0...32).contains(prefix), let hostValue = ipv4Value(host), let networkValue = ipv4Value(network) else {
            return false
        }
        if prefix == 0 { return true }
        let mask = UInt32.max << UInt32(32 - prefix)
        return (hostValue & mask) == (networkValue & mask)
    }

    static func ipv6RouteContains(host: String, network: String, prefix: Int) -> Bool {
        guard (0...128).contains(prefix), let hostBytes = ipv6Bytes(host), let networkBytes = ipv6Bytes(network),
              hostBytes.count == 16, networkBytes.count == 16 else {
            return false
        }
        if prefix == 0 { return true }
        let fullBytes = prefix / 8
        let remainingBits = prefix % 8
        for index in 0..<fullBytes where hostBytes[index] != networkBytes[index] { return false }
        if remainingBits == 0 { return true }
        guard fullBytes < hostBytes.count else { return false }
        let mask = UInt8.max << UInt8(8 - remainingBits)
        return (hostBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask)
    }

    static func routeDiagnostics(
        includedIPv4: [String], baseExcludedIPv4: [String], autoExcludedIPv4: [String], effectiveExcludedIPv4: [String],
        includedIPv6: [String], baseExcludedIPv6: [String], autoExcludedIPv6: [String], effectiveExcludedIPv6: [String]
    ) -> [String: Any] {
        [
            "ipv4": diagnosticFamily(included: includedIPv4, baseExcluded: baseExcludedIPv4, autoExcluded: autoExcludedIPv4, effectiveExcluded: effectiveExcludedIPv4, probeSeed: "127.0.0.1", version: 4),
            "ipv6": diagnosticFamily(included: includedIPv6, baseExcluded: baseExcludedIPv6, autoExcluded: autoExcludedIPv6, effectiveExcluded: effectiveExcludedIPv6, probeSeed: "::1", version: 6),
        ]
    }

    static func hostRouteCIDR(_ host: String) -> (route: String, isIPv6: Bool)? {
        let trimmed = stripBrackets(host)
        guard !trimmed.isEmpty else { return nil }
        let normalized = trimmed.hasPrefix("::ffff:") ? String(trimmed.dropFirst(7)) : trimmed
        if ipv4Value(normalized) != nil { return ("\(normalized)/32", false) }
        if ipv6Bytes(normalized) != nil { return ("\(normalized)/128", true) }
        return nil
    }

    static func ipv4MappedIPv6RouteCIDR(_ host: String) -> String? {
        let trimmed = stripBrackets(host)
        let normalized = trimmed.hasPrefix("::ffff:") ? String(trimmed.dropFirst(7)) : trimmed
        guard ipv4Value(normalized) != nil else { return nil }
        return "::ffff:\(normalized)/128"
    }

    private static func ipv4Value(_ host: String) -> UInt32? {
        let parts = host.split(separator: ".").map(String.init)
        guard parts.count == 4 else { return nil }
        var value: UInt32 = 0
        for part in parts {
            guard let octet = UInt8(part) else { return nil }
            value = (value << 8) | UInt32(octet)
        }
        return value
    }

    private static func stripBrackets(_ host: String) -> String {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix("["), trimmed.hasSuffix("]") else { return trimmed }
        return String(trimmed.dropFirst().dropLast())
    }

    private static func ipv6Bytes(_ host: String) -> [UInt8]? {
        let text = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        guard !text.isEmpty else { return nil }
        let halves = text.components(separatedBy: "::")
        guard halves.count <= 2 else { return nil }
        func groups(_ part: String) -> [String]? {
            guard !part.isEmpty else { return [] }
            var output = part.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
            guard !output.contains("") else { return nil }
            if let last = output.last, last.contains(".") {
                guard let ipv4 = ipv4Value(last) else { return nil }
                output.removeLast()
                output.append(String(format: "%x", (ipv4 >> 16) & 0xffff))
                output.append(String(format: "%x", ipv4 & 0xffff))
            }
            return output
        }
        guard let left = groups(halves[0]), let right = groups(halves.count == 2 ? halves[1] : "") else { return nil }
        let total = left.count + right.count
        let values: [String]
        if halves.count == 2 {
            guard total < 8 else { return nil }
            values = left + Array(repeating: "0", count: 8 - total) + right
        } else {
            guard total == 8 else { return nil }
            values = left
        }
        var bytes: [UInt8] = []
        for value in values {
            guard let group = UInt16(value, radix: 16) else { return nil }
            bytes.append(UInt8(group >> 8)); bytes.append(UInt8(group & 0xff))
        }
        return bytes
    }

    private static func diagnosticFamily(included: [String], baseExcluded: [String], autoExcluded: [String], effectiveExcluded: [String], probeSeed: String, version: Int) -> [String: Any] {
        let probes = dedupe([probeSeed] + autoExcluded.compactMap(hostFromCIDR)).map { routeProbe($0, included: included, excluded: effectiveExcluded, version: version) }
        return ["included_routes": included, "base_excluded_routes": baseExcluded, "auto_peer_excluded_routes": autoExcluded, "effective_excluded_routes": effectiveExcluded, "probes": probes]
    }

    private static func routeProbe(_ host: String, included: [String], excluded: [String], version: Int) -> [String: Any] {
        let matchingIncluded = included.filter { routeContains(host: host, cidr: $0, version: version) }
        let matchingExcluded = excluded.filter { routeContains(host: host, cidr: $0, version: version) }
        return ["host": host, "included": !matchingIncluded.isEmpty, "excluded": !matchingExcluded.isEmpty, "routed_to_tunnel": !matchingIncluded.isEmpty && matchingExcluded.isEmpty, "matching_included_routes": matchingIncluded, "matching_excluded_routes": matchingExcluded]
    }

    private static func routeContains(host: String, cidr: String, version: Int) -> Bool {
        let parts = cidr.split(separator: "/", maxSplits: 1).map(String.init)
        guard parts.count == 2, let prefix = Int(parts[1]) else { return false }
        return version == 4 ? ipv4RouteContains(host: host, network: parts[0], prefix: prefix) : ipv6RouteContains(host: host, network: parts[0], prefix: prefix)
    }

    private static func hostFromCIDR(_ cidr: String) -> String? {
        let host = cidr.split(separator: "/", maxSplits: 1).first.map(String.init)
        return host?.isEmpty == false ? host : nil
    }

    private static func dedupe(_ values: [String]) -> [String] {
        var seen: Set<String> = []; return values.filter { seen.insert($0).inserted }
    }
}

enum ObstacleBridgePacketTunnelConfigurationError: LocalizedError {
    case unsupportedSchema
    case invalidRoute(String)

    var errorDescription: String? {
        switch self {
        case .unsupportedSchema: return "Unsupported ObstacleBridge packet tunnel provider configuration schema"
        case .invalidRoute(let route): return "Invalid ObstacleBridge packet tunnel route: \(route)"
        }
    }
}
