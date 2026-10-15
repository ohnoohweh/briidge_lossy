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
        guard (0...128).contains(prefix), let hostBytes = ipv6Bytes(host), let networkBytes = ipv6Bytes(network) else {
            return false
        }
        if prefix == 0 { return true }
        let fullBytes = prefix / 8
        let remainingBits = prefix % 8
        if fullBytes > 0 && hostBytes[0..<fullBytes] != networkBytes[0..<fullBytes] { return false }
        if remainingBits == 0 { return true }
        let mask = UInt8(0xff << UInt8(8 - remainingBits))
        return (hostBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask)
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
