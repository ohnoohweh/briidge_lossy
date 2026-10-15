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
