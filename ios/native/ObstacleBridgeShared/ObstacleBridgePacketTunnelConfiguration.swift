import Foundation
import NetworkExtension

struct ObstacleBridgePacketTunnelIPv4RouteSpec {
    let destinationAddress: String
    let subnetMask: String
}

struct ObstacleBridgePacketTunnelIPv6RouteSpec {
    let destinationAddress: String
    let networkPrefixLength: Int
}

struct ObstacleBridgePacketTunnelDefaults {
    let tunnelAddress: String
    let tunnelPrefix: Int
    let includedRoutes: [String]
    let excludedRoutes: [String]
    let tunnelAddress6: String
    let tunnelPrefix6: Int
    let includedRoutes6: [String]
    let excludedRoutes6: [String]
}

struct ObstacleBridgePacketTunnelConfiguration {
    let peerHost: String
    let peerPort: UInt16?
    let tunnelAddress: String
    let tunnelSubnetMask: String
    let includedRoutes: [ObstacleBridgePacketTunnelIPv4RouteSpec]
    let excludedRoutes: [ObstacleBridgePacketTunnelIPv4RouteSpec]
    let tunnelAddress6: String
    let tunnelPrefix6: Int
    let includedRoutes6: [ObstacleBridgePacketTunnelIPv6RouteSpec]
    let excludedRoutes6: [ObstacleBridgePacketTunnelIPv6RouteSpec]
    let dnsServers: [String]
    let mtu: Int

    init(
        _ providerConfiguration: [String: Any]?,
        fallbackRuntimeConfig: [String: Any]? = nil,
        defaults: ObstacleBridgePacketTunnelDefaults,
        schema: String = "obstaclebridge.ios.packet-tunnel.v1"
    ) throws {
        let payload = providerConfiguration ?? [:]
        if let configuredSchema = payload["schema"] as? String, !configuredSchema.isEmpty,
           configuredSchema != schema {
            throw ObstacleBridgePacketTunnelConfigurationError.unsupportedSchema
        }

        let runtimeConfig = (payload["runtime_config"] as? [String: Any]) ?? fallbackRuntimeConfig ?? [:]
        let routingOverride = ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: runtimeConfig)
        let runtimeNetworkFallback = Self.runtimeNetworkFallback(from: runtimeConfig)

        if let peer = payload["peer"] as? [String: Any],
           let host = peer["host"] as? String,
           !host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            peerHost = host
        } else {
            peerHost = "127.0.0.1"
        }

        if let peer = payload["peer"] as? [String: Any],
           let portValue = peer["port"],
           let port = Self.uint16Value(from: portValue) {
            peerPort = port
        } else {
            peerPort = nil
        }

        let network = payload["network_settings"] as? [String: Any] ?? [:]
        tunnelAddress = (network["tunnel_address"] as? String)
            ?? routingOverride?.tunnelAddress
            ?? defaults.tunnelAddress
        let prefix = (network["tunnel_prefix"] as? NSNumber)?.intValue
            ?? (network["tunnel_prefix"] as? Int)
            ?? routingOverride?.tunnelPrefix
            ?? defaults.tunnelPrefix
        tunnelSubnetMask = Self.subnetMask(prefix)
        includedRoutes = try Self.routes(
            network["included_routes"] as? [String]
                ?? routingOverride?.includedRoutes
                ?? defaults.includedRoutes
        )
        let baseExcludedRoutes = network["excluded_routes"] as? [String]
            ?? routingOverride?.excludedRoutes
            ?? defaults.excludedRoutes
        let baseExcludedRoutes6 = network["excluded_routes6"] as? [String]
            ?? routingOverride?.excludedRoutes6
            ?? (tunnelAddress6.isEmpty ? [] : defaults.excludedRoutes6)
        let effectiveExcluded = ObstacleBridgeRuntimeConfig.effectiveExcludedRoutes(
            from: runtimeConfig,
            baseIPv4: baseExcludedRoutes,
            baseIPv6: baseExcludedRoutes6
        )
        excludedRoutes = try Self.routes(effectiveExcluded.ipv4)
        tunnelAddress6 = (network["tunnel_address6"] as? String)
            ?? routingOverride?.tunnelAddress6
            ?? defaults.tunnelAddress6
        tunnelPrefix6 = (network["tunnel_prefix6"] as? NSNumber)?.intValue
            ?? (network["tunnel_prefix6"] as? Int)
            ?? routingOverride?.tunnelPrefix6
            ?? defaults.tunnelPrefix6
        includedRoutes6 = try Self.routes6(
            network["included_routes6"] as? [String]
                ?? routingOverride?.includedRoutes6
                ?? (tunnelAddress6.isEmpty ? [] : defaults.includedRoutes6)
        )
        excludedRoutes6 = try Self.routes6(effectiveExcluded.ipv6)
        dnsServers = (network["dns_servers"] as? [String]) ?? runtimeNetworkFallback.dnsServers
        mtu = ((network["mtu"] as? NSNumber)?.intValue ?? (network["mtu"] as? Int))
            ?? runtimeNetworkFallback.mtu
            ?? 1500
    }

    func makeNetworkSettings() -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: peerHost)
        settings.mtu = NSNumber(value: mtu)

        let ipv4 = NEIPv4Settings(addresses: [tunnelAddress], subnetMasks: [tunnelSubnetMask])
        ipv4.includedRoutes = includedRoutes.map { route in
            NEIPv4Route(destinationAddress: route.destinationAddress, subnetMask: route.subnetMask)
        }
        ipv4.excludedRoutes = excludedRoutes.map { route in
            NEIPv4Route(destinationAddress: route.destinationAddress, subnetMask: route.subnetMask)
        }
        settings.ipv4Settings = ipv4

        if !tunnelAddress6.isEmpty {
            let ipv6 = NEIPv6Settings(
                addresses: [tunnelAddress6],
                networkPrefixLengths: [NSNumber(value: tunnelPrefix6)]
            )
            ipv6.includedRoutes = includedRoutes6.map { route in
                NEIPv6Route(
                    destinationAddress: route.destinationAddress,
                    networkPrefixLength: NSNumber(value: route.networkPrefixLength)
                )
            }
            ipv6.excludedRoutes = excludedRoutes6.map { route in
                NEIPv6Route(
                    destinationAddress: route.destinationAddress,
                    networkPrefixLength: NSNumber(value: route.networkPrefixLength)
                )
            }
            settings.ipv6Settings = ipv6
        }

        if !dnsServers.isEmpty {
            settings.dnsSettings = NEDNSSettings(servers: dnsServers)
        }

        return settings
    }

    private struct RuntimeNetworkFallback {
        let dnsServers: [String]
        let mtu: Int?
    }

    private static func runtimeNetworkFallback(from payload: [String: Any]) -> RuntimeNetworkFallback {
        let routingOverride = ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: payload)
        let dnsServers = routingOverride?.dnsServers
            ?? (payload["dns_servers"] as? [String])
            ?? []
        let mtu = routingOverride?.mtu
            ?? ObstacleBridgeRuntimeConfig.intValue(from: payload["mtu"])
        return RuntimeNetworkFallback(dnsServers: dnsServers, mtu: mtu)
    }

    private static func routes(_ values: [String]) throws -> [ObstacleBridgePacketTunnelIPv4RouteSpec] {
        try values.map { cidr in
            let parts = cidr.split(separator: "/", maxSplits: 1).map(String.init)
            guard parts.count == 2, let prefix = Int(parts[1]), prefix >= 0, prefix <= 32 else {
                throw ObstacleBridgePacketTunnelConfigurationError.invalidRoute(cidr)
            }
            return ObstacleBridgePacketTunnelIPv4RouteSpec(
                destinationAddress: parts[0],
                subnetMask: subnetMask(prefix)
            )
        }
    }

    private static func routes6(_ values: [String]) throws -> [ObstacleBridgePacketTunnelIPv6RouteSpec] {
        try values.map { cidr in
            let parts = cidr.split(separator: "/", maxSplits: 1).map(String.init)
            guard parts.count == 2, let prefix = Int(parts[1]), prefix >= 0, prefix <= 128 else {
                throw ObstacleBridgePacketTunnelConfigurationError.invalidRoute(cidr)
            }
            return ObstacleBridgePacketTunnelIPv6RouteSpec(
                destinationAddress: parts[0],
                networkPrefixLength: prefix
            )
        }
    }

    private static func subnetMask(_ prefix: Int) -> String {
        let mask = prefix == 0 ? 0 : UInt32.max << UInt32(32 - prefix)
        return [
            (mask >> 24) & 0xff,
            (mask >> 16) & 0xff,
            (mask >> 8) & 0xff,
            mask & 0xff,
        ].map(String.init).joined(separator: ".")
    }

    private static func uint16Value(from value: Any?) -> UInt16? {
        if let number = value as? NSNumber {
            return UInt16(exactly: number.intValue)
        }
        if let value = value as? Int {
            return UInt16(exactly: value)
        }
        if let value = value as? String, let parsed = Int(value) {
            return UInt16(exactly: parsed)
        }
        return nil
    }
}

enum ObstacleBridgePacketTunnelConfigurationError: LocalizedError {
    case unsupportedSchema
    case invalidRoute(String)

    var errorDescription: String? {
        switch self {
        case .unsupportedSchema:
            return "Unsupported ObstacleBridge packet tunnel provider configuration schema"
        case .invalidRoute(let route):
            return "Invalid ObstacleBridge packet tunnel route: \(route)"
        }
    }
}
