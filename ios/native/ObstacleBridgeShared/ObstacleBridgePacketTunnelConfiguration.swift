import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
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
    let routeDiagnostics: [String: Any]

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
        let resolvedTunnelAddress = (network["tunnel_address"] as? String)
            ?? routingOverride?.tunnelAddress
            ?? defaults.tunnelAddress
        let prefix = (network["tunnel_prefix"] as? NSNumber)?.intValue
            ?? (network["tunnel_prefix"] as? Int)
            ?? routingOverride?.tunnelPrefix
            ?? defaults.tunnelPrefix
        let resolvedTunnelAddress6 = (network["tunnel_address6"] as? String)
            ?? routingOverride?.tunnelAddress6
            ?? defaults.tunnelAddress6
        let resolvedTunnelPrefix6 = (network["tunnel_prefix6"] as? NSNumber)?.intValue
            ?? (network["tunnel_prefix6"] as? Int)
            ?? routingOverride?.tunnelPrefix6
            ?? defaults.tunnelPrefix6
        let resolvedIncludedRoutes = network["included_routes"] as? [String]
            ?? routingOverride?.includedRoutes
            ?? defaults.includedRoutes
        let resolvedIncludedRoutes6 = network["included_routes6"] as? [String]
            ?? routingOverride?.includedRoutes6
            ?? (resolvedTunnelAddress6.isEmpty ? [] : defaults.includedRoutes6)
        tunnelSubnetMask = Self.subnetMask(prefix)
        tunnelAddress = resolvedTunnelAddress
        tunnelAddress6 = resolvedTunnelAddress6
        tunnelPrefix6 = resolvedTunnelPrefix6
        includedRoutes = try Self.routes(resolvedIncludedRoutes)
        let baseExcludedRoutes = network["excluded_routes"] as? [String]
            ?? routingOverride?.excludedRoutes
            ?? defaults.excludedRoutes
        let baseExcludedRoutes6 = network["excluded_routes6"] as? [String]
            ?? routingOverride?.excludedRoutes6
            ?? (resolvedTunnelAddress6.isEmpty ? [] : defaults.excludedRoutes6)
        let effectiveExcluded = ObstacleBridgeRuntimeConfig.effectiveExcludedRoutes(
            from: runtimeConfig,
            baseIPv4: baseExcludedRoutes,
            baseIPv6: baseExcludedRoutes6
        )
        let autoExcluded = ObstacleBridgeRuntimeConfig.overlayPeerExcludedRoutes(from: runtimeConfig)
        excludedRoutes = try Self.routes(effectiveExcluded.ipv4)
        includedRoutes6 = try Self.routes6(resolvedIncludedRoutes6)
        excludedRoutes6 = try Self.routes6(effectiveExcluded.ipv6)
        dnsServers = (network["dns_servers"] as? [String]) ?? runtimeNetworkFallback.dnsServers
        mtu = ((network["mtu"] as? NSNumber)?.intValue ?? (network["mtu"] as? Int))
            ?? runtimeNetworkFallback.mtu
            ?? 1500
        routeDiagnostics = Self.routeDiagnostics(
            includedIPv4: resolvedIncludedRoutes,
            baseExcludedIPv4: baseExcludedRoutes,
            autoExcludedIPv4: autoExcluded.ipv4,
            effectiveExcludedIPv4: effectiveExcluded.ipv4,
            includedIPv6: resolvedIncludedRoutes6,
            baseExcludedIPv6: baseExcludedRoutes6,
            autoExcludedIPv6: autoExcluded.ipv6,
            effectiveExcludedIPv6: effectiveExcluded.ipv6
        )
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

    private static func routeDiagnostics(
        includedIPv4: [String],
        baseExcludedIPv4: [String],
        autoExcludedIPv4: [String],
        effectiveExcludedIPv4: [String],
        includedIPv6: [String],
        baseExcludedIPv6: [String],
        autoExcludedIPv6: [String],
        effectiveExcludedIPv6: [String]
    ) -> [String: Any] {
        let ipv4Probes = dedupe(["127.0.0.1"] + autoExcludedIPv4.compactMap { hostFromCIDR($0) })
        let ipv6Probes = dedupe(["::1"] + autoExcludedIPv6.compactMap { hostFromCIDR($0) })
        return [
            "ipv4": [
                "included_routes": includedIPv4,
                "base_excluded_routes": baseExcludedIPv4,
                "auto_peer_excluded_routes": autoExcludedIPv4,
                "effective_excluded_routes": effectiveExcludedIPv4,
                "probes": ipv4Probes.map {
                    routeProbe($0, includedRoutes: includedIPv4, excludedRoutes: effectiveExcludedIPv4, version: 4)
                },
            ],
            "ipv6": [
                "included_routes": includedIPv6,
                "base_excluded_routes": baseExcludedIPv6,
                "auto_peer_excluded_routes": autoExcludedIPv6,
                "effective_excluded_routes": effectiveExcludedIPv6,
                "probes": ipv6Probes.map {
                    routeProbe($0, includedRoutes: includedIPv6, excludedRoutes: effectiveExcludedIPv6, version: 6)
                },
            ],
        ]
    }

    private static func routeProbe(_ host: String, includedRoutes: [String], excludedRoutes: [String], version: Int) -> [String: Any] {
        let matchingIncluded = includedRoutes.filter { routeContains(host: host, cidr: $0, version: version) }
        let matchingExcluded = excludedRoutes.filter { routeContains(host: host, cidr: $0, version: version) }
        return [
            "host": host,
            "included": !matchingIncluded.isEmpty,
            "excluded": !matchingExcluded.isEmpty,
            "routed_to_tunnel": !matchingIncluded.isEmpty && matchingExcluded.isEmpty,
            "matching_included_routes": matchingIncluded,
            "matching_excluded_routes": matchingExcluded,
        ]
    }

    private static func routeContains(host: String, cidr: String, version: Int) -> Bool {
        let parts = cidr.split(separator: "/", maxSplits: 1).map(String.init)
        guard parts.count == 2, let prefix = Int(parts[1]) else {
            return false
        }
        if version == 4 {
            return ipv4RouteContains(host: host, network: parts[0], prefix: prefix)
        }
        return ipv6RouteContains(host: host, network: parts[0], prefix: prefix)
    }

    private static func ipv4RouteContains(host: String, network: String, prefix: Int) -> Bool {
        guard prefix >= 0, prefix <= 32,
              let hostValue = ipv4Value(host),
              let networkValue = ipv4Value(network) else {
            return false
        }
        if prefix == 0 {
            return true
        }
        let mask = UInt32.max << UInt32(32 - prefix)
        return (hostValue & mask) == (networkValue & mask)
    }

    private static func ipv4Value(_ host: String) -> UInt32? {
        let parts = host.split(separator: ".").map(String.init)
        guard parts.count == 4 else {
            return nil
        }
        var value: UInt32 = 0
        for part in parts {
            guard let octet = UInt8(part) else {
                return nil
            }
            value = (value << 8) | UInt32(octet)
        }
        return value
    }

    private static func ipv6RouteContains(host: String, network: String, prefix: Int) -> Bool {
        guard prefix >= 0, prefix <= 128,
              let hostBytes = ipv6Bytes(host),
              let networkBytes = ipv6Bytes(network) else {
            return false
        }
        if prefix == 0 {
            return true
        }
        let fullBytes = prefix / 8
        let remainingBits = prefix % 8
        if fullBytes > 0 && hostBytes[0..<fullBytes] != networkBytes[0..<fullBytes] {
            return false
        }
        if remainingBits == 0 {
            return true
        }
        let mask = UInt8(0xff << UInt8(8 - remainingBits))
        return (hostBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask)
    }

    private static func ipv6Bytes(_ host: String) -> [UInt8]? {
        var addr = in6_addr()
        let rc = host.withCString { inet_pton(AF_INET6, $0, &addr) }
        guard rc == 1 else {
            return nil
        }
        return withUnsafeBytes(of: addr) { Array($0) }
    }

    private static func hostFromCIDR(_ cidr: String) -> String? {
        let parts = cidr.split(separator: "/", maxSplits: 1).map(String.init)
        return parts.first?.isEmpty == false ? parts.first : nil
    }

    private static func dedupe(_ values: [String]) -> [String] {
        var seen: Set<String> = []
        var out: [String] = []
        for value in values {
            if seen.insert(value).inserted {
                out.append(value)
            }
        }
        return out
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
