import Foundation
import NetworkExtension

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
    let enabledOnStartup: Bool
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
        tunnelSubnetMask = ObstacleBridgePacketTunnelRoutePolicy.subnetMask(prefix)
        tunnelAddress = resolvedTunnelAddress
        tunnelAddress6 = resolvedTunnelAddress6
        tunnelPrefix6 = resolvedTunnelPrefix6
        includedRoutes = try ObstacleBridgePacketTunnelRoutePolicy.routes(resolvedIncludedRoutes)
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
        excludedRoutes = try ObstacleBridgePacketTunnelRoutePolicy.routes(effectiveExcluded.ipv4)
        includedRoutes6 = try ObstacleBridgePacketTunnelRoutePolicy.routes6(resolvedIncludedRoutes6)
        excludedRoutes6 = try ObstacleBridgePacketTunnelRoutePolicy.routes6(effectiveExcluded.ipv6)
        dnsServers = (network["dns_servers"] as? [String]) ?? runtimeNetworkFallback.dnsServers
        mtu = ((network["mtu"] as? NSNumber)?.intValue ?? (network["mtu"] as? Int))
            ?? runtimeNetworkFallback.mtu
            ?? 1500
        enabledOnStartup = routingOverride?.enabledOnStartup ?? true
        routeDiagnostics = ObstacleBridgePacketTunnelRoutePolicy.routeDiagnostics(
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

    func makeNetworkSettings(includeRoutes: Bool = true) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: peerHost)
        settings.mtu = NSNumber(value: mtu)

        let ipv4 = NEIPv4Settings(addresses: [tunnelAddress], subnetMasks: [tunnelSubnetMask])
        ipv4.includedRoutes = (includeRoutes ? includedRoutes : []).map { route in
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
            ipv6.includedRoutes = (includeRoutes ? includedRoutes6 : []).map { route in
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
