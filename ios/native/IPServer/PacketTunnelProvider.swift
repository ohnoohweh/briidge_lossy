import Foundation
import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let pythonBridge = ObstacleBridgePythonBridge.shared()
    private let errorDomain = "ObstacleBridge.IPServer"

    private func bridgeResponse(for payload: [String: Any]) throws -> [String: Any] {
        guard let response = try pythonBridge.sendMessage(payload) as? [String: Any] else {
            throw NSError(
                domain: errorDomain,
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "IPServer bridge returned no response"]
            )
        }
        if let ok = response["ok"] as? Bool, ok {
            return response
        }
        let message = (response["error"] as? String) ?? "IPServer command failed"
        throw NSError(
            domain: errorDomain,
            code: 2,
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let providerConfiguration = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration

        do {
            let configuration = try TunnelProviderConfiguration(providerConfiguration)
            let settings = makeNetworkSettings(configuration)
            setTunnelNetworkSettings(settings) { [weak self] error in
                guard let self else { return }
                if let error {
                    completionHandler(error)
                    return
                }
                do {
                    _ = try self.bridgeResponse(
                        for: [
                            "command": "start_embedded_webadmin",
                            "provider_configuration": providerConfiguration ?? [:],
                        ]
                    )
                    completionHandler(nil)
                } catch {
                    completionHandler(error)
                }
            }
        } catch {
            completionHandler(error)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        _ = try? bridgeResponse(for: ["command": "stop", "reason": reason.rawValue])
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let payload: [String: Any]
        if messageData.isEmpty {
            payload = ["command": "snapshot"]
        } else if
            let json = try? JSONSerialization.jsonObject(with: messageData),
            let dict = json as? [String: Any]
        {
            payload = dict
        } else {
            let errorPayload: [String: Any] = [
                "ok": false,
                "error": "invalid JSON app message",
            ]
            let data = try? JSONSerialization.data(withJSONObject: errorPayload)
            completionHandler?(data)
            return
        }

        do {
            let response = try bridgeResponse(for: payload)
            let data = try JSONSerialization.data(withJSONObject: response)
            completionHandler?(data)
        } catch {
            let errorPayload: [String: Any] = [
                "ok": false,
                "error": error.localizedDescription,
            ]
            let data = try? JSONSerialization.data(withJSONObject: errorPayload)
            completionHandler?(data)
        }
    }

    private func makeNetworkSettings(_ configuration: TunnelProviderConfiguration) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: configuration.peerHost)
        settings.mtu = NSNumber(value: configuration.mtu)

        let ipv4 = NEIPv4Settings(
            addresses: [configuration.tunnelAddress],
            subnetMasks: [configuration.tunnelSubnetMask]
        )
        ipv4.includedRoutes = configuration.includedRoutes.map { route in
            NEIPv4Route(destinationAddress: route.destinationAddress, subnetMask: route.subnetMask)
        }
        ipv4.excludedRoutes = configuration.excludedRoutes.map { route in
            NEIPv4Route(destinationAddress: route.destinationAddress, subnetMask: route.subnetMask)
        }
        settings.ipv4Settings = ipv4

        if !configuration.dnsServers.isEmpty {
            settings.dnsSettings = NEDNSSettings(servers: configuration.dnsServers)
        }

        return settings
    }
}

private struct IPv4RouteSpec {
    let destinationAddress: String
    let subnetMask: String
}

private struct TunnelProviderConfiguration {
    let peerHost: String
    let tunnelAddress: String
    let tunnelSubnetMask: String
    let includedRoutes: [IPv4RouteSpec]
    let excludedRoutes: [IPv4RouteSpec]
    let dnsServers: [String]
    let mtu: Int

    init(_ providerConfiguration: [String: Any]?) throws {
        let payload = providerConfiguration ?? [:]
        if let schema = payload["schema"] as? String, !schema.isEmpty,
           schema != "obstaclebridge.ios.packet-tunnel.v1" {
            throw TunnelError.unsupportedSchema
        }

        if let peer = payload["peer"] as? [String: Any],
           let host = peer["host"] as? String,
           !host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            peerHost = host
        } else {
            peerHost = "127.0.0.1"
        }

        let network = payload["network_settings"] as? [String: Any] ?? [:]
        tunnelAddress = (network["tunnel_address"] as? String) ?? "10.77.0.2"
        let prefix = (network["tunnel_prefix"] as? NSNumber)?.intValue ?? 24
        tunnelSubnetMask = Self.subnetMask(prefix)
        includedRoutes = try Self.routes(network["included_routes"] as? [String] ?? ["10.77.0.0/24"])
        excludedRoutes = try Self.routes(network["excluded_routes"] as? [String] ?? [])
        dnsServers = network["dns_servers"] as? [String] ?? []
        mtu = (network["mtu"] as? NSNumber)?.intValue ?? 1500
    }

    private static func routes(_ values: [String]) throws -> [IPv4RouteSpec] {
        try values.map { cidr in
            let parts = cidr.split(separator: "/", maxSplits: 1).map(String.init)
            guard parts.count == 2, let prefix = Int(parts[1]), prefix >= 0, prefix <= 32 else {
                throw TunnelError.invalidRoute(cidr)
            }
            return IPv4RouteSpec(destinationAddress: parts[0], subnetMask: subnetMask(prefix))
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
}

private enum TunnelError: LocalizedError {
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
