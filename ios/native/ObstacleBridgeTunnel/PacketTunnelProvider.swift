import Foundation
import NetworkExtension
import os.log

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let logger = Logger(subsystem: "com.obstaclebridge.tunnel", category: "PacketTunnelProvider")
    private var bridge: PacketFlowBridge?
    private var status = TunnelStatus.idle

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        guard let protocolConfiguration = protocolConfiguration as? NETunnelProviderProtocol,
              let providerConfiguration = protocolConfiguration.providerConfiguration else {
            completionHandler(TunnelError.missingProviderConfiguration)
            return
        }

        do {
            let configuration = try TunnelProviderConfiguration(providerConfiguration)
            let settings = try makeNetworkSettings(configuration)
            setTunnelNetworkSettings(settings) { [weak self] error in
                guard let self = self else { return }
                if let error = error {
                    self.status.state = .failed
                    self.status.lastError = error.localizedDescription
                    completionHandler(error)
                    return
                }

                let bridge = PacketFlowBridge(packetFlow: self.packetFlow) { [weak self] status in
                    self?.status = status
                }
                self.bridge = bridge
                bridge.start(host: configuration.peerHost, port: configuration.peerPort)
                self.logger.info("ObstacleBridge M3 packet tunnel started")
                completionHandler(nil)
            }
        } catch {
            status.state = .failed
            status.lastError = error.localizedDescription
            completionHandler(error)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        bridge?.stop()
        bridge = nil
        status.state = .stopped
        logger.info("ObstacleBridge M3 packet tunnel stopped, reason: \(reason.rawValue)")
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let completionHandler = completionHandler else { return }
        let encoder = JSONEncoder()
        let response = (try? encoder.encode(status)) ?? Data()
        completionHandler(response)
    }

    private func makeNetworkSettings(_ configuration: TunnelProviderConfiguration) throws -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: configuration.peerHost)
        settings.mtu = NSNumber(value: configuration.mtu)

        let ipv4 = NEIPv4Settings(addresses: [configuration.tunnelAddress], subnetMasks: [configuration.tunnelSubnetMask])
        ipv4.includedRoutes = try configuration.includedRoutes.map { try route($0) }
        ipv4.excludedRoutes = try configuration.excludedRoutes.map { try route($0) }
        settings.ipv4Settings = ipv4

        if !configuration.dnsServers.isEmpty {
            settings.dnsSettings = NEDNSSettings(servers: configuration.dnsServers)
        }

        return settings
    }

    private func route(_ cidr: String) throws -> NEIPv4Route {
        let parts = cidr.split(separator: "/", maxSplits: 1).map(String.init)
        guard parts.count == 2, let prefix = Int(parts[1]), prefix >= 0, prefix <= 32 else {
            throw TunnelError.invalidRoute(cidr)
        }
        return NEIPv4Route(destinationAddress: parts[0], subnetMask: subnetMask(prefix))
    }

    private func subnetMask(_ prefix: Int) -> String {
        let mask = prefix == 0 ? 0 : UInt32.max << UInt32(32 - prefix)
        return [
            (mask >> 24) & 0xff,
            (mask >> 16) & 0xff,
            (mask >> 8) & 0xff,
            mask & 0xff,
        ].map(String.init).joined(separator: ".")
    }
}

private struct TunnelProviderConfiguration {
    let profileID: String
    let peerHost: String
    let peerPort: UInt16
    let tunnelAddress: String
    let tunnelSubnetMask: String
    let includedRoutes: [String]
    let excludedRoutes: [String]
    let dnsServers: [String]
    let mtu: Int

    init(_ providerConfiguration: [String: Any]) throws {
        guard providerConfiguration["schema"] as? String == "obstaclebridge.ios.packet-tunnel.v1" else {
            throw TunnelError.unsupportedSchema
        }
        profileID = providerConfiguration["profile_id"] as? String ?? "unknown"

        guard let peer = providerConfiguration["peer"] as? [String: Any],
              let host = peer["host"] as? String,
              let portNumber = peer["port"] as? NSNumber,
              let port = UInt16(exactly: portNumber.intValue) else {
            throw TunnelError.invalidPeer
        }
        peerHost = host
        peerPort = port

        guard let network = providerConfiguration["network_settings"] as? [String: Any],
              let address = network["tunnel_address"] as? String,
              let prefixNumber = network["tunnel_prefix"] as? NSNumber,
              let mtuNumber = network["mtu"] as? NSNumber else {
            throw TunnelError.invalidNetworkSettings
        }

        tunnelAddress = address
        tunnelSubnetMask = TunnelProviderConfiguration.subnetMask(prefixNumber.intValue)
        includedRoutes = network["included_routes"] as? [String] ?? ["10.77.0.0/24"]
        excludedRoutes = network["excluded_routes"] as? [String] ?? []
        dnsServers = network["dns_servers"] as? [String] ?? []
        mtu = mtuNumber.intValue
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
    case missingProviderConfiguration
    case unsupportedSchema
    case invalidPeer
    case invalidNetworkSettings
    case invalidRoute(String)

    var errorDescription: String? {
        switch self {
        case .missingProviderConfiguration:
            return "Missing NETunnelProviderProtocol provider configuration"
        case .unsupportedSchema:
            return "Unsupported ObstacleBridge packet tunnel provider configuration schema"
        case .invalidPeer:
            return "Invalid ObstacleBridge packet tunnel peer"
        case .invalidNetworkSettings:
            return "Invalid ObstacleBridge packet tunnel network settings"
        case .invalidRoute(let route):
            return "Invalid ObstacleBridge packet tunnel route: \(route)"
        }
    }
}
