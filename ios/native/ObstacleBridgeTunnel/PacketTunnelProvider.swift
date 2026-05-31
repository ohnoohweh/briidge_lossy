import Foundation
import NetworkExtension
import os.log

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private static let packetTunnelDefaults = ObstacleBridgePacketTunnelDefaults(
        tunnelAddress: "10.77.0.1",
        tunnelPrefix: 24,
        includedRoutes: ["10.77.0.0/24"],
        excludedRoutes: [],
        tunnelAddress6: "",
        tunnelPrefix6: 126,
        includedRoutes6: [],
        excludedRoutes6: []
    )

    private let logger = OSLog(subsystem: "com.obstaclebridge.tunnel", category: "PacketTunnelProvider")
    private var bridge: PacketFlowBridge?
    private var status = TunnelStatus.idle

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        guard let protocolConfiguration = protocolConfiguration as? NETunnelProviderProtocol,
              let providerConfiguration = protocolConfiguration.providerConfiguration else {
            completionHandler(TunnelError.missingProviderConfiguration)
            return
        }

        do {
            let configuration = try ObstacleBridgePacketTunnelConfiguration(
                providerConfiguration,
                defaults: Self.packetTunnelDefaults
            )
            guard let peerPort = configuration.peerPort else {
                throw TunnelError.invalidPeer
            }
            let settings = configuration.makeNetworkSettings()
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
                bridge.start(host: configuration.peerHost, port: peerPort)
                os_log("ObstacleBridge M3 packet tunnel started", log: self.logger, type: .info)
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
        os_log("ObstacleBridge M3 packet tunnel stopped, reason: %{public}ld", log: logger, type: .info, reason.rawValue)
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let completionHandler = completionHandler else { return }
        let encoder = JSONEncoder()
        let response = (try? encoder.encode(status)) ?? Data()
        completionHandler(response)
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
