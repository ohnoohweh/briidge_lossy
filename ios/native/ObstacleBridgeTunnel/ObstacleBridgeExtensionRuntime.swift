import Foundation
import NetworkExtension

final class ObstacleBridgeExtensionRuntime {
    private let configuration: TunnelProviderConfiguration
    private let packetFlow: NEPacketTunnelFlow
    private let statusUpdate: (TunnelStatus) -> Void
    private var packetBridge: PacketFlowBridge?
    private var webAdminServer: LocalWebAdminServer?
    private var pythonRuntime: ObstacleBridgePythonRuntime?
    private var currentStatus = TunnelStatus.idle

    init(
        configuration: TunnelProviderConfiguration,
        packetFlow: NEPacketTunnelFlow,
        statusUpdate: @escaping (TunnelStatus) -> Void
    ) {
        self.configuration = configuration
        self.packetFlow = packetFlow
        self.statusUpdate = statusUpdate
    }

    func start() {
        var starting = TunnelStatus.idle
        starting.state = .starting
        starting.runtimeOwner = configuration.runtimeOwner
        starting.runtimeLayers = configuration.runtimeLayers
        publish(starting)

        let bridge = PacketFlowBridge(packetFlow: packetFlow) { [weak self] status in
            guard let self = self else { return }
            var updated = status
            updated.runtimeOwner = self.configuration.runtimeOwner
            updated.runtimeLayers = self.configuration.runtimeLayers
            if let fallbackURL = self.webAdminServer?.url {
                updated.webAdminURL = fallbackURL
                updated.webAdminRunning = true
            } else if self.pythonRuntime != nil {
                updated.webAdminURL = self.webAdminURLFromConfig()
                updated.webAdminRunning = updated.webAdminURL != nil
            }
            self.publish(updated)
        }
        packetBridge = bridge

        let python = ObstacleBridgePythonRuntime()
        do {
            let providerData = try JSONSerialization.data(withJSONObject: configuration.providerConfiguration, options: [.sortedKeys])
            let providerJSON = String(data: providerData, encoding: .utf8) ?? "{}"
            let parentBundlePath = Self.parentApplicationBundlePath()
            try python.start(withProviderConfigurationJSON: providerJSON, parentBundlePath: parentBundlePath)
            pythonRuntime = python
            var pythonStatus = currentStatus
            pythonStatus.webAdminURL = webAdminURLFromConfig()
            pythonStatus.webAdminRunning = pythonStatus.webAdminURL != nil
            publish(pythonStatus)
        } catch {
            startNativeWebAdminFallback(lastError: "extension Python runtime failed: \(error.localizedDescription)")
        }

        bridge.start(host: configuration.peerHost, port: configuration.peerPort)
        let layers = configuration.runtimeLayers.joined(separator: ",")
        NSLog("ObstacleBridge extension runtime started with layers: \(layers)")
    }

    func stop() {
        pythonRuntime?.stop()
        pythonRuntime = nil
        webAdminServer?.stop()
        webAdminServer = nil
        packetBridge?.stop()
        packetBridge = nil
        var stopped = currentStatus
        stopped.state = .stopped
        stopped.webAdminURL = nil
        stopped.webAdminRunning = false
        publish(stopped)
    }

    private func publish(_ status: TunnelStatus) {
        currentStatus = status
        statusUpdate(status)
    }

    private func startNativeWebAdminFallback(lastError: String? = nil) {
        let webAdmin = LocalWebAdminServer(configuration: configuration) { [weak self] in
            self?.currentStatus ?? TunnelStatus.idle
        }
        do {
            try webAdmin.start()
            webAdminServer = webAdmin
            var webStatus = currentStatus
            webStatus.webAdminURL = webAdmin.url
            webStatus.webAdminRunning = webAdmin.url != nil
            webStatus.lastError = lastError
            publish(webStatus)
        } catch {
            var failed = currentStatus
            failed.state = .failed
            failed.lastError = lastError ?? "extension WebAdmin failed: \(error.localizedDescription)"
            publish(failed)
        }
    }

    private func webAdminURLFromConfig() -> String? {
        let enabled = configuration.obstacleBridgeConfig["admin_web"] as? Bool ?? true
        guard enabled else { return nil }
        let port: Int
        if let number = configuration.obstacleBridgeConfig["admin_web_port"] as? NSNumber {
            port = number.intValue
        } else if let value = configuration.obstacleBridgeConfig["admin_web_port"] as? Int {
            port = value
        } else {
            port = 18080
        }
        return "http://127.0.0.1:\(port)/"
    }

    private static func parentApplicationBundlePath() -> String {
        let extensionURL = Bundle.main.bundleURL
        let pluginsURL = extensionURL.deletingLastPathComponent()
        return pluginsURL.deletingLastPathComponent().path
    }
}
