import Foundation
import NetworkExtension

@objc(PacketTunnelProvider)
class PacketTunnelProvider: NEPacketTunnelProvider {
    private let errorDomain = "ObstacleBridge.IPServer"
    private var packetPumpRunning = false

    override init() {
        super.init()
        NSLog("ObstacleBridge IPServer init provider pid=%d", ProcessInfo.processInfo.processIdentifier)
    }

    deinit {
        NSLog("ObstacleBridge IPServer deinit provider pid=%d", ProcessInfo.processInfo.processIdentifier)
    }

    private func recordNativeEvent(_ event: String, fields: [String: Any] = [:]) {
        NSLog("ObstacleBridge IPServer event=%@ fields=%@", event, fields)
        writeNativeProviderLog(event, fields: fields)
    }

    private func writeNativeProviderLog(_ event: String, fields: [String: Any] = [:]) {
        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.obstaclebridge.shared"
        ) else {
            return
        }
        let logDirectory = containerURL.appendingPathComponent("logs", isDirectory: true)
        try? FileManager.default.createDirectory(at: logDirectory, withIntermediateDirectories: true)
        let logURL = logDirectory.appendingPathComponent("ipserver-native-provider.jsonl")
        var payload = fields
        payload["native_event"] = event
        payload["pid"] = ProcessInfo.processInfo.processIdentifier
        payload["timestamp"] = ISO8601DateFormatter().string(from: Date())
        guard JSONSerialization.isValidJSONObject(payload),
              let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]),
              let text = String(data: data, encoding: .utf8)
        else {
            return
        }
        if let handle = try? FileHandle(forWritingTo: logURL) {
            defer {
                try? handle.close()
            }
            handle.seekToEndOfFile()
            handle.write(Data((text + "\n").utf8))
            return
        }
        try? (text + "\n").write(to: logURL, atomically: true, encoding: .utf8)
    }

    #if !OB_IPSERVER_SWIFT_SMOKE
    private func bridgeResponse(for payload: [String: Any]) throws -> [String: Any] {
        NSLog("ObstacleBridge IPServer bridge command=%@", String(describing: payload["command"] ?? ""))
        guard let response = try ObstacleBridgePythonBridge.shared().sendMessage(payload) as? [String: Any] else {
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
    #endif

    private var heartbeatTimer: DispatchSourceTimer?

    private func startProviderHeartbeat() {
        heartbeatTimer?.cancel()

        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now(), repeating: 1.0)

        timer.setEventHandler { [weak self] in
            guard let self else { return }
            self.recordNativeEvent(
                "provider_heartbeat",
                fields: [
                    "uptime": ProcessInfo.processInfo.systemUptime,
                    "physical_memory": ProcessInfo.processInfo.physicalMemory,
                    "packet_pump_running": self.packetPumpRunning,
                ]
            )
        }

        heartbeatTimer = timer
        timer.resume()
    }


    public override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        recordNativeEvent(
            "startTunnel_entered",
            fields: [
                "has_options": options != nil,
                "pid": ProcessInfo.processInfo.processIdentifier,
                "low_power_mode": ProcessInfo.processInfo.isLowPowerModeEnabled,
                "physical_memory": ProcessInfo.processInfo.physicalMemory,
                "system_uptime": ProcessInfo.processInfo.systemUptime,
            ]
        )
        let providerConfiguration = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration

        do {
            let configuration = try TunnelProviderConfiguration(providerConfiguration)
            let settings = makeNetworkSettings(configuration)
            setTunnelNetworkSettings(settings) { [weak self] error in
                guard let self else { return }
                if let error {
                    self.recordNativeEvent(
                        "setTunnelNetworkSettings_failed",
                        fields: ["error": error.localizedDescription]
                    )
                    completionHandler(error)
                    return
                }
                #if OB_IPSERVER_SWIFT_SMOKE
                self.recordNativeEvent("startTunnel_completed_swift_smoke")
                completionHandler(nil)
                #elseif OB_IPSERVER_PYTHON_PROBE
                self.recordNativeEvent("startTunnel_completed_python_probe")
                completionHandler(nil)
                #else
                self.startPacketPump()
                self.startProviderHeartbeat()
                self.recordNativeEvent("startTunnel_completed_runtime_start_async")
                completionHandler(nil)
                DispatchQueue.global(qos: .utility).async {
                    self.recordNativeEvent("embedded_webadmin_call_entered")

                    do {
                        self.recordNativeEvent("embedded_webadmin_bridgeResponse_before")

                        let response = try self.bridgeResponse(
                            for: [
                                "command": "start_embedded_webadmin",
                                "provider_configuration": providerConfiguration ?? [:],
                            ]
                        )

                        self.recordNativeEvent("embedded_webadmin_bridgeResponse_after")

                        self.recordNativeEvent(
                            "embedded_webadmin_started",
                            fields: ["response": response]
                        )
                    } catch {
                        self.recordNativeEvent(
                            "embedded_webadmin_failed",
                            fields: [
                                "error": error.localizedDescription,
                                "error_type": String(describing: type(of: error)),
                            ]
                        )
                    }

                    self.recordNativeEvent("embedded_webadmin_call_exited")
                }
                #endif
            }
        } catch {
            recordNativeEvent(
                "startTunnel_configuration_failed",
                fields: ["error": error.localizedDescription]
            )
            completionHandler(error)
        }
    }

    public override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        recordNativeEvent(
            "stopTunnel_entered",
            fields: [
                "reason": reason.rawValue,
                "reason_text": Self.stopReasonText(reason),
                "pid": ProcessInfo.processInfo.processIdentifier,
                "system_uptime": ProcessInfo.processInfo.systemUptime,
            ]
        )
        heartbeatTimer?.cancel()
        heartbeatTimer = nil
        #if !OB_IPSERVER_SWIFT_SMOKE
        _ = try? bridgeResponse(for: ["command": "stop", "reason": reason.rawValue])
        #endif
        packetPumpRunning = false
        recordNativeEvent("stopTunnel_completed", fields: ["reason": reason.rawValue])
        completionHandler()
    }

    public override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
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
            #if OB_IPSERVER_SWIFT_SMOKE
            let response: [String: Any] = [
                "ok": true,
                "mode": "swift_smoke",
                "status": "provider alive",
                "command": String(describing: payload["command"] ?? ""),
            ]
            #elseif OB_IPSERVER_PYTHON_PROBE
            let command = String(describing: payload["command"] ?? "")
            let response: [String: Any]
            if command == "native_python_probe" {
                guard let probeResponse = try ObstacleBridgePythonBridge.shared().probePythonRuntime() as? [String: Any] else {
                    throw NSError(
                        domain: errorDomain,
                        code: 3,
                        userInfo: [NSLocalizedDescriptionKey: "native Python probe returned no response"]
                    )
                }
                recordNativeEvent("python_probe_completed", fields: ["response": probeResponse])
                response = probeResponse
            } else if command.hasPrefix("probe_module:") {
                let moduleName = String(command.dropFirst("probe_module:".count))
                guard !moduleName.isEmpty else {
                    throw NSError(
                        domain: errorDomain,
                        code: 5,
                        userInfo: [NSLocalizedDescriptionKey: "probe_module command requires a module name"]
                    )
                }
                guard let probeResponse = try ObstacleBridgePythonBridge.shared().probePythonModules([moduleName]) as? [String: Any] else {
                    throw NSError(
                        domain: errorDomain,
                        code: 4,
                        userInfo: [NSLocalizedDescriptionKey: "module probe returned no response for \(moduleName)"]
                    )
                }
                recordNativeEvent("single_module_probe_completed", fields: ["module": moduleName, "response": probeResponse])
                response = probeResponse
            } else if command == "obstaclebridge_module_probe" {
                let defaultModules = [
                    "obstacle_bridge",
                    "obstacle_bridge.core",
                    "obstacle_bridge_ios.diagnostics",
                    "obstacle_bridge_ios.app",
                    "obstacle_bridge_ios.ipserver_extension",
                ]
                let modules = payload["modules"] as? [String] ?? defaultModules
                guard let probeResponse = try ObstacleBridgePythonBridge.shared().probePythonModules(modules) as? [String: Any] else {
                    throw NSError(
                        domain: errorDomain,
                        code: 4,
                        userInfo: [NSLocalizedDescriptionKey: "ObstacleBridge module probe returned no response"]
                    )
                }
                recordNativeEvent("obstaclebridge_module_probe_completed", fields: ["response": probeResponse])
                response = probeResponse
            } else {
                response = [
                    "ok": true,
                    "mode": "python_probe",
                    "status": "provider alive",
                    "command": command,
                ]
            }
            #else
            let response = try bridgeResponse(for: payload)
            #endif
            recordNativeEvent(
                "handleAppMessage_completed",
                fields: ["command": String(describing: payload["command"] ?? "")]
            )
            let data = try JSONSerialization.data(withJSONObject: response)
            completionHandler?(data)
        } catch {
            recordNativeEvent(
                "handleAppMessage_failed",
                fields: [
                    "command": String(describing: payload["command"] ?? ""),
                    "error": error.localizedDescription,
                ]
            )
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

    private func startPacketPump() {
        guard !packetPumpRunning else {
            return
        }
        packetPumpRunning = true
        recordNativeEvent("packet_pump_started")
        readPackets()
    }

    private func readPackets() {
        guard packetPumpRunning else {
            return
        }
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self else {
                return
            }
            if !packets.isEmpty {
                self.recordNativeEvent(
                    "packet_pump_dropped_packets",
                    fields: [
                        "packet_count": packets.count,
                        "protocol_count": protocols.count,
                    ]
                )
            }
            self.readPackets()
        }
    }

    private static func stopReasonText(_ reason: NEProviderStopReason) -> String {
        switch reason {
        case .none:
            return "none"
        case .userInitiated:
            return "userInitiated"
        case .providerFailed:
            return "providerFailed"
        case .noNetworkAvailable:
            return "noNetworkAvailable"
        case .unrecoverableNetworkChange:
            return "unrecoverableNetworkChange"
        case .providerDisabled:
            return "providerDisabled"
        case .authenticationCanceled:
            return "authenticationCanceled"
        case .configurationFailed:
            return "configurationFailed"
        case .idleTimeout:
            return "idleTimeout"
        case .configurationDisabled:
            return "configurationDisabled"
        case .configurationRemoved:
            return "configurationRemoved"
        case .superceded:
            return "superceded"
        case .userLogout:
            return "userLogout"
        case .userSwitch:
            return "userSwitch"
        case .connectionFailed:
            return "connectionFailed"
        case .sleep:
            return "sleep"
        case .appUpdate:
            return "appUpdate"
        case .internalError:
            return "internalError"
        @unknown default:
            return "unknown"
        }
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
