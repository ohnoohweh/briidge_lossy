import Foundation
import Network
import NetworkExtension
import Darwin

@objc(PacketTunnelProvider)
class PacketTunnelProvider: NEPacketTunnelProvider {
    static let defaultTunnelAddress = "192.168.106.1"
    static let defaultTunnelPrefix = 30
    static let defaultIncludedRoutes = ["0.0.0.0/0"]
    static let defaultExcludedRoutes = ["127.0.0.0/8"]
    static let defaultTunnelAddress6 = "fd20:106::1"
    static let defaultTunnelPrefix6 = 126
    static let defaultIncludedRoutes6 = ["::/0"]
    static let defaultExcludedRoutes6 = ["::1/128"]
    private let errorDomain = "ObstacleBridge.IPServer"
    private var packetPumpRunning = false
    private var providerStateUpdateCount = 0
    private var heartbeatTickCount = 0
    private var runtimeMode = "python_runtime"
    private var swiftSimpleUDPPeerBridge: SwiftSimpleUDPPeerBridge?
    private var sharedOverlayBootstrapState: [String: Any] = [:]
    private var sharedCompressLayerRuntime: ObstacleBridgeCompressLayerRuntime?
    private var sharedSecureLinkPskTransportAdapter: ObstacleBridgeSecureLinkPskTransportAdapter?
    private var sharedOverlayLayerTransportAdapter: ObstacleBridgeOverlayLayerTransportAdapter?
    private var sharedWebSocketOverlayRuntime: ObstacleBridgeWebSocketOverlayRuntime?
    private var sharedTcpOverlayRuntime: ObstacleBridgeTcpOverlayRuntime?

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

    private func providerStateURL() -> URL? {
        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.obstaclebridge.shared"
        ) else {
            return nil
        }
        let logDirectory = containerURL.appendingPathComponent("logs", isDirectory: true)
        try? FileManager.default.createDirectory(at: logDirectory, withIntermediateDirectories: true)
        return logDirectory.appendingPathComponent("ipserver-native-provider-state.json")
    }

    private func updateProviderState(_ state: String, extraFields: [String: Any] = [:]) {
        guard let url = providerStateURL() else {
            return
        }
        providerStateUpdateCount += 1
        var payload: [String: Any] = [
            "pid": ProcessInfo.processInfo.processIdentifier,
            "timestamp": ISO8601DateFormatter().string(from: Date()),
            "state": state,
            "runtime_mode": runtimeMode,
            "packet_pump_running": packetPumpRunning,
            "provider_state_update_count": providerStateUpdateCount,
            "system_uptime": ProcessInfo.processInfo.systemUptime,
            "physical_memory": ProcessInfo.processInfo.physicalMemory,
            "bridge_state": ObstacleBridgePacketFlowBridge.bridgeStateSnapshot(),
        ]
        if let swiftBridge = swiftSimpleUDPPeerBridge {
            payload["swift_udp_bridge_state"] = swiftBridge.snapshot()
        }
        if !sharedOverlayBootstrapState.isEmpty {
            payload["shared_overlay_bootstrap_state"] = sharedOverlayBootstrapState
        }
        for (key, value) in Self.processMemorySnapshot() {
            payload[key] = value
        }
        for (key, value) in extraFields {
            payload[key] = value
        }
        guard JSONSerialization.isValidJSONObject(payload),
              let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys, .prettyPrinted])
        else {
            return
        }
        try? data.write(to: url, options: [.atomic])
    }

    func recordPacketBridgeEvent(_ event: String, fields: [String: Any] = [:]) {
        recordNativeEvent(event, fields: fields)
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

    private var swiftUDPRuntimeActive: Bool {
        runtimeMode == "swift_udp"
    }

    private func startProviderHeartbeat() {
        heartbeatTimer?.cancel()
        heartbeatTickCount = 0

        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now(), repeating: 1.0)

        timer.setEventHandler { [weak self] in
            guard let self else { return }
            self.heartbeatTickCount += 1
            let processMemory = Self.processMemorySnapshot()
            var fields: [String: Any] = [
                "uptime": ProcessInfo.processInfo.systemUptime,
                "physical_memory": ProcessInfo.processInfo.physicalMemory,
                "runtime_mode": self.runtimeMode,
                "packet_pump_running": self.packetPumpRunning,
                "bridge_state": ObstacleBridgePacketFlowBridge.bridgeStateSnapshot(),
            ]
            if let swiftBridge = self.swiftSimpleUDPPeerBridge {
                fields["swift_udp_bridge_state"] = swiftBridge.snapshot()
            }
            for (key, value) in processMemory {
                fields[key] = value
            }
            let shouldRecordHeartbeat: Bool
            let shouldUpdateState: Bool
            if self.swiftUDPRuntimeActive {
                shouldRecordHeartbeat = self.heartbeatTickCount <= 3 || (self.heartbeatTickCount % 5) == 0
                shouldUpdateState = self.heartbeatTickCount <= 3 || (self.heartbeatTickCount % 15) == 0
            } else {
                shouldRecordHeartbeat = true
                shouldUpdateState = true
            }
            if shouldRecordHeartbeat {
                self.recordNativeEvent(
                    "provider_heartbeat",
                    fields: fields
                )
            }
            if shouldUpdateState {
                self.updateProviderState("heartbeat")
            }
        }

        heartbeatTimer = timer
        timer.resume()
    }


    public override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        runtimeMode = "python_runtime"
        swiftSimpleUDPPeerBridge = nil
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
        updateProviderState("startTunnel_entered")
        let providerConfiguration = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration

        do {
            let configuration = try TunnelProviderConfiguration(
                providerConfiguration,
                fallbackRuntimeConfig: loadSharedRuntimeConfigJSON()
            )
            recordNativeEvent(
                "tunnel_network_settings_prepared",
                fields: [
                    "peer_host": configuration.peerHost,
                    "tunnel_address": configuration.tunnelAddress,
                    "tunnel_subnet_mask": configuration.tunnelSubnetMask,
                    "included_routes": configuration.includedRoutes.map { ["destination": $0.destinationAddress, "subnet_mask": $0.subnetMask] },
                    "excluded_routes": configuration.excludedRoutes.map { ["destination": $0.destinationAddress, "subnet_mask": $0.subnetMask] },
                    "tunnel_address6": configuration.tunnelAddress6,
                    "tunnel_prefix6": configuration.tunnelPrefix6,
                    "included_routes6": configuration.includedRoutes6.map { ["destination": $0.destinationAddress, "network_prefix_length": $0.networkPrefixLength] },
                    "excluded_routes6": configuration.excludedRoutes6.map { ["destination": $0.destinationAddress, "network_prefix_length": $0.networkPrefixLength] },
                    "dns_servers": configuration.dnsServers,
                    "mtu": configuration.mtu,
                ]
            )
            let settings = makeNetworkSettings(configuration)
            setTunnelNetworkSettings(settings) { [weak self] error in
                guard let self else { return }
                if let error {
                    self.recordNativeEvent(
                        "setTunnelNetworkSettings_failed",
                        fields: ["error": error.localizedDescription]
                    )
                    self.updateProviderState("setTunnelNetworkSettings_failed", extraFields: ["error": error.localizedDescription])
                    completionHandler(error)
                    return
                }
                self.recordNativeEvent(
                    "tunnel_network_settings_applied",
                    fields: [
                        "peer_host": configuration.peerHost,
                        "tunnel_address": configuration.tunnelAddress,
                        "tunnel_subnet_mask": configuration.tunnelSubnetMask,
                        "included_routes": configuration.includedRoutes.map { ["destination": $0.destinationAddress, "subnet_mask": $0.subnetMask] },
                        "excluded_routes": configuration.excludedRoutes.map { ["destination": $0.destinationAddress, "subnet_mask": $0.subnetMask] },
                        "tunnel_address6": configuration.tunnelAddress6,
                        "tunnel_prefix6": configuration.tunnelPrefix6,
                        "included_routes6": configuration.includedRoutes6.map { ["destination": $0.destinationAddress, "network_prefix_length": $0.networkPrefixLength] },
                        "excluded_routes6": configuration.excludedRoutes6.map { ["destination": $0.destinationAddress, "network_prefix_length": $0.networkPrefixLength] },
                        "dns_servers": configuration.dnsServers,
                        "mtu": configuration.mtu,
                    ]
                )
                self.prepareSharedOverlayBootstrap(providerConfiguration: providerConfiguration)
                if let connectorMode = self.packetflowConnectorMode(providerConfiguration: providerConfiguration) {
                    if connectorMode == "simple_udp_peer" {
                        self.runtimeMode = "simple_udp_peer"
                    } else if connectorMode == "swift_udp" || connectorMode == "swift_udp_peer" {
                        self.runtimeMode = "swift_udp"
                    } else {
                        self.runtimeMode = "python_runtime"
                    }
                    self.recordNativeEvent(
                        "packetflow_connector_mode_selected",
                        fields: ["mode": connectorMode]
                    )
                    self.updateProviderState(
                        "packetflow_connector_mode_selected",
                        extraFields: ["mode": connectorMode]
                    )
                }
                if let swiftSettings = self.swiftSimpleUDPPeerSettings(
                    providerConfiguration: providerConfiguration,
                    defaultMTU: configuration.mtu
                ) {
                    do {
                        let tcpServiceSpecs = self.localTCPServiceSpecs(providerConfiguration: providerConfiguration)
                        let bridge = try SwiftSimpleUDPPeerBridge(
                            provider: self,
                            settings: swiftSettings,
                            tunnelAddress: configuration.tunnelAddress,
                            tcpServiceSpecs: tcpServiceSpecs,
                            overlayLayerTransportAdapter: self.sharedOverlayLayerTransportAdapter
                        )
                        self.swiftSimpleUDPPeerBridge = bridge
                        bridge.start()
                        self.recordNativeEvent(
                            swiftSettings.runtimeMode == "swift_udp"
                                ? "startTunnel_swift_udp_bridge_started"
                                : "startTunnel_completed_swift_simple_udp_peer",
                            fields: [
                                "mode": swiftSettings.runtimeMode,
                                "peer_host": swiftSettings.peerHost,
                                "peer_port": swiftSettings.peerPort,
                                "bind_host": swiftSettings.bindHost,
                                "bind_port": swiftSettings.bindPort,
                                "mtu": swiftSettings.mtu,
                            ]
                        )
                        if swiftSettings.runtimeMode == "swift_simple_udp_peer" {
                            self.runtimeMode = "swift_simple_udp_peer"
                            self.startProviderHeartbeat()
                            self.updateProviderState("startTunnel_completed_swift_simple_udp_peer")
                            completionHandler(nil)
                            return
                        }
                        self.runtimeMode = "swift_udp"
                        self.updateProviderState(
                            "startTunnel_swift_udp_bridge_started",
                            extraFields: ["mode": swiftSettings.runtimeMode]
                        )
                    } catch {
                        self.recordNativeEvent(
                            swiftSettings.runtimeMode == "swift_udp"
                                ? "startTunnel_swift_udp_bridge_failed"
                                : "startTunnel_swift_simple_udp_peer_failed",
                            fields: [
                                "mode": swiftSettings.runtimeMode,
                                "error": error.localizedDescription,
                                "error_type": String(describing: type(of: error)),
                            ]
                        )
                        self.updateProviderState(
                            swiftSettings.runtimeMode == "swift_udp"
                                ? "startTunnel_swift_udp_bridge_failed"
                                : "startTunnel_swift_simple_udp_peer_failed",
                            extraFields: [
                                "error": error.localizedDescription,
                                "mode": swiftSettings.runtimeMode,
                            ]
                        )
                        completionHandler(error)
                        return
                    }
                }
                #if OB_IPSERVER_SWIFT_SMOKE
                self.recordNativeEvent("startTunnel_completed_swift_smoke")
                completionHandler(nil)
                #elseif OB_IPSERVER_PYTHON_PROBE
                self.recordNativeEvent("startTunnel_completed_python_probe")
                completionHandler(nil)
                #else
                if !self.swiftUDPRuntimeActive {
                    ObstacleBridgePacketFlowBridge.activate(
                        provider: self,
                        tunnelAddress: configuration.tunnelAddress,
                        mtu: configuration.mtu
                    )
                    self.startPacketPump()
                }
                self.startProviderHeartbeat()
                self.recordNativeEvent("startTunnel_completed_runtime_start_async")
                self.updateProviderState("startTunnel_completed_runtime_start_async")
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
            updateProviderState("startTunnel_configuration_failed", extraFields: ["error": error.localizedDescription])
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
        updateProviderState(
            "stopTunnel_entered",
            extraFields: [
                "reason": reason.rawValue,
                "reason_text": Self.stopReasonText(reason),
            ]
        )
        heartbeatTimer?.cancel()
        heartbeatTimer = nil
        swiftSimpleUDPPeerBridge?.stop()
        swiftSimpleUDPPeerBridge = nil
        #if !OB_IPSERVER_SWIFT_SMOKE
        if runtimeMode != "swift_simple_udp_peer" {
            _ = try? bridgeResponse(for: ["command": "stop", "reason": reason.rawValue])
        }
        #endif
        packetPumpRunning = false
        if runtimeMode != "swift_simple_udp_peer" && runtimeMode != "swift_udp" {
            ObstacleBridgePacketFlowBridge.deactivate()
        }
        recordNativeEvent("stopTunnel_completed", fields: ["reason": reason.rawValue])
        updateProviderState("stopTunnel_completed", extraFields: ["reason": reason.rawValue])
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
            if let adminRequest = ObstacleBridgeAdminAPI.request(fromMessagePayload: payload) {
                let response = ObstacleBridgeAdminAPI.appMessageResponse(for: adminRequest, provider: self)
                recordNativeEvent(
                    "handleAppMessage_completed",
                    fields: [
                        "command": "admin_api_request",
                        "path": adminRequest.path,
                        "method": adminRequest.method,
                    ]
                )
                let data = try JSONSerialization.data(withJSONObject: response)
                completionHandler?(data)
                return
            }
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
            let response: [String: Any]
            if runtimeMode == "swift_simple_udp_peer" {
                response = [
                    "ok": true,
                    "mode": "swift_simple_udp_peer",
                    "status": "provider alive",
                    "command": String(describing: payload["command"] ?? ""),
                    "swift_udp_bridge_state": swiftSimpleUDPPeerBridge?.snapshot() ?? [:],
                ]
            } else {
                response = try bridgeResponse(for: payload)
            }
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

        if !configuration.tunnelAddress6.isEmpty {
            let ipv6 = NEIPv6Settings(
                addresses: [configuration.tunnelAddress6],
                networkPrefixLengths: [NSNumber(value: configuration.tunnelPrefix6)]
            )
            ipv6.includedRoutes = configuration.includedRoutes6.map { route in
                NEIPv6Route(destinationAddress: route.destinationAddress, networkPrefixLength: NSNumber(value: route.networkPrefixLength))
            }
            ipv6.excludedRoutes = configuration.excludedRoutes6.map { route in
                NEIPv6Route(destinationAddress: route.destinationAddress, networkPrefixLength: NSNumber(value: route.networkPrefixLength))
            }
            settings.ipv6Settings = ipv6
        }

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
        updateProviderState("packet_pump_started")
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
                var totalBytes = 0
                for (index, packet) in packets.enumerated() {
                    totalBytes += packet.count
                    let proto = index < protocols.count ? protocols[index] : NSNumber(value: AF_INET)
                    ObstacleBridgePacketFlowBridge.enqueueIncomingPacket(packet, protocolFamily: proto)
                }
                self.recordNativeEvent(
                    "packet_pump_forwarded_packets",
                    fields: [
                        "packet_count": packets.count,
                        "protocol_count": protocols.count,
                        "total_bytes": totalBytes,
                    ]
                )
                if packets.count >= 32 || totalBytes >= 32768 {
                    self.updateProviderState(
                        "packet_pump_forwarded_packets",
                        extraFields: [
                            "packet_count": packets.count,
                            "total_bytes": totalBytes,
                        ]
                    )
                }
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

    private static func processMemorySnapshot() -> [String: Any] {
        var payload: [String: Any] = [:]

        var basicInfo = mach_task_basic_info()
        var basicCount = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size) / 4
        let basicKernReturn: kern_return_t = withUnsafeMutablePointer(to: &basicInfo) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(basicCount)) { rebound in
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), rebound, &basicCount)
            }
        }
        payload["mach_task_basic_info_kern_return"] = basicKernReturn
        if basicKernReturn == KERN_SUCCESS {
            payload["resident_size"] = basicInfo.resident_size
            payload["virtual_size"] = basicInfo.virtual_size
            payload["resident_size_mb"] = Double(basicInfo.resident_size) / 1_048_576.0
            payload["virtual_size_mb"] = Double(basicInfo.virtual_size) / 1_048_576.0
        }

        var vmInfo = task_vm_info_data_t()
        var vmCount = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size) / 4
        let vmKernReturn: kern_return_t = withUnsafeMutablePointer(to: &vmInfo) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(vmCount)) { rebound in
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), rebound, &vmCount)
            }
        }
        payload["task_vm_info_kern_return"] = vmKernReturn
        if vmKernReturn == KERN_SUCCESS {
            payload["phys_footprint"] = vmInfo.phys_footprint
            payload["phys_footprint_mb"] = Double(vmInfo.phys_footprint) / 1_048_576.0
            payload["internal_bytes"] = vmInfo.internal
            payload["compressed_bytes"] = vmInfo.compressed
            payload["reusable_bytes"] = vmInfo.reusable
        }

        return payload
    }

    private func runtimeConfigURL() -> URL? {
        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.obstaclebridge.shared"
        ) else {
            return nil
        }
        return containerURL.appendingPathComponent("config/ObstacleBridge.cfg", isDirectory: false)
    }

    private func loadSharedRuntimeConfigJSON() -> [String: Any]? {
        guard let url = runtimeConfigURL(),
              let data = try? Data(contentsOf: url),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return nil
        }
        return json
    }

    private func swiftSimpleUDPPeerSettings(
        providerConfiguration: [String: Any]?,
        defaultMTU: Int
    ) -> SwiftSimpleUDPPeerSettings? {
        if let payload = runtimeConfigPayload(providerConfiguration: providerConfiguration),
           let settings = Self.swiftSimpleUDPPeerSettings(from: payload, defaultMTU: defaultMTU) {
            return settings
        }
        return nil
    }

    private func packetflowConnectorMode(providerConfiguration: [String: Any]?) -> String? {
        if let payload = runtimeConfigPayload(providerConfiguration: providerConfiguration),
           let mode = Self.packetflowConnectorMode(from: payload) {
            return mode
        }
        return nil
    }

    private func localTCPServiceSpecs(providerConfiguration: [String: Any]?) -> [ObstacleBridgeChannelMuxCodec.ServiceSpec] {
        if let payload = runtimeConfigPayload(providerConfiguration: providerConfiguration) {
            return Self.localTCPServiceSpecs(from: payload)
        }
        return []
    }

    private func runtimeConfigPayload(providerConfiguration: [String: Any]?) -> [String: Any]? {
        if let runtimeConfig = providerConfiguration?["runtime_config"] as? [String: Any] {
            return ObstacleBridgeRuntimeConfig.flatten(runtimeConfig)
        }
        if let payload = loadSharedRuntimeConfigJSON() {
            return ObstacleBridgeRuntimeConfig.flatten(payload)
        }
        return nil
    }

    private func prepareSharedOverlayBootstrap(providerConfiguration: [String: Any]?) {
        sharedCompressLayerRuntime = nil
        sharedSecureLinkPskTransportAdapter = nil
        sharedOverlayLayerTransportAdapter = nil
        sharedWebSocketOverlayRuntime = nil
        sharedTcpOverlayRuntime = nil
        sharedOverlayBootstrapState = [:]

        guard let payload = runtimeConfigPayload(providerConfiguration: providerConfiguration) else {
            return
        }

        do {
            let settings = try ObstacleBridgeOverlayBootstrapSettings(payload: payload)
            var summary = settings.summary()

            if settings.compressWrapped {
                let allowedMTypes = ObstacleBridgeRuntimeConfig.stringValue(from: payload["compress_layer_types"]) ?? "data,data_frag"
                let level = ObstacleBridgeRuntimeConfig.intValue(from: payload["compress_layer_level"]) ?? 3
                let minBytes = ObstacleBridgeRuntimeConfig.intValue(from: payload["compress_layer_min_bytes"]) ?? 64
                sharedCompressLayerRuntime = try ObstacleBridgeCompressLayerRuntime(
                    algorithm: settings.compressAlgo,
                    level: level,
                    minBytes: minBytes,
                    allowedMTypesRaw: allowedMTypes,
                    peerSelectedAllowedMTypesRaw: allowedMTypes
                )
                summary["compress_runtime"] = "ready"
                summary["compress_layer_types"] = allowedMTypes
            }

            if settings.secureLinkMode == "psk" {
                sharedSecureLinkPskTransportAdapter = ObstacleBridgeSecureLinkPskTransportAdapter(
                    runtime: ObstacleBridgeSecureLinkPskRuntime(
                        clientMode: settings.peerHost != nil,
                        psk: settings.secureLinkPSK
                    )
                )
                summary["secure_link_runtime"] = "ready"
            }

            if sharedCompressLayerRuntime != nil || sharedSecureLinkPskTransportAdapter != nil {
                sharedOverlayLayerTransportAdapter = ObstacleBridgeOverlayLayerTransportAdapter(
                    compressRuntime: sharedCompressLayerRuntime,
                    secureLinkAdapter: sharedSecureLinkPskTransportAdapter
                )
            }

            if settings.transport == "ws" {
                let payloadMode = ObstacleBridgeRuntimeConfig.stringValue(from: payload["ws_payload_mode"]) ?? "binary"
                let maxSize = ObstacleBridgeRuntimeConfig.intValue(from: payload["ws_max_size"]) ?? 65535
                let sendTimeout = ObstacleBridgeRuntimeConfig.doubleValue(from: payload["ws_send_timeout"]) ?? 3.0
                let tcpUserTimeout = ObstacleBridgeRuntimeConfig.intValue(from: payload["ws_tcp_user_timeout_ms"]) ?? 10000
                let reconnectGrace = ObstacleBridgeRuntimeConfig.doubleValue(from: payload["ws_reconnect_grace"]) ?? 3.0
                sharedWebSocketOverlayRuntime = try ObstacleBridgeWebSocketOverlayRuntime(
                    payloadMode: payloadMode,
                    wsMaxSize: maxSize,
                    sendTimeoutS: sendTimeout,
                    tcpUserTimeoutMS: tcpUserTimeout,
                    reconnectGraceS: reconnectGrace
                )
                summary["websocket_runtime"] = "ready"
                summary["ws_payload_mode"] = payloadMode
            }

            if settings.transport == "tcp" {
                let threshold = ObstacleBridgeRuntimeConfig.intValue(from: payload["tcp_bp_wbuf_threshold"]) ?? 128 * 1024
                sharedTcpOverlayRuntime = ObstacleBridgeTcpOverlayRuntime(wbufThreshold: threshold)
                summary["tcp_runtime"] = "ready"
                summary["tcp_bp_wbuf_threshold"] = threshold
            }

            sharedOverlayBootstrapState = summary
            recordNativeEvent("shared_overlay_runtime_prepared", fields: summary)
        } catch {
            let summary: [String: Any] = [
                "status": "failed",
                "overlay_transport": ObstacleBridgeRuntimeConfig.stringValue(from: payload["overlay_transport"]) ?? "myudp",
                "error": error.localizedDescription,
            ]
            sharedOverlayBootstrapState = summary
            recordNativeEvent("shared_overlay_runtime_prepare_failed", fields: summary)
        }
    }

    private static func packetflowConnectorMode(from payload: [String: Any]) -> String? {
        ObstacleBridgeRuntimeConfig.packetflowConnectorMode(from: payload)
    }

    private static func localTCPServiceSpecs(from payload: [String: Any]) -> [ObstacleBridgeChannelMuxCodec.ServiceSpec] {
        ObstacleBridgeRuntimeConfig.localTCPServiceSpecs(from: payload)
    }

    private static func intValue(from value: Any?) -> Int? {
        ObstacleBridgeRuntimeConfig.intValue(from: value)
    }

    private static func doubleValue(from value: Any?) -> Double? {
        ObstacleBridgeRuntimeConfig.doubleValue(from: value)
    }

    private static func boolValue(from value: Any?) -> Bool? {
        ObstacleBridgeRuntimeConfig.boolValue(from: value)
    }

    private static func stringValue(from value: Any?) -> String? {
        ObstacleBridgeRuntimeConfig.stringValue(from: value)
    }

    private static func peerHost(for transport: String, payload: [String: Any]) -> String? {
        ObstacleBridgeRuntimeConfig.peerHost(for: transport, payload: payload)
    }

    private static func jsonDictionary(from value: Any?) -> [String: ObstacleBridgeChannelMuxCodec.JSONValue]? {
        guard let value else {
            return nil
        }
        guard let json = ObstacleBridgeChannelMuxCodec.jsonValue(from: value) else {
            return nil
        }
        if case .object(let object) = json {
            return object
        }
        return nil
    }

    private static func swiftSimpleUDPPeerSettings(
        from payload: [String: Any],
        defaultMTU: Int
    ) -> SwiftSimpleUDPPeerSettings? {
        guard let config = ObstacleBridgeRuntimeConfig.swiftUDPPeerConfig(from: payload, defaultMTU: defaultMTU) else {
            return nil
        }
        return SwiftSimpleUDPPeerSettings(
            runtimeMode: config.runtimeMode,
            bindHost: config.bindHost,
            bindPort: config.bindPort,
            peerHost: config.peerHost,
            peerPort: config.peerPort,
            peerResolveFamily: config.peerResolveFamily,
            mtu: config.mtu,
            tunIfname: config.tunIfname
        )
    }
}

extension PacketTunnelProvider: ObstacleBridgeAdminAPIStateProvider {
    func adminStatusSnapshot() -> [String: Any] {
        let bridgeSnapshot = adminBridgeSnapshot()
        var payload: [String: Any] = [
            "runtime_owner": "IPServer Network Extension",
            "runtime_mode": runtimeMode,
            "packet_pump_running": packetPumpRunning,
            "provider_state_update_count": providerStateUpdateCount,
            "heartbeat_tick_count": heartbeatTickCount,
            "bridge_state": ObstacleBridgePacketFlowBridge.bridgeStateSnapshot(),
            "shared_overlay_bootstrap_state": sharedOverlayBootstrapState,
            "transport_runtime": adminTransportRuntimeSnapshot(bridgeSnapshot: bridgeSnapshot),
            "compress_layer": adminCompressLayerSnapshot() ?? NSNull(),
        ]
        if !bridgeSnapshot.isEmpty {
            payload["swift_udp_bridge_state"] = bridgeSnapshot
        }
        for (key, value) in Self.processMemorySnapshot() {
            payload[key] = value
        }
        return payload
    }

    func adminConnectionsSnapshot() -> [String: Any] {
        PacketTunnelProviderAdminSnapshotBuilder.connectionsSnapshot(
            runtimeConfig: adminRuntimeConfigPayload() ?? [:],
            packetPumpRunning: packetPumpRunning,
            bridgeSnapshot: adminBridgeSnapshot(),
            bridgeRows: swiftSimpleUDPPeerBridge?.connectionRows()
        )
    }

    func adminPeersSnapshot() -> [[String: Any]] {
        let bridgeSnapshot = adminBridgeSnapshot()
        let traffic = adminPeerTraffic(bridgeSnapshot: bridgeSnapshot)
        let openConnections = adminOpenConnections(bridgeSnapshot: bridgeSnapshot)
        let state = (adminBoolValue(bridgeSnapshot["active"]) || packetPumpRunning) ? "connected" : "idle"
        let runtimeConfig = adminRuntimeConfigPayload()
        let transport = ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig?["overlay_transport"]) ?? "myudp"
        let endpoint = adminPeerEndpoint(runtimeConfig: runtimeConfig)
        return [[
            "id": 1,
            "transport": transport,
            "state": state,
            "listen": NSNull(),
            "peer": endpoint,
            "decode_errors": 0,
            "inflight": 0,
            "last_incoming_age_seconds": NSNull(),
            "traffic": traffic,
            "open_connections": openConnections,
            "secure_link": adminSecureLinkSnapshot(state: state),
            "compress_layer": adminCompressLayerSnapshot() ?? NSNull(),
            "runtime": adminTransportRuntimeSnapshot(bridgeSnapshot: bridgeSnapshot),
        ]]
    }

    func adminMetaSnapshot() -> [String: Any] {
        let bridgeSnapshot = adminBridgeSnapshot()
        return [
            "runtime_owner": "IPServer Network Extension",
            "runtime_mode": runtimeMode,
            "bootstrap_state": sharedOverlayBootstrapState,
            "control_actions": [
                "restart_supported": false,
                "reconnect_supported": false,
                "shutdown_supported": false,
            ],
            "transport_runtime": adminTransportRuntimeSnapshot(bridgeSnapshot: bridgeSnapshot),
            "compress_layer": adminCompressLayerSnapshot() ?? NSNull(),
            "secure_link": adminSecureLinkSnapshot(state: packetPumpRunning ? "connected" : "idle"),
        ]
    }

    func adminConfigSnapshot() -> [String: Any] {
        [
            "config": adminRuntimeConfigPayload() ?? [:],
            "schema": [:],
        ]
    }

    func adminLogLines(limit: Int) -> [String] {
        guard let url = adminNativeProviderLogURL(),
              let text = try? String(contentsOf: url, encoding: .utf8) else {
            return []
        }
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        return Array(lines.suffix(max(1, min(limit, 1000))))
    }

    private func adminRuntimeConfigPayload() -> [String: Any]? {
        let providerConfiguration = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        return runtimeConfigPayload(providerConfiguration: providerConfiguration)
    }

    private func adminBridgeSnapshot() -> [String: Any] {
        swiftSimpleUDPPeerBridge?.snapshot() ?? [:]
    }

    private func adminTransportRuntimeSnapshot(bridgeSnapshot: [String: Any]) -> [String: Any] {
        let overlayConnected = adminBoolValue(bridgeSnapshot["active"]) || packetPumpRunning
        return [
            "packetflow_bridge": ObstacleBridgePacketFlowBridge.bridgeStateSnapshot(),
            "swift_udp_bridge_state": bridgeSnapshot,
            "tcp": [
                "overlay_connected": overlayConnected,
                "listener_count": adminIntValue(bridgeSnapshot["tcp_listener_count"]),
                "server_connection_count": adminIntValue(bridgeSnapshot["tcp_server_connection_count"]),
                "client_connection_count": adminIntValue(bridgeSnapshot["tcp_client_connection_count"]),
            ],
        ]
    }

    private func adminPeerTraffic(bridgeSnapshot: [String: Any]) -> [String: Any] {
        [
            "rx_bytes": adminIntValue(bridgeSnapshot["bytes_to_system"]),
            "tx_bytes": adminIntValue(bridgeSnapshot["bytes_from_system"]),
            "rx_bytes_per_sec": 0,
            "tx_bytes_per_sec": 0,
        ]
    }

    private func adminOpenConnections(bridgeSnapshot: [String: Any]) -> [String: Any] {
        [
            "udp": 0,
            "tcp": adminIntValue(bridgeSnapshot["tcp_server_connection_count"]) + adminIntValue(bridgeSnapshot["tcp_client_connection_count"]),
            "tun": packetPumpRunning ? 1 : 0,
        ]
    }

    private func adminConnectionRow(
        for spec: ObstacleBridgeRuntimeServiceSpec,
        state: String,
        stats: [String: Any] = [
            "tx_bytes": 0,
            "rx_bytes": 0,
        ]
    ) -> [String: Any] {
        [
            "svc_id": spec.svcID,
            "service_name": spec.name ?? "svc_\(spec.svcID)",
            "state": state,
            "listen_protocol": spec.listenProtocol,
            "local_bind": spec.listenBind,
            "local_port": spec.listenPort,
            "remote_destination": [
                "host": spec.targetHost,
                "port": spec.targetPort,
            ],
            "stats": stats,
        ]
    }

    private func adminIntValue(_ value: Any?) -> Int {
        if let value = value as? Int {
            return value
        }
        if let value = value as? NSNumber {
            return value.intValue
        }
        return 0
    }

    private func adminBoolValue(_ value: Any?) -> Bool {
        if let value = value as? Bool {
            return value
        }
        if let value = value as? NSNumber {
            return value.boolValue
        }
        return false
    }

    private func adminPeerEndpoint(runtimeConfig: [String: Any]?) -> Any {
        guard let runtimeConfig else {
            return NSNull()
        }
        let transport = ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["overlay_transport"]) ?? "myudp"
        let host = ObstacleBridgeRuntimeConfig.peerHost(for: transport, payload: runtimeConfig) ?? ""
        let port: Any
        switch transport {
        case "tcp":
            port = ObstacleBridgeRuntimeConfig.intValue(from: runtimeConfig["tcp_peer_port"]) ?? NSNull()
        case "ws":
            port = ObstacleBridgeRuntimeConfig.intValue(from: runtimeConfig["ws_peer_port"]) ?? NSNull()
        case "quic":
            port = ObstacleBridgeRuntimeConfig.intValue(from: runtimeConfig["quic_peer_port"]) ?? NSNull()
        default:
            port = ObstacleBridgeRuntimeConfig.intValue(from: runtimeConfig["udp_peer_port"]) ?? NSNull()
        }
        guard !host.isEmpty else {
            return NSNull()
        }
        return ["host": host, "port": port]
    }

    private func adminCompressLayerSnapshot() -> [String: Any]? {
        guard let runtime = sharedCompressLayerRuntime else {
            return nil
        }
        let snapshot = runtime.statusSnapshot(peerID: nil)
        return [
            "enabled": snapshot.enabled,
            "algorithm": snapshot.algorithm,
            "transport": snapshot.transport,
            "level": snapshot.level,
            "min_bytes": snapshot.minBytes,
            "compress_attempts_total": snapshot.compressAttemptsTotal,
            "compress_applied_total": snapshot.compressAppliedTotal,
            "compress_skipped_no_gain_total": snapshot.compressSkippedNoGainTotal,
            "compress_input_bytes_total": snapshot.compressInputBytesTotal,
            "compress_output_bytes_total": snapshot.compressOutputBytesTotal,
            "decompress_ok_total": snapshot.decompressOKTotal,
            "decompress_fail_total": snapshot.decompressFailTotal,
        ]
    }

    private func adminSecureLinkSnapshot(state: String) -> [String: Any] {
        let enabled = ObstacleBridgeRuntimeConfig.boolValue(from: adminRuntimeConfigPayload()?["secure_link"]) ?? false
        let mode = ObstacleBridgeRuntimeConfig.stringValue(from: adminRuntimeConfigPayload()?["secure_link_mode"]) ?? "off"
        guard enabled, let adapter = sharedSecureLinkPskTransportAdapter else {
            return [
                "enabled": enabled,
                "mode": mode,
                "state": state,
                "authenticated": false,
                "session_id": NSNull(),
                "rekey_in_progress": false,
                "last_event": "bootstrap",
                "last_event_unix_ts": NSNull(),
                "last_authenticated_unix_ts": NSNull(),
                "connected_since_unix_ts": NSNull(),
                "authenticated_sessions_total": 0,
                "rekeys_completed_total": 0,
                "peer_subject_id": "",
                "peer_subject_name": "",
                "peer_roles": [],
                "peer_deployment_id": "",
                "peer_serial": "",
                "issuer_id": "",
                "trust_validation_state": "n/a",
                "trust_failure_reason": "",
                "trust_failure_detail": "",
                "active_material_generation": 0,
                "last_material_reload_unix_ts": NSNull(),
                "last_material_reload_scope": "",
                "last_material_reload_result": "",
                "last_material_reload_detail": "",
                "trust_enforced_unix_ts": NSNull(),
                "disconnect_reason": "",
                "disconnect_detail": "",
            ]
        }

        let snapshot = adapter.statusSnapshot()
        let secureState: String
        let lastEvent: String
        let disconnectReason: String
        if snapshot.authenticated {
            secureState = "authenticated"
            lastEvent = "authenticated"
            disconnectReason = ""
        } else if snapshot.authFailCode != 0 {
            secureState = "auth_failed"
            lastEvent = "auth_failed"
            disconnectReason = "auth_failed"
        } else if snapshot.sessionID != 0 {
            secureState = "handshaking"
            lastEvent = "handshake_started"
            disconnectReason = ""
        } else {
            secureState = state
            lastEvent = "bootstrap"
            disconnectReason = ""
        }

        return [
            "enabled": true,
            "mode": mode,
            "state": secureState,
            "authenticated": snapshot.authenticated,
            "session_id": snapshot.sessionID == 0 ? NSNull() : snapshot.sessionID,
            "rekey_in_progress": false,
            "last_event": lastEvent,
            "last_event_unix_ts": NSNull(),
            "last_authenticated_unix_ts": snapshot.authenticated ? Int(Date().timeIntervalSince1970) : NSNull(),
            "connected_since_unix_ts": snapshot.sessionID == 0 ? NSNull() : Int(Date().timeIntervalSince1970),
            "authenticated_sessions_total": snapshot.authenticated ? 1 : 0,
            "rekeys_completed_total": 0,
            "peer_subject_id": "",
            "peer_subject_name": "",
            "peer_roles": [],
            "peer_deployment_id": "",
            "peer_serial": "",
            "issuer_id": "",
            "trust_validation_state": snapshot.authenticated ? "validated" : "n/a",
            "trust_failure_reason": snapshot.authFailCode == 0 ? "" : "psk_auth_failed",
            "trust_failure_detail": snapshot.authFailCode == 0 ? "" : "code=\(snapshot.authFailCode)",
            "active_material_generation": snapshot.sessionID == 0 ? 0 : 1,
            "last_material_reload_unix_ts": NSNull(),
            "last_material_reload_scope": "",
            "last_material_reload_result": "",
            "last_material_reload_detail": "",
            "trust_enforced_unix_ts": NSNull(),
            "disconnect_reason": disconnectReason,
            "disconnect_detail": snapshot.authFailCode == 0 ? "" : "code=\(snapshot.authFailCode)",
        ]
    }

    private func adminNativeProviderLogURL() -> URL? {
        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.obstaclebridge.shared"
        ) else {
            return nil
        }
        return containerURL.appendingPathComponent("logs", isDirectory: true).appendingPathComponent("ipserver-native-provider.jsonl")
    }
}

private enum PacketTunnelProviderAdminSnapshotBuilder {
    static func connectionsSnapshot(
        runtimeConfig: [String: Any],
        packetPumpRunning: Bool,
        bridgeSnapshot: [String: Any],
        bridgeRows: (tcp: [[String: Any]], udp: [[String: Any]], tun: [[String: Any]])?
    ) -> [String: Any] {
        let serviceSpecs = ObstacleBridgeRuntimeConfig.ownServerSpecs(from: runtimeConfig, preserveInputIndices: true)
        let tcpConnectedRows = bridgeRows?.tcp ?? []
        let tcpListening = max(intValue(bridgeSnapshot["tcp_listener_count"]), serviceSpecs.filter { $0.listenProtocol == "tcp" }.count)
        let tunActive = packetPumpRunning ? 1 : 0

        var tcpRows = serviceSpecs
            .filter { $0.listenProtocol == "tcp" }
            .map { connectionRow(for: $0, state: "listening") }
        tcpRows.append(contentsOf: tcpConnectedRows)
        tcpRows.sort { lhs, rhs in
            let leftListening = String(describing: lhs["state"] ?? "") == "listening"
            let rightListening = String(describing: rhs["state"] ?? "") == "listening"
            if leftListening != rightListening {
                return !leftListening && rightListening
            }
            let leftChan = lhs["chan_id"] as? Int ?? -1
            let rightChan = rhs["chan_id"] as? Int ?? -1
            return leftChan < rightChan
        }

        let udpRows = serviceSpecs
            .filter { $0.listenProtocol == "udp" }
            .map { connectionRow(for: $0, state: "listening") }

        var tunRows = serviceSpecs
            .filter { $0.listenProtocol == "tun" }
            .map { connectionRow(for: $0, state: "listening") }
        if tunActive > 0, let primaryTun = serviceSpecs.first(where: { $0.listenProtocol == "tun" }) {
            tunRows.append(connectionRow(for: primaryTun, state: "connected"))
        }

        return [
            "counts": [
                "udp": 0,
                "tcp": tcpConnectedRows.count,
                "tun": tunActive,
                "udp_listening": udpRows.count,
                "tcp_listening": tcpListening,
                "tun_listening": tunRows.filter { ($0["state"] as? String) == "listening" }.count,
            ],
            "udp": udpRows,
            "tcp": tcpRows,
            "tun": tunRows,
        ]
    }

    private static func connectionRow(
        for spec: ObstacleBridgeRuntimeServiceSpec,
        state: String,
        stats: [String: Any] = [
            "tx_bytes": 0,
            "rx_bytes": 0,
        ]
    ) -> [String: Any] {
        [
            "svc_id": spec.svcID,
            "service_name": spec.name ?? "svc_\(spec.svcID)",
            "state": state,
            "listen_protocol": spec.listenProtocol,
            "local_bind": spec.listenBind,
            "local_port": spec.listenPort,
            "remote_destination": [
                "host": spec.targetHost,
                "port": spec.targetPort,
            ],
            "stats": stats,
        ]
    }

    private static func intValue(_ value: Any?) -> Int {
        if let value = value as? Int {
            return value
        }
        if let value = value as? NSNumber {
            return value.intValue
        }
        return 0
    }
}

private struct IPv4RouteSpec {
    let destinationAddress: String
    let subnetMask: String
}

private struct IPv6RouteSpec {
    let destinationAddress: String
    let networkPrefixLength: Int
}

private struct TunnelProviderConfiguration {
    let peerHost: String
    let tunnelAddress: String
    let tunnelSubnetMask: String
    let includedRoutes: [IPv4RouteSpec]
    let excludedRoutes: [IPv4RouteSpec]
    let tunnelAddress6: String
    let tunnelPrefix6: Int
    let includedRoutes6: [IPv6RouteSpec]
    let excludedRoutes6: [IPv6RouteSpec]
    let dnsServers: [String]
    let mtu: Int

    init(
        _ providerConfiguration: [String: Any]?,
        fallbackRuntimeConfig: [String: Any]? = nil
    ) throws {
        let payload = providerConfiguration ?? [:]
        if let schema = payload["schema"] as? String, !schema.isEmpty,
           schema != "obstaclebridge.ios.packet-tunnel.v1" {
            throw TunnelError.unsupportedSchema
        }

        let runtimeConfig = (payload["runtime_config"] as? [String: Any]) ?? fallbackRuntimeConfig ?? [:]
        let runtimeNetworkFallback = Self.runtimeNetworkFallback(from: runtimeConfig)

        if let peer = payload["peer"] as? [String: Any],
           let host = peer["host"] as? String,
           !host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            peerHost = host
        } else {
            peerHost = "127.0.0.1"
        }

        let network = payload["network_settings"] as? [String: Any] ?? [:]
        tunnelAddress = (network["tunnel_address"] as? String) ?? PacketTunnelProvider.defaultTunnelAddress
        let prefix = (network["tunnel_prefix"] as? NSNumber)?.intValue ?? PacketTunnelProvider.defaultTunnelPrefix
        tunnelSubnetMask = Self.subnetMask(prefix)
        includedRoutes = try Self.routes(network["included_routes"] as? [String] ?? PacketTunnelProvider.defaultIncludedRoutes)
        excludedRoutes = try Self.routes(network["excluded_routes"] as? [String] ?? PacketTunnelProvider.defaultExcludedRoutes)
        tunnelAddress6 = (network["tunnel_address6"] as? String) ?? PacketTunnelProvider.defaultTunnelAddress6
        tunnelPrefix6 = (network["tunnel_prefix6"] as? NSNumber)?.intValue ?? PacketTunnelProvider.defaultTunnelPrefix6
        includedRoutes6 = try Self.routes6(network["included_routes6"] as? [String] ?? (tunnelAddress6.isEmpty ? [] : PacketTunnelProvider.defaultIncludedRoutes6))
        excludedRoutes6 = try Self.routes6(network["excluded_routes6"] as? [String] ?? (tunnelAddress6.isEmpty ? [] : PacketTunnelProvider.defaultExcludedRoutes6))
        dnsServers = (network["dns_servers"] as? [String]) ?? runtimeNetworkFallback.dnsServers
        mtu = ((network["mtu"] as? NSNumber)?.intValue ?? (network["mtu"] as? Int))
            ?? runtimeNetworkFallback.mtu
            ?? 1500
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

    private static func routes(_ values: [String]) throws -> [IPv4RouteSpec] {
        try values.map { cidr in
            let parts = cidr.split(separator: "/", maxSplits: 1).map(String.init)
            guard parts.count == 2, let prefix = Int(parts[1]), prefix >= 0, prefix <= 32 else {
                throw TunnelError.invalidRoute(cidr)
            }
            return IPv4RouteSpec(destinationAddress: parts[0], subnetMask: subnetMask(prefix))
        }
    }

    private static func routes6(_ values: [String]) throws -> [IPv6RouteSpec] {
        try values.map { cidr in
            let parts = cidr.split(separator: "/", maxSplits: 1).map(String.init)
            guard parts.count == 2, let prefix = Int(parts[1]), prefix >= 0, prefix <= 128 else {
                throw TunnelError.invalidRoute(cidr)
            }
            return IPv6RouteSpec(destinationAddress: parts[0], networkPrefixLength: prefix)
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

private struct SwiftSimpleUDPPeerSettings {
    let runtimeMode: String
    let bindHost: String
    let bindPort: Int
    let peerHost: String
    let peerPort: Int
    let peerResolveFamily: String
    let mtu: Int
    let tunIfname: String
}

private final class SwiftSimpleUDPPeerBridge {
    private struct ConnectionState {
        let proto: String
        let role: String
        let chanID: Int
        let svcID: Int
        let serviceName: String
        let remoteHost: String
        let remotePort: Int
        var state: String
        var localHost: String?
        var localPort: Int?
        var stats: [String: Int]

        func snapshot() -> [String: Any] {
            [
                "protocol": proto,
                "role": role,
                "state": state,
                "chan_id": chanID,
                "svc_id": svcID,
                "service_name": serviceName,
                "source": NSNull(),
                "local": endpoint(host: localHost, port: localPort),
                "local_port": localPort ?? NSNull(),
                "remote_destination": endpoint(host: remoteHost, port: remotePort),
                "stats": stats,
            ]
        }

        private func endpoint(host: String?, port: Int?) -> Any {
            guard let host, let port else {
                return NSNull()
            }
            return ["host": host, "port": port]
        }
    }

    private static let queueKey = DispatchSpecificKey<UInt8>()
    private static let peerFallbackIdleNS: UInt64 = 3_000_000_000
    private weak var provider: PacketTunnelProvider?
    private let settings: SwiftSimpleUDPPeerSettings
    private let tunnelAddress: String
    private let tcpServiceSpecs: [ObstacleBridgeChannelMuxCodec.ServiceSpec]
    private let queue = DispatchQueue(label: "com.obstaclebridge.ipserver.swift-simple-udp-peer")
    private var socketFD: Int32 = -1
    private let socketFamily: Int32
    private let peerCandidates: [ResolvedAddress]
    private var peerCandidateIndex = 0
    private var peerAddress: ResolvedAddress
    private var overlayRuntime: ObstacleBridgeUdpOverlayPeerRuntime?
    private var channelMuxTunRuntime: ObstacleBridgeChannelMuxTunRuntime?
    private var channelMuxTcpTransportOwner: ObstacleBridgeChannelMuxTCPTransportOwner?
    private var overlayLayerTransportAdapter: ObstacleBridgeOverlayLayerTransportAdapter?
    private var tcpListeners: [Int: NWListener] = [:]
    private var readSource: DispatchSourceRead?
    private var controlTimer: DispatchSourceTimer?
    private var retransmitTimer: DispatchSourceTimer?
    private var peerFallbackTimer: DispatchSourceTimer?
    private var started = false
    private var startedAt = Date().timeIntervalSince1970
    private var currentPeerSelectedAtNS: UInt64 = 0
    private var lastInboundDatagramNS: UInt64 = 0
    private var packetsFromSystem = 0
    private var packetsToSystem = 0
    private var bytesFromSystem = 0
    private var bytesToSystem = 0
    private var readBatches = 0
    private var writeBatches = 0
    private var sendFailures = 0
    private var recvFailures = 0
    private var packetFlowCallbacks = 0
    private var lastFromSystemAt = 0.0
    private var lastToSystemAt = 0.0
    private var overlayFramesFromSystem = 0
    private var overlayFramesToSystem = 0
    private var tcpListenerFailures = 0
    private var tcpConnectionsAccepted = 0
    private var tcpConnectionsDialed = 0
    private var tcpConnectionStates: [Int: ConnectionState] = [:]

    init(
        provider: PacketTunnelProvider? = nil,
        settings: SwiftSimpleUDPPeerSettings,
        tunnelAddress: String,
        tcpServiceSpecs: [ObstacleBridgeChannelMuxCodec.ServiceSpec],
        overlayLayerTransportAdapter: ObstacleBridgeOverlayLayerTransportAdapter? = nil
    ) throws {
        self.provider = provider
        self.settings = settings
        self.tunnelAddress = tunnelAddress
        self.tcpServiceSpecs = tcpServiceSpecs
        self.overlayLayerTransportAdapter = overlayLayerTransportAdapter
        self.queue.setSpecific(key: Self.queueKey, value: 1)
        let boundSocket = try Self.makeBoundSocket(
            bindHost: settings.bindHost,
            bindPort: settings.bindPort,
            peerHost: settings.peerHost,
            peerPort: settings.peerPort,
            peerResolveFamily: settings.peerResolveFamily
        )
        self.socketFD = boundSocket.socketFD
        self.socketFamily = boundSocket.socketFamily
        self.peerCandidates = boundSocket.peerCandidates
        self.peerAddress = boundSocket.peerAddress
        if settings.runtimeMode == "swift_udp" {
            self.overlayRuntime = ObstacleBridgeUdpOverlayPeerRuntime()
            self.channelMuxTunRuntime = ObstacleBridgeChannelMuxTunRuntime(
                instanceID: UInt64.random(in: 1...UInt64.max),
                connectionSeq: UInt32.random(in: 1...UInt32.max),
                localSpec: ObstacleBridgeRuntimeConfig.localTunServiceSpec(ifname: settings.tunIfname, mtu: settings.mtu)
            )
            let tcpRuntime = ObstacleBridgeChannelMuxTcpRuntime(
                instanceID: UInt64.random(in: 1...UInt64.max),
                connectionSeq: UInt32.random(in: 1...UInt32.max)
            )
            self.channelMuxTcpTransportOwner = ObstacleBridgeChannelMuxTCPTransportOwner(
                runtime: tcpRuntime,
                queue: queue,
                eventPrefix: "swift_udp",
                eventSink: { [weak self] event, fields in
                    self?.provider?.recordPacketBridgeEvent(event, fields: fields)
                },
                muxFrameSink: { [weak self] frames in
                    self?.sendMuxFrames(frames)
                },
                metricSink: { [weak self] metric in
                    switch metric {
                    case "server_accepted":
                        self?.tcpConnectionsAccepted += 1
                    case "client_dialed":
                        self?.tcpConnectionsDialed += 1
                    default:
                        break
                    }
                },
                transportEventSink: { [weak self] event in
                    self?.handleTCPTransportEvent(event)
                }
            )
        }
    }

    deinit {
        stop()
    }

    func start() {
        guard !started, let provider else { return }
        started = true
        startedAt = Date().timeIntervalSince1970
        currentPeerSelectedAtNS = monotonicNowNS()
        lastInboundDatagramNS = 0

        let source = DispatchSource.makeReadSource(fileDescriptor: socketFD, queue: queue)
        source.setEventHandler { [weak self] in
            self?.drainSocket()
        }
        readSource = source
        source.resume()
        startPeerFallbackTimer()
        if settings.runtimeMode == "swift_udp" {
            startOverlayTimers()
            startTCPServices()
            sendInitialIdleProbe()
        }

        provider.recordPacketBridgeEvent(
            "swift_simple_udp_peer_started",
            fields: [
                "bind_host": settings.bindHost,
                "bind_port": settings.bindPort,
                "peer_host": settings.peerHost,
                "peer_port": settings.peerPort,
                "peer_resolve_family": settings.peerResolveFamily,
                "mtu": settings.mtu,
                "tunnel_address": tunnelAddress,
            ]
        )
        beginPacketFlowReadLoop()
    }

    func startForProbe() {
        guard !started else { return }
        started = true
        startedAt = Date().timeIntervalSince1970
        currentPeerSelectedAtNS = monotonicNowNS()
        lastInboundDatagramNS = 0

        let source = DispatchSource.makeReadSource(fileDescriptor: socketFD, queue: queue)
        source.setEventHandler { [weak self] in
            self?.drainSocket()
        }
        readSource = source
        source.resume()
        startPeerFallbackTimer()
        if settings.runtimeMode == "swift_udp" {
            startOverlayTimers()
            startTCPServices()
            sendInitialIdleProbe()
        }
    }

    func stop() {
        guard started else { return }
        started = false
        controlTimer?.cancel()
        controlTimer = nil
        retransmitTimer?.cancel()
        retransmitTimer = nil
        peerFallbackTimer?.cancel()
        peerFallbackTimer = nil
        readSource?.cancel()
        readSource = nil
        stopTCPServices()
        tcpConnectionStates.removeAll()
        if socketFD >= 0 {
            Darwin.close(socketFD)
            socketFD = -1
        }
        provider?.recordPacketBridgeEvent(
            "swift_simple_udp_peer_stopped",
            fields: snapshot()
        )
    }

    func snapshot() -> [String: Any] {
        withState {
            [
                "active": started,
                "bind_host": settings.bindHost,
                "bind_port": settings.bindPort,
                "peer_host": settings.peerHost,
                "peer_port": settings.peerPort,
                "peer_resolve_family": settings.peerResolveFamily,
                "resolved_peer_host": peerAddress.host,
                "resolved_peer_port": peerAddress.port,
                "resolved_peer_family": Self.familyName(peerAddress.family),
                "resolved_peer_index": peerCandidateIndex,
                "resolved_peer_candidate_count": peerCandidates.count,
                "resolved_peer_candidates": peerCandidates.map { "\($0.host):\($0.port)/\(Self.familyName($0.family))" },
                "mtu": settings.mtu,
                "tunnel_address": tunnelAddress,
                "socket_fd": socketFD,
                "socket_family": Self.familyName(socketFamily),
                "packets_from_system": packetsFromSystem,
                "packets_to_system": packetsToSystem,
                "bytes_from_system": bytesFromSystem,
                "bytes_to_system": bytesToSystem,
                "packetflow_callbacks": packetFlowCallbacks,
                "read_batches": readBatches,
                "write_batches": writeBatches,
                "send_failures": sendFailures,
                "recv_failures": recvFailures,
                "overlay_mode": settings.runtimeMode,
                "overlay_frames_from_system": overlayFramesFromSystem,
                "overlay_frames_to_system": overlayFramesToSystem,
                "tcp_listener_count": tcpListeners.count,
                "tcp_server_connection_count": channelMuxTcpTransportOwner?.serverConnectionCount ?? 0,
                "tcp_client_connection_count": channelMuxTcpTransportOwner?.clientConnectionCount ?? 0,
                "tcp_listener_failures": tcpListenerFailures,
                "tcp_connections_accepted": tcpConnectionsAccepted,
                "tcp_connections_dialed": tcpConnectionsDialed,
                "last_from_system_at": lastFromSystemAt,
                "last_to_system_at": lastToSystemAt,
                "started_at": startedAt,
            ]
        }
    }

    func connectionRows() -> (tcp: [[String: Any]], udp: [[String: Any]], tun: [[String: Any]]) {
        withState {
            let tcpRows = tcpConnectionStates.values.map { $0.snapshot() }.sorted { lhs, rhs in
                (lhs["chan_id"] as? Int ?? -1) < (rhs["chan_id"] as? Int ?? -1)
            }
            return (tcpRows, [], [])
        }
    }

    func overlayEstablishedForProbe() -> Bool {
        withState {
            guard let overlayRuntime else {
                return false
            }
            return overlayRuntime.establishedNS != 0 || overlayRuntime.lastRxWallNS != 0
        }
    }

    private func withState<T>(_ body: () -> T) -> T {
        if DispatchQueue.getSpecific(key: Self.queueKey) != nil {
            return body()
        }
        return queue.sync(execute: body)
    }

    private func beginPacketFlowReadLoop() {
        guard started, let provider else { return }
        provider.packetFlow.readPackets { [weak self] packets, protocols in
            guard let self else { return }
            self.queue.async { [weak self] in
                guard let self, self.started else { return }
                self.packetFlowCallbacks += 1
                self.handlePacketFlowRead(packets: packets, protocols: protocols)
                if self.packetFlowCallbacks <= 3 || (self.packetFlowCallbacks % 128) == 0 {
                    self.provider?.recordPacketBridgeEvent(
                        "swift_simple_udp_peer_packetflow_batch",
                        fields: [
                            "callback_index": self.packetFlowCallbacks,
                            "packet_count": packets.count,
                            "protocol_count": protocols.count,
                        ]
                    )
                }
                self.beginPacketFlowReadLoop()
            }
        }
    }

    private func handlePacketFlowRead(packets: [Data], protocols: [NSNumber]) {
        guard started, let provider else { return }
        if packets.isEmpty {
            return
        }
        var totalBytes = 0
        for packet in packets {
            if settings.runtimeMode == "swift_udp" {
                sendOverlayPayload(packet)
            } else {
                sendDatagram(packet)
            }
            totalBytes += packet.count
        }
        withState {
            packetsFromSystem += packets.count
            bytesFromSystem += totalBytes
            readBatches += 1
            lastFromSystemAt = Date().timeIntervalSince1970
        }
        if packetsFromSystem <= 3 || (packetsFromSystem % 128) == 0 {
            provider.recordPacketBridgeEvent(
                "swift_simple_udp_peer_packetflow_read",
                fields: [
                    "packet_count": packets.count,
                    "protocol_count": protocols.count,
                    "total_bytes": totalBytes,
                ]
            )
        }
    }

    private func drainSocket() {
        guard started else { return }
        var packets: [Data] = []
        var protocols: [NSNumber] = []
        var totalBytes = 0
        var buffer = [UInt8](repeating: 0, count: 65535)

        while started {
            var fromStorage = sockaddr_storage()
            var fromLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let received = withUnsafeMutablePointer(to: &fromStorage) { fromPtr -> Int in
                fromPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                    recvfrom(socketFD, &buffer, buffer.count, 0, sockaddrPtr, &fromLength)
                }
            }
            if received > 0 {
                lastInboundDatagramNS = monotonicNowNS()
                let packet = Data(buffer[0..<received])
                if settings.runtimeMode == "swift_udp" {
                    let completed = handleOverlayDatagram(packet)
                    for payload in completed {
                        packets.append(payload)
                        protocols.append(NSNumber(value: Self.protocolFamily(for: payload)))
                        totalBytes += payload.count
                    }
                } else {
                    packets.append(packet)
                    protocols.append(NSNumber(value: Self.protocolFamily(for: packet)))
                    totalBytes += Int(received)
                }
                continue
            }
            if received == 0 {
                break
            }
            if errno == EAGAIN || errno == EWOULDBLOCK {
                break
            }
            provider?.recordPacketBridgeEvent(
                "swift_simple_udp_peer_recv_failed",
                fields: ["errno": errno]
            )
            withState {
                recvFailures += 1
            }
            break
        }

        guard !packets.isEmpty else {
            return
        }
        provider?.packetFlow.writePackets(packets, withProtocols: protocols)
        withState {
            packetsToSystem += packets.count
            bytesToSystem += totalBytes
            writeBatches += 1
            lastToSystemAt = Date().timeIntervalSince1970
        }
        if packetsToSystem <= 3 || (packetsToSystem % 128) == 0 {
            provider?.recordPacketBridgeEvent(
                "swift_simple_udp_peer_socket_read",
                fields: [
                    "packet_count": packets.count,
                    "total_bytes": totalBytes,
                ]
            )
        }
    }

    private func startOverlayTimers() {
        let control = DispatchSource.makeTimerSource(queue: queue)
        control.schedule(deadline: .now() + .milliseconds(25), repeating: .milliseconds(25))
        control.setEventHandler { [weak self] in
            self?.handleOverlayControlTimer()
        }
        control.resume()
        controlTimer = control

        let retransmit = DispatchSource.makeTimerSource(queue: queue)
        retransmit.schedule(deadline: .now() + .milliseconds(25), repeating: .milliseconds(25))
        retransmit.setEventHandler { [weak self] in
            self?.handleOverlayRetransmitTimer()
        }
        retransmit.resume()
        retransmitTimer = retransmit
    }

    private func startPeerFallbackTimer() {
        guard peerCandidates.count > 1 else {
            return
        }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .seconds(1), repeating: .seconds(1))
        timer.setEventHandler { [weak self] in
            self?.handlePeerFallbackTimer()
        }
        timer.resume()
        peerFallbackTimer = timer
    }

    private func handlePeerFallbackTimer() {
        guard started, peerCandidateIndex + 1 < peerCandidates.count else {
            return
        }
        let nowNS = monotonicNowNS()
        guard lastInboundDatagramNS == 0 || lastInboundDatagramNS < currentPeerSelectedAtNS else {
            return
        }
        guard nowNS >= currentPeerSelectedAtNS,
              nowNS - currentPeerSelectedAtNS >= Self.peerFallbackIdleNS
        else {
            return
        }
        rotateToNextPeerCandidate(nowNS: nowNS)
    }

    private func rotateToNextPeerCandidate(nowNS: UInt64) {
        guard peerCandidateIndex + 1 < peerCandidates.count else {
            return
        }
        peerCandidateIndex += 1
        peerAddress = peerCandidates[peerCandidateIndex]
        currentPeerSelectedAtNS = nowNS
        lastInboundDatagramNS = 0
        provider?.recordPacketBridgeEvent(
            "swift_simple_udp_peer_fallback_rotate",
            fields: [
                "candidate_index": peerCandidateIndex,
                "resolved_peer_host": peerAddress.host,
                "resolved_peer_port": peerAddress.port,
                "resolved_peer_family": Self.familyName(peerAddress.family),
            ]
        )
        if settings.runtimeMode == "swift_udp" {
            sendInitialIdleProbe()
        }
    }

    private func startTCPServices() {
        guard settings.runtimeMode == "swift_udp" else {
            return
        }
        for spec in tcpServiceSpecs {
            guard tcpListeners[spec.svcID] == nil else {
                continue
            }
            guard let port = NWEndpoint.Port(rawValue: UInt16(spec.lPort)) else {
                provider?.recordPacketBridgeEvent(
                    "swift_udp_tcp_listener_invalid_port",
                    fields: ["service_id": spec.svcID, "port": spec.lPort]
                )
                tcpListenerFailures += 1
                continue
            }
            do {
                let parameters = NWParameters.tcp
                parameters.allowLocalEndpointReuse = true
                parameters.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(spec.lBind), port: port)
                let listener = try NWListener(using: parameters)
                listener.stateUpdateHandler = { [weak self] state in
                    self?.queue.async {
                        self?.handleTCPListenerState(state, spec: spec)
                    }
                }
                listener.newConnectionHandler = { [weak self] connection in
                    self?.queue.async {
                        self?.handleAcceptedTCPConnection(connection, spec: spec)
                    }
                }
                tcpListeners[spec.svcID] = listener
                listener.start(queue: queue)
            } catch {
                provider?.recordPacketBridgeEvent(
                    "swift_udp_tcp_listener_start_failed",
                    fields: [
                        "service_id": spec.svcID,
                        "bind": spec.lBind,
                        "port": spec.lPort,
                        "error": error.localizedDescription,
                    ]
                )
                tcpListenerFailures += 1
            }
        }
    }

    private func stopTCPServices() {
        for listener in tcpListeners.values {
            listener.stateUpdateHandler = nil
            listener.newConnectionHandler = nil
            listener.cancel()
        }
        tcpListeners.removeAll()
        channelMuxTcpTransportOwner?.stop()
    }

    private func handleTCPListenerState(_ state: NWListener.State, spec: ObstacleBridgeChannelMuxCodec.ServiceSpec) {
        switch state {
        case .ready:
            provider?.recordPacketBridgeEvent(
                "swift_udp_tcp_listener_ready",
                fields: ["service_id": spec.svcID, "bind": spec.lBind, "port": spec.lPort]
            )
        case .failed(let error):
            tcpListenerFailures += 1
            provider?.recordPacketBridgeEvent(
                "swift_udp_tcp_listener_failed",
                fields: [
                    "service_id": spec.svcID,
                    "bind": spec.lBind,
                    "port": spec.lPort,
                    "error": error.localizedDescription,
                ]
            )
        default:
            break
        }
    }

    private func handleAcceptedTCPConnection(_ connection: NWConnection, spec: ObstacleBridgeChannelMuxCodec.ServiceSpec) {
        guard let owner = channelMuxTcpTransportOwner else {
            cancelConnection(connection)
            return
        }
        guard let chanID = owner.acceptLocalConnection(connection, spec: spec) else {
            cancelConnection(connection)
            return
        }
        tcpConnectionStates[chanID] = ConnectionState(
            proto: "tcp",
            role: "server",
            chanID: chanID,
            svcID: spec.svcID,
            serviceName: serviceName(spec),
            remoteHost: spec.rHost,
            remotePort: spec.rPort,
            state: "connecting",
            localHost: spec.lBind,
            localPort: spec.lPort,
            stats: ["rx_msgs": 0, "tx_msgs": 0, "rx_bytes": 0, "tx_bytes": 0]
        )
    }

    private func sendInitialIdleProbe() {
        guard settings.runtimeMode == "swift_udp" else {
            return
        }
        do {
            let frame = try ObstacleBridgeUdpOverlayCodec.buildProtocolFrame(
                ptype: ObstacleBridgeUdpOverlayCodec.ptypeIdle,
                payload: Data(),
                txNS: monotonicNowNS(),
                echoNS: 0
            )
            sendDatagram(frame)
        } catch {
            provider?.recordPacketBridgeEvent(
                "swift_udp_idle_probe_failed",
                fields: ["error": error.localizedDescription]
            )
        }
    }

    private func handleOverlayControlTimer() {
        guard started, settings.runtimeMode == "swift_udp", let runtime = overlayRuntime else {
            return
        }
        let nowNS = monotonicNowNS()
        let snapshot = runtime.handleControlTimerTick(nowNS: nowNS, sendPortPresent: true)
        guard snapshot.controlShouldEmit else {
            return
        }
        do {
            let control = try runtime.buildOutboundControl(nowNS: nowNS, echoNS: currentEchoNS(nowNS))
            sendDatagram(control.frame)
        } catch {
            provider?.recordPacketBridgeEvent(
                "swift_udp_control_timer_failed",
                fields: ["error": error.localizedDescription]
            )
        }
    }

    private func handleOverlayRetransmitTimer() {
        guard started, settings.runtimeMode == "swift_udp", let runtime = overlayRuntime else {
            return
        }
        do {
            let snapshot = try runtime.handleRetransmitTimerTick(nowNS: monotonicNowNS(), sendPortPresent: true)
            for frame in snapshot.emittedFrames {
                sendDatagram(frame)
            }
        } catch {
            provider?.recordPacketBridgeEvent(
                "swift_udp_retransmit_timer_failed",
                fields: ["error": error.localizedDescription]
            )
        }
    }

    private func sendOverlayPayload(_ packet: Data) {
        guard let runtime = overlayRuntime else {
            sendDatagram(packet)
            return
        }
        do {
            if let muxRuntime = channelMuxTunRuntime {
                guard let localSnapshot = try muxRuntime.handleLocalTunPacket(
                    packet: packet,
                    mtu: settings.mtu,
                    spec: ObstacleBridgeRuntimeConfig.localTunServiceSpec(ifname: settings.tunIfname, mtu: settings.mtu),
                    overlayConnected: true,
                    acceptingEnabled: true
                ) else {
                    return
                }
                for muxFrame in localSnapshot.frames {
                    try sendOverlayApplicationPayload(muxFrame, runtime: runtime)
                }
                return
            }
            try sendOverlayApplicationPayload(packet, runtime: runtime)
        } catch {
            provider?.recordPacketBridgeEvent(
                "swift_udp_payload_send_failed",
                fields: [
                    "error": error.localizedDescription,
                    "packet_bytes": packet.count,
                ]
            )
        }
    }

    private func handleOverlayDatagram(_ datagram: Data) -> [Data] {
        guard let runtime = overlayRuntime,
              let frame = ObstacleBridgeUdpOverlayCodec.parseProtocolFrame(datagram)
        else {
            return []
        }
        let nowNS = monotonicNowNS()
        switch frame.ptype {
        case ObstacleBridgeUdpOverlayCodec.ptypeData:
            guard let snapshot = runtime.handleInboundDataFrame(
                frame: datagram,
                nowNS: nowNS,
                txNS: frame.txNS,
                echoNS: frame.echoNS,
                sendPortPresent: true
            ) else {
                return []
            }
            if !snapshot.controlReasons.isEmpty {
                do {
                    let control = try runtime.buildOutboundControl(nowNS: nowNS, echoNS: currentEchoNS(nowNS))
                    sendDatagram(control.frame)
                } catch {
                    provider?.recordPacketBridgeEvent(
                        "swift_udp_data_control_emit_failed",
                        fields: ["error": error.localizedDescription]
                    )
                }
            }
            overlayFramesToSystem += 1
            return routeOverlayPayloadsToSystem(handleInboundOverlayApplicationPayloads(snapshot.completedPayloads))
        case ObstacleBridgeUdpOverlayCodec.ptypeControl:
            guard let control = ObstacleBridgeUdpOverlayCodec.parseControlFrame(datagram) else {
                return []
            }
            do {
                let snapshot = try runtime.handleInboundControlPacket(
                    nowNS: nowNS,
                    packetLastInOrder: control.lastInOrderRX,
                    packetHighest: control.highestRX,
                    packetMissed: control.missed,
                    sendPortPresent: true
                )
                for frame in snapshot.emittedFrames {
                    sendDatagram(frame)
                }
                if snapshot.controlShouldEmit {
                    let outbound = try runtime.buildOutboundControl(nowNS: nowNS, echoNS: currentEchoNS(nowNS))
                    sendDatagram(outbound.frame)
                }
            } catch {
                provider?.recordPacketBridgeEvent(
                    "swift_udp_inbound_control_failed",
                    fields: ["error": error.localizedDescription]
                )
            }
            overlayFramesToSystem += 1
            return []
        case ObstacleBridgeUdpOverlayCodec.ptypeIdle:
            do {
                let snapshot = try runtime.handleInboundIdleFrame(
                    nowNS: nowNS,
                    txNS: frame.txNS,
                    echoNS: frame.echoNS,
                    sendPortPresent: true
                )
                if let reflected = snapshot.reflectedFrame {
                    sendDatagram(reflected)
                }
            } catch {
                provider?.recordPacketBridgeEvent(
                    "swift_udp_inbound_idle_failed",
                    fields: ["error": error.localizedDescription]
                )
            }
            overlayFramesToSystem += 1
            return []
        default:
            return []
        }
    }

    private func sendDatagram(_ packet: Data) {
        packet.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else { return }
            peerAddress.storage.withUnsafeBytes { peerBuffer in
                guard let peerBase = peerBuffer.baseAddress else { return }
                let sockaddrPtr = peerBase.assumingMemoryBound(to: sockaddr.self)
                let sent = Darwin.sendto(socketFD, base, rawBuffer.count, 0, sockaddrPtr, peerAddress.length)
                if sent < 0 {
                    let err = errno
                    withState {
                        sendFailures += 1
                    }
                    provider?.recordPacketBridgeEvent(
                        "swift_simple_udp_peer_send_failed",
                        fields: [
                            "errno": err,
                            "packet_bytes": rawBuffer.count,
                        ]
                    )
                }
            }
        }
    }

    private func sendOverlayApplicationPayload(_ payload: Data, runtime: ObstacleBridgeUdpOverlayPeerRuntime) throws {
        if let adapter = overlayLayerTransportAdapter {
            let snapshot = try adapter.handleOutboundPayload(payload)
            for frame in snapshot.emittedFrames {
                try sendOverlayTransportPayload(frame, runtime: runtime)
            }
            return
        }
        try sendOverlayTransportPayload(payload, runtime: runtime)
    }

    private func sendOverlayTransportPayload(_ payload: Data, runtime: ObstacleBridgeUdpOverlayPeerRuntime) throws {
        let nowNS = monotonicNowNS()
        let snapshot = try runtime.sendApplicationPayload(payload, nowNS: nowNS, echoNS: currentEchoNS(nowNS))
        for frame in snapshot.frames {
            sendDatagram(frame)
        }
        overlayFramesFromSystem += snapshot.frames.count
    }

    private func handleInboundOverlayApplicationPayloads(_ payloads: [Data]) -> [Data] {
        guard let adapter = overlayLayerTransportAdapter else {
            return payloads
        }
        guard let runtime = overlayRuntime else {
            return []
        }
        var deliveredPayloads: [Data] = []
        for payload in payloads {
            let snapshot = adapter.handleInboundFrame(payload)
            do {
                for frame in snapshot.emittedFrames {
                    try sendOverlayTransportPayload(frame, runtime: runtime)
                }
            } catch {
                provider?.recordPacketBridgeEvent(
                    "swift_udp_overlay_layer_emit_failed",
                    fields: [
                        "error": error.localizedDescription,
                        "payload_bytes": payload.count,
                    ]
                )
            }
            deliveredPayloads.append(contentsOf: snapshot.deliveredPayloads)
        }
        return deliveredPayloads
    }

    private func routeOverlayPayloadsToSystem(_ payloads: [Data]) -> [Data] {
        var packets: [Data] = []
        for payload in payloads {
            guard let frame = ObstacleBridgeChannelMuxCodec.unpackMux(payload) else {
                continue
            }
            switch frame.proto {
            case .tun:
                guard let muxRuntime = channelMuxTunRuntime else {
                    continue
                }
                switch frame.mtype {
                case .open:
                    let snapshot = muxRuntime.handleInboundTunOpen(chanID: frame.chanID, payload: frame.body)
                    if !snapshot.accepted {
                        provider?.recordPacketBridgeEvent(
                            "swift_udp_channelmux_tun_open_rejected",
                            fields: ["chan_id": frame.chanID]
                        )
                    }
                case .openChunk:
                    let snapshot = muxRuntime.handleInboundTunOpenChunk(chanID: frame.chanID, payload: frame.body)
                    if snapshot.assembled && !snapshot.accepted {
                        provider?.recordPacketBridgeEvent(
                            "swift_udp_channelmux_tun_open_chunk_rejected",
                            fields: ["chan_id": frame.chanID]
                        )
                    }
                case .data:
                    let snapshot = muxRuntime.handleInboundTunData(chanID: frame.chanID, body: frame.body, mtu: settings.mtu)
                    if let packet = snapshot.packet, snapshot.delivered {
                        packets.append(packet)
                    }
                case .dataFrag:
                    let snapshot = muxRuntime.handleInboundTunFragment(chanID: frame.chanID, payload: frame.body, mtu: settings.mtu)
                    if let packet = snapshot.packet, snapshot.delivered {
                        packets.append(packet)
                    }
                case .close:
                    _ = muxRuntime.handleInboundTunClose(chanID: frame.chanID)
                default:
                    continue
                }
            case .tcp:
                handleInboundTCPMuxFrame(frame)
            default:
                continue
            }
        }
        return packets
    }

    private func handleInboundTCPMuxFrame(_ frame: ObstacleBridgeChannelMuxCodec.MuxFrame) {
        guard let owner = channelMuxTcpTransportOwner else {
            return
        }
        owner.handleInboundMuxFrame(frame)
    }

    private func sendMuxFrames(_ muxFrames: [Data]) {
        guard let runtime = overlayRuntime, let provider else {
            return
        }
        for muxFrame in muxFrames {
            do {
                let nowNS = monotonicNowNS()
                let snapshot = try runtime.sendApplicationPayload(
                    muxFrame,
                    nowNS: nowNS,
                    echoNS: currentEchoNS(nowNS)
                )
                for frame in snapshot.frames {
                    sendDatagram(frame)
                }
                overlayFramesFromSystem += snapshot.frames.count
            } catch {
                provider.recordPacketBridgeEvent(
                    "swift_udp_tcp_mux_send_failed",
                    fields: [
                        "error": error.localizedDescription,
                        "mux_frame_bytes": muxFrame.count,
                    ]
                )
            }
        }
    }

    private func sendOnTCPConnection(_ connection: NWConnection, payload: Data, chanID: Int, event: String) {
        connection.send(content: payload, completion: .contentProcessed { [weak self] error in
            guard let self, let error else { return }
            self.queue.async {
                self.provider?.recordPacketBridgeEvent(
                    event,
                    fields: ["chan_id": chanID, "error": error.localizedDescription]
                )
            }
        })
    }

    private func cancelConnection(_ connection: NWConnection) {
        connection.stateUpdateHandler = nil
        connection.cancel()
    }

    private func serviceName(_ spec: ObstacleBridgeChannelMuxCodec.ServiceSpec) -> String {
        spec.name ?? ""
    }

    private func updateConnectedState(chanID: Int, localHost: String?, localPort: Int?) {
        guard var state = tcpConnectionStates[chanID] else {
            return
        }
        state.state = "connected"
        state.localHost = localHost ?? state.localHost
        state.localPort = localPort ?? state.localPort
        tcpConnectionStates[chanID] = state
    }

    private func recordInbound(chanID: Int, bytes: Int) {
        guard var state = tcpConnectionStates[chanID] else {
            return
        }
        state.stats["rx_msgs", default: 0] += 1
        state.stats["rx_bytes", default: 0] += bytes
        tcpConnectionStates[chanID] = state
    }

    private func recordOutbound(chanID: Int, bytes: Int) {
        guard var state = tcpConnectionStates[chanID] else {
            return
        }
        state.stats["tx_msgs", default: 0] += 1
        state.stats["tx_bytes", default: 0] += bytes
        tcpConnectionStates[chanID] = state
    }

    private func handleTCPTransportEvent(_ event: ObstacleBridgeChannelMuxTCPTransportOwner.TransportEvent) {
        switch event {
        case .clientAccepted(let chanID, let spec, let connected):
            tcpConnectionStates[chanID] = ConnectionState(
                proto: "tcp",
                role: "client",
                chanID: chanID,
                svcID: spec.svcID,
                serviceName: serviceName(spec),
                remoteHost: spec.rHost,
                remotePort: spec.rPort,
                state: connected ? "connected" : "connecting",
                localHost: nil,
                localPort: nil,
                stats: ["rx_msgs": 0, "tx_msgs": 0, "rx_bytes": 0, "tx_bytes": 0]
            )
        case .clientConnected(let chanID, let localHost, let localPort):
            updateConnectedState(chanID: chanID, localHost: localHost, localPort: localPort)
        case .clientInbound(let chanID, let bytes):
            recordInbound(chanID: chanID, bytes: bytes)
        case .clientOutbound(let chanID, let bytes):
            recordOutbound(chanID: chanID, bytes: bytes)
        case .clientClosed(let chanID):
            tcpConnectionStates.removeValue(forKey: chanID)
        case .serverConnected(let chanID):
            updateConnectedState(chanID: chanID, localHost: nil, localPort: nil)
        case .serverInbound(let chanID, let bytes):
            recordInbound(chanID: chanID, bytes: bytes)
        case .serverOutbound(let chanID, let bytes):
            recordOutbound(chanID: chanID, bytes: bytes)
        case .serverClosed(let chanID):
            tcpConnectionStates.removeValue(forKey: chanID)
        }
    }

    private static let maxTCPReadSize = 65527

    private func currentEchoNS(_ nowNS: UInt64) -> UInt64 {
        guard let runtime = overlayRuntime,
              runtime.lastRxTxNS != 0,
              runtime.lastRxWallNS != 0,
              nowNS >= runtime.lastRxWallNS
        else {
            return 0
        }
        return runtime.lastRxTxNS + (nowNS - runtime.lastRxWallNS)
    }

    private func monotonicNowNS() -> UInt64 {
        return DispatchTime.now().uptimeNanoseconds
    }

    private static func protocolFamily(for packet: Data) -> Int32 {
        guard let first = packet.first else {
            return AF_INET
        }
        let version = (first & 0xF0) >> 4
        return version == 6 ? AF_INET6 : AF_INET
    }

    private enum PeerResolveMode {
        case preferIPv6
        case ipv4
        case ipv6

        init(rawValue: String) {
            switch rawValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
            case "ipv4":
                self = .ipv4
            case "ipv6":
                self = .ipv6
            default:
                self = .preferIPv6
            }
        }

        func rank(for family: Int32) -> Int {
            switch self {
            case .preferIPv6, .ipv6:
                return family == AF_INET6 ? 0 : 1
            case .ipv4:
                return family == AF_INET ? 0 : 1
            }
        }

        var localhostFallback: (host: String, family: Int32)? {
            switch self {
            case .ipv4:
                return ("127.0.0.1", AF_INET)
            case .ipv6:
                return ("::1", AF_INET6)
            case .preferIPv6:
                return nil
            }
        }

        var preferredFamily: Int32? {
            switch self {
            case .ipv4:
                return AF_INET
            case .ipv6:
                return AF_INET6
            case .preferIPv6:
                return nil
            }
        }
    }

    private static func familyName(_ family: Int32) -> String {
        switch family {
        case AF_INET:
            return "ipv4"
        case AF_INET6:
            return "ipv6"
        default:
            return "unspecified"
        }
    }

    private static func stripBrackets(_ host: String) -> String {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("[") && trimmed.hasSuffix("]") {
            return String(trimmed.dropFirst().dropLast())
        }
        return trimmed
    }

    private static func splitConfiguredPeerHosts(_ host: String) -> [String] {
        let rendered = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !rendered.isEmpty else {
            return []
        }
        guard rendered.contains(",") || rendered.contains(";") else {
            return [rendered]
        }
        return rendered
            .replacingOccurrences(of: ";", with: ",")
            .split(separator: ",")
            .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    private static func hostIPFamily(_ host: String) -> Int32? {
        let rendered = stripBrackets(host)
        guard !rendered.isEmpty else {
            return nil
        }
        var ipv4 = in_addr()
        if rendered.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            return AF_INET
        }
        var ipv6 = in6_addr()
        if rendered.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
            return AF_INET6
        }
        return nil
    }

    private static func bindFamilyConstraint(_ bindHost: String) -> Int32? {
        let rendered = stripBrackets(bindHost)
        if rendered.isEmpty || rendered == "::" {
            return nil
        }
        return hostIPFamily(rendered)
    }

    private static func ipv4MappedIPv6(_ host: String) -> String {
        return "::ffff:\(host)"
    }

    private static func numericHostPort(from storage: Data, length: socklen_t) throws -> (String, Int) {
        var hostBuffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        var serviceBuffer = [CChar](repeating: 0, count: Int(NI_MAXSERV))
        let status: Int32 = storage.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else {
                return EAI_FAIL
            }
            let sockaddrPtr = base.assumingMemoryBound(to: sockaddr.self)
            return getnameinfo(
                sockaddrPtr,
                length,
                &hostBuffer,
                socklen_t(hostBuffer.count),
                &serviceBuffer,
                socklen_t(serviceBuffer.count),
                NI_NUMERICHOST | NI_NUMERICSERV
            )
        }
        guard status == 0 else {
            throw NSError(
                domain: "ObstacleBridge.IPServer",
                code: 35,
                userInfo: [NSLocalizedDescriptionKey: "getnameinfo() failed status=\(status)"]
            )
        }
        return (String(cString: hostBuffer), Int(String(cString: serviceBuffer)) ?? 0)
    }

    private static func resolveAddressCandidates(host: String, port: Int, passive: Bool, family: Int32) throws -> [ResolvedAddress] {
        var hints = addrinfo(
            ai_flags: passive ? AI_PASSIVE : 0,
            ai_family: family,
            ai_socktype: SOCK_DGRAM,
            ai_protocol: IPPROTO_UDP,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )
        var results: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, String(port), &hints, &results)
        guard status == 0, let info = results else {
            throw NSError(
                domain: "ObstacleBridge.IPServer",
                code: 34,
                userInfo: [NSLocalizedDescriptionKey: "getaddrinfo() failed for \(host):\(port) status=\(status)"]
            )
        }
        defer { freeaddrinfo(results) }
        var candidates: [ResolvedAddress] = []
        var cursor: UnsafeMutablePointer<addrinfo>? = info
        while let current = cursor {
            let family = current.pointee.ai_family
            if (family == AF_INET || family == AF_INET6), let addr = current.pointee.ai_addr {
                let data = Data(bytes: addr, count: Int(current.pointee.ai_addrlen))
                let numeric = try numericHostPort(from: data, length: current.pointee.ai_addrlen)
                let resolved = ResolvedAddress(
                    family: family,
                    host: numeric.0,
                    port: numeric.1,
                    storage: data,
                    length: current.pointee.ai_addrlen
                )
                if !candidates.contains(where: { $0.family == resolved.family && $0.host == resolved.host && $0.port == resolved.port }) {
                    candidates.append(resolved)
                }
            }
            cursor = current.pointee.ai_next
        }
        guard !candidates.isEmpty else {
            throw NSError(
                domain: "ObstacleBridge.IPServer",
                code: 36,
                userInfo: [NSLocalizedDescriptionKey: "Could not resolve overlay peer \(host)"]
            )
        }
        return candidates
    }

    private static func resolveAddress(host: String, port: Int, passive: Bool, family: Int32) throws -> ResolvedAddress {
        guard let first = try resolveAddressCandidates(host: host, port: port, passive: passive, family: family).first else {
            throw NSError(
                domain: "ObstacleBridge.IPServer",
                code: 36,
                userInfo: [NSLocalizedDescriptionKey: "Could not resolve overlay peer \(host)"]
            )
        }
        return first
    }

    private static func resolvePeerCandidates(
        host: String,
        port: Int,
        mode: PeerResolveMode,
        strictFamily: Bool
    ) throws -> [ResolvedAddress] {
        let rendered = stripBrackets(host)
        guard !rendered.isEmpty else {
            throw NSError(
                domain: "ObstacleBridge.IPServer",
                code: 37,
                userInfo: [NSLocalizedDescriptionKey: "overlay peer requires a non-empty host name"]
            )
        }
        if let family = hostIPFamily(rendered) {
            var resolvedHost = rendered
            var resolvedFamily = family
            if strictFamily {
                switch mode {
                case .ipv4 where family != AF_INET:
                    throw NSError(
                        domain: "ObstacleBridge.IPServer",
                        code: 38,
                        userInfo: [NSLocalizedDescriptionKey: "overlay peer '\(rendered)' is not an IPv4 address"]
                    )
                case .ipv6 where family != AF_INET6:
                    if family == AF_INET {
                        resolvedHost = ipv4MappedIPv6(rendered)
                        resolvedFamily = AF_INET6
                    } else {
                        throw NSError(
                            domain: "ObstacleBridge.IPServer",
                            code: 39,
                            userInfo: [NSLocalizedDescriptionKey: "overlay peer '\(rendered)' is not an IPv6 address"]
                        )
                    }
                default:
                    break
                }
            }
            return [try resolveAddress(host: resolvedHost, port: port, passive: false, family: resolvedFamily)]
        }

        let lookupFamily = strictFamily ? (mode.preferredFamily ?? AF_UNSPEC) : AF_UNSPEC
        do {
            return try resolveAddressCandidates(host: rendered, port: port, passive: false, family: lookupFamily)
        } catch {
            if rendered.lowercased() == "localhost", let fallback = mode.localhostFallback {
                return [try resolveAddress(host: fallback.host, port: port, passive: false, family: fallback.family)]
            }
            throw error
        }
    }

    private static func normalizePeerCandidate(
        _ candidate: ResolvedAddress,
        socketFamily: Int32
    ) throws -> ResolvedAddress {
        guard candidate.family != socketFamily else {
            return candidate
        }
        if socketFamily == AF_INET6, candidate.family == AF_INET {
            return try resolveAddress(
                host: ipv4MappedIPv6(candidate.host),
                port: candidate.port,
                passive: false,
                family: AF_INET6
            )
        }
        throw NSError(
            domain: "ObstacleBridge.IPServer",
            code: 41,
            userInfo: [NSLocalizedDescriptionKey: "overlay peer '\(candidate.host)' is not compatible with socket family \(familyName(socketFamily))"]
        )
    }

    private static func resolvePeerAddresses(
        host: String,
        port: Int,
        resolveFamily: String,
        bindHost: String
    ) throws -> [ResolvedAddress] {
        let configuredHosts = splitConfiguredPeerHosts(host)
        guard !configuredHosts.isEmpty else {
            throw NSError(
                domain: "ObstacleBridge.IPServer",
                code: 37,
                userInfo: [NSLocalizedDescriptionKey: "overlay peer requires a non-empty host name"]
            )
        }
        let mode = PeerResolveMode(rawValue: resolveFamily)
        let strictFamily = configuredHosts.count == 1
        var candidates: [ResolvedAddress] = []
        if strictFamily {
            candidates = try resolvePeerCandidates(host: configuredHosts[0], port: port, mode: mode, strictFamily: true)
        } else {
            for configuredHost in configuredHosts {
                if let resolved = try? resolvePeerCandidates(host: configuredHost, port: port, mode: mode, strictFamily: false) {
                    candidates.append(contentsOf: resolved)
                }
            }
            if candidates.isEmpty {
                throw NSError(
                    domain: "ObstacleBridge.IPServer",
                    code: 36,
                    userInfo: [NSLocalizedDescriptionKey: "Could not resolve overlay peer '\(host)'"]
                )
            }
        }

        candidates.sort { lhs, rhs in
            let lhsRank = mode.rank(for: lhs.family)
            let rhsRank = mode.rank(for: rhs.family)
            if lhsRank != rhsRank {
                return lhsRank < rhsRank
            }
            if lhs.family != rhs.family {
                return lhs.family < rhs.family
            }
            if lhs.host != rhs.host {
                return lhs.host < rhs.host
            }
            return lhs.port < rhs.port
        }

        if let bindFamily = bindFamilyConstraint(bindHost) {
            let compatible = candidates.filter { $0.family == bindFamily }
            if !compatible.isEmpty {
                return compatible
            }
            let famName = bindFamily == AF_INET6 ? "IPv6" : "IPv4"
            throw NSError(
                domain: "ObstacleBridge.IPServer",
                code: 40,
                userInfo: [NSLocalizedDescriptionKey: "overlay peer '\(host)' resolved, but no \(famName) address is compatible with bind '\(bindHost)'"]
            )
        }

        guard let first = candidates.first else {
            throw NSError(
                domain: "ObstacleBridge.IPServer",
                code: 36,
                userInfo: [NSLocalizedDescriptionKey: "Could not resolve overlay peer '\(host)'"]
            )
        }
        _ = first
        return candidates
    }

    private static func makeBoundSocket(
        bindHost: String,
        bindPort: Int,
        peerHost: String,
        peerPort: Int,
        peerResolveFamily: String
    ) throws -> (socketFD: Int32, socketFamily: Int32, peerCandidates: [ResolvedAddress], peerAddress: ResolvedAddress) {
        let resolvedCandidates = try resolvePeerAddresses(
            host: peerHost,
            port: peerPort,
            resolveFamily: peerResolveFamily,
            bindHost: bindHost
        )
        let socketFamily: Int32
        if let bindFamily = bindFamilyConstraint(bindHost) {
            socketFamily = bindFamily
        } else if resolvedCandidates.contains(where: { $0.family == AF_INET6 }) {
            socketFamily = AF_INET6
        } else {
            socketFamily = resolvedCandidates[0].family
        }

        var peerCandidates: [ResolvedAddress] = []
        for candidate in resolvedCandidates {
            let normalized = try normalizePeerCandidate(candidate, socketFamily: socketFamily)
            if !peerCandidates.contains(where: {
                $0.family == normalized.family && $0.host == normalized.host && $0.port == normalized.port
            }) {
                peerCandidates.append(normalized)
            }
        }
        guard let peer = peerCandidates.first else {
            throw NSError(
                domain: "ObstacleBridge.IPServer",
                code: 36,
                userInfo: [NSLocalizedDescriptionKey: "Could not resolve overlay peer '\(peerHost)'"]
            )
        }

        let sock = socket(socketFamily, SOCK_DGRAM, IPPROTO_UDP)
        guard sock >= 0 else {
            throw NSError(domain: "ObstacleBridge.IPServer", code: 31, userInfo: [NSLocalizedDescriptionKey: "socket() failed"])
        }
        let flags = fcntl(sock, F_GETFL, 0)
        _ = fcntl(sock, F_SETFL, flags | O_NONBLOCK)
        if socketFamily == AF_INET6 {
            var dualStackOff: Int32 = 0
            _ = withUnsafePointer(to: &dualStackOff) { ptr in
                setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, ptr, socklen_t(MemoryLayout<Int32>.size))
            }
        }
        var noSigPipe: Int32 = 1
        _ = withUnsafePointer(to: &noSigPipe) { ptr in
            setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, ptr, socklen_t(MemoryLayout<Int32>.size))
        }

        do {
            let resolvedBindHost: String
            if socketFamily == AF_INET6 && bindHost == "0.0.0.0" {
                resolvedBindHost = "::"
            } else {
                resolvedBindHost = bindHost
            }
            let bindAddr = try resolveAddress(host: resolvedBindHost, port: bindPort, passive: true, family: socketFamily)
            let bindResult = bindAddr.storage.withUnsafeBytes { rawBuffer -> Int32 in
                let sockaddrPtr = rawBuffer.baseAddress!.assumingMemoryBound(to: sockaddr.self)
                return Darwin.bind(sock, sockaddrPtr, bindAddr.length)
            }
            guard bindResult == 0 else {
                throw NSError(domain: "ObstacleBridge.IPServer", code: 32, userInfo: [NSLocalizedDescriptionKey: "bind() failed errno=\(errno)"])
            }
            return (sock, socketFamily, peerCandidates, peer)
        } catch {
            Darwin.close(sock)
            throw error
        }
    }

    private struct ResolvedAddress {
        let family: Int32
        let host: String
        let port: Int
        let storage: Data
        let length: socklen_t
    }
}

#if OB_IPSERVER_SWIFT_PROBE
extension PacketTunnelProvider {
    fileprivate static func makeSwiftUDPBridgeProbeComponents(
        runtimeMode: String,
        bindHost: String,
        bindPort: Int,
        peerHost: String,
        peerPort: Int,
        peerResolveFamily: String = "prefer-ipv6",
        mtu: Int,
        tunIfname: String,
        tunnelAddress: String,
        tcpServiceSpecs: [ObstacleBridgeChannelMuxCodec.ServiceSpec],
        overlayLayerTransportAdapter: ObstacleBridgeOverlayLayerTransportAdapter? = nil
    ) throws -> SwiftSimpleUDPPeerBridge {
        let settings = SwiftSimpleUDPPeerSettings(
            runtimeMode: runtimeMode,
            bindHost: bindHost,
            bindPort: bindPort,
            peerHost: peerHost,
            peerPort: peerPort,
            peerResolveFamily: peerResolveFamily,
            mtu: mtu,
            tunIfname: tunIfname
        )
        let bridge = try SwiftSimpleUDPPeerBridge(
            provider: nil,
            settings: settings,
            tunnelAddress: tunnelAddress,
            tcpServiceSpecs: tcpServiceSpecs,
            overlayLayerTransportAdapter: overlayLayerTransportAdapter
        )
        return bridge
    }
}

final class PacketTunnelProviderSwiftUDPBridgeProbe {
    private let bridge: SwiftSimpleUDPPeerBridge

    init(
        runtimeMode: String,
        bindHost: String,
        bindPort: Int,
        peerHost: String,
        peerPort: Int,
        peerResolveFamily: String = "prefer-ipv6",
        mtu: Int,
        tunIfname: String,
        tunnelAddress: String,
        tcpServiceSpecs: [ObstacleBridgeChannelMuxCodec.ServiceSpec],
        overlayLayerTransportAdapter: ObstacleBridgeOverlayLayerTransportAdapter? = nil
    ) throws {
        let components = try PacketTunnelProvider.makeSwiftUDPBridgeProbeComponents(
            runtimeMode: runtimeMode,
            bindHost: bindHost,
            bindPort: bindPort,
            peerHost: peerHost,
            peerPort: peerPort,
            peerResolveFamily: peerResolveFamily,
            mtu: mtu,
            tunIfname: tunIfname,
            tunnelAddress: tunnelAddress,
            tcpServiceSpecs: tcpServiceSpecs,
            overlayLayerTransportAdapter: overlayLayerTransportAdapter
        )
        self.bridge = components
    }

    func start() {
        bridge.startForProbe()
    }

    func stop() {
        bridge.stop()
    }

    func overlayEstablished() -> Bool {
        bridge.overlayEstablishedForProbe()
    }

    func bridgeSnapshot() -> [String: Any] {
        bridge.snapshot()
    }

    func adminConnectionsSnapshot() -> [String: Any] {
        PacketTunnelProviderAdminSnapshotBuilder.connectionsSnapshot(
            runtimeConfig: [:],
            packetPumpRunning: false,
            bridgeSnapshot: bridge.snapshot(),
            bridgeRows: bridge.connectionRows()
        )
    }
}
#endif

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
