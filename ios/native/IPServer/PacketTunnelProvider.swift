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
                            tcpServiceSpecs: tcpServiceSpecs
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
        if let runtimeConfig = providerConfiguration?["runtime_config"] as? [String: Any],
           let settings = Self.swiftSimpleUDPPeerSettings(from: runtimeConfig, defaultMTU: defaultMTU) {
            return settings
        }
        if let payload = loadSharedRuntimeConfigJSON(),
           let settings = Self.swiftSimpleUDPPeerSettings(from: payload, defaultMTU: defaultMTU) {
            return settings
        }
        return nil
    }

    private func packetflowConnectorMode(providerConfiguration: [String: Any]?) -> String? {
        if let runtimeConfig = providerConfiguration?["runtime_config"] as? [String: Any],
           let mode = Self.packetflowConnectorMode(from: runtimeConfig) {
            return mode
        }
        if let payload = loadSharedRuntimeConfigJSON(),
           let mode = Self.packetflowConnectorMode(from: payload) {
            return mode
        }
        return nil
    }

    private func localTCPServiceSpecs(providerConfiguration: [String: Any]?) -> [ObstacleBridgeChannelMuxCodec.ServiceSpec] {
        if let runtimeConfig = providerConfiguration?["runtime_config"] as? [String: Any] {
            let specs = Self.localTCPServiceSpecs(from: runtimeConfig)
            if !specs.isEmpty {
                return specs
            }
        }
        if let payload = loadSharedRuntimeConfigJSON() {
            return Self.localTCPServiceSpecs(from: payload)
        }
        return []
    }

    private func runtimeConfigPayload(providerConfiguration: [String: Any]?) -> [String: Any]? {
        if let runtimeConfig = providerConfiguration?["runtime_config"] as? [String: Any] {
            return runtimeConfig
        }
        return loadSharedRuntimeConfigJSON()
    }

    private func prepareSharedOverlayBootstrap(providerConfiguration: [String: Any]?) {
        sharedCompressLayerRuntime = nil
        sharedWebSocketOverlayRuntime = nil
        sharedTcpOverlayRuntime = nil
        sharedOverlayBootstrapState = [:]

        guard let payload = runtimeConfigPayload(providerConfiguration: providerConfiguration) else {
            return
        }

        let overlayTransport = Self.stringValue(from: payload["overlay_transport"]) ?? "myudp"
        let configuredPeers: [String: Bool] = [
            "myudp": Self.stringValue(from: payload["udp_peer"]) != nil,
            "tcp": Self.stringValue(from: payload["tcp_peer"]) != nil,
            "quic": Self.stringValue(from: payload["quic_peer"]) != nil,
            "ws": Self.stringValue(from: payload["ws_peer"]) != nil,
        ]

        do {
            let transports = try ObstacleBridgeOverlayStackPlanner.parseOverlayTransports(
                raw: overlayTransport,
                hasConfiguredPeerByTransport: configuredPeers
            )
            let selectedTransport = transports.first ?? "myudp"
            let peerHost = Self.peerHost(for: selectedTransport, payload: payload)
            let secureLinkEnabled = Self.boolValue(from: payload["secure_link"]) ?? false
            let secureLinkMode = Self.stringValue(from: payload["secure_link_mode"]) ?? "off"
            let secureLinkPSK = Self.stringValue(from: payload["secure_link_psk"]) ?? ""
            let compressEnabled = Self.boolValue(from: payload["compress_layer"]) ?? false
            let compressAlgo = Self.stringValue(from: payload["compress_layer_algo"]) ?? "zlib"
            let plan = try ObstacleBridgeOverlayStackPlanner.planTransport(
                transport: selectedTransport,
                peerHost: peerHost,
                secureLinkEnabled: secureLinkEnabled,
                secureLinkModeRaw: secureLinkMode,
                secureLinkPSK: secureLinkPSK,
                compressLayerEnabled: compressEnabled,
                compressLayerAlgoRaw: compressAlgo
            )

            var summary: [String: Any] = [
                "status": "prepared",
                "transport": plan.transport,
                "transports": transports,
                "layers_top_down": plan.layersTopDown,
                "compress_wrapped": plan.compressWrapped,
                "compress_configured_enabled": plan.compressConfiguredEnabled,
            ]
            if let peerHost = plan.peerHost {
                summary["peer_host"] = peerHost
            }
            if let secureLinkMode = plan.secureLinkMode {
                summary["secure_link_mode"] = secureLinkMode
            }

            if plan.compressWrapped {
                let allowedMTypes = Self.stringValue(from: payload["compress_layer_types"]) ?? "data,data_frag"
                let level = Self.intValue(from: payload["compress_layer_level"]) ?? 3
                let minBytes = Self.intValue(from: payload["compress_layer_min_bytes"]) ?? 64
                sharedCompressLayerRuntime = try ObstacleBridgeCompressLayerRuntime(
                    algorithm: compressAlgo,
                    level: level,
                    minBytes: minBytes,
                    allowedMTypesRaw: allowedMTypes,
                    peerSelectedAllowedMTypesRaw: allowedMTypes
                )
                summary["compress_runtime"] = "ready"
                summary["compress_layer_types"] = allowedMTypes
            }

            if plan.transport == "ws" {
                let payloadMode = Self.stringValue(from: payload["ws_payload_mode"]) ?? "binary"
                let maxSize = Self.intValue(from: payload["ws_max_size"]) ?? 65535
                let sendTimeout = Self.doubleValue(from: payload["ws_send_timeout"]) ?? 3.0
                let tcpUserTimeout = Self.intValue(from: payload["ws_tcp_user_timeout_ms"]) ?? 10000
                let reconnectGrace = Self.doubleValue(from: payload["ws_reconnect_grace"]) ?? 3.0
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

            if plan.transport == "tcp" {
                let threshold = Self.intValue(from: payload["tcp_bp_wbuf_threshold"]) ?? 128 * 1024
                sharedTcpOverlayRuntime = ObstacleBridgeTcpOverlayRuntime(wbufThreshold: threshold)
                summary["tcp_runtime"] = "ready"
                summary["tcp_bp_wbuf_threshold"] = threshold
            }

            sharedOverlayBootstrapState = summary
            recordNativeEvent("shared_overlay_runtime_prepared", fields: summary)
        } catch {
            let summary: [String: Any] = [
                "status": "failed",
                "overlay_transport": overlayTransport,
                "error": error.localizedDescription,
            ]
            sharedOverlayBootstrapState = summary
            recordNativeEvent("shared_overlay_runtime_prepare_failed", fields: summary)
        }
    }

    private static func packetflowConnectorMode(from payload: [String: Any]) -> String? {
        guard let experiment = packetflowConnectorSection(from: payload) else {
            return nil
        }
        let connectorMode = (experiment["packetflow_connector"] as? String ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        guard !connectorMode.isEmpty else {
            return nil
        }
        return connectorMode
    }

    private static func localTCPServiceSpecs(from payload: [String: Any]) -> [ObstacleBridgeChannelMuxCodec.ServiceSpec] {
        guard
            let channelMux = payload["channel_mux"] as? [String: Any],
            let ownServers = channelMux["own_servers"] as? [Any]
        else {
            return []
        }
        var specs: [ObstacleBridgeChannelMuxCodec.ServiceSpec] = []
        var serviceID = 1
        for item in ownServers {
            defer { serviceID += 1 }
            guard
                let object = item as? [String: Any],
                let listen = object["listen"] as? [String: Any],
                let target = object["target"] as? [String: Any]
            else {
                continue
            }
            let listenProto = String(describing: listen["protocol"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let targetProto = String(describing: target["protocol"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard listenProto == "tcp", targetProto == "tcp" else {
                continue
            }
            guard
                let bind = (listen["bind"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines),
                !bind.isEmpty,
                let host = (target["host"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines),
                !host.isEmpty,
                let listenPort = intValue(from: listen["port"]),
                let targetPort = intValue(from: target["port"]),
                listenPort > 0,
                targetPort > 0
            else {
                continue
            }
            let lifecycleHooks = jsonDictionary(from: object["lifecycle_hooks"])
            let options = jsonDictionary(from: object["options"])
            specs.append(
                ObstacleBridgeChannelMuxCodec.ServiceSpec(
                    svcID: serviceID,
                    lProto: "tcp",
                    lBind: bind,
                    lPort: listenPort,
                    rProto: "tcp",
                    rHost: host,
                    rPort: targetPort,
                    name: (object["name"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines),
                    lifecycleHooks: lifecycleHooks,
                    options: options
                )
            )
        }
        return specs
    }

    private static func intValue(from value: Any?) -> Int? {
        if let number = value as? NSNumber {
            return number.intValue
        }
        if let value = value as? Int {
            return value
        }
        if let value = value as? String {
            return Int(value)
        }
        return nil
    }

    private static func doubleValue(from value: Any?) -> Double? {
        if let number = value as? NSNumber {
            return number.doubleValue
        }
        if let value = value as? Double {
            return value
        }
        if let value = value as? Int {
            return Double(value)
        }
        if let value = value as? String {
            return Double(value)
        }
        return nil
    }

    private static func boolValue(from value: Any?) -> Bool? {
        if let value = value as? Bool {
            return value
        }
        if let number = value as? NSNumber {
            return number.boolValue
        }
        if let value = value as? String {
            switch value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
            case "1", "true", "yes", "on":
                return true
            case "0", "false", "no", "off":
                return false
            default:
                return nil
            }
        }
        return nil
    }

    private static func stringValue(from value: Any?) -> String? {
        guard let value else {
            return nil
        }
        if let string = value as? String {
            let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? nil : trimmed
        }
        if let number = value as? NSNumber {
            return number.stringValue
        }
        return nil
    }

    private static func peerHost(for transport: String, payload: [String: Any]) -> String? {
        switch transport {
        case "myudp":
            return stringValue(from: payload["udp_peer"])
        case "tcp":
            return stringValue(from: payload["tcp_peer"])
        case "quic":
            return stringValue(from: payload["quic_peer"])
        case "ws":
            return stringValue(from: payload["ws_peer"])
        default:
            return nil
        }
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
        guard let experiment = packetflowConnectorSection(from: payload) else {
            return nil
        }
        let connectorMode = (experiment["packetflow_connector"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard connectorMode == "swift_simple_udp_peer" || connectorMode == "swift_udp" || connectorMode == "swift_udp_peer" else {
            return nil
        }
        guard let peerHost = experiment["peer_host"] as? String,
              !peerHost.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else {
            return nil
        }
        let peerPort = (experiment["peer_port"] as? NSNumber)?.intValue ?? (experiment["peer_port"] as? Int ?? 0)
        guard peerPort > 0 else {
            return nil
        }
        let bindHost = (experiment["bind_host"] as? String) ?? "0.0.0.0"
        let bindPort = (experiment["bind_port"] as? NSNumber)?.intValue ?? (experiment["bind_port"] as? Int ?? peerPort)
        let mtu = (experiment["mtu"] as? NSNumber)?.intValue ?? (experiment["mtu"] as? Int ?? defaultMTU)
        let tunIfname = ((experiment["ifname"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)).flatMap { $0.isEmpty ? nil : $0 } ?? "ios-utun"
        return SwiftSimpleUDPPeerSettings(
            runtimeMode: connectorMode == "swift_udp_peer" ? "swift_udp" : connectorMode,
            bindHost: bindHost,
            bindPort: bindPort > 0 ? bindPort : peerPort,
            peerHost: peerHost,
            peerPort: peerPort,
            mtu: mtu,
            tunIfname: tunIfname
        )
    }

    private static func packetflowConnectorSection(from payload: [String: Any]) -> [String: Any]? {
        return payload["iOS_TUN_connector"] as? [String: Any]
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
        let override = payload["TUN_routing"] as? [String: Any]
        let dnsServers = (override?["dns_servers"] as? [String])
            ?? (payload["dns_servers"] as? [String])
            ?? []
        let mtu = (override?["mtu"] as? NSNumber)?.intValue
            ?? (override?["mtu"] as? Int)
            ?? (payload["mtu"] as? NSNumber)?.intValue
            ?? (payload["mtu"] as? Int)
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
    let mtu: Int
    let tunIfname: String
}

private final class SwiftSimpleUDPPeerBridge {
    private static let queueKey = DispatchSpecificKey<UInt8>()
    private weak var provider: PacketTunnelProvider?
    private let settings: SwiftSimpleUDPPeerSettings
    private let tunnelAddress: String
    private let tcpServiceSpecs: [ObstacleBridgeChannelMuxCodec.ServiceSpec]
    private let queue = DispatchQueue(label: "com.obstaclebridge.ipserver.swift-simple-udp-peer")
    private var socketFD: Int32 = -1
    private let peerAddress: ResolvedAddress
    private var overlayRuntime: ObstacleBridgeUdpOverlayPeerRuntime?
    private var channelMuxTunRuntime: ObstacleBridgeChannelMuxTunRuntime?
    private var channelMuxTcpRuntime: ObstacleBridgeChannelMuxTcpRuntime?
    private let tcpOpenChunkReassembler = ObstacleBridgeChannelMuxCodec.ControlChunkReassembler()
    private var tcpListeners: [Int: NWListener] = [:]
    private var tcpServerConnections: [Int: NWConnection] = [:]
    private var tcpClientConnections: [Int: NWConnection] = [:]
    private var readSource: DispatchSourceRead?
    private var controlTimer: DispatchSourceTimer?
    private var retransmitTimer: DispatchSourceTimer?
    private var started = false
    private var startedAt = Date().timeIntervalSince1970
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

    init(
        provider: PacketTunnelProvider,
        settings: SwiftSimpleUDPPeerSettings,
        tunnelAddress: String,
        tcpServiceSpecs: [ObstacleBridgeChannelMuxCodec.ServiceSpec]
    ) throws {
        self.provider = provider
        self.settings = settings
        self.tunnelAddress = tunnelAddress
        self.tcpServiceSpecs = tcpServiceSpecs
        self.queue.setSpecific(key: Self.queueKey, value: 1)
        let boundSocket = try Self.makeBoundSocket(
            bindHost: settings.bindHost,
            bindPort: settings.bindPort,
            peerHost: settings.peerHost,
            peerPort: settings.peerPort
        )
        self.socketFD = boundSocket.socketFD
        self.peerAddress = boundSocket.peerAddress
        if settings.runtimeMode == "swift_udp" {
            self.overlayRuntime = ObstacleBridgeUdpOverlayPeerRuntime()
            self.channelMuxTunRuntime = ObstacleBridgeChannelMuxTunRuntime(
                instanceID: UInt64.random(in: 1...UInt64.max),
                connectionSeq: UInt32.random(in: 1...UInt32.max),
                localSpec: Self.localTunServiceSpec(settings: settings)
            )
            self.channelMuxTcpRuntime = ObstacleBridgeChannelMuxTcpRuntime(
                instanceID: UInt64.random(in: 1...UInt64.max),
                connectionSeq: UInt32.random(in: 1...UInt32.max)
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

        let source = DispatchSource.makeReadSource(fileDescriptor: socketFD, queue: queue)
        source.setEventHandler { [weak self] in
            self?.drainSocket()
        }
        readSource = source
        source.resume()
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
                "mtu": settings.mtu,
                "tunnel_address": tunnelAddress,
            ]
        )
        beginPacketFlowReadLoop()
    }

    func stop() {
        guard started else { return }
        started = false
        controlTimer?.cancel()
        controlTimer = nil
        retransmitTimer?.cancel()
        retransmitTimer = nil
        readSource?.cancel()
        readSource = nil
        stopTCPServices()
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
                "mtu": settings.mtu,
                "tunnel_address": tunnelAddress,
                "socket_fd": socketFD,
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
                "tcp_server_connection_count": tcpServerConnections.count,
                "tcp_client_connection_count": tcpClientConnections.count,
                "tcp_listener_failures": tcpListenerFailures,
                "tcp_connections_accepted": tcpConnectionsAccepted,
                "tcp_connections_dialed": tcpConnectionsDialed,
                "last_from_system_at": lastFromSystemAt,
                "last_to_system_at": lastToSystemAt,
                "started_at": startedAt,
            ]
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
        guard started, let provider else { return }
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
            provider.recordPacketBridgeEvent(
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
        provider.packetFlow.writePackets(packets, withProtocols: protocols)
        withState {
            packetsToSystem += packets.count
            bytesToSystem += totalBytes
            writeBatches += 1
            lastToSystemAt = Date().timeIntervalSince1970
        }
        if packetsToSystem <= 3 || (packetsToSystem % 128) == 0 {
            provider.recordPacketBridgeEvent(
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
        for connection in tcpServerConnections.values {
            cancelConnection(connection)
        }
        tcpServerConnections.removeAll()
        for connection in tcpClientConnections.values {
            cancelConnection(connection)
        }
        tcpClientConnections.removeAll()
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
        guard let runtime = channelMuxTcpRuntime else {
            cancelConnection(connection)
            return
        }
        do {
            guard let acceptSnapshot = try runtime.handleAcceptedServerConnection(
                spec: spec,
                overlayConnected: true,
                acceptingEnabled: true
            ) else {
                cancelConnection(connection)
                return
            }
            tcpConnectionsAccepted += 1
            tcpServerConnections[acceptSnapshot.chanID] = connection
            connection.stateUpdateHandler = { [weak self] state in
                self?.queue.async {
                    self?.handleTCPServerConnectionState(state, chanID: acceptSnapshot.chanID)
                }
            }
            connection.start(queue: queue)
            sendMuxFrames(acceptSnapshot.frames)
            receiveFromTCPServerConnection(chanID: acceptSnapshot.chanID)
        } catch {
            provider?.recordPacketBridgeEvent(
                "swift_udp_tcp_accept_failed",
                fields: [
                    "service_id": spec.svcID,
                    "error": error.localizedDescription,
                ]
            )
            cancelConnection(connection)
        }
    }

    private func handleTCPServerConnectionState(_ state: NWConnection.State, chanID: Int) {
        switch state {
        case .failed(let error):
            provider?.recordPacketBridgeEvent(
                "swift_udp_tcp_server_connection_failed",
                fields: ["chan_id": chanID, "error": error.localizedDescription]
            )
            closeTCPServerConnection(chanID: chanID, overlayConnected: true)
        case .cancelled:
            closeTCPServerConnection(chanID: chanID, overlayConnected: true)
        default:
            break
        }
    }

    private func receiveFromTCPServerConnection(chanID: Int) {
        guard started, let connection = tcpServerConnections[chanID] else {
            return
        }
        connection.receive(minimumIncompleteLength: 1, maximumLength: Self.maxTCPReadSize) { [weak self] data, _, isComplete, error in
            self?.queue.async {
                guard let self, self.started else { return }
                if let data, !data.isEmpty, let runtime = self.channelMuxTcpRuntime {
                    do {
                        let snapshot = try runtime.handleLocalServerData(
                            chanID: chanID,
                            payload: data,
                            overlayConnected: true
                        )
                        self.sendMuxFrames(snapshot.frames)
                    } catch {
                        self.provider?.recordPacketBridgeEvent(
                            "swift_udp_tcp_server_data_failed",
                            fields: ["chan_id": chanID, "error": error.localizedDescription]
                        )
                    }
                }
                if isComplete || error != nil {
                    self.closeTCPServerConnection(chanID: chanID, overlayConnected: true)
                    return
                }
                self.receiveFromTCPServerConnection(chanID: chanID)
            }
        }
    }

    private func closeTCPServerConnection(chanID: Int, overlayConnected: Bool) {
        let connection = tcpServerConnections.removeValue(forKey: chanID)
        if let runtime = channelMuxTcpRuntime {
            do {
                let snapshot = try runtime.handleLocalServerEOF(chanID: chanID, overlayConnected: overlayConnected)
                sendMuxFrames(snapshot.frames)
            } catch {
                provider?.recordPacketBridgeEvent(
                    "swift_udp_tcp_server_close_failed",
                    fields: ["chan_id": chanID, "error": error.localizedDescription]
                )
            }
        }
        if let connection {
            cancelConnection(connection)
        }
    }

    private func handleInboundTCPClientOpen(chanID: Int, payload: Data) {
        guard let runtime = channelMuxTcpRuntime,
              let parsed = ObstacleBridgeChannelMuxCodec.parseOpenPayload(payload)
        else {
            provider?.recordPacketBridgeEvent(
                "swift_udp_tcp_client_open_parse_failed",
                fields: ["chan_id": chanID]
            )
            return
        }
        let snapshot = runtime.handleInboundClientOpen(chanID: chanID, payload: payload)
        if snapshot.accepted && snapshot.connectRequested {
            startOutboundTCPConnection(chanID: chanID, spec: parsed.spec)
            return
        }
        if !snapshot.accepted {
            provider?.recordPacketBridgeEvent(
                "swift_udp_tcp_client_open_rejected",
                fields: ["chan_id": chanID]
            )
        }
    }

    private func handleInboundTCPClientOpenChunk(chanID: Int, payload: Data) {
        guard let assembled = tcpOpenChunkReassembler.consume(
            chanID: chanID,
            proto: .tcp,
            mtype: .open,
            payload: payload,
            peerID: nil
        ) else {
            return
        }
        handleInboundTCPClientOpen(chanID: chanID, payload: assembled)
    }

    private func startOutboundTCPConnection(chanID: Int, spec: ObstacleBridgeChannelMuxCodec.ServiceSpec) {
        guard tcpClientConnections[chanID] == nil, let runtime = channelMuxTcpRuntime else {
            return
        }
        guard let port = NWEndpoint.Port(rawValue: UInt16(spec.rPort)) else {
            provider?.recordPacketBridgeEvent(
                "swift_udp_tcp_client_connect_invalid_port",
                fields: ["chan_id": chanID, "port": spec.rPort]
            )
            return
        }
        let connection = NWConnection(host: NWEndpoint.Host(spec.rHost), port: port, using: .tcp)
        tcpClientConnections[chanID] = connection
        connection.stateUpdateHandler = { [weak self] state in
            self?.queue.async {
                self?.handleTCPClientConnectionState(state, chanID: chanID, spec: spec)
            }
        }
        connection.start(queue: queue)
        tcpConnectionsDialed += 1
        let connectSnapshot = runtime.handleClientConnected(
            chanID: chanID,
            peerAddrHost: spec.rHost,
            peerAddrPort: spec.rPort
        )
        for buffer in connectSnapshot.flushedBuffers {
            sendOnTCPConnection(connection, payload: buffer, chanID: chanID, event: "swift_udp_tcp_client_flush_failed")
        }
        receiveFromTCPClientConnection(chanID: chanID)
    }

    private func handleTCPClientConnectionState(
        _ state: NWConnection.State,
        chanID: Int,
        spec: ObstacleBridgeChannelMuxCodec.ServiceSpec
    ) {
        switch state {
        case .failed(let error):
            provider?.recordPacketBridgeEvent(
                "swift_udp_tcp_client_connection_failed",
                fields: [
                    "chan_id": chanID,
                    "host": spec.rHost,
                    "port": spec.rPort,
                    "error": error.localizedDescription,
                ]
            )
            closeTCPClientConnection(chanID: chanID, overlayConnected: true)
        case .cancelled:
            closeTCPClientConnection(chanID: chanID, overlayConnected: true)
        default:
            break
        }
    }

    private func receiveFromTCPClientConnection(chanID: Int) {
        guard started, let connection = tcpClientConnections[chanID] else {
            return
        }
        connection.receive(minimumIncompleteLength: 1, maximumLength: Self.maxTCPReadSize) { [weak self] data, _, isComplete, error in
            self?.queue.async {
                guard let self, self.started else { return }
                if let data, !data.isEmpty, let runtime = self.channelMuxTcpRuntime {
                    do {
                        if let snapshot = try runtime.handleLocalClientData(
                            chanID: chanID,
                            payload: data,
                            overlayConnected: true
                        ) {
                            self.sendMuxFrames(snapshot.frames)
                        }
                    } catch {
                        self.provider?.recordPacketBridgeEvent(
                            "swift_udp_tcp_client_data_failed",
                            fields: ["chan_id": chanID, "error": error.localizedDescription]
                        )
                    }
                }
                if isComplete || error != nil {
                    self.closeTCPClientConnection(chanID: chanID, overlayConnected: true)
                    return
                }
                self.receiveFromTCPClientConnection(chanID: chanID)
            }
        }
    }

    private func closeTCPClientConnection(chanID: Int, overlayConnected: Bool) {
        let connection = tcpClientConnections.removeValue(forKey: chanID)
        if let runtime = channelMuxTcpRuntime {
            do {
                let snapshot = try runtime.handleLocalClientEOF(chanID: chanID, overlayConnected: overlayConnected)
                sendMuxFrames(snapshot.frames)
            } catch {
                provider?.recordPacketBridgeEvent(
                    "swift_udp_tcp_client_close_failed",
                    fields: ["chan_id": chanID, "error": error.localizedDescription]
                )
            }
        }
        if let connection {
            cancelConnection(connection)
        }
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
                    spec: Self.localTunServiceSpec(settings: settings),
                    overlayConnected: true,
                    acceptingEnabled: true
                ) else {
                    return
                }
                for muxFrame in localSnapshot.frames {
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
                }
                return
            }
            let nowNS = monotonicNowNS()
            let snapshot = try runtime.sendApplicationPayload(packet, nowNS: nowNS, echoNS: currentEchoNS(nowNS))
            for frame in snapshot.frames {
                sendDatagram(frame)
            }
            overlayFramesFromSystem += snapshot.frames.count
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
            return routeOverlayPayloadsToSystem(snapshot.completedPayloads)
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
        guard let provider else {
            return
        }
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
                    provider.recordPacketBridgeEvent(
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
        guard let runtime = channelMuxTcpRuntime else {
            return
        }
        if let connection = tcpServerConnections[frame.chanID] {
            switch frame.mtype {
            case .data:
                let snapshot = runtime.handleInboundServerData(chanID: frame.chanID, body: frame.body)
                for buffer in snapshot.writtenBuffers {
                    sendOnTCPConnection(connection, payload: buffer, chanID: frame.chanID, event: "swift_udp_tcp_server_write_failed")
                }
            case .close:
                let snapshot = runtime.handleInboundServerClose(chanID: frame.chanID)
                if snapshot.localConnectionClosed {
                    tcpServerConnections.removeValue(forKey: frame.chanID)
                    cancelConnection(connection)
                }
            default:
                break
            }
            return
        }

        switch frame.mtype {
        case .open:
            handleInboundTCPClientOpen(chanID: frame.chanID, payload: frame.body)
        case .openChunk:
            handleInboundTCPClientOpenChunk(chanID: frame.chanID, payload: frame.body)
        case .data:
            let snapshot = runtime.handleInboundClientData(chanID: frame.chanID, body: frame.body)
            if let connection = tcpClientConnections[frame.chanID] {
                for buffer in snapshot.writtenBuffers {
                    sendOnTCPConnection(connection, payload: buffer, chanID: frame.chanID, event: "swift_udp_tcp_client_write_failed")
                }
            }
        case .close:
            let snapshot = runtime.handleInboundClientClose(chanID: frame.chanID)
            if snapshot.closed, let connection = tcpClientConnections.removeValue(forKey: frame.chanID) {
                cancelConnection(connection)
            }
        default:
            break
        }
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

    private static func localTunServiceSpec(settings: SwiftSimpleUDPPeerSettings) -> ObstacleBridgeChannelMuxCodec.ServiceSpec {
        ObstacleBridgeChannelMuxCodec.ServiceSpec(
            svcID: 0,
            lProto: "tun",
            lBind: settings.tunIfname,
            lPort: settings.mtu,
            rProto: "tun",
            rHost: settings.tunIfname,
            rPort: settings.mtu,
            name: nil,
            lifecycleHooks: nil,
            options: nil
        )
    }

    private static let maxTCPReadSize = 65527
    }

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

    private static func makeBoundSocket(
        bindHost: String,
        bindPort: Int,
        peerHost: String,
        peerPort: Int
    ) throws -> (socketFD: Int32, peerAddress: ResolvedAddress) {
        let peer = try resolveAddress(host: peerHost, port: peerPort, passive: false, family: AF_UNSPEC)
        let sock = socket(peer.family, SOCK_DGRAM, IPPROTO_UDP)
        guard sock >= 0 else {
            throw NSError(domain: "ObstacleBridge.IPServer", code: 31, userInfo: [NSLocalizedDescriptionKey: "socket() failed"])
        }
        let flags = fcntl(sock, F_GETFL, 0)
        _ = fcntl(sock, F_SETFL, flags | O_NONBLOCK)
        var noSigPipe: Int32 = 1
        _ = withUnsafePointer(to: &noSigPipe) { ptr in
            setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, ptr, socklen_t(MemoryLayout<Int32>.size))
        }

        do {
            let bindFamily = peer.family
            let resolvedBindHost: String
            if bindFamily == AF_INET6 && bindHost == "0.0.0.0" {
                resolvedBindHost = "::"
            } else {
                resolvedBindHost = bindHost
            }
            let bindAddr = try resolveAddress(host: resolvedBindHost, port: bindPort, passive: true, family: bindFamily)
            let bindResult = bindAddr.storage.withUnsafeBytes { rawBuffer -> Int32 in
                let sockaddrPtr = rawBuffer.baseAddress!.assumingMemoryBound(to: sockaddr.self)
                return Darwin.bind(sock, sockaddrPtr, bindAddr.length)
            }
            guard bindResult == 0 else {
                throw NSError(domain: "ObstacleBridge.IPServer", code: 32, userInfo: [NSLocalizedDescriptionKey: "bind() failed errno=\(errno)"])
            }
            return (sock, peer)
        } catch {
            Darwin.close(sock)
            throw error
        }
    }

    private struct ResolvedAddress {
        let family: Int32
        let storage: Data
        let length: socklen_t
    }

    private static func resolveAddress(host: String, port: Int, passive: Bool, family: Int32) throws -> ResolvedAddress {
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
        let addrData = Data(bytes: info.pointee.ai_addr, count: Int(info.pointee.ai_addrlen))
        return ResolvedAddress(family: info.pointee.ai_family, storage: addrData, length: info.pointee.ai_addrlen)
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
