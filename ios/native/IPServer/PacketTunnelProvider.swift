import Foundation
import Network
import NetworkExtension
import Darwin

private enum PacketTunnelProviderOnboardingError: LocalizedError {
    case invalidArgument(String)

    var errorDescription: String? {
        switch self {
        case .invalidArgument(let message):
            return message
        }
    }
}

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

    private static let packetTunnelDefaults = ObstacleBridgePacketTunnelDefaults(
        tunnelAddress: defaultTunnelAddress,
        tunnelPrefix: defaultTunnelPrefix,
        includedRoutes: defaultIncludedRoutes,
        excludedRoutes: defaultExcludedRoutes,
        tunnelAddress6: defaultTunnelAddress6,
        tunnelPrefix6: defaultTunnelPrefix6,
        includedRoutes6: defaultIncludedRoutes6,
        excludedRoutes6: defaultExcludedRoutes6,
    )
    private let errorDomain = "ObstacleBridge.IPServer"
    private var packetPumpRunning = false
    private var providerStateUpdateCount = 0
    private var heartbeatTickCount = 0
    private var runtimeMode = "unconfigured"
    private var swiftSimpleUDPPeerBridge: SwiftSimpleUDPPeerBridge?
    private var sharedOverlayBootstrapState: [String: Any] = [:]
    private var effectivePacketTunnelSettingsState: [String: Any] = [:]
    private var sharedCompressLayerRuntime: ObstacleBridgeCompressLayerRuntime?
    private var sharedSecureLinkPskTransportAdapter: ObstacleBridgeSecureLinkPskTransportAdapter?
    private var sharedOverlayLayerTransportAdapter: ObstacleBridgeOverlayLayerTransportAdapter?
    private var sharedWebSocketOverlayRuntime: ObstacleBridgeWebSocketOverlayRuntime?
    private var sharedTcpOverlayRuntime: ObstacleBridgeTcpOverlayRuntime?
    private var controlServer: ObstacleBridgeWebAdminServer?
    private var providerStartedAt = Date().timeIntervalSince1970
    private var runtimeReloadInProgress = false
    private var peerTrafficRateState: (timestamp: TimeInterval, rxBytes: Int, txBytes: Int)?
    private var secureLinkConnectedSinceUnixTS: Int?
    private var secureLinkLastAuthenticatedUnixTS: Int?
    private var secureLinkLastSessionID: UInt64 = 0
    private lazy var adminAuth = ObstacleBridgeAdminAuth(
        queueLabel: "PacketTunnelProvider.AdminAuth",
        authRequiredProvider: { [weak self] in
            self?.adminAuthRequired() ?? false
        },
        usernameProvider: { [weak self] in
            self?.adminAuthUsername() ?? ""
        },
        passwordProvider: { [weak self] in
            self?.adminAuthPassword() ?? ""
        },
        bearerTokenProvider: { [weak self] in
            self?.adminWebToken() ?? ""
        },
        cookieScopeProvider: { [weak self] in
            self?.adminSessionCookieScope() ?? ""
        }
    )
    private lazy var adminConfigChallengeStore = ObstacleBridgeAdminConfigChallenge(
        queueLabel: "PacketTunnelProvider.AdminConfigChallenge",
        usernameProvider: { [weak self] in
            self?.adminAuthUsername() ?? ""
        },
        passwordProvider: { [weak self] in
            self?.adminAuthPassword() ?? ""
        }
    )

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
        if !effectivePacketTunnelSettingsState.isEmpty {
            payload["effective_tunnel_network_settings"] = effectivePacketTunnelSettingsState
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

    private var heartbeatTimer: DispatchSourceTimer?

    private var swiftUDPRuntimeActive: Bool {
        runtimeMode == "swift_udp"
    }

    private var nativeRuntimeActive: Bool {
        runtimeMode == "swift_simple_udp" || runtimeMode == "swift_udp"
    }

    private func nativeAppMessageResponse(for payload: [String: Any]) throws -> [String: Any] {
        let command = String(describing: payload["command"] ?? "")
        switch command {
        case "", "snapshot":
            return [
                "ok": true,
                "started": true,
                "mode": runtimeMode,
                "status": adminStatusSnapshot(),
                "connections": adminConnectionsSnapshot(),
                "peers": adminPeersSnapshot(),
                "config": adminRuntimeConfigPayload() ?? [:],
                "swift_udp_bridge_state": swiftSimpleUDPPeerBridge?.snapshot() ?? [:],
            ]
        case "stop":
            return [
                "ok": true,
                "stopped": true,
                "mode": runtimeMode,
            ]
        default:
            return [
                "ok": true,
                "mode": runtimeMode,
                "status": "provider alive",
                "command": command,
                "swift_udp_bridge_state": swiftSimpleUDPPeerBridge?.snapshot() ?? [:],
            ]
        }
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
        runtimeMode = "unconfigured"
        swiftSimpleUDPPeerBridge = nil
        effectivePacketTunnelSettingsState = [:]
        providerStartedAt = Date().timeIntervalSince1970
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
            let configuration = try ObstacleBridgePacketTunnelConfiguration(
                providerConfiguration,
                fallbackRuntimeConfig: loadSharedRuntimeConfigJSON(),
                defaults: Self.packetTunnelDefaults
            )
            let settingsPayload = Self.packetTunnelSettingsSnapshot(configuration)
            effectivePacketTunnelSettingsState = settingsPayload
            recordNativeEvent(
                "tunnel_network_settings_prepared",
                fields: settingsPayload
            )
            let settings = configuration.makeNetworkSettings()
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
                    fields: settingsPayload
                )
                self.prepareSharedOverlayBootstrap(providerConfiguration: providerConfiguration)
                let connectorMode = self.packetflowConnectorMode(providerConfiguration: providerConfiguration) ?? ""
                guard let swiftSettings = self.swiftSimpleUDPPeerSettings(
                    providerConfiguration: providerConfiguration,
                    defaultMTU: configuration.mtu
                ) else {
                    if connectorMode == "swift_udp" {
                        self.runtimeMode = "swift_udp"
                        do {
                            try self.startControlServer()
                        } catch {
                            self.recordNativeEvent(
                                "startTunnel_admin_web_failed",
                                fields: ["error": error.localizedDescription]
                            )
                            self.updateProviderState(
                                "startTunnel_admin_web_failed",
                                extraFields: ["error": error.localizedDescription]
                            )
                            completionHandler(error)
                            return
                        }
                        self.startProviderHeartbeat()
                        self.recordNativeEvent(
                            "startTunnel_waiting_for_onboarding",
                            fields: ["mode": connectorMode]
                        )
                        self.updateProviderState(
                            "startTunnel_waiting_for_onboarding",
                            extraFields: ["mode": connectorMode]
                        )
                        completionHandler(nil)
                        return
                    }
                    let error = NSError(
                        domain: self.errorDomain,
                        code: 3,
                        userInfo: [NSLocalizedDescriptionKey: "IPServer requires packetflow_connector to be swift_udp or swift_simple_udp"]
                    )
                    self.recordNativeEvent(
                        "startTunnel_unsupported_runtime_mode",
                        fields: ["mode": connectorMode]
                    )
                    self.updateProviderState(
                        "startTunnel_unsupported_runtime_mode",
                        extraFields: ["mode": connectorMode]
                    )
                    completionHandler(error)
                    return
                }
                self.runtimeMode = swiftSettings.runtimeMode
                self.recordNativeEvent(
                    "packetflow_connector_mode_selected",
                    fields: ["mode": swiftSettings.runtimeMode]
                )
                self.updateProviderState(
                    "packetflow_connector_mode_selected",
                    extraFields: ["mode": swiftSettings.runtimeMode]
                )
                do {
                    let muxInstanceID = UInt64.random(in: 1...UInt64.max)
                    let muxConnectionSeq = UInt32.random(in: 1...UInt32.max)
                    let tcpServiceSpecs = self.localTCPServiceSpecs(providerConfiguration: providerConfiguration)
                    let startupMuxFrames = self.remoteServiceCatalogMuxFrames(
                        providerConfiguration: providerConfiguration,
                        instanceID: muxInstanceID,
                        connectionSeq: muxConnectionSeq
                    )
                    let bridge = try SwiftSimpleUDPPeerBridge(
                        provider: self,
                        settings: swiftSettings,
                        tunnelAddress: configuration.tunnelAddress,
                        tunnelAddress6: configuration.tunnelAddress6,
                        tcpServiceSpecs: tcpServiceSpecs,
                        startupMuxFrames: startupMuxFrames,
                        muxInstanceID: muxInstanceID,
                        muxConnectionSeq: muxConnectionSeq,
                        overlayLayerTransportAdapter: self.sharedOverlayLayerTransportAdapter
                    )
                    self.swiftSimpleUDPPeerBridge = bridge
                    bridge.start()
                    do {
                        try self.startControlServer()
                    } catch {
                        self.recordNativeEvent(
                            "startTunnel_admin_web_failed",
                            fields: ["error": error.localizedDescription]
                        )
                        self.updateProviderState(
                            "startTunnel_admin_web_failed",
                            extraFields: ["error": error.localizedDescription]
                        )
                        completionHandler(error)
                        return
                    }
                    self.recordNativeEvent(
                        swiftSettings.runtimeMode == "swift_udp"
                            ? "startTunnel_swift_udp_bridge_started"
                            : "startTunnel_completed_swift_simple_udp",
                        fields: [
                            "mode": swiftSettings.runtimeMode,
                            "peer_host": swiftSettings.peerHost,
                            "peer_port": swiftSettings.peerPort,
                            "bind_host": swiftSettings.bindHost,
                            "bind_port": swiftSettings.bindPort,
                            "mtu": swiftSettings.mtu,
                        ]
                    )
                    if swiftSettings.runtimeMode == "swift_simple_udp" {
                        self.startProviderHeartbeat()
                        self.updateProviderState("startTunnel_completed_swift_simple_udp")
                        completionHandler(nil)
                        return
                    }
                    self.startProviderHeartbeat()
                    self.recordNativeEvent("startTunnel_completed_swift_udp")
                    self.updateProviderState(
                        "startTunnel_completed_swift_udp",
                        extraFields: ["mode": swiftSettings.runtimeMode]
                    )
                    completionHandler(nil)
                    return
                } catch {
                    self.recordNativeEvent(
                        swiftSettings.runtimeMode == "swift_udp"
                            ? "startTunnel_swift_udp_bridge_failed"
                            : "startTunnel_swift_simple_udp_failed",
                        fields: [
                            "mode": swiftSettings.runtimeMode,
                            "error": error.localizedDescription,
                            "error_type": String(describing: type(of: error)),
                        ]
                    )
                    self.updateProviderState(
                        swiftSettings.runtimeMode == "swift_udp"
                            ? "startTunnel_swift_udp_bridge_failed"
                            : "startTunnel_swift_simple_udp_failed",
                        extraFields: [
                            "error": error.localizedDescription,
                            "mode": swiftSettings.runtimeMode,
                        ]
                    )
                    completionHandler(error)
                    return
                }
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
        controlServer?.stop()
        controlServer = nil
        swiftSimpleUDPPeerBridge?.stop()
        swiftSimpleUDPPeerBridge = nil
        packetPumpRunning = false
        if !nativeRuntimeActive {
            ObstacleBridgePacketFlowBridge.deactivate()
        }
        recordNativeEvent("stopTunnel_completed", fields: ["reason": reason.rawValue])
        updateProviderState("stopTunnel_completed", extraFields: ["reason": reason.rawValue])
        completionHandler()
    }

    private func stopEmbeddedRuntimeForReload() {
        heartbeatTimer?.cancel()
        heartbeatTimer = nil
        controlServer?.stop()
        controlServer = nil
        swiftSimpleUDPPeerBridge?.stop()
        swiftSimpleUDPPeerBridge = nil
        packetPumpRunning = false
        if !nativeRuntimeActive {
            ObstacleBridgePacketFlowBridge.deactivate()
        }
    }

    private func scheduleEmbeddedRuntimeReload(action: String) {
        guard !runtimeReloadInProgress else {
            recordNativeEvent("embedded_runtime_reload_already_in_progress", fields: ["action": action])
            return
        }
        runtimeReloadInProgress = true
        recordNativeEvent("embedded_runtime_reload_requested", fields: ["action": action])
        updateProviderState("embedded_runtime_reload_requested", extraFields: ["action": action])
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 0.2) { [weak self] in
            guard let self else { return }
            self.stopEmbeddedRuntimeForReload()
            self.startTunnel(options: nil) { error in
                self.runtimeReloadInProgress = false
                if let error {
                    self.recordNativeEvent("embedded_runtime_reload_failed", fields: [
                        "action": action,
                        "error": error.localizedDescription,
                    ])
                    self.updateProviderState("embedded_runtime_reload_failed", extraFields: [
                        "action": action,
                        "error": error.localizedDescription,
                    ])
                    return
                }
                self.recordNativeEvent("embedded_runtime_reload_completed", fields: ["action": action])
                self.updateProviderState("embedded_runtime_reload_completed", extraFields: ["action": action])
            }
        }
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
            #else
            guard nativeRuntimeActive else {
                throw NSError(
                    domain: errorDomain,
                    code: 4,
                    userInfo: [NSLocalizedDescriptionKey: "IPServer Swift runtime is not active"]
                )
            }
            let response = try nativeAppMessageResponse(for: payload)
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

    private func sharedAdminWebDirectoryURL() -> URL? {
        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.obstaclebridge.shared"
        ) else {
            return nil
        }
        let directory = containerURL.appendingPathComponent("admin_web", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    private func loadSharedRuntimeConfigJSON() -> [String: Any]? {
        guard let url = runtimeConfigURL(),
              let data = try? Data(contentsOf: url),
              let rawJSON = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return nil
        }
        return (try? ObstacleBridgeConfigSecretCodec.decryptPayload(rawJSON)) ?? rawJSON
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

    private func remoteServiceCatalogMuxFrames(
        providerConfiguration: [String: Any]?,
        instanceID: UInt64 = 0,
        connectionSeq: UInt32 = 0
    ) -> [Data] {
        guard let payload = runtimeConfigPayload(providerConfiguration: providerConfiguration) else {
            return []
        }
        return ObstacleBridgeRuntimeConfig.remoteServiceCatalogMuxFrames(
            from: payload,
            instanceID: instanceID,
            connectionSeq: connectionSeq
        )
    }

    private static func decodedProviderRuntimeConfig(_ providerConfiguration: [String: Any]?) -> [String: Any]? {
        guard let runtimeConfig = providerConfiguration?["runtime_config"] as? [String: Any] else {
            return nil
        }
        if let decrypted = try? ObstacleBridgeConfigSecretCodec.decryptPayload(runtimeConfig) {
            return decrypted
        }
        return runtimeConfig
    }

    private func runtimeConfigPayload(providerConfiguration: [String: Any]?) -> [String: Any]? {
        if let payload = loadSharedRuntimeConfigJSON() {
            return ObstacleBridgeRuntimeConfig.flatten(payload)
        }
        if let runtimeConfig = Self.decodedProviderRuntimeConfig(providerConfiguration) {
            return ObstacleBridgeRuntimeConfig.flatten(runtimeConfig)
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
                sharedCompressLayerRuntime = ObstacleBridgeCompressLayerRuntime(
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

            if settings.transport == "quic" {
                summary["quic_runtime"] = "ready"
                summary["quic_alpn"] = ObstacleBridgeRuntimeConfig.stringValue(from: payload["quic_alpn"]) ?? "hq-29"
                summary["quic_insecure"] = ObstacleBridgeRuntimeConfig.boolValue(from: payload["quic_insecure"]) ?? false
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

    private func startControlServer() throws {
        controlServer?.stop()
        let runtimeConfig = adminRuntimeConfigPayload() ?? [:]
        let bindHost = ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["admin_web_bind"]) ?? "127.0.0.1"
        let port = ObstacleBridgeRuntimeConfig.intValue(from: runtimeConfig["admin_web_port"]) ?? 18080
        let server = try ObstacleBridgeWebAdminServer(
            bindHost: bindHost,
            port: port,
            fallbackIndexTitle: "ObstacleBridge iOS Network Extension",
            fallbackIndexSubtitle: "Network-extension hosted WebAdmin backed directly by the packet-tunnel runtime.",
            statusProvider: { [weak self] in
                self?.adminStatusSnapshot() ?? ["ok": false, "error": "provider unavailable"]
            },
            apiProvider: { [weak self] method, path, headers, body in
                guard let self else {
                    return nil
                }
                let request = ObstacleBridgeAdminAPIRequest(method: method, path: path, headers: headers, body: body)
                return ObstacleBridgeAdminAPI.response(for: request, provider: self)
            },
            staticFileProvider: { [weak self] path in
                self?.staticFileResponse(path: path)
            },
            liveTopicProvider: { [weak self] topic in
                guard let self else {
                    return nil
                }
                return ObstacleBridgeAdminAPI.liveTopicPayload(topic: topic, provider: self)
            },
            authRequiredProvider: { [weak self] in
                self?.adminAuthRequired() ?? false
            },
            authenticatedProvider: { [weak self] headers in
                self?.adminIsAuthenticated(headers: headers) ?? false
            }
        )
        controlServer = server
        server.start()
        recordNativeEvent(
            "admin_web_started",
            fields: [
                "bind_host": bindHost,
                "port": port,
                "admin_web_dir": sharedAdminWebDirectoryURL()?.path ?? "",
            ]
        )
    }

    private func staticFileResponse(path: String) -> (contentType: String, body: Data)? {
        guard let adminWebDirectory = sharedAdminWebDirectoryURL() else {
            return nil
        }
        return ObstacleBridgeAdminWebSupport.staticFileResponse(baseDirectoryURL: adminWebDirectory, path: path)
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
        let tunServiceSpec = ObstacleBridgeRuntimeConfig.ownServerSpecs(from: payload, preserveInputIndices: true)
            .first(where: { $0.listenProtocol == "tun" && $0.targetProtocol == "tun" })?
            .toChannelMuxServiceSpec()
        return SwiftSimpleUDPPeerSettings(
            runtimeMode: config.runtimeMode,
            bindHost: config.bindHost,
            overlayBindHost: config.overlayBindHost,
            bindPort: config.bindPort,
            peerHost: config.peerHost,
            peerPort: config.peerPort,
            peerResolveFamily: config.peerResolveFamily,
            mtu: config.mtu,
            tunIfname: config.tunIfname,
            tunServiceSpec: tunServiceSpec,
            tunnelAddress6: (ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: payload)?.tunnelAddress6 ?? PacketTunnelProvider.defaultTunnelAddress6),
            runtimeConfig: payload
        )
    }
}

extension PacketTunnelProvider: ObstacleBridgeAdminAPIStateProvider {
    func adminStatusSnapshot() -> [String: Any] {
        let bridgeSnapshot = adminBridgeSnapshot()
        let startedAt = adminStartedAt(bridgeSnapshot: bridgeSnapshot)
        let runtimeConfig = adminRuntimeConfigPayload() ?? [:]
        var payload = ObstacleBridgeAdminSnapshotSupport.statusEnvelope(
            runtimeOwner: "IPServer Network Extension",
            runtimeMode: runtimeMode,
            adminWebName: ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["admin_web_name"]) ?? "",
            adminUI: adminUIPayload(runtimeConfig: runtimeConfig),
            securityAdvisor: securityAdvisorPayload(runtimeConfig: runtimeConfig),
            startedAt: startedAt,
            uptimeSec: adminUptimeSeconds(startedAt: startedAt),
            bootstrapState: sharedOverlayBootstrapState,
            transportRuntime: adminTransportRuntimeSnapshot(bridgeSnapshot: bridgeSnapshot),
            compressLayer: adminCompressLayerSnapshot() ?? NSNull(),
            extra: [
                "packet_pump_running": packetPumpRunning,
                "provider_state_update_count": providerStateUpdateCount,
                "heartbeat_tick_count": heartbeatTickCount,
                "bridge_state": ObstacleBridgePacketFlowBridge.bridgeStateSnapshot(),
                "shared_overlay_bootstrap_state": sharedOverlayBootstrapState,
            ]
        )
        if !bridgeSnapshot.isEmpty {
            payload["swift_udp_bridge_state"] = bridgeSnapshot
        }
        if !effectivePacketTunnelSettingsState.isEmpty {
            payload["effective_tunnel_network_settings"] = effectivePacketTunnelSettingsState
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

    func adminTunRoutingSnapshot() -> [String: Any] {
        ObstacleBridgeAdminAPI.tunRoutingSnapshot(fromConnections: adminConnectionsSnapshot())
    }

    func adminPeersSnapshot() -> [[String: Any]] {
        let bridgeSnapshot = adminBridgeSnapshot()
        let connections = adminConnectionsSnapshot()
        let traffic = adminPeerTraffic(bridgeSnapshot: bridgeSnapshot)
        let openConnections = adminOpenConnections(bridgeSnapshot: bridgeSnapshot)
        let state = adminTransportConnectedState(bridgeSnapshot: bridgeSnapshot) ? "connected" : "connecting"
        let runtimeConfig = adminRuntimeConfigPayload()
        let transport = ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig?["overlay_transport"]) ?? "myudp"
        let endpoint = adminPeerEndpoint(runtimeConfig: runtimeConfig)
        let transportRuntime = adminTransportRuntimeSnapshot(bridgeSnapshot: bridgeSnapshot)
        let myudpRuntime = transportRuntime["myudp"] as? [String: Any] ?? [:]
        let protocolStats = myudpRuntime["protocol_stats"] as? [String: Any] ?? [:]
        return [[
            "id": 1,
            "transport": transport,
            "state": state,
            "listen": NSNull(),
            "peer": endpoint,
            "decode_errors": 0,
            "inflight": protocolStats["buffered_frames"] ?? 0,
            "last_incoming_age_seconds": adminLastIncomingAgeSeconds(runtime: myudpRuntime),
            "rtt_est_ms": myudpRuntime["rtt_est_ms"] ?? NSNull(),
            "transmit_delay_est_ms": myudpRuntime["transmit_delay_est_ms"] ?? NSNull(),
            "traffic": traffic,
            "open_connections": openConnections,
            "secure_link": adminSecureLinkSnapshot(state: state),
            "compress_layer": adminCompressLayerSnapshot() ?? NSNull(),
            "throttle": ObstacleBridgeAdminSnapshotSupport.peerThrottleSnapshot(peerID: 1, connectionsSnapshot: connections),
            "runtime": transportRuntime,
            "myudp": [
                "buffered_frames": protocolStats["buffered_frames"] ?? 0,
                "first_pass": protocolStats["first_pass"] ?? 0,
                "repeated_once": protocolStats["repeated_once"] ?? 0,
                "repeated_multiple": protocolStats["repeated_multiple"] ?? 0,
                "confirmed_total": protocolStats["confirmed_total"] ?? 0,
            ],
        ]]
    }

    private func adminTransportConnectedState(bridgeSnapshot: [String: Any]) -> Bool {
        guard adminBoolValue(bridgeSnapshot["active"]) else {
            return false
        }
        let transport = ObstacleBridgeRuntimeConfig.stringValue(from: adminRuntimeConfigPayload()?["overlay_transport"]) ?? "myudp"
        let transportRuntime = bridgeSnapshot["transport_runtime"] as? [String: Any] ?? [:]
        if transport != "myudp" {
            return adminBoolValue(transportRuntime["overlay_connected"])
        }
        let myudpRuntime = bridgeSnapshot["myudp_runtime"] as? [String: Any] ?? transportRuntime
        return ObstacleBridgeAdminSnapshotSupport.transportConnected(
            lastRttOKNSValue: myudpRuntime["last_rtt_ok_ns"],
            lastRxWallNSValue: myudpRuntime["last_rx_wall_ns"],
            fallbackConnected: adminBoolValue(myudpRuntime["connected"])
        )
    }

    private func adminLastIncomingAgeSeconds(runtime: [String: Any]) -> Any {
        ObstacleBridgeAdminSnapshotSupport.lastIncomingAgeSeconds(from: runtime)
    }

    func adminMetaSnapshot() -> [String: Any] {
        let bridgeSnapshot = adminBridgeSnapshot()
        let startedAt = adminStartedAt(bridgeSnapshot: bridgeSnapshot)
        let runtimeConfig = adminRuntimeConfigPayload() ?? [:]
        return ObstacleBridgeAdminSnapshotSupport.metaEnvelope(
            runtimeOwner: "IPServer Network Extension",
            runtimeMode: runtimeMode,
            adminWebName: ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["admin_web_name"]) ?? "",
            adminUI: adminUIPayload(runtimeConfig: runtimeConfig),
            securityAdvisor: securityAdvisorPayload(runtimeConfig: runtimeConfig),
            startedAt: startedAt,
            uptimeSec: adminUptimeSeconds(startedAt: startedAt),
            bootstrapState: sharedOverlayBootstrapState,
            transportRuntime: adminTransportRuntimeSnapshot(bridgeSnapshot: bridgeSnapshot),
            compressLayer: adminCompressLayerSnapshot() ?? NSNull(),
            extra: [
                "effective_tunnel_network_settings": effectivePacketTunnelSettingsState,
                "control_actions": [
                "restart_supported": true,
                "reconnect_supported": true,
                "shutdown_supported": false,
                ],
                "secure_link": adminSecureLinkSnapshot(state: packetPumpRunning ? "connected" : "idle"),
            ]
        )
    }

    func adminConfigSnapshot() -> [String: Any] {
        ObstacleBridgeAdminSnapshotSupport.configEnvelope(
            config: ObstacleBridgeRuntimeConfig.maskedConfigSnapshot(adminRuntimeConfigPayload() ?? [:]),
            schema: ObstacleBridgeRuntimeConfig.configSchemaSnapshot()
        )
    }

    func adminConfigChallenge(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        ObstacleBridgeAdminConfigSupport.configChallengeResponse(
            request: request,
            authRequired: adminAuthRequired(),
            authenticated: adminIsAuthenticated(headers: request.headers),
            challengeIssuer: { [weak self] updates in
                guard let self else {
                    throw NSError(domain: "ObstacleBridge.IPServer", code: 27, userInfo: [NSLocalizedDescriptionKey: "provider unavailable"])
                }
                return try self.adminConfigChallengeStore.issueChallenge(updates: updates)
            }
        )
    }

    func adminAuthRequired() -> Bool {
        let runtimeConfig = adminRuntimeConfigPayload() ?? [:]
        if ObstacleBridgeRuntimeConfig.boolValue(from: runtimeConfig["admin_web_auth_disable"]) ?? false {
            return false
        }
        return !adminAuthUsername().isEmpty && !adminAuthPassword().isEmpty
    }

    func adminIsAuthenticated(headers: [String: String]) -> Bool {
        adminAuth.isAuthenticated(headers: headers)
    }

    func adminAuthState(headers: [String: String]) -> [String: Any] {
        adminAuth.authState(headers: headers)
    }

    func adminAuthChallenge(method: String) -> ObstacleBridgeAdminAPIResponse {
        adminAuth.authChallenge(method: method)
    }

    func adminAuthLogin(method: String, body: Data?) -> ObstacleBridgeAdminAPIResponse {
        adminAuth.authLogin(method: method, body: body)
    }

    func adminAuthLogout(method: String, headers: [String: String]) -> ObstacleBridgeAdminAPIResponse {
        adminAuth.authLogout(method: method, headers: headers)
    }

    func adminOnboardingConnectionProfiles() -> [[String: Any]] {
        ObstacleBridgeOnboarding.connectionProfiles(runtimeConfig: adminRuntimeConfigPayload() ?? [:])
    }

    func adminOnboardingBlueprints() -> [[String: Any]] {
        []
    }

    func adminOnboardingInviteGenerate(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        let profiles = adminOnboardingConnectionProfiles()
        return ObstacleBridgeAdminConfigSupport.inviteGenerateResponse(
            method: request.method,
            body: request.body,
            runtimeConfig: adminRuntimeConfigPayload() ?? [:],
            profiles: profiles,
            encryptSecrets: ObstacleBridgeConfigSecretCodec.encryptPayload
        )
    }

    func adminOnboardingInvitePreview(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        ObstacleBridgeAdminConfigSupport.invitePreviewResponse(
            method: request.method,
            body: request.body,
            decryptSecrets: ObstacleBridgeConfigSecretCodec.decryptPayload
        )
    }

    func adminUpdateConfig(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        let payload: [String: Any]
        switch ObstacleBridgeAdminConfigSupport.jsonObjectBody(method: request.method, expectedMethod: "POST", body: request.body) {
        case .response(let response):
            return response
        case .payload(let value):
            payload = value
        }
        let updates: [String: Any]
        switch ObstacleBridgeAdminConfigSupport.updatesObject(from: payload) {
        case .response(let response):
            return response
        case .payload(let value):
            updates = value
        }

        if let response = ObstacleBridgeAdminConfigSupport.validateConfigChallengePayload(
            payload: payload,
            updates: updates,
            authRequired: adminAuthRequired(),
            challengeValidator: { [weak self] challengeID, proof, updates in
                self?.adminConfigChallengeStore.validate(challengeID: challengeID, proof: proof, updates: updates)
            }
        ) {
            return response
        }

        do {
            try persistAdminConfigUpdates(updates)
        } catch {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "error": error.localizedDescription,
            ], statusLine: "HTTP/1.1 400 Bad Request")
        }

        let restartAfterSave = (payload["restart_after_save"] as? Bool) ?? false
        if restartAfterSave {
            scheduleEmbeddedRuntimeReload(action: "restart_after_save")
        }
        if updates.keys.contains(where: { ["admin_web_auth_disable", "admin_web_username", "admin_web_password", "secure_link_psk"].contains($0) }) {
            adminConfigChallengeStore.reset()
            adminAuth.resetState()
        }
        return ObstacleBridgeAdminConfigSupport.configUpdateSuccessResponse(
            maskedConfig: ObstacleBridgeRuntimeConfig.maskedConfigSnapshot(adminRuntimeConfigPayload() ?? [:]),
            restartAfterSave: restartAfterSave,
            restartEmbedded: restartAfterSave
        )
    }

    func adminLogLines(limit: Int) -> [String] {
        guard let url = adminNativeProviderLogURL(),
              let text = try? String(contentsOf: url, encoding: .utf8) else {
            return []
        }
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        return Array(lines.suffix(max(1, min(limit, 1000))))
    }

    func adminRequestRestart() -> [String: Any] {
        scheduleEmbeddedRuntimeReload(action: "restart")
        return [
            "ok": true,
            "restart_requested": true,
            "restart_supported": true,
            "restart_delay_sec": 0,
            "restart_embedded": true,
            "restart_mode": "immediate",
        ]
    }

    func adminRequestReconnect() -> [String: Any] {
        scheduleEmbeddedRuntimeReload(action: "reconnect")
        return [
            "ok": true,
            "reconnect_requested": true,
            "reconnect_supported": true,
            "restart_embedded": true,
        ]
    }

    func adminRequestRestart(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        guard request.method.uppercased() == "POST" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        if let forbidden = adminAuth.validateBearer(headers: request.headers) {
            return forbidden
        }
        return ObstacleBridgeAdminAPI.jsonResponse(adminRequestRestart())
    }

    func adminRequestReconnect(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        guard request.method.uppercased() == "POST" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        if let forbidden = adminAuth.validateBearer(headers: request.headers) {
            return forbidden
        }
        return ObstacleBridgeAdminAPI.jsonResponse(adminRequestReconnect())
    }

    func adminRequestShutdown(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        guard request.method.uppercased() == "POST" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        if let forbidden = adminAuth.validateBearer(headers: request.headers) {
            return forbidden
        }
        return ObstacleBridgeAdminAPI.jsonResponse(adminRequestShutdown())
    }

    private func adminRuntimeDependenciesPayload() -> [String: Any] {
        ObstacleBridgeAdminWebSupport.adminRuntimeDependenciesPayload()
    }

    private func adminUIPayload(runtimeConfig: [String: Any]) -> [String: Any] {
        ObstacleBridgeAdminWebSupport.adminUIPayload(
            runtimeConfig: runtimeConfig,
            platform: "ios",
            runtimeDependencies: adminRuntimeDependenciesPayload()
        )
    }

    private func securityAdvisorPayload(runtimeConfig: [String: Any]) -> [String: Any] {
        ObstacleBridgeAdminWebSupport.securityAdvisorPayload(
            runtimeConfig: runtimeConfig,
            bindHostFallback: "127.0.0.1"
        )
    }

    private func adminAuthUsername() -> String {
        ObstacleBridgeRuntimeConfig.stringValue(from: adminRuntimeConfigPayload()?["admin_web_username"]) ?? ""
    }

    private func adminAuthPassword() -> String {
        ObstacleBridgeRuntimeConfig.stringValue(from: adminRuntimeConfigPayload()?["admin_web_password"]) ?? ""
    }

    private func adminWebToken() -> String {
        ObstacleBridgeRuntimeConfig.stringValue(from: adminRuntimeConfigPayload()?["admin_web_token"]) ?? ""
    }

    private func adminSessionCookieScope() -> String {
        let runtimeConfig = adminRuntimeConfigPayload() ?? [:]
        let bindHost = ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["admin_web_bind"]) ?? "127.0.0.1"
        let port = ObstacleBridgeRuntimeConfig.intValue(from: runtimeConfig["admin_web_port"]) ?? 18080
        let path = ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["admin_web_path"]) ?? "/"
        return [bindHost, String(port), path].joined(separator: "|")
    }

    private func adminRuntimeConfigPayload() -> [String: Any]? {
        if let payload = loadSharedRuntimeConfigJSON() {
            return ObstacleBridgeRuntimeConfig.flatten(payload)
        }
        let providerConfiguration = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        if let runtimeConfig = Self.decodedProviderRuntimeConfig(providerConfiguration) {
            return ObstacleBridgeRuntimeConfig.flatten(runtimeConfig)
        }
        return nil
    }

    private func adminRuntimeConfigRawPayload() -> [String: Any] {
        if let payload = loadSharedRuntimeConfigJSON() {
            return payload
        }
        let providerConfiguration = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        if let runtimeConfig = Self.decodedProviderRuntimeConfig(providerConfiguration) {
            return runtimeConfig
        }
        return [:]
    }

    private func persistAdminConfigUpdates(_ updates: [String: Any]) throws {
        let currentRawConfig = adminRuntimeConfigRawPayload()
        let currentRuntimeConfig = ObstacleBridgeRuntimeConfig.flatten(currentRawConfig)
        let result = try ObstacleBridgeAdminConfigSupport.validatedNextRawConfig(
            currentRawConfig: currentRawConfig,
            currentRuntimeConfig: currentRuntimeConfig,
            updates: updates
        )
        let nextRawConfig = result.nextRawConfig
        try persistSharedRuntimeConfigJSON(nextRawConfig)
        recordNativeEvent("admin_config_updated", fields: ["keys": result.normalizedKeys])
    }

    private func persistSharedRuntimeConfigJSON(_ payload: [String: Any]) throws {
        guard let url = runtimeConfigURL() else {
            throw NSError(domain: errorDomain, code: 26, userInfo: [NSLocalizedDescriptionKey: "shared config location unavailable"])
        }
        let directoryURL = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: true)
        let persistedPayload = try ObstacleBridgeConfigSecretCodec.encryptPayload(payload)
        let data = try JSONSerialization.data(withJSONObject: persistedPayload, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: url, options: [.atomic])
    }

    private func adminBridgeSnapshot() -> [String: Any] {
        swiftSimpleUDPPeerBridge?.snapshot() ?? [:]
    }

    private func adminStartedAt(bridgeSnapshot: [String: Any]) -> TimeInterval {
        if let startedAt = bridgeSnapshot["started_at"] as? TimeInterval {
            return startedAt
        }
        if let startedAt = bridgeSnapshot["started_at"] as? NSNumber {
            return startedAt.doubleValue
        }
        return providerStartedAt
    }

    private func adminUptimeSeconds(startedAt: TimeInterval) -> Int {
        max(0, Int(Date().timeIntervalSince1970 - startedAt))
    }

    private func adminTransportRuntimeSnapshot(bridgeSnapshot: [String: Any]) -> [String: Any] {
        let overlayConnected = adminTransportConnectedState(bridgeSnapshot: bridgeSnapshot)
        let transport = ObstacleBridgeRuntimeConfig.stringValue(from: adminRuntimeConfigPayload()?["overlay_transport"]) ?? "myudp"
        let transportRuntime = bridgeSnapshot["transport_runtime"] as? [String: Any] ?? [:]
        let myudpRuntime = bridgeSnapshot["myudp_runtime"] as? [String: Any] ?? (transport == "myudp" ? transportRuntime : [:])
        let tcpRuntime: [String: Any]? = transport == "tcp"
            ? transportRuntime
            : [
                "overlay_connected": overlayConnected,
                "listener_count": adminIntValue(bridgeSnapshot["tcp_listener_count"]),
                "server_connection_count": adminIntValue(bridgeSnapshot["tcp_server_connection_count"]),
                "client_connection_count": adminIntValue(bridgeSnapshot["tcp_client_connection_count"]),
            ]
        let websocketRuntime: [String: Any]? = transport == "ws" ? transportRuntime : nil
        let quicRuntime: [String: Any]? = transport == "quic" ? transportRuntime : nil
        return ObstacleBridgeAdminSnapshotSupport.transportRuntimeEnvelope(
            kind: transport,
            status: sharedOverlayBootstrapState["status"] ?? "unknown",
            myudp: myudpRuntime,
            tcp: tcpRuntime,
            quic: quicRuntime,
            websocket: websocketRuntime,
            extra: [
                "packetflow_bridge": ObstacleBridgePacketFlowBridge.bridgeStateSnapshot(),
                "swift_udp_bridge_state": bridgeSnapshot,
            ]
        )
    }

    private func adminPeerTraffic(bridgeSnapshot: [String: Any]) -> [String: Any] {
        let bridgeRows = swiftSimpleUDPPeerBridge?.connectionRows()
        let tcpRows = bridgeRows?.tcp ?? []
        let udpRows = bridgeRows?.udp ?? []
        let tunRows = bridgeRows?.tun ?? []

        var rxBytes = adminIntValue(bridgeSnapshot["bytes_to_system"])
        var txBytes = adminIntValue(bridgeSnapshot["bytes_from_system"])
        for row in tcpRows + udpRows + tunRows {
            guard let stats = row["stats"] as? [String: Any] else {
                continue
            }
            rxBytes += adminIntValue(stats["rx_bytes"])
            txBytes += adminIntValue(stats["tx_bytes"])
        }

        let now = Date().timeIntervalSince1970
        var rxRate = 0.0
        var txRate = 0.0
        if let previous = peerTrafficRateState {
            let dt = now - previous.timestamp
            if dt > 0 {
                rxRate = Double(max(0, rxBytes - previous.rxBytes)) / dt
                txRate = Double(max(0, txBytes - previous.txBytes)) / dt
            }
        }
        peerTrafficRateState = (timestamp: now, rxBytes: rxBytes, txBytes: txBytes)

        return [
            "rx_bytes": rxBytes,
            "tx_bytes": txBytes,
            "rx_bytes_per_sec": rxRate,
            "tx_bytes_per_sec": txRate,
        ]
    }

    private func adminOpenConnections(bridgeSnapshot: [String: Any]) -> [String: Any] {
        let transportRuntime = bridgeSnapshot["transport_runtime"] as? [String: Any] ?? [:]
        return [
            "udp": 0,
            "tcp": adminIntValue(bridgeSnapshot["tcp_server_connection_count"]) + adminIntValue(bridgeSnapshot["tcp_client_connection_count"]),
            "tun": max(packetPumpRunning ? 1 : 0, adminIntValue(transportRuntime["tun_channels"])),
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

    private static func packetTunnelSettingsSnapshot(_ configuration: ObstacleBridgePacketTunnelConfiguration) -> [String: Any] {
        [
            "peer_host": configuration.peerHost,
            "peer_port": configuration.peerPort.map { Int($0) } ?? NSNull(),
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
            secureLinkConnectedSinceUnixTS = nil
            secureLinkLastAuthenticatedUnixTS = nil
            secureLinkLastSessionID = 0
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
        let nowUnixTS = Int(Date().timeIntervalSince1970)
        let displayAuthenticated = snapshot.peerConfirmedAuthenticated
        let previousSessionID = secureLinkLastSessionID
        if snapshot.sessionID == 0 {
            secureLinkConnectedSinceUnixTS = nil
            secureLinkLastSessionID = 0
        } else {
            if previousSessionID != snapshot.sessionID || secureLinkConnectedSinceUnixTS == nil {
                secureLinkConnectedSinceUnixTS = nowUnixTS
            }
            secureLinkLastSessionID = snapshot.sessionID
        }
        if displayAuthenticated {
            if secureLinkLastAuthenticatedUnixTS == nil || previousSessionID != snapshot.sessionID {
                secureLinkLastAuthenticatedUnixTS = nowUnixTS
            }
        } else if snapshot.authFailCode != 0 {
            secureLinkLastAuthenticatedUnixTS = nil
        }
        let secureState: String
        let lastEvent: String
        let disconnectReason: String
        if displayAuthenticated {
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
            "authenticated": displayAuthenticated,
            "session_id": snapshot.sessionID == 0 ? NSNull() : snapshot.sessionID,
            "rekey_in_progress": false,
            "last_event": lastEvent,
            "last_event_unix_ts": NSNull(),
            "last_authenticated_unix_ts": displayAuthenticated ? (secureLinkLastAuthenticatedUnixTS ?? nowUnixTS) : NSNull(),
            "connected_since_unix_ts": snapshot.sessionID == 0 ? NSNull() : (secureLinkConnectedSinceUnixTS ?? nowUnixTS),
            "authenticated_sessions_total": displayAuthenticated ? 1 : 0,
            "rekeys_completed_total": 0,
            "peer_subject_id": "",
            "peer_subject_name": "",
            "peer_roles": [],
            "peer_deployment_id": "",
            "peer_serial": "",
            "issuer_id": "",
            "trust_validation_state": displayAuthenticated ? "validated" : "n/a",
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
        let myudpRuntime = bridgeSnapshot["myudp_runtime"] as? [String: Any] ?? [:]
        let tunConnectedRows = bridgeRows?.tun ?? []
        let tunActive = max(packetPumpRunning ? 1 : 0, intValue(myudpRuntime["tun_channels"]), tunConnectedRows.count)
        let tunStats = (myudpRuntime["tun_stats"] as? [String: Int]) ?? [
            "rx_msgs": 0,
            "tx_msgs": 0,
            "rx_bytes": intValue(bridgeSnapshot["bytes_to_system"]),
            "tx_bytes": intValue(bridgeSnapshot["bytes_from_system"]),
        ]

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
        tunRows.append(contentsOf: tunConnectedRows)
        if tunConnectedRows.isEmpty, tunActive > 0, let primaryTun = serviceSpecs.first(where: { $0.listenProtocol == "tun" }) {
            tunRows.append(connectionRow(for: primaryTun, state: "connected", stats: tunStats))
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
        var row: [String: Any] = [
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
        if spec.listenProtocol == "tun",
           spec.targetProtocol == "tun",
           let ownershipValue = ObstacleBridgeChannelMuxCodec.sharedTunOwnershipSnapshot(for: spec.toChannelMuxServiceSpec()),
           let ownership = ObstacleBridgeChannelMuxCodec.foundationObject(from: ownershipValue) as? [String: Any] {
            var runtime = ownership
            runtime["active_peer_bindings"] = []
            runtime["throttle_scopes"] = []
            runtime["drop_counters"] = ["total": 0, "by_reason": [:] as [String: Int]]
            runtime["recent_drops"] = []
            row["shared_tun_ownership"] = runtime
        }
        return row
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

    private static func normalizePeerHost(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return ""
        }
        let token: String
        if trimmed.contains(",") || trimmed.contains(";") {
            token = trimmed
                .replacingOccurrences(of: ";", with: ",")
                .split(separator: ",")
                .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
                .first(where: { !$0.isEmpty }) ?? trimmed
        } else {
            token = trimmed
        }
        if token.hasPrefix("[") && token.hasSuffix("]") {
            return String(token.dropFirst().dropLast())
        }
        return token
    }

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
           let host = peer["host"] as? String {
            let normalizedHost = Self.normalizePeerHost(host)
            peerHost = normalizedHost.isEmpty ? "127.0.0.1" : normalizedHost
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
    let overlayBindHost: String
    let bindPort: Int
    let peerHost: String
    let peerPort: Int
    let peerResolveFamily: String
    let mtu: Int
    let tunIfname: String
    let tunServiceSpec: ObstacleBridgeChannelMuxCodec.ServiceSpec?
    let tunnelAddress6: String
    let runtimeConfig: [String: Any]
}

private final class SwiftSimpleUDPPeerBridge {
    private static let queueKey = DispatchSpecificKey<UInt8>()
    private static let peerFallbackIdleNS: UInt64 = 3_000_000_000
    private weak var provider: PacketTunnelProvider?
    private let settings: SwiftSimpleUDPPeerSettings
    private let selectedTransport: String
    private let tunnelAddress: String
    private let tunnelAddress6: String
    private let tcpServiceSpecs: [ObstacleBridgeChannelMuxCodec.ServiceSpec]
    private let startupMuxFrames: [Data]
    private let muxInstanceID: UInt64
    private let muxConnectionSeq: UInt32
    private let queue = DispatchQueue(label: "com.obstaclebridge.ipserver.swift-simple-udp-peer")
    private var udpOverlayTransportOwner: ObstacleBridgeUdpOverlayTransportOwner?
    private var tcpOverlayTransportOwner: ObstacleBridgeTcpOverlayTransportOwner?
    private var wsOverlayTransportOwner: ObstacleBridgeWebSocketOverlayTransportOwner?
    private var quicOverlayTransportOwnerBox: AnyObject?
    private var socketFD: Int32 = -1
    private var socketFamily: Int32
    private var peerCandidates: [ResolvedAddress]
    private var peerCandidateIndex = 0
    private var peerAddress: ResolvedAddress
    private var overlayLayerTransportAdapter: ObstacleBridgeOverlayLayerTransportAdapter?
    private var tcpListeners: [Int: NWListener] = [:]
    private var readSource: DispatchSourceRead?
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
    private var tcpListenerFailures = 0

    @available(iOS 15.0, *)
    private var quicOverlayTransportOwner: ObstacleBridgeQuicOverlayTransportOwner? {
        get { quicOverlayTransportOwnerBox as? ObstacleBridgeQuicOverlayTransportOwner }
        set { quicOverlayTransportOwnerBox = newValue }
    }

    init(
        provider: PacketTunnelProvider? = nil,
        settings: SwiftSimpleUDPPeerSettings,
        tunnelAddress: String,
        tunnelAddress6: String,
        tcpServiceSpecs: [ObstacleBridgeChannelMuxCodec.ServiceSpec],
        startupMuxFrames: [Data] = [],
        muxInstanceID: UInt64 = UInt64.random(in: 1...UInt64.max),
        muxConnectionSeq: UInt32 = UInt32.random(in: 1...UInt32.max),
        overlayLayerTransportAdapter: ObstacleBridgeOverlayLayerTransportAdapter? = nil
    ) throws {
        self.provider = provider
        self.settings = settings
        let configuredTransport = ObstacleBridgeRuntimeConfig.stringValue(from: settings.runtimeConfig["overlay_transport"]) ?? "myudp"
        self.selectedTransport = configuredTransport
            .split(separator: ",")
            .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
            .first(where: { !$0.isEmpty }) ?? "myudp"
        self.tunnelAddress = tunnelAddress
        self.tunnelAddress6 = tunnelAddress6
        self.tcpServiceSpecs = tcpServiceSpecs
        self.startupMuxFrames = startupMuxFrames
        self.muxInstanceID = muxInstanceID
        self.muxConnectionSeq = muxConnectionSeq
        self.overlayLayerTransportAdapter = overlayLayerTransportAdapter
        let sessionMaxAppPayload = ObstacleBridgeRuntimeConfig.overlaySessionMaxAppPayload(from: settings.runtimeConfig)
        self.queue.setSpecific(key: Self.queueKey, value: 1)
        if settings.runtimeMode == "swift_udp" {
            self.socketFD = -1
            self.socketFamily = AF_INET
            self.peerCandidates = []
            self.peerAddress = try Self.placeholderResolvedAddress()
            if selectedTransport == "tcp" {
                let threshold = ObstacleBridgeRuntimeConfig.intValue(from: settings.runtimeConfig["tcp_bp_wbuf_threshold"]) ?? 128 * 1024
                let runtime = ObstacleBridgeTcpOverlayRuntime(wbufThreshold: threshold)
                self.tcpOverlayTransportOwner = ObstacleBridgeTcpOverlayTransportOwner(
                    peerHost: settings.peerHost,
                    peerPort: settings.peerPort,
                    bindHost: ObstacleBridgeRuntimeConfig.stringValue(from: settings.runtimeConfig["tcp_bind"]) ?? "0.0.0.0",
                    bindPort: ObstacleBridgeRuntimeConfig.intValue(from: settings.runtimeConfig["tcp_own_port"]) ?? 0,
                    overlayRuntime: runtime,
                    reconnectRetryDelayMS: ObstacleBridgeRuntimeConfig.intValue(from: settings.runtimeConfig["overlay_reconnect_retry_delay_ms"]) ?? 30000,
                    sessionMaxAppPayload: sessionMaxAppPayload,
                    overlayLayerTransportAdapter: overlayLayerTransportAdapter,
                    startupMuxFrames: startupMuxFrames,
                    queue: queue,
                    serviceNameByID: Dictionary(uniqueKeysWithValues: tcpServiceSpecs.map { ($0.svcID, $0.name ?? "") }),
                    tunServiceSpec: settings.tunServiceSpec,
                    tunIfname: settings.tunIfname,
                    tunMTU: settings.mtu,
                    tunLocalAddress: tunnelAddress,
                    tunLocalAddress6: tunnelAddress6,
                    sharedTunDisableOutgoingNormalization: ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: settings.runtimeConfig)?.sharedTunDisableOutgoingNormalization ?? false,
                    sharedTunDisableInflowFilter: ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: settings.runtimeConfig)?.sharedTunDisableInflowFilter ?? false,
                    sharedTunDisableOutflowFilter: ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: settings.runtimeConfig)?.sharedTunDisableOutflowFilter ?? false,
                    sharedTunDisableScopedThrottle: ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: settings.runtimeConfig)?.sharedTunDisableScopedThrottle ?? false,
                    tunPacketSink: { [weak self] packet in self?.deliverPacketToSystem(packet) },
                    muxInstanceID: muxInstanceID,
                    muxConnectionSeq: muxConnectionSeq,
                    eventSink: { [weak self] event, fields in
                        self?.provider?.recordPacketBridgeEvent(event, fields: fields)
                    }
                )
            } else if selectedTransport == "ws" {
                let payloadMode = ObstacleBridgeRuntimeConfig.stringValue(from: settings.runtimeConfig["ws_payload_mode"]) ?? "binary"
                let maxSize = ObstacleBridgeRuntimeConfig.intValue(from: settings.runtimeConfig["ws_max_size"]) ?? 65535
                let sendTimeout = ObstacleBridgeRuntimeConfig.doubleValue(from: settings.runtimeConfig["ws_send_timeout"]) ?? 3.0
                let tcpUserTimeout = ObstacleBridgeRuntimeConfig.intValue(from: settings.runtimeConfig["ws_tcp_user_timeout_ms"]) ?? 10000
                let reconnectGrace = ObstacleBridgeRuntimeConfig.doubleValue(from: settings.runtimeConfig["ws_reconnect_grace"]) ?? 3.0
                let runtime = try ObstacleBridgeWebSocketOverlayRuntime(
                    payloadMode: payloadMode,
                    wsMaxSize: maxSize,
                    sendTimeoutS: sendTimeout,
                    tcpUserTimeoutMS: tcpUserTimeout,
                    reconnectGraceS: reconnectGrace
                )
                self.wsOverlayTransportOwner = ObstacleBridgeWebSocketOverlayTransportOwner(
                    peerHost: settings.peerHost,
                    peerPort: settings.peerPort,
                    useTLS: ObstacleBridgeRuntimeConfig.boolValue(from: settings.runtimeConfig["ws_tls"]) ?? (settings.peerPort == 443),
                    wsPath: ObstacleBridgeRuntimeConfig.stringValue(from: settings.runtimeConfig["ws_path"]) ?? "/",
                    wsSubprotocol: ObstacleBridgeRuntimeConfig.stringValue(from: settings.runtimeConfig["ws_subprotocol"]),
                    overlayRuntime: runtime,
                    reconnectRetryDelayMS: ObstacleBridgeRuntimeConfig.intValue(from: settings.runtimeConfig["overlay_reconnect_retry_delay_ms"]) ?? 30000,
                    sessionMaxAppPayload: sessionMaxAppPayload,
                    overlayLayerTransportAdapter: overlayLayerTransportAdapter,
                    startupMuxFrames: startupMuxFrames,
                    queue: queue,
                    serviceNameByID: Dictionary(uniqueKeysWithValues: tcpServiceSpecs.map { ($0.svcID, $0.name ?? "") }),
                    tunServiceSpec: settings.tunServiceSpec,
                    tunIfname: settings.tunIfname,
                    tunMTU: settings.mtu,
                    tunLocalAddress: tunnelAddress,
                    tunLocalAddress6: tunnelAddress6,
                    sharedTunDisableOutgoingNormalization: ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: settings.runtimeConfig)?.sharedTunDisableOutgoingNormalization ?? false,
                    sharedTunDisableInflowFilter: ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: settings.runtimeConfig)?.sharedTunDisableInflowFilter ?? false,
                    sharedTunDisableOutflowFilter: ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: settings.runtimeConfig)?.sharedTunDisableOutflowFilter ?? false,
                    sharedTunDisableScopedThrottle: ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: settings.runtimeConfig)?.sharedTunDisableScopedThrottle ?? false,
                    tunPacketSink: { [weak self] packet in self?.deliverPacketToSystem(packet) },
                    muxInstanceID: muxInstanceID,
                    muxConnectionSeq: muxConnectionSeq,
                    eventSink: { [weak self] event, fields in
                        self?.provider?.recordPacketBridgeEvent(event, fields: fields)
                    }
                )
            } else if selectedTransport == "quic" {
                if #available(iOS 15.0, *) {
                    self.quicOverlayTransportOwner = ObstacleBridgeQuicOverlayTransportOwner(
                        peerHost: settings.peerHost,
                        peerPort: settings.peerPort,
                        bindHost: ObstacleBridgeRuntimeConfig.stringValue(from: settings.runtimeConfig["quic_bind"]) ?? "::",
                        bindPort: ObstacleBridgeRuntimeConfig.intValue(from: settings.runtimeConfig["quic_own_port"]) ?? 0,
                        peerResolveFamily: settings.peerResolveFamily,
                        alpn: ObstacleBridgeRuntimeConfig.stringValue(from: settings.runtimeConfig["quic_alpn"]) ?? "hq-29",
                        insecure: ObstacleBridgeRuntimeConfig.boolValue(from: settings.runtimeConfig["quic_insecure"]) ?? false,
                        overlayRuntime: ObstacleBridgeQuicOverlayRuntime(wbufThreshold: 128 * 1024),
                        reconnectRetryDelayMS: ObstacleBridgeRuntimeConfig.intValue(from: settings.runtimeConfig["overlay_reconnect_retry_delay_ms"]) ?? 30000,
                        sessionMaxAppPayload: sessionMaxAppPayload,
                        overlayLayerTransportAdapter: overlayLayerTransportAdapter,
                        startupMuxFrames: startupMuxFrames,
                        queue: queue,
                        serviceNameByID: Dictionary(uniqueKeysWithValues: tcpServiceSpecs.map { ($0.svcID, $0.name ?? "") }),
                        tunServiceSpec: settings.tunServiceSpec,
                        tunIfname: settings.tunIfname,
                        tunMTU: settings.mtu,
                        tunLocalAddress: tunnelAddress,
                        tunLocalAddress6: tunnelAddress6,
                        sharedTunDisableOutgoingNormalization: ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: settings.runtimeConfig)?.sharedTunDisableOutgoingNormalization ?? false,
                        sharedTunDisableInflowFilter: ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: settings.runtimeConfig)?.sharedTunDisableInflowFilter ?? false,
                        sharedTunDisableOutflowFilter: ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: settings.runtimeConfig)?.sharedTunDisableOutflowFilter ?? false,
                        sharedTunDisableScopedThrottle: ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: settings.runtimeConfig)?.sharedTunDisableScopedThrottle ?? false,
                        tunPacketSink: { [weak self] packet in self?.deliverPacketToSystem(packet) },
                        muxInstanceID: muxInstanceID,
                        muxConnectionSeq: muxConnectionSeq,
                        eventSink: { [weak self] event, fields in
                            self?.provider?.recordPacketBridgeEvent(event, fields: fields)
                        }
                    )
                }
            } else {
                let resolvedPeers = try Self.resolvePeerCandidates(
                    bindHost: settings.overlayBindHost,
                    peerHost: settings.peerHost,
                    peerPort: settings.peerPort,
                    peerResolveFamily: settings.peerResolveFamily
                )
                self.socketFamily = resolvedPeers.socketFamily
                self.peerCandidates = resolvedPeers.peerCandidates
                self.peerAddress = resolvedPeers.peerAddress
                self.udpOverlayTransportOwner = ObstacleBridgeUdpOverlayTransportOwner(
                    bindHost: settings.overlayBindHost,
                    bindPort: settings.bindPort,
                    peerHost: settings.peerHost,
                    peerPort: settings.peerPort,
                    peerResolveFamily: settings.peerResolveFamily,
                    sessionMaxAppPayload: sessionMaxAppPayload,
                    overlayLayerTransportAdapter: overlayLayerTransportAdapter,
                    startupMuxFrames: startupMuxFrames,
                    queue: queue,
                    serviceNameByID: Dictionary(uniqueKeysWithValues: tcpServiceSpecs.map { ($0.svcID, $0.name ?? "") }),
                    tunServiceSpec: settings.tunServiceSpec,
                    tunIfname: settings.tunIfname,
                    tunMTU: settings.mtu,
                    tunLocalAddress: tunnelAddress,
                    tunLocalAddress6: tunnelAddress6,
                    sharedTunDisableOutgoingNormalization: ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: settings.runtimeConfig)?.sharedTunDisableOutgoingNormalization ?? false,
                    sharedTunDisableInflowFilter: ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: settings.runtimeConfig)?.sharedTunDisableInflowFilter ?? false,
                    sharedTunDisableOutflowFilter: ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: settings.runtimeConfig)?.sharedTunDisableOutflowFilter ?? false,
                    sharedTunDisableScopedThrottle: ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: settings.runtimeConfig)?.sharedTunDisableScopedThrottle ?? false,
                    tunPacketSink: { [weak self] packet in
                        self?.deliverPacketToSystem(packet)
                    },
                    muxInstanceID: muxInstanceID,
                    muxConnectionSeq: muxConnectionSeq,
                    eventSink: { [weak self] event, fields in
                        self?.provider?.recordPacketBridgeEvent(event, fields: fields)
                    }
                )
            }
        } else {
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

        if settings.runtimeMode == "swift_udp" {
            try? udpOverlayTransportOwner?.start()
            tcpOverlayTransportOwner?.start()
            wsOverlayTransportOwner?.start()
            if #available(iOS 15.0, *) {
                quicOverlayTransportOwner?.start()
            }
            startTCPServices()
        } else {
            let source = DispatchSource.makeReadSource(fileDescriptor: socketFD, queue: queue)
            source.setEventHandler { [weak self] in
                self?.drainSocket()
            }
            readSource = source
            source.resume()
            startPeerFallbackTimer()
        }

        provider.recordPacketBridgeEvent(
            "swift_simple_udp_started",
            fields: [
                "bind_host": settings.bindHost,
                "overlay_bind_host": settings.overlayBindHost,
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

        if settings.runtimeMode == "swift_udp" {
            do {
                try udpOverlayTransportOwner?.start()
                tcpOverlayTransportOwner?.start()
                wsOverlayTransportOwner?.start()
                if #available(iOS 15.0, *) {
                    quicOverlayTransportOwner?.start()
                }
            } catch {
                started = false
                fatalError("swift_udp probe start failed: \(error.localizedDescription)")
            }
            startTCPServices()
        } else {
            let source = DispatchSource.makeReadSource(fileDescriptor: socketFD, queue: queue)
            source.setEventHandler { [weak self] in
                self?.drainSocket()
            }
            readSource = source
            source.resume()
            startPeerFallbackTimer()
        }
    }

    func stop() {
        guard started else { return }
        started = false
        peerFallbackTimer?.cancel()
        peerFallbackTimer = nil
        readSource?.cancel()
        readSource = nil
        udpOverlayTransportOwner?.stop()
        tcpOverlayTransportOwner?.stop()
        wsOverlayTransportOwner?.stop()
        if #available(iOS 15.0, *) {
            quicOverlayTransportOwner?.stop()
        }
        stopTCPServices()
        if socketFD >= 0 {
            Darwin.close(socketFD)
            socketFD = -1
        }
        provider?.recordPacketBridgeEvent(
            "swift_simple_udp_stopped",
            fields: snapshot()
        )
    }

    func snapshot() -> [String: Any] {
        withState {
            let selectedRuntime =
                udpOverlayTransportOwner?.transportSnapshot()
                ?? tcpOverlayTransportOwner?.transportSnapshot()
                ?? wsOverlayTransportOwner?.transportSnapshot()
                ?? {
                    if #available(iOS 15.0, *) {
                        return quicOverlayTransportOwner?.transportSnapshot()
                    }
                    return nil
                }()
                ?? [:]
            let resolvedPeerHost = Self.runtimeStringValue(selectedRuntime["overlay_peer_host"]) ?? peerAddress.host
            let resolvedPeerPort = Self.runtimeIntValue(selectedRuntime["overlay_peer_port"]) ?? peerAddress.port
            let resolvedPeerFamily = Self.runtimeStringValue(selectedRuntime["overlay_peer_family"]) ?? Self.familyName(peerAddress.family)
            let resolvedPeerIndex = Self.runtimeIntValue(selectedRuntime["overlay_peer_candidate_index"]) ?? peerCandidateIndex
            let resolvedPeerCandidateCount = Self.runtimeIntValue(selectedRuntime["overlay_peer_candidate_count"]) ?? peerCandidates.count
            return [
                "active": started,
                "bind_host": settings.bindHost,
                "overlay_bind_host": settings.overlayBindHost,
                "bind_port": settings.bindPort,
                "peer_host": settings.peerHost,
                "peer_port": settings.peerPort,
                "peer_resolve_family": settings.peerResolveFamily,
                "resolved_peer_host": resolvedPeerHost,
                "resolved_peer_port": resolvedPeerPort,
                "resolved_peer_family": resolvedPeerFamily,
                "resolved_peer_index": resolvedPeerIndex,
                "resolved_peer_candidate_count": resolvedPeerCandidateCount,
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
                "tcp_listener_count": tcpListeners.count,
                "mux_instance_id": muxInstanceID,
                "mux_connection_seq": muxConnectionSeq,
                "tcp_server_connection_count": selectedRuntime["server_tcp_channels"] ?? 0,
                "tcp_client_connection_count": selectedRuntime["client_tcp_channels"] ?? 0,
                "tcp_listener_failures": tcpListenerFailures,
                "last_from_system_at": lastFromSystemAt,
                "last_to_system_at": lastToSystemAt,
                "started_at": startedAt,
                "transport_runtime": selectedRuntime,
                "myudp_runtime": selectedTransport == "myudp" ? selectedRuntime : [:],
            ]
        }
    }

    func connectionRows() -> (tcp: [[String: Any]], udp: [[String: Any]], tun: [[String: Any]]) {
        withState {
            if let udpOverlayTransportOwner {
                let rows = udpOverlayTransportOwner.connectionRows()
                return (rows.tcp, rows.udp, rows.tun)
            }
            if let tcpOverlayTransportOwner {
                let rows = tcpOverlayTransportOwner.connectionRows()
                return (rows.tcp, rows.udp, rows.tun)
            }
            if let wsOverlayTransportOwner {
                let rows = wsOverlayTransportOwner.connectionRows()
                return (rows.tcp, rows.udp, rows.tun)
            }
            if #available(iOS 15.0, *), let quicOverlayTransportOwner {
                let rows = quicOverlayTransportOwner.connectionRows()
                return (rows.tcp, rows.udp, rows.tun)
            }
            return ([], [], [])
        }
    }

    func overlayEstablishedForProbe() -> Bool {
        withState {
            if let udpOverlayTransportOwner {
                return udpOverlayTransportOwner.overlayConnected
            }
            if let tcpOverlayTransportOwner {
                return (tcpOverlayTransportOwner.transportSnapshot()["overlay_connected"] as? Bool) ?? false
            }
            if let wsOverlayTransportOwner {
                return (wsOverlayTransportOwner.transportSnapshot()["overlay_connected"] as? Bool) ?? false
            }
            if #available(iOS 15.0, *), let quicOverlayTransportOwner {
                return (quicOverlayTransportOwner.transportSnapshot()["overlay_connected"] as? Bool) ?? false
            }
            return false
        }
    }

    func sendTunPacketForProbe(_ packet: Data) {
        withState {
            guard started else {
                return
            }
            if let udpOverlayTransportOwner {
                udpOverlayTransportOwner.sendLocalTunPacket(packet)
                return
            }
            if let tcpOverlayTransportOwner {
                tcpOverlayTransportOwner.sendLocalTunPacket(packet)
                return
            }
            if let wsOverlayTransportOwner {
                wsOverlayTransportOwner.sendLocalTunPacket(packet)
                return
            }
            if #available(iOS 15.0, *), let quicOverlayTransportOwner {
                quicOverlayTransportOwner.sendLocalTunPacket(packet)
            }
        }
    }

    func secureLinkStatusForProbe() -> [String: Any] {
        withState {
            guard let snapshot = overlayLayerTransportAdapter?.secureLinkStatusSnapshot() else {
                return ["configured": false, "authenticated": false, "session_id": 0, "auth_fail_code": 0]
            }
            return [
                "configured": true,
                "authenticated": snapshot.authenticated,
                "session_id": snapshot.sessionID,
                "auth_fail_code": snapshot.authFailCode,
            ]
        }
    }

    private func withState<T>(_ body: () -> T) -> T {
        if DispatchQueue.getSpecific(key: Self.queueKey) != nil {
            return body()
        }
        return queue.sync(execute: body)
    }

    private func deliverPacketToSystem(_ packet: Data) {
        guard let provider else {
            return
        }
        provider.packetFlow.writePackets([packet], withProtocols: [NSNumber(value: Self.protocolFamily(for: packet))])
        packetsToSystem += 1
        bytesToSystem += packet.count
        writeBatches += 1
        lastToSystemAt = Date().timeIntervalSince1970
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
                        "swift_simple_udp_packetflow_batch",
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
                if let udpOverlayTransportOwner {
                    udpOverlayTransportOwner.sendLocalTunPacket(packet)
                } else if let tcpOverlayTransportOwner {
                    tcpOverlayTransportOwner.sendLocalTunPacket(packet)
                } else if let wsOverlayTransportOwner {
                    wsOverlayTransportOwner.sendLocalTunPacket(packet)
                } else if #available(iOS 15.0, *), let quicOverlayTransportOwner {
                    quicOverlayTransportOwner.sendLocalTunPacket(packet)
                }
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
                "swift_simple_udp_packetflow_read",
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
                packets.append(packet)
                protocols.append(NSNumber(value: Self.protocolFamily(for: packet)))
                totalBytes += Int(received)
                continue
            }
            if received == 0 {
                break
            }
            if errno == EAGAIN || errno == EWOULDBLOCK {
                break
            }
            provider?.recordPacketBridgeEvent(
                "swift_simple_udp_recv_failed",
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
                "swift_simple_udp_socket_read",
                fields: [
                    "packet_count": packets.count,
                    "total_bytes": totalBytes,
                ]
            )
        }
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
            "swift_simple_udp_fallback_rotate",
            fields: [
                "candidate_index": peerCandidateIndex,
                "resolved_peer_host": peerAddress.host,
                "resolved_peer_port": peerAddress.port,
                "resolved_peer_family": Self.familyName(peerAddress.family),
            ]
        )
    }

    private func handleImmediatePeerFallback(sendErrno: Int32) {
        guard started, peerCandidateIndex + 1 < peerCandidates.count else {
            return
        }
        switch sendErrno {
        case ENETUNREACH, EHOSTUNREACH, EADDRNOTAVAIL:
            provider?.recordPacketBridgeEvent(
                "swift_simple_udp_send_error_fallback",
                fields: [
                    "errno": sendErrno,
                    "candidate_index": peerCandidateIndex,
                    "resolved_peer_host": peerAddress.host,
                    "resolved_peer_port": peerAddress.port,
                    "resolved_peer_family": Self.familyName(peerAddress.family),
                ]
            )
            rotateToNextPeerCandidate(nowNS: monotonicNowNS())
        default:
            break
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
        if let owner = udpOverlayTransportOwner {
            guard owner.acceptLocalTCPConnection(connection, spec: spec, listenerHost: spec.lBind, listenerPort: spec.lPort) else {
                cancelConnection(connection)
                return
            }
            return
        }
        if let owner = tcpOverlayTransportOwner {
            guard owner.acceptLocalTCPConnection(connection, spec: spec, listenerHost: spec.lBind, listenerPort: spec.lPort) else {
                cancelConnection(connection)
                return
            }
            return
        }
        if let owner = wsOverlayTransportOwner {
            guard owner.acceptLocalTCPConnection(connection, spec: spec, listenerHost: spec.lBind, listenerPort: spec.lPort) else {
                cancelConnection(connection)
                return
            }
            return
        }
        if #available(iOS 15.0, *), let owner = quicOverlayTransportOwner {
            guard owner.acceptLocalTCPConnection(connection, spec: spec, listenerHost: spec.lBind, listenerPort: spec.lPort) else {
                cancelConnection(connection)
                return
            }
            return
        }
        cancelConnection(connection)
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
                        "swift_simple_udp_send_failed",
                        fields: [
                            "errno": err,
                            "packet_bytes": rawBuffer.count,
                        ]
                    )
                    handleImmediatePeerFallback(sendErrno: err)
                }
            }
        }
    }

    private func cancelConnection(_ connection: NWConnection) {
        connection.stateUpdateHandler = nil
        connection.cancel()
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

    private static func familyName(_ family: Int32) -> String {
        ObstacleBridgePeerAddressResolver.familyName(family)
    }

    private static func runtimeStringValue(_ value: Any?) -> String? {
        guard let text = value as? String, !text.isEmpty else {
            return nil
        }
        return text
    }

    private static func runtimeIntValue(_ value: Any?) -> Int? {
        if let number = value as? NSNumber {
            return number.intValue
        }
        return value as? Int
    }

    private static func makeBoundSocket(
        bindHost: String,
        bindPort: Int,
        peerHost: String,
        peerPort: Int,
        peerResolveFamily: String
    ) throws -> (socketFD: Int32, socketFamily: Int32, peerCandidates: [ResolvedAddress], peerAddress: ResolvedAddress) {
        let resolved = try resolvePeerCandidates(
            bindHost: bindHost,
            peerHost: peerHost,
            peerPort: peerPort,
            peerResolveFamily: peerResolveFamily
        )
        let socketFamily = resolved.socketFamily
        let peerCandidates = resolved.peerCandidates
        let peer = resolved.peerAddress

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
            let bindAddr = try ObstacleBridgePeerAddressResolver.resolveAddress(
                host: resolvedBindHost,
                port: bindPort,
                passive: true,
                family: socketFamily,
                errorDomain: "ObstacleBridge.IPServer"
            )
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

    private static func resolvePeerCandidates(
        bindHost: String,
        peerHost: String,
        peerPort: Int,
        peerResolveFamily: String
    ) throws -> (socketFamily: Int32, peerCandidates: [ResolvedAddress], peerAddress: ResolvedAddress) {
        let resolvedCandidates = try ObstacleBridgePeerAddressResolver.resolvePeerAddresses(
            host: peerHost,
            port: peerPort,
            resolveFamily: peerResolveFamily,
            bindHost: bindHost,
            errorDomain: "ObstacleBridge.IPServer"
        )
        let socketFamily: Int32
        if let bindFamily = ObstacleBridgePeerAddressResolver.bindFamilyConstraint(bindHost) {
            socketFamily = bindFamily
        } else if resolvedCandidates.contains(where: { $0.family == AF_INET6 }) {
            socketFamily = AF_INET6
        } else {
            socketFamily = resolvedCandidates[0].family
        }

        var peerCandidates: [ResolvedAddress] = []
        for candidate in resolvedCandidates {
            let normalized = try ObstacleBridgePeerAddressResolver.normalizePeerCandidate(
                candidate,
                socketFamily: socketFamily,
                errorDomain: "ObstacleBridge.IPServer"
            )
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
        return (socketFamily, peerCandidates, peer)
    }

    private static func placeholderResolvedAddress() throws -> ResolvedAddress {
        try ObstacleBridgePeerAddressResolver.resolveAddress(
            host: "127.0.0.1",
            port: 0,
            passive: false,
            family: AF_INET,
            errorDomain: "ObstacleBridge.IPServer"
        )
    }

    private typealias ResolvedAddress = ObstacleBridgeResolvedAddress
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
        overlayTransport: String = "myudp",
        runtimeConfigOverrides: [String: Any] = [:],
        overlayLayerTransportAdapter: ObstacleBridgeOverlayLayerTransportAdapter? = nil
    ) throws -> SwiftSimpleUDPPeerBridge {
        var runtimeConfig: [String: Any] = [
            "overlay_transport": overlayTransport,
            "secure_link": overlayLayerTransportAdapter != nil,
        ]
        for (key, value) in runtimeConfigOverrides {
            runtimeConfig[key] = value
        }
        let flattenedRuntimeConfig = ObstacleBridgeRuntimeConfig.flatten(runtimeConfig)
        let tunOwnServerSpec = ObstacleBridgeRuntimeConfig.ownServerSpecs(from: flattenedRuntimeConfig, preserveInputIndices: true)
            .first(where: { $0.listenProtocol == "tun" && $0.targetProtocol == "tun" })
        let tunServiceSpec = tunOwnServerSpec?.toChannelMuxServiceSpec()
        let settings = SwiftSimpleUDPPeerSettings(
            runtimeMode: runtimeMode,
            bindHost: bindHost,
            overlayBindHost: bindHost,
            bindPort: bindPort,
            peerHost: peerHost,
            peerPort: peerPort,
            peerResolveFamily: peerResolveFamily,
            mtu: mtu,
            tunIfname: tunIfname,
            tunServiceSpec: tunServiceSpec,
            tunnelAddress6: (ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: flattenedRuntimeConfig)?.tunnelAddress6 ?? PacketTunnelProvider.defaultTunnelAddress6),
            runtimeConfig: flattenedRuntimeConfig
        )
        let bridge = try SwiftSimpleUDPPeerBridge(
            provider: nil,
            settings: settings,
            tunnelAddress: tunnelAddress,
            tunnelAddress6: settings.tunnelAddress6,
            tcpServiceSpecs: tcpServiceSpecs,
            overlayLayerTransportAdapter: overlayLayerTransportAdapter
        )
        return bridge
    }

    static func probeEncodedProviderRuntimeConfig(
        runtimeConfig: [String: Any]
    ) throws -> [String: Any] {
        try ObstacleBridgeConfigSecretCodec.encryptPayload(runtimeConfig)
    }

    static func probeDecodedProviderRuntimeConfig(
        providerConfiguration: [String: Any]
    ) -> [String: Any]? {
        decodedProviderRuntimeConfig(providerConfiguration)
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
        overlayTransport: String = "myudp",
        runtimeConfigOverrides: [String: Any] = [:],
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
            overlayTransport: overlayTransport,
            runtimeConfigOverrides: runtimeConfigOverrides,
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

    func sendTunPacket(_ packet: Data) {
        bridge.sendTunPacketForProbe(packet)
    }

    func bridgeSnapshot() -> [String: Any] {
        bridge.snapshot()
    }

    func secureLinkStatus() -> [String: Any] {
        bridge.secureLinkStatusForProbe()
    }

    func adminConnectionsSnapshot(runtimeConfig: [String: Any] = [:], packetPumpRunning: Bool = false) -> [String: Any] {
        PacketTunnelProviderAdminSnapshotBuilder.connectionsSnapshot(
            runtimeConfig: runtimeConfig,
            packetPumpRunning: packetPumpRunning,
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
