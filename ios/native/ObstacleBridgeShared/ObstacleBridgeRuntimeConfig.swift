import Foundation

struct ObstacleBridgeDerivedTunnelSettings {
    let tunnelAddress: String
    let tunnelPrefix: Int
    let includedRoutes: [String]
    let excludedRoutes: [String]
    let tunnelAddress6: String
    let tunnelPrefix6: Int
    let includedRoutes6: [String]
    let excludedRoutes6: [String]
    let dnsServers: [String]
    let mtu: Int

    func applying(_ override: ObstacleBridgeTunnelRoutingOverride) -> ObstacleBridgeDerivedTunnelSettings {
        ObstacleBridgeDerivedTunnelSettings(
            tunnelAddress: override.tunnelAddress ?? tunnelAddress,
            tunnelPrefix: override.tunnelPrefix ?? tunnelPrefix,
            includedRoutes: override.includedRoutes ?? includedRoutes,
            excludedRoutes: override.excludedRoutes ?? excludedRoutes,
            tunnelAddress6: override.tunnelAddress6 ?? tunnelAddress6,
            tunnelPrefix6: override.tunnelPrefix6 ?? tunnelPrefix6,
            includedRoutes6: override.includedRoutes6 ?? includedRoutes6,
            excludedRoutes6: override.excludedRoutes6 ?? excludedRoutes6,
            dnsServers: override.dnsServers ?? dnsServers,
            mtu: override.mtu ?? mtu
        )
    }
}

struct ObstacleBridgeTunnelRoutingOverride {
    let tunnelAddress: String?
    let tunnelPrefix: Int?
    let includedRoutes: [String]?
    let excludedRoutes: [String]?
    let tunnelAddress6: String?
    let tunnelPrefix6: Int?
    let includedRoutes6: [String]?
    let excludedRoutes6: [String]?
    let dnsServers: [String]?
    let mtu: Int?
}

struct ObstacleBridgeRuntimeServiceSpec {
    let svcID: Int
    let name: String?
    let listenProtocol: String
    let listenBind: String
    let listenPort: Int
    let targetProtocol: String
    let targetHost: String
    let targetPort: Int
    let lifecycleHooks: [String: ObstacleBridgeChannelMuxCodec.JSONValue]?
    let options: [String: ObstacleBridgeChannelMuxCodec.JSONValue]?

    var listenIfname: String? {
        listenProtocol == "tun" ? listenBind : nil
    }

    var targetIfname: String? {
        targetProtocol == "tun" ? targetHost : nil
    }

    func mtu(fallback: Int) -> Int {
        if listenProtocol == "tun" {
            return listenPort
        }
        if targetProtocol == "tun" {
            return targetPort
        }
        return fallback
    }

    func listenerHookEnvBlocks() -> [[String: Any]] {
        guard let lifecycleHooks,
              case .object(let listenerContainer)? = lifecycleHooks["listener"]
        else {
            return []
        }
        var out: [[String: Any]] = []
        for event in ["on_created", "on_channel_connected", "on_stopped"] {
            guard case .object(let command)? = listenerContainer[event],
                  case .object(let env)? = command["env"]
            else {
                continue
            }
            out.append(Self.foundationObject(from: env))
        }
        return out
    }

    func derivedLocalTunnelSettings(
        defaultTunnelAddress6: String,
        defaultTunnelPrefix6: Int,
        defaultIncludedRoutes: [String],
        defaultExcludedRoutes: [String],
        defaultIncludedRoutes6: [String],
        defaultExcludedRoutes6: [String],
        defaultDNS: [String],
        fallbackMTU: Int
    ) -> ObstacleBridgeDerivedTunnelSettings? {
        for env in listenerHookEnvBlocks() {
            guard let tunAddr = env["TUN_ADDR"] as? String,
                  let (addr, prefix) = Self.parseCIDR(tunAddr, maxPrefix: 32)
            else {
                continue
            }
            let tunnelAddr6 = (env["TUN_ADDR6"] as? String).flatMap { Self.parseCIDR($0, maxPrefix: 128) }
            return ObstacleBridgeDerivedTunnelSettings(
                tunnelAddress: addr,
                tunnelPrefix: prefix,
                includedRoutes: defaultIncludedRoutes,
                excludedRoutes: defaultExcludedRoutes,
                tunnelAddress6: tunnelAddr6?.0 ?? defaultTunnelAddress6,
                tunnelPrefix6: tunnelAddr6?.1 ?? defaultTunnelPrefix6,
                includedRoutes6: tunnelAddr6 == nil ? [] : defaultIncludedRoutes6,
                excludedRoutes6: tunnelAddr6 == nil ? [] : defaultExcludedRoutes6,
                dnsServers: defaultDNS,
                mtu: mtu(fallback: fallbackMTU)
            )
        }
        return nil
    }

    func derivedRemoteTunnelSettings(
        defaultTunnelPrefix: Int,
        defaultTunnelPrefix6: Int,
        defaultIncludedRoutes: [String],
        defaultExcludedRoutes: [String],
        defaultIncludedRoutes6: [String],
        defaultExcludedRoutes6: [String],
        defaultDNS: [String],
        fallbackMTU: Int
    ) -> ObstacleBridgeDerivedTunnelSettings? {
        for env in listenerHookEnvBlocks() {
            guard let peerAddr = env["PEER_ADDR"] as? String,
                  !peerAddr.isEmpty
            else {
                continue
            }
            let prefix = Self.parseCIDR(env["TUN_ADDR"] as? String ?? "", maxPrefix: 32)?.1
                ?? Self.parseCIDR(env["TUN_SUBNET"] as? String ?? "", maxPrefix: 32)?.1
                ?? defaultTunnelPrefix
            let peerAddr6 = env["PEER_ADDR6"] as? String ?? ""
            let prefix6 = Self.parseCIDR(env["TUN_ADDR6"] as? String ?? "", maxPrefix: 128)?.1
                ?? Self.parseCIDR(env["TUN_SUBNET6"] as? String ?? "", maxPrefix: 128)?.1
                ?? defaultTunnelPrefix6
            return ObstacleBridgeDerivedTunnelSettings(
                tunnelAddress: peerAddr,
                tunnelPrefix: prefix,
                includedRoutes: defaultIncludedRoutes,
                excludedRoutes: defaultExcludedRoutes,
                tunnelAddress6: peerAddr6,
                tunnelPrefix6: prefix6,
                includedRoutes6: peerAddr6.isEmpty ? [] : defaultIncludedRoutes6,
                excludedRoutes6: peerAddr6.isEmpty ? [] : defaultExcludedRoutes6,
                dnsServers: defaultDNS,
                mtu: mtu(fallback: fallbackMTU)
            )
        }
        return nil
    }

    func toChannelMuxServiceSpec() -> ObstacleBridgeChannelMuxCodec.ServiceSpec {
        ObstacleBridgeChannelMuxCodec.ServiceSpec(
            svcID: svcID,
            lProto: listenProtocol,
            lBind: listenBind,
            lPort: listenPort,
            rProto: targetProtocol,
            rHost: targetHost,
            rPort: targetPort,
            name: name,
            lifecycleHooks: lifecycleHooks,
            options: options
        )
    }

    private static func foundationObject(from object: [String: ObstacleBridgeChannelMuxCodec.JSONValue]) -> [String: Any] {
        var result: [String: Any] = [:]
        for (key, value) in object {
            result[key] = foundationValue(from: value)
        }
        return result
    }

    private static func foundationValue(from value: ObstacleBridgeChannelMuxCodec.JSONValue) -> Any {
        switch value {
        case .object(let object):
            return foundationObject(from: object)
        case .array(let array):
            return array.map(foundationValue(from:))
        case .string(let string):
            return string
        case .integer(let integer):
            return Int(integer)
        case .double(let double):
            return double
        case .bool(let bool):
            return bool
        case .null:
            return NSNull()
        }
    }

    private static func parseCIDR(_ text: String, maxPrefix: Int) -> (String, Int)? {
        let parts = text.split(separator: "/", maxSplits: 1).map(String.init)
        guard parts.count == 2,
              let prefix = Int(parts[1]),
              prefix >= 0,
              prefix <= maxPrefix
        else {
            return nil
        }
        return (parts[0], prefix)
    }
}

struct ObstacleBridgeSwiftUDPPeerConfig {
    let runtimeMode: String
    let bindHost: String
    let bindPort: Int
    let peerHost: String
    let peerPort: Int
    let mtu: Int
    let tunIfname: String
}

struct ObstacleBridgeOverlayBootstrapSettings {
    let overlayTransport: String
    let transports: [String]
    let transport: String
    let layersTopDown: [String]
    let compressWrapped: Bool
    let compressConfiguredEnabled: Bool
    let peerHost: String?
    let secureLinkMode: String?
    let secureLinkEnabled: Bool
    let secureLinkPSK: String
    let compressEnabled: Bool
    let compressAlgo: String

    init(payload: [String: Any]) throws {
        let overlayTransport = ObstacleBridgeRuntimeConfig.stringValue(from: payload["overlay_transport"]) ?? "myudp"
        let configuredPeers: [String: Bool] = [
            "myudp": ObstacleBridgeRuntimeConfig.stringValue(from: payload["udp_peer"]) != nil,
            "tcp": ObstacleBridgeRuntimeConfig.stringValue(from: payload["tcp_peer"]) != nil,
            "quic": ObstacleBridgeRuntimeConfig.stringValue(from: payload["quic_peer"]) != nil,
            "ws": ObstacleBridgeRuntimeConfig.stringValue(from: payload["ws_peer"]) != nil,
        ]
        let transports = try ObstacleBridgeOverlayStackPlanner.parseOverlayTransports(
            raw: overlayTransport,
            hasConfiguredPeerByTransport: configuredPeers
        )
        let selectedTransport = transports.first ?? "myudp"
        let peerHost = ObstacleBridgeRuntimeConfig.peerHost(for: selectedTransport, payload: payload)
        let secureLinkEnabled = ObstacleBridgeRuntimeConfig.boolValue(from: payload["secure_link"]) ?? false
        let secureLinkModeRaw = ObstacleBridgeRuntimeConfig.stringValue(from: payload["secure_link_mode"]) ?? "off"
        let secureLinkPSK = ObstacleBridgeRuntimeConfig.stringValue(from: payload["secure_link_psk"]) ?? ""
        let compressEnabled = ObstacleBridgeRuntimeConfig.boolValue(from: payload["compress_layer"]) ?? false
        let compressAlgo = ObstacleBridgeRuntimeConfig.stringValue(from: payload["compress_layer_algo"]) ?? "zlib"
        let plan = try ObstacleBridgeOverlayStackPlanner.planTransport(
            transport: selectedTransport,
            peerHost: peerHost,
            secureLinkEnabled: secureLinkEnabled,
            secureLinkModeRaw: secureLinkModeRaw,
            secureLinkPSK: secureLinkPSK,
            compressLayerEnabled: compressEnabled,
            compressLayerAlgoRaw: compressAlgo
        )

        self.overlayTransport = overlayTransport
        self.transports = transports
        self.transport = plan.transport
        self.layersTopDown = plan.layersTopDown
        self.compressWrapped = plan.compressWrapped
        self.compressConfiguredEnabled = plan.compressConfiguredEnabled
        self.peerHost = plan.peerHost
        self.secureLinkMode = plan.secureLinkMode
        self.secureLinkEnabled = secureLinkEnabled
        self.secureLinkPSK = secureLinkPSK
        self.compressEnabled = compressEnabled
        self.compressAlgo = compressAlgo
    }

    func summary(runtimeConfigGrouped: Bool? = nil) -> [String: Any] {
        var summary: [String: Any] = [
            "status": "prepared",
            "transport": transport,
            "transports": transports,
            "layers_top_down": layersTopDown,
            "compress_wrapped": compressWrapped,
            "compress_configured_enabled": compressConfiguredEnabled,
        ]
        if let peerHost {
            summary["peer_host"] = peerHost
        }
        if let secureLinkMode {
            summary["secure_link_mode"] = secureLinkMode
        }
        if let runtimeConfigGrouped {
            summary["runtime_config_grouped"] = runtimeConfigGrouped
        }
        return summary
    }
}

enum ObstacleBridgeRuntimeConfig {
    private static let knownGroupedSections = [
        "runner",
        "udp_session",
        "tcp_session",
        "ws_session",
        "secure_link",
        "compress_layer",
        "admin_web",
        "debug_logging",
    ]

    static func flatten(_ payload: [String: Any]) -> [String: Any] {
        var merged: [String: Any] = [:]
        for section in knownGroupedSections {
            if let block = payload[section] as? [String: Any] {
                for (key, value) in block {
                    merged[key] = value
                }
            }
        }
        if let channelMux = payload["channel_mux"] as? [String: Any] {
            for (key, value) in channelMux {
                merged[key] = value
            }
            merged["channel_mux"] = channelMux
        }
        if let connector = payload["iOS_TUN_connector"] as? [String: Any] {
            merged["iOS_TUN_connector"] = connector
        }
        for (key, value) in payload where !(value is [String: Any]) {
            merged[key] = value
        }
        return merged
    }

    static func looksGrouped(_ payload: [String: Any]) -> Bool {
        payload.values.contains { $0 is [String: Any] }
    }

    static func tunnelRoutingOverride(from payload: [String: Any]) -> ObstacleBridgeTunnelRoutingOverride? {
        guard let override = payload["TUN_routing"] as? [String: Any] else {
            return nil
        }
        return ObstacleBridgeTunnelRoutingOverride(
            tunnelAddress: stringValue(from: override["tunnel_address"]),
            tunnelPrefix: intValue(from: override["tunnel_prefix"]),
            includedRoutes: override["included_routes"] as? [String],
            excludedRoutes: override["excluded_routes"] as? [String],
            tunnelAddress6: stringValue(from: override["tunnel_address6"]),
            tunnelPrefix6: intValue(from: override["tunnel_prefix6"]),
            includedRoutes6: override["included_routes6"] as? [String],
            excludedRoutes6: override["excluded_routes6"] as? [String],
            dnsServers: override["dns_servers"] as? [String],
            mtu: intValue(from: override["mtu"])
        )
    }

    static func localTunServiceSpec(ifname: String, mtu: Int, svcID: Int = 0, name: String? = nil) -> ObstacleBridgeChannelMuxCodec.ServiceSpec {
        ObstacleBridgeRuntimeServiceSpec(
            svcID: svcID,
            name: name,
            listenProtocol: "tun",
            listenBind: ifname,
            listenPort: mtu,
            targetProtocol: "tun",
            targetHost: ifname,
            targetPort: mtu,
            lifecycleHooks: nil,
            options: nil
        ).toChannelMuxServiceSpec()
    }

    static func intValue(from value: Any?) -> Int? {
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

    static func doubleValue(from value: Any?) -> Double? {
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

    static func boolValue(from value: Any?) -> Bool? {
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

    static func stringValue(from value: Any?) -> String? {
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

    static func peerHost(for transport: String, payload: [String: Any]) -> String? {
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

    static func packetflowConnectorMode(from payload: [String: Any]) -> String? {
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

    static func swiftUDPPeerConfig(from payload: [String: Any], defaultMTU: Int) -> ObstacleBridgeSwiftUDPPeerConfig? {
        guard let experiment = packetflowConnectorSection(from: payload) else {
            return nil
        }
        let connectorMode = (experiment["packetflow_connector"] as? String ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        guard connectorMode == "swift_simple_udp_peer" || connectorMode == "swift_udp" || connectorMode == "swift_udp_peer" else {
            return nil
        }
        guard let peerHost = stringValue(from: experiment["peer_host"]) else {
            return nil
        }
        let peerPort = intValue(from: experiment["peer_port"]) ?? 0
        guard peerPort > 0 else {
            return nil
        }
        let bindHost = stringValue(from: experiment["bind_host"]) ?? "0.0.0.0"
        let bindPort = intValue(from: experiment["bind_port"]) ?? peerPort
        let mtu = intValue(from: experiment["mtu"]) ?? defaultMTU
        let tunIfname = stringValue(from: experiment["ifname"]) ?? "ios-utun"
        return ObstacleBridgeSwiftUDPPeerConfig(
            runtimeMode: connectorMode == "swift_udp_peer" ? "swift_udp" : connectorMode,
            bindHost: bindHost,
            bindPort: bindPort > 0 ? bindPort : peerPort,
            peerHost: peerHost,
            peerPort: peerPort,
            mtu: mtu,
            tunIfname: tunIfname
        )
    }

    static func ownServerSpecs(from payload: [String: Any], preserveInputIndices: Bool = false) -> [ObstacleBridgeRuntimeServiceSpec] {
        serviceSpecs(from: payload, key: "own_servers", preserveInputIndices: preserveInputIndices)
    }

    static func remoteServerSpecs(from payload: [String: Any], preserveInputIndices: Bool = false) -> [ObstacleBridgeRuntimeServiceSpec] {
        serviceSpecs(from: payload, key: "remote_servers", preserveInputIndices: preserveInputIndices)
    }

    static func localTCPServiceSpecs(from payload: [String: Any]) -> [ObstacleBridgeChannelMuxCodec.ServiceSpec] {
        ownServerSpecs(from: payload, preserveInputIndices: true)
            .filter { $0.listenProtocol == "tcp" && $0.targetProtocol == "tcp" }
            .map { $0.toChannelMuxServiceSpec() }
    }

    private static func serviceSpecs(
        from payload: [String: Any],
        key: String,
        preserveInputIndices: Bool
    ) -> [ObstacleBridgeRuntimeServiceSpec] {
        guard let rawSpecs = serviceArray(from: payload, key: key) else {
            return []
        }
        var specs: [ObstacleBridgeRuntimeServiceSpec] = []
        var nextDenseID = 1
        for (index, item) in rawSpecs.enumerated() {
            let svcID = preserveInputIndices ? (index + 1) : nextDenseID
            guard let spec = parseOwnServerSpec(item, svcID: svcID) else {
                continue
            }
            specs.append(spec)
            if !preserveInputIndices {
                nextDenseID += 1
            }
        }
        return specs
    }

    private static func packetflowConnectorSection(from payload: [String: Any]) -> [String: Any]? {
        payload["iOS_TUN_connector"] as? [String: Any]
    }

    private static func serviceArray(from payload: [String: Any], key: String) -> [Any]? {
        if let channelMux = payload["channel_mux"] as? [String: Any],
           let specs = channelMux[key] as? [Any] {
            return specs
        }
        return payload[key] as? [Any]
    }

    private static func parseOwnServerSpec(_ item: Any, svcID: Int) -> ObstacleBridgeRuntimeServiceSpec? {
        guard let dictionary = item as? [String: Any],
              let listen = dictionary["listen"] as? [String: Any],
              let target = dictionary["target"] as? [String: Any],
              let listenProtocol = stringValue(from: listen["protocol"]),
              let targetProtocol = stringValue(from: target["protocol"]) else {
            return nil
        }
        guard listenProtocol == "tcp" || listenProtocol == "udp" || listenProtocol == "tun" else {
            return nil
        }
        guard targetProtocol == "tcp" || targetProtocol == "udp" || targetProtocol == "tun" else {
            return nil
        }

        let listenBind: String?
        let listenPort: Int?
        if listenProtocol == "tun" {
            listenBind = stringValue(from: listen["ifname"])
            listenPort = intValue(from: listen["mtu"])
        } else {
            listenBind = stringValue(from: listen["bind"])
            listenPort = intValue(from: listen["port"])
        }

        let targetHost: String?
        let targetPort: Int?
        if targetProtocol == "tun" {
            targetHost = stringValue(from: target["ifname"])
            targetPort = intValue(from: target["mtu"])
        } else {
            targetHost = stringValue(from: target["host"])
            targetPort = intValue(from: target["port"])
        }

        guard let listenBind,
              let listenPort,
              let targetHost,
              let targetPort else {
            return nil
        }
        return ObstacleBridgeRuntimeServiceSpec(
            svcID: svcID,
            name: stringValue(from: dictionary["name"]),
            listenProtocol: listenProtocol,
            listenBind: listenBind,
            listenPort: listenPort,
            targetProtocol: targetProtocol,
            targetHost: targetHost,
            targetPort: targetPort,
            lifecycleHooks: jsonDictionary(from: dictionary["lifecycle_hooks"]),
            options: jsonDictionary(from: dictionary["options"])
        )
    }

    private static func jsonDictionary(from value: Any?) -> [String: ObstacleBridgeChannelMuxCodec.JSONValue]? {
        guard let value,
              let json = ObstacleBridgeChannelMuxCodec.jsonValue(from: value),
              case .object(let object) = json
        else {
            return nil
        }
        return object
    }
}