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
    let tunnelGateway: String?
    let includedRoutes: [String]?
    let excludedRoutes: [String]?
    let tunnelAddress6: String?
    let tunnelPrefix6: Int?
    let tunnelGateway6: String?
    let includedRoutes6: [String]?
    let excludedRoutes6: [String]?
    let dnsServers: [String]?
    let mtu: Int?
    let enabledOnStartup: Bool?
    let enableTCPMSS: Bool?
    let enableTunTcpdump: Bool?
    let tunTcpdumpPcapPath: String?
    let sharedTunDisableOutgoingNormalization: Bool?
    let sharedTunDisableInflowFilter: Bool?
    let sharedTunDisableOutflowFilter: Bool?
    let sharedTunDisableScopedThrottle: Bool?
}

struct ObstacleBridgeSwiftUDPPeerConfig {
    let runtimeMode: String
    let bindHost: String
    let overlayBindHost: String
    let bindPort: Int
    let peerHost: String
    let peerPort: Int
    let peerResolveFamily: String
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

    init(
        overlayTransport: String,
        configuredPeers: [String: Bool],
        peerHost: String?,
        secureLinkEnabled: Bool,
        secureLinkModeRaw: String,
        secureLinkPSK: String,
        compressEnabled: Bool,
        compressAlgo: String
    ) throws {
        let transports = try ObstacleBridgeOverlayStackPlanner.parseOverlayTransports(
            raw: overlayTransport,
            hasConfiguredPeerByTransport: configuredPeers
        )
        let plan = try ObstacleBridgeOverlayStackPlanner.planTransport(
            transport: transports.first ?? "myudp",
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
            "status": "prepared", "transport": transport, "transports": transports,
            "layers_top_down": layersTopDown, "compress_wrapped": compressWrapped,
            "compress_configured_enabled": compressConfiguredEnabled,
        ]
        if let peerHost { summary["peer_host"] = peerHost }
        if let secureLinkMode { summary["secure_link_mode"] = secureLinkMode }
        if let runtimeConfigGrouped { summary["runtime_config_grouped"] = runtimeConfigGrouped }
        return summary
    }
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

    func nativeServiceSpec() -> ObstacleBridgeNativeServiceSpec {
        ObstacleBridgeNativeServiceSpec(
            channelMuxSpec: .init(
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
        )
    }

    var listenIfname: String? { listenProtocol == "tun" ? listenBind : nil }
    var targetIfname: String? { targetProtocol == "tun" ? targetHost : nil }

    func mtu(fallback: Int) -> Int {
        if listenProtocol == "tun" { return listenPort }
        if targetProtocol == "tun" { return targetPort }
        return fallback
    }

    func listenerHookEnvBlocks() -> [[String: Any]] {
        guard let lifecycleHooks,
              case .object(let listenerContainer)? = lifecycleHooks["listener"]
        else { return [] }
        var out: [[String: Any]] = []
        for event in ["on_created", "on_channel_connected", "on_stopped"] {
            guard case .object(let command)? = listenerContainer[event],
                  case .object(let env)? = command["env"]
            else { continue }
            out.append(Self.foundationObject(env))
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
            else { continue }
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

    func toChannelMuxServiceSpec() -> ObstacleBridgeChannelMuxCodec.ServiceSpec {
        ObstacleBridgeChannelMuxCodec.ServiceSpec(
            svcID: svcID, lProto: listenProtocol, lBind: listenBind, lPort: listenPort,
            rProto: targetProtocol, rHost: targetHost, rPort: targetPort, name: name,
            lifecycleHooks: lifecycleHooks, options: options
        )
    }

    private static func foundationObject(_ object: [String: ObstacleBridgeChannelMuxCodec.JSONValue]) -> [String: Any] {
        Dictionary(uniqueKeysWithValues: object.map { ($0.key, foundationValue($0.value)) })
    }

    private static func foundationValue(_ value: ObstacleBridgeChannelMuxCodec.JSONValue) -> Any {
        switch value {
        case .object(let object): return foundationObject(object)
        case .array(let array): return array.map(foundationValue)
        case .string(let string): return string
        case .integer(let integer): return Int(integer)
        case .double(let double): return double
        case .bool(let bool): return bool
        case .null: return NSNull()
        }
    }

    private static func parseCIDR(_ text: String, maxPrefix: Int) -> (String, Int)? {
        let parts = text.split(separator: "/", maxSplits: 1).map(String.init)
        guard parts.count == 2, let prefix = Int(parts[1]), prefix >= 0, prefix <= maxPrefix else { return nil }
        return (parts[0], prefix)
    }
}

public struct ObstacleBridgeNativeServiceSpec {
    public let svcID: Int
    public let name: String?
    public let listenProtocol: String
    public let listenBind: String
    public let listenPort: Int
    public let targetProtocol: String
    public let targetHost: String
    public let targetPort: Int
    let lifecycleHooks: [String: ObstacleBridgeChannelMuxCodec.JSONValue]?
    let options: [String: ObstacleBridgeChannelMuxCodec.JSONValue]?

    public init(
        svcID: Int,
        name: String?,
        listenProtocol: String,
        listenBind: String,
        listenPort: Int,
        targetProtocol: String,
        targetHost: String,
        targetPort: Int
    ) {
        self.svcID = svcID
        self.name = name
        self.listenProtocol = listenProtocol
        self.listenBind = listenBind
        self.listenPort = listenPort
        self.targetProtocol = targetProtocol
        self.targetHost = targetHost
        self.targetPort = targetPort
        self.lifecycleHooks = nil
        self.options = nil
    }

    init(channelMuxSpec: ObstacleBridgeChannelMuxCodec.ServiceSpec) {
        self.svcID = channelMuxSpec.svcID
        self.name = channelMuxSpec.name
        self.listenProtocol = channelMuxSpec.lProto
        self.listenBind = channelMuxSpec.lBind
        self.listenPort = channelMuxSpec.lPort
        self.targetProtocol = channelMuxSpec.rProto
        self.targetHost = channelMuxSpec.rHost
        self.targetPort = channelMuxSpec.rPort
        self.lifecycleHooks = channelMuxSpec.lifecycleHooks
        self.options = channelMuxSpec.options
    }

    init(coreSpec: ObstacleBridgeServiceSpec) {
        self.svcID = Int(coreSpec.serviceID)
        self.name = coreSpec.name
        self.listenProtocol = Self.protocolName(coreSpec.listenProtocol)
        self.listenBind = coreSpec.listenHost
        self.listenPort = Int(coreSpec.listenPort)
        self.targetProtocol = Self.protocolName(coreSpec.targetProtocol)
        self.targetHost = coreSpec.targetHost
        self.targetPort = Int(coreSpec.targetPort)
        self.lifecycleHooks = nil
        self.options = nil
    }

    private static func protocolName(_ value: UInt8) -> String {
        switch ObstacleBridgeChannelMuxSessionProtocol(rawValue: value) {
        case .udp: return "udp"
        case .tcp: return "tcp"
        case .tun: return "tun"
        case nil: return ""
        }
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
}
