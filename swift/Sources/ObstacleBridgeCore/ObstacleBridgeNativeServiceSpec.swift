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
