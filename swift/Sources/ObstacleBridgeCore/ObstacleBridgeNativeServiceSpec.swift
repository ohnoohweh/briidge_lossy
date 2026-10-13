import Foundation

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
