import Foundation

struct ObstacleBridgeNativeServiceSpec {
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
