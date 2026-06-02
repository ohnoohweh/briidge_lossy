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

    init(sharedSpec: ObstacleBridgeRuntimeServiceSpec) {
        self.svcID = sharedSpec.svcID
        self.name = sharedSpec.name
        self.listenProtocol = sharedSpec.listenProtocol
        self.listenBind = sharedSpec.listenBind
        self.listenPort = sharedSpec.listenPort
        self.targetProtocol = sharedSpec.targetProtocol
        self.targetHost = sharedSpec.targetHost
        self.targetPort = sharedSpec.targetPort
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
            lifecycleHooks: nil,
            options: nil
        )
    }
}
