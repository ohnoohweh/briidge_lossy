import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgeOverlayConnectionPolicyTests {
    @Test func projectsAndUpdatesConnectionState() {
        let spec = ObstacleBridgeChannelMuxCodec.ServiceSpec(
            svcID: 7, lProto: "tcp", lBind: "127.0.0.1", lPort: 0,
            rProto: "tcp", rHost: "example.test", rPort: 443, name: "web"
        )
        var states = [7: ObstacleBridgeOverlayConnectionSupport.makeState(
            proto: "tcp", role: "client", chanID: 7, spec: spec, serviceName: "web",
            state: "connecting", localHost: nil, localPort: nil
        )]
        ObstacleBridgeOverlayConnectionSupport.updateConnectedState(
            states: &states, proto: "tcp", chanID: 7, localHost: "10.0.0.2", localPort: 50123
        )
        ObstacleBridgeOverlayConnectionSupport.recordTraffic(
            states: &states, proto: "tcp", chanID: 7, direction: "inbound", bytes: 12
        )
        let row = ObstacleBridgeOverlayConnectionSupport.connectionRows(from: states)[0]
        #expect(row["state"] as? String == "connected")
        #expect(row["chan_id"] as? Int == 7)
        #expect((row["stats"] as? [String: Int])?["rx_bytes"] == 12)
        #expect((row["local"] as? [String: Any])?["host"] as? String == "10.0.0.2")
    }
}
