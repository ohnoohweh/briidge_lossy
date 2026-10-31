import Foundation
import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgeOverlayConnectionPolicyTests {
    @Test func normalizesSecureLinkLifecycleFieldsForEveryPeerProducer() {
        let row = ObstacleBridgeAdminSnapshotSupport.peerEnvelope(
            id: "peer-1",
            transport: "myudp",
            state: "connected",
            connected: true,
            appReady: true,
            connectedSinceUnixTS: 1_700_000_000,
            secureLink: [
                "state": "authenticated",
                "authenticated": true,
                "authenticated_generations_total": 3,
            ]
        )
        let secureLink = try! #require(row["secure_link"] as? [String: Any])
        #expect(secureLink["last_event"] as? String == "authenticated")
        #expect((secureLink["last_event_unix_ts"] as? NSNumber)?.doubleValue == 1_700_000_000)
        #expect((secureLink["last_authenticated_unix_ts"] as? NSNumber)?.doubleValue == 1_700_000_000)
        #expect(secureLink["authenticated_sessions_total"] as? Int == 3)
        #expect(secureLink["last_rekey_trigger"] as? String == "none")
    }

    @Test func exposesAnIdleOpenTunAsAListeningAdminRow() {
        let runtime = ObstacleBridgeChannelMuxTunRuntime(instanceID: 1, connectionSeq: 1)
        let rows = ObstacleBridgeOverlayChannelCore.tunRows(
            activeTunChanIDs: [],
            tunStats: ["rx_bytes": 0, "tx_bytes": 0],
            tunRuntime: runtime,
            tunServiceSpec: nil,
            tunIfname: "obtun0",
            tunMTU: 1600
        )
        #expect(rows.count == 1)
        #expect(rows[0]["state"] as? String == "listening")
        #expect(rows[0]["chan_id"] is NSNull)
        let local = try! #require(rows[0]["local"] as? [String: Any])
        #expect(local["ifname"] as? String == "obtun0")
        #expect(local["mtu"] as? Int == 1600)
    }

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
