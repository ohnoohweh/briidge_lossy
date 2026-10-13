import Foundation
import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgeTunPingTests {
    @Test func buildsBoundedIPv4ProbePacket() throws {
        let payload = ObstacleBridgeTunPing.probePayload(
            probeKind: ObstacleBridgeTunPing.probeKindPeer,
            nonce: Data(repeating: 7, count: 16),
            sentMonotonicNS: 42
        )
        let packet = try #require(ObstacleBridgeTunPing.buildIPv4EchoRequest(
            sourceIP: "192.0.2.1",
            destinationIP: "198.51.100.2",
            identifier: 9,
            sequence: 3,
            payload: payload
        ))

        #expect(packet[0] == 0x45)
        #expect(packet[20] == 8)
        #expect(packet.count == 20 + 8 + payload.count)
    }
}
