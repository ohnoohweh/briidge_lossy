import Foundation
import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgeTunPingTests {
    @Test func protocolV1FramesAndControlsRemainPythonCompatible() throws {
        let control = try ObstacleBridgeTunHelperProtocolV1.control(operation: "HELLO", payload: ["token": "test-token"])
        let frame = try ObstacleBridgeTunHelperProtocolV1.frame(kind: .controlRequest, body: control)
        let header = try ObstacleBridgeTunHelperProtocolV1.header(Data(frame.prefix(ObstacleBridgeTunHelperProtocolV1.headerBytes)))
        #expect(header.kind == .controlRequest)
        #expect(header.bodyLength == control.count)
        let decoded = try ObstacleBridgeTunHelperProtocolV1.decodeControl(Data(frame.dropFirst(ObstacleBridgeTunHelperProtocolV1.headerBytes)))
        #expect(decoded.operation == "HELLO")
        #expect(decoded.payload["token"] as? String == "test-token")
    }
    @Test func protocolV1EnforcesPythonCompatibleFrameLimit() throws {
        let limit = ObstacleBridgeTunHelperProtocolV1.maximumFrameBytes
        let frame = try ObstacleBridgeTunHelperProtocolV1.frame(kind: .packetToHelper, body: Data(repeating: 1, count: limit))
        let header = try ObstacleBridgeTunHelperProtocolV1.header(Data(frame.prefix(ObstacleBridgeTunHelperProtocolV1.headerBytes)))
        #expect(header.bodyLength == limit)
        #expect(throws: ObstacleBridgeTunHelperProtocolV1.Error.frameTooLarge) {
            try ObstacleBridgeTunHelperProtocolV1.frame(kind: .packetToHelper, body: Data(repeating: 1, count: limit + 1))
        }
        #expect(throws: ObstacleBridgeTunHelperProtocolV1.Error.frameTooLarge) {
            try ObstacleBridgeTunHelperProtocolV1.header(Data([4, 0, 0x10, 0, 1]))
        }
    }
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

    @Test func buildsAndParsesIPv6ProbeWithoutPlatformSocketTypes() throws {
        var packet = try #require(ObstacleBridgeTunPing.buildIPv6EchoRequest(
            sourceIP: "2001:db8::1",
            destinationIP: "::1",
            identifier: 7,
            sequence: 9,
            payload: Data([1, 2, 3])
        ))
        packet[40] = 129
        let reply = try #require(ObstacleBridgeTunPing.parseEchoReply(packet))
        #expect(reply.sourceIP == "2001:db8::1")
        #expect(reply.destinationIP == "::1")
        #expect(reply.identifier == 7)
        #expect(reply.sequence == 9)
        #expect(reply.payload == Data([1, 2, 3]))
        switch reply.family {
        case .ipv6:
            break
        case .ipv4:
            Issue.record("expected IPv6 reply family")
        }
    }
}
