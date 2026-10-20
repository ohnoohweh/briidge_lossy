import Foundation
import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgeChannelMuxChannelIDAllocationTests {
    @Test func partitionsPeerAndListenerIDsAcrossIndependentOwners() throws {
        #expect(ObstacleBridgeChannelMuxChannelIDAllocation.peerClient() == .init(role: .peerClient))
        #expect(ObstacleBridgeChannelMuxChannelIDAllocation.listener() == .init(role: .listener))

        let clientFirst = ObstacleBridgeChannelMuxChannelIDAllocation.peerClient(ownerIndex: 0, ownerCount: 3)
        let clientThird = ObstacleBridgeChannelMuxChannelIDAllocation.peerClient(ownerIndex: 2, ownerCount: 3)
        let listenerSecond = ObstacleBridgeChannelMuxChannelIDAllocation.listener(ownerIndex: 1, ownerCount: 3)
        #expect(clientFirst.initialChannelID == 1)
        #expect(clientThird.initialChannelID == 5)
        #expect(listenerSecond.initialChannelID == 4)
        #expect(clientFirst.channelIDStride == 6)
        #expect(listenerSecond.channelIDStride == 6)

        let runtime = ObstacleBridgeChannelMuxTcpRuntime(allocation: clientThird)
        let service = ObstacleBridgeNativeServiceSpec(svcID: 7, name: "test", listenProtocol: "tcp", listenBind: "127.0.0.1", listenPort: 3128, targetProtocol: "tcp", targetHost: "127.0.0.1", targetPort: 13881)
        let first = try #require(try runtime.acceptLocalServerConnection(service: service, overlayConnected: true, acceptingEnabled: true))
        let second = try #require(try runtime.acceptLocalServerConnection(service: service, overlayConnected: true, acceptingEnabled: true))
        #expect(first.chanID == 5)
        #expect(second.chanID == 11)
    }

    @Test func splitsMaximumMyUDPRecordAtTheChannelMuxWireBoundary() throws {
        let runtime = ObstacleBridgeChannelMuxTcpRuntime(sessionMaxAppPayload: 65_535)
        let service = ObstacleBridgeNativeServiceSpec(
            svcID: 1, name: "record-boundary", listenProtocol: "tcp",
            listenBind: "127.0.0.1", listenPort: 3128, targetProtocol: "tcp",
            targetHost: "127.0.0.1", targetPort: 13881
        )
        let accepted = try #require(try runtime.acceptLocalServerConnection(
            service: service, overlayConnected: true, acceptingEnabled: true
        ))
        let payload = Data(repeating: 0x57, count: 65_535)
        let sent = try runtime.handleLocalServerData(
            chanID: accepted.chanID, payload: payload, overlayConnected: true
        )

        #expect(sent.frames.count == 2)
        let frames = try sent.frames.map { try ObstacleBridgeChannelMuxCodec.decode($0) }
        #expect(frames.allSatisfy { $0.body.count + ObstacleBridgeChannelMuxCodec.muxHeaderSize <= 65_535 })
        #expect(Data(frames.flatMap(\.body)) == payload)
        #expect(frames.map(\.counter) == [2, 3])
    }
}
