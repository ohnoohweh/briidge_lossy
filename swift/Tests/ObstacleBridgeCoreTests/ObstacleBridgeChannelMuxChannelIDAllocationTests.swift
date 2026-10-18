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
}
