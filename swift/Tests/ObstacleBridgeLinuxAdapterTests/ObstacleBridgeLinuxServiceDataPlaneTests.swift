import Foundation
import Testing
@testable import ObstacleBridgeLinuxAdapters
@testable import ObstacleBridgePortable

struct ObstacleBridgeLinuxServiceDataPlaneTests {
    @Test func localTcpConnectionProducesOpenDataAndClose() throws {
        let plane = ObstacleBridgeLinuxServiceDataPlane(instanceID: 9, connectionSequence: 4)
        let id = try plane.acceptLocalService(service)
        try plane.localData(channelID: id, payload: Data("hello".utf8))
        try plane.localEOF(channelID: id)
        let frames = plane.drainOutbound()
        #expect(frames.map(\.messageType) == [.open, .data, .close])
        #expect(frames[0].channelID == id)
        #expect(Data(frames[0].body.dropFirst(2).prefix(8)) == Data(repeating: 0, count: 7) + Data([9]))
        #expect(Data(frames[0].body.dropFirst(10).prefix(4)) == Data([0, 0, 0, 4]))
        #expect(frames[1].body == Data("hello".utf8))

        let peer = ObstacleBridgeLinuxServiceDataPlane()
        let event = try peer.receive(frames[0])
        #expect(event == .connectRequested(channelID: id, spec: service))
        #expect(try peer.receive(frames[1]) == .deliverLocal(channelID: id, payload: Data("hello".utf8)))
        #expect(try peer.receive(frames[2]) == .closeLocal(channelID: id))
    }

    @Test func boundedQueueCountsBackpressureDrop() throws {
        let plane = ObstacleBridgeLinuxServiceDataPlane(maximumQueuedFrames: 1)
        _ = try plane.acceptLocalService(service)
        #expect(throws: ObstacleBridgeLinuxServiceDataPlaneError.queueFull) {
            try plane.acceptLocalService(service)
        }
        let snapshot = plane.snapshot()
        #expect(snapshot.queuedFrames == 1)
        #expect(snapshot.droppedFrames == 1)
    }

    private let service = ObstacleBridgeLinuxServiceSpec(serviceID: 1, name: "echo", listenProtocol: .tcp, listenHost: "127.0.0.1", listenPort: 7001, targetProtocol: .tcp, targetHost: "127.0.0.1", targetPort: 7002)
}
