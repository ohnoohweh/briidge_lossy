import Foundation
import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgeChannelMuxEgressSequencerTests {
    @Test func allMuxMessageTypesSharePersistentSourceTurns() {
        let scheduler = ObstacleBridgeChannelMuxEgressSequencer<String>()
        let tcp = ObstacleBridgeChannelMuxEgressSource(protocolType: 1, channelID: 7)
        let udp = ObstacleBridgeChannelMuxEgressSource(protocolType: 0, channelID: 9)
        let tun = ObstacleBridgeChannelMuxEgressSource(protocolType: 2, channelID: 11)

        scheduler.enqueue("tcp-open", from: tcp)
        scheduler.enqueue("tcp-data", from: tcp)
        scheduler.enqueue("tcp-close", from: tcp)
        scheduler.enqueue("udp-data", from: udp)
        scheduler.enqueue("udp-catalog", from: udp)
        scheduler.enqueue("tun-data", from: tun)
        scheduler.enqueue("tun-control", from: tun)

        var delivered: [String] = []
        while let next = scheduler.dequeueNext() { delivered.append(next) }
        #expect(delivered == ["tcp-open", "udp-data", "tun-data", "tcp-data", "udp-catalog", "tun-control", "tcp-close"])

        scheduler.enqueue("tcp-next", from: tcp)
        scheduler.enqueue("udp-next", from: udp)
        #expect(scheduler.dequeueNext() == "tcp-next")
        #expect(scheduler.dequeueNext() == "udp-next")
        #expect(scheduler.isEmpty)
    }

    @Test func frameSourceDoesNotDependOnMessageType() {
        let open = ObstacleBridgeChannelMuxFrame(channelID: 4, protocolType: .tcp, counter: 0, messageType: .open, body: Data())
        let close = ObstacleBridgeChannelMuxFrame(channelID: 4, protocolType: .tcp, counter: 2, messageType: .close, body: Data())
        #expect(ObstacleBridgeChannelMuxEgressSource(open) == ObstacleBridgeChannelMuxEgressSource(close))
    }

    @Test func concurrentEnqueueAndDrainProtectsNativeSetStorage() async {
        let scheduler = ObstacleBridgeChannelMuxEgressSequencer<Int>()
        await withTaskGroup(of: Void.self) { group in
            for sourceID in 0..<8 {
                group.addTask {
                    let source = ObstacleBridgeChannelMuxEgressSource(protocolType: 1, channelID: UInt16(sourceID + 1))
                    for value in 0..<200 {
                        scheduler.enqueue(sourceID * 1_000 + value, from: source)
                    }
                }
            }
        }
        var delivered: Set<Int> = []
        while let value = scheduler.dequeueNext() {
            delivered.insert(value)
        }
        #expect(delivered.count == 1_600)
        #expect(scheduler.isEmpty)
    }
}
