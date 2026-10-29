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
}
