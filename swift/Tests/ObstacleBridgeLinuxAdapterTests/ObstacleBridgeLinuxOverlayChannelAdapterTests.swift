import Foundation
import Testing
@testable import ObstacleBridgeLinuxAdapters
@testable import ObstacleBridgeCore

private final class OverlayPacketDevice: ObstacleBridgeLinuxPacketDevice {
    var packets: [Data] = []
    var failWrites = false

    func writePacket(_ packet: Data) throws {
        if failWrites { throw CocoaError(.fileWriteUnknown) }
        packets.append(packet)
    }
}

private final class OverlayEvents {
    var sent: [[Data]] = []
    var diagnostics: [(String, [String: Any])] = []
}

struct ObstacleBridgeLinuxOverlayChannelAdapterTests {
    private func packet(source: [UInt8] = [10, 0, 0, 1], destination: [UInt8] = [10, 0, 0, 2]) -> Data {
        Data([0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0] + source + destination)
    }

    private func makeAdapter(
        device: OverlayPacketDevice? = OverlayPacketDevice(),
        delayMS: Double = 0,
        sharedTunPeers: [ObstacleBridgeOverlayChannelRuntime.SharedTunPeer] = [],
        events: OverlayEvents
    ) -> ObstacleBridgeLinuxOverlayChannelAdapter {
        ObstacleBridgeLinuxOverlayChannelAdapter(
            interfaceName: "obtun0", mtu: 1500, instanceID: 7, connectionSequence: 3,
            packetDevice: device,
            sharedTunPeers: sharedTunPeers,
            backpressureSnapshot: { .init(bufferedFrames: 0, transmitDelayEstMS: delayMS) },
            startupFrames: { [Data([0xca, 0xfe])] },
            sendMuxFrames: { events.sent.append($0) },
            diagnosticSink: { event, fields in events.diagnostics.append((event, fields)) }
        )
    }

    private func inboundOpen(channelID: UInt16 = 9) throws -> ObstacleBridgeChannelMuxFrame {
        let service = ObstacleBridgeServiceSpec(
            serviceID: 0, name: nil, listenProtocol: 2, listenHost: "peer-tun", listenPort: 1500,
            targetProtocol: 2, targetHost: "obtun0", targetPort: 1500
        )
        return .init(
            channelID: channelID, protocolType: .tun, counter: 0, messageType: .open,
            body: try ObstacleBridgeServiceCodec.encodeOpen(instanceID: 8, connectionSequence: 3, service: service)
        )
    }

    @Test func preReadyAndNoDeviceReadsFailClosed() {
        let events = OverlayEvents()
        let adapter = makeAdapter(events: events)
        adapter.receivedPacketFromDevice(packet())
        #expect(events.sent.isEmpty)
        #expect(events.diagnostics.contains { $0.0 == "tun_packet_dropped" && $0.1["reason"] as? String == "overlay_not_connected" })

        let noDevice = makeAdapter(device: nil, events: events)
        noDevice.overlayLifecycleChanged(ready: true)
        noDevice.receivedPacketFromDevice(packet())
        #expect(events.diagnostics.contains { $0.0 == "tun_packet_device_unavailable" })
    }

    @Test func catalogPrecedesFirstOpenAndEpochReplacementForcesNewOpen() throws {
        let events = OverlayEvents()
        let adapter = makeAdapter(events: events)
        adapter.overlayLifecycleChanged(ready: true)
        adapter.receivedPacketFromDevice(packet())
        let first = try #require(events.sent.first)
        #expect(first.first == Data([0xca, 0xfe]))
        let firstMux = try #require(first.dropFirst().compactMap { try? ObstacleBridgeChannelMuxCodec.decode($0) }.first)
        #expect(firstMux.messageType == .open)

        adapter.overlayLifecycleChanged(ready: true, epochChanged: true)
        adapter.receivedPacketFromDevice(packet())
        let second = try #require(events.sent.last)
        let secondMux = try #require(second.dropFirst().compactMap { try? ObstacleBridgeChannelMuxCodec.decode($0) }.first)
        #expect(secondMux.messageType == .open)
    }

    @Test func postMuxDelayDropsTunDataButRetainsCatalogAndOpen() throws {
        let events = OverlayEvents()
        let adapter = makeAdapter(delayMS: 5_000, events: events)
        adapter.overlayLifecycleChanged(ready: true)
        adapter.receivedPacketFromDevice(packet())
        let batch = try #require(events.sent.first)
        #expect(batch.first == Data([0xca, 0xfe]))
        let types = batch.dropFirst().compactMap { try? ObstacleBridgeChannelMuxCodec.decode($0).messageType }
        #expect(types == [.open])
        #expect(events.diagnostics.contains { $0.0 == "tun_packet_dropped" && $0.1["reason"] as? String == "transport_delay_post_mux_tun" })
    }

    @Test func inboundCounterDiscontinuityAndPacketWriteFailureAreReportedOnce() throws {
        let device = OverlayPacketDevice()
        device.failWrites = true
        let events = OverlayEvents()
        let adapter = makeAdapter(device: device, events: events)
        adapter.overlayLifecycleChanged(ready: true)
        adapter.receivedMuxFrame(try inboundOpen())
        adapter.receivedMuxFrame(.init(channelID: 9, protocolType: .tun, counter: 1, messageType: .data, body: packet()))
        adapter.receivedMuxFrame(.init(channelID: 9, protocolType: .tun, counter: 3, messageType: .data, body: packet()))
        #expect(events.diagnostics.filter { $0.0 == "tun_packet_device_write_failed" }.count == 2)
        #expect(events.diagnostics.filter { $0.0 == "tun_counter_discontinuity" }.count == 1)
    }

    @Test func sharedRouteFansOutAndInboundUnicastRelaysThroughCore() throws {
        let device = OverlayPacketDevice()
        let events = OverlayEvents()
        let peers: [ObstacleBridgeOverlayChannelRuntime.SharedTunPeer] = [
            .init(reference: "one", ipv4: ["10.0.0.1"]),
            .init(reference: "two", ipv4: ["10.0.0.2"]),
        ]
        let adapter = makeAdapter(device: device, sharedTunPeers: peers, events: events)
        adapter.overlayLifecycleChanged(ready: true)
        adapter.receivedMuxFrame(try inboundOpen(channelID: 9), peerID: 1)
        adapter.receivedMuxFrame(try inboundOpen(channelID: 10), peerID: 2)
        // Learn both Core-owned peer references before asking Core to select a route.
        adapter.receivedMuxFrame(.init(channelID: 10, protocolType: .tun, counter: 1, messageType: .data, body: packet(source: [10, 0, 0, 2], destination: [10, 0, 0, 99])), peerID: 2)
        adapter.receivedMuxFrame(.init(channelID: 9, protocolType: .tun, counter: 1, messageType: .data, body: packet(source: [10, 0, 0, 1], destination: [10, 0, 0, 2])), peerID: 1)
        #expect(events.diagnostics.contains { $0.0 == "tun_packet_relayed" && $0.1["channel_id"] as? Int == 9 })

        let batchesBeforeBroadcast = events.sent.count
        adapter.receivedPacketFromDevice(packet(source: [10, 0, 0, 99], destination: [255, 255, 255, 255]))
        #expect(events.sent.count == batchesBeforeBroadcast + 2)
        #expect(events.sent.suffix(2).allSatisfy { batch in
            batch.compactMap { try? ObstacleBridgeChannelMuxCodec.decode($0) }.contains { $0.messageType == .data }
        })
    }
}
