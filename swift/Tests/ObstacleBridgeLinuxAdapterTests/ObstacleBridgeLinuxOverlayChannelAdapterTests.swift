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
    private func packet() -> Data {
        Data([0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2])
    }

    private func makeAdapter(
        device: OverlayPacketDevice? = OverlayPacketDevice(),
        delayMS: Double = 0,
        events: OverlayEvents
    ) -> ObstacleBridgeLinuxOverlayChannelAdapter {
        ObstacleBridgeLinuxOverlayChannelAdapter(
            interfaceName: "obtun0", mtu: 1500, instanceID: 7, connectionSequence: 3,
            packetDevice: device,
            backpressureSnapshot: { .init(bufferedFrames: 0, transmitDelayEstMS: delayMS) },
            startupFrames: { [Data([0xca, 0xfe])] },
            sendMuxFrames: { events.sent.append($0) },
            diagnosticSink: { event, fields in events.diagnostics.append((event, fields)) }
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
}
