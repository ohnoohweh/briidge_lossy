import Foundation
import ObstacleBridgeCore

/// Linux resource boundary for Core-owned overlay TUN policy.
///
/// This deliberately accepts an injected packet-device owner.  Opening or
/// configuring `/dev/net/tun` is still outside the admitted foreground product
/// until LSW-005; a missing owner therefore fails closed instead of falling
/// back to an in-process or Apple-specific transport.
public protocol ObstacleBridgeLinuxPacketDevice: AnyObject {
    func writePacket(_ packet: Data) throws
}

public final class ObstacleBridgeLinuxOverlayChannelAdapter {
    public typealias DiagnosticSink = (String, [String: Any]) -> Void

    private let runtime: ObstacleBridgeOverlayChannelRuntime
    /// The adapter is the selected packet-device resource owner for its
    /// lifetime. Retaining the injected owner prevents a transient caller
    /// reference from silently changing a ready TUN channel into no-device.
    private let packetDevice: (any ObstacleBridgeLinuxPacketDevice)?
    private let backpressureSnapshot: () -> ObstacleBridgeOverlayChannelRuntime.Backpressure
    private let startupFrames: () -> [Data]
    private let sendMuxFrames: ([Data]) -> Void
    private let diagnosticSink: DiagnosticSink

    public init(
        interfaceName: String,
        mtu: Int,
        instanceID: UInt64,
        connectionSequence: UInt32,
        packetDevice: (any ObstacleBridgeLinuxPacketDevice)? = nil,
        localAddress: String? = nil,
        localAddress6: String? = nil,
        backpressureSnapshot: @escaping () -> ObstacleBridgeOverlayChannelRuntime.Backpressure,
        startupFrames: @escaping () -> [Data],
        sendMuxFrames: @escaping ([Data]) -> Void,
        diagnosticSink: @escaping DiagnosticSink = { _, _ in }
    ) {
        self.runtime = .init(
            interfaceName: interfaceName,
            mtu: mtu,
            instanceID: instanceID,
            connectionSequence: connectionSequence,
            localAddress: localAddress,
            localAddress6: localAddress6
        )
        self.packetDevice = packetDevice
        self.backpressureSnapshot = backpressureSnapshot
        self.startupFrames = startupFrames
        self.sendMuxFrames = sendMuxFrames
        self.diagnosticSink = diagnosticSink
    }

    /// The selected overlay owner reports authenticated readiness and epoch
    /// replacement. Core fences the old ChannelMux state before more TUN input.
    public func overlayLifecycleChanged(ready: Bool, epochChanged: Bool = false) {
        if epochChanged {
            runtime.transportEpochChanged()
        }
        runtime.setOverlayReady(ready)
    }

    /// Called once for each packet read by the selected Linux packet owner.
    public func receivedPacketFromDevice(_ packet: Data) {
        guard packetDevice != nil else {
            diagnosticSink("tun_packet_device_unavailable", [
                "reason": "LSW-005: no admitted /dev/net/tun packet-device owner",
                "packet_bytes": packet.count,
            ])
            return
        }
        runtime.sendLocalPacket(
            packet,
            backpressure: backpressureSnapshot(),
            startupFrames: startupFrames,
            sendMuxFrames: sendMuxFrames,
            effectSink: emit
        )
    }

    /// Called by the selected overlay owner for each authenticated TUN frame.
    public func receivedMuxFrame(_ frame: ObstacleBridgeChannelMuxFrame, peerID: Int? = nil) {
        runtime.receiveMuxFrame(
            frame,
            currentPeerID: peerID,
            sendMuxFrames: sendMuxFrames,
            deliverPacket: { [weak self] packet in self?.writePacketOnce(packet) },
            effectSink: emit
        )
    }

    public func connectionRows() -> [[String: Any]] {
        runtime.connectionRows(backpressure: backpressureSnapshot())
    }

    public func stop() {
        runtime.stop()
    }

    private func writePacketOnce(_ packet: Data) {
        guard let packetDevice else {
            diagnosticSink("tun_packet_device_unavailable", [
                "reason": "LSW-005: no admitted /dev/net/tun packet-device owner",
                "packet_bytes": packet.count,
            ])
            return
        }
        do {
            try packetDevice.writePacket(packet)
        } catch {
            diagnosticSink("tun_packet_device_write_failed", [
                "packet_bytes": packet.count,
                "error": error.localizedDescription,
            ])
        }
    }

    private func emit(_ effect: ObstacleBridgeOverlayChannelRuntime.PacketDeviceEffect) {
        switch effect {
        case .dropped(let reason):
            diagnosticSink("tun_packet_dropped", ["reason": reason])
        case .forwarded(let channelID, let allocatedChannel):
            diagnosticSink("tun_packet_forwarded", ["channel_id": channelID, "allocated_channel": allocatedChannel])
        case .relayed(let channelID):
            diagnosticSink("tun_packet_relayed", ["channel_id": channelID])
        case .delivered(let channelID):
            diagnosticSink("tun_packet_delivered", ["channel_id": channelID])
        case .counterDiscontinuity(let channelID, let counter):
            diagnosticSink("tun_counter_discontinuity", ["channel_id": channelID, "counter": counter])
        case .openRejected(let channelID):
            diagnosticSink("tun_open_rejected", ["channel_id": channelID])
        case .openChunkRejected(let channelID):
            diagnosticSink("tun_open_chunk_rejected", ["channel_id": channelID])
        }
    }
}
