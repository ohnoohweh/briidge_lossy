import Foundation
import NetworkExtension

@objc(ObstacleBridgePacketFlowBridge)
final class ObstacleBridgePacketFlowBridge: NSObject {
    private static let shared = ObstacleBridgePacketFlowBridge()
    private let queue = DispatchQueue(label: "com.obstaclebridge.ipserver.packet-flow-bridge")
    private weak var provider: PacketTunnelProvider?
    private var active = false
    private var tunnelAddress = ""
    private var mtu = 0
    private var incomingPackets: [Data] = []
    private var incomingProtocols: [NSNumber] = []
    private var packetsFromSystem = 0
    private var packetsToSystem = 0
    private var bytesFromSystem = 0
    private var bytesToSystem = 0
    private var droppedIncomingPackets = 0
    private let maxQueuedPackets = 2048

    class func activate(provider: PacketTunnelProvider, tunnelAddress: String, mtu: Int) {
        shared.queue.sync {
            shared.provider = provider
            shared.active = true
            shared.tunnelAddress = tunnelAddress
            shared.mtu = mtu
            shared.incomingPackets.removeAll(keepingCapacity: true)
            shared.incomingProtocols.removeAll(keepingCapacity: true)
            shared.packetsFromSystem = 0
            shared.packetsToSystem = 0
            shared.bytesFromSystem = 0
            shared.bytesToSystem = 0
            shared.droppedIncomingPackets = 0
        }
        provider.recordPacketBridgeEvent(
            "packet_bridge_activated",
            fields: [
                "tunnel_address": tunnelAddress,
                "mtu": mtu,
            ]
        )
    }

    class func deactivate() {
        let state = shared.queue.sync { () -> (PacketTunnelProvider?, [String: Any]) in
            let provider = shared.provider
            let payload: [String: Any] = [
                "active": shared.active,
                "tunnel_address": shared.tunnelAddress,
                "mtu": shared.mtu,
                "queued_packets": shared.incomingPackets.count,
                "queued_protocols": shared.incomingProtocols.count,
                "packets_from_system": shared.packetsFromSystem,
                "packets_to_system": shared.packetsToSystem,
                "bytes_from_system": shared.bytesFromSystem,
                "bytes_to_system": shared.bytesToSystem,
                "dropped_incoming_packets": shared.droppedIncomingPackets,
            ]
            shared.active = false
            shared.provider = nil
            shared.incomingPackets.removeAll(keepingCapacity: false)
            shared.incomingProtocols.removeAll(keepingCapacity: false)
            return (provider, payload)
        }
        if let provider = state.0 {
            provider.recordPacketBridgeEvent("packet_bridge_deactivated", fields: state.1)
        } else {
            NSLog("ObstacleBridge IPServer packet_bridge_deactivated snapshot=%@", state.1 as NSDictionary)
        }
    }

    class func enqueueIncomingPacket(_ packet: Data, protocolFamily: NSNumber) {
        let eventPayload = shared.queue.sync { () -> [String: Any]? in
            guard shared.active else {
                return ["reason": "bridge_inactive", "packet_bytes": packet.count]
            }
            if shared.incomingPackets.count >= shared.maxQueuedPackets {
                shared.droppedIncomingPackets += 1
                return [
                    "reason": "queue_full",
                    "packet_bytes": packet.count,
                    "queued_packets": shared.incomingPackets.count,
                    "dropped_incoming_packets": shared.droppedIncomingPackets,
                ]
            }
            shared.incomingPackets.append(packet)
            shared.incomingProtocols.append(protocolFamily)
            shared.packetsFromSystem += 1
            shared.bytesFromSystem += packet.count
            if shared.packetsFromSystem <= 3 || (shared.packetsFromSystem % 128) == 0 {
                return [
                    "packet_bytes": packet.count,
                    "protocol_family": protocolFamily.intValue,
                    "queued_packets": shared.incomingPackets.count,
                    "packets_from_system": shared.packetsFromSystem,
                    "bytes_from_system": shared.bytesFromSystem,
                ]
            }
            return nil
        }
        guard let payload = eventPayload, let provider = shared.provider else {
            return
        }
        provider.recordPacketBridgeEvent("packet_bridge_incoming_enqueued", fields: payload)
    }

    @objc class func dequeueIncomingPacket() -> NSData? {
        shared.queue.sync {
            guard shared.active, !shared.incomingPackets.isEmpty else {
                return nil
            }
            if !shared.incomingProtocols.isEmpty {
                shared.incomingProtocols.removeFirst()
            }
            return shared.incomingPackets.removeFirst() as NSData
        }
    }

    @objc class func writePacket(_ packet: NSData) -> Bool {
        let data = packet as Data
        let outcome = shared.queue.sync { () -> (PacketTunnelProvider?, Bool, Int32, Int, Int) in
            let proto = protocolFamily(for: data)
            guard shared.active, let provider = shared.provider else {
                return (nil, false, proto, 0, 0)
            }
            shared.packetsToSystem += 1
            shared.bytesToSystem += data.count
            return (provider, true, proto, shared.packetsToSystem, shared.bytesToSystem)
        }
        guard outcome.1, let provider = outcome.0 else {
            return false
        }
        let protocolNumber = NSNumber(value: outcome.2)
        DispatchQueue.global(qos: .utility).async {
            provider.packetFlow.writePackets([data], withProtocols: [protocolNumber])
        }
        if outcome.3 <= 3 || (outcome.3 % 128) == 0 {
            provider.recordPacketBridgeEvent(
                "packet_bridge_outgoing_written",
                fields: [
                    "packet_bytes": data.count,
                    "protocol_family": outcome.2,
                    "packets_to_system": outcome.3,
                    "bytes_to_system": outcome.4,
                ]
            )
        }
        return true
    }

    @objc class func bridgeStateJSONData() -> NSData? {
        let payload = shared.snapshotPayload()
        guard JSONSerialization.isValidJSONObject(payload),
              let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]) else {
            return nil
        }
        return data as NSData
    }

    private func snapshotPayload() -> [String: Any] {
        queue.sync {
            [
                "active": active,
                "tunnel_address": tunnelAddress,
                "mtu": mtu,
                "queued_packets": incomingPackets.count,
                "queued_protocols": incomingProtocols.count,
                "packets_from_system": packetsFromSystem,
                "packets_to_system": packetsToSystem,
                "bytes_from_system": bytesFromSystem,
                "bytes_to_system": bytesToSystem,
                "dropped_incoming_packets": droppedIncomingPackets,
            ]
        }
    }

    private static func protocolFamily(for packet: Data) -> Int32 {
        guard let first = packet.first else {
            return AF_INET
        }
        let version = (first & 0xF0) >> 4
        if version == 6 {
            return AF_INET6
        }
        return AF_INET
    }
}
