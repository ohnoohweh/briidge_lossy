import Foundation
import NetworkExtension
import Darwin

@objc(ObstacleBridgePacketFlowBridge)
final class ObstacleBridgePacketFlowBridge: NSObject {
    private final class PacketFlowPCAPWriter {
        private var fd: Int32 = -1
        let path: String

        init?(url: URL) {
            let opened = open(url.path, O_WRONLY | O_CREAT | O_TRUNC, mode_t(0o644))
            guard opened >= 0 else {
                NSLog("ObstacleBridge IPServer packet-flow pcap open failed path=%@", url.path)
                return nil
            }
            fd = opened
            path = url.path
            guard writeGlobalHeader() else {
                close()
                NSLog("ObstacleBridge IPServer packet-flow pcap header write failed path=%@", url.path)
                return nil
            }
        }

        deinit {
            close()
        }

        func writePacket(_ packet: Data, timestamp: Date = Date()) {
            guard fd >= 0 else { return }
            let absolute = timestamp.timeIntervalSince1970
            let seconds = UInt32(absolute)
            let micros = UInt32(max(0.0, (absolute - Double(seconds)) * 1_000_000.0))
            let capturedLength = UInt32(min(packet.count, Int(UInt32.max)))

            var record = Data()
            appendLE(seconds, to: &record)
            appendLE(micros, to: &record)
            appendLE(capturedLength, to: &record)
            appendLE(capturedLength, to: &record)

            guard writeAll(record), writeAll(packet) else {
                NSLog("ObstacleBridge IPServer packet-flow pcap packet write failed path=%@", path)
                return
            }
            _ = fsync(fd)
        }

        func close() {
            guard fd >= 0 else { return }
            _ = fsync(fd)
            _ = Darwin.close(fd)
            fd = -1
        }

        private func writeGlobalHeader() -> Bool {
            var header = Data()
            appendLE(UInt32(0xa1b2c3d4), to: &header)
            appendLE(UInt16(2), to: &header)
            appendLE(UInt16(4), to: &header)
            appendLE(UInt32(0), to: &header)
            appendLE(UInt32(0), to: &header)
            appendLE(UInt32(65535), to: &header)
            appendLE(UInt32(101), to: &header) // DLT_RAW for raw IPv4/IPv6 packets
            guard writeAll(header) else {
                return false
            }
            _ = fsync(fd)
            return true
        }

        private func writeAll(_ data: Data) -> Bool {
            guard fd >= 0 else { return false }
            var remaining = data.count
            var offset = 0
            while remaining > 0 {
                let written = data.withUnsafeBytes { rawBuffer -> Int in
                    guard let base = rawBuffer.baseAddress else {
                        return -1
                    }
                    return Darwin.write(fd, base.advanced(by: offset), remaining)
                }
                if written <= 0 {
                    return false
                }
                remaining -= written
                offset += written
            }
            return true
        }

        private func appendLE<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
            var littleEndian = value.littleEndian
            withUnsafeBytes(of: &littleEndian) { data.append(contentsOf: $0) }
        }
    }

    private static let shared = ObstacleBridgePacketFlowBridge()
    private let queue = DispatchQueue(label: "com.obstaclebridge.ipserver.packet-flow-bridge")
    private let outgoingDrainQueue = DispatchQueue(label: "com.obstaclebridge.ipserver.packet-flow-bridge.outgoing-drain")
    private weak var provider: PacketTunnelProvider?
    private var active = false
    private var tunnelAddress = ""
    private var mtu = 0
    private var incomingPCAPWriter: PacketFlowPCAPWriter?
    private var outgoingPCAPWriter: PacketFlowPCAPWriter?
    private var incomingPCAPPath = ""
    private var outgoingPCAPPath = ""
    private var wakeupFD: Int32 = -1
    private var incomingPackets: [Data] = []
    private var incomingProtocols: [NSNumber] = []
    private var packetsFromSystem = 0
    private var packetsToSystem = 0
    private var bytesFromSystem = 0
    private var bytesToSystem = 0
    private var droppedIncomingPackets = 0
    private var outgoingWriteCalls = 0
    private var outgoingWriteSlowCalls = 0
    private var outgoingWriteMaxDurationMs = 0.0
    private var outgoingWriteLastDurationMs = 0.0
    private var outgoingWriteInflight = 0
    private var outgoingWriteInflightMax = 0
    private var outgoingWriteLastStartedAt = 0.0
    private var outgoingWriteLastFinishedAt = 0.0
    private var outgoingQueuedPackets = 0
    private var outgoingQueuedPacketsMax = 0
    private var outgoingWriteBatches = 0
    private var outgoingPendingPackets: [Data] = []
    private var outgoingPendingProtocols: [NSNumber] = []
    private var outgoingDrainScheduled = false
    private let maxQueuedPackets = 2048
    private let maxOutgoingQueuedPackets = 2048
    private let maxOutgoingBatchPackets = 64
    private let outgoingDrainCoalesceDelayMs = 2

    class func activate(provider: PacketTunnelProvider, tunnelAddress: String, mtu: Int) {
        let pcapFields = shared.queue.sync { () -> [String: Any] in
            shared.provider = provider
            shared.active = true
            shared.tunnelAddress = tunnelAddress
            shared.mtu = mtu
            let capture = shared.configurePCAPWriters()
            shared.incomingPackets.removeAll(keepingCapacity: true)
            shared.incomingProtocols.removeAll(keepingCapacity: true)
            shared.packetsFromSystem = 0
            shared.packetsToSystem = 0
            shared.bytesFromSystem = 0
            shared.bytesToSystem = 0
            shared.droppedIncomingPackets = 0
            shared.outgoingWriteCalls = 0
            shared.outgoingWriteSlowCalls = 0
            shared.outgoingWriteMaxDurationMs = 0.0
            shared.outgoingWriteLastDurationMs = 0.0
            shared.outgoingWriteInflight = 0
            shared.outgoingWriteInflightMax = 0
            shared.outgoingWriteLastStartedAt = 0.0
            shared.outgoingWriteLastFinishedAt = 0.0
            shared.outgoingQueuedPackets = 0
            shared.outgoingQueuedPacketsMax = 0
            shared.outgoingWriteBatches = 0
            shared.outgoingPendingPackets.removeAll(keepingCapacity: false)
            shared.outgoingPendingProtocols.removeAll(keepingCapacity: false)
            shared.outgoingDrainScheduled = false
            return capture
        }
        var fields = pcapFields
        fields["tunnel_address"] = tunnelAddress
        fields["mtu"] = mtu
        provider.recordPacketBridgeEvent("packet_bridge_activated", fields: fields)
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
                "outgoing_write_calls": shared.outgoingWriteCalls,
                "outgoing_write_slow_calls": shared.outgoingWriteSlowCalls,
                "outgoing_write_max_duration_ms": shared.outgoingWriteMaxDurationMs,
                "outgoing_write_last_duration_ms": shared.outgoingWriteLastDurationMs,
                "outgoing_write_inflight": shared.outgoingWriteInflight,
                "outgoing_write_inflight_max": shared.outgoingWriteInflightMax,
                "outgoing_write_last_started_at": shared.outgoingWriteLastStartedAt,
                "outgoing_write_last_finished_at": shared.outgoingWriteLastFinishedAt,
                "outgoing_queued_packets": shared.outgoingQueuedPackets,
                "outgoing_queued_packets_max": shared.outgoingQueuedPacketsMax,
                "outgoing_write_batches": shared.outgoingWriteBatches,
                "incoming_pcap_path": shared.incomingPCAPPath,
                "outgoing_pcap_path": shared.outgoingPCAPPath,
            ]
            shared.incomingPCAPWriter?.close()
            shared.outgoingPCAPWriter?.close()
            shared.incomingPCAPWriter = nil
            shared.outgoingPCAPWriter = nil
            shared.incomingPCAPPath = ""
            shared.outgoingPCAPPath = ""
            shared.wakeupFD = -1
            shared.active = false
            shared.provider = nil
            shared.incomingPackets.removeAll(keepingCapacity: false)
            shared.incomingProtocols.removeAll(keepingCapacity: false)
            shared.outgoingPendingPackets.removeAll(keepingCapacity: false)
            shared.outgoingPendingProtocols.removeAll(keepingCapacity: false)
            shared.outgoingDrainScheduled = false
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
            shared.incomingPCAPWriter?.writePacket(packet)
            if shared.incomingPackets.count >= shared.maxQueuedPackets {
                shared.droppedIncomingPackets += 1
                return [
                    "reason": "queue_full",
                    "packet_bytes": packet.count,
                    "queued_packets": shared.incomingPackets.count,
                    "dropped_incoming_packets": shared.droppedIncomingPackets,
                ]
            }
            let shouldSignal = shared.incomingPackets.isEmpty
            shared.incomingPackets.append(packet)
            shared.incomingProtocols.append(protocolFamily)
            if shouldSignal {
                shared.signalWakeupFD()
            }
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

    @objc class func registerWakeupFD(_ fd: Int32) -> Bool {
        shared.queue.sync {
            guard fd >= 0 else {
                shared.wakeupFD = -1
                return false
            }
            shared.wakeupFD = fd
            if !shared.incomingPackets.isEmpty {
                shared.signalWakeupFD()
            }
            return true
        }
    }

    @objc class func resetWakeupFD() {
        shared.queue.sync {
            shared.wakeupFD = -1
        }
    }

    @objc class func writePacket(_ packet: NSData) -> Bool {
        let data = packet as Data
        let outcome = shared.queue.sync { () -> (PacketTunnelProvider?, Bool, Int32, Int, Int, Int, Int, Bool) in
            let proto = protocolFamily(for: data)
            guard shared.active, let provider = shared.provider else {
                return (nil, false, proto, 0, 0, 0, 0, false)
            }
            guard shared.outgoingPendingPackets.count < shared.maxOutgoingQueuedPackets else {
                return (
                    provider,
                    false,
                    proto,
                    shared.packetsToSystem,
                    shared.bytesToSystem,
                    shared.outgoingWriteInflight,
                    shared.outgoingPendingPackets.count,
                    false
                )
            }
            shared.outgoingPCAPWriter?.writePacket(data)
            shared.packetsToSystem += 1
            shared.bytesToSystem += data.count
            shared.outgoingPendingPackets.append(data)
            shared.outgoingPendingProtocols.append(NSNumber(value: proto))
            shared.outgoingQueuedPackets = shared.outgoingPendingPackets.count
            shared.outgoingQueuedPacketsMax = max(shared.outgoingQueuedPacketsMax, shared.outgoingQueuedPackets)
            let shouldSchedule = !shared.outgoingDrainScheduled
            if shouldSchedule {
                shared.outgoingDrainScheduled = true
            }
            return (
                provider,
                true,
                proto,
                shared.packetsToSystem,
                shared.bytesToSystem,
                shared.outgoingWriteInflight,
                shared.outgoingQueuedPackets,
                shouldSchedule
            )
        }
        guard outcome.1, let provider = outcome.0 else {
            if let provider = outcome.0 {
                provider.recordPacketBridgeEvent(
                    "packet_bridge_outgoing_write_rejected",
                    fields: [
                        "packet_bytes": data.count,
                        "protocol_family": outcome.2,
                        "queued_packets": outcome.6,
                        "max_queued_packets": shared.maxOutgoingQueuedPackets,
                    ]
                )
            }
            return false
        }
        if outcome.7 {
            scheduleOutgoingDrain(provider: provider)
        }
        if outcome.3 <= 3 || (outcome.3 % 128) == 0 {
            provider.recordPacketBridgeEvent(
                "packet_bridge_outgoing_enqueued",
                fields: [
                    "packet_bytes": data.count,
                    "protocol_family": outcome.2,
                    "packets_to_system": outcome.3,
                    "bytes_to_system": outcome.4,
                    "outgoing_write_inflight": outcome.5,
                    "outgoing_queued_packets": outcome.6,
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

    class func bridgeStateSnapshot() -> [String: Any] {
        shared.snapshotPayload()
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
                "outgoing_write_calls": outgoingWriteCalls,
                "outgoing_write_slow_calls": outgoingWriteSlowCalls,
                "outgoing_write_max_duration_ms": outgoingWriteMaxDurationMs,
                "outgoing_write_last_duration_ms": outgoingWriteLastDurationMs,
                "outgoing_write_inflight": outgoingWriteInflight,
                "outgoing_write_inflight_max": outgoingWriteInflightMax,
                "outgoing_write_last_started_at": outgoingWriteLastStartedAt,
                "outgoing_write_last_finished_at": outgoingWriteLastFinishedAt,
                "outgoing_queued_packets": outgoingQueuedPackets,
                "outgoing_queued_packets_max": outgoingQueuedPacketsMax,
                "outgoing_write_batches": outgoingWriteBatches,
                "incoming_pcap_path": incomingPCAPPath,
                "outgoing_pcap_path": outgoingPCAPPath,
                "wakeup_fd": wakeupFD,
            ]
        }
    }

    private func configurePCAPWriters() -> [String: Any] {
        incomingPCAPWriter?.close()
        outgoingPCAPWriter?.close()
        incomingPCAPWriter = nil
        outgoingPCAPWriter = nil
        incomingPCAPPath = ""
        outgoingPCAPPath = ""

        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.obstaclebridge.shared"
        ) else {
            return ["pcap_enabled": false, "pcap_error": "missing_app_group_container"]
        }

        let logDirectory = containerURL.appendingPathComponent("logs", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: logDirectory, withIntermediateDirectories: true)
        } catch {
            return [
                "pcap_enabled": false,
                "pcap_error": "create_logs_dir_failed",
                "pcap_error_detail": error.localizedDescription,
            ]
        }

        let stamp = Self.captureTimestamp()
        let incomingURL = logDirectory.appendingPathComponent("ipserver-nepacketflow-in-\(stamp).pcap")
        let outgoingURL = logDirectory.appendingPathComponent("ipserver-nepacketflow-out-\(stamp).pcap")

        incomingPCAPWriter = PacketFlowPCAPWriter(url: incomingURL)
        outgoingPCAPWriter = PacketFlowPCAPWriter(url: outgoingURL)
        incomingPCAPPath = incomingPCAPWriter?.path ?? ""
        outgoingPCAPPath = outgoingPCAPWriter?.path ?? ""

        return [
            "pcap_enabled": incomingPCAPWriter != nil || outgoingPCAPWriter != nil,
            "incoming_pcap_path": incomingPCAPPath,
            "outgoing_pcap_path": outgoingPCAPPath,
        ]
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

    private static func captureTimestamp() -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return formatter.string(from: Date())
    }

    private func signalWakeupFD() {
        guard wakeupFD >= 0 else {
            return
        }
        var signalByte: UInt8 = 1
        let wrote = withUnsafePointer(to: &signalByte) { ptr in
            Darwin.write(wakeupFD, ptr, 1)
        }
        if wrote < 0 {
            let err = errno
            if err != EAGAIN && err != EWOULDBLOCK {
                NSLog("ObstacleBridge IPServer wakeup fd write failed fd=%d errno=%d", wakeupFD, err)
            }
        }
    }

    private static func scheduleOutgoingDrain(provider: PacketTunnelProvider) {
        let delayNs = UInt64(max(0, shared.outgoingDrainCoalesceDelayMs)) * 1_000_000
        shared.outgoingDrainQueue.asyncAfter(deadline: .now() + .nanoseconds(Int(delayNs))) {
            drainOutgoingPackets(provider: provider)
        }
    }

    private static func drainOutgoingPackets(provider: PacketTunnelProvider) {
        while true {
            let batch = shared.queue.sync { () -> ([Data], [NSNumber], Int) in
                guard shared.active,
                      let currentProvider = shared.provider,
                      currentProvider === provider,
                      !shared.outgoingPendingPackets.isEmpty else {
                    shared.outgoingDrainScheduled = false
                    shared.outgoingQueuedPackets = shared.outgoingPendingPackets.count
                    return ([], [], 0)
                }
                let count = min(shared.maxOutgoingBatchPackets, shared.outgoingPendingPackets.count)
                let packets = Array(shared.outgoingPendingPackets.prefix(count))
                let protocols = Array(shared.outgoingPendingProtocols.prefix(count))
                shared.outgoingPendingPackets.removeFirst(count)
                shared.outgoingPendingProtocols.removeFirst(count)
                shared.outgoingQueuedPackets = shared.outgoingPendingPackets.count
                shared.outgoingWriteInflight += packets.count
                shared.outgoingWriteInflightMax = max(shared.outgoingWriteInflightMax, shared.outgoingWriteInflight)
                shared.outgoingWriteBatches += 1
                shared.outgoingWriteLastStartedAt = Date().timeIntervalSince1970
                return (packets, protocols, shared.outgoingWriteBatches)
            }
            guard !batch.0.isEmpty else {
                return
            }
            let started = CFAbsoluteTimeGetCurrent()
            provider.packetFlow.writePackets(batch.0, withProtocols: batch.1)
            let elapsedMs = (CFAbsoluteTimeGetCurrent() - started) * 1000.0
            recordOutgoingWriteCompletion(
                provider: provider,
                packetBytes: batch.0.reduce(0) { $0 + $1.count },
                protocolFamily: batch.1.first?.int32Value ?? 0,
                durationMs: elapsedMs,
                batchPackets: batch.0.count,
                batchNumber: batch.2
            )
        }
    }

    private static func recordOutgoingWriteCompletion(
        provider: PacketTunnelProvider,
        packetBytes: Int,
        protocolFamily: Int32,
        durationMs: Double,
        batchPackets: Int = 1,
        batchNumber: Int = 0
    ) {
        let payload = shared.queue.sync { () -> [String: Any] in
            shared.outgoingWriteInflight = max(0, shared.outgoingWriteInflight - batchPackets)
            shared.outgoingWriteCalls += 1
            shared.outgoingWriteLastDurationMs = durationMs
            shared.outgoingWriteMaxDurationMs = max(shared.outgoingWriteMaxDurationMs, durationMs)
            shared.outgoingWriteLastFinishedAt = Date().timeIntervalSince1970
            if durationMs >= 20.0 {
                shared.outgoingWriteSlowCalls += 1
            }
            return [
                "packet_bytes": packetBytes,
                "batch_packets": batchPackets,
                "batch_number": batchNumber,
                "protocol_family": protocolFamily,
                "duration_ms": durationMs,
                "outgoing_write_calls": shared.outgoingWriteCalls,
                "outgoing_write_slow_calls": shared.outgoingWriteSlowCalls,
                "outgoing_write_max_duration_ms": shared.outgoingWriteMaxDurationMs,
                "outgoing_write_inflight": shared.outgoingWriteInflight,
                "outgoing_write_inflight_max": shared.outgoingWriteInflightMax,
                "outgoing_queued_packets": shared.outgoingQueuedPackets,
                "outgoing_queued_packets_max": shared.outgoingQueuedPacketsMax,
                "outgoing_write_batches": shared.outgoingWriteBatches,
            ]
        }
        if (payload["outgoing_write_calls"] as? Int ?? 0) <= 3 || ((payload["outgoing_write_calls"] as? Int ?? 0) % 128) == 0 {
            provider.recordPacketBridgeEvent("packet_bridge_outgoing_write_completed", fields: payload)
        }
        if durationMs >= 20.0 {
            provider.recordPacketBridgeEvent("packet_bridge_outgoing_write_slow", fields: payload)
        }
    }
}
