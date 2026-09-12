import Foundation
import ObstacleBridgeCore

public enum ObstacleBridgeLinuxServiceDataPlaneError: Error, Equatable {
    case unsupportedProtocol
    case malformedOpen
    case duplicateChannel
    case unknownChannel
    case queueFull
}

public struct ObstacleBridgeLinuxServiceDataPlaneSnapshot: Codable, Equatable, Sendable {
    public let activeTCPChannels: Int
    public let activeUDPChannels: Int
    public let queuedFrames: Int
    public let droppedFrames: Int
    public let malformedFrames: Int
    public let serviceFailures: Int
    public let openedTCPChannels: Int
    public let openedUDPChannels: Int
}

/// ChannelMux service-side state, intentionally independent from socket I/O.
/// A POSIX listener owns descriptors and feeds this serial core; the core owns
/// channel identities, OPEN/DATA/CLOSE encoding, bounded outbound buffering,
/// and malformed-frame accounting.
public final class ObstacleBridgeLinuxServiceDataPlane {
    private struct Channel {
        let spec: ObstacleBridgeLinuxServiceSpec
        let protocolType: ObstacleBridgeChannelMuxProtocol
        var counter: UInt16
    }

    private let maximumQueuedFrames: Int
    private let instanceID: UInt64
    private let connectionSequence: UInt32
    private var nextTCPChannel: UInt16 = 1
    private var nextUDPChannel: UInt16 = 1
    private var channels: [UInt16: Channel] = [:]
    private var outbound: [ObstacleBridgeChannelMuxFrame] = []
    private var droppedFrames = 0
    private var malformedFrames = 0
    private var serviceFailures = 0
    private var openedTCPChannels = 0
    private var openedUDPChannels = 0

    public init(maximumQueuedFrames: Int = 128, instanceID: UInt64 = 0, connectionSequence: UInt32 = 0) {
        self.maximumQueuedFrames = max(1, maximumQueuedFrames)
        self.instanceID = instanceID
        self.connectionSequence = connectionSequence
    }

    public func acceptLocalService(_ spec: ObstacleBridgeLinuxServiceSpec) throws -> UInt16 {
        guard spec.listenProtocol == .tcp || spec.listenProtocol == .udp,
              spec.listenProtocol == spec.targetProtocol else {
            serviceFailures += 1
            throw ObstacleBridgeLinuxServiceDataPlaneError.unsupportedProtocol
        }
        let channelID = allocate(protocolType: spec.listenProtocol)
        guard channels[channelID] == nil else {
            serviceFailures += 1
            throw ObstacleBridgeLinuxServiceDataPlaneError.duplicateChannel
        }
        channels[channelID] = .init(spec: spec, protocolType: spec.listenProtocol, counter: 0)
        if spec.listenProtocol == .tcp { openedTCPChannels += 1 } else { openedUDPChannels += 1 }
        try enqueue(.init(channelID: channelID, protocolType: spec.listenProtocol, counter: 0, messageType: .open, body: try openPayload(spec)))
        return channelID
    }

    public func localData(channelID: UInt16, payload: Data) throws {
        guard var channel = channels[channelID] else {
            serviceFailures += 1
            throw ObstacleBridgeLinuxServiceDataPlaneError.unknownChannel
        }
        channel.counter &+= 1
        channels[channelID] = channel
        try enqueue(.init(channelID: channelID, protocolType: channel.protocolType, counter: channel.counter, messageType: .data, body: payload))
    }

    /// Local EOF is represented as CLOSE after all frames already queued for
    /// that channel. The descriptor owner may then half-close its write side.
    public func localEOF(channelID: UInt16) throws {
        guard let channel = channels.removeValue(forKey: channelID) else {
            serviceFailures += 1
            throw ObstacleBridgeLinuxServiceDataPlaneError.unknownChannel
        }
        try enqueue(.init(channelID: channelID, protocolType: channel.protocolType, counter: channel.counter &+ 1, messageType: .close, body: Data()))
    }

    /// Handles a peer frame and returns data to write to the local descriptor,
    /// or an OPEN request which the descriptor owner must connect/bind.
    public func receive(_ frame: ObstacleBridgeChannelMuxFrame) throws -> ObstacleBridgeLinuxServiceDataPlaneEvent? {
        switch frame.messageType {
        case .open:
            guard channels[frame.channelID] == nil, let spec = try? decodeOpenPayload(frame.body), spec.listenProtocol == frame.protocolType else {
                malformedFrames += 1
                throw ObstacleBridgeLinuxServiceDataPlaneError.malformedOpen
            }
            channels[frame.channelID] = .init(spec: spec, protocolType: frame.protocolType, counter: frame.counter)
            if frame.protocolType == .tcp { openedTCPChannels += 1 } else if frame.protocolType == .udp { openedUDPChannels += 1 }
            return .connectRequested(channelID: frame.channelID, spec: spec)
        case .data:
            guard channels[frame.channelID] != nil else {
                malformedFrames += 1
                throw ObstacleBridgeLinuxServiceDataPlaneError.unknownChannel
            }
            return .deliverLocal(channelID: frame.channelID, payload: frame.body)
        case .close:
            guard channels.removeValue(forKey: frame.channelID) != nil else {
                malformedFrames += 1
                throw ObstacleBridgeLinuxServiceDataPlaneError.unknownChannel
            }
            return .closeLocal(channelID: frame.channelID)
        default:
            return nil
        }
    }

    public func drainOutbound() -> [ObstacleBridgeChannelMuxFrame] {
        defer { outbound.removeAll(keepingCapacity: true) }
        return outbound
    }

    public func snapshot() -> ObstacleBridgeLinuxServiceDataPlaneSnapshot {
        .init(
            activeTCPChannels: channels.values.filter { $0.protocolType == .tcp }.count,
            activeUDPChannels: channels.values.filter { $0.protocolType == .udp }.count,
            queuedFrames: outbound.count,
            droppedFrames: droppedFrames,
            malformedFrames: malformedFrames,
            serviceFailures: serviceFailures,
            openedTCPChannels: openedTCPChannels,
            openedUDPChannels: openedUDPChannels
        )
    }

    private func allocate(protocolType: ObstacleBridgeChannelMuxProtocol) -> UInt16 {
        if protocolType == .tcp {
            defer { nextTCPChannel = nextTCPChannel == UInt16.max ? 1 : nextTCPChannel &+ 1 }
            return nextTCPChannel
        }
        defer { nextUDPChannel = nextUDPChannel == UInt16.max ? 1 : nextUDPChannel &+ 1 }
        return nextUDPChannel
    }

    private func enqueue(_ frame: ObstacleBridgeChannelMuxFrame) throws {
        guard outbound.count < maximumQueuedFrames else {
            droppedFrames += 1
            throw ObstacleBridgeLinuxServiceDataPlaneError.queueFull
        }
        outbound.append(frame)
    }

    private func openPayload(_ spec: ObstacleBridgeLinuxServiceSpec) throws -> Data {
        let bind = Data(spec.listenHost.utf8)
        let host = Data(spec.targetHost.utf8)
        guard bind.count <= Int(UInt16.max), host.count <= Int(UInt16.max) else { throw ObstacleBridgeLinuxServiceDataPlaneError.malformedOpen }
        let metadata: [String: Any] = ["name": spec.name ?? NSNull(), "lifecycle_hooks": NSNull(), "options": NSNull()]
        let metadataData = try JSONSerialization.data(withJSONObject: metadata, options: [.sortedKeys])
        var value = Data("O5".utf8)
        append(instanceID, to: &value); append(connectionSequence, to: &value); append(spec.serviceID, to: &value)
        value.append(spec.listenProtocol.rawValue); append(UInt16(bind.count), to: &value); value.append(bind)
        append(UInt16(spec.listenPort), to: &value); value.append(spec.targetProtocol.rawValue); append(UInt16(host.count), to: &value); value.append(host)
        append(UInt16(spec.targetPort), to: &value); append(UInt32(metadataData.count), to: &value); value.append(metadataData)
        return value
    }

    private func decodeOpenPayload(_ data: Data) throws -> ObstacleBridgeLinuxServiceSpec {
        guard data.count >= 25, data.prefix(2) == Data("O5".utf8) else { throw ObstacleBridgeLinuxServiceDataPlaneError.malformedOpen }
        var offset = 2 + 8 + 4
        let serviceID = readUInt16(data, &offset)
        guard let listenProtocol = ObstacleBridgeChannelMuxProtocol(rawValue: readByte(data, &offset)) else { throw ObstacleBridgeLinuxServiceDataPlaneError.malformedOpen }
        let bind = try readString(data, &offset, count: Int(readUInt16(data, &offset)))
        let listenPort = Int(readUInt16(data, &offset))
        guard let targetProtocol = ObstacleBridgeChannelMuxProtocol(rawValue: readByte(data, &offset)) else { throw ObstacleBridgeLinuxServiceDataPlaneError.malformedOpen }
        let host = try readString(data, &offset, count: Int(readUInt16(data, &offset)))
        let targetPort = Int(readUInt16(data, &offset))
        let metadataLength = Int(readUInt32(data, &offset))
        guard offset + metadataLength == data.count,
              let metadata = try JSONSerialization.jsonObject(with: data[offset..<(offset + metadataLength)]) as? [String: Any] else { throw ObstacleBridgeLinuxServiceDataPlaneError.malformedOpen }
        return .init(serviceID: serviceID, name: metadata["name"] as? String, listenProtocol: listenProtocol, listenHost: bind, listenPort: listenPort, targetProtocol: targetProtocol, targetHost: host, targetPort: targetPort)
    }

    private func readByte(_ data: Data, _ offset: inout Int) -> UInt8 { defer { offset += 1 }; return data[offset] }
    private func readUInt16(_ data: Data, _ offset: inout Int) -> UInt16 { defer { offset += 2 }; return (UInt16(data[offset]) << 8) | UInt16(data[offset + 1]) }
    private func readUInt32(_ data: Data, _ offset: inout Int) -> UInt32 { defer { offset += 4 }; return data[offset..<(offset + 4)].reduce(0) { ($0 << 8) | UInt32($1) } }
    private func readString(_ data: Data, _ offset: inout Int, count: Int) throws -> String {
        guard count >= 0, offset + count <= data.count, let value = String(data: data[offset..<(offset + count)], encoding: .utf8) else { throw ObstacleBridgeLinuxServiceDataPlaneError.malformedOpen }
        offset += count
        return value
    }
    private func append(_ value: UInt16, to data: inout Data) { data.append(UInt8(value >> 8)); data.append(UInt8(value & 0xff)) }
    private func append(_ value: UInt32, to data: inout Data) { var encoded = value.bigEndian; data.append(Data(bytes: &encoded, count: 4)) }
    private func append(_ value: UInt64, to data: inout Data) { var encoded = value.bigEndian; data.append(Data(bytes: &encoded, count: 8)) }
}

public enum ObstacleBridgeLinuxServiceDataPlaneEvent: Equatable, Sendable {
    case connectRequested(channelID: UInt16, spec: ObstacleBridgeLinuxServiceSpec)
    case deliverLocal(channelID: UInt16, payload: Data)
    case closeLocal(channelID: UInt16)
}
