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
        guard let core = coreSpec(spec) else { throw ObstacleBridgeLinuxServiceDataPlaneError.malformedOpen }
        do { return try ObstacleBridgeServiceCodec.encodeOpen(instanceID: instanceID, connectionSequence: connectionSequence, service: core) }
        catch { throw ObstacleBridgeLinuxServiceDataPlaneError.malformedOpen }
    }

    private func decodeOpenPayload(_ data: Data) throws -> ObstacleBridgeLinuxServiceSpec {
        do {
            let service = try ObstacleBridgeServiceCodec.decodeOpen(data).service
            guard let result = linuxSpec(service) else { throw ObstacleBridgeLinuxServiceDataPlaneError.malformedOpen }
            return result
        } catch { throw ObstacleBridgeLinuxServiceDataPlaneError.malformedOpen }
    }

    private func coreSpec(_ value: ObstacleBridgeLinuxServiceSpec) -> ObstacleBridgeServiceSpec? {
        guard (1...Int(UInt16.max)).contains(value.listenPort), (1...Int(UInt16.max)).contains(value.targetPort) else { return nil }
        return .init(serviceID: value.serviceID, name: value.name, listenProtocol: value.listenProtocol.rawValue, listenHost: value.listenHost, listenPort: UInt16(value.listenPort), targetProtocol: value.targetProtocol.rawValue, targetHost: value.targetHost, targetPort: UInt16(value.targetPort))
    }
    private func linuxSpec(_ value: ObstacleBridgeServiceSpec) -> ObstacleBridgeLinuxServiceSpec? {
        guard value.listenPort > 0, value.targetPort > 0 else { return nil }
        guard let listenProtocol = ObstacleBridgeChannelMuxProtocol(rawValue: value.listenProtocol), let targetProtocol = ObstacleBridgeChannelMuxProtocol(rawValue: value.targetProtocol) else { return nil }
        return .init(serviceID: value.serviceID, name: value.name, listenProtocol: listenProtocol, listenHost: value.listenHost, listenPort: Int(value.listenPort), targetProtocol: targetProtocol, targetHost: value.targetHost, targetPort: Int(value.targetPort))
    }
}

public enum ObstacleBridgeLinuxServiceDataPlaneEvent: Equatable, Sendable {
    case connectRequested(channelID: UInt16, spec: ObstacleBridgeLinuxServiceSpec)
    case deliverLocal(channelID: UInt16, payload: Data)
    case closeLocal(channelID: UInt16)
}
