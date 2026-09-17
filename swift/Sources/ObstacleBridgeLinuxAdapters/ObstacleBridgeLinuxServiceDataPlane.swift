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

/// POSIX-facing translation facade.  Channel lifecycle policy is implemented
/// by `ObstacleBridgeChannelMuxSession`; this type converts its value effects
/// into descriptor-owner operations and performs no ChannelMux state updates.
public final class ObstacleBridgeLinuxServiceDataPlane {
    private let core: ObstacleBridgeChannelMuxSession
    private let maximumQueuedFrames: Int
    private var pendingOutbound: [ObstacleBridgeChannelMuxFrame] = []
    private var effectDeliveryDrops = 0

    public init(maximumQueuedFrames: Int = 128, instanceID: UInt64 = 0, connectionSequence: UInt32 = 0) {
        self.maximumQueuedFrames = max(1, maximumQueuedFrames)
        core = .init(maximumQueuedFrames: maximumQueuedFrames, instanceID: instanceID, connectionSequence: connectionSequence)
    }

    public func acceptLocalService(_ spec: ObstacleBridgeLinuxServiceSpec) throws -> UInt16 {
        let effects = try map { try core.acceptLocal(service: coreSpec(spec)) }
        try retainOutbound(effects)
        guard case .outbound(let frame) = effects.first else { throw ObstacleBridgeLinuxServiceDataPlaneError.malformedOpen }
        return frame.channelID
    }

    public func localData(channelID: UInt16, payload: Data) throws {
        try retainOutbound(try map { try core.localData(channelID: channelID, payload: payload) })
    }

    public func localEOF(channelID: UInt16) throws {
        try retainOutbound(try map { try core.localEOF(channelID: channelID) })
    }

    public func receive(_ frame: ObstacleBridgeChannelMuxFrame) throws -> ObstacleBridgeLinuxServiceDataPlaneEvent? {
        let effects = try map { try core.receive(sessionFrame(frame)) }
        guard let effect = effects.first else { return nil }
        switch effect {
        case .connectLocal(let channelID, let service): return .connectRequested(channelID: channelID, spec: linuxSpec(service))
        case .writeLocal(let channelID, let payload): return .deliverLocal(channelID: channelID, payload: payload)
        case .closeLocal(let channelID): return .closeLocal(channelID: channelID)
        case .outbound: return nil
        }
    }

    public func drainOutbound() -> [ObstacleBridgeChannelMuxFrame] {
        defer { pendingOutbound.removeAll(keepingCapacity: true) }
        return pendingOutbound
    }

    public func snapshot() -> ObstacleBridgeLinuxServiceDataPlaneSnapshot {
        let snapshot = core.snapshot()
        return .init(activeTCPChannels: snapshot.activeTCPChannels, activeUDPChannels: snapshot.activeUDPChannels, queuedFrames: pendingOutbound.count, droppedFrames: snapshot.droppedFrames + effectDeliveryDrops, malformedFrames: snapshot.malformedFrames, serviceFailures: snapshot.serviceFailures, openedTCPChannels: snapshot.openedTCPChannels, openedUDPChannels: snapshot.openedUDPChannels)
    }

    private func map<T>(_ operation: () throws -> T) throws -> T {
        do { return try operation() }
        catch let error as ObstacleBridgeChannelMuxSessionError {
            switch error {
            case .unsupportedProtocol: throw ObstacleBridgeLinuxServiceDataPlaneError.unsupportedProtocol
            case .malformedOpen: throw ObstacleBridgeLinuxServiceDataPlaneError.malformedOpen
            case .duplicateChannel: throw ObstacleBridgeLinuxServiceDataPlaneError.duplicateChannel
            case .unknownChannel: throw ObstacleBridgeLinuxServiceDataPlaneError.unknownChannel
            case .staleEpoch, .invalidCounter, .queueFull: throw ObstacleBridgeLinuxServiceDataPlaneError.queueFull
            }
        }
    }

    private func retainOutbound(_ effects: [ObstacleBridgeChannelMuxSessionEffect]) throws {
        let frames = effects.compactMap { effect -> ObstacleBridgeChannelMuxFrame? in
            guard case .outbound(let frame) = effect else { return nil }
            guard let protocolType = ObstacleBridgeChannelMuxProtocol(rawValue: frame.protocolType),
                  let messageType = ObstacleBridgeChannelMuxMessageType(rawValue: frame.messageType) else { return nil }
            return .init(channelID: frame.channelID, protocolType: protocolType, counter: frame.counter, messageType: messageType, body: frame.body)
        }
        guard pendingOutbound.count + frames.count <= maximumQueuedFrames else {
            effectDeliveryDrops += frames.count
            throw ObstacleBridgeLinuxServiceDataPlaneError.queueFull
        }
        pendingOutbound.append(contentsOf: frames)
    }

    private func coreSpec(_ value: ObstacleBridgeLinuxServiceSpec) -> ObstacleBridgeServiceSpec {
        .init(serviceID: value.serviceID, name: value.name, listenProtocol: value.listenProtocol.rawValue, listenHost: value.listenHost, listenPort: UInt16(clamping: value.listenPort), targetProtocol: value.targetProtocol.rawValue, targetHost: value.targetHost, targetPort: UInt16(clamping: value.targetPort))
    }

    private func linuxSpec(_ value: ObstacleBridgeServiceSpec) -> ObstacleBridgeLinuxServiceSpec {
        .init(serviceID: value.serviceID, name: value.name, listenProtocol: .init(rawValue: value.listenProtocol)!, listenHost: value.listenHost, listenPort: Int(value.listenPort), targetProtocol: .init(rawValue: value.targetProtocol)!, targetHost: value.targetHost, targetPort: Int(value.targetPort))
    }

    private func sessionFrame(_ value: ObstacleBridgeChannelMuxFrame) -> ObstacleBridgeChannelMuxSessionFrame {
        .init(channelID: value.channelID, protocolType: value.protocolType.rawValue, counter: value.counter, messageType: value.messageType.rawValue, body: value.body)
    }
}

public enum ObstacleBridgeLinuxServiceDataPlaneEvent: Equatable, Sendable {
    case connectRequested(channelID: UInt16, spec: ObstacleBridgeLinuxServiceSpec)
    case deliverLocal(channelID: UInt16, payload: Data)
    case closeLocal(channelID: UInt16)
}
