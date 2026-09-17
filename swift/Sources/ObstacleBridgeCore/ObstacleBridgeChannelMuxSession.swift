import Foundation

/// Deterministic ChannelMux service-session state.  It models only portable
/// channel lifecycle and emits local-I/O effects; descriptors and packet
/// devices stay in platform adapters.
public enum ObstacleBridgeChannelMuxSessionError: Error, Equatable, Sendable {
    case unsupportedProtocol
    case malformedOpen
    case duplicateChannel
    case unknownChannel
    case staleEpoch
    case invalidCounter
    case queueFull
}

/// A raw ChannelMux frame used by the session owner.  It deliberately does
/// not depend on the SwiftPM-only `ObstacleBridgeChannelMuxCodec` model: the
/// iOS and macOS flat builds compile the same state machine beside their
/// native wire adapter.
public struct ObstacleBridgeChannelMuxSessionFrame: Equatable, Sendable {
    public let channelID: UInt16
    public let protocolType: UInt8
    public let counter: UInt16
    public let messageType: UInt8
    public let body: Data

    public init(channelID: UInt16, protocolType: UInt8, counter: UInt16, messageType: UInt8, body: Data) {
        self.channelID = channelID
        self.protocolType = protocolType
        self.counter = counter
        self.messageType = messageType
        self.body = body
    }
}

public enum ObstacleBridgeChannelMuxSessionProtocol: UInt8, Sendable {
    case udp = 0
    case tcp = 1
}

public enum ObstacleBridgeChannelMuxSessionMessageType: UInt8, Sendable {
    case data = 0
    case open = 1
    case close = 2
    case openChunk = 7
}

public struct ObstacleBridgeChannelMuxSessionSnapshot: Codable, Equatable, Sendable {
    public let activeTCPChannels: Int
    public let activeUDPChannels: Int
    public let queuedFrames: Int
    public let droppedFrames: Int
    public let malformedFrames: Int
    public let serviceFailures: Int
    public let openedTCPChannels: Int
    public let openedUDPChannels: Int
}

public enum ObstacleBridgeChannelMuxSessionEffect: Equatable, Sendable {
    case outbound(ObstacleBridgeChannelMuxSessionFrame)
    case connectLocal(channelID: UInt16, service: ObstacleBridgeServiceSpec)
    case writeLocal(channelID: UInt16, payload: Data)
    case closeLocal(channelID: UInt16)
}

public final class ObstacleBridgeChannelMuxSession: @unchecked Sendable {
    private struct Channel: Sendable {
        let service: ObstacleBridgeServiceSpec
        let protocolType: ObstacleBridgeChannelMuxSessionProtocol
        var nextOutboundCounter: UInt16
        var nextInboundCounter: UInt16
    }

    /// OPEN chunks occupy the first wire records on a channel, but do not
    /// create a local socket until their complete service record is admitted.
    /// Keep their counter progression separate from active channels so a
    /// partial control record cannot bypass lifecycle ordering.
    private struct OpeningChannel: Sendable {
        let protocolType: ObstacleBridgeChannelMuxSessionProtocol
        var nextInboundCounter: UInt16
    }

    private let maximumQueuedFrames: Int
    private let maximumApplicationPayload: Int
    private let instanceID: UInt64
    private let connectionSequence: UInt32
    private let expectedInboundInstanceID: UInt64?
    private let expectedInboundConnectionSequence: UInt32?
    private var nextChannel: UInt16
    private let firstChannelID: UInt16
    private let channelStride: UInt16
    private var reservedChannels: Set<UInt16> = []
    private var channels: [UInt16: Channel] = [:]
    private var openingChannels: [UInt16: OpeningChannel] = [:]
    private var outbound: [ObstacleBridgeChannelMuxSessionFrame] = []
    private var droppedFrames = 0
    private var malformedFrames = 0
    private var serviceFailures = 0
    private var openedTCPChannels = 0
    private var openedUDPChannels = 0
    private var nextControlTransactionID: UInt32 = 1
    private let controlReassembler = ObstacleBridgeControlChunkReassembler()

    public init(
        maximumQueuedFrames: Int = 128,
        maximumApplicationPayload: Int = Int(UInt16.max),
        instanceID: UInt64 = 0,
        connectionSequence: UInt32 = 0,
        expectedInboundInstanceID: UInt64? = nil,
        expectedInboundConnectionSequence: UInt32? = nil,
        initialChannelID: UInt16 = 1,
        channelStride: UInt16 = 1
    ) {
        self.maximumQueuedFrames = max(1, maximumQueuedFrames)
        self.maximumApplicationPayload = max(ObstacleBridgeControlChunkCodec.channelMuxHeaderSize + ObstacleBridgeControlChunkCodec.headerSize + 1, maximumApplicationPayload)
        self.instanceID = instanceID
        self.connectionSequence = connectionSequence
        self.expectedInboundInstanceID = expectedInboundInstanceID
        self.expectedInboundConnectionSequence = expectedInboundConnectionSequence
        self.nextChannel = initialChannelID == 0 ? 1 : initialChannelID
        self.firstChannelID = initialChannelID == 0 ? 1 : initialChannelID
        self.channelStride = max(1, channelStride)
    }

    public func acceptLocal(service: ObstacleBridgeServiceSpec) throws -> [ObstacleBridgeChannelMuxSessionEffect] {
        guard isSupported(service, protocolType: .init(rawValue: service.listenProtocol)) else {
            serviceFailures += 1
            throw ObstacleBridgeChannelMuxSessionError.unsupportedProtocol
        }
        let protocolType = ObstacleBridgeChannelMuxSessionProtocol(rawValue: service.listenProtocol)!
        let channelID = allocate(protocolType: protocolType)
        guard channels[channelID] == nil else {
            serviceFailures += 1
            throw ObstacleBridgeChannelMuxSessionError.duplicateChannel
        }
        // OPEN occupies counter zero in each direction, so the peer's first
        // DATA/CLOSE record must carry counter one.
        channels[channelID] = .init(service: service, protocolType: protocolType, nextOutboundCounter: 0, nextInboundCounter: 1)
        if protocolType == .tcp { openedTCPChannels += 1 } else { openedUDPChannels += 1 }
        let payload: Data
        do { payload = try ObstacleBridgeServiceCodec.encodeOpen(instanceID: instanceID, connectionSequence: connectionSequence, service: service) }
        catch { serviceFailures += 1; throw ObstacleBridgeChannelMuxSessionError.malformedOpen }
        if ObstacleBridgeChannelMuxFrameCodec.headerSize + payload.count <= maximumApplicationPayload {
            try enqueue(.init(channelID: channelID, protocolType: protocolType.rawValue, counter: 0, messageType: ObstacleBridgeChannelMuxSessionMessageType.open.rawValue, body: payload))
        } else {
            let transaction = ObstacleBridgeControlChunkCodec.nextTransactionID(current: nextControlTransactionID)
            nextControlTransactionID = transaction.next
            let chunks: [Data]
            do { chunks = try ObstacleBridgeControlChunkCodec.chunk(transactionID: transaction.transactionID, maximumApplicationPayload: maximumApplicationPayload, payload: payload) }
            catch { channels.removeValue(forKey: channelID); serviceFailures += 1; throw ObstacleBridgeChannelMuxSessionError.malformedOpen }
            for chunk in chunks {
                channels[channelID]?.nextOutboundCounter &+= 1
                try enqueue(.init(channelID: channelID, protocolType: protocolType.rawValue, counter: channels[channelID]!.nextOutboundCounter, messageType: ObstacleBridgeChannelMuxSessionMessageType.openChunk.rawValue, body: chunk))
            }
        }
        return drainOutbound().map(ObstacleBridgeChannelMuxSessionEffect.outbound)
    }

    public func localData(channelID: UInt16, payload: Data) throws -> [ObstacleBridgeChannelMuxSessionEffect] {
        guard var channel = channels[channelID] else { serviceFailures += 1; throw ObstacleBridgeChannelMuxSessionError.unknownChannel }
        channel.nextOutboundCounter &+= 1
        channels[channelID] = channel
        try enqueue(.init(channelID: channelID, protocolType: channel.protocolType.rawValue, counter: channel.nextOutboundCounter, messageType: ObstacleBridgeChannelMuxSessionMessageType.data.rawValue, body: payload))
        return drainOutbound().map(ObstacleBridgeChannelMuxSessionEffect.outbound)
    }

    public func localEOF(channelID: UInt16) throws -> [ObstacleBridgeChannelMuxSessionEffect] {
        guard let channel = channels.removeValue(forKey: channelID) else { serviceFailures += 1; throw ObstacleBridgeChannelMuxSessionError.unknownChannel }
        try enqueue(.init(channelID: channelID, protocolType: channel.protocolType.rawValue, counter: channel.nextOutboundCounter &+ 1, messageType: ObstacleBridgeChannelMuxSessionMessageType.close.rawValue, body: Data()))
        return drainOutbound().map(ObstacleBridgeChannelMuxSessionEffect.outbound)
    }

    public func receive(_ frame: ObstacleBridgeChannelMuxSessionFrame) throws -> [ObstacleBridgeChannelMuxSessionEffect] {
        guard let protocolType = ObstacleBridgeChannelMuxSessionProtocol(rawValue: frame.protocolType),
              let messageType = ObstacleBridgeChannelMuxSessionMessageType(rawValue: frame.messageType) else {
            malformedFrames += 1
            throw ObstacleBridgeChannelMuxSessionError.malformedOpen
        }
        if messageType == .openChunk {
            guard channels[frame.channelID] == nil else {
                malformedFrames += 1
                throw ObstacleBridgeChannelMuxSessionError.invalidCounter
            }
            var opening = openingChannels[frame.channelID] ?? .init(protocolType: protocolType, nextInboundCounter: 1)
            guard opening.protocolType == protocolType,
                  frame.counter == opening.nextInboundCounter else {
                malformedFrames += 1
                throw ObstacleBridgeChannelMuxSessionError.invalidCounter
            }
            opening.nextInboundCounter &+= 1
            openingChannels[frame.channelID] = opening
            guard let body = controlReassembler.consume(channelID: frame.channelID, protocolType: frame.protocolType, messageType: frame.messageType, payload: frame.body, peerID: nil) else { return [] }
            // OPEN chunks have their own wire counters.  The reassembled
            // logical OPEN is always the first lifecycle record on a channel.
            openingChannels.removeValue(forKey: frame.channelID)
            return try receive(.init(channelID: frame.channelID, protocolType: frame.protocolType, counter: 0, messageType: ObstacleBridgeChannelMuxSessionMessageType.open.rawValue, body: body))
        }
        switch messageType {
        case .open:
            guard channels[frame.channelID] == nil,
                  openingChannels[frame.channelID] == nil,
                  let opened = try? ObstacleBridgeServiceCodec.decodeOpen(frame.body),
                  isSupported(opened.service, protocolType: protocolType),
                  frame.counter == 0,
                  epochMatches(opened)
            else { malformedFrames += 1; throw ObstacleBridgeChannelMuxSessionError.malformedOpen }
            channels[frame.channelID] = .init(service: opened.service, protocolType: protocolType, nextOutboundCounter: 0, nextInboundCounter: 1)
            if protocolType == .tcp { openedTCPChannels += 1 } else { openedUDPChannels += 1 }
            return [.connectLocal(channelID: frame.channelID, service: opened.service)]
        case .data:
            guard var channel = channels[frame.channelID] else { malformedFrames += 1; throw ObstacleBridgeChannelMuxSessionError.unknownChannel }
            guard channel.protocolType == protocolType, frame.counter == channel.nextInboundCounter else { malformedFrames += 1; throw ObstacleBridgeChannelMuxSessionError.invalidCounter }
            channel.nextInboundCounter &+= 1
            channels[frame.channelID] = channel
            return [.writeLocal(channelID: frame.channelID, payload: frame.body)]
        case .close:
            guard let channel = channels[frame.channelID] else { malformedFrames += 1; throw ObstacleBridgeChannelMuxSessionError.unknownChannel }
            guard channel.protocolType == protocolType, frame.counter == channel.nextInboundCounter else { malformedFrames += 1; throw ObstacleBridgeChannelMuxSessionError.invalidCounter }
            channels.removeValue(forKey: frame.channelID)
            return [.closeLocal(channelID: frame.channelID)]
        case .openChunk:
            return []
        }
    }

    public func snapshot() -> ObstacleBridgeChannelMuxSessionSnapshot {
        .init(activeTCPChannels: channels.values.filter { $0.protocolType == .tcp }.count, activeUDPChannels: channels.values.filter { $0.protocolType == .udp }.count, queuedFrames: outbound.count, droppedFrames: droppedFrames, malformedFrames: malformedFrames, serviceFailures: serviceFailures, openedTCPChannels: openedTCPChannels, openedUDPChannels: openedUDPChannels)
    }

    /// Adapter cancellation is explicit: callers receive the local resources
    /// that must be closed and the portable state cannot leak into the next
    /// authenticated overlay epoch.
    public func cancelAll() -> [ObstacleBridgeChannelMuxSessionEffect] {
        let effects = channels.keys.sorted().map(ObstacleBridgeChannelMuxSessionEffect.closeLocal)
        channels.removeAll(keepingCapacity: true)
        openingChannels.removeAll(keepingCapacity: true)
        reservedChannels.removeAll(keepingCapacity: true)
        outbound.removeAll(keepingCapacity: true)
        return effects
    }

    public var nextAvailableChannelID: UInt16 { nextChannel }

    public func nextOutboundCounter(channelID: UInt16) -> UInt16? {
        channels[channelID]?.nextOutboundCounter
    }

    /// Adapters may retrieve a service only after the session has admitted its
    /// OPEN record. This preserves Core as the sole OPEN validation owner
    /// while allowing native code to create the corresponding local socket.
    public func service(channelID: UInt16) -> ObstacleBridgeServiceSpec? {
        channels[channelID]?.service
    }

    /// Reserve an adapter-managed channel while a capability-limited fallback
    /// (for example pre-R007.4 fragmentation) is still active.  This keeps
    /// Core allocation collision-free during an incremental migration.
    public func reserve(channelID: UInt16) throws {
        guard channelID != 0, channels[channelID] == nil, !reservedChannels.contains(channelID) else {
            throw ObstacleBridgeChannelMuxSessionError.duplicateChannel
        }
        reservedChannels.insert(channelID)
    }

    public func releaseReservation(channelID: UInt16) {
        reservedChannels.remove(channelID)
    }

    private func isSupported(_ service: ObstacleBridgeServiceSpec, protocolType: ObstacleBridgeChannelMuxSessionProtocol?) -> Bool {
        guard let protocolType, protocolType == .tcp || protocolType == .udp,
              service.listenProtocol == service.targetProtocol,
              service.targetPort > 0 else { return false }
        return true
    }

    private func allocate(protocolType: ObstacleBridgeChannelMuxSessionProtocol) -> UInt16 {
        let initial = nextChannel
        repeat {
            let candidate = nextChannel
            let next = Int(nextChannel) + Int(channelStride)
            nextChannel = next <= Int(UInt16.max) ? UInt16(next) : firstChannelID
            if channels[candidate] == nil, !reservedChannels.contains(candidate) { return candidate }
        } while nextChannel != initial
        serviceFailures += 1
        fatalError("no free ChannelMux channel identifiers")
    }

    private func enqueue(_ frame: ObstacleBridgeChannelMuxSessionFrame) throws {
        guard outbound.count < maximumQueuedFrames else { droppedFrames += 1; throw ObstacleBridgeChannelMuxSessionError.queueFull }
        outbound.append(frame)
    }

    private func drainOutbound() -> [ObstacleBridgeChannelMuxSessionFrame] {
        defer { outbound.removeAll(keepingCapacity: true) }
        return outbound
    }

    private func epochMatches(_ opened: ObstacleBridgeOpenPayload) -> Bool {
        (expectedInboundInstanceID == nil || opened.instanceID == expectedInboundInstanceID)
            && (expectedInboundConnectionSequence == nil || opened.connectionSequence == expectedInboundConnectionSequence)
    }
}
