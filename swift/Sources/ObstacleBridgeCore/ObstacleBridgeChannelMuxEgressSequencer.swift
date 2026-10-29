import Foundation

/// The identity used by a peer-scoped ChannelMux egress scheduler.  Message
/// type is deliberately excluded: OPEN, DATA, CLOSE, catalog, and liveness
/// records from one channel retain their order in the same source queue.
public struct ObstacleBridgeChannelMuxEgressSource: Hashable, Sendable {
    public let protocolType: UInt8
    public let channelID: UInt16

    public init(protocolType: UInt8, channelID: UInt16) {
        self.protocolType = protocolType
        self.channelID = channelID
    }

    public init(_ frame: ObstacleBridgeChannelMuxFrame) {
        self.init(protocolType: frame.protocolType.rawValue, channelID: frame.channelID)
    }

    public init(_ frame: ObstacleBridgeChannelMuxWireFrame) {
        self.init(protocolType: frame.protocolType, channelID: frame.channelID)
    }
}

/// A serial-owner round-robin scheduler for one peer's outbound mux records.
/// Owners call `dequeueNext()` once per lower-layer send opportunity.  A source
/// appears at most once in the ready ring, so continuously ready traffic
/// cannot regain the turn before every other ready source has had one record.
public final class ObstacleBridgeChannelMuxEgressSequencer<Element>: @unchecked Sendable {
    private var queues: [ObstacleBridgeChannelMuxEgressSource: [Element]] = [:]
    private var readySources: [ObstacleBridgeChannelMuxEgressSource] = []
    private var readySet: Set<ObstacleBridgeChannelMuxEgressSource> = []

    public init() {}

    public var isEmpty: Bool { readySources.isEmpty }
    public var queuedCount: Int { queues.values.reduce(0) { $0 + $1.count } }

    public func enqueue(_ element: Element, from source: ObstacleBridgeChannelMuxEgressSource) {
        queues[source, default: []].append(element)
        if readySet.insert(source).inserted { readySources.append(source) }
    }

    public func enqueue<S: Sequence>(_ elements: S, from source: ObstacleBridgeChannelMuxEgressSource) where S.Element == Element {
        for element in elements { enqueue(element, from: source) }
    }

    /// Returns exactly one record and advances the persistent source cursor.
    public func dequeueNext() -> Element? {
        guard !readySources.isEmpty else { return nil }
        let source = readySources.removeFirst()
        readySet.remove(source)
        guard var queue = queues[source], !queue.isEmpty else { return dequeueNext() }
        let element = queue.removeFirst()
        if queue.isEmpty {
            queues.removeValue(forKey: source)
        } else {
            queues[source] = queue
            readySources.append(source)
            readySet.insert(source)
        }
        return element
    }

    public func removeAll() {
        queues.removeAll(keepingCapacity: false)
        readySources.removeAll(keepingCapacity: false)
        readySet.removeAll(keepingCapacity: false)
    }
}
