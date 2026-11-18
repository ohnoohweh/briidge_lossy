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
/// The enclosing transport owner serializes scheduler access. This type stays
/// non-Sendable so a queue cannot be transferred independently of that owner.
public final class ObstacleBridgeChannelMuxEgressSequencer<Element> {
    // OBSTACLEBRIDGE-CONCURRENCY: lock; test=ObstacleBridgeChannelMuxEgressSequencerTests
    // Linux service owners and Apple framework callbacks may enqueue on a
    // different executor while a transport drain is in flight.  The owner
    // normally serializes those calls, but that is not a memory-safety
    // contract: native Set/Dictionary mutation must remain protected during
    // handoff and shutdown as well.
    private let lock = NSLock()
    private var queues: [ObstacleBridgeChannelMuxEgressSource: [Element]] = [:]
    private var readySources: [ObstacleBridgeChannelMuxEgressSource] = []
    private var readySet: Set<ObstacleBridgeChannelMuxEgressSource> = []
    private let byteCount: ((Element) -> Int)?
    private let maximumQueuedElements: Int
    private let maximumQueuedBytes: Int
    private var queuedBytes = 0
    private var droppedElements = 0

    public init(
        byteCount: ((Element) -> Int)? = nil,
        maximumQueuedElements: Int = 512,
        maximumQueuedBytes: Int = 2 * 1_024 * 1_024
    ) {
        self.byteCount = byteCount
        self.maximumQueuedElements = max(1, maximumQueuedElements)
        self.maximumQueuedBytes = max(1, maximumQueuedBytes)
    }

    public var isEmpty: Bool {
        lock.lock(); defer { lock.unlock() }
        return readySources.isEmpty
    }

    public var queuedCount: Int {
        lock.lock(); defer { lock.unlock() }
        return queues.values.reduce(0) { $0 + $1.count }
    }

    public var droppedCount: Int {
        lock.lock(); defer { lock.unlock() }
        return droppedElements
    }

    /// Bounds retained application frames when an overlay cannot transmit at
    /// line rate.  Callers intentionally shed the newest TUN frame on
    /// overload: allowing an unbounded heap queue would kill the extension.
    @discardableResult
    public func enqueue(_ element: Element, from source: ObstacleBridgeChannelMuxEgressSource) -> Bool {
        lock.lock(); defer { lock.unlock() }
        let bytes = elementByteCount(element)
        guard elementCountLocked() < maximumQueuedElements,
              queuedBytes + bytes <= maximumQueuedBytes else {
            droppedElements += 1
            return false
        }
        queues[source, default: []].append(element)
        queuedBytes += bytes
        if readySet.insert(source).inserted { readySources.append(source) }
        return true
    }

    @discardableResult
    public func enqueue<S: Sequence>(_ elements: S, from source: ObstacleBridgeChannelMuxEgressSource) -> Int where S.Element == Element {
        lock.lock(); defer { lock.unlock() }
        var appended = 0
        for element in elements {
            let bytes = elementByteCount(element)
            guard elementCountLocked() < maximumQueuedElements,
                  queuedBytes + bytes <= maximumQueuedBytes else {
                droppedElements += 1
                continue
            }
            queues[source, default: []].append(element)
            queuedBytes += bytes
            appended += 1
        }
        if appended > 0, readySet.insert(source).inserted {
            readySources.append(source)
        }
        return appended
    }

    /// Returns exactly one record and advances the persistent source cursor.
    public func dequeueNext() -> Element? {
        lock.lock(); defer { lock.unlock() }
        while !readySources.isEmpty {
            let source = readySources.removeFirst()
            readySet.remove(source)
            guard var queue = queues[source], !queue.isEmpty else { continue }
            let element = queue.removeFirst()
            queuedBytes = max(0, queuedBytes - elementByteCount(element))
            if queue.isEmpty {
                queues.removeValue(forKey: source)
            } else {
                queues[source] = queue
                readySources.append(source)
                readySet.insert(source)
            }
            return element
        }
        return nil
    }

    public func removeAll() {
        lock.lock(); defer { lock.unlock() }
        queues.removeAll(keepingCapacity: false)
        readySources.removeAll(keepingCapacity: false)
        readySet.removeAll(keepingCapacity: false)
        queuedBytes = 0
    }

    private func elementCountLocked() -> Int {
        queues.values.reduce(0) { $0 + $1.count }
    }

    private func elementByteCount(_ element: Element) -> Int {
        max(0, byteCount?(element) ?? 0)
    }

}
