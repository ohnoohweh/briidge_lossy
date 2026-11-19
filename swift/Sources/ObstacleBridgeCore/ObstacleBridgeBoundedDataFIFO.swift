import Foundation

/// A serial-owner FIFO for payloads that must survive an asynchronous boundary.
///
/// It makes the retention contract explicit: data is bounded by count and
/// logical bytes, optionally expires before it can be consumed, and has a
/// deterministic overload policy.  Instances are deliberately not internally
/// synchronized; the owning actor or serial DispatchQueue provides that
/// synchronization and keeps the fast packet path allocation-free apart from
/// the payload itself.
public final class ObstacleBridgeBoundedFIFO<Element> {
    public enum OverflowPolicy: Sendable {
        /// Preserve already accepted order and shed the arriving payload.
        case dropNewest
        /// Make room for the arriving payload by shedding oldest payloads.
        case dropOldest
    }

    public struct Limits: Sendable {
        public let maximumItems: Int
        public let maximumBytes: Int
        public let maximumAge: TimeInterval?
        public let overflowPolicy: OverflowPolicy

        public init(
            maximumItems: Int,
            maximumBytes: Int,
            maximumAge: TimeInterval? = nil,
            overflowPolicy: OverflowPolicy = .dropNewest
        ) {
            self.maximumItems = max(1, maximumItems)
            self.maximumBytes = max(1, maximumBytes)
            self.maximumAge = maximumAge.map { max(0, $0) }
            self.overflowPolicy = overflowPolicy
        }
    }

    public struct Counters: Equatable, Sendable {
        public let retainedItems: Int
        public let retainedBytes: Int
        public let peakRetainedItems: Int
        public let peakRetainedBytes: Int
        public let acceptedItems: Int
        public let acceptedBytes: Int
        public let releasedItems: Int
        public let releasedBytes: Int
        public let droppedItems: Int
        public let droppedBytes: Int
        public let expiredItems: Int
        public let expiredBytes: Int
    }

    private struct Entry {
        let element: Element
        let enqueuedAt: TimeInterval
    }

    public let limits: Limits
    private let now: () -> TimeInterval
    private let byteCountForElement: (Element) -> Int
    private var entries: [Entry] = []
    private var retainedBytes = 0
    private var peakRetainedItems = 0
    private var peakRetainedBytes = 0
    private var acceptedItems = 0
    private var acceptedBytes = 0
    private var releasedItems = 0
    private var releasedBytes = 0
    private var droppedItems = 0
    private var droppedBytes = 0
    private var expiredItems = 0
    private var expiredBytes = 0

    public init(
        limits: Limits,
        byteCount: @escaping (Element) -> Int,
        now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }
    ) {
        self.limits = limits
        self.byteCountForElement = byteCount
        self.now = now
    }

    public var isEmpty: Bool { entries.isEmpty }
    public var count: Int { entries.count }
    public var byteCount: Int { retainedBytes }

    public var counters: Counters {
        .init(
            retainedItems: entries.count,
            retainedBytes: retainedBytes,
            peakRetainedItems: peakRetainedItems,
            peakRetainedBytes: peakRetainedBytes,
            acceptedItems: acceptedItems,
            acceptedBytes: acceptedBytes,
            releasedItems: releasedItems,
            releasedBytes: releasedBytes,
            droppedItems: droppedItems,
            droppedBytes: droppedBytes,
            expiredItems: expiredItems,
            expiredBytes: expiredBytes
        )
    }

    /// Returns false when the payload is deliberately shed under this FIFO's
    /// declared overload policy. Empty payloads are valid retained items.
    @discardableResult
    public func append(_ element: Element) -> Bool {
        discardExpired()
        let bytes = max(0, byteCountForElement(element))
        guard bytes <= limits.maximumBytes else {
            recordDrop(element)
            return false
        }
        if limits.overflowPolicy == .dropOldest {
            while !entries.isEmpty && (entries.count >= limits.maximumItems || retainedBytes + bytes > limits.maximumBytes) {
                release(entries.removeFirst(), expired: false)
            }
        }
        guard entries.count < limits.maximumItems, retainedBytes + bytes <= limits.maximumBytes else {
            recordDrop(element)
            return false
        }
        entries.append(.init(element: element, enqueuedAt: now()))
        retainedBytes += bytes
        acceptedItems += 1
        acceptedBytes += bytes
        peakRetainedItems = max(peakRetainedItems, entries.count)
        peakRetainedBytes = max(peakRetainedBytes, retainedBytes)
        return true
    }

    /// Restores a payload after a failed hand-off. Normal owners call this only
    /// immediately after `popFirst`, so it cannot silently grow retention.
    @discardableResult
    public func prepend(_ element: Element) -> Bool {
        discardExpired()
        let bytes = max(0, byteCountForElement(element))
        guard bytes <= limits.maximumBytes,
              entries.count < limits.maximumItems,
              retainedBytes + bytes <= limits.maximumBytes else {
            recordDrop(element)
            return false
        }
        entries.insert(.init(element: element, enqueuedAt: now()), at: 0)
        retainedBytes += bytes
        acceptedItems += 1
        acceptedBytes += bytes
        peakRetainedItems = max(peakRetainedItems, entries.count)
        peakRetainedBytes = max(peakRetainedBytes, retainedBytes)
        return true
    }

    /// Removes the oldest surviving payload and transfers ownership to caller.
    public func popFirst() -> Element? {
        discardExpired()
        guard !entries.isEmpty else { return nil }
        let entry = entries.removeFirst()
        let bytes = max(0, byteCountForElement(entry.element))
        retainedBytes -= bytes
        releasedItems += 1
        releasedBytes += bytes
        return entry.element
    }

    /// Transfers all surviving FIFO elements to the caller in FIFO order.
    public func drainAll() -> [Element] {
        discardExpired()
        var drained: [Element] = []
        drained.reserveCapacity(entries.count)
        while let element = popFirst() { drained.append(element) }
        return drained
    }

    /// Returns a stable view without transferring ownership. Snapshot owners
    /// use this for deliberately replayable, still-bounded configuration.
    public func snapshot() -> [Element] {
        discardExpired()
        return entries.map(\.element)
    }

    /// Releases all retained payloads. This is required at stop/disconnect
    /// boundaries, even when an owner is about to be discarded.
    public func removeAll(keepingCapacity: Bool = false) {
        discardExpired()
        for entry in entries { release(entry, expired: false) }
        entries.removeAll(keepingCapacity: keepingCapacity)
        retainedBytes = 0
    }

    private func discardExpired() {
        guard let maximumAge = limits.maximumAge else { return }
        let cutoff = now() - maximumAge
        while let entry = entries.first, entry.enqueuedAt <= cutoff {
            release(entries.removeFirst(), expired: true)
        }
    }

    private func release(_ entry: Entry, expired: Bool) {
        let bytes = max(0, byteCountForElement(entry.element))
        retainedBytes -= bytes
        releasedItems += 1
        releasedBytes += bytes
        if expired {
            expiredItems += 1
            expiredBytes += bytes
        }
    }

    private func recordDrop(_ element: Element) {
        droppedItems += 1
        droppedBytes += max(0, byteCountForElement(element))
    }
}

public typealias ObstacleBridgeBoundedDataFIFO = ObstacleBridgeBoundedFIFO<Data>

public extension ObstacleBridgeBoundedFIFO where Element == Data {
    convenience init(limits: Limits, now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.init(limits: limits, byteCount: \.count, now: now)
    }
}

/// A serial-owner bounded store for coalesced snapshots. Unlike a FIFO, a
/// newer value for the same key replaces its predecessor without retaining an
/// event history. It is for the few protocols where "latest state per topic"
/// is the required delivery semantic.
public final class ObstacleBridgeBoundedKeyedDataStore<Key: Hashable> {
    private struct Entry {
        let data: Data
        let storedAt: TimeInterval
    }

    public let limits: ObstacleBridgeBoundedFIFO<Data>.Limits
    private let now: () -> TimeInterval
    private var entries: [Key: Entry] = [:]
    private var retainedBytes = 0

    public init(
        limits: ObstacleBridgeBoundedFIFO<Data>.Limits,
        now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }
    ) {
        self.limits = limits
        self.now = now
    }

    public var count: Int { entries.count }
    public var byteCount: Int { retainedBytes }

    public func data(for key: Key) -> Data? {
        discardExpired()
        return entries[key]?.data
    }

    /// Replaces a coalesced value only when the resulting store remains inside
    /// its declared item and byte limits. A rejected value is never retained.
    @discardableResult
    public func replace(_ data: Data, for key: Key) -> Bool {
        discardExpired()
        let previousBytes = entries[key]?.data.count ?? 0
        guard data.count <= limits.maximumBytes,
              entries[key] != nil || entries.count < limits.maximumItems,
              retainedBytes - previousBytes + data.count <= limits.maximumBytes else {
            return false
        }
        entries[key] = .init(data: data, storedAt: now())
        retainedBytes = retainedBytes - previousBytes + data.count
        return true
    }

    @discardableResult
    public func removeValue(forKey key: Key) -> Data? {
        discardExpired()
        guard let entry = entries.removeValue(forKey: key) else { return nil }
        retainedBytes -= entry.data.count
        return entry.data
    }

    public func removeAll(keepingCapacity: Bool = false) {
        entries.removeAll(keepingCapacity: keepingCapacity)
        retainedBytes = 0
    }

    private func discardExpired() {
        guard let maximumAge = limits.maximumAge else { return }
        let cutoff = now() - maximumAge
        for (key, entry) in entries where entry.storedAt <= cutoff {
            entries.removeValue(forKey: key)
            retainedBytes -= entry.data.count
        }
    }
}
