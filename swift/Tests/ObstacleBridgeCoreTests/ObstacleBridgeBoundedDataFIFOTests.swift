import Foundation
import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgeBoundedDataFIFOTests {
    @Test func dropNewestKeepsRetainedBytesBoundedAndDrainsInOrder() {
        let fifo = ObstacleBridgeBoundedDataFIFO(limits: .init(maximumItems: 2, maximumBytes: 5))
        #expect(fifo.append(Data([1, 2])))
        #expect(fifo.append(Data([3, 4, 5])))
        #expect(!fifo.append(Data([6])))
        #expect(fifo.count == 2)
        #expect(fifo.byteCount == 5)
        #expect(fifo.counters.droppedItems == 1)
        #expect(fifo.counters.droppedBytes == 1)
        #expect(fifo.popFirst() == Data([1, 2]))
        #expect(fifo.popFirst() == Data([3, 4, 5]))
        #expect(fifo.counters.retainedBytes == 0)
        #expect(fifo.counters.releasedItems == 2)
    }

    @Test func dropOldestAdmitsNewestWithinItemAndByteBounds() {
        let fifo = ObstacleBridgeBoundedDataFIFO(limits: .init(maximumItems: 2, maximumBytes: 4, overflowPolicy: .dropOldest))
        #expect(fifo.append(Data([1, 2])))
        #expect(fifo.append(Data([3, 4])))
        #expect(fifo.append(Data([5, 6])))
        #expect(fifo.count == 2)
        #expect(fifo.byteCount == 4)
        #expect(fifo.popFirst() == Data([3, 4]))
        #expect(fifo.popFirst() == Data([5, 6]))
    }

    @Test func expirationAndStopReleaseAllRetainedPayloads() {
        var clock: TimeInterval = 10
        let fifo = ObstacleBridgeBoundedDataFIFO(
            limits: .init(maximumItems: 4, maximumBytes: 16, maximumAge: 5),
            now: { clock }
        )
        #expect(fifo.append(Data([1, 2, 3])))
        clock = 16
        #expect(fifo.popFirst() == nil)
        #expect(fifo.counters.expiredItems == 1)
        #expect(fifo.counters.retainedBytes == 0)
        #expect(fifo.append(Data([4, 5])))
        #expect(fifo.append(Data([6])))
        fifo.removeAll()
        #expect(fifo.isEmpty)
        #expect(fifo.counters.retainedItems == 0)
        #expect(fifo.counters.releasedItems == 3)
    }

    @Test func keyedStoreCoalescesAndRejectsOverfill() {
        var clock: TimeInterval = 10
        let store = ObstacleBridgeBoundedKeyedDataStore<String>(
            limits: .init(maximumItems: 2, maximumBytes: 5, maximumAge: 5),
            now: { clock }
        )
        #expect(store.replace(Data([1, 2]), for: "status"))
        #expect(store.replace(Data([3, 4, 5]), for: "peers"))
        #expect(store.byteCount == 5)
        #expect(store.replace(Data([6]), for: "status"))
        #expect(store.byteCount == 4)
        #expect(!store.replace(Data([7]), for: "other"))
        #expect(store.count == 2)

        clock += 6
        #expect(store.data(for: "status") == nil)
        #expect(store.byteCount == 0)
    }
}
