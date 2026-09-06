import Dispatch
import Foundation
import Testing
@testable import ObstacleBridgeLinuxAdapters

struct ObstacleBridgeLinuxReceiveWorkerTests {
    @Test func workerDeliversEpochTaggedFramesAndCancelsBlockingReceive() {
        let gate = DispatchSemaphore(value: 0)
        let delivered = DispatchSemaphore(value: 0)
        let values = LockedValues()
        var first = true
        let worker = ObstacleBridgeLinuxReceiveWorker(epoch: 7, capacity: 1, receive: {
            if first { first = false; return Data("one".utf8) }
            gate.wait()
            throw WorkerError.stopped
        }, cancelReceive: { gate.signal() }, sink: { epoch, data in
            values.append((epoch, data)); delivered.signal()
        })
        worker.start()
        #expect(delivered.wait(timeout: .now() + 2) == .success)
        worker.stop()
        #expect(values.all.count == 1)
        #expect(values.all.first?.0 == 7)
        #expect(values.all.first?.1 == Data("one".utf8))
        #expect(worker.snapshot().state == "stopped")
    }

    private enum WorkerError: Error { case stopped }
}

private final class LockedValues: @unchecked Sendable {
    private let lock = NSLock(); private var values: [(UInt64, Data)] = []
    var all: [(UInt64, Data)] { lock.lock(); defer { lock.unlock() }; return values }
    func append(_ value: (UInt64, Data)) { lock.lock(); values.append(value); lock.unlock() }
}
