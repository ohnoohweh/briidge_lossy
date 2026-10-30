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
        #expect(worker.snapshot().lastReceivedUnixTS != nil)
        #expect(worker.snapshot().state == "stopped")
    }

    @Test func asyncWorkerRearmsAfterEachDeliveredFrame() {
        let source = AsyncReceiveSource()
        let delivered = DispatchSemaphore(value: 0)
        let values = LockedValues()
        let worker = ObstacleBridgeLinuxReceiveWorker(
            epoch: 9,
            receive: { throw WorkerError.stopped },
            asyncReceive: source.register,
            cancelReceive: {},
            sink: { epoch, data in
                values.append((epoch, data))
                delivered.signal()
            }
        )

        worker.start()
        #expect(source.waitForRegistration(timeout: 2))
        source.completeNext(.success(Data("one".utf8)))
        #expect(delivered.wait(timeout: .now() + 2) == .success)
        #expect(source.waitForRegistration(timeout: 2))
        source.completeNext(.success(Data("two".utf8)))
        #expect(delivered.wait(timeout: .now() + 2) == .success)
        worker.stop()

        #expect(values.all.count == 2)
        #expect(values.all[0].0 == 9)
        #expect(values.all[0].1 == Data("one".utf8))
        #expect(values.all[1].0 == 9)
        #expect(values.all[1].1 == Data("two".utf8))
        #expect(source.registrations >= 3)
    }

    private enum WorkerError: Error { case stopped }
}

private final class LockedValues: @unchecked Sendable {
    private let lock = NSLock(); private var values: [(UInt64, Data)] = []
    var all: [(UInt64, Data)] { lock.lock(); defer { lock.unlock() }; return values }
    func append(_ value: (UInt64, Data)) { lock.lock(); values.append(value); lock.unlock() }
}

private final class AsyncReceiveSource: @unchecked Sendable {
    private let lock = NSLock()
    private let registered = DispatchSemaphore(value: 0)
    private var callbacks: [(Result<Data?, Error>) -> Void] = []
    private var registrationCount = 0
    var registrations: Int { lock.lock(); defer { lock.unlock() }; return registrationCount }

    func register(_ callback: @escaping (Result<Data?, Error>) -> Void) {
        lock.lock()
        callbacks.append(callback)
        registrationCount += 1
        lock.unlock()
        registered.signal()
    }

    func waitForRegistration(timeout: TimeInterval) -> Bool {
        registered.wait(timeout: .now() + timeout) == .success
    }

    func completeNext(_ result: Result<Data?, Error>) {
        lock.lock()
        let callback = callbacks.removeFirst()
        lock.unlock()
        callback(result)
    }
}
