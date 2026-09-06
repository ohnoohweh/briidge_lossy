import Dispatch
import Foundation

public struct ObstacleBridgeLinuxReceiveWorkerSnapshot: Equatable, Sendable {
    public let epoch: UInt64
    public let state: String
    public let receivedFrames: Int
    public let droppedFrames: Int
    public let queueDepth: Int
    public let failureReason: String?
}

/// One blocking reader for one lower-transport epoch. The worker never invokes
/// its sink on the reader queue: a bounded handoff queue keeps descriptor reads
/// isolated from ChannelMux processing and cancellation is epoch-scoped.
public final class ObstacleBridgeLinuxReceiveWorker: @unchecked Sendable {
    private let epoch: UInt64
    private let receive: () throws -> Data
    private let cancelReceive: () -> Void
    private let sink: (UInt64, Data) -> Void
    private let reader = DispatchQueue(label: "org.obstaclebridge.linux.receive-reader")
    private let dispatchQueue = DispatchQueue(label: "org.obstaclebridge.linux.receive-dispatch")
    private let lock = NSLock()
    private let capacity: Int
    private var queued: [Data] = []
    private var stopped = true
    private var dispatching = false
    private var received = 0
    private var dropped = 0
    private var failure: String?

    public init(epoch: UInt64, capacity: Int = 128, receive: @escaping () throws -> Data, cancelReceive: @escaping () -> Void, sink: @escaping (UInt64, Data) -> Void) {
        self.epoch = epoch; self.capacity = max(1, capacity); self.receive = receive; self.cancelReceive = cancelReceive; self.sink = sink
    }

    public func start() {
        lock.lock(); guard stopped else { lock.unlock(); return }; stopped = false; lock.unlock()
        reader.async { [weak self] in self?.readLoop() }
    }

    public func stop() {
        lock.lock(); stopped = true; queued.removeAll(); lock.unlock()
        cancelReceive()
    }

    public func snapshot() -> ObstacleBridgeLinuxReceiveWorkerSnapshot {
        lock.lock(); defer { lock.unlock() }
        return .init(epoch: epoch, state: stopped ? "stopped" : (failure == nil ? "running" : "failed"), receivedFrames: received, droppedFrames: dropped, queueDepth: queued.count, failureReason: failure)
    }

    private func readLoop() {
        while true {
            lock.lock(); let isStopped = stopped; lock.unlock(); if isStopped { return }
            do { enqueue(try receive()) }
            catch {
                lock.lock(); if !stopped { failure = error.localizedDescription }; lock.unlock()
                return
            }
        }
    }

    private func enqueue(_ data: Data) {
        lock.lock(); defer { lock.unlock() }
        guard !stopped else { return }
        received += 1
        guard queued.count < capacity else { dropped += 1; return }
        queued.append(data)
        guard !dispatching else { return }
        dispatching = true
        dispatchQueue.async { [weak self] in self?.drain() }
    }

    private func drain() {
        while true {
            lock.lock()
            guard !stopped, !queued.isEmpty else { dispatching = false; lock.unlock(); return }
            let data = queued.removeFirst(); lock.unlock()
            sink(epoch, data)
        }
    }
}
