import Dispatch
import Foundation
import ObstacleBridgeCore

public struct ObstacleBridgeLinuxReceiveWorkerSnapshot: Equatable, Sendable {
    public let epoch: UInt64
    public let state: String
    public let receivedFrames: Int
    public let droppedFrames: Int
    public let queueDepth: Int
    public let queuedBytes: Int
    public let lastReceivedUnixTS: TimeInterval?
    public let failureReason: String?
}

/// One receive owner for one lower-transport epoch. POSIX stream transports
/// use its reader queue; readiness-driven transports supply callbacks. In both
/// cases a bounded handoff queue keeps ChannelMux processing isolated.
public final class ObstacleBridgeLinuxReceiveWorker: @unchecked Sendable {
    private let epoch: UInt64
    private let receive: () throws -> Data
    private let asyncReceive: ((@escaping (Result<Data?, Error>) -> Void) -> Void)?
    private let cancelReceive: () -> Void
    private let sink: (UInt64, Data) -> Void
    private let onFailure: (UInt64, String) -> Void
    private let reader = DispatchQueue(label: "org.obstaclebridge.linux.receive-reader")
    private let dispatchQueue = DispatchQueue(label: "org.obstaclebridge.linux.receive-dispatch")
    private let lock = NSLock()
    private let queued: ObstacleBridgeBoundedDataFIFO
    private var stopped = true
    private var dispatching = false
    private var received = 0
    private var dropped = 0
    private var failure: String?
    private var lastReceivedUnixTS: TimeInterval?

    public init(epoch: UInt64, capacity: Int = 128, maximumQueuedBytes: Int = 2 * 1_024 * 1_024, receive: @escaping () throws -> Data, asyncReceive: ((@escaping (Result<Data?, Error>) -> Void) -> Void)? = nil, cancelReceive: @escaping () -> Void, sink: @escaping (UInt64, Data) -> Void, onFailure: @escaping (UInt64, String) -> Void = { _, _ in }) {
        self.epoch = epoch
        self.queued = .init(limits: .init(maximumItems: capacity, maximumBytes: maximumQueuedBytes, maximumAge: 60))
        self.receive = receive; self.asyncReceive = asyncReceive; self.cancelReceive = cancelReceive; self.sink = sink; self.onFailure = onFailure
    }

    public func start() {
        lock.lock(); guard stopped else { lock.unlock(); return }; stopped = false; lock.unlock()
        if asyncReceive != nil {
            armAsyncReceive()
        } else {
            reader.async { [weak self] in self?.readLoop() }
        }
    }

    public func stop() {
        lock.lock(); stopped = true; queued.removeAll(); lock.unlock()
        cancelReceive()
    }

    public func snapshot() -> ObstacleBridgeLinuxReceiveWorkerSnapshot {
        lock.lock(); defer { lock.unlock() }
        return .init(epoch: epoch, state: stopped ? "stopped" : (failure == nil ? "running" : "failed"), receivedFrames: received, droppedFrames: dropped, queueDepth: queued.count, queuedBytes: queued.byteCount, lastReceivedUnixTS: lastReceivedUnixTS, failureReason: failure)
    }

    private func readLoop() {
        while true {
            lock.lock(); let isStopped = stopped; lock.unlock(); if isStopped { return }
            do { enqueue(try receive()) }
            catch {
                let reason = error.localizedDescription
                lock.lock()
                let reportFailure = !stopped
                if reportFailure { failure = reason }
                lock.unlock()
                if reportFailure { onFailure(epoch, reason) }
                return
            }
        }
    }

    private func receiveAsyncResult(_ result: Result<Data?, Error>) {
        lock.lock(); let isStopped = stopped; lock.unlock()
        guard !isStopped else { return }
        switch result {
        case .success(let data):
            if let data { enqueue(data) }
            armAsyncReceive()
        case .failure(let error):
            let reason = error.localizedDescription
            lock.lock(); let reportFailure = !stopped; if reportFailure { failure = reason }; lock.unlock()
            if reportFailure { onFailure(epoch, reason) }
        }
    }

    /// The callback supplied by a lower transport completes one record. Keep
    /// exactly one request armed for the lifetime of this receive owner.
    private func armAsyncReceive() {
        lock.lock(); let shouldContinue = !stopped; lock.unlock()
        guard shouldContinue, let asyncReceive else { return }
        asyncReceive { [weak self] result in self?.receiveAsyncResult(result) }
    }

    private func enqueue(_ data: Data) {
        lock.lock(); defer { lock.unlock() }
        guard !stopped else { return }
        received += 1
        lastReceivedUnixTS = Date().timeIntervalSince1970
        guard queued.append(data) else { dropped += 1; return }
        guard !dispatching else { return }
        dispatching = true
        dispatchQueue.async { [weak self] in self?.drain() }
    }

    private func drain() {
        var drainedFrames = 0
        var drainedBytes = 0
        while true {
            lock.lock()
            guard !stopped, !queued.isEmpty else { dispatching = false; lock.unlock(); return }
            guard let data = queued.popFirst() else { dispatching = false; lock.unlock(); return }
            lock.unlock()
            sink(epoch, data)
            drainedFrames += 1
            drainedBytes += data.count
            if drainedFrames >= 64 || drainedBytes >= 2 * 1_024 * 1_024 {
                lock.lock()
                guard !stopped, !queued.isEmpty else { dispatching = false; lock.unlock(); return }
                dispatchQueue.async { [weak self] in self?.drain() }
                lock.unlock()
                return
            }
        }
    }
}
