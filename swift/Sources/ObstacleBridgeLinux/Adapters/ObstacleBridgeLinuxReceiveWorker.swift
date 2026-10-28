import Dispatch
import Foundation

public struct ObstacleBridgeLinuxReceiveWorkerSnapshot: Equatable, Sendable {
    public let epoch: UInt64
    public let state: String
    public let receivedFrames: Int
    public let droppedFrames: Int
    public let queueDepth: Int
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
    private let capacity: Int
    private var queued: [Data] = []
    private var stopped = true
    private var dispatching = false
    private var received = 0
    private var dropped = 0
    private var failure: String?
    private var lastReceivedUnixTS: TimeInterval?

    public init(epoch: UInt64, capacity: Int = 128, receive: @escaping () throws -> Data, asyncReceive: ((@escaping (Result<Data?, Error>) -> Void) -> Void)? = nil, cancelReceive: @escaping () -> Void, sink: @escaping (UInt64, Data) -> Void, onFailure: @escaping (UInt64, String) -> Void = { _, _ in }) {
        self.epoch = epoch; self.capacity = max(1, capacity); self.receive = receive; self.asyncReceive = asyncReceive; self.cancelReceive = cancelReceive; self.sink = sink; self.onFailure = onFailure
    }

    public func start() {
        lock.lock(); guard stopped else { lock.unlock(); return }; stopped = false; lock.unlock()
        if let asyncReceive {
            asyncReceive { [weak self] result in self?.receiveAsyncResult(result) }
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
        return .init(epoch: epoch, state: stopped ? "stopped" : (failure == nil ? "running" : "failed"), receivedFrames: received, droppedFrames: dropped, queueDepth: queued.count, lastReceivedUnixTS: lastReceivedUnixTS, failureReason: failure)
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
        case .failure(let error):
            let reason = error.localizedDescription
            lock.lock(); let reportFailure = !stopped; if reportFailure { failure = reason }; lock.unlock()
            if reportFailure { onFailure(epoch, reason) }
        }
    }

    private func enqueue(_ data: Data) {
        lock.lock(); defer { lock.unlock() }
        guard !stopped else { return }
        received += 1
        lastReceivedUnixTS = Date().timeIntervalSince1970
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
