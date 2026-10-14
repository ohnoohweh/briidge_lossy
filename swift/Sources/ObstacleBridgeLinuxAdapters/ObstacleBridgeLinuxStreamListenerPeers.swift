import Foundation

/// Resource-owner accounting for stream listener peers.  It retains no peer
/// payload or credential material: only active resource identities and the
/// one-write admission bit needed to keep a slow socket from accumulating an
/// unbounded Linux-side queue.
public struct ObstacleBridgeLinuxStreamListenerSnapshot: Equatable, Sendable {
    public let activePeerCount: Int
    public let writesInFlight: Int
    public let backpressureRejections: Int
}

final class ObstacleBridgeLinuxStreamListenerPeers: @unchecked Sendable {
    private let lock = NSLock()
    private var activePeerIDs: Set<Int> = []
    private var writingPeerIDs: Set<Int> = []
    private var rejectedWrites = 0

    func add(_ peerID: Int) {
        lock.lock(); activePeerIDs.insert(peerID); lock.unlock()
    }

    /// A stream peer owns at most one synchronous write.  Rather than adding
    /// another user-space buffer, callers reject concurrent admission and let
    /// the higher ChannelMux/service owner apply stream backpressure.
    func beginWrite(_ peerID: Int) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard activePeerIDs.contains(peerID), !writingPeerIDs.contains(peerID) else {
            rejectedWrites += 1
            return false
        }
        writingPeerIDs.insert(peerID)
        return true
    }

    func finishWrite(_ peerID: Int) {
        lock.lock(); writingPeerIDs.remove(peerID); lock.unlock()
    }

    func remove(_ peerID: Int) {
        lock.lock()
        activePeerIDs.remove(peerID)
        writingPeerIDs.remove(peerID)
        lock.unlock()
    }

    var snapshot: ObstacleBridgeLinuxStreamListenerSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return .init(activePeerCount: activePeerIDs.count, writesInFlight: writingPeerIDs.count, backpressureRejections: rejectedWrites)
    }
}
