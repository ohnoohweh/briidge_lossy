import Foundation

public enum ObstacleBridgeChannelMuxReplyPolicyError: Error, Equatable, Sendable { case tooManyInFlightFrames }

/// Portable one-request admission and reply matcher. Platform adapters retain
/// waits and transport I/O; this type owns the matching state and policy.
public final class ObstacleBridgeChannelMuxReplyPolicy: @unchecked Sendable {
    private let lock = NSLock()
    private var inFlight = false
    private var receiveOwnerActive = false
    private var awaited: ObstacleBridgeChannelMuxFrame?

    public init() {}

    public func beginExchange(_ frame: ObstacleBridgeChannelMuxFrame) throws -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !inFlight else { throw ObstacleBridgeChannelMuxReplyPolicyError.tooManyInFlightFrames }
        inFlight = true
        if receiveOwnerActive { awaited = frame }
        return receiveOwnerActive
    }

    public func finishExchange() {
        lock.lock(); inFlight = false; awaited = nil; lock.unlock()
    }

    public func activateReceiveOwner() { lock.lock(); receiveOwnerActive = true; lock.unlock() }

    public func matchesAwaitedReply(_ inbound: ObstacleBridgeChannelMuxFrame) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard let awaited else { return false }
        return inbound.channelID == awaited.channelID && inbound.protocolType == awaited.protocolType && inbound.counter == awaited.counter
    }
}
