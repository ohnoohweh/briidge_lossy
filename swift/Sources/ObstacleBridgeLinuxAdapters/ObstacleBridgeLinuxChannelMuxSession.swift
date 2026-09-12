import Foundation
import ObstacleBridgeCore

public enum ObstacleBridgeLinuxChannelMuxError: Error, Equatable {
    case notReady
    case staleEpoch
    case tooManyInFlightFrames
}

/// The Linux admission boundary for ChannelMux frames. It deliberately keeps
/// only one synchronous frame in flight, which bounds memory until the full
/// queue/backpressure runtime is introduced with TUN ownership.
public final class ObstacleBridgeLinuxChannelMuxSession {
    private let runtime: ObstacleBridgeLinuxConfiguredRuntime
    private let session: ObstacleBridgeLinuxConfiguredSession
    private let epoch: UInt64
    private let lock = NSLock()
    private var inFlight = false
    private var receiveOwnerActive = false
    private var awaited: ObstacleBridgeChannelMuxFrame?
    private var reply: ObstacleBridgeChannelMuxFrame?
    private var replySignal: DispatchSemaphore?
    public var onUnsolicitedFrame: ((ObstacleBridgeChannelMuxFrame) -> Void)?

    public init(runtime: ObstacleBridgeLinuxConfiguredRuntime, session: ObstacleBridgeLinuxConfiguredSession, startupFrames: [ObstacleBridgeChannelMuxFrame] = []) throws {
        guard runtime.status().appReady else { throw ObstacleBridgeLinuxChannelMuxError.notReady }
        self.runtime = runtime
        self.session = session
        self.epoch = runtime.connectionEpoch
        for frame in startupFrames {
            guard try exchange(frame) == frame else { throw ObstacleBridgeLinuxChannelMuxError.staleEpoch }
        }
    }

    public func exchange(_ frame: ObstacleBridgeChannelMuxFrame) throws -> ObstacleBridgeChannelMuxFrame {
        guard runtime.connectionEpoch == epoch, runtime.status().appReady else { throw ObstacleBridgeLinuxChannelMuxError.staleEpoch }
        lock.lock()
        guard !inFlight else { throw ObstacleBridgeLinuxChannelMuxError.tooManyInFlightFrames }
        inFlight = true
        let duplex = receiveOwnerActive
        let signal = duplex ? DispatchSemaphore(value: 0) : nil
        if duplex { awaited = frame; reply = nil; replySignal = signal }
        lock.unlock()
        defer {
            lock.lock(); inFlight = false; awaited = nil; replySignal = nil; lock.unlock()
        }
        let wire = try ObstacleBridgeChannelMuxCodec.encode(channelID: frame.channelID, protocolType: frame.protocolType, counter: frame.counter, messageType: frame.messageType, body: frame.body)
        if !duplex { return try ObstacleBridgeChannelMuxCodec.decode(session.send(wire)) }
        try session.sendOneWay(wire)
        guard signal?.wait(timeout: .now() + 10) == .success else { throw ObstacleBridgeLinuxChannelMuxError.staleEpoch }
        lock.lock(); let value = reply; lock.unlock()
        guard let value else { throw ObstacleBridgeLinuxChannelMuxError.staleEpoch }
        return value
    }

    /// Sends a frame whose result is expected to arrive asynchronously (for
    /// example a service OPEN/DATA exchange).  A live duplex peer must not be
    /// forced into the legacy request/reply matcher merely because it has no
    /// immediate ChannelMux acknowledgement to send.
    public func sendUnsolicited(_ frame: ObstacleBridgeChannelMuxFrame) throws {
        guard runtime.connectionEpoch == epoch, runtime.status().appReady else { throw ObstacleBridgeLinuxChannelMuxError.staleEpoch }
        let wire = try ObstacleBridgeChannelMuxCodec.encode(channelID: frame.channelID, protocolType: frame.protocolType, counter: frame.counter, messageType: frame.messageType, body: frame.body)
        try session.sendOneWay(wire)
    }

    /// Marks this mux as driven by the one live receive owner. Once enabled,
    /// request/reply compatibility waits on that owner instead of reading the
    /// lower descriptor a second time.
    public func activateReceiveOwner() {
        lock.lock(); receiveOwnerActive = true; lock.unlock()
    }

    /// Called only by the configured session's receive worker after it has
    /// authenticated and decoded a complete ChannelMux record.
    public func receive(_ frame: ObstacleBridgeChannelMuxFrame) {
        lock.lock()
        if let awaited, framesMatchReply(frame, awaited) {
            reply = frame
            let signal = replySignal
            lock.unlock()
            signal?.signal()
            return
        }
        let handler = onUnsolicitedFrame
        lock.unlock()
        handler?(frame)
    }

    private func framesMatchReply(_ inbound: ObstacleBridgeChannelMuxFrame, _ outbound: ObstacleBridgeChannelMuxFrame) -> Bool {
        inbound.channelID == outbound.channelID && inbound.protocolType == outbound.protocolType && inbound.counter == outbound.counter
    }
}
