import Foundation
import ObstacleBridgePortable

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
    private var inFlight = false

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
        guard !inFlight else { throw ObstacleBridgeLinuxChannelMuxError.tooManyInFlightFrames }
        inFlight = true
        defer { inFlight = false }
        let wire = try ObstacleBridgeChannelMuxCodec.encode(channelID: frame.channelID, protocolType: frame.protocolType, counter: frame.counter, messageType: frame.messageType, body: frame.body)
        return try ObstacleBridgeChannelMuxCodec.decode(session.send(wire))
    }
}
