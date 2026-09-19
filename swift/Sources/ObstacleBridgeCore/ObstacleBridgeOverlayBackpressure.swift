import Foundation

/// Portable bounded-overlay egress accounting. Adapters supply native queue
/// counts and timer values; Core owns the window rollover and redacted policy
/// projection used by every consumer.
public struct ObstacleBridgeOverlayBackpressureState: Equatable, Sendable {
    public var windowStartNS: UInt64?
    public var previousBytes: Int
    public var currentBytes: Int

    public init(windowStartNS: UInt64? = nil, previousBytes: Int = 0, currentBytes: Int = 0) {
        self.windowStartNS = windowStartNS
        self.previousBytes = max(0, previousBytes)
        self.currentBytes = max(0, currentBytes)
    }
}

public struct ObstacleBridgeOverlayBackpressureSnapshot: Equatable, Sendable {
    public let waitingCount: Int
    public let inflight: Int
    public let maxInflight: Int
    public let transmitDelayEstMS: Double
    public let previousWindowBytes: Int
    public let currentWindowBytes: Int
    public let stalled: Bool
}

public enum ObstacleBridgeOverlayBackpressurePolicy {
    public static func recordEgress(bytes: Int, state: inout ObstacleBridgeOverlayBackpressureState, nowNS: UInt64 = DispatchTime.now().uptimeNanoseconds) {
        guard bytes > 0 else { return }
        let windowNS: UInt64 = 1_000_000_000
        if state.windowStartNS == nil {
            state.windowStartNS = nowNS
        } else if let start = state.windowStartNS, nowNS >= start + windowNS {
            state.previousBytes = state.currentBytes
            state.currentBytes = 0
            state.windowStartNS = nowNS
        }
        state.currentBytes += bytes
    }

    public static func snapshot(
        waitingCount: Int,
        inflight: Int,
        maxInflight: Int,
        state: ObstacleBridgeOverlayBackpressureState,
        transmitDelayEstMS: Double = 0.0,
        stalled: Bool = false
    ) -> ObstacleBridgeOverlayBackpressureSnapshot {
        .init(
            waitingCount: max(0, waitingCount),
            inflight: max(0, inflight),
            maxInflight: max(0, maxInflight),
            transmitDelayEstMS: max(0.0, transmitDelayEstMS),
            previousWindowBytes: max(0, state.previousBytes),
            currentWindowBytes: max(0, state.currentBytes),
            stalled: stalled
        )
    }
}
