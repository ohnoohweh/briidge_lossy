import Foundation

/// State machine used by an Apple HTTPS transport. It owns no sockets, so all
/// DNS, TLS, and request work remains outside producer and packet callbacks.
public final class ObstacleBridgeTelemetryUploadPolicy: @unchecked Sendable {
    public struct Request: Sendable { public let endpoint: URL; public let payload: Data; public let installationID: String; public let sessionID: String; public let firstSequence: UInt64; public let lastSequence: UInt64 }
    private let spool: ObstacleBridgeTelemetrySpool
    private let endpoint: URL
    private let clock: () -> TimeInterval
    private let random: () -> Double
    private let budget: Int
    private let gate = DispatchSemaphore(value: 1)
    private var inFlight: Request?
    private var sentBytes = 0
    private var nextAttempt = 0.0
    private var backoff = 1.0

    public init(spool: ObstacleBridgeTelemetrySpool, endpoint: URL, byteBudgetPerDay: Int = 8 * 1024 * 1024, clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }, random: @escaping () -> Double = { Double.random(in: 0...1) }) throws {
        guard endpoint.scheme?.lowercased() == "https" else { throw ObstacleBridgeTelemetryError.invalidBatch }
        self.spool = spool; self.endpoint = endpoint; self.budget = max(1024, byteBudgetPerDay); self.clock = clock; self.random = random
    }

    public func nextRequest() -> Request? {
        guard gate.wait(timeout: .now()) == .success else { return nil }; defer { gate.signal() }
        guard inFlight == nil, clock() >= nextAttempt else { return nil }
        let recovered = spool.recover()
        guard let first = recovered.first else { return nil }
        let events = recovered.prefix { $0.installationID == first.installationID && $0.sessionID == first.sessionID }
        guard let batch = try? ObstacleBridgeTelemetryBatch(events: Array(events)), let data = try? ObstacleBridgeTelemetry.encode(batch: batch), sentBytes + data.count <= budget, let last = events.last else { return nil }
        let request = Request(endpoint: endpoint, payload: data, installationID: first.installationID, sessionID: first.sessionID, firstSequence: first.sequence, lastSequence: last.sequence)
        inFlight = request; return request
    }

    @discardableResult public func accept(acceptedThrough: UInt64) -> Int {
        guard gate.wait(timeout: .now()) == .success else { return 0 }; defer { gate.signal() }
        guard let request = inFlight, acceptedThrough >= request.firstSequence, acceptedThrough <= request.lastSequence else { return 0 }
        let removed = spool.acknowledge(through: acceptedThrough, installationID: request.installationID, sessionID: request.sessionID)
        sentBytes += request.payload.count; inFlight = nil; nextAttempt = clock(); backoff = 1
        return removed
    }

    public func fail() {
        guard gate.wait(timeout: .now()) == .success else { return }; defer { gate.signal() }
        inFlight = nil; nextAttempt = clock() + backoff + random() * backoff * 0.2; backoff = min(300, backoff * 2)
    }

    public func statusSnapshot() -> [String: Any] {
        guard gate.wait(timeout: .now()) == .success else { return ["available": false] }
        defer { gate.signal() }
        let now = clock()
        return [
            "available": true,
            "in_flight": inFlight != nil,
            "sent_bytes": sentBytes,
            "backoff_remaining_sec": max(0, nextAttempt - now),
        ]
    }
}
