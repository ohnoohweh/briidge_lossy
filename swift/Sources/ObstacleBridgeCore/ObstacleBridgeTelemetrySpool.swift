import Crypto
import Foundation

/// Fixed-capacity producer for telemetry events. `emit` uses an immediate
/// semaphore acquisition: contention and saturation are loss signals, never a
/// reason to wait on a bridge or packet callback.
public final class ObstacleBridgeTelemetryEmitter: @unchecked Sendable {
    private let gate = DispatchSemaphore(value: 1)
    private let installationID: String
    private let sessionID: String
    private let capacity: Int
    private var nextSequence: UInt64 = 0
    private var pending: [ObstacleBridgeTelemetryEvent] = []
    public private(set) var dropped: [String: UInt64] = [:]

    public init(installationID: String, sessionID: String, capacity: Int = 256) throws {
        guard !installationID.isEmpty, installationID.count <= ObstacleBridgeTelemetry.maximumIdentifierLength,
              !sessionID.isEmpty, sessionID.count <= ObstacleBridgeTelemetry.maximumIdentifierLength
        else { throw ObstacleBridgeTelemetryError.invalidEvent }
        self.installationID = installationID
        self.sessionID = sessionID
        self.capacity = max(1, capacity)
    }

    @discardableResult
    public func emit(event: String, fields: [String: ObstacleBridgeTelemetryFieldValue] = [:], priority: ObstacleBridgeTelemetryPriority = .normal, monotonicNanoseconds: UInt64 = DispatchTime.now().uptimeNanoseconds, wallTime: Double = Date().timeIntervalSince1970) -> Bool {
        guard gate.wait(timeout: .now()) == .success else { return false }
        defer { gate.signal() }
        nextSequence &+= 1
        guard let candidate = try? ObstacleBridgeTelemetryEvent(
            installationID: installationID, sessionID: sessionID, sequence: nextSequence,
            monotonicNanoseconds: monotonicNanoseconds, wallTime: wallTime,
            priority: priority, event: event, fields: fields
        ), (try? ObstacleBridgeTelemetry.encode(event: candidate)) != nil else {
            increment("invalid_event")
            return false
        }
        if pending.count >= capacity {
            if priority == .critical, let low = pending.firstIndex(where: { $0.priority == .low }) {
                pending.remove(at: low); increment("evicted_low")
            } else { increment("queue_full"); return false }
        }
        pending.append(candidate)
        return true
    }

    public func drain(limit: Int = ObstacleBridgeTelemetry.maximumBatchEvents) -> [ObstacleBridgeTelemetryEvent] {
        guard gate.wait(timeout: .now()) == .success else { return [] }
        defer { gate.signal() }
        let count = min(max(1, limit), ObstacleBridgeTelemetry.maximumBatchEvents, pending.count)
        let result = Array(pending.prefix(count)); pending.removeFirst(count)
        return result
    }

    public func dropSnapshot() -> [String: UInt64] {
        guard gate.wait(timeout: .now()) == .success else { return [:] }
        defer { gate.signal() }; return dropped
    }

    public func statusSnapshot() -> [String: Any] {
        guard gate.wait(timeout: .now()) == .success else { return ["available": false] }
        defer { gate.signal() }
        return [
            "available": true,
            "pending_events": pending.count,
            "newest_sequence": nextSequence == 0 ? NSNull() : nextSequence,
            "drops": dropped,
        ]
    }

    private func increment(_ reason: String) { dropped[reason, default: 0] += 1 }
}

/// Bounded private file spool. Each segment is an atomic checksum envelope;
/// failure is recorded locally and never propagated to the producer caller.
public final class ObstacleBridgeTelemetrySpool: @unchecked Sendable {
    private struct Envelope: Codable { let event: ObstacleBridgeTelemetryEvent; let sha256: String }
    private let gate = DispatchSemaphore(value: 1)
    public let directory: URL
    public let maximumBytes: Int
    public let maximumFiles: Int
    public private(set) var dropped: [String: UInt64] = [:]

    public init(directory: URL, maximumBytes: Int = 4 * 1024 * 1024, maximumFiles: Int = 1024) throws {
        self.directory = directory; self.maximumBytes = max(ObstacleBridgeTelemetry.maximumEventBytes, maximumBytes); self.maximumFiles = max(1, maximumFiles)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }

    @discardableResult public func append(_ event: ObstacleBridgeTelemetryEvent) -> Bool {
        guard gate.wait(timeout: .now()) == .success else { return false }
        defer { gate.signal() }
        guard let eventData = try? ObstacleBridgeTelemetry.encode(event: event) else { increment("invalid_event"); return false }
        let envelope = Envelope(event: event, sha256: SHA256.hash(data: eventData).map { String(format: "%02x", $0) }.joined())
        guard let data = try? JSONEncoder().encode(envelope), evict(for: data.count, priority: event.priority) else { increment("write_failure"); return false }
        let name = String(format: "event-%020llu-%@-%@.json", event.sequence, UUID().uuidString, event.priority.rawValue)
        do { try data.write(to: directory.appendingPathComponent(name), options: .atomic); return true }
        catch { increment("write_failure"); return false }
    }

    public func recover(limit: Int = ObstacleBridgeTelemetry.maximumBatchEvents) -> [ObstacleBridgeTelemetryEvent] {
        guard gate.wait(timeout: .now()) == .success else { return [] }
        defer { gate.signal() }
        return segments().compactMap { url in
            guard let event = read(url) else { try? FileManager.default.moveItem(at: url, to: url.appendingPathExtension("corrupt")); increment("corrupt_segment"); return nil }
            return event
        }.sorted { $0.sequence < $1.sequence }.prefix(max(1, min(limit, ObstacleBridgeTelemetry.maximumBatchEvents))).map { $0 }
    }

    @discardableResult public func acknowledge(through sequence: UInt64, installationID: String, sessionID: String) -> Int {
        guard gate.wait(timeout: .now()) == .success else { return 0 }
        defer { gate.signal() }; var removed = 0
        for url in segments() where read(url).map({ $0.sequence <= sequence && $0.installationID == installationID && $0.sessionID == sessionID }) == true { try? FileManager.default.removeItem(at: url); removed += 1 }
        return removed
    }

    public func statusSnapshot() -> [String: Any] {
        guard gate.wait(timeout: .now()) == .success else { return ["available": false] }
        defer { gate.signal() }
        let entries = segments()
        let events = entries.compactMap(read).sorted { $0.sequence < $1.sequence }
        return [
            "available": true,
            "pending_events": events.count,
            "pending_bytes": usage(),
            "oldest_sequence": events.first.map { $0.sequence } ?? NSNull(),
            "newest_sequence": events.last.map { $0.sequence } ?? NSNull(),
            "drops": dropped,
        ]
    }

    private func segments() -> [URL] { (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: [.fileSizeKey], options: [.skipsHiddenFiles]))?.filter { $0.lastPathComponent.hasPrefix("event-") && $0.pathExtension == "json" } ?? [] }
    private func read(_ url: URL) -> ObstacleBridgeTelemetryEvent? { guard let data = try? Data(contentsOf: url), let envelope = try? JSONDecoder().decode(Envelope.self, from: data), let eventData = try? ObstacleBridgeTelemetry.encode(event: envelope.event), SHA256.hash(data: eventData).map({ String(format: "%02x", $0) }).joined() == envelope.sha256 else { return nil }; return envelope.event }
    private func usage() -> Int { segments().reduce(0) { $0 + ((try? $1.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0) } }
    private func evict(for bytes: Int, priority: ObstacleBridgeTelemetryPriority) -> Bool { var candidates = segments(); while candidates.count >= maximumFiles || usage() + bytes > maximumBytes { guard let victim = candidates.first(where: { read($0)?.priority == .low }) else { increment("spool_full"); return false }; try? FileManager.default.removeItem(at: victim); increment("evicted_low"); candidates = segments() }; return true }
    private func increment(_ reason: String) { dropped[reason, default: 0] += 1 }
}
