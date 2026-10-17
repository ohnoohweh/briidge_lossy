import Foundation

/// The portable `telemetry/v1` contract shared by Apple runtime owners and the
/// Python reference collector. Values outside this allowlist are rejected
/// before they can reach a spool or transport.
public enum ObstacleBridgeTelemetryError: Error, Equatable, Sendable {
    case invalidEvent
    case invalidBatch
    case invalidField
    case malformedEncoding
    case eventTooLarge
    case batchTooLarge
}

public enum ObstacleBridgeTelemetryPriority: String, Codable, CaseIterable, Sendable {
    case low
    case normal
    case critical
}

public enum ObstacleBridgeTelemetryFieldValue: Codable, Equatable, Sendable {
    case bool(Bool)
    case integer(Int64)
    case number(Double)
    case string(String)

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Int64.self) {
            self = .integer(value)
        } else if let value = try? container.decode(Double.self) {
            guard value.isFinite else { throw ObstacleBridgeTelemetryError.invalidField }
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else {
            throw ObstacleBridgeTelemetryError.invalidField
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .bool(let value): try container.encode(value)
        case .integer(let value): try container.encode(value)
        case .number(let value):
            guard value.isFinite else { throw ObstacleBridgeTelemetryError.invalidField }
            try container.encode(value)
        case .string(let value):
            guard value.count <= ObstacleBridgeTelemetry.maximumFieldValueLength else {
                throw ObstacleBridgeTelemetryError.invalidField
            }
            try container.encode(value)
        }
    }
}

public struct ObstacleBridgeTelemetryEvent: Codable, Equatable, Sendable {
    public let installationID: String
    public let sessionID: String
    public let sequence: UInt64
    public let monotonicNanoseconds: UInt64
    public let wallTime: Double
    public let priority: ObstacleBridgeTelemetryPriority
    public let event: String
    public let fields: [String: ObstacleBridgeTelemetryFieldValue]

    enum CodingKeys: String, CodingKey {
        case version = "v"
        case kind
        case installationID = "installation_id"
        case sessionID = "session_id"
        case sequence
        case monotonicNanoseconds = "monotonic_ns"
        case wallTime = "wall_time"
        case priority
        case event
        case fields
    }

    public init(
        installationID: String,
        sessionID: String,
        sequence: UInt64,
        monotonicNanoseconds: UInt64,
        wallTime: Double,
        priority: ObstacleBridgeTelemetryPriority,
        event: String,
        fields: [String: ObstacleBridgeTelemetryFieldValue]
    ) throws {
        self.installationID = installationID
        self.sessionID = sessionID
        self.sequence = sequence
        self.monotonicNanoseconds = monotonicNanoseconds
        self.wallTime = wallTime
        self.priority = priority
        self.event = event
        self.fields = fields
        try validate()
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard try container.decode(Int.self, forKey: .version) == ObstacleBridgeTelemetry.version,
              try container.decode(String.self, forKey: .kind) == ObstacleBridgeTelemetry.eventKind
        else { throw ObstacleBridgeTelemetryError.invalidEvent }
        installationID = try container.decode(String.self, forKey: .installationID)
        sessionID = try container.decode(String.self, forKey: .sessionID)
        sequence = try container.decode(UInt64.self, forKey: .sequence)
        monotonicNanoseconds = try container.decode(UInt64.self, forKey: .monotonicNanoseconds)
        wallTime = try container.decode(Double.self, forKey: .wallTime)
        priority = try container.decode(ObstacleBridgeTelemetryPriority.self, forKey: .priority)
        event = try container.decode(String.self, forKey: .event)
        fields = try container.decode([String: ObstacleBridgeTelemetryFieldValue].self, forKey: .fields)
        try validate()
    }

    public func encode(to encoder: any Encoder) throws {
        try validate()
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(ObstacleBridgeTelemetry.version, forKey: .version)
        try container.encode(ObstacleBridgeTelemetry.eventKind, forKey: .kind)
        try container.encode(installationID, forKey: .installationID)
        try container.encode(sessionID, forKey: .sessionID)
        try container.encode(sequence, forKey: .sequence)
        try container.encode(monotonicNanoseconds, forKey: .monotonicNanoseconds)
        try container.encode(wallTime, forKey: .wallTime)
        try container.encode(priority, forKey: .priority)
        try container.encode(event, forKey: .event)
        try container.encode(fields, forKey: .fields)
    }

    public func validate() throws {
        guard !installationID.isEmpty, installationID.count <= ObstacleBridgeTelemetry.maximumIdentifierLength,
              !sessionID.isEmpty, sessionID.count <= ObstacleBridgeTelemetry.maximumIdentifierLength,
              sequence > 0, wallTime.isFinite, wallTime >= 0,
              !event.isEmpty, event.count <= ObstacleBridgeTelemetry.maximumEventNameLength,
              event.unicodeScalars.allSatisfy({ $0.value >= 48 && $0.value <= 57 || $0.value >= 97 && $0.value <= 122 || "._-".unicodeScalars.contains($0) }),
              fields.count <= ObstacleBridgeTelemetry.allowedFieldNames.count
        else { throw ObstacleBridgeTelemetryError.invalidEvent }
        for (name, value) in fields {
            guard ObstacleBridgeTelemetry.allowedFieldNames.contains(name),
                  !ObstacleBridgeTelemetry.sensitiveFieldTokens.contains(where: { name.lowercased().contains($0) })
            else { throw ObstacleBridgeTelemetryError.invalidField }
            if case .string(let string) = value, string.count > ObstacleBridgeTelemetry.maximumFieldValueLength {
                throw ObstacleBridgeTelemetryError.invalidField
            }
        }
    }
}

public struct ObstacleBridgeTelemetryBatch: Codable, Equatable, Sendable {
    public let events: [ObstacleBridgeTelemetryEvent]

    enum CodingKeys: String, CodingKey { case version = "v", kind, events }

    public init(events: [ObstacleBridgeTelemetryEvent]) throws {
        self.events = events
        try validate()
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard try container.decode(Int.self, forKey: .version) == ObstacleBridgeTelemetry.version,
              try container.decode(String.self, forKey: .kind) == ObstacleBridgeTelemetry.batchKind
        else { throw ObstacleBridgeTelemetryError.invalidBatch }
        events = try container.decode([ObstacleBridgeTelemetryEvent].self, forKey: .events)
        try validate()
    }

    public func encode(to encoder: any Encoder) throws {
        try validate()
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(ObstacleBridgeTelemetry.version, forKey: .version)
        try container.encode(ObstacleBridgeTelemetry.batchKind, forKey: .kind)
        try container.encode(events, forKey: .events)
    }

    public func validate() throws {
        guard !events.isEmpty, events.count <= ObstacleBridgeTelemetry.maximumBatchEvents else {
            throw ObstacleBridgeTelemetryError.invalidBatch
        }
        for event in events { try event.validate() }
    }
}

public enum ObstacleBridgeTelemetry {
    public static let version = 1
    public static let eventKind = "telemetry.event"
    public static let batchKind = "telemetry.batch"
    public static let maximumEventBytes = 4_096
    public static let maximumBatchEvents = 128
    public static let maximumFieldValueLength = 256
    public static let maximumIdentifierLength = 128
    public static let maximumEventNameLength = 96
    public static let allowedFieldNames: Set<String> = ["counter", "dropped", "error_code", "load_1m", "memory_bytes", "queue_depth", "reason", "state", "transport"]
    static let sensitiveFieldTokens = ["address", "cookie", "header", "key", "packet", "payload", "psk", "secret", "token"]

    public static func encode(event: ObstacleBridgeTelemetryEvent) throws -> Data {
        let encoded = try encoder.encode(event)
        guard encoded.count <= maximumEventBytes else { throw ObstacleBridgeTelemetryError.eventTooLarge }
        return encoded
    }

    public static func decodeEvent(_ payload: Data) throws -> ObstacleBridgeTelemetryEvent {
        guard payload.count <= maximumEventBytes,
              let object = try JSONSerialization.jsonObject(with: payload) as? [String: Any],
              Set(object.keys) == ["v", "kind", "installation_id", "session_id", "sequence", "monotonic_ns", "wall_time", "priority", "event", "fields"]
        else { throw ObstacleBridgeTelemetryError.malformedEncoding }
        do { return try decoder.decode(ObstacleBridgeTelemetryEvent.self, from: payload) }
        catch { throw ObstacleBridgeTelemetryError.malformedEncoding }
    }

    public static func encode(batch: ObstacleBridgeTelemetryBatch) throws -> Data {
        let encoded = try encoder.encode(batch)
        guard encoded.count <= maximumEventBytes * maximumBatchEvents else { throw ObstacleBridgeTelemetryError.batchTooLarge }
        return encoded
    }

    public static func decodeBatch(_ payload: Data) throws -> ObstacleBridgeTelemetryBatch {
        guard payload.count <= maximumEventBytes * maximumBatchEvents,
              let object = try JSONSerialization.jsonObject(with: payload) as? [String: Any],
              Set(object.keys) == ["v", "kind", "events"]
        else { throw ObstacleBridgeTelemetryError.malformedEncoding }
        do { return try decoder.decode(ObstacleBridgeTelemetryBatch.self, from: payload) }
        catch { throw ObstacleBridgeTelemetryError.malformedEncoding }
    }

    private static let encoder: JSONEncoder = {
        let value = JSONEncoder()
        value.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return value
    }()

    private static let decoder = JSONDecoder()
}
