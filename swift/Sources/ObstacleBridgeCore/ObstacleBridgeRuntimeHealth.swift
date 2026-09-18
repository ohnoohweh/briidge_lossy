import Foundation

/// Redacted diagnostic evidence for one runtime-health observation. This value
/// deliberately excludes packet contents, credentials, keys, nonces, and peer
/// traffic detail so it may be retained outside a live Admin endpoint.
public struct ObstacleBridgeRuntimeHealthRecord: Codable, Equatable, Sendable {
    public static let schemaVersion = 1

    public let schemaVersion: Int
    public let sequence: UInt64
    public let timestampUnixMilliseconds: UInt64
    public let event: String
    public let controlledStop: Bool
    public let processResidentBytes: UInt64?
    public let processFootprintBytes: UInt64?
    public let heartbeatAgeMilliseconds: UInt64?
    public let packetPumpRunning: Bool?
    public let overlayState: String?
    public let secureLinkState: String?
    public let transportEpoch: UInt64?
    public let incomingQueuedPackets: UInt64?
    public let outgoingQueuedPackets: UInt64?
    public let outgoingInflightWrites: UInt64?
    public let incomingDroppedPackets: UInt64?
    public let outgoingDroppedPackets: UInt64?
    public let slowWrites: UInt64?
    public let packetsFromSystem: UInt64?
    public let packetsToSystem: UInt64?

    public init(
        sequence: UInt64,
        timestampUnixMilliseconds: UInt64,
        event: String,
        controlledStop: Bool = false,
        processResidentBytes: UInt64? = nil,
        processFootprintBytes: UInt64? = nil,
        heartbeatAgeMilliseconds: UInt64? = nil,
        packetPumpRunning: Bool? = nil,
        overlayState: String? = nil,
        secureLinkState: String? = nil,
        transportEpoch: UInt64? = nil,
        incomingQueuedPackets: UInt64? = nil,
        outgoingQueuedPackets: UInt64? = nil,
        outgoingInflightWrites: UInt64? = nil,
        incomingDroppedPackets: UInt64? = nil,
        outgoingDroppedPackets: UInt64? = nil,
        slowWrites: UInt64? = nil,
        packetsFromSystem: UInt64? = nil,
        packetsToSystem: UInt64? = nil
    ) {
        self.schemaVersion = Self.schemaVersion
        self.sequence = sequence
        self.timestampUnixMilliseconds = timestampUnixMilliseconds
        self.event = event
        self.controlledStop = controlledStop
        self.processResidentBytes = processResidentBytes
        self.processFootprintBytes = processFootprintBytes
        self.heartbeatAgeMilliseconds = heartbeatAgeMilliseconds
        self.packetPumpRunning = packetPumpRunning
        self.overlayState = overlayState
        self.secureLinkState = secureLinkState
        self.transportEpoch = transportEpoch
        self.incomingQueuedPackets = incomingQueuedPackets
        self.outgoingQueuedPackets = outgoingQueuedPackets
        self.outgoingInflightWrites = outgoingInflightWrites
        self.incomingDroppedPackets = incomingDroppedPackets
        self.outgoingDroppedPackets = outgoingDroppedPackets
        self.slowWrites = slowWrites
        self.packetsFromSystem = packetsFromSystem
        self.packetsToSystem = packetsToSystem
    }

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case sequence
        case timestampUnixMilliseconds = "timestamp_unix_milliseconds"
        case event
        case controlledStop = "controlled_stop"
        case processResidentBytes = "process_resident_bytes"
        case processFootprintBytes = "process_footprint_bytes"
        case heartbeatAgeMilliseconds = "heartbeat_age_milliseconds"
        case packetPumpRunning = "packet_pump_running"
        case overlayState = "overlay_state"
        case secureLinkState = "securelink_state"
        case transportEpoch = "transport_epoch"
        case incomingQueuedPackets = "incoming_queued_packets"
        case outgoingQueuedPackets = "outgoing_queued_packets"
        case outgoingInflightWrites = "outgoing_inflight_writes"
        case incomingDroppedPackets = "incoming_dropped_packets"
        case outgoingDroppedPackets = "outgoing_dropped_packets"
        case slowWrites = "slow_writes"
        case packetsFromSystem = "packets_from_system"
        case packetsToSystem = "packets_to_system"
    }
}

/// A small in-memory ring used by adapters before persisting a platform-owned
/// diagnostic snapshot. The caller chooses when to persist; append is O(1)
/// for the usual retained capacity and never grows beyond `capacity`.
public struct ObstacleBridgeRuntimeHealthRing: Codable, Equatable, Sendable {
    public let capacity: Int
    public private(set) var records: [ObstacleBridgeRuntimeHealthRecord]

    public init(capacity: Int = 128, records: [ObstacleBridgeRuntimeHealthRecord] = []) {
        precondition(capacity > 0, "runtime health ring capacity must be positive")
        self.capacity = capacity
        self.records = Array(records.suffix(capacity))
    }

    enum CodingKeys: String, CodingKey {
        case capacity
        case records
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let capacity = try container.decode(Int.self, forKey: .capacity)
        guard capacity > 0 else {
            throw DecodingError.dataCorruptedError(
                forKey: .capacity,
                in: container,
                debugDescription: "runtime health ring capacity must be positive"
            )
        }
        self.capacity = capacity
        self.records = Array(try container.decode([ObstacleBridgeRuntimeHealthRecord].self, forKey: .records).suffix(capacity))
    }

    public mutating func append(_ record: ObstacleBridgeRuntimeHealthRecord) {
        if records.count == capacity {
            records.removeFirst()
        }
        records.append(record)
    }

    /// `nil` means no persisted lifetime has been observed. `false` means the
    /// previous retained lifetime has no controlled-stop marker and therefore
    /// must be reported as unclean without claiming a termination cause.
    public var previousLifetimeEndedCleanly: Bool? {
        guard !records.isEmpty else { return nil }
        return records.last?.controlledStop == true
    }
}

/// Platform owners use this small file helper instead of each defining its own
/// persistence format. The file contains only `ObstacleBridgeRuntimeHealthRing`
/// and is replaced atomically so a process loss can leave, at worst, the last
/// complete observation available for restart classification.
public enum ObstacleBridgeRuntimeHealthPersistence {
    public static func load(from url: URL) -> ObstacleBridgeRuntimeHealthRing? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(ObstacleBridgeRuntimeHealthRing.self, from: data)
    }

    public static func save(_ ring: ObstacleBridgeRuntimeHealthRing, to url: URL) throws {
        let directory = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(ring)
        try data.write(to: url, options: .atomic)
        #if os(Linux)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        #endif
    }
}
