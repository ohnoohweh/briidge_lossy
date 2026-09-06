import Foundation
import ObstacleBridgePortable

public enum ObstacleBridgeLinuxServiceCatalogError: Error, Equatable {
    case invalidPayload
    case payloadTooLarge
    case duplicateServiceID
}

public struct ObstacleBridgeLinuxServiceCatalogInstall: Equatable, Sendable {
    public let accepted: Bool
    public let removed: [ObstacleBridgeLinuxServiceSpec]
    public let installed: [ObstacleBridgeLinuxServiceSpec]
    public let instanceID: UInt64?
    public let connectionSequence: UInt32?
}

/// Serial catalog state for one peer. A replacement is atomic from the
/// listener owner's point of view: it gets the old rows to withdraw before it
/// activates the new rows. Replays of an equal or older sequence from the
/// same instance are ignored; a new instance begins a new peer epoch.
public final class ObstacleBridgeLinuxServiceCatalogStore {
    private var instanceID: UInt64?
    private var connectionSequence: UInt32?
    private var services: [ObstacleBridgeLinuxServiceSpec] = []

    public init() {}

    public func install(instanceID proposedInstanceID: UInt64, connectionSequence proposedConnectionSequence: UInt32, services proposedServices: [ObstacleBridgeLinuxServiceSpec]) throws -> ObstacleBridgeLinuxServiceCatalogInstall {
        guard Set(proposedServices.map(\.serviceID)).count == proposedServices.count else {
            throw ObstacleBridgeLinuxServiceCatalogError.duplicateServiceID
        }
        if let instanceID, let connectionSequence,
           instanceID == proposedInstanceID,
           proposedConnectionSequence <= connectionSequence {
            return .init(accepted: false, removed: [], installed: services, instanceID: instanceID, connectionSequence: connectionSequence)
        }
        let removed = services
        instanceID = proposedInstanceID
        connectionSequence = proposedConnectionSequence
        services = proposedServices.sorted { $0.serviceID < $1.serviceID }
        return .init(accepted: true, removed: removed, installed: services, instanceID: instanceID, connectionSequence: connectionSequence)
    }

    public func withdraw() -> ObstacleBridgeLinuxServiceCatalogInstall {
        let removed = services
        services = []
        return .init(accepted: true, removed: removed, installed: [], instanceID: instanceID, connectionSequence: connectionSequence)
    }
}

/// RS3 catalog bytes used by ChannelMux REMOTE_SERVICES_SET_V2. The catalog is
/// immutable per connection epoch; callers create a fresh instance/revision on
/// reconnect so peers can replace stale installed listeners deterministically.
public enum ObstacleBridgeLinuxServiceCatalog {
    public static func encode(instanceID: UInt64, connectionSequence: UInt32, services: [ObstacleBridgeLinuxServiceSpec]) throws -> Data {
        guard Set(services.map(\.serviceID)).count == services.count else { throw ObstacleBridgeLinuxServiceCatalogError.duplicateServiceID }
        let rows: [[String: Any]] = services.map { service in
            [
                "svc_id": Int(service.serviceID),
                "l_proto": protocolName(service.listenProtocol),
                "l_bind": service.listenHost,
                "l_port": service.listenPort,
                "r_proto": protocolName(service.targetProtocol),
                "r_host": service.targetHost,
                "r_port": service.targetPort,
                "name": service.name ?? NSNull(),
                "lifecycle_hooks": NSNull(),
                "options": NSNull(),
            ]
        }
        let body = try JSONSerialization.data(withJSONObject: rows, options: [.sortedKeys])
        guard body.count <= Int(UInt32.max) else { throw ObstacleBridgeLinuxServiceCatalogError.payloadTooLarge }
        var output = Data("RS3".utf8)
        append(instanceID, to: &output)
        append(connectionSequence, to: &output)
        append(UInt32(body.count), to: &output)
        output.append(body)
        return output
    }

    public static func decode(_ payload: Data) throws -> (instanceID: UInt64, connectionSequence: UInt32, services: [ObstacleBridgeLinuxServiceSpec]) {
        guard payload.count >= 19, payload.prefix(3) == Data("RS3".utf8) else { throw ObstacleBridgeLinuxServiceCatalogError.invalidPayload }
        let instanceID = readUInt64(payload, at: 3)
        let connectionSequence = readUInt32(payload, at: 11)
        let length = Int(readUInt32(payload, at: 15))
        guard payload.count == 19 + length,
              let rows = try JSONSerialization.jsonObject(with: payload.dropFirst(19)) as? [[String: Any]]
        else { throw ObstacleBridgeLinuxServiceCatalogError.invalidPayload }
        let services = try rows.enumerated().map { index, row in
            guard let serviceID = integer(row["svc_id"]), (1...65535).contains(serviceID),
                  let listenProtocol = protocolValue(row["l_proto"]),
                  let targetProtocol = protocolValue(row["r_proto"]),
                  let listenHost = row["l_bind"] as? String,
                  let listenPort = integer(row["l_port"]), (1...65535).contains(listenPort),
                  let targetHost = row["r_host"] as? String,
                  let targetPort = integer(row["r_port"]), (1...65535).contains(targetPort),
                  listenProtocol == targetProtocol
            else { throw ObstacleBridgeLinuxServiceCatalogError.invalidPayload }
            return ObstacleBridgeLinuxServiceSpec(serviceID: UInt16(serviceID), name: row["name"] as? String, listenProtocol: listenProtocol, listenHost: listenHost, listenPort: listenPort, targetProtocol: targetProtocol, targetHost: targetHost, targetPort: targetPort)
        }
        guard Set(services.map(\.serviceID)).count == services.count else { throw ObstacleBridgeLinuxServiceCatalogError.duplicateServiceID }
        return (instanceID, connectionSequence, services)
    }

    private static func protocolName(_ value: ObstacleBridgeChannelMuxProtocol) -> String { value == .tcp ? "tcp" : "udp" }
    private static func protocolValue(_ value: Any?) -> ObstacleBridgeChannelMuxProtocol? {
        switch (value as? String)?.lowercased() {
        case "tcp": return .tcp
        case "udp": return .udp
        default: return nil
        }
    }
    private static func integer(_ value: Any?) -> Int? { value as? Int ?? (value as? NSNumber)?.intValue }
    private static func append(_ value: UInt64, to data: inout Data) { var encoded = value.bigEndian; data.append(Data(bytes: &encoded, count: 8)) }
    private static func append(_ value: UInt32, to data: inout Data) { var encoded = value.bigEndian; data.append(Data(bytes: &encoded, count: 4)) }
    private static func readUInt32(_ data: Data, at offset: Int) -> UInt32 { data[offset..<(offset + 4)].reduce(0) { ($0 << 8) | UInt32($1) } }
    private static func readUInt64(_ data: Data, at offset: Int) -> UInt64 { data[offset..<(offset + 8)].reduce(0) { ($0 << 8) | UInt64($1) } }
}
