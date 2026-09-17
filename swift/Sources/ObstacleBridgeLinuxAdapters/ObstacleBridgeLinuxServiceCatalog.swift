import Foundation
import ObstacleBridgeCore

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
    private let core = ObstacleBridgeServiceCatalogStore()

    public init() {}

    public func install(instanceID proposedInstanceID: UInt64, connectionSequence proposedConnectionSequence: UInt32, services proposedServices: [ObstacleBridgeLinuxServiceSpec]) throws -> ObstacleBridgeLinuxServiceCatalogInstall {
        do {
            let installed = try core.install(
                instanceID: proposedInstanceID,
                connectionSequence: proposedConnectionSequence,
                services: try proposedServices.map(ObstacleBridgeLinuxServiceCatalog.coreSpec)
            )
            return .init(
                accepted: installed.accepted,
                removed: try installed.removed.map(ObstacleBridgeLinuxServiceCatalog.linuxSpec),
                installed: try installed.installed.map(ObstacleBridgeLinuxServiceCatalog.linuxSpec),
                instanceID: installed.instanceID,
                connectionSequence: installed.connectionSequence
            )
        } catch ObstacleBridgeServiceCatalogError.duplicateServiceID {
            throw ObstacleBridgeLinuxServiceCatalogError.duplicateServiceID
        } catch {
            throw ObstacleBridgeLinuxServiceCatalogError.invalidPayload
        }
    }

    public func withdraw() -> ObstacleBridgeLinuxServiceCatalogInstall {
        let installed = core.withdraw()
        return .init(
            accepted: installed.accepted,
            removed: (try? installed.removed.map(ObstacleBridgeLinuxServiceCatalog.linuxSpec)) ?? [],
            installed: [],
            instanceID: installed.instanceID,
            connectionSequence: installed.connectionSequence
        )
    }
}

/// RS3 catalog bytes used by ChannelMux REMOTE_SERVICES_SET_V2. The catalog is
/// immutable per connection epoch; callers create a fresh instance/revision on
/// reconnect so peers can replace stale installed listeners deterministically.
public enum ObstacleBridgeLinuxServiceCatalog {
    public static func encode(instanceID: UInt64, connectionSequence: UInt32, services: [ObstacleBridgeLinuxServiceSpec]) throws -> Data {
        do {
            let coreServices = try services.map { service -> ObstacleBridgeServiceSpec in
                guard (1...Int(UInt16.max)).contains(service.listenPort), (1...Int(UInt16.max)).contains(service.targetPort) else { throw ObstacleBridgeLinuxServiceCatalogError.invalidPayload }
                return .init(serviceID: service.serviceID, name: service.name, listenProtocol: service.listenProtocol.rawValue, listenHost: service.listenHost, listenPort: UInt16(service.listenPort), targetProtocol: service.targetProtocol.rawValue, targetHost: service.targetHost, targetPort: UInt16(service.targetPort))
            }
            return try ObstacleBridgeServiceCodec.encodeRemoteServices(instanceID: instanceID, connectionSequence: connectionSequence, services: coreServices)
        }
        catch ObstacleBridgeServiceCodecError.duplicateServiceID { throw ObstacleBridgeLinuxServiceCatalogError.duplicateServiceID }
        catch ObstacleBridgeServiceCodecError.payloadTooLarge { throw ObstacleBridgeLinuxServiceCatalogError.payloadTooLarge }
        catch { throw ObstacleBridgeLinuxServiceCatalogError.invalidPayload }
    }

    public static func decode(_ payload: Data) throws -> (instanceID: UInt64, connectionSequence: UInt32, services: [ObstacleBridgeLinuxServiceSpec]) {
        do {
            let decoded = try ObstacleBridgeServiceCodec.decodeRemoteServices(payload)
            let services = try decoded.services.map(linuxSpec)
            guard services.allSatisfy({ $0.listenProtocol == $0.targetProtocol }) else { throw ObstacleBridgeLinuxServiceCatalogError.invalidPayload }
            return (decoded.instanceID, decoded.connectionSequence, services)
        } catch ObstacleBridgeLinuxServiceCatalogError.invalidPayload { throw ObstacleBridgeLinuxServiceCatalogError.invalidPayload }
        catch ObstacleBridgeServiceCodecError.duplicateServiceID { throw ObstacleBridgeLinuxServiceCatalogError.duplicateServiceID }
        catch { throw ObstacleBridgeLinuxServiceCatalogError.invalidPayload }
    }

    static func linuxSpec(_ value: ObstacleBridgeServiceSpec) throws -> ObstacleBridgeLinuxServiceSpec {
        guard value.listenPort > 0, value.targetPort > 0 else { throw ObstacleBridgeLinuxServiceCatalogError.invalidPayload }
        guard let listenProtocol = ObstacleBridgeChannelMuxProtocol(rawValue: value.listenProtocol), let targetProtocol = ObstacleBridgeChannelMuxProtocol(rawValue: value.targetProtocol) else { throw ObstacleBridgeLinuxServiceCatalogError.invalidPayload }
        return .init(serviceID: value.serviceID, name: value.name, listenProtocol: listenProtocol, listenHost: value.listenHost, listenPort: Int(value.listenPort), targetProtocol: targetProtocol, targetHost: value.targetHost, targetPort: Int(value.targetPort))
    }

    static func coreSpec(_ value: ObstacleBridgeLinuxServiceSpec) throws -> ObstacleBridgeServiceSpec {
        guard (1...Int(UInt16.max)).contains(value.listenPort),
              (1...Int(UInt16.max)).contains(value.targetPort) else {
            throw ObstacleBridgeLinuxServiceCatalogError.invalidPayload
        }
        return .init(
            serviceID: value.serviceID,
            name: value.name,
            listenProtocol: value.listenProtocol.rawValue,
            listenHost: value.listenHost,
            listenPort: UInt16(value.listenPort),
            targetProtocol: value.targetProtocol.rawValue,
            targetHost: value.targetHost,
            targetPort: UInt16(value.targetPort)
        )
    }
}
