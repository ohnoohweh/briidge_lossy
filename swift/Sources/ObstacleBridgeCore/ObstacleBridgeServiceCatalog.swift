import Foundation

/// The portable replacement rule for a peer-published service catalog.
/// Socket listeners are adapter resources; this state owns only the ordered,
/// epoch-scoped catalog decision that tells an adapter which resources to
/// withdraw and which ones to activate.
public enum ObstacleBridgeServiceCatalogError: Error, Equatable, Sendable {
    case duplicateServiceID
    case invalidService
}

public struct ObstacleBridgeServiceCatalogInstall: Equatable, Sendable {
    public let accepted: Bool
    public let removed: [ObstacleBridgeServiceSpec]
    public let installed: [ObstacleBridgeServiceSpec]
    public let instanceID: UInt64?
    public let connectionSequence: UInt32?
}

public final class ObstacleBridgeServiceCatalogStore: @unchecked Sendable {
    private var instanceID: UInt64?
    private var connectionSequence: UInt32?
    private var services: [ObstacleBridgeServiceSpec] = []

    public init() {}

    public func install(
        instanceID proposedInstanceID: UInt64,
        connectionSequence proposedConnectionSequence: UInt32,
        services proposedServices: [ObstacleBridgeServiceSpec]
    ) throws -> ObstacleBridgeServiceCatalogInstall {
        try Self.validate(proposedServices)
        if let instanceID, let connectionSequence,
           instanceID == proposedInstanceID,
           proposedConnectionSequence <= connectionSequence {
            return .init(
                accepted: false,
                removed: [],
                installed: services,
                instanceID: instanceID,
                connectionSequence: connectionSequence
            )
        }
        let removed = services
        instanceID = proposedInstanceID
        connectionSequence = proposedConnectionSequence
        services = proposedServices.sorted { $0.serviceID < $1.serviceID }
        return .init(
            accepted: true,
            removed: removed,
            installed: services,
            instanceID: instanceID,
            connectionSequence: connectionSequence
        )
    }

    public func withdraw() -> ObstacleBridgeServiceCatalogInstall {
        let removed = services
        services = []
        let withdrawnInstanceID = instanceID
        let withdrawnConnectionSequence = connectionSequence
        instanceID = nil
        connectionSequence = nil
        return .init(
            accepted: true,
            removed: removed,
            installed: [],
            instanceID: withdrawnInstanceID,
            connectionSequence: withdrawnConnectionSequence
        )
    }

    private static func validate(_ proposedServices: [ObstacleBridgeServiceSpec]) throws {
        guard Set(proposedServices.map(\.serviceID)).count == proposedServices.count else {
            throw ObstacleBridgeServiceCatalogError.duplicateServiceID
        }
        for service in proposedServices {
            guard (service.listenProtocol == 0 || service.listenProtocol == 1 || service.listenProtocol == 2),
                  service.listenProtocol == service.targetProtocol,
                  service.listenPort > 0,
                  service.targetPort > 0 else {
                throw ObstacleBridgeServiceCatalogError.invalidService
            }
        }
    }
}
