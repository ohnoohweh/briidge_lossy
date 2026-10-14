import Foundation

/// Resource-neutral catalog effects expressed in the public native service
/// model. Adapters create and withdraw their own listeners from these effects;
/// Core remains the sole owner of replay and replacement admission.
public struct ObstacleBridgeNativeServiceCatalogInstall {
    public let accepted: Bool
    public let removed: [ObstacleBridgeNativeServiceSpec]
    public let installed: [ObstacleBridgeNativeServiceSpec]
    public let instanceID: UInt64?
    public let connectionSequence: UInt32?
}

/// Portable facade for a peer-published RS3 catalog. The Core store owns
/// epoch/replay validation and atomic replacement; resource owners only turn
/// an accepted result into platform listener start/stop operations.
public final class ObstacleBridgeAppleServiceCatalog: @unchecked Sendable {
    struct Install {
        let accepted: Bool
        let removed: [ObstacleBridgeChannelMuxCodec.ServiceSpec]
        let installed: [ObstacleBridgeChannelMuxCodec.ServiceSpec]
        let instanceID: UInt64?
        let connectionSequence: UInt32?
    }

    private let store = ObstacleBridgeServiceCatalogStore()
    private let chunks = ObstacleBridgeControlChunkReassembler()

    public init() {}

    /// Admit a typed catalog for a non-Apple resource owner. This avoids
    /// exposing the legacy compatibility codec to Linux while preserving the
    /// same Core-owned epoch and replacement rules used by Apple adapters.
    public func install(
        instanceID: UInt64,
        connectionSequence: UInt32,
        services: [ObstacleBridgeNativeServiceSpec]
    ) throws -> ObstacleBridgeNativeServiceCatalogInstall {
        let install = try store.install(
            instanceID: instanceID,
            connectionSequence: connectionSequence,
            services: try services.map {
                try ObstacleBridgeChannelMuxCodec.coreServiceSpec($0.toChannelMuxServiceSpec())
            }
        )
        return .init(
            accepted: install.accepted,
            removed: install.removed.map(ObstacleBridgeNativeServiceSpec.init(coreSpec:)),
            installed: install.installed.map(ObstacleBridgeNativeServiceSpec.init(coreSpec:)),
            instanceID: install.instanceID,
            connectionSequence: install.connectionSequence
        )
    }

    /// Withdraw all admitted services and return the resources that the
    /// platform owner must close.
    public func withdrawNativeServices() -> ObstacleBridgeNativeServiceCatalogInstall {
        let install = store.withdraw()
        return .init(
            accepted: install.accepted,
            removed: install.removed.map(ObstacleBridgeNativeServiceSpec.init(coreSpec:)),
            installed: [],
            instanceID: install.instanceID,
            connectionSequence: install.connectionSequence
        )
    }

    func receive(_ frame: ObstacleBridgeChannelMuxCodec.MuxFrame) -> Install? {
        let payload: Data
        switch frame.mtype {
        case .remoteServicesSetV2:
            payload = frame.body
        case .remoteServicesSetV2Chunk:
            guard let reassembled = chunks.consume(
                channelID: UInt16(clamping: frame.chanID),
                protocolType: UInt8(clamping: frame.proto.rawValue),
                messageType: UInt8(clamping: frame.mtype.rawValue),
                payload: frame.body,
                peerID: nil
            ) else { return nil }
            payload = reassembled
        default:
            return nil
        }
        guard let decoded = try? ObstacleBridgeServiceCodec.decodeRemoteServices(payload),
              let install = try? store.install(
                instanceID: decoded.instanceID,
                connectionSequence: decoded.connectionSequence,
                services: decoded.services
              )
        else { return nil }
        let removed = install.removed.compactMap(ObstacleBridgeChannelMuxCodec.serviceSpec)
        let installed = install.installed.compactMap(ObstacleBridgeChannelMuxCodec.serviceSpec)
        guard removed.count == install.removed.count, installed.count == install.installed.count else {
            return nil
        }
        return .init(
            accepted: install.accepted,
            removed: removed,
            installed: installed,
            instanceID: install.instanceID,
            connectionSequence: install.connectionSequence
        )
    }

    func withdraw() -> Install {
        let install = store.withdraw()
        return .init(
            accepted: install.accepted,
            removed: install.removed.compactMap(ObstacleBridgeChannelMuxCodec.serviceSpec),
            installed: [],
            instanceID: install.instanceID,
            connectionSequence: install.connectionSequence
        )
    }
}
