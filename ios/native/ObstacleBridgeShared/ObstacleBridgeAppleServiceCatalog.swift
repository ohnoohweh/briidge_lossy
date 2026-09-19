import Foundation

/// Apple adapter facade for a peer-published RS3 catalog. The Core store owns
/// epoch/replay validation and atomic replacement; overlay owners only turn an
/// accepted result into native listener start/stop operations.
final class ObstacleBridgeAppleServiceCatalog {
    struct Install {
        let accepted: Bool
        let removed: [ObstacleBridgeChannelMuxCodec.ServiceSpec]
        let installed: [ObstacleBridgeChannelMuxCodec.ServiceSpec]
        let instanceID: UInt64?
        let connectionSequence: UInt32?
    }

    private let store = ObstacleBridgeServiceCatalogStore()
    private let chunks = ObstacleBridgeControlChunkReassembler()

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
