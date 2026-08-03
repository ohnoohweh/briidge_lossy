import Foundation

final class ObstacleBridgeOverlayLayerTransportAdapter {
    struct OutboundSnapshot {
        var emittedFrames: [Data]
    }

    struct InboundSnapshot {
        var emittedFrames: [Data]
        var deliveredPayloads: [Data]
    }

    private let compressRuntime: ObstacleBridgeCompressLayerRuntime?
    private let secureLinkAdapter: ObstacleBridgeSecureLinkPskTransportAdapter?

    init(
        compressRuntime: ObstacleBridgeCompressLayerRuntime? = nil,
        secureLinkAdapter: ObstacleBridgeSecureLinkPskTransportAdapter? = nil
    ) {
        self.compressRuntime = compressRuntime
        self.secureLinkAdapter = secureLinkAdapter
    }

    static func appReady(from layers: [[String: Any]]) -> Bool {
        guard let last = layers.last else {
            return false
        }
        return (last["app_ready"] as? Bool) ?? false
    }

    static func connectionLayersSnapshot(
        transport: String,
        transportConnected: Bool,
        transportEpoch: UInt64 = 0,
        compressionEnabled: Bool,
        secureLinkStatus: ObstacleBridgeSecureLinkPskRuntime.StatusSnapshot?,
        preserveConnectedDuringEpochRestart: Bool = false
    ) -> [[String: Any]] {
        var layers: [[String: Any]] = [[
            "layer": "transport",
            "transport": transport,
            "state": transportConnected ? "connected" : "disconnected",
            "epoch": Int(transportEpoch),
            "connected": transportConnected,
            "app_ready": transportConnected,
        ]]
        if compressionEnabled {
            layers.append([
                "layer": "compression",
                "transport": transport,
                "state": "enabled",
                "epoch": Int(transportEpoch),
                "connected": transportConnected,
                "app_ready": transportConnected,
                "enabled": true,
            ])
        }
        if let secureLinkStatus {
            let appReady = secureLinkStatus.authenticated
            let connected = appReady || preserveConnectedDuringEpochRestart
            let state: String
            if appReady {
                state = "authenticated"
            } else if secureLinkStatus.authFailCode != 0 {
                state = "failed"
            } else if secureLinkStatus.sessionID != 0 {
                state = "handshaking"
            } else {
                state = "waiting_transport"
            }
            layers.append([
                "layer": "secure_link",
                "transport": transport,
                "state": state,
                "epoch": Int(secureLinkStatus.sessionID),
                "connected": connected,
                "app_ready": appReady,
                "preserve_connected_during_epoch_restart": preserveConnectedDuringEpochRestart,
            ])
        }
        return layers
    }

    func secureLinkStatusSnapshot() -> ObstacleBridgeSecureLinkPskRuntime.StatusSnapshot? {
        secureLinkAdapter?.statusSnapshot()
    }

    func connectionLayersSnapshot(
        transport: String,
        transportConnected: Bool,
        transportEpoch: UInt64 = 0,
        preserveConnectedDuringEpochRestart: Bool = false
    ) -> [[String: Any]] {
        Self.connectionLayersSnapshot(
            transport: transport,
            transportConnected: transportConnected,
            transportEpoch: transportEpoch,
            compressionEnabled: compressRuntime != nil,
            secureLinkStatus: secureLinkAdapter?.statusSnapshot(),
            preserveConnectedDuringEpochRestart: preserveConnectedDuringEpochRestart
        )
    }

    func handleTransportDisconnected() {
        secureLinkAdapter?.handleTransportDisconnected()
    }

    func handleTransportConnected() throws -> OutboundSnapshot {
        guard let secureLinkAdapter else {
            return OutboundSnapshot(emittedFrames: [])
        }
        let snapshot = try secureLinkAdapter.handleTransportConnected()
        return OutboundSnapshot(emittedFrames: snapshot.emittedFrames)
    }

    func handleOutboundPayload(_ payload: Data) throws -> OutboundSnapshot {
        let outboundPayload = compressRuntime?.handleSendPayload(payload).wirePayload ?? payload
        if let secureLinkAdapter {
            let snapshot = try secureLinkAdapter.handleOutboundPayload(outboundPayload)
            return OutboundSnapshot(emittedFrames: snapshot.emittedFrames)
        }
        return OutboundSnapshot(emittedFrames: [outboundPayload])
    }

    func handleInboundFrame(_ payload: Data) -> InboundSnapshot {
        var deliveredPayloads: [Data] = []
        var emittedFrames: [Data] = []
        let secureDelivered: [Data]
        if let secureLinkAdapter {
            let snapshot = secureLinkAdapter.handleInboundFrame(payload)
            emittedFrames.append(contentsOf: snapshot.emittedFrames)
            secureDelivered = snapshot.deliveredPayloads
        } else {
            secureDelivered = [payload]
        }

        for delivered in secureDelivered {
            if let compressRuntime {
                let snapshot = compressRuntime.handleInboundPayload(delivered)
                if let payload = snapshot.deliveredPayload, !snapshot.dropped {
                    deliveredPayloads.append(payload)
                }
            } else {
                deliveredPayloads.append(delivered)
            }
        }

        return InboundSnapshot(emittedFrames: emittedFrames, deliveredPayloads: deliveredPayloads)
    }
}
