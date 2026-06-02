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

    func secureLinkStatusSnapshot() -> ObstacleBridgeSecureLinkPskRuntime.StatusSnapshot? {
        secureLinkAdapter?.statusSnapshot()
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
