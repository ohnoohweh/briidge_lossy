import Foundation

final class ObstacleBridgeSecureLinkPskTransportAdapter {
    struct OutboundSnapshot {
        var emittedFrames: [Data]
        var queuedPayloads: Int
        var authenticated: Bool
        var sessionID: UInt64
    }

    struct InboundSnapshot {
        var emittedFrames: [Data]
        var deliveredPayloads: [Data]
        var queuedPayloads: Int
        var authenticated: Bool
        var sessionID: UInt64
        var authFailCode: Int?
    }

    private let runtime: ObstacleBridgeSecureLinkPskRuntime
    private var pendingPayloads: [Data] = []

    init(runtime: ObstacleBridgeSecureLinkPskRuntime) {
        self.runtime = runtime
    }

    func statusSnapshot() -> ObstacleBridgeSecureLinkPskRuntime.StatusSnapshot {
        runtime.statusSnapshot()
    }

    func handleTransportDisconnected() {
        pendingPayloads.removeAll(keepingCapacity: false)
        runtime.handleTransportDisconnected()
    }

    func handleTransportConnected() throws -> OutboundSnapshot {
        let status = runtime.statusSnapshot()
        guard status.clientMode, !status.authenticated else {
            return OutboundSnapshot(
                emittedFrames: [],
                queuedPayloads: pendingPayloads.count,
                authenticated: status.authenticated,
                sessionID: status.sessionID
            )
        }
        if status.sessionID != 0, status.authFailCode == 0 {
            return OutboundSnapshot(
                emittedFrames: [],
                queuedPayloads: pendingPayloads.count,
                authenticated: status.authenticated,
                sessionID: status.sessionID
            )
        }

        let handshake = try runtime.beginClientHandshake()
        let emittedFrames = handshake.emittedFrames

        let updatedStatus = runtime.statusSnapshot()
        return OutboundSnapshot(
            emittedFrames: emittedFrames,
            queuedPayloads: pendingPayloads.count,
            authenticated: updatedStatus.authenticated,
            sessionID: updatedStatus.sessionID
        )
    }

    func handleOutboundPayload(_ payload: Data) throws -> OutboundSnapshot {
        let status = runtime.statusSnapshot()
        if status.authenticated {
            let snapshot = try runtime.sendApp(payload)
            return OutboundSnapshot(
                emittedFrames: snapshot.emittedFrames,
                queuedPayloads: pendingPayloads.count,
                authenticated: snapshot.authenticated,
                sessionID: snapshot.sessionID
            )
        }

        pendingPayloads.append(payload)
        let primed = try handleTransportConnected()

        let updatedStatus = runtime.statusSnapshot()
        return OutboundSnapshot(
            emittedFrames: primed.emittedFrames,
            queuedPayloads: pendingPayloads.count,
            authenticated: updatedStatus.authenticated,
            sessionID: updatedStatus.sessionID
        )
    }

    func handleInboundFrame(_ payload: Data) -> InboundSnapshot {
        let snapshot = runtime.handleInboundFrame(payload)
        var emittedFrames = snapshot.emittedFrames
        let deliveredPayloads = snapshot.deliveredPayloads
        if snapshot.authFailCode != nil {
            pendingPayloads.removeAll()
        }
        if runtime.statusSnapshot().authenticated, !pendingPayloads.isEmpty {
            do {
                emittedFrames.append(contentsOf: try flushPendingPayloads())
            } catch {
            }
        }
        let status = runtime.statusSnapshot()
        return InboundSnapshot(
            emittedFrames: emittedFrames,
            deliveredPayloads: deliveredPayloads,
            queuedPayloads: pendingPayloads.count,
            authenticated: status.authenticated,
            sessionID: status.sessionID,
            authFailCode: snapshot.authFailCode
        )
    }

    private func flushPendingPayloads() throws -> [Data] {
        guard runtime.statusSnapshot().authenticated, !pendingPayloads.isEmpty else {
            return []
        }
        let payloads = pendingPayloads
        pendingPayloads.removeAll()
        var emittedFrames: [Data] = []
        do {
            for payload in payloads {
                let snapshot = try runtime.sendApp(payload)
                emittedFrames.append(contentsOf: snapshot.emittedFrames)
            }
            return emittedFrames
        } catch {
            pendingPayloads = payloads + pendingPayloads
            throw error
        }
    }
}
