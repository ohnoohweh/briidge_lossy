import Foundation

enum ObstacleBridgeConnectionLifecycleState: String {
    case disconnected
    case connected
}

struct ObstacleBridgeConnectionLifecycleEvent {
    let state: ObstacleBridgeConnectionLifecycleState
    let epoch: UInt64
    let reason: String
    let changedAt: TimeInterval
}

struct ObstacleBridgeConnectionRotationResult {
    let accepted: Bool
    let reason: String
    let epoch: UInt64
    let candidateCycle: Int
    let restartRequired: Bool
}

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
    private let lifecycleTimeProvider: () -> TimeInterval
    private let connectionRotationDelay: TimeInterval
    private var transportLifecycle: ObstacleBridgeConnectionLifecycleEvent
    private var outerLifecycle: ObstacleBridgeConnectionLifecycleEvent
    private var compressionFailureEpoch: UInt64?
    private var disconnectedSince: TimeInterval?
    private var rotationWaitingForNewEpoch: UInt64?
    private var requestedRotations = 0
    private var completedCandidateCycles = 0

    init(
        compressRuntime: ObstacleBridgeCompressLayerRuntime? = nil,
        secureLinkAdapter: ObstacleBridgeSecureLinkPskTransportAdapter? = nil,
        connectionRotationDelay: TimeInterval = 30.0,
        lifecycleTimeProvider: (() -> TimeInterval)? = nil
    ) {
        self.compressRuntime = compressRuntime
        self.secureLinkAdapter = secureLinkAdapter
        self.connectionRotationDelay = max(0.0, connectionRotationDelay)
        self.lifecycleTimeProvider = lifecycleTimeProvider ?? { Date().timeIntervalSince1970 }
        let initial = ObstacleBridgeConnectionLifecycleEvent(
            state: .disconnected,
            epoch: 0,
            reason: "initial",
            changedAt: self.lifecycleTimeProvider()
        )
        self.transportLifecycle = initial
        self.outerLifecycle = initial
        self.disconnectedSince = initial.changedAt
    }

    static func appReady(from layers: [[String: Any]]) -> Bool {
        guard let last = layers.last else {
            return false
        }
        return (last["app_ready"] as? Bool) ?? false
    }

    static func inflowAllowed(from layers: [[String: Any]]) -> Bool {
        // A live lower transport is insufficient while SecureLink recovers.
        return appReady(from: layers)
    }

    private static func jsonEpochValue(_ value: UInt64) -> Any {
        if value <= UInt64(Int.max) {
            return Int(value)
        }
        return String(value)
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
            "epoch": jsonEpochValue(transportEpoch),
            "connected": transportConnected,
            "app_ready": transportConnected,
        ]]
        if let secureLinkStatus {
            let appReady = secureLinkStatus.authenticated
            let connected = appReady || preserveConnectedDuringEpochRestart
            let state: String
            if appReady {
                state = "authenticated"
            } else if secureLinkStatus.authFailCode != 0 {
                state = "failed"
            } else if preserveConnectedDuringEpochRestart
                && (secureLinkStatus.authenticatedSessionsTotal > 0 || secureLinkStatus.peerConfirmedAuthenticated) {
                state = "reauthenticating"
            } else if secureLinkStatus.sessionID != 0 {
                state = "handshaking"
            } else {
                state = "waiting_transport"
            }
            layers.append([
                "layer": "secure_link",
                "transport": transport,
                "state": state,
                "epoch": jsonEpochValue(secureLinkStatus.sessionID),
                "connected": connected,
                "app_ready": appReady,
                "preserve_connected_during_epoch_restart": preserveConnectedDuringEpochRestart,
            ])
        }
        if compressionEnabled {
            let lowerReady = secureLinkStatus?.authenticated ?? transportConnected
            layers.append([
                "layer": "compression",
                "transport": transport,
                "state": lowerReady ? "connected" : "disconnected",
                "epoch": jsonEpochValue(transportEpoch),
                "connected": lowerReady,
                "app_ready": lowerReady,
                "enabled": true,
            ])
        }
        return layers
    }

    func lifecycleSnapshot() -> ObstacleBridgeConnectionLifecycleEvent {
        outerLifecycle
    }

    func connectionRotationDue(candidateCount: Int) -> ObstacleBridgeConnectionRotationResult? {
        guard outerLifecycle.state == .disconnected,
              let disconnectedSince,
              lifecycleTimeProvider() - disconnectedSince >= connectionRotationDelay,
              rotationWaitingForNewEpoch == nil
        else {
            return nil
        }

        let candidates = max(1, candidateCount)
        requestedRotations += 1
        if requestedRotations % candidates == 0 {
            completedCandidateCycles += 1
        }
        rotationWaitingForNewEpoch = transportLifecycle.epoch
        return ObstacleBridgeConnectionRotationResult(
            accepted: true,
            reason: "channelmux_disconnected",
            epoch: transportLifecycle.epoch,
            candidateCycle: completedCandidateCycles,
            restartRequired: completedCandidateCycles >= 3
        )
    }

    func secureLinkStatusSnapshot() -> ObstacleBridgeSecureLinkPskRuntime.StatusSnapshot? {
        secureLinkAdapter?.statusSnapshot()
    }

    func requestSecureLinkRekey() throws -> OutboundSnapshot {
        guard let secureLinkAdapter else {
            return OutboundSnapshot(emittedFrames: [])
        }
        let snapshot = try secureLinkAdapter.requestSecureLinkRekey()
        return OutboundSnapshot(emittedFrames: snapshot.emittedFrames)
    }

    func pollSecureLinkDueFrames() throws -> OutboundSnapshot {
        guard let secureLinkAdapter else {
            return OutboundSnapshot(emittedFrames: [])
        }
        let snapshot = try secureLinkAdapter.pollDueFrames()
        return OutboundSnapshot(emittedFrames: snapshot.emittedFrames)
    }

    func connectionLayersSnapshot(
        transport: String,
        transportConnected: Bool,
        transportEpoch: UInt64 = 0,
        preserveConnectedDuringEpochRestart: Bool = false
    ) -> [[String: Any]] {
        observeTransportState(connected: transportConnected)
        let secureStatus = secureLinkAdapter?.statusSnapshot()
        refreshOuterLifecycle(secureLinkStatus: secureStatus)
        var layers = Self.connectionLayersSnapshot(
            transport: transport,
            transportConnected: transportLifecycle.state == .connected,
            transportEpoch: max(transportEpoch, transportLifecycle.epoch),
            compressionEnabled: compressRuntime != nil,
            secureLinkStatus: secureStatus,
            preserveConnectedDuringEpochRestart: preserveConnectedDuringEpochRestart
        )
        if compressionFailureEpoch == transportLifecycle.epoch, !layers.isEmpty {
            let index = layers.count - 1
            layers[index]["state"] = "disconnected"
            layers[index]["connected"] = false
            layers[index]["app_ready"] = false
            layers[index]["reason"] = "compression_failure"
        }
        if !layers.isEmpty {
            let index = layers.count - 1
            layers[index]["lifecycle_state"] = outerLifecycle.state.rawValue
            layers[index]["lifecycle_epoch"] = Self.jsonEpochValue(outerLifecycle.epoch)
            layers[index]["lifecycle_reason"] = outerLifecycle.reason
            layers[index]["lifecycle_changed_at"] = outerLifecycle.changedAt
        }
        return layers
    }

    func handleTransportDisconnected() {
        secureLinkAdapter?.handleTransportDisconnected()
        observeTransportState(connected: false, reason: "transport_disconnected")
        refreshOuterLifecycle(secureLinkStatus: secureLinkAdapter?.statusSnapshot())
    }

    // A candidate rotation starts a new transport attempt while its reported
    // state remains disconnected. Publish the new epoch so ChannelMux can
    // schedule another attempt when this one does not recover.
    func beginTransportEpoch(reason: String) {
        secureLinkAdapter?.handleTransportDisconnected()
        transportLifecycle = ObstacleBridgeConnectionLifecycleEvent(
            state: .disconnected,
            epoch: transportLifecycle.epoch + 1,
            reason: reason,
            changedAt: lifecycleTimeProvider()
        )
        if let waitingEpoch = rotationWaitingForNewEpoch,
           transportLifecycle.epoch > waitingEpoch {
            rotationWaitingForNewEpoch = nil
        }
        refreshOuterLifecycle(secureLinkStatus: secureLinkAdapter?.statusSnapshot())
    }

    func handleTransportConnected() throws -> OutboundSnapshot {
        observeTransportState(connected: true, reason: "transport_connected")
        guard let secureLinkAdapter else {
            refreshOuterLifecycle(secureLinkStatus: nil)
            return OutboundSnapshot(emittedFrames: [])
        }
        let snapshot = try secureLinkAdapter.handleTransportConnected()
        refreshOuterLifecycle(secureLinkStatus: secureLinkAdapter.statusSnapshot())
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
                } else if snapshot.dropped {
                    compressionFailureEpoch = transportLifecycle.epoch
                }
            } else {
                deliveredPayloads.append(delivered)
            }
        }

        refreshOuterLifecycle(secureLinkStatus: secureLinkAdapter?.statusSnapshot())
        return InboundSnapshot(emittedFrames: emittedFrames, deliveredPayloads: deliveredPayloads)
    }

    private func observeTransportState(connected: Bool, reason: String = "transport_state") {
        let nextState: ObstacleBridgeConnectionLifecycleState = connected ? .connected : .disconnected
        guard transportLifecycle.state != nextState else {
            return
        }
        let epoch = connected ? transportLifecycle.epoch + 1 : transportLifecycle.epoch
        transportLifecycle = ObstacleBridgeConnectionLifecycleEvent(
            state: nextState,
            epoch: epoch,
            reason: reason,
            changedAt: lifecycleTimeProvider()
        )
        if connected {
            compressionFailureEpoch = nil
            rotationWaitingForNewEpoch = nil
        }
    }

    private func refreshOuterLifecycle(secureLinkStatus: ObstacleBridgeSecureLinkPskRuntime.StatusSnapshot?) {
        let transportReady = transportLifecycle.state == .connected
        let secureReady = secureLinkStatus?.authenticated ?? transportReady
        let compressionReady = compressionFailureEpoch != transportLifecycle.epoch
        let connected = transportReady && secureReady && compressionReady
        let nextState: ObstacleBridgeConnectionLifecycleState = connected ? .connected : .disconnected
        guard outerLifecycle.state != nextState || outerLifecycle.epoch != transportLifecycle.epoch else {
            return
        }
        let reason: String
        if !transportReady {
            reason = "transport_disconnected"
        } else if !compressionReady {
            reason = "compression_failure"
        } else if secureLinkStatus?.authFailCode != 0 {
            reason = "secure_link_failed"
        } else if !secureReady {
            reason = "secure_link_handshaking"
        } else {
            reason = "connected"
        }
        outerLifecycle = ObstacleBridgeConnectionLifecycleEvent(
            state: nextState,
            epoch: transportLifecycle.epoch,
            reason: reason,
            changedAt: lifecycleTimeProvider()
        )
        if nextState == .connected {
            disconnectedSince = nil
            requestedRotations = 0
            completedCandidateCycles = 0
        } else if disconnectedSince == nil {
            disconnectedSince = outerLifecycle.changedAt
        }
    }
}
