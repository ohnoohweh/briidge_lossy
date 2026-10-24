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

public final class ObstacleBridgeOverlayLayerTransportAdapter {
    // This is the layered application-readiness grace used by every native
    // overlay owner. Transport-up alone never makes the overlay usable.
    static let outerReadinessGrace: TimeInterval = 15.0
    static let defaultTransportDelayRotationThresholdMS: Double = 5_000.0
    static let defaultTransportDelayRotationGrace: TimeInterval = 30.0

    public struct OutboundSnapshot {
        public let emittedFrames: [Data]
        public let queuedPayloads: Int

        public init(emittedFrames: [Data], queuedPayloads: Int = 0) {
            self.emittedFrames = emittedFrames
            self.queuedPayloads = queuedPayloads
        }
    }

    public struct InboundSnapshot {
        public let emittedFrames: [Data]
        public let deliveredPayloads: [Data]
    }

    private let compressRuntime: ObstacleBridgeCompressLayerRuntime?
    private let secureLinkAdapter: ObstacleBridgeSecureLinkPskTransportAdapter?
    private let peerAddressRuntime: ObstacleBridgePeerAddressProtocolRuntime?
    private let lifecycleTimeProvider: () -> TimeInterval
    private let coreCoordinator: ObstacleBridgeOverlayCoordinator
    // Shared with native queue metrics only; Core consumes the same values for
    // the lifecycle decision below.
    let transportDelayRotationThresholdMS: Double
    let transportDelayRotationGrace: TimeInterval
    // The owning TCP/WebSocket adapter supplies this native-effect executor.
    // Core never reaches into Network or URLSession directly.
    private var coreEffectSink: (([ObstacleBridgeOverlayCoordinatorEffect]) -> Void)?
    private var transportLifecycle: ObstacleBridgeConnectionLifecycleEvent
    private var outerLifecycle: ObstacleBridgeConnectionLifecycleEvent
    private var compressionFailureEpoch: UInt64?
    private var disconnectedSince: TimeInterval?

    init(
        compressRuntime: ObstacleBridgeCompressLayerRuntime? = nil,
        secureLinkAdapter: ObstacleBridgeSecureLinkPskTransportAdapter? = nil,
        peerAddressRuntime: ObstacleBridgePeerAddressProtocolRuntime? = nil,
        transportDelayRotationThresholdMS: Double = ObstacleBridgeOverlayLayerTransportAdapter.defaultTransportDelayRotationThresholdMS,
        transportDelayRotationGrace: TimeInterval = ObstacleBridgeOverlayLayerTransportAdapter.defaultTransportDelayRotationGrace,
        lifecycleTimeProvider: (() -> TimeInterval)? = nil
    ) {
        self.compressRuntime = compressRuntime
        self.secureLinkAdapter = secureLinkAdapter
        self.peerAddressRuntime = peerAddressRuntime
        self.lifecycleTimeProvider = lifecycleTimeProvider ?? { Date().timeIntervalSince1970 }
        self.transportDelayRotationThresholdMS = max(0, transportDelayRotationThresholdMS)
        self.transportDelayRotationGrace = max(0, transportDelayRotationGrace)
        self.coreCoordinator = .init(
            candidateCount: 1,
            livenessPolicy: .init(
                transportDelayThresholdMilliseconds: self.transportDelayRotationThresholdMS,
                transportDelayGraceMilliseconds: Int(self.transportDelayRotationGrace * 1_000)
            )
        )
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

    /// Public Linux/Apple transport boundary for a PSK-protected overlay.
    /// The resource owner supplies only lower-transport I/O; this Core object
    /// owns SecureLink framing, layered readiness, and failure gating.
    public convenience init(clientPSK: String) {
        self.init(secureLinkAdapter: .init(clientPSK: clientPSK))
    }

    func setCoreEffectSink(_ sink: @escaping ([ObstacleBridgeOverlayCoordinatorEffect]) -> Void) {
        coreEffectSink = sink
    }

    func setPendingSecureLinkPayloadWorkSink(_ sink: @escaping () -> Void) {
        secureLinkAdapter?.setPendingPayloadWorkSink(sink)
    }

    /// Starts the portable lifecycle only after the native owner has installed
    /// its effect executor. This prevents a constructor-time connection from
    /// bypassing Core's epoch admission.
    func startCoreLifecycle() {
        applyCore(.start)
    }

    func configureCoreCandidateCount(_ count: Int) {
        coreCoordinator.configureCandidateCount(count)
    }

    func stopCoreLifecycle() {
        applyCore(.stop)
    }

    func retryTimerFired(token: UInt64) {
        applyCore(.retryTimerFired(token: token))
    }

    private func applyCore(_ input: ObstacleBridgeOverlayCoordinatorInput) {
        let transition = coreCoordinator.handle(input)
        guard !transition.effects.isEmpty else { return }
        coreEffectSink?(transition.effects)
    }

    static func appReady(from layers: [[String: Any]]) -> Bool {
        guard let last = layers.last else {
            return false
        }
        return (last["app_ready"] as? Bool) ?? false
    }

    /// The transport owner reports facts; Core owns the conjunction that
    /// admits application traffic across its configured layers.
    public static func applicationReady(
        transportConnected: Bool,
        secureLinkRequired: Bool,
        secureLinkAuthenticated: Bool,
        compressionHealthy: Bool
    ) -> Bool {
        transportConnected
            && (!secureLinkRequired || secureLinkAuthenticated)
            && compressionHealthy
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

    func coreLifecycleSnapshot() -> ObstacleBridgeOverlayCoordinatorSnapshot {
        coreCoordinator.snapshot
    }

    /// Native timers report a measurement only. Core owns the threshold,
    /// duration, candidate rotation, retry, and cancellation decision.
    func reportTransportLiveness(delayMilliseconds: Double) {
        guard let epoch = coreCoordinator.snapshot.epoch else { return }
        let now = UInt64(max(0, lifecycleTimeProvider()) * 1_000)
        applyCore(.transportLivenessSample(epoch: epoch, delayMilliseconds: delayMilliseconds, nowMilliseconds: now))
    }

    func secureLinkStatusSnapshot() -> ObstacleBridgeSecureLinkPskRuntime.StatusSnapshot? {
        secureLinkAdapter?.statusSnapshot()
    }

    /// Redacted protocol state for an adapter-owned session. It carries no
    /// secret material and is safe for the Linux Admin projection.
    public func secureLinkProtocolState() -> ObstacleBridgeSecureLinkPSKState? {
        secureLinkAdapter?.protocolState
    }

    func observedPublicIPSnapshot() -> String {
        peerAddressRuntime?.observedPublicIP ?? ""
    }

    func observedPublicPortSnapshot() -> Int? {
        peerAddressRuntime?.observedPublicPort
    }

    public func requestSecureLinkRekey(sessionID: UInt64? = nil, clientNonce: Data? = nil) throws -> OutboundSnapshot {
        guard let secureLinkAdapter else {
            return OutboundSnapshot(emittedFrames: [])
        }
        let snapshot = try secureLinkAdapter.requestSecureLinkRekey(sessionID: sessionID, clientNonce: clientNonce)
        return OutboundSnapshot(emittedFrames: snapshot.emittedFrames, queuedPayloads: snapshot.queuedPayloads)
    }

    public func pollSecureLinkDueFrames() throws -> OutboundSnapshot {
        guard let secureLinkAdapter else {
            return OutboundSnapshot(emittedFrames: [])
        }
        let snapshot = try secureLinkAdapter.pollDueFrames()
        return OutboundSnapshot(emittedFrames: snapshot.emittedFrames, queuedPayloads: snapshot.queuedPayloads)
    }

    func connectionLayersSnapshot(
        transport: String,
        transportConnected: Bool,
        transportEpoch: UInt64 = 0,
        preserveConnectedDuringEpochRestart: Bool = false
    ) -> [[String: Any]] {
        observeTransportState(connected: transportConnected)
        enforceAuthenticatedTransportReadiness(transportConnected: transportConnected)
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
        if let peerAddressRuntime {
            layers.insert([
                "layer": "peer_address_protocol",
                "transport": transport,
                "state": peerAddressRuntime.observedPublicIP.isEmpty
                    ? (transportLifecycle.state == .connected ? "discovering" : "disconnected")
                    : "resolved",
                "epoch": Self.jsonEpochValue(max(transportEpoch, transportLifecycle.epoch)),
                "connected": transportLifecycle.state == .connected,
                "app_ready": transportLifecycle.state == .connected,
                "observed_public_ip": peerAddressRuntime.observedPublicIP,
                "observed_public_port": peerAddressRuntime.observedPublicPort ?? NSNull(),
            ], at: min(1, layers.count))
        }
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

    public func handleTransportDisconnected() {
        peerAddressRuntime?.handleTransportDisconnected()
        secureLinkAdapter?.handleTransportDisconnected()
        observeTransportState(connected: false, reason: "transport_disconnected")
        if let epoch = coreCoordinator.snapshot.epoch {
            applyCore(.transportFailed(epoch: epoch, reason: "transport_disconnected"))
        }
        refreshOuterLifecycle(secureLinkStatus: secureLinkAdapter?.statusSnapshot())
    }

    // Owners publish lower transport state independently of SecureLink. If a
    // queued disconnect callback was missed, the next observed lower-state
    // snapshot is still authoritative: authenticated SecureLink must never
    // remain visible above a disconnected transport.
    private func enforceAuthenticatedTransportReadiness(transportConnected: Bool) {
        guard !transportConnected,
              secureLinkAdapter?.statusSnapshot().authenticated == true
        else {
            return
        }
        handleTransportDisconnected()
    }

    // A candidate rotation starts a new transport attempt while its reported
    // state remains disconnected. Publish the new epoch so ChannelMux can
    // schedule another attempt when this one does not recover.
    func beginTransportEpoch(reason: String) {
        peerAddressRuntime?.handleTransportDisconnected()
        secureLinkAdapter?.handleTransportDisconnected()
        applyCore(.start)
        transportLifecycle = ObstacleBridgeConnectionLifecycleEvent(
            state: .disconnected,
            epoch: transportLifecycle.epoch + 1,
            reason: reason,
            changedAt: lifecycleTimeProvider()
        )
        refreshOuterLifecycle(secureLinkStatus: secureLinkAdapter?.statusSnapshot())
    }

    public func handleTransportConnected(sessionID: UInt64? = nil, clientNonce: Data? = nil) throws -> OutboundSnapshot {
        observeTransportState(connected: true, reason: "transport_connected")
        if let epoch = coreCoordinator.snapshot.epoch {
            applyCore(.transportConnected(epoch: epoch))
        }
        var emittedFrames = peerAddressRuntime?.handleTransportConnected() ?? []
        guard let secureLinkAdapter else {
            refreshOuterLifecycle(secureLinkStatus: nil)
            return OutboundSnapshot(emittedFrames: emittedFrames)
        }
        let snapshot = try secureLinkAdapter.handleTransportConnected(sessionID: sessionID, clientNonce: clientNonce)
        emittedFrames.append(contentsOf: snapshot.emittedFrames)
        refreshOuterLifecycle(secureLinkStatus: secureLinkAdapter.statusSnapshot())
        return OutboundSnapshot(emittedFrames: emittedFrames, queuedPayloads: snapshot.queuedPayloads)
    }

    public func handleOutboundPayload(_ payload: Data) throws -> OutboundSnapshot {
        let outboundPayload = compressRuntime?.handleSendPayload(payload).wirePayload ?? payload
        if let secureLinkAdapter {
            let snapshot = try secureLinkAdapter.handleOutboundPayload(outboundPayload)
            return OutboundSnapshot(emittedFrames: snapshot.emittedFrames, queuedPayloads: snapshot.queuedPayloads)
        }
        return OutboundSnapshot(emittedFrames: [outboundPayload])
    }

    public func handleInboundFrame(
        _ payload: Data,
        observedPeerHost: String? = nil,
        observedPeerPort: Int? = nil
    ) -> InboundSnapshot {
        var deliveredPayloads: [Data] = []
        var emittedFrames: [Data] = []
        if let peerAddressRuntime {
            let peerAddressSnapshot = peerAddressRuntime.handleInboundFrame(
                payload,
                observedPeerHost: observedPeerHost,
                observedPeerPort: observedPeerPort
            )
            if peerAddressSnapshot.consumed {
                return InboundSnapshot(
                    emittedFrames: peerAddressSnapshot.emittedFrames,
                    deliveredPayloads: []
                )
            }
        }
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

    /// Runs exactly one queued SecureLink application payload.  This method is
    /// deliberately not timed as a worker: the nested `securelink` scope is
    /// the atomic encrypt/decrypt operation reported to WebAdmin.
    func drainOnePendingSecureLinkPayload() throws -> OutboundSnapshot {
        guard let secureLinkAdapter else { return OutboundSnapshot(emittedFrames: []) }
        let snapshot = try secureLinkAdapter.drainOnePendingPayload()
        return OutboundSnapshot(emittedFrames: snapshot.emittedFrames, queuedPayloads: snapshot.queuedPayloads)
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
        }
    }

    private func refreshOuterLifecycle(secureLinkStatus: ObstacleBridgeSecureLinkPskRuntime.StatusSnapshot?) {
        let transportReady = transportLifecycle.state == .connected
        let secureReady = secureLinkStatus?.authenticated ?? transportReady
        if transportReady && secureReady, let epoch = coreCoordinator.snapshot.epoch {
            applyCore(.authenticated(epoch: epoch))
        }
        let coreReady = coreCoordinator.snapshot.appReady
        let compressionReady = compressionFailureEpoch != transportLifecycle.epoch
        let connected = transportReady && secureReady && coreReady && compressionReady
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
        } else if disconnectedSince == nil {
            disconnectedSince = outerLifecycle.changedAt
        }
    }
}
