import Foundation

enum ObstacleBridgeSecureLinkPskRuntimeError: Error { case invalidState, invalidFrame, authFailed(Int) }

/// Apple transport/status adapter. SecureLink protocol behavior belongs to Core.
final class ObstacleBridgeSecureLinkPskRuntime {
    static let typeClientHello = Int(ObstacleBridgeSecureLinkPSKFrameType.clientHello)
    static let typeServerHello = Int(ObstacleBridgeSecureLinkPSKFrameType.serverHello)
    static let typeAuthFail = Int(ObstacleBridgeSecureLinkPSKFrameType.authFail)
    static let typeData = Int(ObstacleBridgeSecureLinkPSKFrameType.authenticatedData)
    static let typeRekeyHello = Int(ObstacleBridgeSecureLinkPSKFrameType.rekeyHello)
    static let typeRekeyReply = Int(ObstacleBridgeSecureLinkPSKFrameType.rekeyReply)
    static let typeRekeyCommit = Int(ObstacleBridgeSecureLinkPSKFrameType.rekeyCommit)
    static let typeRekeyDone = Int(ObstacleBridgeSecureLinkPSKFrameType.rekeyDone)
    static let capabilityPSKV1 = Int(ObstacleBridgeSecureLinkPSKFrameType.capabilityPSKV1)
    static let authFailBadPSK = 1, authFailUnsupported = 2, authFailReplay = 3, authFailDecode = 4, authFailLifecycle = 5

    struct OutboundSnapshot { var sent: Bool; var emittedFrames: [Data]; var authenticated: Bool; var sessionID: UInt64; var txCounter: UInt64 }
    struct InboundSnapshot { var emittedFrames: [Data]; var deliveredPayloads: [Data]; var authenticated: Bool; var sessionID: UInt64; var rxCounter: UInt64; var authFailCode: Int? }
    struct StatusSnapshot {
        var clientMode: Bool; var authenticated: Bool; var peerConfirmedAuthenticated: Bool; var sessionID: UInt64; var txCounter: UInt64; var rxCounter: UInt64; var authFailCode: Int; var lastEvent: String; var lastEventUnixTs: TimeInterval?; var authenticatedSessionsTotal: Int; var rekeySupported: Bool; var rekeyInProgress: Bool; var rekeysCompletedTotal: Int; var lastRekeyTrigger: String; var disconnectReason: String; var disconnectDetail: String; var trustValidationState: String; var appDataSendingBlocked: Bool; var framesFromClientPassedTotal: Int; var framesFromClientDroppedTotal: Int; var framesToClientPassedTotal: Int; var handshakeAttemptsTotal: Int; var consecutiveFailures: Int; var retryBackoffSec: TimeInterval; var nextRetryUnixTs: TimeInterval?
    }

    private let clientMode: Bool
    private let psk: Data
    private let randomBytes: (Int) -> Data
    private let sessionIDProvider: () -> UInt64
    private let timeProvider: () -> TimeInterval
    private let unixTimeProvider: () -> TimeInterval
    private var coreClient: ObstacleBridgeSecureLinkPSKClient?
    private var coreServer: ObstacleBridgeSecureLinkPSKServer?
    // These are status snapshots from Core, not a second protocol state machine.
    private var sessionID: UInt64 = 0
    private var authenticated = false
    private var peerConfirmedAuthenticated = false
    private var txCounter: UInt64 = 1
    private var rxCounter: UInt64 = 0
    private var lastAuthFailCode = 0, authenticatedSessionsTotal = 0, rekeysCompletedTotal = 0
    private var pendingSessionID: UInt64 = 0
    private var lastEvent = "bootstrap", lastRekeyTrigger = "", disconnectReason = "", disconnectDetail = "", trustValidationState = "n/a"
    private var lastEventUnixTs: TimeInterval?
    private var clientRekeyHoldAfterCommit = false
    private var framesFromClientPassedTotal = 0, framesFromClientDroppedTotal = 0, framesToClientPassedTotal = 0

    init(clientMode: Bool, psk: String, rekeyAfterFrames: Int = 0, rekeyAfterSeconds: TimeInterval = 0.0, randomBytes: ((Int) -> Data)? = nil, sessionIDProvider: (() -> UInt64)? = nil, timeProvider: (() -> TimeInterval)? = nil, unixTimeProvider: (() -> TimeInterval)? = nil) {
        self.clientMode = clientMode; self.psk = Data(psk.utf8)
        self.randomBytes = randomBytes ?? { Data((0..<$0).map { _ in UInt8.random(in: 0...UInt8.max) }) }
        self.sessionIDProvider = sessionIDProvider ?? { UInt64.random(in: 1...UInt64.max) }
        self.timeProvider = timeProvider ?? { ProcessInfo.processInfo.systemUptime }
        self.unixTimeProvider = unixTimeProvider ?? { Date().timeIntervalSince1970 }
        guard !self.psk.isEmpty else { return }
        if clientMode {
            coreClient = try? ObstacleBridgeSecureLinkPSKClient(psk: self.psk, timeProvider: self.timeProvider, rekeyPolicy: .init(afterProtectedFrames: UInt64(max(0, rekeyAfterFrames)), afterAuthenticatedSeconds: max(0, rekeyAfterSeconds)), sessionIDProvider: self.sessionIDProvider, randomBytes: self.randomBytes)
        } else { coreServer = try? ObstacleBridgeSecureLinkPSKServer(psk: self.psk, timeProvider: self.timeProvider) }
    }

    var isAuthenticated: Bool { authenticated && peerConfirmedAuthenticated }
    func statusSnapshot() -> StatusSnapshot {
        expireHandshakeIfNeeded()
        return StatusSnapshot(clientMode: clientMode, authenticated: isAuthenticated, peerConfirmedAuthenticated: peerConfirmedAuthenticated, sessionID: sessionID, txCounter: txCounter, rxCounter: rxCounter, authFailCode: lastAuthFailCode, lastEvent: lastEvent, lastEventUnixTs: lastEventUnixTs, authenticatedSessionsTotal: authenticatedSessionsTotal, rekeySupported: true, rekeyInProgress: pendingSessionID != 0, rekeysCompletedTotal: rekeysCompletedTotal, lastRekeyTrigger: lastRekeyTrigger, disconnectReason: disconnectReason, disconnectDetail: disconnectDetail, trustValidationState: trustValidationState, appDataSendingBlocked: clientRekeyHoldAfterCommit, framesFromClientPassedTotal: framesFromClientPassedTotal, framesFromClientDroppedTotal: framesFromClientDroppedTotal, framesToClientPassedTotal: framesToClientPassedTotal, handshakeAttemptsTotal: 0, consecutiveFailures: 0, retryBackoffSec: 0, nextRetryUnixTs: nil)
    }
    func handleTransportDisconnected() { coreClient?.reset(); coreServer?.reset(); reset(false); disconnectReason = "transport_disconnected"; record("transport_disconnected") }
    func beginClientHandshake() throws -> OutboundSnapshot {
        guard clientMode, let coreClient else { throw ObstacleBridgeSecureLinkPskRuntimeError.invalidState }
        coreClient.reset(); reset(false); record("handshake_started")
        let f = try coreClient.begin(sessionID: sessionIDProvider(), clientNonce: Data(randomBytes(32).prefix(32))); syncClient(); return outbound([f])
    }
    func sendApp(_ payload: Data) throws -> OutboundSnapshot {
        if clientMode, let coreClient { var frames = [try coreClient.protect(payload)]; if let r = try coreClient.pollAutomaticRekey() { frames.append(r) }; syncClient(); framesFromClientPassedTotal &+= 1; return outbound(frames) }
        if !clientMode, let coreServer { let f = try coreServer.protect(payload); syncServer(); framesToClientPassedTotal &+= 1; return outbound([f]) }
        throw ObstacleBridgeSecureLinkPskRuntimeError.invalidState
    }
    func handleInboundFrame(_ wire: Data) -> InboundSnapshot {
        expireHandshakeIfNeeded()
        guard let frame = ObstacleBridgeSecureLinkPskCodec.parseFrame(wire) else { return fail(0, Self.authFailDecode) }
        switch frame.slType {
        case Self.typeClientHello where !clientMode: return coreServerHello(wire)
        case Self.typeServerHello where clientMode: return coreClientHello(wire)
        case Self.typeData where clientMode: return coreClientData(wire)
        case Self.typeData where !clientMode: return coreServerData(wire)
        case Self.typeRekeyHello where !clientMode: return coreServerRekeyHello(wire)
        case Self.typeRekeyReply where clientMode: return coreClientRekeyReply(wire)
        case Self.typeRekeyCommit where !clientMode: return coreServerRekeyCommit(wire)
        case Self.typeRekeyDone where clientMode: return coreClientRekeyDone(wire)
        case Self.typeAuthFail:
            let code = frame.payload.first.map(Int.init) ?? Self.authFailDecode; coreClient?.reset(); coreServer?.reset(); reset(true); lastAuthFailCode = code; disconnectReason = "auth_failed"; disconnectDetail = "code=\(code)"; trustValidationState = "failed"; record(authFailEvent(code)); return inbound([], [], code)
        default: return fail(frame.sessionID, Self.authFailUnsupported)
        }
    }
    func requestClientRekey() throws -> OutboundSnapshot {
        guard clientMode, let coreClient else { throw ObstacleBridgeSecureLinkPskRuntimeError.invalidState }
        let f = try coreClient.beginRekey(sessionID: nextSessionID(), clientNonce: Data(randomBytes(32).prefix(32))); syncClient(); lastRekeyTrigger = "operator"; record("rekey_started"); return outbound([f])
    }
    func pollDueFrames() throws -> [Data] { guard clientMode, let coreClient else { return [] }; let frames = try coreClient.pollAutomaticRekey().map { [$0] } ?? []; syncClient(); return frames }
    func expireHandshakeIfNeeded() { do { if clientMode, let c = coreClient { try c.expireHandshakeIfNeeded(); syncClient() } else if let s = coreServer { try s.expireHandshakeIfNeeded(); syncServer() } } catch { _ = fail(sessionID, Self.authFailLifecycle) } }

    private func coreClientHello(_ wire: Data) -> InboundSnapshot { guard let c = coreClient else { return fail(0, Self.authFailLifecycle) }; do { let f = try c.handleServerHello(wire); syncClient(); lastAuthFailCode = 0; disconnectReason = ""; disconnectDetail = ""; trustValidationState = "n/a"; record("server_hello_validated"); return inbound([f], []) } catch { return fail(sessionID, Self.authFailBadPSK) } }
    private func coreClientData(_ wire: Data) -> InboundSnapshot { guard let c = coreClient else { return fail(0, Self.authFailLifecycle) }; do { let p: Data; if !c.isAuthenticated { try c.handleServerAcknowledgement(wire); p = Data(); peerConfirmedAuthenticated = true; authenticatedSessionsTotal &+= 1; trustValidationState = "validated"; record("authenticated") } else { p = try c.unprotect(wire) }; syncClient(); framesToClientPassedTotal &+= 1; return inbound([], p.isEmpty ? [] : [p]) } catch { return fail(sessionID, Self.authFailBadPSK) } }
    private func coreClientRekeyReply(_ wire: Data) -> InboundSnapshot { guard let c = coreClient else { return fail(0, Self.authFailLifecycle) }; do { let f = try c.handleRekeyReply(wire); syncClient(); record("rekey_commit_sent"); return inbound([f], []) } catch { return fail(sessionID, Self.authFailBadPSK) } }
    private func coreClientRekeyDone(_ wire: Data) -> InboundSnapshot { guard let c = coreClient else { return fail(0, Self.authFailLifecycle) }; do { try c.handleRekeyDone(wire); syncClient(); rekeysCompletedTotal &+= 1; record("rekey_completed"); return inbound([], []) } catch { return fail(sessionID, Self.authFailBadPSK) } }
    private func coreServerHello(_ wire: Data) -> InboundSnapshot { guard let s = coreServer else { return fail(0, Self.authFailLifecycle) }; do { let f = try s.handleClientHello(wire, serverNonce: Data(randomBytes(32).prefix(32))); syncServer(); record("server_hello_sent"); return inbound([f], []) } catch { return fail(0, Self.authFailDecode) } }
    private func coreServerData(_ wire: Data) -> InboundSnapshot { guard let s = coreServer else { return fail(0, Self.authFailLifecycle) }; do { let p: Data; let frames: [Data]; if !s.isAuthenticated { frames = [try s.handleClientProof(wire)]; p = Data(); authenticatedSessionsTotal &+= 1; trustValidationState = "validated"; record("authenticated") } else { p = try s.unprotect(wire); frames = [] }; syncServer(); framesFromClientPassedTotal &+= 1; return inbound(frames, p.isEmpty ? [] : [p]) } catch { return fail(sessionID, Self.authFailBadPSK) } }
    private func coreServerRekeyHello(_ wire: Data) -> InboundSnapshot { guard let s = coreServer else { return fail(0, Self.authFailLifecycle) }; do { let f = try s.handleRekeyHello(wire, serverNonce: Data(randomBytes(32).prefix(32))); syncServer(); lastRekeyTrigger = "remote"; record("rekey_reply_sent"); return inbound([f], []) } catch { return fail(sessionID, Self.authFailBadPSK) } }
    private func coreServerRekeyCommit(_ wire: Data) -> InboundSnapshot { guard let s = coreServer else { return fail(0, Self.authFailLifecycle) }; do { let f = try s.handleRekeyCommit(wire); syncServer(); rekeysCompletedTotal &+= 1; record("rekey_completed"); return inbound([f], []) } catch { return fail(sessionID, Self.authFailBadPSK) } }
    private func syncClient() { guard let s = coreClient?.state else { return }; sessionID = s.sessionID; txCounter = s.txCounter; rxCounter = s.rxCounter; authenticated = s.authenticated; pendingSessionID = s.pendingRekeySessionID; clientRekeyHoldAfterCommit = s.applicationSendingBlocked }
    private func syncServer() { guard let s = coreServer?.state else { return }; sessionID = s.sessionID; txCounter = s.txCounter; rxCounter = s.rxCounter; authenticated = s.authenticated; peerConfirmedAuthenticated = s.authenticated; pendingSessionID = s.pendingRekeySessionID }
    private func outbound(_ frames: [Data]) -> OutboundSnapshot { OutboundSnapshot(sent: true, emittedFrames: frames, authenticated: isAuthenticated, sessionID: sessionID, txCounter: txCounter) }
    private func inbound(_ frames: [Data], _ payloads: [Data], _ code: Int? = nil) -> InboundSnapshot { InboundSnapshot(emittedFrames: frames, deliveredPayloads: payloads, authenticated: isAuthenticated, sessionID: sessionID, rxCounter: rxCounter, authFailCode: code) }
    private func fail(_ failedSessionID: UInt64, _ code: Int) -> InboundSnapshot { coreClient?.reset(); coreServer?.reset(); reset(true); if failedSessionID != 0 { sessionID = failedSessionID }; lastAuthFailCode = code; disconnectReason = "auth_failed"; disconnectDetail = "code=\(code)"; trustValidationState = "failed"; if !clientMode { framesFromClientDroppedTotal &+= 1 }; record(authFailEvent(code)); let f = ObstacleBridgeSecureLinkPskCodec.buildFrame(slType: Self.typeAuthFail, sessionID: failedSessionID, counter: 0, payload: Data([UInt8(code & 0xff)])); return inbound([f], [], code) }
    private func reset(_ keepSessionID: Bool) { if !keepSessionID { sessionID = 0; lastEvent = "bootstrap"; lastEventUnixTs = nil; authenticatedSessionsTotal = 0; rekeysCompletedTotal = 0; lastRekeyTrigger = ""; disconnectReason = ""; disconnectDetail = ""; trustValidationState = "n/a"; framesFromClientPassedTotal = 0; framesFromClientDroppedTotal = 0; framesToClientPassedTotal = 0 }; authenticated = false; peerConfirmedAuthenticated = false; txCounter = 1; rxCounter = 0; pendingSessionID = 0; clientRekeyHoldAfterCommit = false; lastAuthFailCode = 0 }
    private func nextSessionID() -> UInt64 { var candidate = sessionIDProvider(); while candidate == 0 || candidate == sessionID || candidate == pendingSessionID { candidate = sessionIDProvider() }; return candidate }
    private func record(_ event: String) { lastEvent = event; lastEventUnixTs = unixTimeProvider() }
    private func authFailEvent(_ code: Int) -> String { switch code { case Self.authFailBadPSK: return "auth_failed_bad_psk"; case Self.authFailUnsupported: return "auth_failed_unsupported"; case Self.authFailReplay: return "auth_failed_replay"; case Self.authFailDecode: return "auth_failed_decode"; case Self.authFailLifecycle: return "auth_failed_lifecycle"; default: return "auth_failed" } }
}
