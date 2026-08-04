import CryptoKit
import Foundation

enum ObstacleBridgeSecureLinkPskRuntimeError: Error {
    case invalidState
    case invalidFrame
    case authFailed(Int)
}

final class ObstacleBridgeSecureLinkPskRuntime {
    private static let clientTelemetryKind = "secure_link_client_telemetry_v1"
    private static let clientPlaintextTelemetryKind = "secure_link_client_plaintext_telemetry_v1"
    private static let clientTelemetryImplRevision = "swift-securelink-telemetry-r1"
    static let typeClientHello = 1
    static let typeServerHello = 2
    static let typeAuthFail = 3
    static let typeData = 4
    static let typeRekeyHello = 5
    static let typeRekeyReply = 6
    static let typeRekeyCommit = 7
    static let typeRekeyDone = 8
    static let typeClientPlaintextTelemetry = 9

    static let capabilityPSKV1 = 1

    static let authFailBadPSK = 1
    static let authFailUnsupported = 2
    static let authFailReplay = 3
    static let authFailDecode = 4
    static let authFailLifecycle = 5

    private static let firstDataCounter: UInt64 = 1
    private static let maxDataCounter: UInt64 = UInt64.max
    private static let handshakeTimeoutSeconds: TimeInterval = 60.0
    private static let plaintextTelemetryIntervalSeconds: TimeInterval = 1.0
    private static let clientRekeyCommitPrefix = Data("obstaclebridge-securelink-client-rekey-commit-v1|".utf8)

    struct OutboundSnapshot {
        var sent: Bool
        var emittedFrames: [Data]
        var authenticated: Bool
        var sessionID: UInt64
        var txCounter: UInt64
    }

    struct InboundSnapshot {
        var emittedFrames: [Data]
        var deliveredPayloads: [Data]
        var authenticated: Bool
        var sessionID: UInt64
        var rxCounter: UInt64
        var authFailCode: Int?
    }

    struct StatusSnapshot {
        var clientMode: Bool
        var authenticated: Bool
        var peerConfirmedAuthenticated: Bool
        var clientHandshakeProofSent: Bool
        var clientHandshakeProofSessionID: UInt64
        var clientHandshakeProofCounter: UInt64
        var serverAckSeen: Bool
        var lastFailureSessionID: UInt64
        var lastFailureUnixTS: TimeInterval?
        var lastFailureClientProofSent: Bool
        var lastFailureClientProofSessionID: UInt64
        var lastFailureClientProofCounter: UInt64
        var lastFailureServerAckSeen: Bool
        var sessionID: UInt64
        var txCounter: UInt64
        var rxCounter: UInt64
        var authFailCode: Int
        var authFailContext: String
        var lastInboundSLType: Int
        var lastInboundSessionID: UInt64
        var lastInboundCounter: UInt64
        var lastOutboundSLType: Int
        var lastOutboundSessionID: UInt64
        var lastOutboundCounter: UInt64
        var serverHelloReceived: Bool
        var serverHelloValidated: Bool
        var serverHelloValidatedSessionID: UInt64
        var serverHelloValidatedTxCounter: UInt64
        var serverHelloValidatedC2SKeySHA256Prefix: String
        var serverHelloValidatedS2CKeySHA256Prefix: String
        var clientHandshakeProofEmitSessionID: UInt64
        var clientHandshakeProofEmitCounter: UInt64
        var clientHandshakeProofEmitPayloadBytes: Int
        var clientHandshakeProofEmitPayloadSHA256Prefix: String
        var clientHandshakeProofEmitC2SKeySHA256Prefix: String
        var clientHandshakeProofSessionMatchesValidatedSession: Bool
        var clientHandshakeProofKeyMatchesValidatedKey: Bool
        var clientTelemetrySource: String
        var clientTelemetryReceivedUnixTS: TimeInterval?
        var clientTelemetryCurrentAttemptSessionID: UInt64
        var clientTelemetryLocalAuthenticated: Bool
        var clientTelemetryPeerConfirmedAuthenticated: Bool
        var clientTelemetryServerHelloReceived: Bool
        var clientTelemetryServerHelloValidated: Bool
        var clientTelemetryHandshakeProofSessionID: UInt64
        var clientTelemetryHandshakeProofCounter: UInt64
        var clientTelemetryLastInboundSLType: Int
        var clientTelemetryLastInboundSessionID: UInt64
        var clientTelemetryLastInboundCounter: UInt64
        var clientTelemetryLastOutboundSLType: Int
        var clientTelemetryLastOutboundSessionID: UInt64
        var clientTelemetryLastOutboundCounter: UInt64
        var clientHandshakeTelemetryBuildSucceeded: Bool
        var clientHandshakeTelemetryPayloadBytes: Int
        var clientHandshakeTelemetryPayloadSHA256Prefix: String
        var clientHandshakeTelemetryBuildError: String
        var clientPlaintextTelemetryImplRevision: String
        var clientPlaintextTelemetryBuildSucceeded: Bool
        var clientPlaintextTelemetryPayloadBytes: Int
        var clientPlaintextTelemetryPayloadSHA256Prefix: String
        var clientPlaintextTelemetryBuildError: String
        var clientPlaintextTelemetryFrameSessionID: UInt64
        var stickyAuthFailCode: Int
        var stickyAuthFailReason: String
        var stickyAuthFailContext: String
        var pendingSessionID: UInt64
        var clientRekeyHoldAfterCommit: Bool
        var rekeysCompletedTotal: Int
        var lastRekeyTrigger: String
    }

    private let clientMode: Bool
    private let psk: Data
    private let randomBytes: (Int) -> Data
    private let sessionIDProvider: () -> UInt64
    private let timeProvider: () -> TimeInterval
    private let rekeyAfterFrames: Int

    private var sessionID: UInt64 = 0
    private var authenticated = false
    private var peerConfirmedAuthenticated = false
    private var clientNonce = Data()
    private var serverNonce = Data()
    private var c2sKey: Data?
    private var s2cKey: Data?
    private var txCounter: UInt64 = 1
    private var rxCounter: UInt64 = 0
    private var clientHandshakeProofSent = false
    private var clientHandshakeProofSessionID: UInt64 = 0
    private var clientHandshakeProofCounter: UInt64 = 0
    private var serverAckSeen = false
    private var lastFailureSessionID: UInt64 = 0
    private var lastFailureUnixTS: TimeInterval?
    private var lastFailureClientProofSent = false
    private var lastFailureClientProofSessionID: UInt64 = 0
    private var lastFailureClientProofCounter: UInt64 = 0
    private var lastFailureServerAckSeen = false
    private var lastAuthFailCode = 0
    private var lastAuthFailContext = ""
    private var handshakeStartedAt: TimeInterval?
    private var lastInboundSLType = 0
    private var lastInboundSessionID: UInt64 = 0
    private var lastInboundCounter: UInt64 = 0
    private var lastOutboundSLType = 0
    private var lastOutboundSessionID: UInt64 = 0
    private var lastOutboundCounter: UInt64 = 0
    private var serverHelloReceived = false
    private var serverHelloValidated = false
    private var serverHelloValidatedSessionID: UInt64 = 0
    private var serverHelloValidatedTxCounter: UInt64 = 0
    private var serverHelloValidatedC2SKeySHA256Prefix = ""
    private var serverHelloValidatedS2CKeySHA256Prefix = ""
    private var clientHandshakeProofEmitSessionID: UInt64 = 0
    private var clientHandshakeProofEmitCounter: UInt64 = 0
    private var clientHandshakeProofEmitPayloadBytes = 0
    private var clientHandshakeProofEmitPayloadSHA256Prefix = ""
    private var clientHandshakeProofEmitC2SKeySHA256Prefix = ""
    private var clientHandshakeProofSessionMatchesValidatedSession = false
    private var clientHandshakeProofKeyMatchesValidatedKey = false
    private var clientTelemetrySource = ""
    private var clientTelemetryReceivedUnixTS: TimeInterval?
    private var clientTelemetryCurrentAttemptSessionID: UInt64 = 0
    private var clientTelemetryLocalAuthenticated = false
    private var clientTelemetryPeerConfirmedAuthenticated = false
    private var clientTelemetryServerHelloReceived = false
    private var clientTelemetryServerHelloValidated = false
    private var clientTelemetryHandshakeProofSessionID: UInt64 = 0
    private var clientTelemetryHandshakeProofCounter: UInt64 = 0
    private var clientTelemetryLastInboundSLType = 0
    private var clientTelemetryLastInboundSessionID: UInt64 = 0
    private var clientTelemetryLastInboundCounter: UInt64 = 0
    private var clientTelemetryLastOutboundSLType = 0
    private var clientTelemetryLastOutboundSessionID: UInt64 = 0
    private var clientTelemetryLastOutboundCounter: UInt64 = 0
    private var clientHandshakeTelemetryBuildSucceeded = false
    private var clientHandshakeTelemetryPayloadBytes = 0
    private var clientHandshakeTelemetryPayloadSHA256Prefix = ""
    private var clientHandshakeTelemetryBuildError = ""
    private var clientPlaintextTelemetryImplRevision = ObstacleBridgeSecureLinkPskRuntime.clientTelemetryImplRevision
    private var clientPlaintextTelemetryBuildSucceeded = false
    private var clientPlaintextTelemetryPayloadBytes = 0
    private var clientPlaintextTelemetryPayloadSHA256Prefix = ""
    private var clientPlaintextTelemetryBuildError = ""
    private var clientPlaintextTelemetryFrameSessionID: UInt64 = 0
    private var lastPlaintextTelemetryUnixTS: TimeInterval?
    private var stickyAuthFailCode = 0
    private var stickyAuthFailReason = ""
    private var stickyAuthFailContext = ""
    private var pendingSessionID: UInt64 = 0
    private var pendingClientNonce = Data()
    private var pendingServerNonce = Data()
    private var pendingC2SKey: Data?
    private var pendingS2CKey: Data?
    private var clientRekeyHoldAfterCommit = false
    private var rekeysCompletedTotal = 0
    private var lastRekeyTrigger = ""

    init(
        clientMode: Bool,
        psk: String,
        rekeyAfterFrames: Int = 0,
        randomBytes: ((Int) -> Data)? = nil,
        sessionIDProvider: (() -> UInt64)? = nil,
        timeProvider: (() -> TimeInterval)? = nil
    ) {
        self.clientMode = clientMode
        self.psk = Data(psk.utf8)
        self.rekeyAfterFrames = max(0, rekeyAfterFrames)
        self.randomBytes = randomBytes ?? { count in
            Data((0..<count).map { _ in UInt8.random(in: 0...UInt8.max) })
        }
        self.sessionIDProvider = sessionIDProvider ?? {
            var candidate = UInt64.random(in: 1...UInt64.max)
            if candidate == 0 {
                candidate = 1
            }
            return candidate
        }
        self.timeProvider = timeProvider ?? { ProcessInfo.processInfo.systemUptime }
    }

    var isAuthenticated: Bool {
        authenticated
    }

    func statusSnapshot() -> StatusSnapshot {
        expireHandshakeIfNeeded()
        return StatusSnapshot(
            clientMode: clientMode,
            authenticated: authenticated,
            peerConfirmedAuthenticated: peerConfirmedAuthenticated,
            clientHandshakeProofSent: clientHandshakeProofSent,
            clientHandshakeProofSessionID: clientHandshakeProofSessionID,
            clientHandshakeProofCounter: clientHandshakeProofCounter,
            serverAckSeen: serverAckSeen,
            lastFailureSessionID: lastFailureSessionID,
            lastFailureUnixTS: lastFailureUnixTS,
            lastFailureClientProofSent: lastFailureClientProofSent,
            lastFailureClientProofSessionID: lastFailureClientProofSessionID,
            lastFailureClientProofCounter: lastFailureClientProofCounter,
            lastFailureServerAckSeen: lastFailureServerAckSeen,
            sessionID: sessionID,
            txCounter: txCounter,
            rxCounter: rxCounter,
            authFailCode: lastAuthFailCode,
            authFailContext: lastAuthFailContext,
            lastInboundSLType: lastInboundSLType,
            lastInboundSessionID: lastInboundSessionID,
            lastInboundCounter: lastInboundCounter,
            lastOutboundSLType: lastOutboundSLType,
            lastOutboundSessionID: lastOutboundSessionID,
            lastOutboundCounter: lastOutboundCounter,
            serverHelloReceived: serverHelloReceived,
            serverHelloValidated: serverHelloValidated,
            serverHelloValidatedSessionID: serverHelloValidatedSessionID,
            serverHelloValidatedTxCounter: serverHelloValidatedTxCounter,
            serverHelloValidatedC2SKeySHA256Prefix: serverHelloValidatedC2SKeySHA256Prefix,
            serverHelloValidatedS2CKeySHA256Prefix: serverHelloValidatedS2CKeySHA256Prefix,
            clientHandshakeProofEmitSessionID: clientHandshakeProofEmitSessionID,
            clientHandshakeProofEmitCounter: clientHandshakeProofEmitCounter,
            clientHandshakeProofEmitPayloadBytes: clientHandshakeProofEmitPayloadBytes,
            clientHandshakeProofEmitPayloadSHA256Prefix: clientHandshakeProofEmitPayloadSHA256Prefix,
            clientHandshakeProofEmitC2SKeySHA256Prefix: clientHandshakeProofEmitC2SKeySHA256Prefix,
            clientHandshakeProofSessionMatchesValidatedSession: clientHandshakeProofSessionMatchesValidatedSession,
            clientHandshakeProofKeyMatchesValidatedKey: clientHandshakeProofKeyMatchesValidatedKey,
            clientTelemetrySource: clientTelemetrySource,
            clientTelemetryReceivedUnixTS: clientTelemetryReceivedUnixTS,
            clientTelemetryCurrentAttemptSessionID: clientTelemetryCurrentAttemptSessionID,
            clientTelemetryLocalAuthenticated: clientTelemetryLocalAuthenticated,
            clientTelemetryPeerConfirmedAuthenticated: clientTelemetryPeerConfirmedAuthenticated,
            clientTelemetryServerHelloReceived: clientTelemetryServerHelloReceived,
            clientTelemetryServerHelloValidated: clientTelemetryServerHelloValidated,
            clientTelemetryHandshakeProofSessionID: clientTelemetryHandshakeProofSessionID,
            clientTelemetryHandshakeProofCounter: clientTelemetryHandshakeProofCounter,
            clientTelemetryLastInboundSLType: clientTelemetryLastInboundSLType,
            clientTelemetryLastInboundSessionID: clientTelemetryLastInboundSessionID,
            clientTelemetryLastInboundCounter: clientTelemetryLastInboundCounter,
            clientTelemetryLastOutboundSLType: clientTelemetryLastOutboundSLType,
            clientTelemetryLastOutboundSessionID: clientTelemetryLastOutboundSessionID,
            clientTelemetryLastOutboundCounter: clientTelemetryLastOutboundCounter,
            clientHandshakeTelemetryBuildSucceeded: clientHandshakeTelemetryBuildSucceeded,
            clientHandshakeTelemetryPayloadBytes: clientHandshakeTelemetryPayloadBytes,
            clientHandshakeTelemetryPayloadSHA256Prefix: clientHandshakeTelemetryPayloadSHA256Prefix,
            clientHandshakeTelemetryBuildError: clientHandshakeTelemetryBuildError,
            clientPlaintextTelemetryImplRevision: clientPlaintextTelemetryImplRevision,
            clientPlaintextTelemetryBuildSucceeded: clientPlaintextTelemetryBuildSucceeded,
            clientPlaintextTelemetryPayloadBytes: clientPlaintextTelemetryPayloadBytes,
            clientPlaintextTelemetryPayloadSHA256Prefix: clientPlaintextTelemetryPayloadSHA256Prefix,
            clientPlaintextTelemetryBuildError: clientPlaintextTelemetryBuildError,
            clientPlaintextTelemetryFrameSessionID: clientPlaintextTelemetryFrameSessionID,
            stickyAuthFailCode: stickyAuthFailCode,
            stickyAuthFailReason: stickyAuthFailReason,
            stickyAuthFailContext: stickyAuthFailContext,
            pendingSessionID: pendingSessionID,
            clientRekeyHoldAfterCommit: clientRekeyHoldAfterCommit,
            rekeysCompletedTotal: rekeysCompletedTotal,
            lastRekeyTrigger: lastRekeyTrigger
        )
    }

    func handleTransportDisconnected() {
        resetAuthState(keepSessionID: false)
        lastAuthFailCode = 0
    }

    func beginClientHandshake() throws -> OutboundSnapshot {
        guard clientMode, !psk.isEmpty else {
            throw ObstacleBridgeSecureLinkPskRuntimeError.invalidState
        }
        resetAuthState(keepSessionID: false)
        sessionID = sessionIDProvider()
        handshakeStartedAt = timeProvider()
        clientNonce = Data(randomBytes(32).prefix(32))
        let payload = clientNonce + Data([UInt8(Self.capabilityPSKV1), 0])
        let frame = ObstacleBridgeSecureLinkPskCodec.buildFrame(
            slType: Self.typeClientHello,
            sessionID: sessionID,
            counter: 0,
            payload: payload
        )
        noteOutboundFrame(slType: Self.typeClientHello, sessionID: sessionID, counter: 0)
        return OutboundSnapshot(
            sent: true,
            emittedFrames: [frame],
            authenticated: authenticated,
            sessionID: sessionID,
            txCounter: txCounter
        )
    }

    func retryClientHandshake() throws -> OutboundSnapshot {
        guard clientMode, !psk.isEmpty, sessionID > 0, !authenticated, lastAuthFailCode == 0, !clientNonce.isEmpty else {
            throw ObstacleBridgeSecureLinkPskRuntimeError.invalidState
        }
        if handshakeStartedAt == nil {
            handshakeStartedAt = timeProvider()
        }
        let payload = clientNonce + Data([UInt8(Self.capabilityPSKV1), 0])
        let frame = ObstacleBridgeSecureLinkPskCodec.buildFrame(
            slType: Self.typeClientHello,
            sessionID: sessionID,
            counter: 0,
            payload: payload
        )
        noteOutboundFrame(slType: Self.typeClientHello, sessionID: sessionID, counter: 0)
        return OutboundSnapshot(
            sent: true,
            emittedFrames: [frame],
            authenticated: authenticated,
            sessionID: sessionID,
            txCounter: txCounter
        )
    }

    func emitClientPeerConfirmationProbe() throws -> OutboundSnapshot {
        guard clientMode, authenticated, !peerConfirmedAuthenticated, lastAuthFailCode == 0 else {
            throw ObstacleBridgeSecureLinkPskRuntimeError.invalidState
        }
        let snapshot = try sendApp(Data())
        return OutboundSnapshot(
            sent: snapshot.sent,
            emittedFrames: snapshot.emittedFrames,
            authenticated: snapshot.authenticated,
            sessionID: snapshot.sessionID,
            txCounter: snapshot.txCounter
        )
    }

    func emitPeriodicClientPlaintextTelemetry() -> Data? {
        guard clientMode else {
            return nil
        }
        let now = timeProvider()
        if let lastPlaintextTelemetryUnixTS,
           now >= lastPlaintextTelemetryUnixTS,
           (now - lastPlaintextTelemetryUnixTS) < Self.plaintextTelemetryIntervalSeconds {
            return nil
        }
        let telemetrySessionID = pendingSessionID != 0 ? pendingSessionID : sessionID
        let payload = clientPlaintextTelemetryPayload()
        guard !payload.isEmpty else {
            return nil
        }
        lastPlaintextTelemetryUnixTS = now
        clientPlaintextTelemetryFrameSessionID = telemetrySessionID
        noteOutboundFrame(slType: Self.typeClientPlaintextTelemetry, sessionID: telemetrySessionID, counter: 0)
        return ObstacleBridgeSecureLinkPskCodec.buildFrame(
            slType: Self.typeClientPlaintextTelemetry,
            sessionID: telemetrySessionID,
            counter: 0,
            payload: payload
        )
    }

    func sendApp(_ payload: Data) throws -> OutboundSnapshot {
        expireHandshakeIfNeeded()
        guard !clientRekeyHoldAfterCommit else {
            throw ObstacleBridgeSecureLinkPskRuntimeError.invalidState
        }
        guard authenticated, sessionID > 0 else {
            throw ObstacleBridgeSecureLinkPskRuntimeError.invalidState
        }
        guard txCounter >= Self.firstDataCounter, txCounter <= Self.maxDataCounter else {
            throw ObstacleBridgeSecureLinkPskRuntimeError.authFailed(Self.authFailLifecycle)
        }
        guard let outboundKey = clientMode ? c2sKey : s2cKey else {
            throw ObstacleBridgeSecureLinkPskRuntimeError.invalidState
        }
        let aad = ObstacleBridgeSecureLinkPskCodec.headerBytes(
            slType: Self.typeData,
            sessionID: sessionID,
            counter: txCounter
        )
        let ciphertext = try seal(payload: payload, key: outboundKey, counter: txCounter, aad: aad)
        let frame = aad + ciphertext
        noteOutboundFrame(slType: Self.typeData, sessionID: sessionID, counter: txCounter)
        txCounter &+= 1
        var emittedFrames = [frame]
        if clientMode, pendingSessionID == 0, rekeyAfterFrames > 0 {
            let sentFrames = max(0, Int(txCounter) - 1 - (clientHandshakeProofSent ? 1 : 0))
            if sentFrames >= rekeyAfterFrames {
                emittedFrames.append(try startClientRekey(trigger: "frame_threshold"))
            }
        }
        return OutboundSnapshot(
            sent: true,
            emittedFrames: emittedFrames,
            authenticated: authenticated,
            sessionID: sessionID,
            txCounter: txCounter
        )
    }

    func handleInboundFrame(_ payload: Data) -> InboundSnapshot {
        expireHandshakeIfNeeded()
        guard let frame = ObstacleBridgeSecureLinkPskCodec.parseFrame(payload) else {
            return fail(sessionID: 0, code: Self.authFailDecode)
        }
        if shouldIgnoreStaleInboundFrame(frame) {
            return InboundSnapshot(
                emittedFrames: [],
                deliveredPayloads: [],
                authenticated: authenticated,
                sessionID: self.sessionID,
                rxCounter: rxCounter,
                authFailCode: nil
            )
        }
        lastInboundSLType = frame.slType
        lastInboundSessionID = frame.sessionID
        lastInboundCounter = frame.counter
        switch frame.slType {
        case Self.typeClientHello:
            return handleClientHello(sessionID: frame.sessionID, body: frame.payload)
        case Self.typeServerHello:
            return handleServerHello(sessionID: frame.sessionID, body: frame.payload)
        case Self.typeAuthFail:
            let code = frame.payload.first.map(Int.init) ?? Self.authFailDecode
            lastAuthFailCode = code
            authenticated = false
            peerConfirmedAuthenticated = false
            return InboundSnapshot(
                emittedFrames: [],
                deliveredPayloads: [],
                authenticated: authenticated,
                sessionID: sessionID,
                rxCounter: rxCounter,
                authFailCode: code
            )
        case Self.typeData:
            let aad = ObstacleBridgeSecureLinkPskCodec.headerBytes(
                slType: frame.slType,
                sessionID: frame.sessionID,
                counter: frame.counter
            )
            return handleData(sessionID: frame.sessionID, counter: frame.counter, body: frame.payload, aad: aad)
        case Self.typeRekeyHello:
            return handleRekeyHello(sessionID: frame.sessionID, body: frame.payload)
        case Self.typeRekeyReply:
            return handleRekeyReply(sessionID: frame.sessionID, body: frame.payload)
        case Self.typeRekeyCommit:
            return handleRekeyCommit(sessionID: frame.sessionID, body: frame.payload)
        case Self.typeRekeyDone:
            return handleRekeyDone(sessionID: frame.sessionID)
        case Self.typeClientPlaintextTelemetry:
            if !clientMode {
                _ = captureClientPlaintextTelemetry(frame.payload, observedSessionID: frame.sessionID)
            }
            return InboundSnapshot(
                emittedFrames: [],
                deliveredPayloads: [],
                authenticated: authenticated,
                sessionID: self.sessionID,
                rxCounter: rxCounter,
                authFailCode: nil
            )
        default:
            return fail(sessionID: frame.sessionID, code: Self.authFailUnsupported)
        }
    }

    private func handleClientHello(sessionID: UInt64, body: Data) -> InboundSnapshot {
        guard !clientMode, sessionID > 0 else {
            return fail(sessionID: sessionID, code: Self.authFailDecode)
        }
        guard !psk.isEmpty, body.count >= 34 else {
            return fail(sessionID: sessionID, code: Self.authFailDecode)
        }
        let clientNonce = body.prefix(32)
        let capability = Int(body[32])
        guard capability == Self.capabilityPSKV1 else {
            return fail(sessionID: sessionID, code: Self.authFailUnsupported)
        }
        if self.sessionID == sessionID,
           !authenticated,
           lastAuthFailCode == 0,
           self.clientNonce == clientNonce,
           serverNonce.count == 32,
           c2sKey != nil,
           s2cKey != nil {
            let proof = serverProof(sessionID: sessionID, clientNonce: self.clientNonce, serverNonce: self.serverNonce)
            let responsePayload = self.serverNonce + Data([UInt8(Self.capabilityPSKV1)]) + proof
            let response = ObstacleBridgeSecureLinkPskCodec.buildFrame(
                slType: Self.typeServerHello,
                sessionID: sessionID,
                counter: 0,
                payload: responsePayload
            )
            noteOutboundFrame(slType: Self.typeServerHello, sessionID: sessionID, counter: 0)
            return InboundSnapshot(
                emittedFrames: [response],
                deliveredPayloads: [],
                authenticated: authenticated,
                sessionID: self.sessionID,
                rxCounter: rxCounter,
                authFailCode: nil
            )
        }
        resetAuthState(keepSessionID: false)
        self.sessionID = sessionID
        handshakeStartedAt = timeProvider()
        self.clientNonce = Data(clientNonce)
        self.serverNonce = Data(randomBytes(32).prefix(32))
        let keys = ObstacleBridgeSecureLinkPskCodec.deriveKeys(
            psk: psk,
            sessionID: sessionID,
            clientNonce: self.clientNonce,
            serverNonce: self.serverNonce
        )
        c2sKey = keys.0
        s2cKey = keys.1
        let proof = serverProof(sessionID: sessionID, clientNonce: self.clientNonce, serverNonce: self.serverNonce)
        let responsePayload = self.serverNonce + Data([UInt8(Self.capabilityPSKV1)]) + proof
        let response = ObstacleBridgeSecureLinkPskCodec.buildFrame(
            slType: Self.typeServerHello,
            sessionID: sessionID,
            counter: 0,
            payload: responsePayload
        )
        noteOutboundFrame(slType: Self.typeServerHello, sessionID: sessionID, counter: 0)
        return InboundSnapshot(
            emittedFrames: [response],
            deliveredPayloads: [],
            authenticated: authenticated,
            sessionID: self.sessionID,
            rxCounter: rxCounter,
            authFailCode: nil
        )
    }

    private func handleServerHello(sessionID: UInt64, body: Data) -> InboundSnapshot {
        serverHelloReceived = true
        guard clientMode, sessionID > 0, self.sessionID == sessionID else {
            return fail(sessionID: sessionID, code: Self.authFailDecode)
        }
        guard !psk.isEmpty, body.count >= 65 else {
            return fail(sessionID: sessionID, code: Self.authFailDecode)
        }
        let serverNonce = body.prefix(32)
        let capability = Int(body[32])
        let proof = body.subdata(in: 33..<65)
        guard capability == Self.capabilityPSKV1 else {
            return fail(sessionID: sessionID, code: Self.authFailUnsupported)
        }
        let expected = serverProof(sessionID: sessionID, clientNonce: clientNonce, serverNonce: Data(serverNonce))
        guard proof == expected else {
            return fail(sessionID: sessionID, code: Self.authFailBadPSK)
        }
        serverHelloValidated = true
        self.serverNonce = Data(serverNonce)
        let keys = ObstacleBridgeSecureLinkPskCodec.deriveKeys(
            psk: psk,
            sessionID: sessionID,
            clientNonce: clientNonce,
            serverNonce: self.serverNonce
        )
        c2sKey = keys.0
        s2cKey = keys.1
        serverHelloValidatedSessionID = sessionID
        serverHelloValidatedTxCounter = txCounter
        serverHelloValidatedC2SKeySHA256Prefix = sha256Prefix(keys.0)
        serverHelloValidatedS2CKeySHA256Prefix = sha256Prefix(keys.1)
        authenticated = true
        peerConfirmedAuthenticated = false
        lastAuthFailCode = 0
        if clientHandshakeProofSent {
            return InboundSnapshot(
                emittedFrames: [],
                deliveredPayloads: [],
                authenticated: authenticated,
                sessionID: self.sessionID,
                rxCounter: rxCounter,
                authFailCode: nil
            )
        }
        do {
            let proofFrame = try buildClientHandshakeProofFrame()
            return InboundSnapshot(
                emittedFrames: [proofFrame],
                deliveredPayloads: [],
                authenticated: authenticated,
                sessionID: self.sessionID,
                rxCounter: rxCounter,
                authFailCode: nil
            )
        } catch {
            return fail(sessionID: sessionID, code: Self.authFailLifecycle, context: "handle_server_hello.proof_frame_emit")
        }
    }

    private func handleData(sessionID: UInt64, counter: UInt64, body: Data, aad: Data) -> InboundSnapshot {
        guard self.sessionID > 0, self.sessionID == sessionID else {
            return fail(sessionID: sessionID, code: Self.authFailDecode)
        }
        guard counter >= Self.firstDataCounter, counter <= Self.maxDataCounter else {
            return fail(sessionID: sessionID, code: Self.authFailLifecycle, context: "handle_data.counter_range")
        }
        guard counter > rxCounter else {
            return fail(sessionID: sessionID, code: Self.authFailReplay)
        }
        guard let inboundKey = clientMode ? s2cKey : c2sKey else {
            return fail(sessionID: sessionID, code: Self.authFailDecode)
        }
        let plaintext: Data
        do {
            plaintext = try open(ciphertext: body, key: inboundKey, counter: counter, aad: aad)
        } catch {
            return fail(sessionID: sessionID, code: Self.authFailBadPSK)
        }
        rxCounter = counter
        var emittedFrames: [Data] = []
        if !authenticated {
            authenticated = true
            lastAuthFailCode = 0
            if !clientMode, let outboundKey = s2cKey {
                do {
                    let ackAAD = ObstacleBridgeSecureLinkPskCodec.headerBytes(
                        slType: Self.typeData,
                        sessionID: sessionID,
                        counter: txCounter
                    )
                    let ackCiphertext = try seal(payload: Data(), key: outboundKey, counter: txCounter, aad: ackAAD)
                    emittedFrames.append(ackAAD + ackCiphertext)
                    noteOutboundFrame(slType: Self.typeData, sessionID: sessionID, counter: txCounter)
                    txCounter &+= 1
                } catch {
                    return fail(sessionID: sessionID, code: Self.authFailLifecycle, context: "handle_data.server_ack_emit")
                }
            }
        }
        if !peerConfirmedAuthenticated {
            peerConfirmedAuthenticated = true
            serverAckSeen = clientMode
            handshakeStartedAt = nil
        }
        if !clientMode && captureClientHandshakeTelemetry(
            plaintext,
            observedSessionID: sessionID,
            observedCounter: counter
        ) {
            return InboundSnapshot(
                emittedFrames: emittedFrames,
                deliveredPayloads: [],
                authenticated: authenticated,
                sessionID: self.sessionID,
                rxCounter: rxCounter,
                authFailCode: nil
            )
        }
        return InboundSnapshot(
            emittedFrames: emittedFrames,
            deliveredPayloads: plaintext.isEmpty ? [] : [plaintext],
            authenticated: authenticated,
            sessionID: self.sessionID,
            rxCounter: rxCounter,
            authFailCode: nil
        )
    }

    private func buildClientHandshakeProofFrame() throws -> Data {
        guard clientMode, authenticated, !clientHandshakeProofSent else {
            throw ObstacleBridgeSecureLinkPskRuntimeError.invalidState
        }
        guard let outboundKey = c2sKey else {
            throw ObstacleBridgeSecureLinkPskRuntimeError.invalidState
        }
        let counter = txCounter
        guard counter >= Self.firstDataCounter, counter <= Self.maxDataCounter else {
            throw ObstacleBridgeSecureLinkPskRuntimeError.authFailed(Self.authFailLifecycle)
        }
        let aad = ObstacleBridgeSecureLinkPskCodec.headerBytes(
            slType: Self.typeData,
            sessionID: sessionID,
            counter: counter
        )
        let telemetry = clientHandshakeTelemetryPayload(proofCounter: counter)
        let outboundKeySHA256Prefix = sha256Prefix(outboundKey)
        clientHandshakeProofEmitSessionID = sessionID
        clientHandshakeProofEmitCounter = counter
        clientHandshakeProofEmitPayloadBytes = telemetry.count
        clientHandshakeProofEmitPayloadSHA256Prefix = telemetry.isEmpty ? "" : sha256Prefix(telemetry)
        clientHandshakeProofEmitC2SKeySHA256Prefix = outboundKeySHA256Prefix
        clientHandshakeProofSessionMatchesValidatedSession = serverHelloValidatedSessionID != 0 && serverHelloValidatedSessionID == sessionID
        clientHandshakeProofKeyMatchesValidatedKey =
            !serverHelloValidatedC2SKeySHA256Prefix.isEmpty &&
            serverHelloValidatedC2SKeySHA256Prefix == outboundKeySHA256Prefix
        let ciphertext = try seal(payload: telemetry, key: outboundKey, counter: counter, aad: aad)
        noteOutboundFrame(slType: Self.typeData, sessionID: sessionID, counter: counter)
        txCounter &+= 1
        clientHandshakeProofSent = true
        clientHandshakeProofSessionID = sessionID
        clientHandshakeProofCounter = counter
        return aad + ciphertext
    }

    private func clientHandshakeTelemetryPayload(proofCounter: UInt64) -> Data {
        let payload: [String: Any] = [
            "kind": Self.clientTelemetryKind,
            "impl": "swift",
            "impl_rev": Self.clientTelemetryImplRevision,
            "current_attempt_session_id": sessionID == 0 ? NSNull() : NSNumber(value: sessionID),
            "local_authenticated": authenticated,
            "peer_confirmed_authenticated": peerConfirmedAuthenticated,
            "server_hello_received": serverHelloReceived,
            "server_hello_validated": serverHelloValidated,
            "client_handshake_proof_session_id": sessionID == 0 ? NSNull() : NSNumber(value: sessionID),
            "client_handshake_proof_counter": NSNumber(value: proofCounter),
            "last_inbound_sl_type": lastInboundSLType == 0 ? NSNull() : NSNumber(value: lastInboundSLType),
            "last_inbound_session_id": lastInboundSessionID == 0 ? NSNull() : NSNumber(value: lastInboundSessionID),
            "last_inbound_counter": lastInboundCounter == 0 ? NSNull() : NSNumber(value: lastInboundCounter),
            "last_outbound_sl_type": NSNumber(value: Self.typeData),
            "last_outbound_session_id": sessionID == 0 ? NSNull() : NSNumber(value: sessionID),
            "last_outbound_counter": NSNumber(value: proofCounter),
        ]
        guard JSONSerialization.isValidJSONObject(payload) else {
            clientHandshakeTelemetryBuildSucceeded = false
            clientHandshakeTelemetryPayloadBytes = 0
            clientHandshakeTelemetryPayloadSHA256Prefix = ""
            clientHandshakeTelemetryBuildError = "invalid_json_object"
            return Data()
        }
        guard let encoded = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]) else {
            clientHandshakeTelemetryBuildSucceeded = false
            clientHandshakeTelemetryPayloadBytes = 0
            clientHandshakeTelemetryPayloadSHA256Prefix = ""
            clientHandshakeTelemetryBuildError = "json_serialization_failed"
            return Data()
        }
        clientHandshakeTelemetryBuildSucceeded = true
        clientHandshakeTelemetryPayloadBytes = encoded.count
        clientHandshakeTelemetryPayloadSHA256Prefix = sha256Prefix(encoded)
        clientHandshakeTelemetryBuildError = ""
        return encoded
    }

    private func clientPlaintextTelemetryPayload() -> Data {
        let payload: [String: Any] = [
            "kind": Self.clientPlaintextTelemetryKind,
            "impl": "swift",
            "impl_rev": Self.clientTelemetryImplRevision,
            "current_attempt_session_id": sessionID == 0 ? NSNull() : NSNumber(value: sessionID),
            "pending_session_id": pendingSessionID == 0 ? NSNull() : NSNumber(value: pendingSessionID),
            "local_authenticated": authenticated,
            "peer_confirmed_authenticated": peerConfirmedAuthenticated,
            "server_hello_received": serverHelloReceived,
            "server_hello_validated": serverHelloValidated,
            "server_ack_seen": serverAckSeen,
            "client_handshake_proof_sent": clientHandshakeProofSent,
            "client_handshake_proof_session_id": clientHandshakeProofSessionID == 0 ? NSNull() : NSNumber(value: clientHandshakeProofSessionID),
            "client_handshake_proof_counter": clientHandshakeProofCounter == 0 ? NSNull() : NSNumber(value: clientHandshakeProofCounter),
            "client_handshake_telemetry_build_succeeded": clientHandshakeTelemetryBuildSucceeded,
            "client_handshake_telemetry_payload_bytes": NSNumber(value: clientHandshakeTelemetryPayloadBytes),
            "client_handshake_telemetry_payload_sha256_prefix": clientHandshakeTelemetryPayloadSHA256Prefix,
            "client_handshake_telemetry_build_error": clientHandshakeTelemetryBuildError,
            "client_handshake_proof_emit_session_id": clientHandshakeProofEmitSessionID == 0 ? NSNull() : NSNumber(value: clientHandshakeProofEmitSessionID),
            "client_handshake_proof_emit_counter": clientHandshakeProofEmitCounter == 0 ? NSNull() : NSNumber(value: clientHandshakeProofEmitCounter),
            "client_handshake_proof_emit_payload_bytes": NSNumber(value: clientHandshakeProofEmitPayloadBytes),
            "client_handshake_proof_emit_payload_sha256_prefix": clientHandshakeProofEmitPayloadSHA256Prefix,
            "rekey_in_progress": pendingSessionID != 0,
            "last_rekey_trigger": lastRekeyTrigger,
            "auth_fail_code": NSNumber(value: lastAuthFailCode),
            "auth_fail_context": lastAuthFailContext,
            "sticky_auth_fail_code": NSNumber(value: stickyAuthFailCode),
            "sticky_auth_fail_reason": stickyAuthFailReason,
            "sticky_auth_fail_context": stickyAuthFailContext,
            "last_inbound_sl_type": lastInboundSLType == 0 ? NSNull() : NSNumber(value: lastInboundSLType),
            "last_inbound_session_id": lastInboundSessionID == 0 ? NSNull() : NSNumber(value: lastInboundSessionID),
            "last_inbound_counter": lastInboundCounter == 0 ? NSNull() : NSNumber(value: lastInboundCounter),
            "last_outbound_sl_type": lastOutboundSLType == 0 ? NSNull() : NSNumber(value: lastOutboundSLType),
            "last_outbound_session_id": lastOutboundSessionID == 0 ? NSNull() : NSNumber(value: lastOutboundSessionID),
            "last_outbound_counter": lastOutboundCounter == 0 ? NSNull() : NSNumber(value: lastOutboundCounter),
            "tx_counter": NSNumber(value: txCounter),
            "rekeys_completed_total": NSNumber(value: rekeysCompletedTotal),
        ]
        clientPlaintextTelemetryImplRevision = Self.clientTelemetryImplRevision
        guard JSONSerialization.isValidJSONObject(payload) else {
            clientPlaintextTelemetryBuildSucceeded = false
            clientPlaintextTelemetryPayloadBytes = 0
            clientPlaintextTelemetryPayloadSHA256Prefix = ""
            clientPlaintextTelemetryBuildError = "invalid_json_object"
            return Data()
        }
        guard let encoded = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]) else {
            clientPlaintextTelemetryBuildSucceeded = false
            clientPlaintextTelemetryPayloadBytes = 0
            clientPlaintextTelemetryPayloadSHA256Prefix = ""
            clientPlaintextTelemetryBuildError = "json_serialization_failed"
            return Data()
        }
        clientPlaintextTelemetryBuildSucceeded = true
        clientPlaintextTelemetryPayloadBytes = encoded.count
        clientPlaintextTelemetryPayloadSHA256Prefix = sha256Prefix(encoded)
        clientPlaintextTelemetryBuildError = ""
        return encoded
    }

    private func sha256Prefix(_ data: Data, count: Int = 16) -> String {
        let digest = SHA256.hash(data: data)
        return digest.compactMap { String(format: "%02x", $0) }.joined().prefix(count).description
    }

    private func captureClientHandshakeTelemetry(
        _ payload: Data,
        observedSessionID: UInt64,
        observedCounter: UInt64
    ) -> Bool {
        guard !payload.isEmpty else {
            return false
        }
        guard let object = try? JSONSerialization.jsonObject(with: payload, options: []),
              let telemetry = object as? [String: Any],
              String(describing: telemetry["kind"] ?? "") == Self.clientTelemetryKind else {
            return false
        }
        clientTelemetrySource = String(describing: telemetry["impl"] ?? "")
        clientTelemetryReceivedUnixTS = timeProvider()
        clientTelemetryCurrentAttemptSessionID = UInt64((telemetry["current_attempt_session_id"] as? NSNumber)?.uint64Value ?? 0)
        clientTelemetryLocalAuthenticated = telemetry["local_authenticated"] as? Bool ?? false
        clientTelemetryPeerConfirmedAuthenticated = telemetry["peer_confirmed_authenticated"] as? Bool ?? false
        clientTelemetryServerHelloReceived = telemetry["server_hello_received"] as? Bool ?? false
        clientTelemetryServerHelloValidated = telemetry["server_hello_validated"] as? Bool ?? false
        clientTelemetryHandshakeProofSessionID = UInt64((telemetry["client_handshake_proof_session_id"] as? NSNumber)?.uint64Value ?? observedSessionID)
        clientTelemetryHandshakeProofCounter = UInt64((telemetry["client_handshake_proof_counter"] as? NSNumber)?.uint64Value ?? observedCounter)
        clientTelemetryLastInboundSLType = (telemetry["last_inbound_sl_type"] as? NSNumber)?.intValue ?? 0
        clientTelemetryLastInboundSessionID = UInt64((telemetry["last_inbound_session_id"] as? NSNumber)?.uint64Value ?? 0)
        clientTelemetryLastInboundCounter = UInt64((telemetry["last_inbound_counter"] as? NSNumber)?.uint64Value ?? 0)
        clientTelemetryLastOutboundSLType = (telemetry["last_outbound_sl_type"] as? NSNumber)?.intValue ?? 0
        clientTelemetryLastOutboundSessionID = UInt64((telemetry["last_outbound_session_id"] as? NSNumber)?.uint64Value ?? 0)
        clientTelemetryLastOutboundCounter = UInt64((telemetry["last_outbound_counter"] as? NSNumber)?.uint64Value ?? 0)
        return true
    }

    private func captureClientPlaintextTelemetry(
        _ payload: Data,
        observedSessionID: UInt64
    ) -> Bool {
        guard !payload.isEmpty,
              let object = try? JSONSerialization.jsonObject(with: payload, options: []),
              let telemetry = object as? [String: Any],
              String(describing: telemetry["kind"] ?? "") == Self.clientPlaintextTelemetryKind
        else {
            return false
        }
        clientTelemetrySource = String(describing: telemetry["impl"] ?? "")
        clientTelemetryReceivedUnixTS = timeProvider()
        clientTelemetryCurrentAttemptSessionID = UInt64((telemetry["current_attempt_session_id"] as? NSNumber)?.uint64Value ?? observedSessionID)
        clientTelemetryLocalAuthenticated = telemetry["local_authenticated"] as? Bool ?? false
        clientTelemetryPeerConfirmedAuthenticated = telemetry["peer_confirmed_authenticated"] as? Bool ?? false
        clientTelemetryServerHelloReceived = telemetry["server_hello_received"] as? Bool ?? false
        clientTelemetryServerHelloValidated = telemetry["server_hello_validated"] as? Bool ?? false
        clientTelemetryHandshakeProofSessionID = UInt64((telemetry["current_attempt_session_id"] as? NSNumber)?.uint64Value ?? observedSessionID)
        clientTelemetryHandshakeProofCounter = 0
        clientTelemetryLastInboundSLType = (telemetry["last_inbound_sl_type"] as? NSNumber)?.intValue ?? 0
        clientTelemetryLastInboundSessionID = UInt64((telemetry["last_inbound_session_id"] as? NSNumber)?.uint64Value ?? 0)
        clientTelemetryLastInboundCounter = UInt64((telemetry["last_inbound_counter"] as? NSNumber)?.uint64Value ?? 0)
        clientTelemetryLastOutboundSLType = (telemetry["last_outbound_sl_type"] as? NSNumber)?.intValue ?? 0
        clientTelemetryLastOutboundSessionID = UInt64((telemetry["last_outbound_session_id"] as? NSNumber)?.uint64Value ?? 0)
        clientTelemetryLastOutboundCounter = UInt64((telemetry["last_outbound_counter"] as? NSNumber)?.uint64Value ?? 0)
        return true
    }

    private func clearPendingRekey() {
        pendingSessionID = 0
        pendingClientNonce = Data()
        pendingServerNonce = Data()
        pendingC2SKey = nil
        pendingS2CKey = nil
        clientRekeyHoldAfterCommit = false
    }

    private func promotePendingRekey() -> Bool {
        guard pendingSessionID > 0 else {
            return false
        }
        sessionID = pendingSessionID
        clientNonce = pendingClientNonce
        serverNonce = pendingServerNonce
        c2sKey = pendingC2SKey
        s2cKey = pendingS2CKey
        authenticated = true
        peerConfirmedAuthenticated = true
        clientHandshakeProofSent = false
        txCounter = Self.firstDataCounter
        rxCounter = 0
        lastAuthFailCode = 0
        handshakeStartedAt = nil
        clearPendingRekey()
        rekeysCompletedTotal += 1
        return true
    }

    private func startClientRekey(trigger: String) throws -> Data {
        guard clientMode, authenticated, pendingSessionID == 0 else {
            throw ObstacleBridgeSecureLinkPskRuntimeError.invalidState
        }
        pendingSessionID = newSessionID(avoiding: [sessionID])
        pendingClientNonce = Data(randomBytes(32).prefix(32))
        pendingServerNonce = Data()
        pendingC2SKey = nil
        pendingS2CKey = nil
        lastRekeyTrigger = trigger
        let payload = pendingClientNonce + Data([UInt8(Self.capabilityPSKV1), 0])
        let frame = ObstacleBridgeSecureLinkPskCodec.buildFrame(
            slType: Self.typeRekeyHello,
            sessionID: pendingSessionID,
            counter: 0,
            payload: payload
        )
        noteOutboundFrame(slType: Self.typeRekeyHello, sessionID: pendingSessionID, counter: 0)
        return frame
    }

    private func handleRekeyHello(sessionID: UInt64, body: Data) -> InboundSnapshot {
        guard !clientMode, sessionID > 0, authenticated, self.sessionID > 0, c2sKey != nil, s2cKey != nil else {
            return fail(sessionID: sessionID, code: Self.authFailDecode)
        }
        if pendingSessionID > 0, pendingSessionID != sessionID {
            return fail(sessionID: sessionID, code: Self.authFailLifecycle, context: "handle_rekey_hello.pending_session_mismatch")
        }
        guard !psk.isEmpty, body.count >= 34 else {
            return fail(sessionID: sessionID, code: Self.authFailDecode)
        }
        let clientNonce = body.prefix(32)
        let capability = Int(body[32])
        guard capability == Self.capabilityPSKV1 else {
            return fail(sessionID: sessionID, code: Self.authFailUnsupported)
        }
        let serverNonce = Data(randomBytes(32).prefix(32))
        let keys = ObstacleBridgeSecureLinkPskCodec.deriveKeys(
            psk: psk,
            sessionID: sessionID,
            clientNonce: Data(clientNonce),
            serverNonce: serverNonce
        )
        pendingSessionID = sessionID
        pendingClientNonce = Data(clientNonce)
        pendingServerNonce = serverNonce
        pendingC2SKey = keys.0
        pendingS2CKey = keys.1
        lastRekeyTrigger = "remote"
        let proof = serverProof(sessionID: sessionID, clientNonce: pendingClientNonce, serverNonce: serverNonce)
        let payload = serverNonce + Data([UInt8(Self.capabilityPSKV1)]) + proof
        let response = ObstacleBridgeSecureLinkPskCodec.buildFrame(
            slType: Self.typeRekeyReply,
            sessionID: sessionID,
            counter: 0,
            payload: payload
        )
        noteOutboundFrame(slType: Self.typeRekeyReply, sessionID: sessionID, counter: 0)
        return InboundSnapshot(
            emittedFrames: [response],
            deliveredPayloads: [],
            authenticated: authenticated,
            sessionID: self.sessionID,
            rxCounter: rxCounter,
            authFailCode: nil
        )
    }

    private func handleRekeyReply(sessionID: UInt64, body: Data) -> InboundSnapshot {
        guard clientMode, sessionID > 0, pendingSessionID == sessionID else {
            return fail(sessionID: sessionID, code: Self.authFailDecode)
        }
        guard !psk.isEmpty, body.count >= 65 else {
            return fail(sessionID: sessionID, code: Self.authFailDecode)
        }
        let serverNonce = body.prefix(32)
        let capability = Int(body[32])
        let proof = body.subdata(in: 33..<65)
        guard capability == Self.capabilityPSKV1 else {
            return fail(sessionID: sessionID, code: Self.authFailUnsupported)
        }
        let expected = serverProof(sessionID: sessionID, clientNonce: pendingClientNonce, serverNonce: Data(serverNonce))
        guard proof == expected else {
            return fail(sessionID: sessionID, code: Self.authFailBadPSK)
        }
        let keys = ObstacleBridgeSecureLinkPskCodec.deriveKeys(
            psk: psk,
            sessionID: sessionID,
            clientNonce: pendingClientNonce,
            serverNonce: Data(serverNonce)
        )
        pendingServerNonce = Data(serverNonce)
        pendingC2SKey = keys.0
        pendingS2CKey = keys.1
        let commit = clientRekeyCommitProof(sessionID: sessionID, clientNonce: pendingClientNonce, serverNonce: pendingServerNonce)
        let frame = ObstacleBridgeSecureLinkPskCodec.buildFrame(
            slType: Self.typeRekeyCommit,
            sessionID: sessionID,
            counter: 0,
            payload: commit
        )
        noteOutboundFrame(slType: Self.typeRekeyCommit, sessionID: sessionID, counter: 0)
        clientRekeyHoldAfterCommit = true
        return InboundSnapshot(
            emittedFrames: [frame],
            deliveredPayloads: [],
            authenticated: authenticated,
            sessionID: self.sessionID,
            rxCounter: rxCounter,
            authFailCode: nil
        )
    }

    private func handleRekeyCommit(sessionID: UInt64, body: Data) -> InboundSnapshot {
        guard !clientMode, sessionID > 0, pendingSessionID == sessionID else {
            return fail(sessionID: sessionID, code: Self.authFailDecode)
        }
        let expected = clientRekeyCommitProof(sessionID: sessionID, clientNonce: pendingClientNonce, serverNonce: pendingServerNonce)
        guard body == expected else {
            return fail(sessionID: sessionID, code: Self.authFailBadPSK)
        }
        guard promotePendingRekey() else {
            return fail(sessionID: sessionID, code: Self.authFailLifecycle, context: "handle_rekey_commit.pending_session_mismatch")
        }
        let frame = ObstacleBridgeSecureLinkPskCodec.buildFrame(
            slType: Self.typeRekeyDone,
            sessionID: sessionID,
            counter: 0,
            payload: Data()
        )
        noteOutboundFrame(slType: Self.typeRekeyDone, sessionID: sessionID, counter: 0)
        return InboundSnapshot(
            emittedFrames: [frame],
            deliveredPayloads: [],
            authenticated: authenticated,
            sessionID: self.sessionID,
            rxCounter: rxCounter,
            authFailCode: nil
        )
    }

    private func handleRekeyDone(sessionID: UInt64) -> InboundSnapshot {
        guard clientMode, sessionID > 0, pendingSessionID == sessionID else {
            return fail(sessionID: sessionID, code: Self.authFailDecode)
        }
        guard promotePendingRekey() else {
            return fail(sessionID: sessionID, code: Self.authFailLifecycle, context: "handle_rekey_done.promote_pending_failed")
        }
        return InboundSnapshot(
            emittedFrames: [],
            deliveredPayloads: [],
            authenticated: authenticated,
            sessionID: self.sessionID,
            rxCounter: rxCounter,
            authFailCode: nil
        )
    }

    private func fail(sessionID: UInt64, code: Int, context: String = "") -> InboundSnapshot {
        lastFailureSessionID = sessionID > 0 ? sessionID : self.sessionID
        lastFailureUnixTS = Date().timeIntervalSince1970
        lastFailureClientProofSent = clientHandshakeProofSent
        lastFailureClientProofSessionID = clientHandshakeProofSessionID
        lastFailureClientProofCounter = clientHandshakeProofCounter
        lastFailureServerAckSeen = serverAckSeen
        lastAuthFailCode = code
        lastAuthFailContext = context
        stickyAuthFailCode = code
        stickyAuthFailReason = authFailReason(code)
        stickyAuthFailContext = context
        authenticated = false
        peerConfirmedAuthenticated = false
        handshakeStartedAt = nil
        let frame = ObstacleBridgeSecureLinkPskCodec.buildFrame(
            slType: Self.typeAuthFail,
            sessionID: sessionID,
            counter: 0,
            payload: Data([UInt8(code & 0xFF)])
        )
        noteOutboundFrame(slType: Self.typeAuthFail, sessionID: sessionID, counter: 0)
        return InboundSnapshot(
            emittedFrames: [frame],
            deliveredPayloads: [],
            authenticated: authenticated,
            sessionID: self.sessionID,
            rxCounter: rxCounter,
            authFailCode: code
        )
    }

    private func resetAuthState(keepSessionID: Bool) {
        if !keepSessionID {
            sessionID = 0
        }
        authenticated = false
        peerConfirmedAuthenticated = false
        handshakeStartedAt = nil
        clientNonce = Data()
        serverNonce = Data()
        c2sKey = nil
        s2cKey = nil
        txCounter = Self.firstDataCounter
        rxCounter = 0
        clientHandshakeProofSent = false
        clientHandshakeProofSessionID = 0
        clientHandshakeProofCounter = 0
        serverAckSeen = false
        clearPendingRekey()
        lastAuthFailCode = 0
        lastAuthFailContext = ""
        lastInboundSLType = 0
        lastInboundSessionID = 0
        lastInboundCounter = 0
        lastOutboundSLType = 0
        lastOutboundSessionID = 0
        lastOutboundCounter = 0
        serverHelloReceived = false
        serverHelloValidated = false
        serverHelloValidatedSessionID = 0
        serverHelloValidatedTxCounter = 0
        serverHelloValidatedC2SKeySHA256Prefix = ""
        serverHelloValidatedS2CKeySHA256Prefix = ""
        clientHandshakeProofEmitSessionID = 0
        clientHandshakeProofEmitCounter = 0
        clientHandshakeProofEmitPayloadBytes = 0
        clientHandshakeProofEmitPayloadSHA256Prefix = ""
        clientHandshakeProofEmitC2SKeySHA256Prefix = ""
        clientHandshakeProofSessionMatchesValidatedSession = false
        clientHandshakeProofKeyMatchesValidatedKey = false
        clientTelemetrySource = ""
        clientTelemetryReceivedUnixTS = nil
        clientTelemetryCurrentAttemptSessionID = 0
        clientTelemetryLocalAuthenticated = false
        clientTelemetryPeerConfirmedAuthenticated = false
        clientTelemetryServerHelloReceived = false
        clientTelemetryServerHelloValidated = false
        clientTelemetryHandshakeProofSessionID = 0
        clientTelemetryHandshakeProofCounter = 0
        clientTelemetryLastInboundSLType = 0
        clientTelemetryLastInboundSessionID = 0
        clientTelemetryLastInboundCounter = 0
        clientTelemetryLastOutboundSLType = 0
        clientTelemetryLastOutboundSessionID = 0
        clientTelemetryLastOutboundCounter = 0
        clientHandshakeTelemetryBuildSucceeded = false
        clientHandshakeTelemetryPayloadBytes = 0
        clientHandshakeTelemetryPayloadSHA256Prefix = ""
        clientHandshakeTelemetryBuildError = ""
        clientPlaintextTelemetryImplRevision = Self.clientTelemetryImplRevision
        clientPlaintextTelemetryBuildSucceeded = false
        clientPlaintextTelemetryPayloadBytes = 0
        clientPlaintextTelemetryPayloadSHA256Prefix = ""
        clientPlaintextTelemetryBuildError = ""
        clientPlaintextTelemetryFrameSessionID = 0
        lastPlaintextTelemetryUnixTS = nil
        stickyAuthFailCode = 0
        stickyAuthFailReason = ""
        stickyAuthFailContext = ""
    }

    private func shouldIgnoreStaleInboundFrame(_ frame: ObstacleBridgeSecureLinkPskCodec.ParsedFrame) -> Bool {
        guard clientMode,
              !authenticated,
              sessionID > 0,
              frame.sessionID != 0,
              frame.sessionID != sessionID
        else {
            return false
        }

        switch frame.slType {
        case Self.typeServerHello,
             Self.typeAuthFail,
             Self.typeData,
             Self.typeRekeyHello,
             Self.typeRekeyReply,
             Self.typeRekeyCommit,
             Self.typeRekeyDone:
            return true
        default:
            return false
        }
    }

    private func noteOutboundFrame(slType: Int, sessionID: UInt64, counter: UInt64) {
        lastOutboundSLType = slType
        lastOutboundSessionID = sessionID
        lastOutboundCounter = counter
    }

    func expireHandshakeIfNeeded() {
        guard sessionID > 0, !peerConfirmedAuthenticated, lastAuthFailCode == 0 else {
            return
        }
        guard let handshakeStartedAt else {
            return
        }
        if (timeProvider() - handshakeStartedAt) >= Self.handshakeTimeoutSeconds {
            _ = fail(sessionID: sessionID, code: Self.authFailLifecycle, context: "expire_handshake.timeout")
        }
    }

    private func serverProof(sessionID: UInt64, clientNonce: Data, serverNonce: Data) -> Data {
        ObstacleBridgeSecureLinkPskCodec.serverProof(
            psk: psk,
            sessionID: sessionID,
            clientNonce: clientNonce,
            serverNonce: serverNonce
        )
    }

    private func clientRekeyCommitProof(sessionID: UInt64, clientNonce: Data, serverNonce: Data) -> Data {
        let message = Self.clientRekeyCommitPrefix + sessionID.bigEndianData + clientNonce + serverNonce
        let authenticationCode = HMAC<SHA256>.authenticationCode(
            for: message,
            using: SymmetricKey(data: psk)
        )
        return Data(authenticationCode)
    }

    private func newSessionID(avoiding blockedIDs: [UInt64]) -> UInt64 {
        let blocked = Set(blockedIDs.filter { $0 > 0 })
        var candidate: UInt64 = 0
        repeat {
            candidate = sessionIDProvider()
            if candidate == 0 {
                candidate = 1
            }
        } while blocked.contains(candidate)
        return candidate
    }

    private func authFailReason(_ code: Int) -> String {
        switch code {
        case Self.authFailBadPSK:
            return "bad_psk"
        case Self.authFailUnsupported:
            return "unsupported"
        case Self.authFailReplay:
            return "replay"
        case Self.authFailDecode:
            return "decode"
        case Self.authFailLifecycle:
            return "lifecycle"
        default:
            return code == 0 ? "" : "unknown"
        }
    }

    private func seal(payload: Data, key: Data, counter: UInt64, aad: Data) throws -> Data {
        let sealed = try ChaChaPoly.seal(
            payload,
            using: SymmetricKey(data: key),
            nonce: try ChaChaPoly.Nonce(data: ObstacleBridgeSecureLinkPskCodec.nonce(counter: counter)),
            authenticating: aad
        )
        return sealed.ciphertext + sealed.tag
    }

    private func open(ciphertext: Data, key: Data, counter: UInt64, aad: Data) throws -> Data {
        let sealed = try ChaChaPoly.SealedBox(
            nonce: try ChaChaPoly.Nonce(data: ObstacleBridgeSecureLinkPskCodec.nonce(counter: counter)),
            ciphertext: ciphertext.dropLast(16),
            tag: ciphertext.suffix(16)
        )
        return try ChaChaPoly.open(
            sealed,
            using: SymmetricKey(data: key),
            authenticating: aad
        )
    }
}

private extension UInt64 {
    var bigEndianData: Data {
        var data = Data()
        data.appendUInt64(self)
        return data
    }
}
