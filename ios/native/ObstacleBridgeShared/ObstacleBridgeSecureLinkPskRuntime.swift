import CryptoKit
import Foundation

enum ObstacleBridgeSecureLinkPskRuntimeError: Error {
    case invalidState
    case invalidFrame
    case authFailed(Int)
}

final class ObstacleBridgeSecureLinkPskRuntime {
    static let typeClientHello = 1
    static let typeServerHello = 2
    static let typeAuthFail = 3
    static let typeData = 4
    static let typeRekeyHello = 5
    static let typeRekeyReply = 6
    static let typeRekeyCommit = 7
    static let typeRekeyDone = 8

    static let capabilityPSKV1 = 1

    static let authFailBadPSK = 1
    static let authFailUnsupported = 2
    static let authFailReplay = 3
    static let authFailDecode = 4
    static let authFailLifecycle = 5

    private static let firstDataCounter: UInt64 = 1
    private static let maxDataCounter: UInt64 = UInt64.max
    private static let handshakeTimeoutSeconds: TimeInterval = 60.0

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
        var sessionID: UInt64
        var txCounter: UInt64
        var rxCounter: UInt64
        var authFailCode: Int
        var lastEvent: String
        var lastEventUnixTs: TimeInterval?
        var authenticatedSessionsTotal: Int
        var rekeySupported: Bool
        var rekeyInProgress: Bool
        var rekeysCompletedTotal: Int
        var lastRekeyTrigger: String
        var disconnectReason: String
        var disconnectDetail: String
        var trustValidationState: String
        var appDataSendingBlocked: Bool
        var framesFromClientPassedTotal: Int
        var framesFromClientDroppedTotal: Int
        var framesToClientPassedTotal: Int
        var handshakeAttemptsTotal: Int
        var consecutiveFailures: Int
        var retryBackoffSec: TimeInterval
        var nextRetryUnixTs: TimeInterval?
    }

    private let clientMode: Bool
    private let psk: Data
    private let randomBytes: (Int) -> Data
    private let sessionIDProvider: () -> UInt64
    private let timeProvider: () -> TimeInterval
    private let rekeyAfterFrames: Int
    private let rekeyAfterSeconds: TimeInterval

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
    private var lastAuthFailCode = 0
    private var handshakeStartedAt: TimeInterval?
    private var lastEvent = "bootstrap"
    private var lastEventUnixTs: TimeInterval?
    private var authenticatedSessionsTotal = 0
    private var pendingSessionID: UInt64 = 0
    private var pendingClientNonce = Data()
    private var pendingServerNonce = Data()
    private var pendingC2SKey: Data?
    private var pendingS2CKey: Data?
    private var pendingRekeyStartedAt: TimeInterval?
    private var rekeysCompletedTotal = 0
    private var lastRekeyTrigger = ""
    private var disconnectReason = ""
    private var disconnectDetail = ""
    private var trustValidationState = "n/a"
    private var clientRekeyHoldAfterCommit = false
    private var framesFromClientPassedTotal = 0
    private var framesFromClientDroppedTotal = 0
    private var framesToClientPassedTotal = 0
    private let unixTimeProvider: () -> TimeInterval
    private var rekeyDueMono: TimeInterval?

    init(
        clientMode: Bool,
        psk: String,
        rekeyAfterFrames: Int = 0,
        rekeyAfterSeconds: TimeInterval = 0.0,
        randomBytes: ((Int) -> Data)? = nil,
        sessionIDProvider: (() -> UInt64)? = nil,
        timeProvider: (() -> TimeInterval)? = nil,
        unixTimeProvider: (() -> TimeInterval)? = nil
    ) {
        self.clientMode = clientMode
        self.psk = Data(psk.utf8)
        self.rekeyAfterFrames = max(0, rekeyAfterFrames)
        self.rekeyAfterSeconds = max(0.0, rekeyAfterSeconds)
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
        self.unixTimeProvider = unixTimeProvider ?? { Date().timeIntervalSince1970 }
    }

    var isAuthenticated: Bool {
        authenticated && peerConfirmedAuthenticated
    }

    func statusSnapshot() -> StatusSnapshot {
        expireHandshakeIfNeeded()
        return StatusSnapshot(
            clientMode: clientMode,
            authenticated: isAuthenticated,
            peerConfirmedAuthenticated: peerConfirmedAuthenticated,
            sessionID: sessionID,
            txCounter: txCounter,
            rxCounter: rxCounter,
            authFailCode: lastAuthFailCode,
            lastEvent: lastEvent,
            lastEventUnixTs: lastEventUnixTs,
            authenticatedSessionsTotal: authenticatedSessionsTotal,
            rekeySupported: true,
            rekeyInProgress: pendingSessionID != 0,
            rekeysCompletedTotal: rekeysCompletedTotal,
            lastRekeyTrigger: lastRekeyTrigger,
            disconnectReason: disconnectReason,
            disconnectDetail: disconnectDetail,
            trustValidationState: trustValidationState,
            appDataSendingBlocked: clientRekeyHoldAfterCommit,
            framesFromClientPassedTotal: framesFromClientPassedTotal,
            framesFromClientDroppedTotal: framesFromClientDroppedTotal,
            framesToClientPassedTotal: framesToClientPassedTotal,
            handshakeAttemptsTotal: 0,
            consecutiveFailures: 0,
            retryBackoffSec: 0.0,
            nextRetryUnixTs: nil,
        )
    }

    func handleTransportDisconnected() {
        resetAuthState(keepSessionID: false)
        lastAuthFailCode = 0
        disconnectReason = "transport_disconnected"
        disconnectDetail = ""
        trustValidationState = "n/a"
        recordEvent("transport_disconnected")
    }

    func beginClientHandshake() throws -> OutboundSnapshot {
        guard clientMode, !psk.isEmpty else {
            throw ObstacleBridgeSecureLinkPskRuntimeError.invalidState
        }
        resetAuthState(keepSessionID: false)
        sessionID = sessionIDProvider()
        handshakeStartedAt = timeProvider()
        recordEvent("handshake_started")
        clientNonce = Data(randomBytes(32).prefix(32))
        let payload = clientNonce + Data([UInt8(Self.capabilityPSKV1), 0])
        let frame = ObstacleBridgeSecureLinkPskCodec.buildFrame(
            slType: Self.typeClientHello,
            sessionID: sessionID,
            counter: 0,
            payload: payload
        )
        return OutboundSnapshot(
            sent: true,
            emittedFrames: [frame],
            authenticated: authenticated,
            sessionID: sessionID,
            txCounter: txCounter
        )
    }

    func sendApp(_ payload: Data) throws -> OutboundSnapshot {
        expireHandshakeIfNeeded()
        let timeTriggeredFrames = try maybeTriggerTimeBasedRekey()
        guard !clientRekeyHoldAfterCommit else {
            throw ObstacleBridgeSecureLinkPskRuntimeError.invalidState
        }
        guard isAuthenticated, sessionID > 0 else {
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
        txCounter &+= 1
        if clientMode {
            framesFromClientPassedTotal &+= 1
        } else {
            framesToClientPassedTotal &+= 1
        }
        var emittedFrames = timeTriggeredFrames
        emittedFrames.append(frame)
        emittedFrames.append(contentsOf: try maybeTriggerFrameBasedRekey())
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
        _ = try? maybeTriggerTimeBasedRekey()
        guard let frame = ObstacleBridgeSecureLinkPskCodec.parseFrame(payload) else {
            return fail(sessionID: 0, code: Self.authFailDecode)
        }
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
            clientRekeyHoldAfterCommit = false
            clearPendingRekey()
            disconnectReason = "auth_failed"
            disconnectDetail = "code=\(code)"
            trustValidationState = "failed"
            recordEvent(authFailEventName(code))
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
        default:
            return fail(sessionID: frame.sessionID, code: Self.authFailUnsupported)
        }
    }

    func requestClientRekey() throws -> OutboundSnapshot {
        expireHandshakeIfNeeded()
        guard clientMode, authenticated, peerConfirmedAuthenticated, sessionID > 0 else {
            throw ObstacleBridgeSecureLinkPskRuntimeError.invalidState
        }
        guard pendingSessionID == 0 else {
            throw ObstacleBridgeSecureLinkPskRuntimeError.invalidState
        }
        let frame = try startClientRekey(trigger: "operator")
        return OutboundSnapshot(
            sent: true,
            emittedFrames: [frame],
            authenticated: authenticated,
            sessionID: sessionID,
            txCounter: txCounter
        )
    }

    func pollDueFrames() throws -> [Data] {
        expireHandshakeIfNeeded()
        return try maybeTriggerTimeBasedRekey()
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
        resetAuthState(keepSessionID: false)
        self.sessionID = sessionID
        handshakeStartedAt = timeProvider()
        disconnectReason = ""
        disconnectDetail = ""
        trustValidationState = "n/a"
        recordEvent("handshake_started")
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
        recordEvent("server_hello_sent")
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
        self.serverNonce = Data(serverNonce)
        let keys = ObstacleBridgeSecureLinkPskCodec.deriveKeys(
            psk: psk,
            sessionID: sessionID,
            clientNonce: clientNonce,
            serverNonce: self.serverNonce
        )
        c2sKey = keys.0
        s2cKey = keys.1
        authenticated = true
        peerConfirmedAuthenticated = false
        lastAuthFailCode = 0
        disconnectReason = ""
        disconnectDetail = ""
        trustValidationState = "n/a"
        recordEvent("server_hello_validated")
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
            return fail(sessionID: sessionID, code: Self.authFailLifecycle)
        }
    }

    private func handleData(sessionID: UInt64, counter: UInt64, body: Data, aad: Data) -> InboundSnapshot {
        guard self.sessionID > 0, self.sessionID == sessionID else {
            return fail(sessionID: sessionID, code: Self.authFailDecode)
        }
        guard counter >= Self.firstDataCounter, counter <= Self.maxDataCounter else {
            return fail(sessionID: sessionID, code: Self.authFailLifecycle)
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
            disconnectReason = ""
            disconnectDetail = ""
            trustValidationState = "validated"
            recordEvent("handshake_local_authenticated")
            if !clientMode, let outboundKey = s2cKey {
                do {
                    let ackAAD = ObstacleBridgeSecureLinkPskCodec.headerBytes(
                        slType: Self.typeData,
                        sessionID: sessionID,
                        counter: txCounter
                    )
                    let ackCiphertext = try seal(payload: Data(), key: outboundKey, counter: txCounter, aad: ackAAD)
                    emittedFrames.append(ackAAD + ackCiphertext)
                    txCounter &+= 1
                    framesToClientPassedTotal &+= 1
                } catch {
                    return fail(sessionID: sessionID, code: Self.authFailLifecycle)
                }
            }
        }
        if !peerConfirmedAuthenticated {
            peerConfirmedAuthenticated = true
            handshakeStartedAt = nil
            authenticatedSessionsTotal &+= 1
            disconnectReason = ""
            disconnectDetail = ""
            trustValidationState = "validated"
            recordEvent("authenticated")
            scheduleTimeBasedRekeyIfNeeded()
        }
        if clientMode {
            framesToClientPassedTotal &+= 1
        } else {
            framesFromClientPassedTotal &+= 1
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

    private func handleRekeyHello(sessionID: UInt64, body: Data) -> InboundSnapshot {
        guard !clientMode, authenticated, peerConfirmedAuthenticated, self.sessionID > 0 else {
            return fail(sessionID: sessionID, code: Self.authFailDecode)
        }
        guard pendingSessionID == 0 || pendingSessionID == sessionID else {
            return fail(sessionID: sessionID, code: Self.authFailLifecycle)
        }
        guard body.count >= 34 else {
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
        if pendingSessionID == 0 {
            pendingRekeyStartedAt = timeProvider()
        }
        pendingSessionID = sessionID
        pendingClientNonce = Data(clientNonce)
        pendingServerNonce = serverNonce
        pendingC2SKey = keys.0
        pendingS2CKey = keys.1
        lastRekeyTrigger = "remote"
        let proof = serverProof(sessionID: sessionID, clientNonce: Data(clientNonce), serverNonce: serverNonce)
        let payload = serverNonce + Data([UInt8(Self.capabilityPSKV1)]) + proof
        let response = ObstacleBridgeSecureLinkPskCodec.buildFrame(
            slType: Self.typeRekeyReply,
            sessionID: sessionID,
            counter: 0,
            payload: payload
        )
        recordEvent("rekey_reply_sent")
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
        guard clientMode, pendingSessionID == sessionID, body.count >= 65 else {
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
        let commit = clientRekeyCommitProof(
            sessionID: sessionID,
            clientNonce: pendingClientNonce,
            serverNonce: pendingServerNonce
        )
        clientRekeyHoldAfterCommit = true
        let frame = ObstacleBridgeSecureLinkPskCodec.buildFrame(
            slType: Self.typeRekeyCommit,
            sessionID: sessionID,
            counter: 0,
            payload: commit
        )
        recordEvent("rekey_commit_sent")
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
        guard !clientMode, pendingSessionID == sessionID else {
            return fail(sessionID: sessionID, code: Self.authFailDecode)
        }
        let expected = clientRekeyCommitProof(
            sessionID: sessionID,
            clientNonce: pendingClientNonce,
            serverNonce: pendingServerNonce
        )
        guard body == expected else {
            return fail(sessionID: sessionID, code: Self.authFailBadPSK)
        }
        promotePendingRekey()
        let frame = ObstacleBridgeSecureLinkPskCodec.buildFrame(
            slType: Self.typeRekeyDone,
            sessionID: sessionID,
            counter: 0,
            payload: Data()
        )
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
        guard clientMode, pendingSessionID == sessionID else {
            return fail(sessionID: sessionID, code: Self.authFailDecode)
        }
        promotePendingRekey()
        clientRekeyHoldAfterCommit = false
        return InboundSnapshot(
            emittedFrames: [],
            deliveredPayloads: [],
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
        let ciphertext = try seal(payload: Data(), key: outboundKey, counter: counter, aad: aad)
        txCounter &+= 1
        clientHandshakeProofSent = true
        framesFromClientPassedTotal &+= 1
        return aad + ciphertext
    }

    private func fail(sessionID: UInt64, code: Int) -> InboundSnapshot {
        lastAuthFailCode = code
        authenticated = false
        peerConfirmedAuthenticated = false
        handshakeStartedAt = nil
        clientRekeyHoldAfterCommit = false
        clearPendingRekey()
        clearRekeySchedule()
        disconnectReason = "auth_failed"
        disconnectDetail = "code=\(code)"
        trustValidationState = "failed"
        recordEvent(authFailEventName(code))
        if !clientMode {
            framesFromClientDroppedTotal &+= 1
        }
        let frame = ObstacleBridgeSecureLinkPskCodec.buildFrame(
            slType: Self.typeAuthFail,
            sessionID: sessionID,
            counter: 0,
            payload: Data([UInt8(code & 0xFF)])
        )
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
        clearPendingRekey()
        txCounter = Self.firstDataCounter
        rxCounter = 0
        clientHandshakeProofSent = false
        lastAuthFailCode = 0
        clientRekeyHoldAfterCommit = false
        clearRekeySchedule()
        lastEvent = keepSessionID ? lastEvent : "bootstrap"
        lastEventUnixTs = keepSessionID ? lastEventUnixTs : nil
        authenticatedSessionsTotal = keepSessionID ? authenticatedSessionsTotal : 0
        rekeysCompletedTotal = keepSessionID ? rekeysCompletedTotal : 0
        lastRekeyTrigger = keepSessionID ? lastRekeyTrigger : ""
        disconnectReason = keepSessionID ? disconnectReason : ""
        disconnectDetail = keepSessionID ? disconnectDetail : ""
        trustValidationState = keepSessionID ? trustValidationState : "n/a"
        framesFromClientPassedTotal = 0
        framesFromClientDroppedTotal = 0
        framesToClientPassedTotal = 0
    }

    func expireHandshakeIfNeeded() {
        guard lastAuthFailCode == 0 else {
            return
        }
        if pendingSessionID != 0,
           let pendingRekeyStartedAt,
           (timeProvider() - pendingRekeyStartedAt) >= Self.handshakeTimeoutSeconds {
            _ = fail(sessionID: pendingSessionID, code: Self.authFailLifecycle)
            return
        }
        guard sessionID > 0, !peerConfirmedAuthenticated else {
            return
        }
        guard let handshakeStartedAt else {
            return
        }
        if (timeProvider() - handshakeStartedAt) >= Self.handshakeTimeoutSeconds {
            _ = fail(sessionID: sessionID, code: Self.authFailLifecycle)
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

    private func recordEvent(_ event: String) {
        lastEvent = event
        lastEventUnixTs = unixTimeProvider()
    }

    private func clearPendingRekey() {
        pendingSessionID = 0
        pendingClientNonce = Data()
        pendingServerNonce = Data()
        pendingC2SKey = nil
        pendingS2CKey = nil
        pendingRekeyStartedAt = nil
    }

    private func promotePendingRekey() {
        guard pendingSessionID != 0 else {
            return
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
        authenticatedSessionsTotal &+= 1
        rekeysCompletedTotal &+= 1
        disconnectReason = ""
        disconnectDetail = ""
        trustValidationState = "validated"
        recordEvent("rekey_completed")
        clearPendingRekey()
        scheduleTimeBasedRekeyIfNeeded()
    }

    private func nextSessionID() -> UInt64 {
        var candidate = sessionIDProvider()
        while candidate == 0 || candidate == sessionID || candidate == pendingSessionID {
            candidate = sessionIDProvider()
        }
        return candidate
    }

    private func clientRekeyCommitProof(sessionID: UInt64, clientNonce: Data, serverNonce: Data) -> Data {
        ObstacleBridgeSecureLinkPskCodec.clientRekeyCommitProof(
            psk: psk,
            sessionID: sessionID,
            clientNonce: clientNonce,
            serverNonce: serverNonce
        )
    }

    private func authFailEventName(_ code: Int) -> String {
        switch code {
        case Self.authFailBadPSK:
            return "auth_failed_bad_psk"
        case Self.authFailUnsupported:
            return "auth_failed_unsupported"
        case Self.authFailReplay:
            return "auth_failed_replay"
        case Self.authFailDecode:
            return "auth_failed_decode"
        case Self.authFailLifecycle:
            return "auth_failed_lifecycle"
        default:
            return "auth_failed"
        }
    }

    private func startClientRekey(trigger: String) throws -> Data {
        guard clientMode, authenticated, peerConfirmedAuthenticated, sessionID > 0, pendingSessionID == 0 else {
            throw ObstacleBridgeSecureLinkPskRuntimeError.invalidState
        }
        let nextSessionID = nextSessionID()
        let nextClientNonce = Data(randomBytes(32).prefix(32))
        pendingSessionID = nextSessionID
        pendingRekeyStartedAt = timeProvider()
        pendingClientNonce = nextClientNonce
        pendingServerNonce = Data()
        pendingC2SKey = nil
        pendingS2CKey = nil
        lastRekeyTrigger = trigger
        clearRekeySchedule()
        recordEvent("rekey_started")
        let payload = nextClientNonce + Data([UInt8(Self.capabilityPSKV1), 0])
        return ObstacleBridgeSecureLinkPskCodec.buildFrame(
            slType: Self.typeRekeyHello,
            sessionID: nextSessionID,
            counter: 0,
            payload: payload
        )
    }

    private func maybeTriggerFrameBasedRekey() throws -> [Data] {
        guard clientMode, rekeyAfterFrames > 0, authenticated, peerConfirmedAuthenticated, pendingSessionID == 0 else {
            return []
        }
        let sentFrames = max(0, Int(txCounter) - 1 - (clientHandshakeProofSent ? 1 : 0))
        guard sentFrames >= rekeyAfterFrames else {
            return []
        }
        return [try startClientRekey(trigger: "frame_threshold")]
    }

    private func maybeTriggerTimeBasedRekey() throws -> [Data] {
        guard clientMode, rekeyAfterSeconds > 0.0, authenticated, peerConfirmedAuthenticated, pendingSessionID == 0 else {
            return []
        }
        guard let rekeyDueMono else {
            scheduleTimeBasedRekeyIfNeeded()
            return []
        }
        guard timeProvider() >= rekeyDueMono else {
            return []
        }
        return [try startClientRekey(trigger: "time_threshold")]
    }

    private func scheduleTimeBasedRekeyIfNeeded() {
        guard clientMode, rekeyAfterSeconds > 0.0, authenticated, peerConfirmedAuthenticated, pendingSessionID == 0 else {
            clearRekeySchedule()
            return
        }
        rekeyDueMono = timeProvider() + rekeyAfterSeconds
    }

    private func clearRekeySchedule() {
        rekeyDueMono = nil
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
