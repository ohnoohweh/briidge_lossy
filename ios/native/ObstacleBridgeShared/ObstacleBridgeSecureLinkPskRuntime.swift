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

    static let capabilityPSKV1 = 1

    static let authFailBadPSK = 1
    static let authFailUnsupported = 2
    static let authFailReplay = 3
    static let authFailDecode = 4
    static let authFailLifecycle = 5

    private static let firstDataCounter: UInt64 = 1
    private static let maxDataCounter: UInt64 = UInt64.max
    private static let serverProofPrefix = Data("obstaclebridge-securelink-server-proof-v1|".utf8)

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
    }

    private let clientMode: Bool
    private let psk: Data
    private let randomBytes: (Int) -> Data
    private let sessionIDProvider: () -> UInt64

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

    init(
        clientMode: Bool,
        psk: String,
        randomBytes: ((Int) -> Data)? = nil,
        sessionIDProvider: (() -> UInt64)? = nil
    ) {
        self.clientMode = clientMode
        self.psk = Data(psk.utf8)
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
    }

    var isAuthenticated: Bool {
        authenticated
    }

    func statusSnapshot() -> StatusSnapshot {
        StatusSnapshot(
            clientMode: clientMode,
            authenticated: authenticated,
            peerConfirmedAuthenticated: peerConfirmedAuthenticated,
            sessionID: sessionID,
            txCounter: txCounter,
            rxCounter: rxCounter,
            authFailCode: lastAuthFailCode
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
        txCounter &+= 1
        return OutboundSnapshot(
            sent: true,
            emittedFrames: [frame],
            authenticated: authenticated,
            sessionID: sessionID,
            txCounter: txCounter
        )
    }

    func handleInboundFrame(_ payload: Data) -> InboundSnapshot {
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
        resetAuthState(keepSessionID: false)
        self.sessionID = sessionID
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
                } catch {
                    return fail(sessionID: sessionID, code: Self.authFailLifecycle)
                }
            }
        }
        if !peerConfirmedAuthenticated {
            peerConfirmedAuthenticated = true
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
        let ciphertext = try seal(payload: Data(), key: outboundKey, counter: counter, aad: aad)
        txCounter &+= 1
        clientHandshakeProofSent = true
        return aad + ciphertext
    }

    private func fail(sessionID: UInt64, code: Int) -> InboundSnapshot {
        lastAuthFailCode = code
        authenticated = false
        peerConfirmedAuthenticated = false
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
        clientNonce = Data()
        serverNonce = Data()
        c2sKey = nil
        s2cKey = nil
        txCounter = Self.firstDataCounter
        rxCounter = 0
        clientHandshakeProofSent = false
        lastAuthFailCode = 0
    }

    private func serverProof(sessionID: UInt64, clientNonce: Data, serverNonce: Data) -> Data {
        let message = Self.serverProofPrefix + sessionID.bigEndianData + clientNonce + serverNonce
        let authenticationCode = HMAC<SHA256>.authenticationCode(
            for: message,
            using: SymmetricKey(data: psk)
        )
        return Data(authenticationCode)
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
