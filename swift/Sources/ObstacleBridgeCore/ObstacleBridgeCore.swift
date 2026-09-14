import Foundation
import Crypto

/// The intentionally small portable surface introduced by LSW-002.
/// Runtime migration from the Apple-oriented source tree begins in LSW-003.
public enum ObstacleBridgeCoreRuntime {
    public static let productName = "ObstacleBridgeLinux"
    public static let runtimeStatus = "Linux runtime migration is not yet implemented"
}

public enum ObstacleBridgeCryptoError: Error, Equatable {
    case invalidKeyLength(expected: Int, actual: Int)
    case invalidNonceLength(expected: Int, actual: Int)
    case invalidPublicKeyLength(expected: Int, actual: Int)
    case invalidPrivateKeyLength(expected: Int, actual: Int)
    case malformedCiphertext
    case authenticationFailed
    case cryptoFailure
}

/// Portable cryptographic primitives used by future Linux runtime targets.
/// All authenticated-encryption functions require caller-provided 96-bit
/// nonces so nonce allocation remains visible to the protocol owner.
public enum ObstacleBridgeCrypto {
    private static let keyLength = 32
    private static let nonceLength = 12
    private static let authenticationTagLength = 16

    public static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    public static func hmacSHA256(key: Data, message: Data) throws -> Data {
        return Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    }

    public static func hkdfSHA256(salt: Data, info: Data, keyMaterial: Data, outputByteCount: Int) throws -> Data {
        guard outputByteCount >= 0 else { throw ObstacleBridgeCryptoError.cryptoFailure }
        let normalizedSalt = salt.isEmpty ? Data(repeating: 0, count: SHA256.Digest.byteCount) : salt
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: keyMaterial),
            salt: normalizedSalt,
            info: info,
            outputByteCount: outputByteCount
        )
        return derived.withUnsafeBytes { Data($0) }
    }

    public static func pbkdf2SHA256(password: Data, salt: Data, iterations: Int, outputByteCount: Int) throws -> Data {
        guard iterations > 0, outputByteCount >= 0 else { throw ObstacleBridgeCryptoError.cryptoFailure }
        let digestLength = SHA256.Digest.byteCount
        let blockCount = (outputByteCount + digestLength - 1) / digestLength
        var output = Data()
        output.reserveCapacity(blockCount * digestLength)
        for blockIndex in 1...blockCount {
            var block = salt
            let index = UInt32(blockIndex).bigEndian
            withUnsafeBytes(of: index) { block.append(contentsOf: $0) }
            var accumulator = try hmacSHA256(key: password, message: block)
            var previous = accumulator
            if iterations > 1 {
                for _ in 2...iterations {
                    previous = try hmacSHA256(key: password, message: previous)
                    for index in accumulator.indices {
                        accumulator[index] ^= previous[index]
                    }
                }
            }
            output.append(accumulator)
        }
        return Data(output.prefix(outputByteCount))
    }

    /// Returns ciphertext followed by the 16-byte authentication tag.
    public static func aesGCMSeal(plaintext: Data, key: Data, nonce: Data, authenticatedData: Data = Data()) throws -> Data {
        try validateKey(key)
        try validateNonce(nonce)
        do {
            let sealed = try AES.GCM.seal(
                plaintext,
                using: SymmetricKey(data: key),
                nonce: try AES.GCM.Nonce(data: nonce),
                authenticating: authenticatedData
            )
            return sealed.ciphertext + sealed.tag
        } catch {
            throw ObstacleBridgeCryptoError.cryptoFailure
        }
    }

    public static func aesGCMOpen(ciphertextAndTag: Data, key: Data, nonce: Data, authenticatedData: Data = Data()) throws -> Data {
        try validateKey(key)
        try validateNonce(nonce)
        guard ciphertextAndTag.count >= authenticationTagLength else { throw ObstacleBridgeCryptoError.malformedCiphertext }
        let ciphertext = ciphertextAndTag.dropLast(authenticationTagLength)
        let tag = ciphertextAndTag.suffix(authenticationTagLength)
        do {
            let sealed = try AES.GCM.SealedBox(
                nonce: try AES.GCM.Nonce(data: nonce),
                ciphertext: ciphertext,
                tag: tag
            )
            return try AES.GCM.open(sealed, using: SymmetricKey(data: key), authenticating: authenticatedData)
        } catch {
            throw ObstacleBridgeCryptoError.authenticationFailed
        }
    }

    /// Returns ciphertext followed by the 16-byte authentication tag.
    public static func chaChaPolySeal(plaintext: Data, key: Data, nonce: Data, authenticatedData: Data = Data()) throws -> Data {
        try validateKey(key)
        try validateNonce(nonce)
        do {
            let sealed = try ChaChaPoly.seal(
                plaintext,
                using: SymmetricKey(data: key),
                nonce: try ChaChaPoly.Nonce(data: nonce),
                authenticating: authenticatedData
            )
            return sealed.ciphertext + sealed.tag
        } catch {
            throw ObstacleBridgeCryptoError.cryptoFailure
        }
    }

    public static func chaChaPolyOpen(ciphertextAndTag: Data, key: Data, nonce: Data, authenticatedData: Data = Data()) throws -> Data {
        try validateKey(key)
        try validateNonce(nonce)
        guard ciphertextAndTag.count >= authenticationTagLength else { throw ObstacleBridgeCryptoError.malformedCiphertext }
        let ciphertext = ciphertextAndTag.dropLast(authenticationTagLength)
        let tag = ciphertextAndTag.suffix(authenticationTagLength)
        do {
            let sealed = try ChaChaPoly.SealedBox(
                nonce: try ChaChaPoly.Nonce(data: nonce),
                ciphertext: ciphertext,
                tag: tag
            )
            return try ChaChaPoly.open(sealed, using: SymmetricKey(data: key), authenticating: authenticatedData)
        } catch {
            throw ObstacleBridgeCryptoError.authenticationFailed
        }
    }

    public static func ed25519PublicKey(privateKey: Data) throws -> Data {
        try validatePrivateKey(privateKey)
        do {
            return try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey).publicKey.rawRepresentation
        } catch {
            throw ObstacleBridgeCryptoError.cryptoFailure
        }
    }

    /// Generates a new Ed25519 private key through the shared crypto backend.
    public static func generateEd25519PrivateKey() -> Data {
        Curve25519.Signing.PrivateKey().rawRepresentation
    }

    public static func ed25519Sign(message: Data, privateKey: Data) throws -> Data {
        try validatePrivateKey(privateKey)
        do {
            return try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey).signature(for: message)
        } catch {
            throw ObstacleBridgeCryptoError.cryptoFailure
        }
    }

    public static func ed25519Verify(signature: Data, message: Data, publicKey: Data) throws -> Bool {
        try validatePublicKey(publicKey)
        do {
            return try Curve25519.Signing.PublicKey(rawRepresentation: publicKey).isValidSignature(signature, for: message)
        } catch {
            throw ObstacleBridgeCryptoError.cryptoFailure
        }
    }

    public static func x25519PublicKey(privateKey: Data) throws -> Data {
        try validatePrivateKey(privateKey)
        do {
            return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey).publicKey.rawRepresentation
        } catch {
            throw ObstacleBridgeCryptoError.cryptoFailure
        }
    }

    /// Generates a new X25519 private key through the shared crypto backend.
    public static func generateX25519PrivateKey() -> Data {
        Curve25519.KeyAgreement.PrivateKey().rawRepresentation
    }

    public static func x25519SharedSecret(privateKey: Data, peerPublicKey: Data) throws -> Data {
        try validatePrivateKey(privateKey)
        try validatePublicKey(peerPublicKey)
        do {
            let local = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
            let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey)
            let secret = try local.sharedSecretFromKeyAgreement(with: peer)
            return secret.withUnsafeBytes { Data($0) }
        } catch {
            throw ObstacleBridgeCryptoError.cryptoFailure
        }
    }

    private static func validateKey(_ key: Data) throws {
        guard key.count == keyLength else {
            throw ObstacleBridgeCryptoError.invalidKeyLength(expected: keyLength, actual: key.count)
        }
    }

    private static func validateNonce(_ nonce: Data) throws {
        guard nonce.count == nonceLength else {
            throw ObstacleBridgeCryptoError.invalidNonceLength(expected: nonceLength, actual: nonce.count)
        }
    }

    private static func validatePrivateKey(_ key: Data) throws {
        guard key.count == keyLength else {
            throw ObstacleBridgeCryptoError.invalidPrivateKeyLength(expected: keyLength, actual: key.count)
        }
    }

    private static func validatePublicKey(_ key: Data) throws {
        guard key.count == keyLength else {
            throw ObstacleBridgeCryptoError.invalidPublicKeyLength(expected: keyLength, actual: key.count)
        }
    }
}

/// Portable PSK transcript primitives shared with the SecureLink v1 wire
/// contract. Session-state ownership remains outside this low-level type.
public enum ObstacleBridgeSecureLinkPSKCrypto {
    public static func deriveKeys(psk: Data, sessionID: UInt64, clientNonce: Data, serverNonce: Data) throws -> (clientToServer: Data, serverToClient: Data) {
        let transcript = ObstacleBridgeSecureLinkPSKTranscript.keyDerivationInfo(
            sessionID: sessionID, clientNonce: clientNonce, serverNonce: serverNonce
        )
        let material = try ObstacleBridgeCrypto.hkdfSHA256(
            salt: ObstacleBridgeCrypto.sha256(psk),
            info: transcript,
            keyMaterial: psk + clientNonce + serverNonce,
            outputByteCount: 64
        )
        return (Data(material.prefix(32)), Data(material.suffix(32)))
    }

    public static func serverProof(psk: Data, sessionID: UInt64, clientNonce: Data, serverNonce: Data) throws -> Data {
        try ObstacleBridgeCrypto.hmacSHA256(
            key: psk,
            message: ObstacleBridgeSecureLinkPSKTranscript.serverProofMessage(
                sessionID: sessionID, clientNonce: clientNonce, serverNonce: serverNonce
            )
        )
    }

    public static func clientRekeyCommitProof(psk: Data, sessionID: UInt64, clientNonce: Data, serverNonce: Data) throws -> Data {
        try ObstacleBridgeCrypto.hmacSHA256(
            key: psk,
            message: ObstacleBridgeSecureLinkPSKTranscript.clientRekeyCommitProofMessage(
                sessionID: sessionID, clientNonce: clientNonce, serverNonce: serverNonce
            )
        )
    }
}

public enum ObstacleBridgeSecureLinkPSKClientError: Error, Equatable {
    case invalidPSK
    case invalidState
    case invalidFrame
    case authenticationFailed
    case replayedFrame
    case handshakeTimedOut
}

/// SecureLink v1 PSK frame-type ownership, including the rekey transition.
public enum ObstacleBridgeSecureLinkPSKFrameType {
    public static let capabilityPSKV1: UInt8 = 1
    public static let clientHello: UInt8 = 1
    public static let serverHello: UInt8 = 2
    public static let authFail: UInt8 = 3
    public static let authenticatedData: UInt8 = 4
    public static let rekeyHello: UInt8 = 5
    public static let rekeyReply: UInt8 = 6
    public static let rekeyCommit: UInt8 = 7
    public static let rekeyDone: UInt8 = 8
}

/// Redacted protocol state exported by a SecureLink PSK role. Platform
/// wrappers consume this snapshot for status publication; key material and
/// nonces remain private to the Core state machine.
public struct ObstacleBridgeSecureLinkPSKState: Sendable, Equatable {
    public let sessionID: UInt64
    public let txCounter: UInt64
    public let rxCounter: UInt64
    public let authenticated: Bool
    public let pendingRekeySessionID: UInt64
    public let applicationSendingBlocked: Bool
    /// Authenticated key generations observed during this Core peer's current
    /// lifecycle. A completed rekey installs another authenticated generation.
    public let authenticatedGenerationsTotal: UInt64
    public let rekeysCompletedTotal: UInt64

    public init(
        sessionID: UInt64,
        txCounter: UInt64,
        rxCounter: UInt64,
        authenticated: Bool,
        pendingRekeySessionID: UInt64,
        applicationSendingBlocked: Bool,
        authenticatedGenerationsTotal: UInt64 = 0,
        rekeysCompletedTotal: UInt64 = 0
    ) {
        self.sessionID = sessionID
        self.txCounter = txCounter
        self.rxCounter = rxCounter
        self.authenticated = authenticated
        self.pendingRekeySessionID = pendingRekeySessionID
        self.applicationSendingBlocked = applicationSendingBlocked
        self.authenticatedGenerationsTotal = authenticatedGenerationsTotal
        self.rekeysCompletedTotal = rekeysCompletedTotal
    }
}

/// Injected automatic-rekey policy for a portable client. Transport owners
/// poll the client at their own scheduler boundary and transmit any returned
/// control frame before their next application frame.
public struct ObstacleBridgeSecureLinkPSKRekeyPolicy: Sendable, Equatable {
    public let afterProtectedFrames: UInt64
    public let afterAuthenticatedSeconds: TimeInterval

    public init(afterProtectedFrames: UInt64 = 0, afterAuthenticatedSeconds: TimeInterval = 0) {
        self.afterProtectedFrames = afterProtectedFrames
        self.afterAuthenticatedSeconds = max(0, afterAuthenticatedSeconds)
    }

    public var isEnabled: Bool {
        afterProtectedFrames > 0 || afterAuthenticatedSeconds > 0
    }
}

/// Deterministic client-side authentication retry policy. Transport adapters
/// own connection attempts and wall-clock presentation; Core owns the bounded
/// failure count and monotonic retry deadline.
public struct ObstacleBridgeSecureLinkPSKRetryPolicy: Sendable, Equatable {
    public let initialBackoff: TimeInterval
    public let maximumBackoff: TimeInterval

    public init(initialBackoff: TimeInterval = 1, maximumBackoff: TimeInterval = 5) {
        self.initialBackoff = max(0, initialBackoff)
        self.maximumBackoff = max(self.initialBackoff, maximumBackoff)
    }
}

public struct ObstacleBridgeSecureLinkPSKRetryState: Sendable, Equatable {
    public private(set) var consecutiveFailures = 0
    public private(set) var retryNotBefore: TimeInterval?
    public let policy: ObstacleBridgeSecureLinkPSKRetryPolicy

    public init(policy: ObstacleBridgeSecureLinkPSKRetryPolicy = .init()) {
        self.policy = policy
    }

    public mutating func recordUnauthenticatedFailure(now: TimeInterval) -> TimeInterval? {
        guard policy.maximumBackoff > 0 else { return nil }
        consecutiveFailures += 1
        let exponent = max(0, consecutiveFailures - 1)
        let delay = min(policy.maximumBackoff, policy.initialBackoff * pow(2, Double(exponent)))
        retryNotBefore = now + delay
        return delay
    }

    public mutating func reset() {
        consecutiveFailures = 0
        retryNotBefore = nil
    }

    public mutating func clearSchedule() {
        retryNotBefore = nil
    }

    public func remainingBackoff(now: TimeInterval) -> TimeInterval {
        max(0, (retryNotBefore ?? now) - now)
    }

    public func isDue(now: TimeInterval) -> Bool {
        guard let retryNotBefore else { return false }
        return retryNotBefore <= now
    }
}

/// The client half of the SecureLink v1 PSK handshake and protected-data
/// envelope. Transport ownership remains external, which makes the same state
/// machine usable over Linux TCP and WebSocket lower transports.
public final class ObstacleBridgeSecureLinkPSKClient: @unchecked Sendable {
    private let psk: Data
    private let handshakeTimeout: TimeInterval
    private let timeProvider: () -> TimeInterval
    private let rekeyPolicy: ObstacleBridgeSecureLinkPSKRekeyPolicy
    private let sessionIDProvider: () -> UInt64
    private let randomBytes: (Int) -> Data
    private let stateLock = NSRecursiveLock()
    private var sessionID: UInt64 = 0
    private var clientNonce = Data()
    private var c2sKey = Data()
    private var s2cKey = Data()
    private var txCounter: UInt64 = 1
    private var rxCounter: UInt64 = 0
    private var authenticated = false
    private var handshakeStartedAt: TimeInterval?
    private var authenticatedAt: TimeInterval?
    private var protectedDataFramesSent: UInt64 = 0
    private var authenticatedGenerationsTotal: UInt64 = 0
    private var rekeysCompletedTotal: UInt64 = 0
    private var pendingSessionID: UInt64 = 0
    private var pendingClientNonce = Data()
    private var pendingServerNonce = Data()
    private var pendingC2SKey = Data()
    private var pendingS2CKey = Data()
    private var pendingCommit = Data()
    private var pendingCommitSent = false
    private var pendingRekeyStartedAt: TimeInterval?

    public var isAuthenticated: Bool {
        stateLock.lock(); defer { stateLock.unlock() }
        return authenticated
    }

    public var state: ObstacleBridgeSecureLinkPSKState {
        stateLock.lock(); defer { stateLock.unlock() }
        return ObstacleBridgeSecureLinkPSKState(
            sessionID: sessionID,
            txCounter: txCounter,
            rxCounter: rxCounter,
            authenticated: authenticated,
            pendingRekeySessionID: pendingSessionID,
            applicationSendingBlocked: pendingCommitSent,
            authenticatedGenerationsTotal: authenticatedGenerationsTotal,
            rekeysCompletedTotal: rekeysCompletedTotal
        )
    }

    /// The monotonic clock is injected so timeout behavior is deterministic in
    /// every package consumer and never depends on a platform event loop.
    public init(
        psk: Data,
        handshakeTimeout: TimeInterval = 60.0,
        timeProvider: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
        rekeyPolicy: ObstacleBridgeSecureLinkPSKRekeyPolicy = .init(),
        sessionIDProvider: @escaping () -> UInt64 = { UInt64.random(in: UInt64.min...UInt64.max) },
        randomBytes: @escaping (Int) -> Data = { count in Data((0..<count).map { _ in UInt8.random(in: UInt8.min...UInt8.max) }) }
    ) throws {
        guard !psk.isEmpty else { throw ObstacleBridgeSecureLinkPSKClientError.invalidPSK }
        self.psk = psk
        self.handshakeTimeout = max(0, handshakeTimeout)
        self.timeProvider = timeProvider
        self.rekeyPolicy = rekeyPolicy
        self.sessionIDProvider = sessionIDProvider
        self.randomBytes = randomBytes
    }

    public func begin(sessionID: UInt64, clientNonce: Data) throws -> Data {
        stateLock.lock(); defer { stateLock.unlock() }
        guard sessionID != 0, clientNonce.count == 32 else { throw ObstacleBridgeSecureLinkPSKClientError.invalidState }
        self.sessionID = sessionID
        self.clientNonce = clientNonce
        self.handshakeStartedAt = timeProvider()
        self.c2sKey = Data()
        self.txCounter = 1
        self.s2cKey = Data()
        self.rxCounter = 0
        self.authenticated = false
        self.authenticatedAt = nil
        self.protectedDataFramesSent = 0
        clearPendingRekey()
        return ObstacleBridgeSecureLinkFrameCodec.encode(type: ObstacleBridgeSecureLinkPSKFrameType.clientHello, sessionID: sessionID, counter: 0, payload: clientNonce + Data([ObstacleBridgeSecureLinkPSKFrameType.capabilityPSKV1, 0]))
    }

    /// Starts a fresh PSK rekey session; the active session remains in place
    /// until the later commit/done cutover is authenticated.
    public func beginRekey(sessionID: UInt64, clientNonce: Data) throws -> Data {
        stateLock.lock(); defer { stateLock.unlock() }
        try expireHandshakeIfNeeded()
        guard sessionID != 0, clientNonce.count == 32 else { throw ObstacleBridgeSecureLinkPSKClientError.invalidState }
        guard authenticated, pendingSessionID == 0, sessionID != self.sessionID else { throw ObstacleBridgeSecureLinkPSKClientError.invalidState }
        pendingSessionID = sessionID
        pendingClientNonce = clientNonce
        pendingRekeyStartedAt = timeProvider()
        return ObstacleBridgeSecureLinkFrameCodec.encode(type: ObstacleBridgeSecureLinkPSKFrameType.rekeyHello, sessionID: sessionID, counter: 0, payload: clientNonce + Data([ObstacleBridgeSecureLinkPSKFrameType.capabilityPSKV1, 0]))
    }

    /// Validates SERVER_HELLO and returns the encrypted client proof frame.
    public func handleServerHello(_ wire: Data) throws -> Data {
        stateLock.lock(); defer { stateLock.unlock() }
        try expireHandshakeIfNeeded()
        let parsed = try parse(wire)
        let expectedSessionID = sessionID
        let expectedClientNonce = clientNonce
        guard parsed.type == ObstacleBridgeSecureLinkPSKFrameType.serverHello, parsed.sessionID == expectedSessionID, parsed.counter == 0, parsed.payload.count >= 65 else {
            throw ObstacleBridgeSecureLinkPSKClientError.invalidFrame
        }
        let serverNonce = Data(parsed.payload.prefix(32))
        guard parsed.payload[32] == ObstacleBridgeSecureLinkPSKFrameType.capabilityPSKV1 else { throw ObstacleBridgeSecureLinkPSKClientError.invalidFrame }
        let proof = Data(parsed.payload[33..<65])
        let expected = try ObstacleBridgeSecureLinkPSKCrypto.serverProof(psk: psk, sessionID: expectedSessionID, clientNonce: expectedClientNonce, serverNonce: serverNonce)
        guard proof == expected else { throw ObstacleBridgeSecureLinkPSKClientError.authenticationFailed }
        let keys = try ObstacleBridgeSecureLinkPSKCrypto.deriveKeys(psk: psk, sessionID: expectedSessionID, clientNonce: expectedClientNonce, serverNonce: serverNonce)
        c2sKey = keys.clientToServer
        s2cKey = keys.serverToClient
        return try protect(Data())
    }

    /// Consumes the server's protected empty acknowledgement. No application
    /// payload is permitted before this confirmation has been authenticated.
    public func handleServerAcknowledgement(_ wire: Data) throws {
        stateLock.lock(); defer { stateLock.unlock() }
        try expireHandshakeIfNeeded()
        let plaintext = try unprotect(wire)
        guard plaintext.isEmpty else { throw ObstacleBridgeSecureLinkPSKClientError.invalidFrame }
        authenticated = true
        handshakeStartedAt = nil
        authenticatedAt = timeProvider()
        protectedDataFramesSent = 0
        authenticatedGenerationsTotal &+= 1
    }

    /// Validates REKEY_REPLY, derives the pending generation, and returns its
    /// transcript-bound REKEY_COMMIT without disturbing active traffic keys.
    public func handleRekeyReply(_ wire: Data) throws -> Data {
        stateLock.lock(); defer { stateLock.unlock() }
        try expireHandshakeIfNeeded()
        let parsed = try parse(wire)
        guard authenticated, pendingSessionID != 0,
              parsed.type == ObstacleBridgeSecureLinkPSKFrameType.rekeyReply,
              parsed.sessionID == pendingSessionID, parsed.counter == 0,
              parsed.payload.count == 65, parsed.payload[32] == ObstacleBridgeSecureLinkPSKFrameType.capabilityPSKV1 else {
            throw ObstacleBridgeSecureLinkPSKClientError.invalidFrame
        }
        let serverNonce = Data(parsed.payload.prefix(32))
        let proof = Data(parsed.payload[33..<65])
        let expected = try ObstacleBridgeSecureLinkPSKCrypto.serverProof(
            psk: psk, sessionID: pendingSessionID,
            clientNonce: pendingClientNonce, serverNonce: serverNonce
        )
        guard proof == expected else { throw ObstacleBridgeSecureLinkPSKClientError.authenticationFailed }
        if pendingCommitSent {
            guard serverNonce == pendingServerNonce, !pendingCommit.isEmpty else {
                throw ObstacleBridgeSecureLinkPSKClientError.invalidFrame
            }
            return pendingCommit
        }
        let keys = try ObstacleBridgeSecureLinkPSKCrypto.deriveKeys(
            psk: psk, sessionID: pendingSessionID,
            clientNonce: pendingClientNonce, serverNonce: serverNonce
        )
        pendingServerNonce = serverNonce
        pendingC2SKey = keys.clientToServer
        pendingS2CKey = keys.serverToClient
        pendingCommitSent = true
        let commitProof = try ObstacleBridgeSecureLinkPSKCrypto.clientRekeyCommitProof(
            psk: psk, sessionID: pendingSessionID,
            clientNonce: pendingClientNonce, serverNonce: serverNonce
        )
        pendingCommit = ObstacleBridgeSecureLinkFrameCodec.encode(
            type: ObstacleBridgeSecureLinkPSKFrameType.rekeyCommit,
            sessionID: pendingSessionID, counter: 0, payload: commitProof
        )
        return pendingCommit
    }

    /// Authenticates REKEY_DONE and atomically installs the pending generation.
    public func handleRekeyDone(_ wire: Data) throws {
        stateLock.lock(); defer { stateLock.unlock() }
        try expireHandshakeIfNeeded()
        let parsed = try parse(wire)
        guard authenticated, pendingCommitSent,
              parsed.type == ObstacleBridgeSecureLinkPSKFrameType.rekeyDone,
              parsed.sessionID == pendingSessionID, parsed.counter == 0,
              parsed.payload.isEmpty, pendingC2SKey.count == 32,
              pendingS2CKey.count == 32 else {
            throw ObstacleBridgeSecureLinkPSKClientError.invalidFrame
        }
        sessionID = pendingSessionID
        clientNonce = pendingClientNonce
        c2sKey = pendingC2SKey
        s2cKey = pendingS2CKey
        txCounter = 1
        rxCounter = 0
        authenticatedAt = timeProvider()
        protectedDataFramesSent = 0
        authenticatedGenerationsTotal &+= 1
        rekeysCompletedTotal &+= 1
        clearPendingRekey()
    }

    /// Starts an injected-policy rekey when its frame or time threshold is
    /// due. A nil result means the active generation remains below both
    /// thresholds or an exchange is already pending.
    public func pollAutomaticRekey() throws -> Data? {
        stateLock.lock(); defer { stateLock.unlock() }
        try expireHandshakeIfNeeded()
        guard authenticated, pendingSessionID == 0, rekeyPolicy.isEnabled else { return nil }
        let frameDue = rekeyPolicy.afterProtectedFrames > 0 &&
            protectedDataFramesSent >= rekeyPolicy.afterProtectedFrames
        let timeDue = rekeyPolicy.afterAuthenticatedSeconds > 0 &&
            (authenticatedAt.map { timeProvider() - $0 >= rekeyPolicy.afterAuthenticatedSeconds } ?? false)
        guard frameDue || timeDue else { return nil }
        let nextSessionID = try nextAutomaticSessionID()
        let nextClientNonce = randomBytes(32)
        guard nextClientNonce.count == 32 else { throw ObstacleBridgeSecureLinkPSKClientError.invalidState }
        return try beginRekey(sessionID: nextSessionID, clientNonce: nextClientNonce)
    }

    public func protect(_ payload: Data) throws -> Data {
        stateLock.lock(); defer { stateLock.unlock() }
        try expireHandshakeIfNeeded()
        guard !pendingCommitSent, sessionID != 0, c2sKey.count == 32, txCounter > 0 else { throw ObstacleBridgeSecureLinkPSKClientError.invalidState }
        let header = ObstacleBridgeSecureLinkFrameCodec.header(type: ObstacleBridgeSecureLinkPSKFrameType.authenticatedData, sessionID: sessionID, counter: txCounter)
        let ciphertext = try ObstacleBridgeCrypto.chaChaPolySeal(
            plaintext: payload,
            key: c2sKey,
            nonce: nonce(counter: txCounter),
            authenticatedData: header
        )
        txCounter &+= 1
        if authenticated, pendingSessionID == 0 {
            protectedDataFramesSent &+= 1
        }
        return header + ciphertext
    }

    public func unprotect(_ wire: Data) throws -> Data {
        stateLock.lock(); defer { stateLock.unlock() }
        try expireHandshakeIfNeeded()
        let parsed = try parse(wire)
        guard parsed.type == ObstacleBridgeSecureLinkPSKFrameType.authenticatedData, parsed.sessionID == sessionID, parsed.counter > rxCounter, s2cKey.count == 32 else {
            throw parsed.counter <= rxCounter ? ObstacleBridgeSecureLinkPSKClientError.replayedFrame : ObstacleBridgeSecureLinkPSKClientError.invalidFrame
        }
        let plaintext: Data
        do {
            plaintext = try ObstacleBridgeCrypto.chaChaPolyOpen(
                ciphertextAndTag: parsed.payload,
                key: s2cKey,
                nonce: nonce(counter: parsed.counter),
                authenticatedData: parsed.header
            )
        } catch {
            throw ObstacleBridgeSecureLinkPSKClientError.authenticationFailed
        }
        rxCounter = parsed.counter
        return plaintext
    }

    /// Invalidates an unconfirmed handshake or pending rekey that has exceeded
    /// the injected monotonic deadline. Both cases fail closed.
    public func expireHandshakeIfNeeded() throws {
        stateLock.lock(); defer { stateLock.unlock() }
        let initialHandshakeExpired = handshakeTimeout > 0 && sessionID != 0 && !authenticated &&
            (handshakeStartedAt.map { timeProvider() - $0 >= handshakeTimeout } ?? false)
        let pendingRekeyExpired = handshakeTimeout > 0 && pendingSessionID != 0 &&
            (pendingRekeyStartedAt.map { timeProvider() - $0 >= handshakeTimeout } ?? false)
        let expired = initialHandshakeExpired || pendingRekeyExpired
        if expired {
            sessionID = 0
            clientNonce = Data()
            authenticated = false
            handshakeStartedAt = nil
            authenticatedAt = nil
            protectedDataFramesSent = 0
        }
        guard expired else { return }
        c2sKey = Data()
        txCounter = 1
        s2cKey = Data()
        rxCounter = 0
        clearPendingRekey()
        throw ObstacleBridgeSecureLinkPSKClientError.handshakeTimedOut
    }

    /// Clears all protocol state when a platform transport moves to a fresh
    /// lifecycle epoch. The adapter retains its own transport/status history.
    public func reset() {
        stateLock.lock(); defer { stateLock.unlock() }
        sessionID = 0
        clientNonce = Data()
        c2sKey = Data()
        s2cKey = Data()
        txCounter = 1
        rxCounter = 0
        authenticated = false
        handshakeStartedAt = nil
        authenticatedAt = nil
        protectedDataFramesSent = 0
        authenticatedGenerationsTotal = 0
        rekeysCompletedTotal = 0
        clearPendingRekey()
    }

    private func clearPendingRekey() {
        pendingSessionID = 0
        pendingClientNonce = Data()
        pendingServerNonce = Data()
        pendingC2SKey = Data()
        pendingS2CKey = Data()
        pendingCommit = Data()
        pendingCommitSent = false
        pendingRekeyStartedAt = nil
    }

    private func nextAutomaticSessionID() throws -> UInt64 {
        for _ in 0..<16 {
            let candidate = sessionIDProvider()
            if candidate != 0, candidate != sessionID, candidate != pendingSessionID {
                return candidate
            }
        }
        throw ObstacleBridgeSecureLinkPSKClientError.invalidState
    }

    private func nonce(counter: UInt64) -> Data {
        var value = counter.bigEndian
        return Data([0, 0, 0, 0]) + Data(bytes: &value, count: MemoryLayout<UInt64>.size)
    }

    private func parse(_ wire: Data) throws -> ObstacleBridgeSecureLinkFrame {
        do { return try ObstacleBridgeSecureLinkFrameCodec.decode(wire) }
        catch { throw ObstacleBridgeSecureLinkPSKClientError.invalidFrame }
    }
}

/// Server half of the SecureLink v1 PSK handshake.  It deliberately mirrors
/// the client directional keys so a Linux listener can authenticate a Python
/// client without delegating any cryptographic operation to Python.
public final class ObstacleBridgeSecureLinkPSKServer: @unchecked Sendable {
    private let psk: Data
    private let handshakeTimeout: TimeInterval
    private let rekeyOverlap: TimeInterval
    private let timeProvider: () -> TimeInterval
    private let stateLock = NSRecursiveLock()
    private var sessionID: UInt64 = 0
    private var clientNonce = Data()
    private var c2sKey = Data()
    private var s2cKey = Data()
    private var txCounter: UInt64 = 1
    private var rxCounter: UInt64 = 0
    private var authenticated = false
    private var handshakeStartedAt: TimeInterval?
    private var authenticatedGenerationsTotal: UInt64 = 0
    private var rekeysCompletedTotal: UInt64 = 0
    private var pendingSessionID: UInt64 = 0
    private var pendingClientNonce = Data()
    private var pendingServerNonce = Data()
    private var pendingC2SKey = Data()
    private var pendingS2CKey = Data()
    private var pendingRekeyStartedAt: TimeInterval?
    private var lastCompletedRekeySessionID: UInt64 = 0
    private var lastCompletedRekeyCommit = Data()
    private var lastCompletedRekeyDone = Data()
    // A client can have old-generation application DATA in flight when its
    // commit causes this server to install the pending generation. Keep that
    // inbound direction available briefly; the client itself holds new sends
    // until REKEY_DONE authenticates its matching cutover.
    private var drainingSessionID: UInt64 = 0
    private var drainingC2SKey = Data()
    private var drainingRxCounter: UInt64 = 0
    private var drainingUntil: TimeInterval?

    public var isAuthenticated: Bool {
        stateLock.lock(); defer { stateLock.unlock() }
        return authenticated
    }

    public var state: ObstacleBridgeSecureLinkPSKState {
        stateLock.lock(); defer { stateLock.unlock() }
        return ObstacleBridgeSecureLinkPSKState(
            sessionID: sessionID,
            txCounter: txCounter,
            rxCounter: rxCounter,
            authenticated: authenticated,
            pendingRekeySessionID: pendingSessionID,
            applicationSendingBlocked: false,
            authenticatedGenerationsTotal: authenticatedGenerationsTotal,
            rekeysCompletedTotal: rekeysCompletedTotal
        )
    }

    public init(
        psk: Data,
        handshakeTimeout: TimeInterval = 60.0,
        rekeyOverlap: TimeInterval = 5.0,
        timeProvider: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }
    ) throws {
        guard !psk.isEmpty else { throw ObstacleBridgeSecureLinkPSKClientError.invalidPSK }
        self.psk = psk
        self.handshakeTimeout = max(0, handshakeTimeout)
        self.rekeyOverlap = max(0, rekeyOverlap)
        self.timeProvider = timeProvider
    }

    /// Validates CLIENT_HELLO and returns SERVER_HELLO using the supplied
    /// nonce so callers can pin deterministic Python-derived vectors.
    public func handleClientHello(_ wire: Data, serverNonce: Data) throws -> Data {
        stateLock.lock(); defer { stateLock.unlock() }
        let parsed = try parse(wire)
        guard parsed.type == ObstacleBridgeSecureLinkPSKFrameType.clientHello, parsed.counter == 0, parsed.payload.count == 34,
              parsed.payload[32] == ObstacleBridgeSecureLinkPSKFrameType.capabilityPSKV1, parsed.payload[33] == 0, serverNonce.count == 32 else {
            throw ObstacleBridgeSecureLinkPSKClientError.invalidFrame
        }
        sessionID = parsed.sessionID
        clientNonce = Data(parsed.payload.prefix(32))
        clearPendingRekey()
        clearDrainingGeneration()
        clearCompletedRekey()
        handshakeStartedAt = timeProvider()
        let keys = try ObstacleBridgeSecureLinkPSKCrypto.deriveKeys(psk: psk, sessionID: sessionID, clientNonce: clientNonce, serverNonce: serverNonce)
        c2sKey = keys.clientToServer
        s2cKey = keys.serverToClient
        txCounter = 1; rxCounter = 0; authenticated = false
        let proof = try ObstacleBridgeSecureLinkPSKCrypto.serverProof(psk: psk, sessionID: sessionID, clientNonce: clientNonce, serverNonce: serverNonce)
        return ObstacleBridgeSecureLinkFrameCodec.encode(type: ObstacleBridgeSecureLinkPSKFrameType.serverHello, sessionID: sessionID, counter: 0, payload: serverNonce + Data([ObstacleBridgeSecureLinkPSKFrameType.capabilityPSKV1]) + proof)
    }

    /// Validates the encrypted empty client proof and returns the encrypted
    /// server acknowledgement which completes the handshake.
    public func handleClientProof(_ wire: Data) throws -> Data {
        stateLock.lock(); defer { stateLock.unlock() }
        try expireHandshakeIfNeeded()
        let plaintext = try unprotect(wire)
        guard plaintext.isEmpty else { throw ObstacleBridgeSecureLinkPSKClientError.invalidFrame }
        authenticated = true
        handshakeStartedAt = nil
        authenticatedGenerationsTotal &+= 1
        return try protect(Data())
    }

    public func handleRekeyHello(_ wire: Data, serverNonce: Data) throws -> Data {
        stateLock.lock(); defer { stateLock.unlock() }
        try expireHandshakeIfNeeded()
        let frame = try parse(wire)
        guard authenticated, pendingSessionID == 0 || pendingSessionID == frame.sessionID,
              frame.type == ObstacleBridgeSecureLinkPSKFrameType.rekeyHello,
              frame.sessionID != 0, frame.sessionID != sessionID, frame.payload.count == 34,
              frame.payload[32] == ObstacleBridgeSecureLinkPSKFrameType.capabilityPSKV1, serverNonce.count == 32 else { throw ObstacleBridgeSecureLinkPSKClientError.invalidFrame }
        let nonce = Data(frame.payload.prefix(32))
        if pendingSessionID == 0 {
            pendingSessionID = frame.sessionID
            pendingRekeyStartedAt = timeProvider()
            pendingClientNonce = nonce
            pendingServerNonce = serverNonce
            let keys = try ObstacleBridgeSecureLinkPSKCrypto.deriveKeys(
                psk: psk, sessionID: frame.sessionID,
                clientNonce: nonce, serverNonce: serverNonce
            )
            pendingC2SKey = keys.clientToServer
            pendingS2CKey = keys.serverToClient
        } else if nonce != pendingClientNonce {
            throw ObstacleBridgeSecureLinkPSKClientError.invalidFrame
        }
        let proof = try ObstacleBridgeSecureLinkPSKCrypto.serverProof(
            psk: psk, sessionID: pendingSessionID,
            clientNonce: pendingClientNonce, serverNonce: pendingServerNonce
        )
        return ObstacleBridgeSecureLinkFrameCodec.encode(
            type: ObstacleBridgeSecureLinkPSKFrameType.rekeyReply,
            sessionID: pendingSessionID, counter: 0,
            payload: pendingServerNonce + Data([ObstacleBridgeSecureLinkPSKFrameType.capabilityPSKV1]) + proof
        )
    }

    /// Authenticates REKEY_COMMIT, installs the pending generation, and
    /// returns REKEY_DONE to authorize the client's matching cutover.
    public func handleRekeyCommit(_ wire: Data) throws -> Data {
        stateLock.lock(); defer { stateLock.unlock() }
        try expireHandshakeIfNeeded()
        let frame = try parse(wire)
        if authenticated, frame.type == ObstacleBridgeSecureLinkPSKFrameType.rekeyCommit,
           frame.sessionID == lastCompletedRekeySessionID,
           frame.payload == lastCompletedRekeyCommit,
           !lastCompletedRekeyDone.isEmpty {
            return lastCompletedRekeyDone
        }
        guard authenticated, pendingSessionID != 0,
              frame.type == ObstacleBridgeSecureLinkPSKFrameType.rekeyCommit,
              frame.sessionID == pendingSessionID, frame.counter == 0,
              frame.payload.count == 32, pendingC2SKey.count == 32,
              pendingS2CKey.count == 32 else {
            throw ObstacleBridgeSecureLinkPSKClientError.invalidFrame
        }
        let expected = try ObstacleBridgeSecureLinkPSKCrypto.clientRekeyCommitProof(
            psk: psk, sessionID: pendingSessionID,
            clientNonce: pendingClientNonce, serverNonce: pendingServerNonce
        )
        guard frame.payload == expected else { throw ObstacleBridgeSecureLinkPSKClientError.authenticationFailed }
        drainingSessionID = sessionID
        drainingC2SKey = c2sKey
        drainingRxCounter = rxCounter
        drainingUntil = rekeyOverlap > 0 ? timeProvider() + rekeyOverlap : nil
        sessionID = pendingSessionID
        clientNonce = pendingClientNonce
        c2sKey = pendingC2SKey
        s2cKey = pendingS2CKey
        txCounter = 1
        rxCounter = 0
        let done = ObstacleBridgeSecureLinkFrameCodec.encode(
            type: ObstacleBridgeSecureLinkPSKFrameType.rekeyDone,
            sessionID: sessionID, counter: 0, payload: Data()
        )
        lastCompletedRekeySessionID = sessionID
        lastCompletedRekeyCommit = frame.payload
        lastCompletedRekeyDone = done
        authenticatedGenerationsTotal &+= 1
        rekeysCompletedTotal &+= 1
        clearPendingRekey()
        return done
    }

    public func protect(_ payload: Data) throws -> Data {
        stateLock.lock(); defer { stateLock.unlock() }
        try expireHandshakeIfNeeded()
        guard sessionID != 0, s2cKey.count == 32, txCounter > 0 else { throw ObstacleBridgeSecureLinkPSKClientError.invalidState }
        let counter = txCounter
        let header = ObstacleBridgeSecureLinkFrameCodec.header(type: ObstacleBridgeSecureLinkPSKFrameType.authenticatedData, sessionID: sessionID, counter: counter)
        let ciphertext = try ObstacleBridgeCrypto.chaChaPolySeal(plaintext: payload, key: s2cKey, nonce: nonce(counter: counter), authenticatedData: header)
        txCounter &+= 1
        return header + ciphertext
    }

    public func unprotect(_ wire: Data) throws -> Data {
        stateLock.lock(); defer { stateLock.unlock() }
        try expireHandshakeIfNeeded()
        let parsed = try parse(wire)
        guard parsed.type == ObstacleBridgeSecureLinkPSKFrameType.authenticatedData else { throw ObstacleBridgeSecureLinkPSKClientError.invalidFrame }
        if parsed.sessionID == sessionID {
            guard parsed.counter > rxCounter, c2sKey.count == 32 else {
                throw parsed.counter <= rxCounter ? ObstacleBridgeSecureLinkPSKClientError.replayedFrame : ObstacleBridgeSecureLinkPSKClientError.invalidFrame
            }
            do {
                let plaintext = try ObstacleBridgeCrypto.chaChaPolyOpen(ciphertextAndTag: parsed.payload, key: c2sKey, nonce: nonce(counter: parsed.counter), authenticatedData: parsed.header)
                rxCounter = parsed.counter
                return plaintext
            } catch { throw ObstacleBridgeSecureLinkPSKClientError.authenticationFailed }
        }
        guard parsed.sessionID == drainingSessionID,
              drainingUntil.map({ timeProvider() <= $0 }) ?? false,
              parsed.counter > drainingRxCounter, drainingC2SKey.count == 32 else {
            throw parsed.counter <= drainingRxCounter ? ObstacleBridgeSecureLinkPSKClientError.replayedFrame : ObstacleBridgeSecureLinkPSKClientError.invalidFrame
        }
        do {
            let plaintext = try ObstacleBridgeCrypto.chaChaPolyOpen(ciphertextAndTag: parsed.payload, key: drainingC2SKey, nonce: nonce(counter: parsed.counter), authenticatedData: parsed.header)
            drainingRxCounter = parsed.counter
            return plaintext
        } catch { throw ObstacleBridgeSecureLinkPSKClientError.authenticationFailed }
    }

    /// Applies the same injected-clock deadline as the client while the
    /// listener awaits its protected client confirmation or rekey commit.
    public func expireHandshakeIfNeeded() throws {
        stateLock.lock(); defer { stateLock.unlock() }
        let initialHandshakeExpired = handshakeTimeout > 0 && sessionID != 0 &&
            !authenticated && (handshakeStartedAt.map { timeProvider() - $0 >= handshakeTimeout } ?? false)
        let pendingRekeyExpired = handshakeTimeout > 0 && pendingSessionID != 0 &&
            (pendingRekeyStartedAt.map { timeProvider() - $0 >= handshakeTimeout } ?? false)
        guard initialHandshakeExpired || pendingRekeyExpired else {
            return
        }
        sessionID = 0
        clientNonce = Data()
        c2sKey = Data()
        s2cKey = Data()
        txCounter = 1
        rxCounter = 0
        authenticated = false
        self.handshakeStartedAt = nil
        clearPendingRekey()
        clearDrainingGeneration()
        throw ObstacleBridgeSecureLinkPSKClientError.handshakeTimedOut
    }

    /// Clears listener-side protocol state after the owning transport drops a
    /// peer lifecycle epoch. Status history remains the adapter's concern.
    public func reset() {
        stateLock.lock(); defer { stateLock.unlock() }
        sessionID = 0
        clientNonce = Data()
        c2sKey = Data()
        s2cKey = Data()
        txCounter = 1
        rxCounter = 0
        authenticated = false
        handshakeStartedAt = nil
        authenticatedGenerationsTotal = 0
        rekeysCompletedTotal = 0
        clearPendingRekey()
        clearDrainingGeneration()
        clearCompletedRekey()
    }

    private func clearPendingRekey() {
        pendingSessionID = 0
        pendingClientNonce = Data()
        pendingServerNonce = Data()
        pendingC2SKey = Data()
        pendingS2CKey = Data()
        pendingRekeyStartedAt = nil
    }

    private func clearDrainingGeneration() {
        drainingSessionID = 0
        drainingC2SKey = Data()
        drainingRxCounter = 0
        drainingUntil = nil
    }

    private func clearCompletedRekey() {
        lastCompletedRekeySessionID = 0
        lastCompletedRekeyCommit = Data()
        lastCompletedRekeyDone = Data()
    }

    private func nonce(counter: UInt64) -> Data { var value = counter.bigEndian; return Data([0, 0, 0, 0]) + Data(bytes: &value, count: MemoryLayout<UInt64>.size) }
    private func parse(_ wire: Data) throws -> ObstacleBridgeSecureLinkFrame {
        do { return try ObstacleBridgeSecureLinkFrameCodec.decode(wire) }
        catch { throw ObstacleBridgeSecureLinkPSKClientError.invalidFrame }
    }
}

private extension UInt64 {
    var bigEndianData: Data {
        var value = bigEndian
        return withUnsafeBytes(of: &value) { Data($0) }
    }
}
