import Foundation
import Crypto

/// The intentionally small portable surface introduced by LSW-002.
/// Runtime migration from the Apple-oriented source tree begins in LSW-003.
public enum ObstacleBridgePortableRuntime {
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
    private static let transcriptPrefix = Data("obstaclebridge-securelink-psk-v1|".utf8)
    private static let serverProofPrefix = Data("obstaclebridge-securelink-server-proof-v1|".utf8)
    private static let clientRekeyCommitProofPrefix = Data("obstaclebridge-securelink-client-rekey-commit-v1|".utf8)

    public static func deriveKeys(psk: Data, sessionID: UInt64, clientNonce: Data, serverNonce: Data) throws -> (clientToServer: Data, serverToClient: Data) {
        let transcript = transcriptPrefix + sessionID.bigEndianData + clientNonce + serverNonce
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
            message: serverProofPrefix + sessionID.bigEndianData + clientNonce + serverNonce
        )
    }

    public static func clientRekeyCommitProof(psk: Data, sessionID: UInt64, clientNonce: Data, serverNonce: Data) throws -> Data {
        try ObstacleBridgeCrypto.hmacSHA256(
            key: psk,
            message: clientRekeyCommitProofPrefix + sessionID.bigEndianData + clientNonce + serverNonce
        )
    }
}

public enum ObstacleBridgeSecureLinkPSKClientError: Error, Equatable {
    case invalidPSK
    case invalidState
    case invalidFrame
    case authenticationFailed
    case replayedFrame
}

/// The client half of the SecureLink v1 PSK handshake and protected-data
/// envelope. Transport ownership remains external, which makes the same state
/// machine usable over Linux TCP and WebSocket lower transports.
public final class ObstacleBridgeSecureLinkPSKClient {
    private let psk: Data
    private var sessionID: UInt64 = 0
    private var clientNonce = Data()
    private var c2sKey = Data()
    private var s2cKey = Data()
    private var txCounter: UInt64 = 1
    private var rxCounter: UInt64 = 0
    private(set) public var isAuthenticated = false

    public init(psk: Data) throws {
        guard !psk.isEmpty else { throw ObstacleBridgeSecureLinkPSKClientError.invalidPSK }
        self.psk = psk
    }

    public func begin(sessionID: UInt64, clientNonce: Data) throws -> Data {
        guard sessionID != 0, clientNonce.count == 32 else { throw ObstacleBridgeSecureLinkPSKClientError.invalidState }
        self.sessionID = sessionID
        self.clientNonce = clientNonce
        self.c2sKey = Data()
        self.s2cKey = Data()
        self.txCounter = 1
        self.rxCounter = 0
        self.isAuthenticated = false
        return frame(type: 1, sessionID: sessionID, counter: 0, payload: clientNonce + Data([1, 0]))
    }

    /// Validates SERVER_HELLO and returns the encrypted client proof frame.
    public func handleServerHello(_ wire: Data) throws -> Data {
        let parsed = try parse(wire)
        guard parsed.type == 2, parsed.sessionID == sessionID, parsed.counter == 0, parsed.payload.count >= 65 else {
            throw ObstacleBridgeSecureLinkPSKClientError.invalidFrame
        }
        let serverNonce = Data(parsed.payload.prefix(32))
        guard parsed.payload[32] == 1 else { throw ObstacleBridgeSecureLinkPSKClientError.invalidFrame }
        let proof = Data(parsed.payload[33..<65])
        let expected = try ObstacleBridgeSecureLinkPSKCrypto.serverProof(psk: psk, sessionID: sessionID, clientNonce: clientNonce, serverNonce: serverNonce)
        guard proof == expected else { throw ObstacleBridgeSecureLinkPSKClientError.authenticationFailed }
        let keys = try ObstacleBridgeSecureLinkPSKCrypto.deriveKeys(psk: psk, sessionID: sessionID, clientNonce: clientNonce, serverNonce: serverNonce)
        c2sKey = keys.clientToServer
        s2cKey = keys.serverToClient
        return try protect(Data())
    }

    /// Consumes the server's protected empty acknowledgement. No application
    /// payload is permitted before this confirmation has been authenticated.
    public func handleServerAcknowledgement(_ wire: Data) throws {
        let plaintext = try unprotect(wire)
        guard plaintext.isEmpty else { throw ObstacleBridgeSecureLinkPSKClientError.invalidFrame }
        isAuthenticated = true
    }

    public func protect(_ payload: Data) throws -> Data {
        guard sessionID != 0, c2sKey.count == 32, txCounter > 0 else { throw ObstacleBridgeSecureLinkPSKClientError.invalidState }
        let header = frameHeader(type: 4, sessionID: sessionID, counter: txCounter)
        let ciphertext = try ObstacleBridgeCrypto.chaChaPolySeal(
            plaintext: payload,
            key: c2sKey,
            nonce: nonce(counter: txCounter),
            authenticatedData: header
        )
        defer { txCounter &+= 1 }
        return header + ciphertext
    }

    public func unprotect(_ wire: Data) throws -> Data {
        let parsed = try parse(wire)
        guard parsed.type == 4, parsed.sessionID == sessionID, parsed.counter > rxCounter, s2cKey.count == 32 else {
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

    private func frame(type: UInt8, sessionID: UInt64, counter: UInt64, payload: Data) -> Data {
        frameHeader(type: type, sessionID: sessionID, counter: counter) + payload
    }

    private func frameHeader(type: UInt8, sessionID: UInt64, counter: UInt64) -> Data {
        var header = Data([1, type, 0, 0])
        var session = sessionID.bigEndian
        var sequence = counter.bigEndian
        header.append(Data(bytes: &session, count: MemoryLayout<UInt64>.size))
        header.append(Data(bytes: &sequence, count: MemoryLayout<UInt64>.size))
        return header
    }

    private func nonce(counter: UInt64) -> Data {
        var value = counter.bigEndian
        return Data([0, 0, 0, 0]) + Data(bytes: &value, count: MemoryLayout<UInt64>.size)
    }

    private func parse(_ wire: Data) throws -> (type: UInt8, sessionID: UInt64, counter: UInt64, header: Data, payload: Data) {
        guard wire.count >= 20, wire[0] == 1 else { throw ObstacleBridgeSecureLinkPSKClientError.invalidFrame }
        let sessionID = readUInt64(wire, offset: 4)
        let counter = readUInt64(wire, offset: 12)
        return (wire[1], sessionID, counter, Data(wire.prefix(20)), Data(wire.dropFirst(20)))
    }

    private func readUInt64(_ data: Data, offset: Int) -> UInt64 {
        var value: UInt64 = 0
        for index in offset..<(offset + 8) {
            value = (value << 8) | UInt64(data[index])
        }
        return value
    }
}

private extension UInt64 {
    var bigEndianData: Data {
        var value = bigEndian
        return withUnsafeBytes(of: &value) { Data($0) }
    }
}
