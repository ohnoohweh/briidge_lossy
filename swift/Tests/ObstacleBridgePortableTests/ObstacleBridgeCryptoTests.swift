import Foundation
import Testing
@testable import ObstacleBridgePortable

struct ObstacleBridgeCryptoTests {
    @Test func channelMuxHeaderMatchesEstablishedWireShape() throws {
        let wire = try ObstacleBridgeChannelMuxCodec.encode(
            channelID: 0x0102,
            protocolType: .tcp,
            counter: 0x0304,
            messageType: .data,
            body: Data([0xaa, 0xbb])
        )
        #expect(wire == Data([0x01, 0x02, 0x01, 0x03, 0x04, 0x00, 0x00, 0x02, 0xaa, 0xbb]))
        #expect(try ObstacleBridgeChannelMuxCodec.decode(wire).body == Data([0xaa, 0xbb]))
        #expect(throws: ObstacleBridgeChannelMuxCodecError.invalidFrame) { try ObstacleBridgeChannelMuxCodec.decode(Data([0])) }
    }

    @Test func myudpDataFrameMatchesPythonV2Layout() throws {
        let wire = try ObstacleBridgeMyUDPCodec.encodeData(payload: Data("udp".utf8), counter: 7, transmittedNanoseconds: 0x0102, echoedNanoseconds: 0x0304)
        #expect(wire == Data([1, 0, 11, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 3, 4, 1, 1, 0, 7, 0, 7, 0, 3, 117, 100, 112]))
        #expect(try ObstacleBridgeMyUDPCodec.decodeData(wire) == .init(counter: 7, payload: Data("udp".utf8), transmittedNanoseconds: 0x0102, echoedNanoseconds: 0x0304))
        #expect(throws: ObstacleBridgeMyUDPCodecError.invalidFrame) { try ObstacleBridgeMyUDPCodec.decodeData(Data([1])) }
    }
    @Test func hashesAndKeyDerivationMatchKnownAnswerVectors() throws {
        #expect(ObstacleBridgeCrypto.sha256(Data("abc".utf8)).hex == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        #expect(try ObstacleBridgeCrypto.hmacSHA256(key: Data("key".utf8), message: Data("The quick brown fox jumps over the lazy dog".utf8)).hex == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
        #expect(try ObstacleBridgeCrypto.hkdfSHA256(salt: .hex("000102030405060708090a0b0c"), info: .hex("f0f1f2f3f4f5f6f7f8f9"), keyMaterial: Data(repeating: 0x0b, count: 22), outputByteCount: 42).hex == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        #expect(try ObstacleBridgeCrypto.pbkdf2SHA256(password: Data("password".utf8), salt: Data("salt".utf8), iterations: 2, outputByteCount: 32).hex == "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
    }

    @Test func authenticatedEncryptionMatchesKnownAnswerVectorsAndFailsClosed() throws {
        let zeroKey = Data(repeating: 0, count: 32)
        let zeroNonce = Data(repeating: 0, count: 12)
        let aes = try ObstacleBridgeCrypto.aesGCMSeal(plaintext: Data(repeating: 0, count: 16), key: zeroKey, nonce: zeroNonce)
        #expect(aes.hex == "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919")
        #expect(try ObstacleBridgeCrypto.aesGCMOpen(ciphertextAndTag: aes, key: zeroKey, nonce: zeroNonce) == Data(repeating: 0, count: 16))

        let chacha = try ObstacleBridgeCrypto.chaChaPolySeal(
            plaintext: Data("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".utf8),
            key: .hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
            nonce: .hex("070000004041424344454647"),
            authenticatedData: .hex("50515253c0c1c2c3c4c5c6c7")
        )
        #expect(chacha.hex == "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691")
        var tampered = chacha
        tampered[tampered.startIndex] ^= 0x01
        #expect(throws: ObstacleBridgeCryptoError.authenticationFailed) {
            try ObstacleBridgeCrypto.chaChaPolyOpen(ciphertextAndTag: tampered, key: .hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"), nonce: .hex("070000004041424344454647"), authenticatedData: .hex("50515253c0c1c2c3c4c5c6c7"))
        }
    }

    @Test func curve25519MatchesKnownAnswerVectors() throws {
        let edPrivate = Data.hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        let edPublic = try ObstacleBridgeCrypto.ed25519PublicKey(privateKey: edPrivate)
        #expect(edPublic.hex == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        let signature = try ObstacleBridgeCrypto.ed25519Sign(message: Data(), privateKey: edPrivate)
        #expect(signature.hex == "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\n5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b".replacingOccurrences(of: "\n", with: ""))
        #expect(try ObstacleBridgeCrypto.ed25519Verify(signature: signature, message: Data(), publicKey: edPublic))

        let alicePrivate = Data.hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let bobPrivate = Data.hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        let shared = try ObstacleBridgeCrypto.x25519SharedSecret(privateKey: alicePrivate, peerPublicKey: try ObstacleBridgeCrypto.x25519PublicKey(privateKey: bobPrivate))
        #expect(shared.hex == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    }

    @Test func secureLinkPskTranscriptMatchesPythonVector() throws {
        let psk = Data(0..<32)
        let clientNonce = Data(0x20..<0x40)
        let serverNonce = Data(0x40..<0x60)
        let sessionID: UInt64 = 0x0102_0304_0506_0708
        let keys = try ObstacleBridgeSecureLinkPSKCrypto.deriveKeys(psk: psk, sessionID: sessionID, clientNonce: clientNonce, serverNonce: serverNonce)
        #expect(keys.clientToServer.hex == "585889eaa8cfcdb9ffc033d5959a54a086e823a3c7e491fe451d94ba824d1361")
        #expect(keys.serverToClient.hex == "026e7f54ab86773658da9ded1bfecd6216d5a3275c7b658adb290b80a8973570")
        #expect(try ObstacleBridgeSecureLinkPSKCrypto.serverProof(psk: psk, sessionID: sessionID, clientNonce: clientNonce, serverNonce: serverNonce).hex == "ad55f84b7533f9b4358694fd88069ab9de2d53708fd66471e83d82db2b4a9e60")
        #expect(try ObstacleBridgeSecureLinkPSKCrypto.clientRekeyCommitProof(psk: psk, sessionID: sessionID, clientNonce: clientNonce, serverNonce: serverNonce).hex == "ad06b7c23e7cd546b0b700ed1dc4dbb3a655f14ca3df8d580e98cd398b196991")
    }

    @Test func invalidSizesAreRejectedBeforeCryptoOperations() throws {
        #expect(throws: ObstacleBridgeCryptoError.invalidKeyLength(expected: 32, actual: 31)) {
            try ObstacleBridgeCrypto.aesGCMSeal(plaintext: Data(), key: Data(repeating: 0, count: 31), nonce: Data(repeating: 0, count: 12))
        }
        #expect(throws: ObstacleBridgeCryptoError.invalidNonceLength(expected: 12, actual: 11)) {
            try ObstacleBridgeCrypto.chaChaPolySeal(plaintext: Data(), key: Data(repeating: 0, count: 32), nonce: Data(repeating: 0, count: 11))
        }
    }
}

private extension Data {
    static func hex(_ value: String) -> Data {
        Data(stride(from: 0, to: value.count, by: 2).map {
            UInt8(value[value.index(value.startIndex, offsetBy: $0)...value.index(value.startIndex, offsetBy: $0 + 1)], radix: 16)!
        })
    }

    var hex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
