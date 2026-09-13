import Foundation
import Testing
@testable import ObstacleBridgeCore

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
    @Test func myudpControlFrameRoundTripsAndRejectsTrailingBytes() throws {
        let wire = try ObstacleBridgeMyUDPCodec.encodeControl(lastInOrder: 4, highestReceived: 7, missing: [5, 6], transmittedNanoseconds: 8, echoedNanoseconds: 9)
        #expect(try ObstacleBridgeMyUDPCodec.decodeControl(wire) == .init(lastInOrder: 4, highestReceived: 7, missing: [5, 6], transmittedNanoseconds: 8, echoedNanoseconds: 9))
        #expect(throws: ObstacleBridgeMyUDPCodecError.invalidFrame) { try ObstacleBridgeMyUDPCodec.decodeControl(wire + Data([0])) }
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

    @Test func secureLinkPskServerCompletesPortableClientHandshake() throws {
        let psk = Data("linux-server-psk".utf8)
        let sessionID: UInt64 = 0x0102_0304_0506_0708
        let clientNonce = Data(0..<32)
        let serverNonce = Data(0x20..<0x40)
        let client = try ObstacleBridgeSecureLinkPSKClient(psk: psk)
        let server = try ObstacleBridgeSecureLinkPSKServer(psk: psk)
        let proof = try client.handleServerHello(server.handleClientHello(try client.begin(sessionID: sessionID, clientNonce: clientNonce), serverNonce: serverNonce))
        try client.handleServerAcknowledgement(server.handleClientProof(proof))
        #expect(client.isAuthenticated && server.isAuthenticated)
        #expect(try server.unprotect(client.protect(Data("python-client".utf8))) == Data("python-client".utf8))
        #expect(try client.unprotect(server.protect(Data("linux-server".utf8))) == Data("linux-server".utf8))
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

struct ObstacleBridgeCorePortTests {
    @Test func channelMuxReplyPolicyAdmitsOneAwaitedFrame() throws {
        let policy = ObstacleBridgeChannelMuxReplyPolicy()
        let frame = ObstacleBridgeChannelMuxFrame(channelID: 3, protocolType: .tcp, counter: 4, messageType: .data, body: Data())
        #expect(try !policy.beginExchange(frame))
        #expect(throws: ObstacleBridgeChannelMuxReplyPolicyError.tooManyInFlightFrames) { try policy.beginExchange(frame) }
        policy.finishExchange(); policy.activateReceiveOwner()
        #expect(try policy.beginExchange(frame))
        #expect(policy.matchesAwaitedReply(frame))
        #expect(!policy.matchesAwaitedReply(.init(channelID: 4, protocolType: .tcp, counter: 4, messageType: .data, body: Data())))
        policy.finishExchange()
    }

    @Test func corePortsUseOnlyValueTypesAtTheAdapterBoundary() throws {
        let endpoint = ObstacleBridgeEndpoint(host: "192.0.2.10", port: 443)
        #expect(endpoint == ObstacleBridgeEndpoint(host: "192.0.2.10", port: 443))
        #expect(ObstacleBridgeIPAddress("2001:db8::10").text == "2001:db8::10")
        #expect(
            ObstacleBridgeCoreEvent.transportConnected(epoch: 4, endpoint: endpoint)
                == .transportConnected(epoch: 4, endpoint: endpoint)
        )

        let resolver = StaticResolver()
        #expect(try resolver.resolve("bridge.example", port: 443) == [endpoint])
        #expect(FixedClock().nowNanoseconds() == 42)
    }

    private struct FixedClock: ObstacleBridgeClock {
        func nowNanoseconds() -> UInt64 { 42 }
    }

    private struct StaticResolver: ObstacleBridgeResolver {
        func resolve(_ host: String, port: UInt16) throws -> [ObstacleBridgeEndpoint] {
            [ObstacleBridgeEndpoint(host: "192.0.2.10", port: port)]
        }
    }
}

struct ObstacleBridgeCoreCodecTests {
    @Test func boundedBinaryCodecAndServiceWireFormatsRoundTrip() throws {
        var writer = ObstacleBridgeBinaryWriter()
        writer.append(UInt8(7)); writer.append(UInt16(0x0102)); writer.append(UInt32(0x0304_0506)); writer.append(UInt64(0x0708_090a_0b0c_0d0e))
        var reader = ObstacleBridgeBinaryReader(writer.encoded)
        #expect(try reader.readUInt8() == 7)
        #expect(try reader.readUInt16() == 0x0102)
        #expect(try reader.readUInt32() == 0x0304_0506)
        #expect(try reader.readUInt64() == 0x0708_090a_0b0c_0d0e)
        #expect(reader.isAtEnd)
        #expect(throws: ObstacleBridgeBinaryCodecError.truncated) { try reader.readUInt8() }

        let service = ObstacleBridgeServiceSpec(serviceID: 7, name: "echo", listenProtocol: .tcp, listenHost: "127.0.0.1", listenPort: 7001, targetProtocol: .tcp, targetHost: "127.0.0.1", targetPort: 7002)
        let open = try ObstacleBridgeServiceCodec.encodeOpen(instanceID: 9, connectionSequence: 4, service: service)
        #expect(open.starts(with: Data("O5".utf8)))
        #expect(try ObstacleBridgeServiceCodec.decodeOpen(open) == .init(instanceID: 9, connectionSequence: 4, service: service))

        var legacyOpen = ObstacleBridgeBinaryWriter()
        legacyOpen.appendUTF8("O4"); legacyOpen.append(UInt64(9)); legacyOpen.append(UInt32(4)); legacyOpen.append(UInt16(7)); legacyOpen.append(ObstacleBridgeChannelMuxProtocol.tcp.rawValue); legacyOpen.append(UInt8(9)); legacyOpen.appendUTF8("127.0.0.1"); legacyOpen.append(UInt16(7001)); legacyOpen.append(ObstacleBridgeChannelMuxProtocol.tcp.rawValue); legacyOpen.append(UInt8(9)); legacyOpen.appendUTF8("127.0.0.1"); legacyOpen.append(UInt16(7002))
        #expect(try ObstacleBridgeServiceCodec.decodeOpen(legacyOpen.encoded).service == serviceWithoutMetadata(service))

        let catalog = try ObstacleBridgeServiceCodec.encodeRemoteServices(instanceID: 9, connectionSequence: 4, services: [service])
        #expect(catalog.starts(with: Data("RS3".utf8)))
        #expect(String(decoding: catalog.dropFirst(19), as: UTF8.self) == "[{\"svc_id\":7,\"l_proto\":\"tcp\",\"l_bind\":\"127.0.0.1\",\"l_port\":7001,\"r_proto\":\"tcp\",\"r_host\":\"127.0.0.1\",\"r_port\":7002,\"name\":\"echo\",\"lifecycle_hooks\":null,\"options\":null}]")
        let decoded = try ObstacleBridgeServiceCodec.decodeRemoteServices(catalog)
        #expect(decoded.instanceID == 9 && decoded.connectionSequence == 4 && decoded.services == [service])
        #expect(throws: ObstacleBridgeServiceCodecError.invalidPayload) { try ObstacleBridgeServiceCodec.decodeOpen(Data("O5".utf8)) }
    }

    @Test func controlChunksMatchPythonLayoutAndRemainBounded() throws {
        let payload = Data(0..<25)
        let chunks = try ObstacleBridgeControlChunkCodec.chunk(transactionID: 9, maximumApplicationPayload: 32, payload: payload)
        #expect(chunks.count == 3)
        #expect(chunks[0].hex == "434b56310000000900000003000102030405060708090a0b")
        #expect(chunks[2].hex == "434b5631000000090002000318")
        #expect(ObstacleBridgeControlChunkCodec.nextTransactionID(current: 0).transactionID == 1)
        #expect(ObstacleBridgeControlChunkCodec.nextTransactionID(current: .max).next == 1)
        #expect(throws: ObstacleBridgeControlChunkCodecError.invalidMaximumPayload) {
            try ObstacleBridgeControlChunkCodec.chunk(transactionID: 1, maximumApplicationPayload: 20, payload: Data())
        }

        let reassembler = ObstacleBridgeControlChunkReassembler(maximumInflight: 1, maximumReassembledBytes: 25, ttl: 1)
        #expect(reassembler.consume(channelID: 2, protocolType: .tcp, messageType: .openChunk, payload: chunks[1], peerID: 3, now: 10) == nil)
        #expect(reassembler.consume(channelID: 2, protocolType: .tcp, messageType: .openChunk, payload: chunks[1], peerID: 3, now: 11) == nil)
        #expect(reassembler.consume(channelID: 2, protocolType: .tcp, messageType: .openChunk, payload: chunks[0], peerID: 3, now: 11) == nil)
        #expect(reassembler.consume(channelID: 2, protocolType: .tcp, messageType: .openChunk, payload: chunks[2], peerID: 3, now: 11) == payload)
        #expect(reassembler.consume(channelID: 2, protocolType: .tcp, messageType: .openChunk, payload: Data("CKV1".utf8), peerID: 3, now: 12) == nil)

        let expired = ObstacleBridgeControlChunkReassembler(ttl: 1)
        #expect(expired.consume(channelID: 2, protocolType: .tcp, messageType: .openChunk, payload: chunks[0], peerID: 3, now: 10) == nil)
        expired.prune(now: 11)
        #expect(expired.consume(channelID: 2, protocolType: .tcp, messageType: .openChunk, payload: chunks[1], peerID: 3, now: 11) == nil)
    }

    @Test func overlayAppPingPongFramesMatchPythonLayout() throws {
        let application = ObstacleBridgeOverlayFrame(kind: .application, payload: Data("hello".utf8))
        let wire = try ObstacleBridgeOverlayFrameCodec.encodeTCP(application)
        #expect(wire.hex == "000000060068656c6c6f")
        #expect(try ObstacleBridgeOverlayFrameCodec.decodeTCP(wire) == application)
        let ping = ObstacleBridgeOverlayFrame(kind: .ping, payload: Data.hex("01020304050607080000000000000000"))
        #expect(try ObstacleBridgeOverlayFrameCodec.pong(forPing: ping) == .init(kind: .pong, payload: Data.hex("0102030405060708")))
        #expect(throws: ObstacleBridgeOverlayFrameCodecError.invalidFrame) {
            try ObstacleBridgeOverlayFrameCodec.decodeTCP(Data.hex("0000000101"))
        }
        #expect(throws: ObstacleBridgeOverlayFrameCodecError.invalidFrame) {
            try ObstacleBridgeOverlayFrameCodec.decodeTCP(wire + Data([0]))
        }
    }

    @Test func webSocketTextPayloadModesRoundTripInCore() throws {
        let wire = Data([0, 1, 2, 0xff])
        for mode in [ObstacleBridgeWebSocketPayloadMode.base64, .jsonBase64, .semiTextShape] {
            let payload = try ObstacleBridgeWebSocketPayloadCodec.encode(wire, mode: mode)
            #expect(try ObstacleBridgeWebSocketPayloadCodec.decode(payload, mode: mode) == wire)
        }
        #expect(throws: ObstacleBridgeWebSocketPayloadCodecError.invalidPayload) {
            try ObstacleBridgeWebSocketPayloadCodec.decode(.text("!"), mode: .semiTextShape)
        }
    }

    @Test func sharedPythonWireCorpusAcceptsCoreAndRejectsMalformedRecords() throws {
        let url = try #require(Bundle.module.url(forResource: "python_wire_codec_corpus", withExtension: "json"))
        let corpus = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        let tcp = try #require(corpus["tcp_application"] as? [String: Any])
        let payload = Data.hex(try #require(tcp["payload_hex"] as? String))
        let wire = Data.hex(try #require(tcp["wire_hex"] as? String))
        #expect(try ObstacleBridgeOverlayFrameCodec.encodeTCP(.init(kind: .application, payload: payload)) == wire)
        for value in try #require(tcp["malformed_wire_hex"] as? [String]) {
            #expect(throws: ObstacleBridgeOverlayFrameCodecError.invalidFrame) { try ObstacleBridgeOverlayFrameCodec.decodeTCP(.hex(value)) }
        }
        let myudp = try #require(corpus["myudp_data"] as? [String: Any])
        let myudpPayload = Data.hex(try #require(myudp["payload_hex"] as? String))
        let myudpWire = Data.hex(try #require(myudp["wire_hex"] as? String))
        #expect(try ObstacleBridgeMyUDPCodec.encodeData(
            payload: myudpPayload,
            counter: UInt16(try #require(myudp["counter"] as? Int)),
            transmittedNanoseconds: UInt64(try #require(myudp["transmitted_nanoseconds"] as? Int)),
            echoedNanoseconds: UInt64(try #require(myudp["echoed_nanoseconds"] as? Int))
        ) == myudpWire)
        #expect(try ObstacleBridgeMyUDPCodec.decodeData(myudpWire) == .init(
            counter: UInt16(try #require(myudp["counter"] as? Int)),
            payload: myudpPayload,
            transmittedNanoseconds: UInt64(try #require(myudp["transmitted_nanoseconds"] as? Int)),
            echoedNanoseconds: UInt64(try #require(myudp["echoed_nanoseconds"] as? Int))
        ))
        for value in try #require(myudp["malformed_wire_hex"] as? [String]) {
            #expect(throws: ObstacleBridgeMyUDPCodecError.invalidFrame) { try ObstacleBridgeMyUDPCodec.decodeData(.hex(value)) }
        }
        let control = try #require(corpus["myudp_control"] as? [String: Any])
        let controlWire = Data.hex(try #require(control["wire_hex"] as? String))
        #expect(try ObstacleBridgeMyUDPCodec.decodeControl(controlWire) == .init(lastInOrder: 4, highestReceived: 7, missing: [5, 6], transmittedNanoseconds: 8, echoedNanoseconds: 9))
        for value in try #require(control["malformed_wire_hex"] as? [String]) {
            #expect(throws: ObstacleBridgeMyUDPCodecError.invalidFrame) { try ObstacleBridgeMyUDPCodec.decodeControl(.hex(value)) }
        }
        let websocket = try #require(corpus["websocket_binary"] as? [String: Any])
        let websocketPayload = Data.hex(try #require(websocket["payload_hex"] as? String))
        let websocketWire = Data.hex(try #require(websocket["wire_hex"] as? String))
        #expect(try ObstacleBridgeOverlayFrameCodec.encodeBody(.init(kind: .application, payload: websocketPayload)) == websocketWire)
        #expect(try ObstacleBridgeOverlayFrameCodec.decodeBody(websocketWire) == .init(kind: .application, payload: websocketPayload))
        for value in try #require(websocket["malformed_wire_hex"] as? [String]) {
            #expect(throws: ObstacleBridgeOverlayFrameCodecError.invalidFrame) { try ObstacleBridgeOverlayFrameCodec.decodeBody(.hex(value)) }
        }
        let secureLink = try #require(corpus["securelink_psk"] as? [String: Any])
        let psk = Data.hex(try #require(secureLink["psk_hex"] as? String))
        let clientNonce = Data.hex(try #require(secureLink["client_nonce_hex"] as? String))
        let serverNonce = Data.hex(try #require(secureLink["server_nonce_hex"] as? String))
        let sessionID = UInt64(try #require(secureLink["session_id"] as? Int))
        let expectedClientToServer = try #require(secureLink["client_to_server_key_hex"] as? String)
        let expectedServerToClient = try #require(secureLink["server_to_client_key_hex"] as? String)
        let expectedServerProof = try #require(secureLink["server_proof_hex"] as? String)
        let expectedRekeyCommitProof = try #require(secureLink["client_rekey_commit_proof_hex"] as? String)
        let keys = try ObstacleBridgeSecureLinkPSKCrypto.deriveKeys(psk: psk, sessionID: sessionID, clientNonce: clientNonce, serverNonce: serverNonce)
        #expect(keys.clientToServer.hex == expectedClientToServer)
        #expect(keys.serverToClient.hex == expectedServerToClient)
        #expect(try ObstacleBridgeSecureLinkPSKCrypto.serverProof(psk: psk, sessionID: sessionID, clientNonce: clientNonce, serverNonce: serverNonce).hex == expectedServerProof)
        #expect(try ObstacleBridgeSecureLinkPSKCrypto.clientRekeyCommitProof(psk: psk, sessionID: sessionID, clientNonce: clientNonce, serverNonce: serverNonce).hex == expectedRekeyCommitProof)
        let expectedClientHello = Data.hex(try #require(secureLink["client_hello_hex"] as? String))
        let expectedServerHello = Data.hex(try #require(secureLink["server_hello_hex"] as? String))
        let client = try ObstacleBridgeSecureLinkPSKClient(psk: psk)
        #expect(try client.begin(sessionID: sessionID, clientNonce: clientNonce) == expectedClientHello)
        let server = try ObstacleBridgeSecureLinkPSKServer(psk: psk)
        #expect(try server.handleClientHello(expectedClientHello, serverNonce: serverNonce) == expectedServerHello)
        for value in try #require(secureLink["malformed_envelope_hex"] as? [String]) {
            #expect(throws: ObstacleBridgeSecureLinkPSKClientError.invalidFrame) { try server.handleClientHello(.hex(value), serverNonce: serverNonce) }
            #expect(throws: ObstacleBridgeSecureLinkPSKClientError.invalidFrame) { try client.handleServerHello(.hex(value)) }
        }
        let chunk = try #require(corpus["control_chunk"] as? [String: Any])
        let transactionID = try #require(chunk["transaction_id"] as? Int)
        let maximumPayload = try #require(chunk["maximum_application_payload"] as? Int)
        let chunkPayload = Data.hex(try #require(chunk["payload_hex"] as? String))
        let expectedChunks = try #require(chunk["chunks_hex"] as? [String])
        let chunks = try ObstacleBridgeControlChunkCodec.chunk(transactionID: UInt32(transactionID), maximumApplicationPayload: maximumPayload, payload: chunkPayload)
        #expect(chunks.map(\.hex) == expectedChunks)
        let serviceRecord = try #require(corpus["service_records"] as? [String: Any])
        let service = ObstacleBridgeServiceSpec(serviceID: 7, name: "echo", listenProtocol: .tcp, listenHost: "127.0.0.1", listenPort: 7001, targetProtocol: .tcp, targetHost: "127.0.0.1", targetPort: 7002)
        let o4 = Data.hex(try #require(serviceRecord["open_o4_hex"] as? String))
        let o5 = Data.hex(try #require(serviceRecord["open_o5_hex"] as? String))
        let rs3 = Data.hex(try #require(serviceRecord["rs3_hex"] as? String))
        #expect(try ObstacleBridgeServiceCodec.decodeOpen(o4) == .init(instanceID: 9, connectionSequence: 4, service: serviceWithoutMetadata(service)))
        #expect(try ObstacleBridgeServiceCodec.encodeOpen(instanceID: 9, connectionSequence: 4, service: service) == o5)
        let rs2 = Data.hex(try #require(serviceRecord["rs2_hex"] as? String))
        #expect(try ObstacleBridgeServiceCodec.decodeRemoteServices(rs2).services == [serviceWithoutMetadata(service)])
        #expect(try ObstacleBridgeServiceCodec.encodeRemoteServices(instanceID: 9, connectionSequence: 4, services: [service]) == rs3)
        let trailing = Data.hex(try #require(serviceRecord["trailing_hex"] as? String))
        #expect(throws: ObstacleBridgeServiceCodecError.invalidPayload) { try ObstacleBridgeServiceCodec.decodeOpen(o4 + trailing) }
        #expect(throws: ObstacleBridgeServiceCodecError.invalidPayload) { try ObstacleBridgeServiceCodec.decodeRemoteServices(rs3 + trailing) }
        for bytes in try #require(serviceRecord["truncated_bytes"] as? [Int]) {
            #expect(throws: ObstacleBridgeServiceCodecError.invalidPayload) { try ObstacleBridgeServiceCodec.decodeOpen(Data(o4.dropLast(bytes))) }
            #expect(throws: ObstacleBridgeServiceCodecError.invalidPayload) { try ObstacleBridgeServiceCodec.decodeOpen(Data(o5.dropLast(bytes))) }
            #expect(throws: ObstacleBridgeServiceCodecError.invalidPayload) { try ObstacleBridgeServiceCodec.decodeRemoteServices(Data(rs2.dropLast(bytes))) }
            #expect(throws: ObstacleBridgeServiceCodecError.invalidPayload) { try ObstacleBridgeServiceCodec.decodeRemoteServices(Data(rs3.dropLast(bytes))) }
        }
    }

    private func serviceWithoutMetadata(_ service: ObstacleBridgeServiceSpec) -> ObstacleBridgeServiceSpec {
        .init(serviceID: service.serviceID, name: nil, listenProtocol: service.listenProtocol, listenHost: service.listenHost, listenPort: service.listenPort, targetProtocol: service.targetProtocol, targetHost: service.targetHost, targetPort: service.targetPort)
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
