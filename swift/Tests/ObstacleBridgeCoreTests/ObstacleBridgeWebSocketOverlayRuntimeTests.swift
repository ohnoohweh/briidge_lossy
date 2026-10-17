import Foundation
import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgeWebSocketOverlayRuntimeTests {
    @Test func overlayLayerReadinessRequiresEveryConfiguredLayer() {
        #expect(!ObstacleBridgeOverlayLayerTransportAdapter.applicationReady(
            transportConnected: true,
            secureLinkRequired: true,
            secureLinkAuthenticated: false,
            compressionHealthy: true
        ))
        #expect(ObstacleBridgeOverlayLayerTransportAdapter.applicationReady(
            transportConnected: true,
            secureLinkRequired: true,
            secureLinkAuthenticated: true,
            compressionHealthy: true
        ))
    }

    @Test func secureLinkAdapterHonorsInjectedHandshakeMaterial() throws {
        let client = ObstacleBridgeSecureLinkPskTransportAdapter(clientPSK: "adapter-psk")
        let server = ObstacleBridgeSecureLinkPskRuntime(clientMode: false, psk: "adapter-psk")
        let nonce = Data(repeating: 7, count: 32)

        let hello = try client.handleTransportConnected(sessionID: 91, clientNonce: nonce)
        #expect(hello.emittedFrames.count == 1)
        let serverHello = server.handleInboundFrame(hello.emittedFrames[0])
        let proof = client.handleInboundFrame(serverHello.emittedFrames[0])
        let acknowledgement = server.handleInboundFrame(proof.emittedFrames[0])
        _ = client.handleInboundFrame(acknowledgement.emittedFrames[0])

        #expect(client.protocolState?.authenticated == true)
        #expect(client.protocolState?.sessionID == 91)
    }

    @Test func nativeServiceSpecRetainsPortableScalarConfiguration() {
        let spec = ObstacleBridgeNativeServiceSpec(
            svcID: 7,
            name: "dns",
            listenProtocol: "udp",
            listenBind: "127.0.0.1",
            listenPort: 53,
            targetProtocol: "udp",
            targetHost: "1.1.1.1",
            targetPort: 53
        )

        #expect(spec.svcID == 7)
        #expect(spec.listenProtocol == "udp")
        #expect(spec.targetHost == "1.1.1.1")
    }

    @Test func udpPeerRuntimeEmitsAndDeliversPortableRecordEffects() throws {
        let sender = ObstacleBridgeUdpOverlayPeerRuntime()
        try sender.enqueueApplicationPayload(Data("udp-core".utf8), nowNS: 10)
        let outbound = try sender.flushSendQueue(nowNS: 10)
        #expect(outbound.frames.count == 1)

        let receiver = ObstacleBridgeUdpOverlayPeerRuntime()
        let inbound = try receiver.receiveWire(outbound.frames[0], nowNS: 20)
        #expect(inbound.deliveredPayloads == [Data("udp-core".utf8)])
    }

    @Test func quicRuntimeProducesThePortableApplicationEnvelope() throws {
        let runtime = ObstacleBridgeQuicOverlayRuntime()
        let effect = runtime.sendApp(
            payload: Data("quic-core".utf8),
            writerPresent: true,
            peerConfigured: true
        )

        #expect(effect.writtenBuffers.count == 1)
        #expect(try ObstacleBridgeOverlayEnvelope.decodeTCP(effect.writtenBuffers[0]) == .application(Data("quic-core".utf8)))
    }

    @Test func proxyConnectRequestPreservesIPv6AuthorityAndAuthorization() throws {
        let runtime = try ObstacleBridgeWebSocketOverlayRuntime(payloadMode: "binary")

        #expect(runtime.buildProxyConnectRequest(
            targetHost: "2001:db8::1",
            targetPort: 443,
            authHeader: "Basic dXNlcjpwYXNz"
        ) == "CONNECT [2001:db8::1]:443 HTTP/1.1\r\n"
            + "Host: [2001:db8::1]:443\r\n"
            + "Connection: keep-alive\r\n"
            + "Proxy-Connection: keep-alive\r\n"
            + "User-Agent: ObstacleBridge-ws-proxy/1.0\r\n"
            + "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n")
    }
}
