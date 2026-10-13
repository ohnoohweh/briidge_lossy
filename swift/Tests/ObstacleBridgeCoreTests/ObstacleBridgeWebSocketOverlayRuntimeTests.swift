import Foundation
import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgeWebSocketOverlayRuntimeTests {
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
