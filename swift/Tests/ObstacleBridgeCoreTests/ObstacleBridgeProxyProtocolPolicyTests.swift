import Foundation
import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgeProxyProtocolPolicyTests {
    @Test func parsesAndRewritesAbsoluteHTTPRequest() throws {
        let raw = Data("GET http://example.test:8080/path?q=1 HTTP/1.1\r\nHost: example.test\r\nProxy-Authorization: Basic ignored\r\n\r\n".utf8)
        let request = try #require(ObstacleBridgeProxyProtocolCodec.parseHTTPRequestHead(raw))
        let authority = ObstacleBridgeProxyProtocolCodec.parseAuthority("example.test:8080", defaultPort: 443)
        #expect(authority?.host == "example.test")
        #expect(authority?.port == 8080)
        let rewritten = try #require(String(data: ObstacleBridgeProxyProtocolCodec.rewriteHTTPRequestForOriginServer(request), encoding: .utf8))
        #expect(rewritten.hasPrefix("GET /path?q=1 HTTP/1.1\r\n"))
        #expect(!rewritten.lowercased().contains("proxy-authorization"))
    }

    @Test func validatesBasicCredentialsAndParsesSocks5Domain() throws {
        let credentials = ObstacleBridgeProxyCredentials(username: "user", password: "pass")
        #expect(ObstacleBridgeProxyProtocolCodec.authorized(
            headers: ["proxy-authorization": ObstacleBridgeProxyProtocolCodec.basicAuthorizationHeader(username: "user", password: "pass")],
            credentials: credentials
        ))
        let request = Data([0x05, 0x01, 0x00, 0x03, 0x04, 0x74, 0x65, 0x73, 0x74, 0x01, 0xbb])
        let parsed = try #require(ObstacleBridgeProxyProtocolCodec.parseSOCKS5ConnectRequest(request))
        #expect(parsed.host == "test")
        #expect(parsed.port == 443)
    }
}
