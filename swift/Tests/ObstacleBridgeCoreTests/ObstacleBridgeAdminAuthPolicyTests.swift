import Foundation
import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgeAdminAuthPolicyTests {
    private func digest(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    @Test func challengeIsSingleUseAndSessionUsesParsedCookie() {
        var state = ObstacleBridgeAdminAuthPolicy.State()
        let challenge = state.issueChallenge(identifier: "challenge", seed: "seed", now: 10, ttl: 30)
        let proof = digest(Data("seed:alice:secret".utf8))

        #expect(state.consumeChallenge(
            identifier: challenge.identifier,
            proof: proof,
            username: "alice",
            password: "secret",
            now: 20,
            digest: digest
        ) == .authenticated)
        #expect(state.consumeChallenge(
            identifier: challenge.identifier,
            proof: proof,
            username: "alice",
            password: "secret",
            now: 20,
            digest: digest
        ) == .invalidOrExpiredChallenge)

        let cookieName = ObstacleBridgeAdminAuthPolicy.sessionCookieName(scope: "scope", digest: digest)
        state.issueSession(token: "token", now: 20, ttl: 60)
        let authenticated = state.isAuthenticated(headers: ["cookie": "unused=x; \(cookieName)=token"], cookieName: cookieName, now: 30)
        #expect(authenticated)
        state.revokeSession(headers: ["cookie": "\(cookieName)=token"], cookieName: cookieName)
        let revoked = state.isAuthenticated(headers: ["cookie": "\(cookieName)=token"], cookieName: cookieName, now: 30)
        #expect(!revoked)
    }
}
