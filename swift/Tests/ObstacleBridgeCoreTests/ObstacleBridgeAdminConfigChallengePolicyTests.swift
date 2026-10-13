import Foundation
import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgeAdminConfigChallengePolicyTests {
    private func digest(_ data: Data) -> String { data.base64EncodedString() }

    @Test func acceptsCanonicalUpdatesAndRejectsChangedPayload() throws {
        let updates: [String: Any] = ["port": 443, "enabled": true]
        let challenge = try ObstacleBridgeAdminConfigChallengePolicy.issue(
            identifier: "challenge-1",
            seed: "seed-1",
            updates: updates,
            now: 10,
            ttl: 60,
            digest: digest
        )
        let proof = digest(Data("seed-1:alice:secret:\(challenge.updatesDigest)".utf8))

        #expect(try ObstacleBridgeAdminConfigChallengePolicy.validate(
            challenge,
            proof: proof,
            updates: ["enabled": true, "port": 443],
            username: "alice",
            password: "secret",
            now: 20,
            digest: digest
        ) == .valid)
        #expect(try ObstacleBridgeAdminConfigChallengePolicy.validate(
            challenge,
            proof: proof,
            updates: ["port": 444, "enabled": true],
            username: "alice",
            password: "secret",
            now: 20,
            digest: digest
        ) == .updatesMismatch)
    }
}
