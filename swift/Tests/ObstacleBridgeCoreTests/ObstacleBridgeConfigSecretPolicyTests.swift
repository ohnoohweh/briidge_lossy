import Foundation
import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgeConfigSecretPolicyTests {
    @Test func transformsOnlyNamedSecretFieldsRecursively() throws {
        let payload: [String: Any] = [
            "admin_web_password": "admin-secret",
            "empty": "",
            "nested": [
                "secure_link_psk": "peer-secret",
                "ordinary": "unchanged",
            ],
            "list": [["secure_link_psk": "list-secret"]],
        ]

        let encrypted = try ObstacleBridgeConfigSecretPolicy.encryptPayload(payload) { "sealed<\($0)>" }
        #expect(encrypted["admin_web_password"] as? String == "sealed<admin-secret>")
        #expect(encrypted["empty"] as? String == "")
        let nested = try #require(encrypted["nested"] as? [String: Any])
        #expect(nested["secure_link_psk"] as? String == "sealed<peer-secret>")
        #expect(nested["ordinary"] as? String == "unchanged")
        let list = try #require(encrypted["list"] as? [[String: Any]])
        #expect(list[0]["secure_link_psk"] as? String == "sealed<list-secret>")

        let decrypted = try ObstacleBridgeConfigSecretPolicy.decryptPayload(encrypted) {
            String($0.dropFirst("sealed<".count).dropLast())
        }
        #expect(decrypted["admin_web_password"] as? String == "admin-secret")
        let restoredNested = try #require(decrypted["nested"] as? [String: Any])
        #expect(restoredNested["secure_link_psk"] as? String == "peer-secret")
    }

    @Test func normalizesURLSafeBase64() throws {
        let value = Data([0xfb, 0xff, 0xef])
        let encoded = ObstacleBridgeConfigSecretPolicy.urlSafeBase64Encode(value)
        #expect(encoded == "-__v")
        #expect(try ObstacleBridgeConfigSecretPolicy.urlSafeBase64Decode(encoded) == value)
    }
}
