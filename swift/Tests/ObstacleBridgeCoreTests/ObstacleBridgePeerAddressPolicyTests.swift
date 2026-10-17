import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgePeerAddressPolicyTests {
    @Test func parsesConfiguredHostsAndNormalizesLiterals() {
        #expect(ObstacleBridgePeerAddressPolicy.splitConfiguredPeerHosts(" [2001:db8::1]; example.test, 203.0.113.1 ") == ["[2001:db8::1]", "example.test", "203.0.113.1"])
        #expect(ObstacleBridgePeerAddressPolicy.stripBrackets(" [2001:db8::1] ") == "2001:db8::1")
        #expect(ObstacleBridgePeerAddressPolicy.literalResolution(
            host: "203.0.113.1", family: .ipv4, mode: .ipv6, strictFamily: true
        ) == .resolve(host: "::ffff:203.0.113.1", family: .ipv6))
        #expect(ObstacleBridgePeerAddressPolicy.literalResolution(
            host: "2001:db8::1", family: .ipv6, mode: .ipv4, strictFamily: true
        ) == .incompatible(expected: .ipv4))
    }

    @Test func ordersAndFiltersCandidatesWithoutSocketTypes() {
        let candidates = [
            ObstacleBridgePeerAddressPolicy.Candidate(family: .ipv4, host: "203.0.113.2", port: 2),
            ObstacleBridgePeerAddressPolicy.Candidate(family: .ipv6, host: "2001:db8::2", port: 2),
            ObstacleBridgePeerAddressPolicy.Candidate(family: .ipv4, host: "203.0.113.1", port: 1),
        ]
        #expect(ObstacleBridgePeerAddressPolicy.orderedCandidateIndices(candidates, mode: .preferIPv6) == [1, 2, 0])
        #expect(ObstacleBridgePeerAddressPolicy.compatibleCandidateIndices(candidates, family: .ipv4) == [0, 2])
        #expect(ObstacleBridgePeerAddressPolicy.normalization(for: .ipv4, socketFamily: .ipv6) == .mapIPv4ToIPv6)
        #expect(ObstacleBridgePeerAddressPolicy.normalization(for: .ipv6, socketFamily: .ipv4) == .incompatible)
    }
}
