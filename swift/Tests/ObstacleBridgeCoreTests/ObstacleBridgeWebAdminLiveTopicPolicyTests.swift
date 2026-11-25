import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgeWebAdminLiveTopicPolicyTests {
    @Test func tabsRestrictTopicsAndUnknownSubscriptionsAreRejected() {
        #expect(ObstacleBridgeWebAdminLiveTopicPolicy.parseTopics(["peers", "unknown"]) == ["peers"])
        #expect(ObstacleBridgeWebAdminLiveTopicPolicy.topicsForControlMessage(
            subscribe: ["meta"], activeTabs: ["tun-routing", "misc"]
        ) == ["status", "tun_routing", "meta"])
        #expect(ObstacleBridgeWebAdminLiveTopicPolicy.interval("meta") == 5)
        #expect(ObstacleBridgeWebAdminLiveTopicPolicy.interval("peers") == 1)
    }

    @Test func connectionsTabRetainsConnectionUpdates() {
        #expect(ObstacleBridgeWebAdminLiveTopicPolicy.topicsForControlMessage(
            subscribe: ["status", "connections"], activeTabs: ["connections"]
        ) == ["status", "connections"])
    }
}
