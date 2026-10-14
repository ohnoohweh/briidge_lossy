import Foundation

/// Portable Admin live-topic admission and polling policy.
enum ObstacleBridgeWebAdminLiveTopicPolicy {
    static let allTopics = ["status", "connections", "peers", "tun_routing", "meta"]

    static func interval(_ topic: String) -> TimeInterval {
        topic == "meta" ? 5.0 : 1.0
    }

    static func topicsForControlMessage(subscribe: Any?, activeTabs: [Any]?, currentTopics: Set<String>? = nil) -> Set<String> {
        var topics = currentTopics ?? Set(allTopics)
        let requested = parseTopics(subscribe)
        if !requested.isEmpty { topics = requested }
        if let activeTabs, !activeTabs.isEmpty {
            var next: Set<String> = ["status"]
            let tabs = Set(activeTabs.compactMap {
                let text = String(describing: $0).trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                return text.isEmpty ? nil : text
            })
            if tabs.contains("status") { next.formUnion(["connections", "peers"]) }
            if tabs.contains("tun-routing") { next.insert("tun_routing") }
            if tabs.contains("misc") { next.insert("meta") }
            topics = next
        }
        return topics
    }

    static func parseTopics(_ value: Any?) -> Set<String> {
        if let value = value as? String {
            let topic = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            return allTopics.contains(topic) ? [topic] : []
        }
        guard let sequence = value as? [Any] else { return [] }
        return Set(sequence.compactMap {
            let topic = String(describing: $0).trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            return allTopics.contains(topic) ? topic : nil
        })
    }
}

/// Public adapter port for validated Admin live-topic names. Platform owners
/// retain their HTTP/WebSocket mechanics while Core owns topic normalization.
public enum ObstacleBridgeAdminLiveTopicPolicyPort {
    public static func normalizedTopic(_ value: String) -> String? {
        ObstacleBridgeWebAdminLiveTopicPolicy.parseTopics(value).first
    }
}
