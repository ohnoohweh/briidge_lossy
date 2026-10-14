import Foundation

/// Portable admission for live Admin topics. Resource owners supply already
/// redacted snapshots; Core decides which topic names are supported and their
/// stable payload envelopes.
public enum ObstacleBridgeAdminLiveTopicPort {
    public static func payload(topic: String, status: [String: Any], peers: [[String: Any]]) -> Any? {
        switch topic {
        case "status": return status
        case "peers": return ["peers": peers]
        default: return nil
        }
    }
}
