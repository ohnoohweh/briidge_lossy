import Foundation

/// Build metadata available to ordinary SwiftPM builds, including CI test
/// discovery. Packaged Linux builds publish their exact identity in the
/// adjacent `ObstacleBridgeLinux.build-info.json` artifact.
enum ObstacleBridgeLinuxBuildInfo {
    static func json() -> String {
        let value: [String: Any] = [
            "artifact": "ObstacleBridgeLinux",
            "available": false,
            "source": "swift-package",
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) else { return "{}" }
        return String(decoding: data, as: UTF8.self)
    }
}
