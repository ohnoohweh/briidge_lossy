import Foundation
import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgeRuntimeConfigPolicyTests {
    @Test func disablesMuxTCPReadAndSendTimeoutsByDefault() throws {
        let schema = ObstacleBridgeRuntimeConfigPort.schemaSnapshot()
        let channelMux = try #require(schema["channel_mux"] as? [[String: Any]])
        let defaults = Dictionary(uniqueKeysWithValues: channelMux.compactMap { row -> (String, Any)? in
            guard let key = row["key"] as? String else { return nil }
            return (key, row["default"] ?? NSNull())
        })

        #expect(defaults["mux_tcp_read_timeout_s"] as? Int == 0)
        #expect(defaults["mux_tcp_send_timeout_s"] as? Int == 0)
    }
}
