import Foundation
import Testing
@testable import ObstacleBridgeLinuxAdapters
@testable import ObstacleBridgeCore

struct ObstacleBridgeLinuxTunHelperAdapterTests {
    @Test func unavailableEndpointFailsClosedWithoutPrivilegedFallback() throws {
        let adapter = try ObstacleBridgeLinuxTunHelperAdapter(
            socketPath: "/tmp/obstaclebridge-no-helper-\(UUID().uuidString).sock",
            timeoutMilliseconds: 50
        )
        #expect(throws: (any Error).self) {
            try adapter.send(command: .snapshot, payload: [:])
        }
    }

    @Test func rejectsMissingEndpointAndInvalidTimeoutBeforeAnyTransportAttempt() {
        #expect(throws: (any Error).self) {
            _ = try ObstacleBridgeLinuxTunHelperAdapter(socketPath: "")
        }
        #expect(throws: (any Error).self) {
            _ = try ObstacleBridgeLinuxTunHelperAdapter(socketPath: "/tmp/helper.sock", timeoutMilliseconds: 0)
        }
    }
}
