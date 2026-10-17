import Testing
@testable import ObstacleBridgeLinuxAdapters

struct ObstacleBridgeLinuxForegroundOptionsTests {
    @Test func defaultsToPythonConfigurationName() {
        #expect(ObstacleBridgeLinuxForegroundOptions.parse([]) == .init(configurationPath: "ObstacleBridge.cfg"))
    }

    @Test func configStartsForegroundWithoutRunVerb() {
        #expect(
            ObstacleBridgeLinuxForegroundOptions.parse(["--config", "client.json", "--admin-port", "13081", "--hold-sec", "5"])
                == .init(configurationPath: "client.json", adminPort: 13081, holdSeconds: 5)
        )
    }

    @Test func retainsExplicitRuntimeCompatibilityAndRejectsMalformedOptions() {
        #expect(ObstacleBridgeLinuxForegroundOptions.parse(["--runtime-config", "client.json", "--run"]) == .init(configurationPath: "client.json"))
        #expect(ObstacleBridgeLinuxForegroundOptions.parse(["--config", "", "--admin-port", "1"]) == nil)
        #expect(ObstacleBridgeLinuxForegroundOptions.parse(["--config", "client.json", "--hold-sec", "-1"]) == nil)
    }
}
