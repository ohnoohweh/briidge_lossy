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

    @Test func adminWebConfigurationUsesConfiguredPortUnlessOperatorOverridesIt() {
        let raw: [String: Any] = ["admin_web": ["admin_web_bind": "127.0.0.1", "admin_web_port": 18080, "admin_web_dir": "/srv/obstaclebridge/admin_web"]]
        #expect(ObstacleBridgeLinuxAdminWebConfiguration(rawConfiguration: raw) == .init(rawConfiguration: raw))
        #expect(ObstacleBridgeLinuxAdminWebConfiguration(rawConfiguration: raw).port == 18080)
        #expect(ObstacleBridgeLinuxAdminWebConfiguration(rawConfiguration: raw, portOverride: 19090).port == 19090)
    }
}
