import Dispatch
import Foundation
import Testing
@testable import ObstacleBridgeLinuxAdapters

struct ObstacleBridgeLinuxLiveRuntimeTests {
    @Test func liveRuntimeOwnsAuthenticatedSessionAndStops() throws {
        let peer = try PythonOverlayPeer(mode: "tcp-securelink")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxLiveRuntime(configuration: .init(
            transport: .tcp,
            host: "127.0.0.1",
            port: peer.port,
            secureLinkPSK: Data("linux-swift-psk".utf8)
        ))
        let connected = DispatchSemaphore(value: 0)
        runtime.onSnapshot = { if $0.state == "connected" { connected.signal() } }
        runtime.start()
        #expect(connected.wait(timeout: .now() + 3) == .success)
        #expect(runtime.configuredRuntime.status().appReady)
        #expect(try runtime.send(Data("live-runtime".utf8)) == Data("python:live-runtime".utf8))
        runtime.stop()
        #expect(runtime.snapshot.state == "stopped")
        #expect(runtime.configuredRuntime.status().state == "disconnected")
        #expect(!runtime.configuredRuntime.status().appReady)
    }

    @Test func liveRuntimeReportsRetryExhaustionAndCancelsItOnStop() {
        let runtime = ObstacleBridgeLinuxLiveRuntime(
            configuration: .init(transport: .tcp, host: "127.0.0.1", port: 1),
            policy: .init(initialDelayMilliseconds: 5, maximumDelayMilliseconds: 10, maximumAttempts: 2)
        )
        let failed = DispatchSemaphore(value: 0)
        runtime.onSnapshot = { if $0.state == "failed" { failed.signal() } }
        runtime.start()
        #expect(failed.wait(timeout: .now() + 3) == .success)
        #expect(runtime.snapshot.attempts == 2)
        #expect(runtime.snapshot.failureReason != nil)
        runtime.stop()
        #expect(runtime.snapshot.state == "stopped")
    }
}
