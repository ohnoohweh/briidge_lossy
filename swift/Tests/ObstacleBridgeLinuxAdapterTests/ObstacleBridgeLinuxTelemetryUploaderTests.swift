import Foundation
import Testing
@testable import ObstacleBridgeLinuxAdapters
@testable import ObstacleBridgeCore

struct ObstacleBridgeLinuxTelemetryUploaderTests {
    @Test func validCollectorAcknowledgementDrainsOnlyTheAcknowledgedSpoolBatch() async throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("obstaclebridge-linux-uploader-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let spool = try ObstacleBridgeTelemetrySpool(directory: directory)
        let emitter = try ObstacleBridgeTelemetryEmitter(installationID: "linux-test", sessionID: "session")
        _ = emitter.emit(event: "runtime.lifecycle", fields: ["state": .string("started")])
        for event in emitter.drain() { _ = spool.append(event) }
        let policy = try ObstacleBridgeTelemetryUploadPolicy(spool: spool, endpoint: try #require(URL(string: "https://collector.example/v1/telemetry/batches")))
        let uploader = ObstacleBridgeLinuxTelemetryUploader(policy: policy, certificatePath: "/unused/cert.pem", privateKeyPath: "/unused/key.pem", trustRootsPath: "/unused/ca.pem") { request in
            let body = try JSONSerialization.data(withJSONObject: ["ok": true, "accepted_through": request.lastSequence])
            return (202, body)
        }
        uploader.uploadOnce()
        try await Task.sleep(for: .milliseconds(50))
        #expect(spool.recover().isEmpty)
        #expect(uploader.statusSnapshot()["accepted_batches"] as? UInt64 == 1)
    }
}
