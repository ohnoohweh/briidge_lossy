import Foundation
import ObstacleBridgeCore

/// Linux-owned, bounded observability producer. It deliberately performs no
/// network I/O on runtime callbacks: telemetry is first persisted through the
/// shared private spool, and a supervisor/uploader may drain it separately.
public final class ObstacleBridgeLinuxObservability: @unchecked Sendable {
    private let lock = NSLock()
    private let fileURL: URL?
    private let emitter: ObstacleBridgeTelemetryEmitter?
    private let spool: ObstacleBridgeTelemetrySpool?
    private let uploader: ObstacleBridgeLinuxTelemetryUploader?
    private var uploadTimer: DispatchSourceTimer?

    public init(configuration: [String: Any], sessionID: String = UUID().uuidString.lowercased()) {
        let logging = ObstacleBridgeRuntimeConfigPort.groupedSectionPayload("debug_logging", from: configuration)
        let logPath = (logging["log_file"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        fileURL = logPath.isEmpty ? nil : URL(fileURLWithPath: logPath)
        let telemetry = ObstacleBridgeRuntimeConfigPort.groupedSectionPayload("telemetry_client", from: configuration)
        let enabled = telemetry["telemetry_enabled"] as? Bool ?? false
        guard enabled,
              let directory = telemetry["telemetry_spool_directory"] as? String,
              !directory.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else { emitter = nil; spool = nil; uploader = nil; return }
        let installation = Host.current().localizedName?.replacingOccurrences(of: " ", with: "-").lowercased() ?? "linux"
        emitter = try? ObstacleBridgeTelemetryEmitter(installationID: installation, sessionID: sessionID)
        spool = try? ObstacleBridgeTelemetrySpool(directory: URL(fileURLWithPath: directory))
        let endpoint = telemetry["telemetry_endpoint"] as? String
        let certificateDirectory = (telemetry["telemetry_client_certificate_directory"] as? String ?? "/etc/obstaclebridge/telemetry-client").trimmingCharacters(in: .whitespacesAndNewlines)
        let certificate = URL(fileURLWithPath: certificateDirectory).appendingPathComponent("client.cert.pem").path
        let privateKey = URL(fileURLWithPath: certificateDirectory).appendingPathComponent("client.key.pem").path
        let ca = URL(fileURLWithPath: certificateDirectory).appendingPathComponent("collector-ca.cert.pem").path
        if let spool, let endpoint, let url = URL(string: endpoint),
           FileManager.default.fileExists(atPath: certificate), FileManager.default.fileExists(atPath: privateKey), FileManager.default.fileExists(atPath: ca),
           let policy = try? ObstacleBridgeTelemetryUploadPolicy(spool: spool, endpoint: url) {
            uploader = ObstacleBridgeLinuxTelemetryUploader(policy: policy, certificatePath: certificate, privateKeyPath: privateKey, trustRootsPath: ca)
            let timer = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "org.obstaclebridge.linux.telemetry-timer"))
            timer.schedule(deadline: .now() + .seconds(1), repeating: .seconds(5))
            timer.setEventHandler { [weak uploader] in uploader?.uploadOnce() }
            uploadTimer = timer; timer.resume()
        } else { uploader = nil }
    }

    public func record(_ event: String, priority: ObstacleBridgeTelemetryPriority = .normal, fields: [String: ObstacleBridgeTelemetryFieldValue] = [:]) {
        writeLog("\(event) \(fields.map { "\($0.key)=\($0.value)" }.sorted().joined(separator: " "))")
        guard let emitter, let spool, emitter.emit(event: event, fields: fields, priority: priority) else { return }
        for item in emitter.drain() { _ = spool.append(item) }
        uploader?.uploadOnce()
    }

    public func telemetryStatus() -> [String: Any] {
        var status = spool?.statusSnapshot() ?? ["enabled": false]
        status["uploader"] = uploader?.statusSnapshot() ?? ["available": false]
        return status
    }

    public func stop() { uploadTimer?.cancel(); uploadTimer = nil; uploader?.uploadOnce(); uploader?.cancel() }

    private func writeLog(_ message: String) {
        guard let fileURL else { return }
        lock.lock(); defer { lock.unlock() }
        let line = "\(ISO8601DateFormatter().string(from: Date())) [linux-swift] \(message)\n"
        let data = Data(line.utf8)
        let manager = FileManager.default
        try? manager.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        if !manager.fileExists(atPath: fileURL.path) {
            _ = manager.createFile(atPath: fileURL.path, contents: nil)
        }
        if let handle = try? FileHandle(forWritingTo: fileURL) {
            do {
                try handle.seekToEnd()
                try handle.write(contentsOf: data)
            } catch {
                // Logging is best effort; the runtime must remain available if the log cannot be written.
            }
            _ = try? handle.close()
        }
    }
}
