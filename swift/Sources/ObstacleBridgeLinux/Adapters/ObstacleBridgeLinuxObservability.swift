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

    public init(configuration: [String: Any], sessionID: String = UUID().uuidString.lowercased()) {
        let logging = ObstacleBridgeRuntimeConfigPort.groupedSectionPayload("debug_logging", from: configuration)
        let logPath = (logging["log_file"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        fileURL = logPath.isEmpty ? nil : URL(fileURLWithPath: logPath)
        let telemetry = ObstacleBridgeRuntimeConfigPort.groupedSectionPayload("telemetry_client", from: configuration)
        let enabled = telemetry["telemetry_enabled"] as? Bool ?? false
        guard enabled,
              let directory = telemetry["telemetry_spool_directory"] as? String,
              !directory.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else { emitter = nil; spool = nil; return }
        let installation = Host.current().localizedName?.replacingOccurrences(of: " ", with: "-").lowercased() ?? "linux"
        emitter = try? ObstacleBridgeTelemetryEmitter(installationID: installation, sessionID: sessionID)
        spool = try? ObstacleBridgeTelemetrySpool(directory: URL(fileURLWithPath: directory))
    }

    public func record(_ event: String, priority: ObstacleBridgeTelemetryPriority = .normal, fields: [String: ObstacleBridgeTelemetryFieldValue] = [:]) {
        writeLog("\(event) \(fields.map { "\($0.key)=\($0.value)" }.sorted().joined(separator: " "))")
        guard let emitter, let spool, emitter.emit(event: event, fields: fields, priority: priority) else { return }
        for item in emitter.drain() { _ = spool.append(item) }
    }

    public func telemetryStatus() -> [String: Any] {
        spool?.statusSnapshot() ?? ["enabled": false]
    }

    private func writeLog(_ message: String) {
        guard let fileURL else { return }
        lock.lock(); defer { lock.unlock() }
        let line = "\(ISO8601DateFormatter().string(from: Date())) [linux-swift] \(message)\n"
        let data = Data(line.utf8)
        let manager = FileManager.default
        try? manager.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        if !manager.fileExists(atPath: fileURL.path) { manager.createFile(atPath: fileURL.path, contents: nil) }
        if let handle = try? FileHandle(forWritingTo: fileURL) {
            try? handle.seekToEnd(); try? handle.write(contentsOf: data); try? handle.close()
        }
    }
}
