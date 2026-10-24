import Foundation
import ObstacleBridgeCore
import ObstacleBridgeDesktopShared

/// Linux-owned, bounded observability producer. It deliberately performs no
/// network I/O on runtime callbacks: telemetry is first persisted through the
/// shared private spool, and the optional uploader drains that spool outside
/// the foreground runtime's callback path.
public final class ObstacleBridgeLinuxObservability: @unchecked Sendable {
    private static let diagnosticLogMaximumBytes = 1_048_576
    private static let diagnosticLogBackupCount = 5
    private static let diagnosticLogMaximumPendingWrites = 64
    private let lock = NSLock()
    private let logWorker: ObstacleBridgeLogWorkerSupervisor?
    private let fileURL: URL?
    private let logMaximumBytes: Int
    private let logBackupCount: Int
    private let fileWriteQueue = DispatchQueue(label: "org.obstaclebridge.linux.diagnostic-log", qos: .utility)
    private let pendingWriteLock = NSLock()
    private var pendingWrites = 0
    private let emitter: ObstacleBridgeTelemetryEmitter?
    private let spool: ObstacleBridgeTelemetrySpool?
    private let uploader: ObstacleBridgeLinuxTelemetryUploader?
    private var uploadTimer: DispatchSourceTimer?
    private let maximumRecentLines: Int
    private var recentLines: [String] = []
    private var lastLifecycleSignature: String?

    public init(configuration: [String: Any], sessionID: String = UUID().uuidString.lowercased(), logWorker: ObstacleBridgeLogWorkerSupervisor? = nil) {
        self.logWorker = logWorker
        let logging = ObstacleBridgeRuntimeConfigPort.groupedSectionPayload("debug_logging", from: configuration)
        let logPath = (logging["log_file"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        fileURL = logPath.isEmpty ? nil : URL(fileURLWithPath: logPath)
        logMaximumBytes = max(0, logging["log_file_max_bytes"] as? Int ?? Self.diagnosticLogMaximumBytes)
        logBackupCount = max(1, logging["log_file_backup_count"] as? Int ?? Self.diagnosticLogBackupCount)
        maximumRecentLines = max(1, min(logging["admin_web_log_max_lines"] as? Int ?? 1_200, 10_000))
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
        logWorker?.emit(name: "linux.runtime", level: "INFO", levelNumber: 20, message: event)
        writeLog("\(event) \(fields.map { "\($0.key)=\(self.logValue($0.value))" }.sorted().joined(separator: " "))")
        guard let emitter, let spool, emitter.emit(event: event, fields: fields, priority: priority) else { return }
        for item in emitter.drain() { _ = spool.append(item) }
        uploader?.uploadOnce()
    }

    /// Records the redacted foreground lifecycle to both configured local
    /// logging and the shared telemetry spool. Repeated snapshots of the same
    /// state are intentionally collapsed so a high-frequency Admin refresh
    /// cannot consume the bounded spool.
    public func recordForegroundLifecycle(state: String, transport: String) {
        let signature = "\(state)@\(transport)"
        lock.lock()
        let isDuplicate = lastLifecycleSignature == signature
        lastLifecycleSignature = signature
        lock.unlock()
        guard !isDuplicate else { return }
        record("runtime.lifecycle", fields: [
            "state": .string(state),
            "transport": .string(transport),
        ])
    }

    /// Stores local runtime diagnostics without converting them to telemetry
    /// field wrappers. This keeps Admin log lines operator-readable and avoids
    /// sending connection-attempt detail through the telemetry pipeline.
    public func recordDiagnostic(_ event: String, fields: [String: String]) {
        writeLog("\(event) \(fields.map { "\($0.key)=\($0.value)" }.sorted().joined(separator: " "))")
    }

    public func telemetryStatus() -> [String: Any] {
        var status = spool?.statusSnapshot() ?? ["enabled": false]
        status["uploader"] = uploader?.statusSnapshot() ?? ["available": false]
        return status
    }

    /// Redacted, bounded lines for the shared Admin Web log view.  These are
    /// lifecycle diagnostics only; packet bytes, key material, and secrets
    /// never enter this producer.
    public func recentLogLines(limit: Int = 400) -> [String] {
        lock.lock(); defer { lock.unlock() }
        return Array(recentLines.suffix(max(1, min(limit, maximumRecentLines))))
    }

    public func stop() { uploadTimer?.cancel(); uploadTimer = nil; uploader?.uploadOnce(); uploader?.cancel(); fileWriteQueue.sync {} }

    private func writeLog(_ message: String) {
        lock.lock(); defer { lock.unlock() }
        let line = "\(ISO8601DateFormatter().string(from: Date())) [linux-swift] \(message)\n"
        recentLines.append(line.trimmingCharacters(in: .newlines))
        if recentLines.count > maximumRecentLines {
            recentLines.removeFirst(recentLines.count - maximumRecentLines)
        }
        guard let fileURL else { return }
        let data = Data(line.utf8)
        pendingWriteLock.lock()
        guard pendingWrites < Self.diagnosticLogMaximumPendingWrites else {
            pendingWriteLock.unlock()
            return
        }
        pendingWrites += 1
        pendingWriteLock.unlock()
        fileWriteQueue.async { [weak self] in
            guard let self else { return }
            defer {
                self.pendingWriteLock.lock(); self.pendingWrites -= 1; self.pendingWriteLock.unlock()
            }
            self.appendLogLine(data, to: fileURL)
        }
    }

    /// Runs only on the utility queue.  File failures are diagnostic-only.
    private func appendLogLine(_ data: Data, to fileURL: URL) {
        let manager = FileManager.default
        try? manager.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        let currentSize = (try? fileURL.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
        if logMaximumBytes > 0, currentSize > 0, currentSize + data.count > logMaximumBytes {
            rotateLog(at: fileURL, manager: manager)
        }
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

    /// Runs only on `fileWriteQueue`.
    private func rotateLog(at fileURL: URL, manager: FileManager) {
        guard manager.fileExists(atPath: fileURL.path) else { return }
        for index in stride(from: logBackupCount, through: 1, by: -1) {
            let destination = fileURL.appendingPathExtension("\(index)")
            try? manager.removeItem(at: destination)
            let source = index == 1 ? fileURL : fileURL.appendingPathExtension("\(index - 1)")
            if manager.fileExists(atPath: source.path) { try? manager.moveItem(at: source, to: destination) }
        }
    }

    private func logValue(_ value: ObstacleBridgeTelemetryFieldValue) -> String {
        switch value {
        case .bool(let value): return value ? "true" : "false"
        case .integer(let value): return String(value)
        case .number(let value): return String(value)
        case .string(let value): return value
        }
    }
}
