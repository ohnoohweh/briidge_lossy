import Foundation
import ObstacleBridgeCore
import ObstacleBridgeDesktopShared

/// Linux-owned, bounded observability producer. It deliberately performs no
/// network I/O on runtime callbacks: telemetry is first persisted through the
/// shared private spool, and the optional uploader drains that spool outside
/// the foreground runtime's callback path.
/// Non-Sendable observability state. Its dedicated file-I/O queue owns log
/// writes; callers receive only telemetry and diagnostic value snapshots.
public final class ObstacleBridgeLinuxObservability {
    private static let diagnosticLogMaximumPendingWrites = 64
    private let lock = NSLock()
    private let logWorker: ObstacleBridgeLogWorkerSupervisor?
    private let fileURL: URL?
    private let managedLogFile: ObstacleBridgeManagedLogFile?
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
        let configuredLog = logPath.isEmpty ? nil : URL(fileURLWithPath: logPath)
        // The desktop collector owns this file when enabled; otherwise this
        // foreground producer owns its direct native log.
        let directLog = logWorker == nil ? configuredLog : nil
        let managedLog = directLog.map { ObstacleBridgeManagedLogFile(url: $0, settings: .debugLogging(from: configuration)) }
        // Use the local value during initialization: capturing `self` in the
        // queue closure here is illegal before telemetry members are set.
        managedLog?.prepareForStart()
        fileURL = directLog
        managedLogFile = managedLog
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
    public func recordDiagnostic(
        _ event: String,
        fields: [String: String],
        level: ObstacleBridgeRuntimeDiagnosticLevel = .info
    ) {
        logWorker?.emit(name: "linux.runtime", level: level.name, levelNumber: level.rawValue, message: event)
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
        let write = DispatchWorkItem { [weak self] in
            guard let self else { return }
            defer {
                self.pendingWriteLock.lock(); self.pendingWrites -= 1; self.pendingWriteLock.unlock()
            }
            self.appendLogLine(data, to: fileURL)
        }
        fileWriteQueue.async(execute: write)
    }

    /// Runs only on the utility queue.  File failures are diagnostic-only.
    private func appendLogLine(_ data: Data, to fileURL: URL) {
        managedLogFile?.append(data)
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
