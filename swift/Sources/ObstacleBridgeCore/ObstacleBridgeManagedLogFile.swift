import Foundation

/// A small, synchronous file sink for redacted native diagnostics.  Owners
/// serialize calls (or call it from their existing file-I/O queue), which
/// keeps rotation and session rollover atomic without putting a lock on packet
/// or transport paths.
public final class ObstacleBridgeManagedLogFile: @unchecked Sendable {
    public struct Settings: Sendable, Equatable {
        public let maximumBytes: Int
        public let backupCount: Int
        public let truncateOnStart: Bool

        public init(maximumBytes: Int = 1_048_576, backupCount: Int = 5, truncateOnStart: Bool = false) {
            self.maximumBytes = max(0, maximumBytes)
            self.backupCount = max(0, backupCount)
            self.truncateOnStart = truncateOnStart
        }

        public static func debugLogging(from root: [String: Any]) -> Settings {
            let section = ObstacleBridgeRuntimeConfigPort.groupedSectionPayload("debug_logging", from: root)
            return .init(
                maximumBytes: integer(section["log_file_max_bytes"]) ?? 1_048_576,
                backupCount: integer(section["log_file_backup_count"]) ?? 5,
                truncateOnStart: boolean(section["log_file_truncate_on_start"]) ?? false
            )
        }

        private static func integer(_ value: Any?) -> Int? {
            if let value = value as? Int { return value }
            if let value = value as? NSNumber { return value.intValue }
            if let value = value as? String { return Int(value.trimmingCharacters(in: .whitespacesAndNewlines)) }
            return nil
        }

        private static func boolean(_ value: Any?) -> Bool? {
            if let value = value as? Bool { return value }
            if let value = value as? NSNumber { return value.boolValue }
            if let value = value as? String {
                switch value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
                case "1", "true", "yes", "on": return true
                case "0", "false", "no", "off": return false
                default: return nil
                }
            }
            return nil
        }
    }

    public let url: URL
    public let settings: Settings

    public init(url: URL, settings: Settings) {
        self.url = url
        self.settings = settings
    }

    /// Starts a new active session.  Preserve the previous active file under
    /// the documented `.lastsession` name before truncating it.
    public func prepareForStart() {
        let manager = FileManager.default
        try? manager.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        guard settings.truncateOnStart, manager.fileExists(atPath: url.path) else { return }
        let previous = url.appendingPathExtension("lastsession")
        try? manager.removeItem(at: previous)
        do {
            try manager.moveItem(at: url, to: previous)
        } catch {
            // A cross-device or permission-constrained move should still
            // honor truncation.  The old file is only removed after an
            // explicit replacement attempt.
            try? manager.removeItem(at: url)
        }
    }

    public func append(_ data: Data) {
        let manager = FileManager.default
        try? manager.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let currentSize = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
        if settings.maximumBytes > 0, currentSize > 0, currentSize + data.count > settings.maximumBytes {
            rotate(manager: manager)
        }
        if !manager.fileExists(atPath: url.path) {
            _ = manager.createFile(atPath: url.path, contents: nil)
        }
        guard let handle = try? FileHandle(forWritingTo: url) else { return }
        defer { try? handle.close() }
        do {
            try handle.seekToEnd()
            try handle.write(contentsOf: data)
        } catch {
            // Diagnostic logging must not fail the foreground runtime.
        }
    }

    private func rotate(manager: FileManager) {
        guard manager.fileExists(atPath: url.path) else { return }
        guard settings.backupCount > 0 else {
            try? manager.removeItem(at: url)
            return
        }
        for index in stride(from: settings.backupCount, through: 1, by: -1) {
            let destination = url.appendingPathExtension("\(index)")
            try? manager.removeItem(at: destination)
            let source = index == 1 ? url : url.appendingPathExtension("\(index - 1)")
            if manager.fileExists(atPath: source.path) {
                try? manager.moveItem(at: source, to: destination)
            }
        }
    }
}
