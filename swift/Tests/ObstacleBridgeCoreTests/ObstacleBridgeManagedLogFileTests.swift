import Foundation
import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgeManagedLogFileTests {
    @Test func preservesPreviousSessionThenRotatesWithConfiguredBounds() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("obstaclebridge-managed-log-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("runtime.log")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Data("previous\n".utf8).write(to: url)

        let log = ObstacleBridgeManagedLogFile(
            url: url,
            settings: .init(maximumBytes: 10, backupCount: 2, truncateOnStart: true)
        )
        log.prepareForStart()
        #expect(String(decoding: try Data(contentsOf: url.appendingPathExtension("lastsession")), as: UTF8.self) == "previous\n")
        #expect(!FileManager.default.fileExists(atPath: url.path))

        log.append(Data("first\n".utf8))
        log.append(Data("second\n".utf8))
        #expect(String(decoding: try Data(contentsOf: url.appendingPathExtension("1")), as: UTF8.self) == "first\n")
        #expect(String(decoding: try Data(contentsOf: url), as: UTF8.self) == "second\n")
    }

    @Test func readsGroupedDebugLoggingSettingsIncludingTruncate() {
        let settings = ObstacleBridgeManagedLogFile.Settings.debugLogging(from: [
            "debug_logging": [
                "log_file_max_bytes": "128",
                "log_file_backup_count": 0,
                "log_file_truncate_on_start": "true",
            ],
        ])
        #expect(settings == .init(maximumBytes: 128, backupCount: 0, truncateOnStart: true))
    }
}
