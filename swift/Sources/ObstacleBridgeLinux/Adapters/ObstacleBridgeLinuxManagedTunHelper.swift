import Foundation
#if os(Linux)
import Glibc
#endif

/// Foreground-owned Swift helper process.  This keeps process ownership out of
/// the IPC adapter: the adapter still sees only an authenticated Unix endpoint
/// and can therefore interoperate with an externally supervised helper.
public final class ObstacleBridgeLinuxManagedTunHelper: @unchecked Sendable {
    private let socketPath: String
    private let sessionToken: String
    private let executable: String
    private let process = Process()

    public init(socketPath: String, sessionToken: String, executable: String? = nil) throws {
        guard !socketPath.isEmpty, !sessionToken.isEmpty else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("managed Swift TUN helper requires socket path and token")
        }
        let selected = executable ?? CommandLine.arguments.first ?? ""
        let resolved = selected.hasPrefix("/")
            ? URL(fileURLWithPath: selected).standardizedFileURL.path
            : URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
                .appendingPathComponent(selected).standardizedFileURL.path
        guard FileManager.default.isExecutableFile(atPath: resolved) else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("managed Swift TUN helper executable is unavailable")
        }
        self.socketPath = socketPath
        self.sessionToken = sessionToken
        self.executable = resolved
    }

    /// Redacted process liveness for the foreground runtime's Admin surface.
    /// The socket path and authentication token remain private to this owner.
    public var isRunning: Bool { process.isRunning }

    /// Keeps the foreground client unprivileged.  `sudo` establishes the
    /// helper's `SUDO_UID`/`SUDO_GID`, which the helper uses to return the
    /// authenticated Unix socket to this invoking account.
    static func launchCommand(executable: String, socketPath: String, sessionToken: String, elevated: Bool) -> (path: String, arguments: [String]) {
        let helperArguments = ["--tun-helper-server", socketPath, sessionToken, "--idle-sec", "30"]
        if elevated {
            return ("/usr/bin/sudo", ["--", executable] + helperArguments)
        }
        return (executable, helperArguments)
    }

    public func start(timeout: TimeInterval = 2) throws {
        guard !process.isRunning else { return }
        if FileManager.default.fileExists(atPath: socketPath) {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("managed Swift TUN helper refuses an existing socket path")
        }
        #if os(Linux)
        let requiresElevation = geteuid() != 0
        #else
        let requiresElevation = false
        #endif
        let command = Self.launchCommand(
            executable: executable,
            socketPath: socketPath,
            sessionToken: sessionToken,
            elevated: requiresElevation
        )
        guard FileManager.default.isExecutableFile(atPath: command.path) else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("sudo is required to launch the privileged Linux TUN helper")
        }
        process.executableURL = URL(fileURLWithPath: command.path)
        process.arguments = command.arguments
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        try process.run()
        let deadline = Date().addingTimeInterval(timeout)
        while !FileManager.default.fileExists(atPath: socketPath), process.isRunning, Date() < deadline {
            Thread.sleep(forTimeInterval: 0.02)
        }
        guard FileManager.default.fileExists(atPath: socketPath) else {
            if process.isRunning { process.terminate() }
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("managed Swift TUN helper did not create its socket")
        }
    }

    /// STOP is authenticated and gives the helper a chance to close its TUN
    /// descriptor and policy state.  Termination is only a bounded fallback.
    public func stop() {
        if process.isRunning,
           let adapter = try? ObstacleBridgeLinuxTunHelperAdapter(socketPath: socketPath, sessionToken: sessionToken, timeoutMilliseconds: 500) {
            _ = try? adapter.send(command: .stop, payload: [:])
        }
        let deadline = Date().addingTimeInterval(0.5)
        while process.isRunning, Date() < deadline { Thread.sleep(forTimeInterval: 0.01) }
        if process.isRunning { process.terminate() }
    }

    deinit { stop() }
}
