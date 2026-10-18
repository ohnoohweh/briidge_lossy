import Foundation
#if os(Linux)
import Glibc
#endif

/// Foreground-owned Swift helper process.  This keeps process ownership out of
/// the IPC adapter: the adapter still sees only an authenticated Unix endpoint
/// and can therefore interoperate with an externally supervised helper.
public final class ObstacleBridgeLinuxManagedTunHelper: @unchecked Sendable {
    /// Linux capability numbers defined by `linux/capability.h`.  Either
    /// capability is sufficient for the helper's TUN and route ownership.
    private static let capNetAdminBit: UInt64 = 1 << 12
    private static let capSysAdminBit: UInt64 = 1 << 21
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
            // Interactive authorization is completed while the foreground
            // command owns the terminal. The delayed helper launch must never
            // compete with the shell for password input.
            return ("/usr/bin/sudo", ["-n", "--", executable] + helperArguments)
        }
        return (executable, helperArguments)
    }

    static func authorizationCommand() -> (path: String, arguments: [String]) {
        ("/usr/bin/sudo", ["-v"])
    }

    /// An interactive sudo prompt needs materially longer than a direct child
    /// launch to create its private socket. The foreground stays responsive
    /// while this bounded wait is in progress.
    static func socketReadyTimeout(elevated: Bool) -> TimeInterval {
        elevated ? 60 : 2
    }

    /// Keep the privilege decision aligned with the Python foreground
    /// runner. An unprivileged foreground process may start the helper
    /// directly when it already has an effective Linux capability, or when
    /// the selected helper executable carries that capability as a file cap.
    /// Otherwise only the separate helper subprocess is launched through
    /// sudo.
    static func canLaunchWithoutSudo(effectiveCapabilityMask: UInt64, fileCapabilityDescription: String) -> Bool {
        if effectiveCapabilityMask & (capNetAdminBit | capSysAdminBit) != 0 {
            return true
        }
        let capabilities = fileCapabilityDescription.lowercased()
        return capabilities.contains("cap_net_admin") || capabilities.contains("cap_sys_admin")
    }

    private static func canLaunchWithoutSudo(executable: String) -> Bool {
        #if os(Linux)
        return canLaunchWithoutSudo(
            effectiveCapabilityMask: effectiveCapabilityMask(),
            fileCapabilityDescription: fileCapabilityDescription(executable: executable)
        )
        #else
        return false
        #endif
    }

    #if os(Linux)
    private static func effectiveCapabilityMask() -> UInt64 {
        guard let status = try? String(contentsOfFile: "/proc/self/status", encoding: .utf8),
              let line = status.split(separator: "\n").first(where: { $0.hasPrefix("CapEff:") })
        else { return 0 }
        let value = line.dropFirst("CapEff:".count).trimmingCharacters(in: .whitespaces)
        return UInt64(value, radix: 16) ?? 0
    }

    private static func fileCapabilityDescription(executable: String) -> String {
        let candidates = ["/usr/sbin/getcap", "/usr/bin/getcap", "/sbin/getcap", "/bin/getcap"]
        guard let tool = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else { return "" }
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = [executable]
        process.standardOutput = output
        process.standardError = Pipe()
        do {
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else { return "" }
            return String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        } catch {
            return ""
        }
    }
    #endif

    /// Establish a sudo timestamp before the asynchronous runtime starts.
    /// Process deliberately inherits stdin/stdout/stderr here: sudo then owns
    /// the caller's foreground terminal and keeps its password entry hidden.
    /// The foreground app itself never becomes privileged; its later helper
    /// child uses the timestamp with `sudo -n`.
    public static func preauthorizeManagedHelperIfNeeded(executable: String? = nil) throws {
        #if os(Linux)
        let selected = executable ?? CommandLine.arguments.first ?? ""
        let resolved = selected.hasPrefix("/")
            ? URL(fileURLWithPath: selected).standardizedFileURL.path
            : URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
                .appendingPathComponent(selected).standardizedFileURL.path
        guard geteuid() != 0, !canLaunchWithoutSudo(executable: resolved) else { return }
        guard isatty(STDIN_FILENO) == 1 else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("managed Swift TUN helper requires an interactive terminal for sudo authentication")
        }
        let command = authorizationCommand()
        let authorization = Process()
        authorization.executableURL = URL(fileURLWithPath: command.path)
        authorization.arguments = command.arguments
        do {
            try authorization.run()
            authorization.waitUntilExit()
        } catch {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("unable to start sudo authorization for the Linux TUN helper")
        }
        guard authorization.terminationStatus == 0 else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("sudo authorization for the Linux TUN helper was not accepted")
        }
        #endif
    }

    public func start(timeout: TimeInterval? = nil) throws {
        guard !process.isRunning else { return }
        if FileManager.default.fileExists(atPath: socketPath) {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("managed Swift TUN helper refuses an existing socket path")
        }
        #if os(Linux)
        let requiresElevation = geteuid() != 0 && !Self.canLaunchWithoutSudo(executable: executable)
        #else
        let requiresElevation = false
        #endif
        let command = Self.launchCommand(
            executable: executable,
            socketPath: socketPath,
            sessionToken: sessionToken,
            elevated: requiresElevation
        )
        let readyTimeout = timeout ?? Self.socketReadyTimeout(elevated: requiresElevation)
        guard FileManager.default.isExecutableFile(atPath: command.path) else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("sudo is required to launch the privileged Linux TUN helper")
        }
        #if os(Linux)
        guard !requiresElevation || isatty(STDIN_FILENO) == 1 else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("managed Swift TUN helper requires an interactive terminal for sudo authentication")
        }
        #endif
        process.executableURL = URL(fileURLWithPath: command.path)
        process.arguments = command.arguments
        // Authorization happened above on the controlling terminal.  The
        // later helper process always uses `sudo -n`, so it must never need
        // terminal input. Keep its protocol startup announcement and any
        // helper diagnostics out of the foreground CLI's JSON output.
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        try process.run()
        let deadline = Date().addingTimeInterval(readyTimeout)
        while !FileManager.default.fileExists(atPath: socketPath), process.isRunning, Date() < deadline {
            Thread.sleep(forTimeInterval: 0.02)
        }
        guard FileManager.default.fileExists(atPath: socketPath) else {
            if process.isRunning { process.terminate() }
            if !process.isRunning {
                throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("managed Swift TUN helper exited before creating its socket (status \(process.terminationStatus))")
            }
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
