import Foundation
import ObstacleBridgeLinuxAdapters
import ObstacleBridgeCore
#if os(Linux)
import Glibc
#endif

enum ObstacleBridgeLinuxMain {
    private final class ForegroundRestartState: @unchecked Sendable {
        let lock = NSLock()
        var requested = false
    }

    private static let foregroundRestartState = ForegroundRestartState()

    static func main() {
        let arguments = Array(CommandLine.arguments.dropFirst())
        if let runOptions = ObstacleBridgeLinuxForegroundOptions.parse(arguments) {
            runForeground(options: runOptions)
            return
        }
        switch arguments {
        case ["--help"], ["-h"]:
            printHelp()
        case ["--version"]:
            print("\(ObstacleBridgeCoreRuntime.productName) build baseline (\(ObstacleBridgeLinuxAdapters.platform))")
        case ["--helper-build-info"]:
            print(ObstacleBridgeLinuxBuildInfo.json())
        case let values where values.count == 5 && values[0] == "--transport-probe":
            runTransportProbe(transportName: values[1], host: values[2], portText: values[3], payloadBase64: values[4])
        case let values where values.count == 3 && values[0] == "--tcp-psk-echo-listener":
            runTCPPSKEchoListener(portText: values[1], psk: values[2])
        case let values where values.count == 2 && values[0] == "--runtime-config":
            validateRuntimeConfig(path: values[1])
        case let values where values.count == 3 && values[0] == "--runtime-config" && values[2] == "--status":
            printRuntimeStatus(configPath: values[1])
        case let values where values.count == 4 && values[0] == "--runtime-config" && values[2] == "--runtime-probe":
            runRuntimeProbe(configPath: values[1], payloadBase64: values[3])
        case let values where values.count == 3 && values[0] == "--tun-helper-server":
            runTunHelperServer(socketPath: values[1], sessionToken: values[2], idleTimeout: 5)
        case let values where values.count == 5 && values[0] == "--tun-helper-server" && values[3] == "--idle-sec":
            guard let idleTimeout = TimeInterval(values[4]), idleTimeout > 0 else {
                writeError("ObstacleBridgeLinux: --idle-sec requires a positive number of seconds")
                exit(2)
            }
            runTunHelperServer(socketPath: values[1], sessionToken: values[2], idleTimeout: idleTimeout)
        case []:
            printHelp()
        default:
            writeError("ObstacleBridgeLinux: unsupported argument(s): \(arguments.joined(separator: " "))")
            writeError("Run ObstacleBridgeLinux --help for the LSW-002 build-baseline interface.")
            exit(2)
        }
    }

    private static func printHelp() {
        print("""
        ObstacleBridgeLinux — Linux Swift client build baseline

        Usage:
          ObstacleBridgeLinux --help
          ObstacleBridgeLinux --version
          ObstacleBridgeLinux --helper-build-info
          ObstacleBridgeLinux --transport-probe <tcp|ws> <host> <port> <payload-base64>
          ObstacleBridgeLinux --tcp-psk-echo-listener <port> <psk>
          ObstacleBridgeLinux --runtime-config <path>
          ObstacleBridgeLinux --runtime-config <path> --status
          ObstacleBridgeLinux --runtime-config <path> --runtime-probe <payload-base64>
          ObstacleBridgeLinux [--config <path>] [--admin-port <port>] [--hold-sec <seconds>]
          ObstacleBridgeLinux --runtime-config <path> --run [--admin-port <port>] [--hold-sec <seconds>]
          ObstacleBridgeLinux --tun-helper-server <socket-path> <session-token> [--idle-sec <seconds>]

        The transport probe validates Linux POSIX lower-layer TCP or cleartext
        WebSocket framing. With no arguments, the foreground runtime reads
        ObstacleBridge.cfg, matching the Python CLI. --config selects another
        sectioned configuration and starts the admitted foreground stack:
        redacted Admin API, overlay/SecureLink lifecycle, ChannelMux services,
        and the configured authenticated TUN helper. --runtime-config validates
        the existing sectioned config shape and Linux transport admission without exposing secrets.
        --runtime-probe is a bounded diagnostic. --run owns a long-lived
        admitted transport, SecureLink epoch, reconnect lifecycle, and
        redacted local Admin API. ChannelMux service routing is qualified by
        its dedicated package. TUN startup requires an explicitly configured,
        authenticated privileged helper; native route/DNS/hook qualification
        is owned by the native helper. --helper-build-info emits the build
        identity embedded in this executable. --tun-helper-server starts the
        Swift protocol-v1 helper endpoint as a separate process.
        """)
    }

    private static func runTunHelperServer(socketPath: String, sessionToken: String, idleTimeout: TimeInterval) {
        do {
            let backend = ObstacleBridgeLinuxNativeTunHelperBackend(
                stateURL: URL(fileURLWithPath: socketPath + ".state.json")
            )
            try backend.recoverPersistedPolicy()
            let stopped = DispatchSemaphore(value: 0)
            let server = try ObstacleBridgeLinuxTunHelperServer(
                socketPath: socketPath,
                sessionToken: sessionToken,
                backend: backend,
                authenticatedClientIdleTimeout: idleTimeout,
                onStop: { stopped.signal() }
            )
            try server.start()
            print("{\"socket_path\":\"\(socketPath)\",\"state\":\"listening\",\"backend\":\"linux-swift-native\"}")
            let resources: [Any] = [server, backend]
                + installForegroundShutdown(stop: { server.stop() }, admin: nil, holdSeconds: nil)
            DispatchQueue.global().async {
                stopped.wait()
                exit(0)
            }
            withExtendedLifetime(resources) { dispatchMain() }
        } catch {
            writeError("ObstacleBridgeLinux: TUN helper server failed: \(error.localizedDescription)")
            exit(1)
        }
    }

    private static func runTransportProbe(transportName: String, host: String, portText: String, payloadBase64: String) {
        guard let transport = ObstacleBridgeLinuxTransport(rawValue: transportName),
              let port = Int(portText),
              let payload = Data(base64Encoded: payloadBase64)
        else {
            writeError("ObstacleBridgeLinux: transport probe requires a supported transport, port, and base64 payload")
            exit(2)
        }
        do {
            let client = try ObstacleBridgeLinuxOverlayTransportClient(host: host, port: port, transport: transport)
            let response = try client.roundTrip(payload)
            print(response.base64EncodedString())
        } catch {
            writeError("ObstacleBridgeLinux: transport probe failed: \(error.localizedDescription)")
            exit(1)
        }
    }

    private static func runTCPPSKEchoListener(portText: String, psk: String) {
        guard let port = Int(portText), !psk.isEmpty else {
            writeError("ObstacleBridgeLinux: TCP PSK listener requires a port and non-empty PSK")
            exit(2)
        }
        do {
            let listener = try ObstacleBridgeLinuxTCPPSKListener(port: port)
            print("{\"port\":\(listener.port),\"state\":\"listening\"}")
            try listener.serveOne(psk: Data(psk.utf8), serverNonce: Data((0..<32).map(UInt8.init)))
        } catch {
            writeError("ObstacleBridgeLinux: TCP PSK listener failed: \(error.localizedDescription)")
            exit(1)
        }
    }

    private static func validateRuntimeConfig(path: String) {
        do {
            let config = try ObstacleBridgeLinuxRuntimeConfiguration.load(path: path)
            let secureLink = config.secureLinkPSK == nil ? "off" : "psk"
            print("validated transport=\(config.transport.rawValue) host=\(config.host) port=\(config.port) secure_link=\(secureLink)")
        } catch {
            writeError("ObstacleBridgeLinux: runtime config rejected: \(error.localizedDescription)")
            exit(2)
        }
    }

    private static func runRuntimeProbe(configPath: String, payloadBase64: String) {
        guard let payload = Data(base64Encoded: payloadBase64) else {
            writeError("ObstacleBridgeLinux: runtime probe requires a base64 payload")
            exit(2)
        }
        do {
            let config = try ObstacleBridgeLinuxRuntimeConfiguration.load(path: configPath)
            var generator = SystemRandomNumberGenerator()
            let sessionID = UInt64.random(in: 1...UInt64.max, using: &generator)
            let nonce = Data((0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
            let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: config)
            let response = try runtime.roundTrip(payload, sessionID: sessionID, clientNonce: nonce)
            print(response.base64EncodedString())
        } catch {
            writeError("ObstacleBridgeLinux: runtime probe failed: \(error.localizedDescription)")
            exit(1)
        }
    }

    private static func printRuntimeStatus(configPath: String) {
        do {
            let config = try ObstacleBridgeLinuxRuntimeConfiguration.load(path: configPath)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            print(String(decoding: try encoder.encode(ObstacleBridgeLinuxConfiguredRuntime(configuration: config).status()), as: UTF8.self))
        } catch {
            writeError("ObstacleBridgeLinux: runtime status unavailable: \(error.localizedDescription)")
            exit(2)
        }
    }

    private static func runForeground(options: ObstacleBridgeLinuxForegroundOptions) {
        do {
            let configuration = try ObstacleBridgeLinuxRuntimeConfiguration.load(path: options.configurationPath)
            let adminConfiguration = try ObstacleBridgeLinuxRuntimeConfiguration.rawConfiguration(path: options.configurationPath)
            let adminWeb = ObstacleBridgeLinuxAdminWebConfiguration(rawConfiguration: adminConfiguration, portOverride: options.adminPort)
            guard adminWeb.enabled else { throw ObstacleBridgeLinuxRuntimeConfigurationError.invalidValue("admin_web.admin_web is disabled; enable it to start the Linux native Admin Web server") }
            if configuration.launchSwiftTunHelper, configuration.packetTunnelEnabled {
                try ObstacleBridgeLinuxManagedTunHelper.preauthorizeManagedHelperIfNeeded(executable: configuration.tunHelperExecutable)
            }
            let staticDirectory = URL(fileURLWithPath: adminWeb.staticDirectory)
            let observability = ObstacleBridgeLinuxObservability(configuration: adminConfiguration)
            observability.recordForegroundLifecycle(state: "started", transport: configuration.transport.rawValue)
            let buildInfo = embeddedBuildInfo()
            let adminConfigurationStore = ObstacleBridgeLinuxAdminConfigurationStore(configuration: adminConfiguration, path: options.configurationPath)
            if configuration.listenerMode, configuration.transport == .myudp {
                let runtime = try ObstacleBridgeLinuxMyUDPListenerRuntime(configuration: configuration)
                let admin = ObstacleBridgeLinuxAdminServer(myudpListenerRuntime: runtime, adminConfiguration: adminConfiguration, configurationStore: adminConfigurationStore, staticDirectory: staticDirectory, restartHandler: requestForegroundRestart, shutdownHandler: requestForegroundShutdown, buildInfo: buildInfo)
                try admin.start(bindHost: adminWeb.bindHost, port: adminWeb.port)
                runtime.start()
                print("{\"admin_port\":\(admin.port),\"state\":\"starting\",\"listener_mode\":true}")
                let resources: [Any] = [runtime, admin, observability]
                    + installForegroundShutdown(stop: { observability.recordForegroundLifecycle(state: "stopped", transport: configuration.transport.rawValue); observability.stop(); runtime.stop() }, admin: admin, holdSeconds: options.holdSeconds)
                withExtendedLifetime(resources) { dispatchMain() }
            }
            let healthURL = URL(fileURLWithPath: options.configurationPath)
                .deletingLastPathComponent()
                .appendingPathComponent(".ObstacleBridgeLinux.runtime-health-v1.json")
            let runtime = ObstacleBridgeLinuxLiveRuntime(configuration: configuration, runtimeHealthURL: healthURL)
            runtime.onDiagnostic = { event, fields in
                observability.recordDiagnostic(event, fields: fields)
            }
            runtime.onDebugDiagnostic = { event, fields in
                observability.recordDiagnostic("debug.\(event)", fields: fields)
            }
            runtime.onSnapshot = { snapshot in
                observability.recordForegroundLifecycle(state: snapshot.state, transport: configuration.transport.rawValue)
            }
            let admin = ObstacleBridgeLinuxAdminServer(
                liveRuntime: runtime,
                adminConfiguration: adminConfiguration,
                configurationStore: adminConfigurationStore,
                staticDirectory: staticDirectory,
                reconnectHandler: runtime.reconnect,
                secureLinkRekeyHandler: runtime.requestSecureLinkRekey,
                restartHandler: requestForegroundRestart,
                shutdownHandler: requestForegroundShutdown,
                debugLogsProvider: observability.recentLogLines,
                buildInfo: buildInfo
            )
            try admin.start(bindHost: adminWeb.bindHost, port: adminWeb.port)
            var resources: [Any] = [observability]
            if configuration.listenerMode {
                guard let psk = configuration.secureLinkPSK else { throw ObstacleBridgeLinuxRuntimeConfigurationError.missingPSK }
                let acceptSession: @Sendable (Data) throws -> ObstacleBridgeLinuxConfiguredSession
                let listenerOpen: @Sendable () -> Bool
                if configuration.transport == .ws, configuration.webSocketTLS {
                    let listener = try ObstacleBridgeLinuxTLSWebSocketPSKListener(
                        port: configuration.port,
                        certificatePath: configuration.webSocketCertificatePath!,
                        privateKeyPath: configuration.webSocketPrivateKeyPath!,
                        webSocketPath: configuration.webSocketPath,
                        timeoutMilliseconds: configuration.receiveIdleTimeoutMilliseconds
                    )
                    acceptSession = { try listener.acceptConfiguredSession(psk: psk, serverNonce: $0) }
                    listenerOpen = { listener.isOpen }
                    resources.append(listener)
                } else {
                    let listener = try ObstacleBridgeLinuxTCPPSKListener(port: configuration.port, transport: configuration.transport, webSocketPath: configuration.webSocketPath)
                    acceptSession = { try listener.acceptConfiguredSession(psk: psk, serverNonce: $0) }
                    listenerOpen = { listener.isOpen }
                    resources.append(listener)
                }
                let acceptor = DispatchQueue(label: "org.obstaclebridge.linux.\(configuration.transport.rawValue)-listener")
                acceptor.async {
                    while listenerOpen() {
                        var generator = SystemRandomNumberGenerator()
                        let nonce = Data((0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
                        do {
                            runtime.adoptInboundSession(try acceptSession(nonce))
                        } catch where listenerOpen() {
                            writeError("ObstacleBridgeLinux: listener admission failed: \(error.localizedDescription)")
                        } catch {
                            break
                        }
                    }
                }
                resources.append(acceptor)
            } else {
                runtime.start()
            }
            let status = "{\"admin_port\":\(admin.port),\"admin_url\":\"http://127.0.0.1:\(admin.port)/\",\"state\":\"starting\",\"listener_mode\":\(configuration.listenerMode)}"
            print(status)
            resources.append(contentsOf: installForegroundShutdown(
                stop: { observability.recordForegroundLifecycle(state: "stopped", transport: configuration.transport.rawValue); observability.stop(); runtime.stop() },
                recordSignal: runtime.recordShutdownSignal,
                admin: admin,
                holdSeconds: options.holdSeconds
            ))
            withExtendedLifetime(resources) { dispatchMain() }
        } catch {
            writeError("ObstacleBridgeLinux: runtime start failed: \(error.localizedDescription)")
            exit(1)
        }
    }

    /// The executable target owns this generated stamp.  Adapters receive a
    /// redacted value object so embedded/test hosts never need to fabricate an
    /// identity merely to serve Admin routes.
    private static func embeddedBuildInfo() -> [String: Any] {
        guard let data = ObstacleBridgeLinuxBuildInfo.json().data(using: .utf8),
              var value = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return ["available": false] }
        let dirty = value["dirty"] as? Bool ?? false
        value["available"] = true
        value["tainted"] = dirty
        value["tracked_changes"] = dirty ? 1 : 0
        value["untracked_changes"] = 0
        return value
    }

    private static func installForegroundShutdown(
        stop: @escaping @Sendable () -> Void,
        recordSignal: (@Sendable (ObstacleBridgeLinuxShutdownSignal) -> Void)? = nil,
        admin: ObstacleBridgeLinuxAdminServer?,
        holdSeconds: Int?
    ) -> [Any] {
        let shutdownLock = NSLock()
        var shutdownStarted = false
        func shutdown(signal: ObstacleBridgeLinuxShutdownSignal? = nil) {
            shutdownLock.lock()
            guard !shutdownStarted else { shutdownLock.unlock(); return }
            shutdownStarted = true
            shutdownLock.unlock()
            DispatchQueue.global(qos: .userInitiated).async {
                if let signal { recordSignal?(signal) }
                stop()
                admin?.stop()
                if consumeForegroundRestartRequest() { restartForegroundProcess() }
                exit(0)
            }
        }
        var resources: [Any] = []
        #if os(Linux)
        signal(SIGINT, SIG_IGN)
        signal(SIGTERM, SIG_IGN)
        let interrupt = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        interrupt.setEventHandler { shutdown(signal: .interrupt) }
        interrupt.resume()
        let terminate = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        terminate.setEventHandler { shutdown(signal: .terminate) }
        terminate.resume()
        resources.append(interrupt)
        resources.append(terminate)
        #endif
        if let holdSeconds {
            let timer = DispatchSource.makeTimerSource(queue: .main)
            timer.schedule(deadline: .now() + .seconds(holdSeconds))
            timer.setEventHandler { shutdown() }
            timer.resume()
            resources.append(timer)
        }
        return resources
    }

    private static func requestForegroundShutdown() {
        #if os(Linux)
        _ = kill(getpid(), SIGTERM)
        #else
        exit(0)
        #endif
    }

    private static func requestForegroundRestart() {
        foregroundRestartState.lock.lock()
        foregroundRestartState.requested = true
        foregroundRestartState.lock.unlock()
        requestForegroundShutdown()
    }

    private static func consumeForegroundRestartRequest() -> Bool {
        foregroundRestartState.lock.lock()
        defer { foregroundRestartState.lock.unlock() }
        let requested = foregroundRestartState.requested
        foregroundRestartState.requested = false
        return requested
    }

    private static func restartForegroundProcess() -> Never {
        #if os(Linux)
        let arguments = CommandLine.arguments
        guard let executable = arguments.first, !executable.isEmpty else { exit(75) }
        let storage = arguments.map { strdup($0) }
        guard storage.allSatisfy({ $0 != nil }) else { exit(75) }
        var argv = storage.map { Optional($0!) }
        argv.append(nil)
        executable.withCString { path in _ = execv(path, &argv) }
        #endif
        exit(75)
    }

    private static func writeError(_ message: String) {
        FileHandle.standardError.write(Data("\(message)\n".utf8))
    }
}

ObstacleBridgeLinuxMain.main()
