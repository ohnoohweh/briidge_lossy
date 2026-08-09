import Darwin
import Foundation
import Network

private enum ObstacleBridgeHostRunnerError: Error, LocalizedError {
    case usage(String)
    case invalidArgument(String)
    case unreadableRuntimeConfig(String)
    case invalidRuntimeConfigRoot
    case invalidEncryptedConfigSecret(String)
    case invalidStatusPort(Int)

    var errorDescription: String? {
        switch self {
        case .usage(let detail):
            return detail
        case .invalidArgument(let detail):
            return detail
        case .unreadableRuntimeConfig(let path):
            return "Unable to read runtime config at \(path)"
        case .invalidRuntimeConfigRoot:
            return "Runtime config JSON must decode to an object"
        case .invalidEncryptedConfigSecret(let key):
            return "Invalid encrypted runtime config secret for key \(key)"
        case .invalidStatusPort(let port):
            return "Invalid status/admin port: \(port)"
        }
    }
}

private final class ObstacleBridgeConfigStore {
    let configPath: String
    let configRoot: String
    private(set) var groupedConfig: [String: Any]
    private(set) var runtimeConfig: [String: Any]

    init(configPath: String, groupedConfig: [String: Any], runtimeConfig: [String: Any]) {
        self.configPath = configPath
        self.groupedConfig = groupedConfig
        self.runtimeConfig = runtimeConfig

        let configURL = URL(fileURLWithPath: configPath)
        let parent = configURL.deletingLastPathComponent()
        if parent.lastPathComponent == "config" {
            self.configRoot = parent.deletingLastPathComponent().path
        } else {
            self.configRoot = parent.path
        }
    }

    func adminWebDirectory() -> String {
        if let explicit = ObstacleBridgeHostRunner.stringValue(from: runtimeConfig["admin_web_dir"]) {
            return explicit
        }
        let fileManager = FileManager.default
        let candidates = [
            URL(fileURLWithPath: configRoot).appendingPathComponent("admin_web").path,
            URL(fileURLWithPath: fileManager.currentDirectoryPath).appendingPathComponent("admin_web").path,
            URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().appendingPathComponent("admin_web").path,
        ]
        for candidate in candidates where fileManager.fileExists(atPath: candidate) {
            return candidate
        }
        return candidates.first ?? URL(fileURLWithPath: configRoot).appendingPathComponent("admin_web").path
    }

    func debugLogFilePath() -> String? {
        if let nested = groupedConfig["debug_logging"] as? [String: Any],
           let path = ObstacleBridgeHostRunner.stringValue(from: nested["log_file"]) {
            return path
        }
        return ObstacleBridgeHostRunner.stringValue(from: runtimeConfig["log_file"])
    }

    func updateConfigs(groupedConfig: [String: Any], runtimeConfig: [String: Any]) {
        self.groupedConfig = groupedConfig
        self.runtimeConfig = runtimeConfig
    }

    func schemaSnapshot() -> [String: Any] {
        ObstacleBridgeRuntimeConfig.configSchemaSnapshot()
    }

    func schemaRow(forKey key: String) -> [String: Any]? {
        ObstacleBridgeRuntimeConfig.schemaRow(forKey: key)
    }

    func sectionName(forKey key: String) -> String? {
        ObstacleBridgeRuntimeConfig.sectionName(forKey: key)
    }
}

private protocol ObstacleBridgeOverlayTransportOwning: AnyObject {
    func stop()
    func connectionRows() -> (tcp: [[String: Any]], udp: [[String: Any]], tun: [[String: Any]])
    func transportSnapshot() -> [String: Any]
    func connectionLayersSnapshot() -> [[String: Any]]
    func requestSecureLinkRekey() -> [String: Any]
    func appReady() -> Bool
    func sendLocalTunPacket(_ packet: Data)
    func acceptLocalTCPConnection(
        _ connection: NWConnection,
        spec: ObstacleBridgeChannelMuxCodec.ServiceSpec,
        listenerHost: String,
        listenerPort: Int
    ) -> Bool
    func acceptLocalUDPConnection(
        _ connection: NWConnection,
        spec: ObstacleBridgeChannelMuxCodec.ServiceSpec,
        listenerHost: String,
        listenerPort: Int,
        serviceKey: String
    ) -> Bool
}

extension ObstacleBridgeWebSocketOverlayTransportOwner: ObstacleBridgeOverlayTransportOwning {}
extension ObstacleBridgeTcpOverlayTransportOwner: ObstacleBridgeOverlayTransportOwning {}
@available(iOS 15.0, *)
extension ObstacleBridgeQuicOverlayTransportOwner: ObstacleBridgeOverlayTransportOwning {}
extension ObstacleBridgeUdpOverlayTransportOwner: ObstacleBridgeOverlayTransportOwning {}

final class ObstacleBridgeHostRunner {
    typealias MacOSTunHelperClientFactory = (
        DispatchQueue,
        @escaping (Data) -> Void,
        ((String, [String: Any]) -> Void)?
    ) -> ObstacleBridgeTunHelperClienting

    private static let configChallengeTTL: TimeInterval = 90
    private static let serviceStateQueueKey = DispatchSpecificKey<UInt8>()

    private let runtimeConfigPath: String
    private var runtimeConfigRaw: [String: Any]
    private var runtimeConfig: [String: Any]
    private let configStore: ObstacleBridgeConfigStore
    private var ownServerSpecs: [ObstacleBridgeNativeServiceSpec]
    private var remoteServerSpecs: [ObstacleBridgeNativeServiceSpec]
    private let bindHost: String
    private let statusPort: Int
    private let macOSTunHelperClientFactory: MacOSTunHelperClientFactory
    private var startedAt = Date()
    private let serviceStateQueue = DispatchQueue(label: "ObstacleBridgeHostRunner.Services")
    private let authStateQueue = DispatchQueue(label: "ObstacleBridgeHostRunner.Auth")
    private let adminSnapshotQueue = DispatchQueue(label: "ObstacleBridgeHostRunner.AdminSnapshots")
    private let controlActionQueue = DispatchQueue(label: "ObstacleBridgeHostRunner.ControlActions")
    private var controlServer: ObstacleBridgeWebAdminServer?
    private var bootstrapState: [String: Any] = [:]
    private var restartCount = 0
    private var reconnectCount = 0
    private var shutdownRequestedAt: Date?
    private var sharedChannelMuxUdpRuntime = ObstacleBridgeChannelMuxUdpRuntime(instanceID: 0, connectionSeq: 0)
    private var sharedChannelMuxTcpRuntime = ObstacleBridgeChannelMuxTcpRuntime()
    private var udpServiceListeners: [Int: NWListener] = [:]
    private var udpConnectionStates: [Int: [String: Any]] = [:]
    private var udpConnectionObjects: [ObjectIdentifier: ObstacleBridgeUDPProxyConnection] = [:]
    private var tcpServiceListeners: [Int: NWListener] = [:]
    private var tcpConnectionStates: [Int: [String: Any]] = [:]
    private var tcpConnectionObjects: [Int: ObstacleBridgeTCPProxyConnection] = [:]
    private var sharedCompressLayerRuntime: ObstacleBridgeCompressLayerRuntime?
    private var sharedSecureLinkPskTransportAdapter: ObstacleBridgeSecureLinkPskTransportAdapter?
    private var sharedOverlayLayerTransportAdapter: ObstacleBridgeOverlayLayerTransportAdapter?
    private var sharedWebSocketOverlayRuntime: ObstacleBridgeWebSocketOverlayRuntime?
    private var sharedTcpOverlayRuntime: ObstacleBridgeTcpOverlayRuntime?
    private var sharedQuicOverlayRuntime: ObstacleBridgeQuicOverlayRuntime?
    private var sharedWebSocketOverlayTransportOwner: ObstacleBridgeWebSocketOverlayTransportOwner?
    private var sharedTcpOverlayTransportOwner: ObstacleBridgeTcpOverlayTransportOwner?
    private var sharedQuicOverlayTransportOwner: ObstacleBridgeOverlayTransportOwning?
    private var sharedUdpOverlayTransportOwner: ObstacleBridgeUdpOverlayTransportOwner?
    private var proxyServers: [String: ObstacleBridgeProxyServer] = [:]
    private var proxyProviderLastError = ""
    private var macOSTunHelperClient: ObstacleBridgeTunHelperClienting?
    private var macOSTunHelperRuntimeSnapshot = ObstacleBridgeTunHelperRuntimeSnapshot()
    private var macOSTunHelperTransportKind = "none"
    private var macOSTunChannelConnectedHookFired = false
    private var macOSOverlayUnderlayGatewayV4 = ""
    private var macOSOverlayUnderlayInterfaceV4 = ""
    private let tunProbeIdentifier = UInt16.random(in: 1...UInt16.max)
    private var tunProbeSequence: UInt16 = 1
    private var tunProbeWaiters: [TunProbeWaiterKey: TunProbeWaiterState] = [:]
    private var tunProbeHistory: [String: TunProbeHistory] = [:]
    private var clientRestartWatchdog: DispatchSourceTimer?
    private var adminSnapshotTimer: DispatchSourceTimer?
    private var cachedStatusSnapshot: [String: Any] = [:]
    private var cachedConnectionsSnapshot: [String: Any] = [:]
    private var cachedPeersSnapshot: [[String: Any]] = []
    private var cachedMetaSnapshot: [String: Any] = [:]
    private var cachedTunRoutingSnapshot: [String: Any] = [:]
    private var peerTrafficRateState: [String: (timestamp: TimeInterval, rxBytes: Int, txBytes: Int)] = [:]
    private var overlayDisconnectedAt: TimeInterval?
    private var secureLinkSnapshotSessionID: UInt64 = 0
    private var secureLinkConnectedSinceUnixTs: Int?
    private var secureLinkLastAuthenticatedUnixTs: Int?
    private lazy var adminAuth = ObstacleBridgeAdminAuth(
        queueLabel: "ObstacleBridgeHostRunner.AdminAuth",
        authRequiredProvider: { [weak self] in
            self?.adminAuthRequired() ?? false
        },
        usernameProvider: { [weak self] in
            self?.adminAuthUsername() ?? ""
        },
        passwordProvider: { [weak self] in
            self?.adminAuthPassword() ?? ""
        },
        bearerTokenProvider: { [weak self] in
            self?.adminWebToken() ?? ""
        },
        cookieScopeProvider: { [weak self] in
            self?.adminSessionCookieScope() ?? ""
        }
    )
    private lazy var adminConfigChallengeStore = ObstacleBridgeAdminConfigChallenge(
        queueLabel: "ObstacleBridgeHostRunner.AdminConfigChallenge",
        usernameProvider: { [weak self] in
            self?.adminAuthUsername() ?? ""
        },
        passwordProvider: { [weak self] in
            self?.adminAuthPassword() ?? ""
        }
    )

    private struct OverlayPeerEndpoint {
        let host: String
        let port: Int
    }

    private struct ActiveOverlayOwner {
        let transport: String
        let owner: ObstacleBridgeOverlayTransportOwning
    }

    private struct TunProbeWaiterKey: Hashable {
        let family: Int32
        let identifier: UInt16
        let sequence: UInt16
        let nonce: Data
    }

    private final class TunProbeWaiterState {
        let semaphore = DispatchSemaphore(value: 0)
        var reply: TunProbeReply?
    }

    private struct TunProbeReply {
        let sourceIP: String
        let destinationIP: String
        let payload: Data
        let receivedMonotonicNS: UInt64
    }

    private struct TunProbeHistory {
        let lastSuccessMonotonic: TimeInterval
        let lastSuccessRTTMS: Double
    }

    init(
        runtimeConfigPath: String,
        bindHostOverride: String?,
        statusPortOverride: Int?,
        macOSTunHelperClientFactory: MacOSTunHelperClientFactory? = nil
    ) throws {
        self.runtimeConfigPath = runtimeConfigPath
        let decoded = try Self.loadRuntimeConfigFromDisk(runtimeConfigPath: runtimeConfigPath)
        self.runtimeConfigRaw = decoded
        self.runtimeConfig = ObstacleBridgeRuntimeConfig.flatten(decoded)
        self.configStore = ObstacleBridgeConfigStore(configPath: runtimeConfigPath, groupedConfig: decoded, runtimeConfig: runtimeConfig)
        self.ownServerSpecs = ObstacleBridgeRuntimeConfig.ownServerSpecs(from: runtimeConfig).map(ObstacleBridgeNativeServiceSpec.init)
        self.remoteServerSpecs = ObstacleBridgeRuntimeConfig.remoteServerSpecs(from: runtimeConfig).map(ObstacleBridgeNativeServiceSpec.init)
        self.bindHost = bindHostOverride ?? (ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["admin_web_bind"]) ?? "127.0.0.1")
        let configuredPort = ObstacleBridgeRuntimeConfig.intValue(from: runtimeConfig["admin_web_port"])
        self.statusPort = statusPortOverride ?? configuredPort ?? 18080
        self.macOSTunHelperClientFactory = macOSTunHelperClientFactory ?? Self.makeDefaultMacOSTunHelperClient
        serviceStateQueue.setSpecific(key: Self.serviceStateQueueKey, value: 1)
    }

    private static func makeDefaultMacOSTunHelperClient(
        queue: DispatchQueue,
        packetSink: @escaping (Data) -> Void,
        eventSink: ((String, [String: Any]) -> Void)?
    ) -> ObstacleBridgeTunHelperClienting {
        let forcedTransport = (ProcessInfo.processInfo.environment["OBSTACLEBRIDGE_MACOS_TUN_HELPER_TRANSPORT"] ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        if forcedTransport == "loopback" {
            return makeLoopbackMacOSTunHelperClient(queue: queue, packetSink: packetSink, eventSink: eventSink)
        }
#if os(macOS)
        let package = ObstacleBridgeMacOSTunHelperService.statusSnapshot()
        if (package["xpc_reachable"] as? Bool) == true {
            let transport = ObstacleBridgeNSXPCTunHelperCommandTransport(
                packetSink: packetSink,
                eventSink: eventSink
            )
            return ObstacleBridgeLoopbackTunHelperClient(transport: transport, transportKind: "xpc")
        }
#endif
        return makeLoopbackMacOSTunHelperClient(queue: queue, packetSink: packetSink, eventSink: eventSink)
    }

    private static func makeLoopbackMacOSTunHelperClient(
        queue: DispatchQueue,
        packetSink: @escaping (Data) -> Void,
        eventSink: ((String, [String: Any]) -> Void)?
    ) -> ObstacleBridgeTunHelperClienting {
        let backend = ObstacleBridgeInProcessMacOSTunHelperClient(
            queue: queue,
            packetSink: packetSink,
            eventSink: eventSink
        )
        let server = ObstacleBridgeTunHelperCommandServer(backend: backend)
        let transport = ObstacleBridgeXPCShapedTunHelperCommandTransport(server: server)
        return ObstacleBridgeLoopbackTunHelperClient(transport: transport, transportKind: "loopback")
    }

    static func appScopedRootURL() throws -> URL {
#if os(macOS)
        guard let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            throw ObstacleBridgeHostRunnerError.unreadableRuntimeConfig("Application Support/ObstacleBridge")
        }
        let root = base.appendingPathComponent("ObstacleBridge", isDirectory: true)
#else
        guard let base = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
            throw ObstacleBridgeHostRunnerError.unreadableRuntimeConfig("Documents")
        }
        let root = base
#endif
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    static func appScopedRuntimeConfigPath() throws -> String {
        return try appScopedRootURL()
            .appendingPathComponent("config", isDirectory: true)
            .appendingPathComponent("ObstacleBridge.cfg", isDirectory: false)
            .path
    }

    static func makeAppScopedRunner() throws -> ObstacleBridgeHostRunner {
        try ObstacleBridgeHostRunner(
            runtimeConfigPath: appScopedRuntimeConfigPath(),
            bindHostOverride: nil,
            statusPortOverride: nil
        )
    }

    static func makeRunner(cli: ObstacleBridgeHostRunnerCLI) throws -> ObstacleBridgeHostRunner {
        try ObstacleBridgeHostRunner(
            runtimeConfigPath: cli.runtimeConfigPath,
            bindHostOverride: cli.bindHost,
            statusPortOverride: cli.statusPort
        )
    }

    static func runMain(arguments: [String]) throws {
        let cli = try ObstacleBridgeHostRunnerCLI.parse(arguments)
        let runner = try makeRunner(cli: cli)
        try runner.start()
        defer { runner.stop() }
        if cli.holdSec > 0 {
            let deadline = Date().addingTimeInterval(cli.holdSec)
            while Date() < deadline {
                _ = RunLoop.current.run(mode: .default, before: min(deadline, Date().addingTimeInterval(0.1)))
            }
            return
        }
        dispatchMain()
    }

    private static func loadRuntimeConfigFromDisk(runtimeConfigPath: String) throws -> [String: Any] {
        let url = URL(fileURLWithPath: runtimeConfigPath)
        guard let data = try? Data(contentsOf: url) else {
            throw ObstacleBridgeHostRunnerError.unreadableRuntimeConfig(runtimeConfigPath)
        }
        guard let object = try? JSONSerialization.jsonObject(with: data),
              let rawDecoded = object as? [String: Any] else {
            throw ObstacleBridgeHostRunnerError.invalidRuntimeConfigRoot
        }
        do {
            return try ObstacleBridgeConfigSecretCodec.decryptPayload(rawDecoded)
        } catch let error as ObstacleBridgeHostRunnerError {
            throw error
        } catch {
            throw ObstacleBridgeHostRunnerError.invalidEncryptedConfigSecret("runtime_config")
        }
    }

    private func reloadRuntimeConfigFromDisk() throws {
        let decoded = try Self.loadRuntimeConfigFromDisk(runtimeConfigPath: runtimeConfigPath)
        runtimeConfigRaw = decoded
        runtimeConfig = ObstacleBridgeRuntimeConfig.flatten(decoded)
        configStore.updateConfigs(groupedConfig: decoded, runtimeConfig: runtimeConfig)
        ownServerSpecs = ObstacleBridgeRuntimeConfig.ownServerSpecs(from: runtimeConfig).map(ObstacleBridgeNativeServiceSpec.init)
        remoteServerSpecs = ObstacleBridgeRuntimeConfig.remoteServerSpecs(from: runtimeConfig).map(ObstacleBridgeNativeServiceSpec.init)
    }

    private func reloadRuntimeStateForControlAction() throws {
        try reloadRuntimeConfigFromDisk()
        stopProxyProvider()
        stopOwnServers()
        prepareSharedOverlayBootstrap()
        try startProxyProviderIfConfigured()
        try startOwnServers()
        startSharedWebSocketOverlayTransportOwnerIfNeeded()
        startSharedTCPOverlayTransportOwnerIfNeeded()
        startSharedQUICOverlayTransportOwnerIfNeeded()
        try startSharedUDPOverlayTransportOwnerIfNeeded()
        startedAt = Date()
    }

    private func ensureControlServerStarted() throws {
        if controlServer != nil {
            return
        }
        let controlServer = try ObstacleBridgeWebAdminServer(
            bindHost: bindHost,
            port: statusPort,
            fallbackIndexTitle: "ObstacleBridge macOS Swift Host Runner",
            fallbackIndexSubtitle: "Swift-only bootstrap and status surface for host-side E2E harnessing.",
            statusProvider: { [weak self] in
                self?.adminStatusSnapshot() ?? [:]
            },
            apiProvider: { [weak self] method, path, headers, body in
                guard let self else {
                    return nil
                }
                let request = ObstacleBridgeAdminAPIRequest(method: method, path: path, headers: headers, body: body)
                return ObstacleBridgeAdminAPI.response(for: request, provider: self)
            },
            staticFileProvider: { [weak self] path in
                self?.staticFileResponse(path: path)
            },
            liveTopicProvider: { [weak self] topic in
                guard let self else {
                    return nil
                }
                return ObstacleBridgeAdminAPI.liveTopicPayload(topic: topic, provider: self)
            },
            authRequiredProvider: { [weak self] in
                self?.adminAuthRequired() ?? false
            },
            authenticatedProvider: { [weak self] headers in
                self?.adminIsAuthenticated(headers: headers) ?? false
            }
        )
        self.controlServer = controlServer
        controlServer.start()
    }

    func start() throws {
        try ensureControlServerStarted()
        prepareSharedOverlayBootstrap()
        do {
            try startProxyProviderIfConfigured()
            try startOwnServers()
            startSharedWebSocketOverlayTransportOwnerIfNeeded()
            startSharedTCPOverlayTransportOwnerIfNeeded()
            startSharedQUICOverlayTransportOwnerIfNeeded()
            try startSharedUDPOverlayTransportOwnerIfNeeded()
            bootstrapState["startup_status"] = "ready"
        } catch {
            NSLog("[ObstacleBridgeHostRunner][startup_failed] %@", error.localizedDescription)
            bootstrapState["startup_status"] = "failed"
            bootstrapState["startup_error"] = error.localizedDescription
        }
        startAdminSnapshotPublisher()
        startClientRestartWatchdog()
    }

    func stop() {
        clientRestartWatchdog?.cancel()
        clientRestartWatchdog = nil
        adminSnapshotTimer?.cancel()
        adminSnapshotTimer = nil
        teardownSharedMacOSTunAdapter(runLifecycleHook: true)
        sharedWebSocketOverlayTransportOwner?.stop()
        sharedWebSocketOverlayTransportOwner = nil
        sharedTcpOverlayTransportOwner?.stop()
        sharedTcpOverlayTransportOwner = nil
        sharedQuicOverlayTransportOwner?.stop()
        sharedQuicOverlayTransportOwner = nil
        sharedUdpOverlayTransportOwner?.stop()
        sharedUdpOverlayTransportOwner = nil
        stopProxyProvider()
        stopOwnServers()
        controlServer?.stop()
        controlServer = nil
    }

    private func startProxyProviderIfConfigured() throws {
        stopProxyProvider()
        let config = proxyProviderConfiguration()
        guard config.enabled else {
            proxyProviderLastError = ""
            return
        }

        var started: [String: ObstacleBridgeProxyServer] = [:]
        do {
            if config.httpEnabled {
                let server = try ObstacleBridgeProxyServer(
                    configuration: ObstacleBridgeProxyServer.Configuration(
                        bindHost: config.bindHost,
                        port: config.httpPort,
                        credentials: config.credentials,
                        allowHTTP: true,
                        allowSOCKS5: config.socks5Enabled && config.socks5Port == config.httpPort
                    )
                )
                server.start()
                started["http"] = server
            }
            if config.socks5Enabled && (!config.httpEnabled || config.socks5Port != config.httpPort) {
                let server = try ObstacleBridgeProxyServer(
                    configuration: ObstacleBridgeProxyServer.Configuration(
                        bindHost: config.bindHost,
                        port: config.socks5Port,
                        credentials: config.credentials,
                        allowHTTP: false,
                        allowSOCKS5: true
                    )
                )
                server.start()
                started["socks5"] = server
            }
        } catch {
            for server in started.values {
                server.stop()
            }
            proxyProviderLastError = error.localizedDescription
            throw error
        }

        proxyServers = started
        proxyProviderLastError = ""
        if !started.isEmpty {
            bootstrapState["proxy_provider"] = "ready"
        }
    }

    private func stopProxyProvider() {
        guard !proxyServers.isEmpty else {
            return
        }
        for server in proxyServers.values {
            server.stop()
        }
        proxyServers.removeAll()
    }

    private func proxyProviderSnapshot() -> [String: Any] {
        let config = proxyProviderConfiguration()
        var listeners: [String: Any] = [:]
        for key in proxyServers.keys.sorted() {
            if let server = proxyServers[key] {
                listeners[key] = server.snapshot()
            }
        }
        return [
            "enabled": !proxyServers.isEmpty,
            "configured": config.configuredPayload(),
            "listeners": listeners,
            "last_error": proxyProviderLastError,
        ]
    }

    private struct ProxyProviderConfig {
        let enabled: Bool
        let bindHost: String
        let httpPort: Int
        let socks5Port: Int
        let protocols: [String]
        let auth: [String: Any]
        let egress: [String: Any]
        let policy: [String: Any]
        let credentials: ObstacleBridgeProxyServer.Credentials?

        var httpEnabled: Bool {
            protocols.contains("http-connect") || protocols.contains("http")
        }

        var socks5Enabled: Bool {
            protocols.contains("socks5-connect") || protocols.contains("socks5")
        }

        func configuredPayload() -> [String: Any] {
            [
                "enabled": enabled,
                "bind": bindHost,
                "http_port": httpPort,
                "socks5_port": socks5Port,
                "protocols": protocols,
                "auth": auth,
                "egress": egress,
                "policy": policy,
            ]
        }
    }

    private func proxyProviderConfiguration() -> ProxyProviderConfig {
        let section = runtimeConfigRaw["proxy_provider"] as? [String: Any]
        let enabled = ObstacleBridgeRuntimeConfig.boolValue(from: section?["enabled"] ?? runtimeConfig["proxy_provider_enabled"]) ?? false
        let bindHost = ObstacleBridgeRuntimeConfig.stringValue(from: section?["bind"] ?? runtimeConfig["proxy_provider_bind"]) ?? "127.0.0.1"
        let httpPort = ObstacleBridgeRuntimeConfig.intValue(from: section?["http_port"] ?? runtimeConfig["proxy_provider_http_port"]) ?? 13881
        let socks5Port = ObstacleBridgeRuntimeConfig.intValue(from: section?["socks5_port"] ?? runtimeConfig["proxy_provider_socks5_port"]) ?? 13882
        let protocols = Self.proxyProviderProtocols(section?["protocols"] ?? runtimeConfig["proxy_provider_protocols"])
        let auth = (section?["auth"] ?? runtimeConfig["proxy_provider_auth"]) as? [String: Any] ?? [
            "mode": "none",
            "username": "",
            "token": "",
        ]
        let egress = (section?["egress"] ?? runtimeConfig["proxy_provider_egress"]) as? [String: Any] ?? [
            "mode": "system",
            "address_families": ["ipv4", "ipv6"],
        ]
        let policy = (section?["policy"] ?? runtimeConfig["proxy_provider_policy"]) as? [String: Any] ?? [
            "allow_private_destinations": false,
            "blocked_host_patterns": [],
        ]
        let authMode = (ObstacleBridgeRuntimeConfig.stringValue(from: auth["mode"] ?? runtimeConfig["proxy_provider_auth_mode"]) ?? "none").lowercased()
        let username = ObstacleBridgeRuntimeConfig.stringValue(from: auth["username"] ?? runtimeConfig["proxy_provider_username"]) ?? ""
        let password = ObstacleBridgeRuntimeConfig.stringValue(from: auth["token"] ?? auth["password"] ?? runtimeConfig["proxy_provider_token"] ?? runtimeConfig["proxy_provider_password"]) ?? ""
        let credentials: ObstacleBridgeProxyServer.Credentials?
        if authMode == "token" || authMode == "basic" || authMode == "password" {
            credentials = username.isEmpty || password.isEmpty ? nil : ObstacleBridgeProxyServer.Credentials(username: username, password: password)
        } else {
            credentials = nil
        }
        return ProxyProviderConfig(
            enabled: enabled,
            bindHost: bindHost,
            httpPort: httpPort,
            socks5Port: socks5Port,
            protocols: protocols,
            auth: auth,
            egress: egress,
            policy: policy,
            credentials: credentials
        )
    }

    private static func proxyProviderProtocols(_ value: Any?) -> [String] {
        let values: [String]
        if let array = value as? [Any] {
            values = array.compactMap { ObstacleBridgeRuntimeConfig.stringValue(from: $0)?.lowercased() }
        } else if let text = ObstacleBridgeRuntimeConfig.stringValue(from: value) {
            values = text.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
        } else {
            values = ["http-connect", "socks5-connect"]
        }
        let filtered = values.filter { !$0.isEmpty }
        return filtered.isEmpty ? ["http-connect", "socks5-connect"] : filtered
    }

    private func startAdminSnapshotPublisher() {
        adminSnapshotTimer?.cancel()
        refreshAdminSnapshotCache()
        let timer = DispatchSource.makeTimerSource(queue: serviceStateQueue)
        timer.schedule(deadline: .now() + .milliseconds(250), repeating: .milliseconds(500))
        timer.setEventHandler { [weak self] in
            self?.refreshAdminSnapshotCache()
        }
        adminSnapshotTimer = timer
        timer.resume()
    }

    private func refreshAdminSnapshotCache(sync: Bool = false) {
        let status = snapshotUncached()
        let connections = connectionsSnapshotUncached()
        let peers = peersSnapshotUncached(connections: connections, transportRuntime: status["transport_runtime"] as? [String: Any])
        let meta = metaSnapshotUncached(transportRuntime: status["transport_runtime"] as? [String: Any])
        var tunRouting = ObstacleBridgeAdminAPI.tunRoutingSnapshot(fromConnections: connections)
        if let tunRoutingConfig = ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: runtimeConfig) {
            let effectiveExcluded = ObstacleBridgeRuntimeConfig.effectiveExcludedRoutes(
                from: runtimeConfig,
                baseIPv4: tunRoutingConfig.excludedRoutes ?? [],
                baseIPv6: tunRoutingConfig.excludedRoutes6 ?? []
            )
            tunRouting["included_routes"] = tunRoutingConfig.includedRoutes ?? []
            tunRouting["excluded_routes"] = effectiveExcluded.ipv4
            tunRouting["included_routes6"] = tunRoutingConfig.includedRoutes6 ?? []
            tunRouting["excluded_routes6"] = effectiveExcluded.ipv6
        }
        tunRouting["tun_helper"] = status["tun_helper"] ?? macOSTunHelperStatusSnapshot()
        let updateCache = { [weak self] in
            self?.cachedStatusSnapshot = status
            self?.cachedConnectionsSnapshot = connections
            self?.cachedPeersSnapshot = peers
            self?.cachedMetaSnapshot = meta
            self?.cachedTunRoutingSnapshot = tunRouting
        }
        if sync {
            adminSnapshotQueue.sync(execute: updateCache)
        } else {
            adminSnapshotQueue.async(execute: updateCache)
        }
    }

    private func withCurrentUptime(_ snapshot: [String: Any]) -> [String: Any] {
        var updated = snapshot
        updated["uptime_ms"] = Int(Date().timeIntervalSince(startedAt) * 1000)
        updated["uptime_sec"] = Int(Date().timeIntervalSince(startedAt))
        return updated
    }

    private func cachedStatusOrBuild() -> [String: Any] {
        let cached = adminSnapshotQueue.sync { cachedStatusSnapshot }
        if cached.isEmpty {
            return snapshotUncached()
        }
        return withCurrentUptime(cached)
    }

    private func cachedConnectionsOrBuild() -> [String: Any] {
        let cached = adminSnapshotQueue.sync { cachedConnectionsSnapshot }
        return cached.isEmpty ? connectionsSnapshotUncached() : cached
    }

    private func cachedPeersOrBuild() -> [[String: Any]] {
        let cached = adminSnapshotQueue.sync { cachedPeersSnapshot }
        return cached.isEmpty ? peersSnapshotUncached() : cached
    }

    private func cachedMetaOrBuild() -> [String: Any] {
        let cached = adminSnapshotQueue.sync { cachedMetaSnapshot }
        if cached.isEmpty {
            return metaSnapshotUncached()
        }
        var updated = cached
        updated["uptime_sec"] = Int(Date().timeIntervalSince(startedAt))
        return updated
    }

    private func cachedTunRoutingOrBuild() -> [String: Any] {
        let cached = adminSnapshotQueue.sync { cachedTunRoutingSnapshot }
        if !cached.isEmpty {
            return cached
        }
        var payload = ObstacleBridgeAdminAPI.tunRoutingSnapshot(fromConnections: connectionsSnapshotUncached())
        if let tunRouting = ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: runtimeConfig) {
            let effectiveExcluded = ObstacleBridgeRuntimeConfig.effectiveExcludedRoutes(
                from: runtimeConfig,
                baseIPv4: tunRouting.excludedRoutes ?? [],
                baseIPv6: tunRouting.excludedRoutes6 ?? []
            )
            payload["included_routes"] = tunRouting.includedRoutes ?? []
            payload["excluded_routes"] = effectiveExcluded.ipv4
            payload["included_routes6"] = tunRouting.includedRoutes6 ?? []
            payload["excluded_routes6"] = effectiveExcluded.ipv6
        }
        payload["tun_helper"] = snapshotUncached()["tun_helper"] ?? macOSTunHelperStatusSnapshot()
        return payload
    }

    private func tunRoutingSnapshotWithVerification(_ payload: [String: Any]) -> [String: Any] {
        var out = payload
        out["verification"] = tunRoutingVerificationPayload(payload: payload)
        return out
    }

    private func tunRoutingVerificationPayload(payload: [String: Any]) -> [String: Any] {
        let ifname = selectedTunVerificationIfname(payload: payload)
        let observed = Self.macOSTunInterfaceAddresses(ifname: ifname)
        let observed4 = (observed["ipv4"] as? [String] ?? []).map { $0.split(separator: "/", maxSplits: 1).first.map(String.init) ?? $0 }
        let observed6 = (observed["ipv6"] as? [String] ?? []).map { $0.split(separator: "/", maxSplits: 1).first.map(String.init) ?? $0 }
        let tunRouting = ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: runtimeConfig)
        let expected4 = (tunRouting?.tunnelAddress ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let expected6 = (tunRouting?.tunnelAddress6 ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let has4 = expected4.isEmpty || observed4.contains(expected4)
        let has6 = expected6.isEmpty || observed6.contains(expected6)
        let configCheck: [String: Any]
        if ifname.isEmpty {
            configCheck = Self.verificationResult(
                label: "TUN config verified",
                ok: false,
                state: "skipped",
                summary: "TUN config verified: skipped",
                detail: "No active TUN interface is available for verification."
            )
        } else if has4 && has6 {
            configCheck = Self.verificationResult(
                label: "TUN config verified",
                ok: true,
                state: "verified",
                summary: "TUN config verified",
                detail: "Observed addresses on \(ifname): IPv4 \(expected4.isEmpty ? "-" : expected4), IPv6 \(expected6.isEmpty ? "-" : expected6)."
            )
        } else {
            var missing: [String] = []
            if !expected4.isEmpty && !has4 {
                missing.append("IPv4 \(expected4)")
            }
            if !expected6.isEmpty && !has6 {
                missing.append("IPv6 \(expected6)")
            }
            configCheck = Self.verificationResult(
                label: "TUN config verified",
                ok: false,
                state: "failed",
                summary: "TUN config verified: failed",
                detail: "Missing expected addresses on \(ifname): \(missing.joined(separator: ", ")). Observed IPv4: \(observed4.isEmpty ? "-" : observed4.joined(separator: ", ")); observed IPv6: \(observed6.isEmpty ? "-" : observed6.joined(separator: ", "))"
            )
        }
        let peerTarget = (tunRouting?.tunnelGateway ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let globalHost = (Self.stringValue(from: runtimeConfig["global_connectivity_host"]) ?? Self.stringValue(from: (runtimeConfig["TUN_routing"] as? [String: Any])?["global_connectivity_host"]) ?? "google.de")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return [
            "ifname": ifname,
            "observed_addresses": observed,
            "global_connectivity_host": globalHost,
            "tun_config": configCheck,
            "tun_connectivity": macOSInternalTunVerification(
                probeKind: "peer",
                target: peerTarget,
                ifname: ifname,
                timeoutSeconds: 1.0
            ),
            "tun_global_connectivity": macOSInternalTunVerification(
                probeKind: "global",
                target: globalHost,
                ifname: ifname,
                timeoutSeconds: 2.0
            ),
        ]
    }

    private func selectedTunVerificationIfname(payload: [String: Any]) -> String {
        let helper = payload["tun_helper"] as? [String: Any] ?? [:]
        let runtime = helper["runtime"] as? [String: Any] ?? [:]
        if let ifname = Self.stringValue(from: runtime["ifname"])?.trimmingCharacters(in: .whitespacesAndNewlines), !ifname.isEmpty {
            return ifname
        }
        for row in payload["tun"] as? [[String: Any]] ?? [] {
            let local = row["local"] as? [String: Any] ?? [:]
            if let ifname = Self.stringValue(from: local["ifname"])?.trimmingCharacters(in: .whitespacesAndNewlines), !ifname.isEmpty {
                return ifname
            }
        }
        return ""
    }

    private static func verificationResult(
        label: String,
        ok: Bool,
        state: String,
        summary: String,
        detail: String,
        target: String = ""
    ) -> [String: Any] {
        [
            "label": label,
            "ok": ok,
            "state": state,
            "summary": summary,
            "detail": detail,
            "target": target,
            "checked_at_unix_ts": Date().timeIntervalSince1970,
        ]
    }

    private func tunProbeResult(
        probeKind: String,
        target: String,
        ok: Bool,
        state: String,
        summary: String,
        detail: String,
        resolvedTarget: String = "",
        valueMS: Double? = nil,
        lastSuccessAgoS: Double? = nil,
        lastSuccessRTTMS: Double? = nil
    ) -> [String: Any] {
        var result: [String: Any] = [
            "label": tunProbeLabel(probeKind),
            "ok": ok,
            "state": state,
            "summary": summary,
            "detail": detail,
            "target": target,
            "resolved_target": resolvedTarget,
            "method": "internal_icmp_echo",
            "checked_at_unix_ts": Date().timeIntervalSince1970,
            "value_ms": NSNull(),
            "last_success_ago_s": NSNull(),
            "last_success_rtt_ms": NSNull(),
        ]
        if let valueMS {
            result["value_ms"] = valueMS
            result["last_success_rtt_ms"] = valueMS
        } else if let lastSuccessRTTMS {
            result["last_success_rtt_ms"] = lastSuccessRTTMS
        }
        if let lastSuccessAgoS {
            result["last_success_ago_s"] = lastSuccessAgoS
        }
        return result
    }

    private static func macOSTunInterfaceAddresses(ifname: String) -> [String: Any] {
        let trimmed = ifname.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return ["ok": false, "ipv4": [] as [String], "ipv6": [] as [String], "detail": "TUN interface name unavailable."]
        }
        guard let result = runProcess(executable: "/sbin/ifconfig", arguments: [trimmed], timeoutSeconds: 1.0) else {
            return ["ok": false, "ipv4": [] as [String], "ipv6": [] as [String], "detail": "ifconfig command failed."]
        }
        var ipv4: [String] = []
        var ipv6: [String] = []
        for rawLine in result.output.split(separator: "\n") {
            let line = String(rawLine).trimmingCharacters(in: .whitespacesAndNewlines)
            if line.hasPrefix("inet ") {
                let parts = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
                if parts.count >= 2 {
                    ipv4.append(parts[1])
                }
            } else if line.hasPrefix("inet6 ") {
                let parts = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
                if parts.count >= 2 {
                    ipv6.append(parts[1].split(separator: "%", maxSplits: 1).first.map(String.init) ?? parts[1])
                }
            }
        }
        return [
            "ok": result.status == 0,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "detail": result.status == 0 ? "" : result.output,
        ]
    }

    private func macOSInternalTunVerification(probeKind: String, target: String, ifname: String, timeoutSeconds: TimeInterval) -> [String: Any] {
        let label = tunProbeLabel(probeKind)
        let trimmedTarget = target.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedIfname = ifname.trimmingCharacters(in: .whitespacesAndNewlines)
        let cacheKey = tunProbeCacheKey(probeKind: probeKind, ifname: trimmedIfname, target: trimmedTarget)
        if trimmedTarget.isEmpty {
            return tunProbeResult(
                probeKind: probeKind,
                target: trimmedTarget,
                ok: false,
                state: "skipped",
                summary: "\(label): skipped",
                detail: "Verification target is not configured."
            )
        }
        if trimmedIfname.isEmpty {
            return tunProbeResult(
                probeKind: probeKind,
                target: trimmedTarget,
                ok: false,
                state: "skipped",
                summary: "\(label): skipped",
                detail: "TUN interface name unavailable."
            )
        }
        let actualIfname = withServiceStateQueue {
            macOSTunHelperClient?.actualIfname.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        }
        if actualIfname != trimmedIfname {
            return tunProbeResult(
                probeKind: probeKind,
                target: trimmedTarget,
                ok: false,
                state: "skipped",
                summary: "\(label): skipped",
                detail: "TUN interface \(trimmedIfname) is not active on this runtime."
            )
        }
        guard currentOverlayOwner() != nil else {
            let history = tunProbeHistorySnapshot(cacheKey: cacheKey)
            return tunProbeResult(
                probeKind: probeKind,
                target: trimmedTarget,
                ok: false,
                state: "failed",
                summary: "\(label): failed",
                detail: "No active overlay owner is available for the TUN probe.",
                lastSuccessAgoS: history.lastSuccessAgoS,
                lastSuccessRTTMS: history.lastSuccessRTTMS
            )
        }
        let candidateFamilies = sourceProbeFamilies()
        let resolved = resolveTunProbeTarget(trimmedTarget, candidateFamilies: candidateFamilies)
        guard let resolvedTarget = resolved.target else {
            let history = tunProbeHistorySnapshot(cacheKey: cacheKey)
            return tunProbeResult(
                probeKind: probeKind,
                target: trimmedTarget,
                ok: false,
                state: "failed",
                summary: "\(label): failed",
                detail: "Probe target resolution failed: \(resolved.error)",
                lastSuccessAgoS: history.lastSuccessAgoS,
                lastSuccessRTTMS: history.lastSuccessRTTMS
            )
        }
        let family = resolved.family
        let sourceIP = sourceAddressForProbeFamily(family)
        guard !sourceIP.isEmpty else {
            let history = tunProbeHistorySnapshot(cacheKey: cacheKey)
            return tunProbeResult(
                probeKind: probeKind,
                target: trimmedTarget,
                ok: false,
                state: "skipped",
                summary: "\(label): skipped",
                detail: "No configured tunnel source address is available for \(resolvedTarget).",
                resolvedTarget: resolvedTarget,
                lastSuccessAgoS: history.lastSuccessAgoS,
                lastSuccessRTTMS: history.lastSuccessRTTMS
            )
        }
        let sentMonotonicNS = DispatchTime.now().uptimeNanoseconds
        let nonce = Self.randomProbeNonce()
        let kindCode = tunProbeKindCode(probeKind)
        let payload = ObstacleBridgeTunPing.probePayload(
            probeKind: kindCode,
            nonce: nonce,
            sentMonotonicNS: sentMonotonicNS
        )
        let identity = allocateTunProbeIdentity()
        let packet: Data?
        if family == AF_INET6 {
            packet = ObstacleBridgeTunPing.buildIPv6EchoRequest(
                sourceIP: sourceIP,
                destinationIP: resolvedTarget,
                identifier: identity.identifier,
                sequence: identity.sequence,
                payload: payload
            )
        } else {
            packet = ObstacleBridgeTunPing.buildIPv4EchoRequest(
                sourceIP: sourceIP,
                destinationIP: resolvedTarget,
                identifier: identity.identifier,
                sequence: identity.sequence,
                payload: payload
            )
        }
        guard let packet else {
            let history = tunProbeHistorySnapshot(cacheKey: cacheKey)
            return tunProbeResult(
                probeKind: probeKind,
                target: trimmedTarget,
                ok: false,
                state: "failed",
                summary: "\(label): failed",
                detail: "Internal probe failed: unable to build ICMP echo request.",
                resolvedTarget: resolvedTarget,
                lastSuccessAgoS: history.lastSuccessAgoS,
                lastSuccessRTTMS: history.lastSuccessRTTMS
            )
        }
        let waiter = TunProbeWaiterState()
        let waiterKey = TunProbeWaiterKey(
            family: family,
            identifier: identity.identifier,
            sequence: identity.sequence,
            nonce: nonce
        )
        withServiceStateQueue {
            tunProbeWaiters[waiterKey] = waiter
        }
        currentOverlayOwner()?.owner.sendLocalTunPacket(packet)
        let timedOut = waiter.semaphore.wait(timeout: .now() + max(0.1, timeoutSeconds)) == .timedOut
        _ = withServiceStateQueue {
            tunProbeWaiters.removeValue(forKey: waiterKey)
        }
        if timedOut || waiter.reply == nil {
            let history = tunProbeHistorySnapshot(cacheKey: cacheKey)
            return tunProbeResult(
                probeKind: probeKind,
                target: trimmedTarget,
                ok: false,
                state: "failed",
                summary: "\(label): failed",
                detail: String(format: "No ICMP echo reply received from %@ within %.1fs.", resolvedTarget, timeoutSeconds),
                resolvedTarget: resolvedTarget,
                lastSuccessAgoS: history.lastSuccessAgoS,
                lastSuccessRTTMS: history.lastSuccessRTTMS
            )
        }
        let receivedMonotonicNS = waiter.reply?.receivedMonotonicNS ?? DispatchTime.now().uptimeNanoseconds
        let rttMS = max(0.0, Double(receivedMonotonicNS &- sentMonotonicNS) / 1_000_000.0)
        recordTunProbeSuccess(cacheKey: cacheKey, rttMS: rttMS)
        return tunProbeResult(
            probeKind: probeKind,
            target: trimmedTarget,
            ok: true,
            state: "verified",
            summary: "\(label): verified",
            detail: "ICMP echo reply received from \(resolvedTarget).",
            resolvedTarget: resolvedTarget,
            valueMS: rttMS,
            lastSuccessAgoS: 0.0,
            lastSuccessRTTMS: rttMS
        )
    }

    private func tunProbeCacheKey(probeKind: String, ifname: String, target: String) -> String {
        "\(probeKind.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())|\(ifname)|\(target)"
    }

    private func tunProbeLabel(_ probeKind: String) -> String {
        switch probeKind.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "peer":
            return "TUN connectivity verified"
        case "global":
            return "TUN global connectivity verified"
        default:
            return "TUN connectivity verification"
        }
    }

    private func tunProbeKindCode(_ probeKind: String) -> UInt8 {
        probeKind.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "global"
            ? ObstacleBridgeTunPing.probeKindGlobal
            : ObstacleBridgeTunPing.probeKindPeer
    }

    private func sourceProbeFamilies() -> [Int32] {
        var families: [Int32] = []
        let tunRouting = ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: runtimeConfig)
        if !(tunRouting?.tunnelAddress ?? "").trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            families.append(AF_INET)
        }
        if !(tunRouting?.tunnelAddress6 ?? "").trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            families.append(AF_INET6)
        }
        if families.isEmpty {
            families.append(AF_INET)
        }
        return families
    }

    private func sourceAddressForProbeFamily(_ family: Int32) -> String {
        let tunRouting = ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: runtimeConfig)
        if family == AF_INET6 {
            return (tunRouting?.tunnelAddress6 ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return (tunRouting?.tunnelAddress ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func allocateTunProbeIdentity() -> (identifier: UInt16, sequence: UInt16) {
        let sequence = withServiceStateQueue { () -> UInt16 in
            let current = (tunProbeSequence == 0) ? 1 : tunProbeSequence
            tunProbeSequence = (current &+ 1)
            if tunProbeSequence == 0 {
                tunProbeSequence = 1
            }
            return current
        }
        return (tunProbeIdentifier, sequence)
    }

    private func recordTunProbeSuccess(cacheKey: String, rttMS: Double) {
        withServiceStateQueue {
            tunProbeHistory[cacheKey] = TunProbeHistory(
                lastSuccessMonotonic: ProcessInfo.processInfo.systemUptime,
                lastSuccessRTTMS: rttMS
            )
        }
    }

    private func tunProbeHistorySnapshot(cacheKey: String) -> (lastSuccessAgoS: Double?, lastSuccessRTTMS: Double?) {
        withServiceStateQueue {
            guard let history = tunProbeHistory[cacheKey] else {
                return (nil, nil)
            }
            return (
                max(0.0, ProcessInfo.processInfo.systemUptime - history.lastSuccessMonotonic),
                history.lastSuccessRTTMS
            )
        }
    }

    private func observeTunProbeReply(_ packet: Data) {
        guard let parsed = ObstacleBridgeTunPing.parseEchoReply(packet) else {
            return
        }
        let payload = parsed.payload
        let minimumPayloadLength = ObstacleBridgeTunPing.probeMagic.count + 1 + 8 + 8
        guard payload.count >= minimumPayloadLength,
              payload.prefix(ObstacleBridgeTunPing.probeMagic.count) == ObstacleBridgeTunPing.probeMagic else {
            return
        }
        let nonce = payload.subdata(in: 5..<13)
        let key = TunProbeWaiterKey(
            family: parsed.family,
            identifier: parsed.identifier,
            sequence: parsed.sequence,
            nonce: nonce
        )
        withServiceStateQueue {
            guard let waiter = tunProbeWaiters.removeValue(forKey: key) else {
                return
            }
            waiter.reply = TunProbeReply(
                sourceIP: parsed.sourceIP,
                destinationIP: parsed.destinationIP,
                payload: payload,
                receivedMonotonicNS: DispatchTime.now().uptimeNanoseconds
            )
            waiter.semaphore.signal()
        }
    }

    private func resolveTunProbeTarget(_ target: String, candidateFamilies: [Int32]) -> (target: String?, family: Int32, error: String) {
        var lastError = "target resolution failed"
        for family in candidateFamilies {
            if let directFamily = ObstacleBridgeTunPing.ipFamily(target), directFamily == family {
                return (target, family, "")
            }
            if let resolved = Self.resolveHost(target, family: family) {
                return (resolved, family, "")
            }
            lastError = "unable to resolve \(target) for family=\(family)"
        }
        return (nil, candidateFamilies.first ?? AF_INET, lastError)
    }

    private static func resolveHost(_ host: String, family: Int32) -> String? {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return nil
        }
        var hints = addrinfo(
            ai_flags: AI_ADDRCONFIG,
            ai_family: family,
            ai_socktype: SOCK_RAW,
            ai_protocol: family == AF_INET6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )
        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(trimmed, nil, &hints, &result)
        guard status == 0, let result else {
            return nil
        }
        defer { freeaddrinfo(result) }
        var cursor: UnsafeMutablePointer<addrinfo>? = result
        while let info = cursor?.pointee {
            if info.ai_family == AF_INET,
               let addr = info.ai_addr?.withMemoryRebound(to: sockaddr_in.self, capacity: 1, { $0.pointee }) {
                var copy = addr.sin_addr
                var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                if inet_ntop(AF_INET, &copy, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil {
                    return String(cString: buffer)
                }
            } else if info.ai_family == AF_INET6,
                      let addr6 = info.ai_addr?.withMemoryRebound(to: sockaddr_in6.self, capacity: 1, { $0.pointee }) {
                var copy = addr6.sin6_addr
                var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                if inet_ntop(AF_INET6, &copy, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil {
                    return String(cString: buffer)
                }
            }
            cursor = info.ai_next
        }
        return nil
    }

    private static func randomProbeNonce() -> Data {
        var bytes = [UInt8](repeating: 0, count: 8)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        if status == errSecSuccess {
            return Data(bytes)
        }
        return Data((0..<8).map { _ in UInt8.random(in: 0...255) })
    }

    private static func runProcess(executable: String, arguments: [String], timeoutSeconds: TimeInterval) -> (status: Int32, output: String)? {
#if os(macOS)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let outputPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = outputPipe
        do {
            try process.run()
        } catch {
            return nil
        }
        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while process.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.02)
        }
        if process.isRunning {
            process.terminate()
        }
        process.waitUntilExit()
        let data = outputPipe.fileHandleForReading.readDataToEndOfFile()
        return (process.terminationStatus, String(data: data, encoding: .utf8) ?? "")
#else
        return nil
#endif
    }

    func snapshot() -> [String: Any] {
        cachedStatusOrBuild()
    }

    private func snapshotUncached() -> [String: Any] {
        let uptimeMS = Int(Date().timeIntervalSince(startedAt) * 1000)
        let uptimeSec = Int(Date().timeIntervalSince(startedAt))
        return [
            "ok": true,
            "mode": "swift_host_runner",
            "pid": ProcessInfo.processInfo.processIdentifier,
            "runtime_config_path": runtimeConfigPath,
            "runtime_config_keys": runtimeConfig.keys.sorted(),
            "admin_bind_host": bindHost,
            "admin_port": statusPort,
            "admin_url": "http://\(bindHost):\(statusPort)/",
            "uptime_ms": uptimeMS,
            "uptime_sec": uptimeSec,
            "bootstrap_state": bootstrapState,
            "admin_web_name": Self.stringValue(from: runtimeConfig["admin_web_name"]) ?? "",
            "build": buildSummary(),
            "admin_ui": adminUIPayload(),
            "security_advisor": securityAdvisorPayload(),
            "control_actions": controlActionSnapshot(),
            "tun_helper": macOSTunHelperStatusSnapshot(),
            "transport_runtime": transportRuntimeSnapshot(),
            "compress_layer": compressLayerSnapshot(peerID: nil) ?? NSNull(),
            "proxy_provider": proxyProviderSnapshot(),
            "secure_link_material_generation": 0,
            "secure_link_last_reload_unix_ts": NSNull(),
            "secure_link_last_reload_scope": "",
            "secure_link_last_reload_result": "",
            "secure_link_last_reload_detail": "",
            "secure_link_peers_dropped_total": 0,
        ]
    }

    private func staticFileResponse(path: String) -> (contentType: String, body: Data)? {
        let adminWebDir = configStore.adminWebDirectory()
        return ObstacleBridgeAdminWebSupport.staticFileResponse(
            baseDirectoryURL: URL(fileURLWithPath: adminWebDir),
            path: path
        )
    }

    private func metaSnapshot() -> [String: Any] {
        cachedMetaOrBuild()
    }

    private func metaSnapshotUncached(transportRuntime: [String: Any]? = nil) -> [String: Any] {
        let uptimeSec = Int(Date().timeIntervalSince(startedAt))
        return ObstacleBridgeAdminSnapshotSupport.metaEnvelope(
            runtimeOwner: "ObstacleBridgeApp swift_host_runner",
            runtimeMode: "swift_host_runner",
            adminWebName: Self.stringValue(from: runtimeConfig["admin_web_name"]) ?? "",
            adminUI: adminUIPayload(),
            securityAdvisor: securityAdvisorPayload(),
            startedAt: startedAt.timeIntervalSince1970,
            uptimeSec: uptimeSec,
            bootstrapState: bootstrapState,
            transportRuntime: transportRuntime ?? transportRuntimeSnapshot(),
            compressLayer: compressLayerSnapshot(peerID: nil) ?? NSNull(),
            extra: [
                "build": buildSummary(),
                "runtime_dependencies": adminRuntimeDependenciesPayload(),
                "control_actions": controlActionSnapshot(),
            ]
        )
    }

    private func peersSnapshot() -> [[String: Any]] {
        cachedPeersOrBuild()
    }

    private func peersSnapshotUncached(
        connections: [String: Any]? = nil,
        transportRuntime suppliedTransportRuntime: [String: Any]? = nil
    ) -> [[String: Any]] {
        let connections = connections ?? connectionsSnapshotUncached()
        let counts = connections["counts"] as? [String: Any] ?? [:]
        let transport = Self.stringValue(from: bootstrapState["transport"]) ?? (Self.stringValue(from: runtimeConfig["overlay_transport"]) ?? "myudp")
        let configuredPeerEndpoint = peerEndpointSnapshot()
        let transportRuntime = suppliedTransportRuntime ?? transportRuntimeSnapshot()
        let resolvedPeer = resolvedPeerSnapshot(transport: transport, transportRuntime: transportRuntime)
        let myudpRuntime = transportRuntime["myudp"] as? [String: Any] ?? [:]
        let protocolStats = ObstacleBridgeAdminSnapshotSupport.selectedProtocolStats(
            from: transportRuntime,
            preferredKind: transport
        )
        let trafficTotals = peerTrafficTotals(from: connections)
        let overlayConnected = overlayCurrentlyConnected() ?? false
        let connectionLayers = ObstacleBridgeAdminSnapshotSupport.connectionLayers(
            from: transportRuntime,
            preferredKind: transport
        )
        let stateText: String
        if overlayConnected {
            stateText = "connected"
        } else if bootstrapState["status"] as? String == "prepared" {
            stateText = "connecting"
        } else {
            stateText = "failed"
        }
        var peer: [String: Any] = [
            "id": 1,
            "transport": transport,
            "state": stateText,
            "listen": NSNull(),
            "peer": resolvedPeer ?? configuredPeerEndpoint,
            "resolved_peer": resolvedPeer ?? NSNull(),
            "resolved_peer_host": resolvedPeer?["host"] ?? NSNull(),
            "resolved_peer_port": resolvedPeer?["port"] ?? NSNull(),
            "resolved_peer_family": resolvedPeer?["family"] ?? NSNull(),
            "decode_errors": 0,
            "inflight": protocolStats["inflight"] ?? 0,
            "last_incoming_age_seconds": ObstacleBridgeAdminSnapshotSupport.peerLastIncomingAgeSeconds(
                from: transportRuntime,
                preferredKind: transport
            ),
            "rtt_est_ms": ObstacleBridgeAdminSnapshotSupport.peerMetric(
                "rtt_est_ms",
                from: transportRuntime,
                preferredKind: transport
            ),
            "transmit_delay_est_ms": ObstacleBridgeAdminSnapshotSupport.peerMetric(
                "transmit_delay_est_ms",
                from: transportRuntime,
                preferredKind: transport
            ),
            "next_address_attempt_in_seconds": ObstacleBridgeAdminSnapshotSupport.peerMetric(
                "next_address_attempt_in_seconds",
                from: transportRuntime,
                preferredKind: transport
            ),
            "restart_in_seconds": ObstacleBridgeAdminSnapshotSupport.peerMetric(
                "restart_in_seconds",
                from: transportRuntime,
                preferredKind: transport
            ),
            "traffic": trafficSnapshot(peerID: "1", rxBytes: trafficTotals.rxBytes, txBytes: trafficTotals.txBytes),
            "open_connections": [
                "udp": counts["udp"] ?? 0,
                "tcp": counts["tcp"] ?? 0,
                "tun": counts["tun"] ?? 0,
            ],
            "connection_layers": connectionLayers,
            "secure_link": secureLinkSnapshot(defaultState: stateText),
            "compress_layer": compressLayerSnapshot(peerID: 1) ?? [
                "enabled": Self.boolValue(from: runtimeConfig["compress_layer"]) ?? false,
                "algorithm": Self.stringValue(from: runtimeConfig["compress_layer_algo"]) ?? "",
                "compress_attempts_total": 0,
                "compress_applied_total": 0,
                "compress_input_bytes_total": 0,
                "compress_output_bytes_total": 0,
                "decompress_ok_total": 0,
                "decompress_fail_total": 0,
            ],
            "throttle": ObstacleBridgeAdminSnapshotSupport.peerThrottleSnapshot(peerID: 1, connectionsSnapshot: connections),
            "runtime": transportRuntime,
        ]
        if transport == "myudp" {
            let myudpProtocolStats = myudpRuntime["protocol_stats"] as? [String: Any] ?? [:]
            peer["myudp"] = [
                "buffered_frames": myudpProtocolStats["buffered_frames"] ?? 0,
                "first_pass": myudpProtocolStats["first_pass"] ?? 0,
                "repeated_once": myudpProtocolStats["repeated_once"] ?? 0,
                "repeated_multiple": myudpProtocolStats["repeated_multiple"] ?? 0,
                "confirmed_total": myudpProtocolStats["confirmed_total"] ?? 0,
            ]
        }
        return [peer]
    }

    private func peerTrafficTotals(from connections: [String: Any]) -> (rxBytes: Int, txBytes: Int) {
        var rxBytes = 0
        var txBytes = 0
        for key in ["udp", "tcp", "tun"] {
            guard let rows = connections[key] as? [[String: Any]] else {
                continue
            }
            for row in rows {
                if row["chan_id"] == nil {
                    continue
                }
                if String(describing: row["state"] ?? "connected").lowercased() == "listening" {
                    continue
                }
                let stats = row["stats"] as? [String: Any] ?? [:]
                rxBytes += Self.intValue(from: stats["rx_bytes"]) ?? 0
                txBytes += Self.intValue(from: stats["tx_bytes"]) ?? 0
            }
        }
        return (rxBytes, txBytes)
    }

    private func trafficSnapshot(peerID: String, rxBytes rawRXBytes: Int, txBytes rawTXBytes: Int) -> [String: Any] {
        let now = Date().timeIntervalSince1970
        var rxBytes = max(0, rawRXBytes)
        var txBytes = max(0, rawTXBytes)
        var rxRate = 0.0
        var txRate = 0.0
        if let previous = peerTrafficRateState[peerID] {
            rxBytes = max(rxBytes, previous.rxBytes)
            txBytes = max(txBytes, previous.txBytes)
            let dt = max(0.000001, now - previous.timestamp)
            rxRate = max(0.0, Double(rxBytes - previous.rxBytes) / dt)
            txRate = max(0.0, Double(txBytes - previous.txBytes) / dt)
        }
        peerTrafficRateState[peerID] = (timestamp: now, rxBytes: rxBytes, txBytes: txBytes)
        return [
            "rx_bytes": rxBytes,
            "tx_bytes": txBytes,
            "rx_bytes_per_sec": rxRate,
            "tx_bytes_per_sec": txRate,
        ]
    }

    private func peerEndpointSnapshot() -> Any {
        let overlayTransport = Self.stringValue(from: bootstrapState["transport"]) ?? (Self.stringValue(from: runtimeConfig["overlay_transport"]) ?? "myudp")
        if overlayTransport == "myudp",
           let ownerSnapshot = withServiceStateQueue({ sharedUdpOverlayTransportOwner?.transportSnapshot() }),
           let host = ownerSnapshot["overlay_peer_host"] as? String,
           !host.isEmpty {
            return ["host": host, "port": ownerSnapshot["overlay_peer_port"] ?? NSNull()]
        }
        let host = bootstrapState["peer_host"] ?? (Self.peerHost(for: overlayTransport, payload: runtimeConfig) ?? "")
        let port: Any
        switch overlayTransport {
        case "tcp":
            port = Self.intValue(from: runtimeConfig["tcp_peer_port"]) ?? NSNull()
        case "ws":
            port = Self.intValue(from: runtimeConfig["ws_peer_port"]) ?? NSNull()
        case "quic":
            port = Self.intValue(from: runtimeConfig["quic_peer_port"]) ?? NSNull()
        default:
            port = Self.intValue(from: runtimeConfig["udp_peer_port"]) ?? NSNull()
        }
        if let hostString = host as? String, !hostString.isEmpty {
            return ["host": hostString, "port": port]
        }
        return NSNull()
    }

    private func resolvedPeerSnapshot(transport: String, transportRuntime: [String: Any]) -> [String: Any]? {
        let selectedRuntime = ObstacleBridgeAdminSnapshotSupport.selectedTransportRuntime(
            from: transportRuntime,
            preferredKind: transport
        )
        let host =
            Self.stringValue(from: selectedRuntime["overlay_peer_host"])
            ?? Self.stringValue(from: selectedRuntime["resolved_peer_host"])
            ?? Self.stringValue(from: transportRuntime["overlay_peer_host"])
            ?? Self.stringValue(from: transportRuntime["resolved_peer_host"])
            ?? ""
        guard !host.isEmpty else {
            return nil
        }
        let port =
            Self.intValue(from: selectedRuntime["overlay_peer_port"])
            ?? Self.intValue(from: selectedRuntime["resolved_peer_port"])
            ?? Self.intValue(from: transportRuntime["overlay_peer_port"])
            ?? Self.intValue(from: transportRuntime["resolved_peer_port"])
        let family =
            Self.stringValue(from: selectedRuntime["overlay_peer_family"])
            ?? Self.stringValue(from: selectedRuntime["resolved_peer_family"])
            ?? Self.stringValue(from: transportRuntime["overlay_peer_family"])
            ?? Self.stringValue(from: transportRuntime["resolved_peer_family"])
            ?? ""
        var snapshot: [String: Any] = [
            "host": host,
            "port": port ?? NSNull(),
        ]
        if !family.isEmpty {
            snapshot["family"] = family
        }
        return snapshot
    }

    private func transportRuntimeSnapshot() -> [String: Any] {
        let transport = Self.stringValue(from: bootstrapState["transport"]) ?? (Self.stringValue(from: runtimeConfig["overlay_transport"]) ?? "myudp")
        return ObstacleBridgeAdminSnapshotSupport.transportRuntimeEnvelope(
            kind: transport,
            status: bootstrapState["status"] ?? "unknown",
            myudp: udpRuntimeSnapshot(),
            tcp: tcpRuntimeSnapshot(),
            quic: quicRuntimeSnapshot(),
            websocket: webSocketRuntimeSnapshot()
        )
    }

    private func macOSTunHelperStatusSnapshot() -> [String: Any] {
        let configured = ownServerSpecs.contains { $0.listenProtocol == "tun" && $0.targetProtocol == "tun" }
#if os(macOS)
        let package = ObstacleBridgeMacOSTunHelperService.statusSnapshot()
#else
        let package: [String: Any] = [
            "install_supported": false,
            "xpc_reachable": false,
            "xpc_mach_service_name": "",
            "xpc_last_error": "macOS privileged helper package is not available on iOS",
        ]
#endif
        let state = withServiceStateQueue {
            (
                adapterPresent: macOSTunHelperClient?.isOpen ?? false,
                transport: macOSTunHelperClient?.transportKind ?? macOSTunHelperTransportKind,
                runtime: macOSTunHelperRuntimeSnapshot.payload()
            )
        }
        let phase: String
        if !configured {
            phase = "disabled"
        } else if state.adapterPresent {
            phase = "connected"
        } else {
            phase = "stopped"
        }
        let runtimeOpened = state.runtime["opened"] as? Bool ?? false
        let networkApplied = state.runtime["network_applied"] as? Bool ?? false
        let xpcReachable = package["xpc_reachable"] as? Bool ?? false
        let packageRuntime = package["xpc_runtime"] as? [String: Any] ?? [:]
        let packageRuntimeOpened = packageRuntime["opened"] as? Bool ?? false
        let runtimeIfname = String(describing: state.runtime["ifname"] ?? "")
        let packageRuntimeIfname = String(describing: packageRuntime["ifname"] ?? "")
        let helperRuntimeLost = configured
            && state.transport == "xpc"
            && xpcReachable
            && (runtimeOpened || networkApplied)
            && (!packageRuntimeOpened || packageRuntimeIfname != runtimeIfname)
        let helperDisconnect = configured && state.transport == "xpc" && (!xpcReachable || helperRuntimeLost)
        let disconnectReason: String
        if helperDisconnect {
            disconnectReason = xpcReachable ? "xpc_runtime_lost" : "xpc_unreachable"
        } else {
            disconnectReason = ""
        }
        let cleanupNeeded = helperDisconnect && (runtimeOpened || networkApplied)
        let cleanupAttempted = state.runtime["cleanup_attempted"] as? Bool ?? false
        let cleanupOK = state.runtime["cleanup_ok"] as? Bool ?? false
        let xpcMachServiceName = String(describing: package["xpc_mach_service_name"] ?? "")
        let socketDisplay = state.transport == "xpc" && !xpcMachServiceName.isEmpty
            ? xpcMachServiceName
            : state.transport
        var payload: [String: Any] = [
            "enabled": configured,
            "mode": ObstacleBridgeTunHelperPlatformScope.desktopHelperMode,
            "backend": ObstacleBridgeTunHelperPlatformScope.macOSBackend,
            "connected": state.adapterPresent,
            "server_started": state.adapterPresent,
            "apply_network": networkApplied,
            "lifecycle_phase": phase,
            "transport": state.transport,
            "socket_path": socketDisplay,
            "xpc_mach_service_name": xpcMachServiceName,
            "pid": ProcessInfo.processInfo.processIdentifier,
            "actual_ifname": state.runtime["ifname"] ?? "",
            "runtime_mtu": state.runtime["mtu"] ?? 0,
            "packets_from_runtime": state.runtime["packets_from_runtime"] ?? 0,
            "packets_to_runtime": state.runtime["packets_to_runtime"] ?? 0,
            "last_hook_action": state.runtime["last_hook_action"] ?? "",
            "last_failure": state.runtime["last_failure"] ?? [:],
            "helper_disconnect": helperDisconnect,
            "disconnect_reason": disconnectReason,
            "disconnect_detail": helperDisconnect ? String(describing: package["xpc_last_error"] ?? "") : "",
            "cleanup": [
                "needed": cleanupNeeded,
                "attempted": cleanupAttempted,
                "ok": cleanupNeeded ? cleanupOK : true,
            ],
            "package": package,
            "runtime": state.runtime,
            "ios_network_extension_boundary": ObstacleBridgeTunHelperPlatformScope.iOSUsesNetworkExtensionBoundary,
        ]
        let recovery = Self.macOSTunHelperRecoverySnapshot(
            helperDisconnect: helperDisconnect,
            runtime: state.runtime,
            networkApplied: networkApplied
        )
        if !recovery.isEmpty {
            payload["recovery"] = recovery
        }
        return payload
    }

    private static func macOSTunHelperRecoverySnapshot(
        helperDisconnect: Bool,
        runtime: [String: Any],
        networkApplied: Bool
    ) -> [String: Any] {
        guard helperDisconnect else {
            return [:]
        }
        let staleNetwork = networkApplied
            || (runtime["network_applied"] as? Bool ?? false)
            || !(runtime["last_apply_payload"] as? [String: Any] ?? [:]).isEmpty
        guard staleNetwork else {
            return [:]
        }
        return [
            "needs_manual_cleanup": true,
            "stale_firewall_possible": false,
            "stale_network_possible": true,
            "warnings": ["helper_owned_network_state_may_remain"],
            "summary": "Privileged TUN helper exited while helper-owned host state may still need manual cleanup.",
            "repair_hint": "Manual cleanup may be required: inspect helper-owned routes, addresses, and DNS state before restarting helper-backed TUN.",
            "repair_supported": false,
        ]
    }

    private func udpRuntimeSnapshot() -> [String: Any]? {
        withServiceStateQueue {
            sharedUdpOverlayTransportOwner?.transportSnapshot()
        }
    }

    private func webSocketRuntimeSnapshot() -> [String: Any]? {
        guard let runtime = sharedWebSocketOverlayRuntime else {
            return nil
        }
        let host = Self.stringValue(from: runtimeConfig["ws_peer"]) ?? ""
        let port = Self.intValue(from: runtimeConfig["ws_peer_port"]) ?? 0
        let useTLS = Self.boolValue(from: runtimeConfig["ws_tls"]) ?? false
        let path = Self.stringValue(from: runtimeConfig["ws_path"]) ?? "/"
        let subprotocol = Self.stringValue(from: runtimeConfig["ws_subprotocol"])
        let proxyMode = (Self.stringValue(from: runtimeConfig["ws_proxy_mode"]) ?? "off").lowercased()
        let proxyActive = proxyMode != "off"
        let socketConfig = runtime.socketConfigSnapshot(socketPresent: false, tcpUserTimeoutAvailable: true)
        let plan = runtime.buildConnectPlan(
            host: host,
            port: max(0, port),
            peerNameHost: host.isEmpty ? nil : host,
            peerNamePort: port > 0 ? port : nil,
            useTLS: useTLS,
            wsPath: path,
            wsSubprotocol: subprotocol,
            proxyActive: proxyActive
        )
        var snapshot: [String: Any] = [
            "payload_mode": bootstrapState["ws_payload_mode"] ?? (Self.stringValue(from: runtimeConfig["ws_payload_mode"]) ?? "binary"),
            "uri": plan.uri,
            "host": host,
            "port": port,
            "path": path,
            "subprotocol": subprotocol ?? NSNull(),
            "proxy_active": proxyActive,
            "proxy_mode": proxyMode,
            "preflight_required": plan.preflightRequired,
            "uses_proxy_socket": plan.usesProxySocket,
            "max_size": plan.maxSize,
            "compression_disabled": plan.compressionDisabled,
            "upgrade_headers": plan.upgradeHeaders,
            "keep_alive_enabled": socketConfig.keepAliveEnabled,
            "tcp_user_timeout_ms": socketConfig.tcpUserTimeoutMS ?? NSNull(),
        ]
        if let ownerSnapshot = withServiceStateQueue({ sharedWebSocketOverlayTransportOwner?.transportSnapshot() }) {
            for (key, value) in ownerSnapshot {
                if key == "uri",
                   let uri = value as? String,
                   uri.isEmpty {
                    continue
                }
                snapshot[key] = value
            }
        }
        return snapshot
    }

    private func tcpRuntimeSnapshot() -> [String: Any]? {
        guard let runtime = sharedTcpOverlayRuntime else {
            return nil
        }
        let threshold = Self.intValue(from: runtimeConfig["tcp_bp_wbuf_threshold"]) ?? 128 * 1024
        let socketConfig = runtime.socketConfigSnapshot(socketPresent: false)
        let backpressure = runtime.backpressureSnapshot(writeBufferSize: 0, threshold: threshold)
        var snapshot: [String: Any] = [
            "host": Self.stringValue(from: runtimeConfig["tcp_peer"]) ?? NSNull(),
            "port": Self.intValue(from: runtimeConfig["tcp_peer_port"]) ?? NSNull(),
            "keep_alive_enabled": socketConfig.keepAliveEnabled,
            "backpressure_threshold": threshold,
            "backpressure_signaled": backpressure.signaled,
        ]
        if let ownerSnapshot = withServiceStateQueue({ sharedTcpOverlayTransportOwner?.transportSnapshot() }) {
            for (key, value) in ownerSnapshot {
                snapshot[key] = value
            }
        }
        return snapshot
    }

    private func quicRuntimeSnapshot() -> [String: Any]? {
        guard let runtime = sharedQuicOverlayRuntime else {
            return nil
        }
        let threshold = 128 * 1024
        let socketConfig = runtime.socketConfigSnapshot(socketPresent: false)
        let backpressure = runtime.backpressureSnapshot(writeBufferSize: 0, threshold: threshold)
        var snapshot: [String: Any] = [
            "host": Self.stringValue(from: runtimeConfig["quic_peer"]) ?? NSNull(),
            "port": Self.intValue(from: runtimeConfig["quic_peer_port"]) ?? NSNull(),
            "bind_host": Self.stringValue(from: runtimeConfig["quic_bind"]) ?? "::",
            "bind_port": Self.intValue(from: runtimeConfig["quic_own_port"]) ?? 0,
            "alpn": Self.stringValue(from: runtimeConfig["quic_alpn"]) ?? "hq-29",
            "insecure": Self.boolValue(from: runtimeConfig["quic_insecure"]) ?? false,
            "keep_alive_enabled": socketConfig.keepAliveEnabled,
            "backpressure_threshold": threshold,
            "backpressure_signaled": backpressure.signaled,
        ]
        if let ownerSnapshot = withServiceStateQueue({ sharedQuicOverlayTransportOwner?.transportSnapshot() }) {
            for (key, value) in ownerSnapshot {
                snapshot[key] = value
            }
        }
        return snapshot
    }

    private func compressLayerSnapshot(peerID: Int?) -> [String: Any]? {
        guard let runtime = sharedCompressLayerRuntime else {
            return nil
        }
        let snapshot = runtime.statusSnapshot(peerID: peerID)
        return [
            "enabled": snapshot.enabled,
            "algorithm": snapshot.algorithm,
            "transport": snapshot.transport,
            "level": snapshot.level,
            "min_bytes": snapshot.minBytes,
            "compress_attempts_total": snapshot.compressAttemptsTotal,
            "compress_applied_total": snapshot.compressAppliedTotal,
            "compress_skipped_no_gain_total": snapshot.compressSkippedNoGainTotal,
            "compress_input_bytes_total": snapshot.compressInputBytesTotal,
            "compress_output_bytes_total": snapshot.compressOutputBytesTotal,
            "decompress_ok_total": snapshot.decompressOKTotal,
            "decompress_fail_total": snapshot.decompressFailTotal,
        ]
    }

    private func secureLinkSnapshot(defaultState: String) -> [String: Any] {
        let enabled = Self.boolValue(from: runtimeConfig["secure_link"]) ?? false
        let mode = Self.stringValue(from: runtimeConfig["secure_link_mode"]) ?? "off"
        guard enabled, let adapter = withServiceStateQueue({ sharedSecureLinkPskTransportAdapter }) else {
            return [
                "enabled": enabled,
                "mode": mode,
                "state": defaultState,
                "authenticated": false,
                "session_id": NSNull(),
                "rekey_supported": false,
                "rekey_in_progress": false,
                "last_event": "bootstrap",
                "last_event_unix_ts": NSNull(),
                "last_authenticated_unix_ts": NSNull(),
                "connected_since_unix_ts": NSNull(),
                "authenticated_sessions_total": 0,
                "rekeys_completed_total": 0,
                "handshake_attempts_total": 0,
                "consecutive_failures": 0,
                "retry_backoff_sec": 0.0,
                "next_retry_unix_ts": NSNull(),
                "recovery_enabled": false,
                "recovery_delay_sec": 0.0,
                "recovery_reconnect_sec": 0.0,
                "next_recovery_reconnect_unix_ts": NSNull(),
                "frames_passed_total": 0,
                "frames_dropped_total": 0,
                "peer_subject_id": "",
                "peer_subject_name": "",
                "peer_roles": [],
                "peer_deployment_id": "",
                "peer_serial": "",
                "issuer_id": "",
                "trust_validation_state": "n/a",
                "trust_failure_reason": "",
                "trust_failure_detail": "",
                "active_material_generation": 0,
                "last_material_reload_unix_ts": NSNull(),
                "last_material_reload_scope": "",
                "last_material_reload_result": "",
                "last_material_reload_detail": "",
                "trust_enforced_unix_ts": NSNull(),
                "disconnect_reason": "",
                "disconnect_detail": "",
            ]
        }

        let snapshot = adapter.statusSnapshot()
        let displayAuthenticated = snapshot.peerConfirmedAuthenticated
        let nowUnix = Int(Date().timeIntervalSince1970)
        if snapshot.sessionID == 0 {
            secureLinkSnapshotSessionID = 0
            secureLinkConnectedSinceUnixTs = nil
            secureLinkLastAuthenticatedUnixTs = nil
        } else if secureLinkSnapshotSessionID != snapshot.sessionID {
            secureLinkSnapshotSessionID = snapshot.sessionID
            secureLinkConnectedSinceUnixTs = nowUnix
            secureLinkLastAuthenticatedUnixTs = displayAuthenticated ? nowUnix : nil
        } else if displayAuthenticated, secureLinkLastAuthenticatedUnixTs == nil {
            secureLinkLastAuthenticatedUnixTs = nowUnix
        }
        let state: String
        if displayAuthenticated {
            state = "authenticated"
        } else if snapshot.authFailCode != 0 {
            state = "failed"
        } else if defaultState == "listening" {
            state = "listening"
        } else if snapshot.sessionID != 0 {
            state = "handshaking"
        } else {
            state = "waiting_transport"
        }

        return [
            "enabled": true,
            "mode": mode,
            "state": state,
            "authenticated": displayAuthenticated,
            "session_id": snapshot.sessionID == 0 ? NSNull() : snapshot.sessionID,
            "rekey_supported": snapshot.rekeySupported,
            "rekey_in_progress": snapshot.rekeyInProgress,
            "last_event": snapshot.lastEvent,
            "last_event_unix_ts": snapshot.lastEventUnixTs ?? NSNull(),
            "last_authenticated_unix_ts": displayAuthenticated ? (secureLinkLastAuthenticatedUnixTs ?? nowUnix) : NSNull(),
            "connected_since_unix_ts": snapshot.sessionID == 0 ? NSNull() : (secureLinkConnectedSinceUnixTs ?? nowUnix),
            "authenticated_sessions_total": snapshot.authenticatedSessionsTotal,
            "rekeys_completed_total": snapshot.rekeysCompletedTotal,
            "handshake_attempts_total": snapshot.handshakeAttemptsTotal,
            "consecutive_failures": snapshot.consecutiveFailures,
            "retry_backoff_sec": snapshot.retryBackoffSec,
            "next_retry_unix_ts": snapshot.nextRetryUnixTs ?? NSNull(),
            "recovery_enabled": snapshot.recoveryEnabled,
            "recovery_delay_sec": snapshot.recoveryDelaySec,
            "recovery_reconnect_sec": snapshot.recoveryReconnectSec,
            "next_recovery_reconnect_unix_ts": snapshot.nextRecoveryReconnectUnixTs ?? NSNull(),
            "last_rekey_trigger": snapshot.lastRekeyTrigger,
            "frames_passed_total": snapshot.framesPassedTotal,
            "frames_dropped_total": snapshot.framesDroppedTotal,
            "peer_subject_id": "",
            "peer_subject_name": "",
            "peer_roles": [],
            "peer_deployment_id": "",
            "peer_serial": "",
            "issuer_id": "",
            "trust_validation_state": snapshot.trustValidationState,
            "trust_failure_reason": snapshot.authFailCode == 0 ? "" : "psk_auth_failed",
            "trust_failure_detail": snapshot.authFailCode == 0 ? "" : "code=\(snapshot.authFailCode)",
            "active_material_generation": snapshot.sessionID == 0 ? 0 : 1,
            "last_material_reload_unix_ts": NSNull(),
            "last_material_reload_scope": "",
            "last_material_reload_result": "",
            "last_material_reload_detail": "",
            "trust_enforced_unix_ts": NSNull(),
            "disconnect_reason": snapshot.disconnectReason,
            "disconnect_detail": snapshot.disconnectDetail,
        ]
    }

    private func readLogLines(limit: Int) -> [String] {
        guard let path = configStore.debugLogFilePath(), !path.isEmpty,
              let text = try? String(contentsOfFile: path, encoding: .utf8) else {
            return []
        }
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        return Array(lines.suffix(max(1, min(limit, 1000))))
    }

    private func buildSummary() -> [String: Any] {
        if let sidecar = loadBuildSummaryFromSidecar() {
            return sidecar
        }

        let env = ProcessInfo.processInfo.environment
        let commit = (env["OBSTACLEBRIDGE_BUILD_COMMIT"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let source = (env["OBSTACLEBRIDGE_BUILD_SOURCE"] ?? "environment").trimmingCharacters(in: .whitespacesAndNewlines)
        let diffSHA = (env["OBSTACLEBRIDGE_BUILD_DIFF_SHA"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let tainted = Self.boolValue(from: env["OBSTACLEBRIDGE_BUILD_DIRTY"]) ?? false
        if !commit.isEmpty {
            return [
                "commit": commit,
                "source": source.isEmpty ? "environment" : source,
                "repo_root": "",
                "tainted": tainted,
                "tracked_changes": 0,
                "untracked_changes": 0,
                "available": true,
                "diff_sha": diffSHA,
            ]
        }

        return [
            "commit": "unknown",
            "source": "swift_host_runner",
            "repo_root": "",
            "tainted": false,
            "tracked_changes": 0,
            "untracked_changes": 0,
            "available": false,
            "diff_sha": "",
        ]
    }

    private func loadBuildSummaryFromSidecar() -> [String: Any]? {
        let executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
        let sidecarURL = executableURL
            .deletingLastPathComponent()
            .appendingPathComponent("\(executableURL.lastPathComponent).build-info.json")
        guard let data = try? Data(contentsOf: sidecarURL),
              let object = try? JSONSerialization.jsonObject(with: data),
              let payload = object as? [String: Any] else {
            return nil
        }
        let commit = Self.stringValue(from: payload["commit"] ?? payload["build_commit"]) ?? "unknown"
        let source = Self.stringValue(from: payload["source"] ?? payload["build_source"]) ?? "embedded"
        let diffSHA = Self.stringValue(from: payload["diff_sha"] ?? payload["build_diff_sha"]) ?? ""
        let repoRoot = Self.stringValue(from: payload["repo_root"]) ?? ""
        let available = Self.boolValue(from: payload["available"])
            ?? !(commit.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || commit == "unknown")
        let tainted = Self.boolValue(from: payload["tainted"] ?? payload["build_dirty"]) ?? false
        let trackedChanges = Self.intValue(from: payload["tracked_changes"]) ?? 0
        let untrackedChanges = Self.intValue(from: payload["untracked_changes"]) ?? 0
        return [
            "commit": commit,
            "source": source,
            "repo_root": repoRoot,
            "tainted": tainted,
            "tracked_changes": trackedChanges,
            "untracked_changes": untrackedChanges,
            "available": available,
            "diff_sha": diffSHA,
        ]
    }

    private func startOwnServers() throws {
        sharedChannelMuxUdpRuntime = ObstacleBridgeChannelMuxUdpRuntime(instanceID: 0, connectionSeq: 0)
        sharedChannelMuxTcpRuntime = ObstacleBridgeChannelMuxTcpRuntime()
        for spec in ownServerSpecs where spec.listenProtocol == "udp" && spec.targetProtocol == "udp" {
            try startUDPService(spec)
        }
        for spec in ownServerSpecs where spec.listenProtocol == "tcp" && spec.targetProtocol == "tcp" {
            try startTCPService(spec)
        }
    }

    private func stopOwnServers() {
        withServiceStateQueue {
            for connection in tcpConnectionObjects.values {
                connection.stop()
            }
            tcpConnectionObjects.removeAll()
            tcpConnectionStates.removeAll()
            for connection in udpConnectionObjects.values {
                connection.stop()
            }
            udpConnectionObjects.removeAll()
            udpConnectionStates.removeAll()
            for listener in tcpServiceListeners.values {
                listener.cancel()
            }
            tcpServiceListeners.removeAll()
            for listener in udpServiceListeners.values {
                listener.cancel()
            }
            udpServiceListeners.removeAll()
        }
    }

    private func teardownSharedMacOSTunAdapter(runLifecycleHook: Bool) {
        if runLifecycleHook,
           let tunService = ownServerSpecs.first(where: { $0.listenProtocol == "tun" && $0.targetProtocol == "tun" }) {
            runMacOSTunLifecycleHook(for: tunService, event: "on_stopped")
        }
        macOSTunHelperClient?.stop()
        if let client = macOSTunHelperClient {
            macOSTunHelperTransportKind = client.transportKind
            macOSTunHelperRuntimeSnapshot = client.runtimeSnapshot
        } else {
            macOSTunHelperRuntimeSnapshot.opened = false
            macOSTunHelperRuntimeSnapshot.networkApplied = false
        }
        macOSTunHelperClient = nil
        macOSTunChannelConnectedHookFired = false
    }

    private func startUDPService(_ spec: ObstacleBridgeNativeServiceSpec) throws {
        guard let port = NWEndpoint.Port(rawValue: UInt16(spec.listenPort)) else {
            throw ObstacleBridgeHostRunnerError.invalidArgument("invalid own_server udp listen port: \(spec.listenPort)")
        }
        let params = NWParameters.udp
        params.allowLocalEndpointReuse = true
        params.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(spec.listenBind), port: port)
        let listener = try NWListener(using: params)
        listener.newConnectionHandler = { [weak self] connection in
            self?.acceptUDPConnection(connection, spec: spec)
        }
        listener.start(queue: serviceStateQueue)
        withServiceStateQueue {
            udpServiceListeners[spec.svcID] = listener
        }
    }

    private func acceptUDPConnection(_ connection: NWConnection, spec: ObstacleBridgeNativeServiceSpec) {
        if let activeOwner = currentOverlayOwner(),
           activeOwner.owner.acceptLocalUDPConnection(
            connection,
            spec: spec.toChannelMuxServiceSpec(),
            listenerHost: spec.listenBind,
            listenerPort: spec.listenPort,
            serviceKey: "svc-\(spec.svcID)"
           ) {
            return
        }
        guard let remotePort = NWEndpoint.Port(rawValue: UInt16(spec.targetPort)) else {
            connection.cancel()
            return
        }
        let remote = NWConnection(host: NWEndpoint.Host(spec.targetHost), port: remotePort, using: .udp)
        var proxy: ObstacleBridgeUDPProxyConnection!
        proxy = ObstacleBridgeUDPProxyConnection(
            spec: spec,
            listenerHost: spec.listenBind,
            listenerPort: spec.listenPort,
            runtime: sharedChannelMuxUdpRuntime,
            localConnection: connection,
            remoteConnection: remote,
            queue: serviceStateQueue,
            updateState: { [weak self] state in
                self?.serviceStateQueue.async {
                    if let state, let chanID = state["chan_id"] as? Int {
                        self?.udpConnectionStates[chanID] = state
                    }
                }
            },
            finish: { [weak self] chanID in
                self?.serviceStateQueue.async {
                    if let chanID {
                        self?.udpConnectionStates.removeValue(forKey: chanID)
                    }
                    self?.udpConnectionObjects.removeValue(forKey: ObjectIdentifier(proxy))
                }
            }
        )
        serviceStateQueue.async {
            self.udpConnectionObjects[ObjectIdentifier(proxy)] = proxy
            proxy.start()
        }
    }

    private func startTCPService(_ spec: ObstacleBridgeNativeServiceSpec) throws {
        guard let port = NWEndpoint.Port(rawValue: UInt16(spec.listenPort)) else {
            throw ObstacleBridgeHostRunnerError.invalidArgument("invalid own_server tcp listen port: \(spec.listenPort)")
        }
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        params.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(spec.listenBind), port: port)
        let listener = try NWListener(using: params)
        listener.newConnectionHandler = { [weak self] connection in
            self?.acceptTCPConnection(connection, spec: spec)
        }
        listener.start(queue: serviceStateQueue)
        withServiceStateQueue {
            tcpServiceListeners[spec.svcID] = listener
        }
    }

    private func acceptTCPConnection(_ connection: NWConnection, spec: ObstacleBridgeNativeServiceSpec) {
        if let activeOwner = currentOverlayOwner(),
           activeOwner.owner.acceptLocalTCPConnection(
            connection,
            spec: spec.toChannelMuxServiceSpec(),
            listenerHost: spec.listenBind,
            listenerPort: spec.listenPort
           ) {
            return
        }
        let acceptSnapshot = try? sharedChannelMuxTcpRuntime.handleAcceptedServerConnection(
            spec: spec.toChannelMuxServiceSpec(),
            overlayConnected: true,
            acceptingEnabled: true
        )
        guard let acceptSnapshot else {
            connection.cancel()
            return
        }
        let remotePort = NWEndpoint.Port(rawValue: UInt16(spec.targetPort)) ?? 0
        let remote = NWConnection(host: NWEndpoint.Host(spec.targetHost), port: remotePort, using: .tcp)
        let proxy = ObstacleBridgeTCPProxyConnection(
            chanID: acceptSnapshot.chanID,
            spec: spec,
            listenerHost: spec.listenBind,
            listenerPort: spec.listenPort,
            runtime: sharedChannelMuxTcpRuntime,
            localConnection: connection,
            remoteConnection: remote,
            queue: serviceStateQueue,
            updateState: { [weak self] state in
                self?.serviceStateQueue.async {
                    self?.tcpConnectionStates[acceptSnapshot.chanID] = state
                }
            },
            finish: { [weak self] (chanID: Int) in
                self?.serviceStateQueue.async {
                    self?.tcpConnectionStates.removeValue(forKey: chanID)
                    self?.tcpConnectionObjects.removeValue(forKey: chanID)
                }
            }
        )
        serviceStateQueue.async {
            self.tcpConnectionObjects[acceptSnapshot.chanID] = proxy
            self.tcpConnectionStates[acceptSnapshot.chanID] = proxy.snapshot()
            proxy.start()
        }
    }

    private func connectionsSnapshot() -> [String: Any] {
        cachedConnectionsOrBuild()
    }

    private func connectionsSnapshotUncached() -> [String: Any] {
        withServiceStateQueue {
            let wsOverlayRows = sharedWebSocketOverlayTransportOwner?.connectionRows()
            let tcpOverlayRows = sharedTcpOverlayTransportOwner?.connectionRows()
            let quicOverlayRows = sharedQuicOverlayTransportOwner?.connectionRows()
            let udpOverlayRows = sharedUdpOverlayTransportOwner?.connectionRows()
            let tcpListeningRows = listeningRows(protocol: "tcp")
            let udpListeningRows = listeningRows(protocol: "udp")
            let tunListeningRows = listeningRows(protocol: "tun")
            let udpConnectedRows = mergedConnectionRows(
                localRows: Array(udpConnectionStates.values),
                overlayRows: [wsOverlayRows?.udp, tcpOverlayRows?.udp, quicOverlayRows?.udp, udpOverlayRows?.udp]
            )
            let tcpConnectedRows = mergedConnectionRows(
                localRows: Array(tcpConnectionStates.values),
                overlayRows: [wsOverlayRows?.tcp, tcpOverlayRows?.tcp, quicOverlayRows?.tcp, udpOverlayRows?.tcp]
            )
            let tunConnectedRows = mergedConnectionRows(
                localRows: [],
                overlayRows: [wsOverlayRows?.tun, tcpOverlayRows?.tun, quicOverlayRows?.tun, udpOverlayRows?.tun]
            )
            let udpRows = sortedConnectionRows(udpConnectedRows + udpListeningRows)
            let tcpRows = sortedConnectionRows(tcpConnectedRows + tcpListeningRows)
            let tunRows = sortedConnectionRows(tunConnectedRows + tunListeningRows)
            return [
                "udp": udpRows,
                "tcp": tcpRows,
                "tun": tunRows,
                "counts": [
                    "udp": udpConnectedRows.count,
                    "tcp": tcpConnectedRows.count,
                    "tun": tunConnectedRows.count,
                    "udp_listening": udpListeningRows.count,
                    "tcp_listening": tcpListeningRows.count,
                    "tun_listening": tunListeningRows.count,
                ],
            ]
        }
    }

    private func listeningRows(protocol protocolName: String) -> [[String: Any]] {
        ownServerSpecs
            .filter { $0.listenProtocol == protocolName && $0.targetProtocol == protocolName }
            .map { listeningRow(for: $0, protocol: protocolName) }
    }

    private func listeningRow(for spec: ObstacleBridgeNativeServiceSpec, protocol protocolName: String) -> [String: Any] {
        var row: [String: Any] = [
            "protocol": protocolName,
            "role": "server",
            "state": "listening",
            "chan_id": NSNull(),
            "svc_id": spec.svcID,
            "service_name": spec.name ?? "",
            "source": NSNull(),
            "local": ["host": spec.listenBind, "port": spec.listenPort],
            "local_port": spec.listenPort,
            "remote_destination": ["host": spec.targetHost, "port": spec.targetPort],
            "stats": ["rx_msgs": 0, "tx_msgs": 0, "rx_bytes": 0, "tx_bytes": 0],
        ]
        if protocolName == "tun" {
            row["shared_tun_ownership"] = sharedTunRuntimeOwnershipSnapshot(for: spec) ?? NSNull()
        }
        return row
    }

    private func mergedConnectionRows(
        localRows: [[String: Any]],
        overlayRows: [[[String: Any]]?]
    ) -> [[String: Any]] {
        var rows = localRows
        for overlay in overlayRows {
            if let overlay {
                rows.append(contentsOf: overlay)
            }
        }
        return rows
    }

    private func sortedConnectionRows(_ rows: [[String: Any]]) -> [[String: Any]] {
        rows.sorted { lhs, rhs in
            let leftListening = String(describing: lhs["state"] ?? "") == "listening"
            let rightListening = String(describing: rhs["state"] ?? "") == "listening"
            if leftListening != rightListening {
                return !leftListening && rightListening
            }
            let leftChan = lhs["chan_id"] as? Int ?? -1
            let rightChan = rhs["chan_id"] as? Int ?? -1
            return leftChan < rightChan
        }
    }

    private func sharedTunRuntimeOwnershipSnapshot(for spec: ObstacleBridgeNativeServiceSpec) -> [String: Any]? {
        guard
            let ownershipValue = ObstacleBridgeChannelMuxCodec.sharedTunOwnershipSnapshot(for: spec.toChannelMuxServiceSpec()),
            let ownership = ObstacleBridgeChannelMuxCodec.foundationObject(from: ownershipValue) as? [String: Any]
        else {
            return nil
        }
        var runtime = ownership
        runtime["active_peer_bindings"] = []
        runtime["throttle_scopes"] = []
        runtime["drop_counters"] = ["total": 0, "by_reason": [:] as [String: Int]]
        runtime["recent_drops"] = []
        return runtime
    }

    private func withServiceStateQueue<T>(_ body: () -> T) -> T {
        if DispatchQueue.getSpecific(key: Self.serviceStateQueueKey) != nil {
            return body()
        }
        return serviceStateQueue.sync(execute: body)
    }

    private func controlActionSnapshot() -> [String: Any] {
        controlActionQueue.sync {
            controlActionSnapshotLocked()
        }
    }

    private func controlActionSnapshotLocked() -> [String: Any] {
        [
            "restart_supported": true,
            "reconnect_supported": true,
            "shutdown_supported": true,
            "restart_count": restartCount,
            "reconnect_count": reconnectCount,
            "shutdown_requested": shutdownRequestedAt != nil,
            "shutdown_requested_unix_ts": shutdownRequestedAt.map { Int($0.timeIntervalSince1970) } ?? NSNull(),
        ]
    }

    private func recordRestartControlAction() -> [String: Any] {
        controlActionQueue.sync {
            restartCount += 1
            return controlActionSnapshotLocked()
        }
    }

    private func recordReconnectControlAction() -> [String: Any] {
        controlActionQueue.sync {
            reconnectCount += 1
            return controlActionSnapshotLocked()
        }
    }

    private func recordShutdownControlAction() -> [String: Any] {
        controlActionQueue.sync {
            shutdownRequestedAt = Date()
            return controlActionSnapshotLocked()
        }
    }

    private func adminRuntimeDependenciesPayload() -> [String: Any] {
        ObstacleBridgeAdminWebSupport.adminRuntimeDependenciesPayload()
    }

    private func adminUIPayload() -> [String: Any] {
        var payload = ObstacleBridgeAdminWebSupport.adminUIPayload(
            runtimeConfig: runtimeConfig,
            platform: "darwin",
            runtimeDependencies: adminRuntimeDependenciesPayload()
        )
        let firstStartDetected = (payload["first_start_detected"] as? Bool) ?? false
        payload["config_file_state"] = firstStartDetected ? "empty" : "unknown"
        return payload
    }

    private func securityAdvisorPayload() -> [String: Any] {
        ObstacleBridgeAdminWebSupport.securityAdvisorPayload(
            runtimeConfig: runtimeConfig,
            bindHostFallback: bindHost
        )
    }

    private func maskedRuntimeConfigSnapshot() -> [String: Any] {
        ObstacleBridgeRuntimeConfig.maskedConfigSnapshot(runtimeConfig)
    }

    private func adminAuthUsername() -> String {
        Self.stringValue(from: runtimeConfig["admin_web_username"]) ?? ""
    }

    private func adminAuthPassword() -> String {
        Self.stringValue(from: runtimeConfig["admin_web_password"]) ?? ""
    }

    private func pruneAuthState() {
        adminConfigChallengeStore.reset()
    }

    private func resetAuthState() {
        adminConfigChallengeStore.reset()
        adminAuth.resetState()
    }

    private func adminWebToken() -> String {
        Self.stringValue(from: runtimeConfig["admin_web_token"]) ?? ""
    }

    private func adminSessionCookieScope() -> String {
        [bindHost, String(statusPort), Self.stringValue(from: runtimeConfig["admin_web_path"]) ?? "/"].joined(separator: "|")
    }

    private func issueConfigChallenge(updates: [String: Any]) throws -> [String: Any] {
        try adminConfigChallengeStore.issueChallenge(updates: updates)
    }

    private func validateConfigChallenge(challengeID: String, proof: String, updates: [String: Any]) -> String? {
        adminConfigChallengeStore.validate(challengeID: challengeID, proof: proof, updates: updates)
    }

    private func onboardingConnectionProfiles() -> [[String: Any]] {
        ObstacleBridgeOnboarding.connectionProfiles(runtimeConfig: runtimeConfig)
    }

    private func onboardingBlueprints() -> [[String: Any]] {
        []
    }

    private func normalizedConfigUpdates(_ updates: [String: Any]) -> [String: Any] {
        var normalized = updates
        if (normalized["admin_web_auth_disable"] as? Bool) == true {
            normalized["admin_web_username"] = ""
            normalized["admin_web_password"] = ""
        } else if
            let password = normalized["admin_web_password"] as? String,
            password.isEmpty,
            (Self.boolValue(from: runtimeConfig["admin_web_auth_disable"]) ?? false),
            normalized["admin_web_auth_disable"] == nil
        {
            normalized["admin_web_username"] = ""
            normalized["admin_web_auth_disable"] = true
        }
        return normalized
    }

    private func persistConfigUpdates(_ updates: [String: Any]) throws {
        let result = try ObstacleBridgeAdminConfigSupport.validatedNextRawConfig(
            currentRawConfig: runtimeConfigRaw,
            currentRuntimeConfig: runtimeConfig,
            updates: normalizedConfigUpdates(updates)
        )
        let nextRaw = result.nextRawConfig
        let persistedPayload = try ObstacleBridgeConfigSecretCodec.encryptPayload(nextRaw)
        let data = try JSONSerialization.data(withJSONObject: persistedPayload, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: URL(fileURLWithPath: runtimeConfigPath), options: [.atomic])
        runtimeConfigRaw = nextRaw
        runtimeConfig = ObstacleBridgeRuntimeConfig.flatten(nextRaw)
        configStore.updateConfigs(groupedConfig: nextRaw, runtimeConfig: runtimeConfig)
    }

    private func requestRestart() -> [String: Any] {
        do {
            try reloadRuntimeStateForControlAction()
        } catch {
            return [
                "ok": false,
                "error": error.localizedDescription,
                "restart_requested": false,
                "control_actions": controlActionSnapshot(),
            ]
        }
        let controlActions = recordRestartControlAction()
        return [
            "ok": true,
            "restart_requested": true,
            "restart_supported": true,
            "restart_delay_sec": 0,
            "restart_mode": "immediate",
            "restart_embedded": true,
            "control_actions": controlActions,
            "bootstrap_state": bootstrapState,
        ]
    }

    private func requestReconnect() -> [String: Any] {
        do {
            try reloadRuntimeStateForControlAction()
        } catch {
            return [
                "ok": false,
                "error": error.localizedDescription,
                "reconnect_requested": false,
                "control_actions": controlActionSnapshot(),
            ]
        }
        let controlActions = recordReconnectControlAction()
        return [
            "ok": true,
            "reconnect_requested": true,
            "reconnect_supported": true,
            "restart_embedded": true,
            "control_actions": controlActions,
            "bootstrap_state": bootstrapState,
        ]
    }

    private func requestShutdown() -> [String: Any] {
        let controlActions = recordShutdownControlAction()
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.2) {
            exit(0)
        }
        return [
            "ok": true,
            "shutdown_requested": true,
            "control_actions": controlActions,
        ]
    }

    private func prepareSharedOverlayBootstrap() {
        macOSTunHelperClient?.stop()
        if let client = macOSTunHelperClient {
            macOSTunHelperTransportKind = client.transportKind
        }
        sharedWebSocketOverlayTransportOwner?.stop()
        sharedTcpOverlayTransportOwner?.stop()
        sharedQuicOverlayTransportOwner?.stop()
        sharedUdpOverlayTransportOwner?.stop()
        sharedCompressLayerRuntime = nil
        sharedSecureLinkPskTransportAdapter = nil
        sharedOverlayLayerTransportAdapter = nil
        sharedWebSocketOverlayRuntime = nil
        sharedTcpOverlayRuntime = nil
        sharedQuicOverlayRuntime = nil
        sharedWebSocketOverlayTransportOwner = nil
        sharedTcpOverlayTransportOwner = nil
        sharedQuicOverlayTransportOwner = nil
        sharedUdpOverlayTransportOwner = nil
        if let client = macOSTunHelperClient {
            macOSTunHelperRuntimeSnapshot = client.runtimeSnapshot
        }
        macOSTunHelperClient = nil
        macOSTunChannelConnectedHookFired = false
        macOSOverlayUnderlayGatewayV4 = ""
        macOSOverlayUnderlayInterfaceV4 = ""
        bootstrapState = [:]

        do {
            let settings = try ObstacleBridgeOverlayBootstrapSettings(payload: runtimeConfig)
            var summary = settings.summary(runtimeConfigGrouped: ObstacleBridgeRuntimeConfig.looksGrouped(runtimeConfigRaw))

            if settings.compressWrapped {
                let allowedMTypes = ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["compress_layer_types"]) ?? "data,data_frag"
                let level = ObstacleBridgeRuntimeConfig.intValue(from: runtimeConfig["compress_layer_level"]) ?? 3
                let minBytes = ObstacleBridgeRuntimeConfig.intValue(from: runtimeConfig["compress_layer_min_bytes"]) ?? 64
                sharedCompressLayerRuntime = ObstacleBridgeCompressLayerRuntime(
                    configuredEnabled: settings.compressEnabled,
                    algorithm: settings.compressAlgo,
                    transportName: settings.transport,
                    level: level,
                    minBytes: minBytes,
                    allowedMTypesRaw: allowedMTypes,
                    peerSelectedLevel: level,
                    peerSelectedMinBytes: minBytes,
                    peerSelectedAllowedMTypesRaw: allowedMTypes
                )
                summary["compress_runtime"] = "ready"
                summary["compress_layer_types"] = allowedMTypes
            }

            if settings.secureLinkMode == "psk" {
                let rekeyAfterFrames = Self.intValue(from: runtimeConfig["secure_link_rekey_after_frames"]) ?? 0
                let rekeyAfterSeconds = Self.doubleValue(from: runtimeConfig["secure_link_rekey_after_seconds"]) ?? 0.0
                let retryBackoffInitialMS = Self.intValue(from: runtimeConfig["secure_link_retry_backoff_initial_ms"]) ?? 1000
                let retryBackoffMaxMS = Self.intValue(from: runtimeConfig["secure_link_retry_backoff_max_ms"]) ?? 5000
                let recoverAfterFailure = Self.boolValue(from: runtimeConfig["secure_link_recover_after_failure"]) ?? true
                let recoverDelaySeconds = Self.doubleValue(from: runtimeConfig["secure_link_recover_delay_seconds"]) ?? 30.0
                sharedSecureLinkPskTransportAdapter = ObstacleBridgeSecureLinkPskTransportAdapter(
                    runtime: ObstacleBridgeSecureLinkPskRuntime(
                        clientMode: settings.peerHost != nil,
                        psk: settings.secureLinkPSK,
                        rekeyAfterFrames: rekeyAfterFrames,
                        rekeyAfterSeconds: rekeyAfterSeconds
                    ),
                    retryBackoffInitialMS: retryBackoffInitialMS,
                    retryBackoffMaxMS: retryBackoffMaxMS,
                    recoverAfterFailure: recoverAfterFailure,
                    recoverDelaySeconds: recoverDelaySeconds
                )
                summary["secure_link_runtime"] = "ready"
                summary["secure_link_rekey_after_frames"] = rekeyAfterFrames
                summary["secure_link_rekey_after_seconds"] = rekeyAfterSeconds
                summary["secure_link_retry_backoff_initial_ms"] = retryBackoffInitialMS
                summary["secure_link_retry_backoff_max_ms"] = retryBackoffMaxMS
                summary["secure_link_recover_after_failure"] = recoverAfterFailure
                summary["secure_link_recover_delay_seconds"] = recoverDelaySeconds
            }

            if sharedCompressLayerRuntime != nil || sharedSecureLinkPskTransportAdapter != nil {
                sharedOverlayLayerTransportAdapter = ObstacleBridgeOverlayLayerTransportAdapter(
                    compressRuntime: sharedCompressLayerRuntime,
                    secureLinkAdapter: sharedSecureLinkPskTransportAdapter
                )
            }

            if settings.transport == "ws" {
                let payloadMode = ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["ws_payload_mode"]) ?? "binary"
                let maxSize = ObstacleBridgeRuntimeConfig.intValue(from: runtimeConfig["ws_max_size"]) ?? 65535
                let sendTimeout = ObstacleBridgeRuntimeConfig.doubleValue(from: runtimeConfig["ws_send_timeout"]) ?? 3.0
                let tcpUserTimeout = ObstacleBridgeRuntimeConfig.intValue(from: runtimeConfig["ws_tcp_user_timeout_ms"]) ?? 10000
                let reconnectGrace = ObstacleBridgeRuntimeConfig.doubleValue(from: runtimeConfig["ws_reconnect_grace"]) ?? 3.0
                sharedWebSocketOverlayRuntime = try ObstacleBridgeWebSocketOverlayRuntime(
                    payloadMode: payloadMode,
                    wsMaxSize: maxSize,
                    sendTimeoutS: sendTimeout,
                    tcpUserTimeoutMS: tcpUserTimeout,
                    reconnectGraceS: reconnectGrace
                )
                summary["websocket_runtime"] = "ready"
                summary["ws_payload_mode"] = payloadMode
            }

            if settings.transport == "tcp" {
                let threshold = ObstacleBridgeRuntimeConfig.intValue(from: runtimeConfig["tcp_bp_wbuf_threshold"]) ?? 128 * 1024
                sharedTcpOverlayRuntime = ObstacleBridgeTcpOverlayRuntime(wbufThreshold: threshold)
                summary["tcp_runtime"] = "ready"
                summary["tcp_bp_wbuf_threshold"] = threshold
            }

            if settings.transport == "quic" {
                sharedQuicOverlayRuntime = ObstacleBridgeQuicOverlayRuntime(wbufThreshold: 128 * 1024)
                summary["quic_runtime"] = "ready"
                summary["quic_alpn"] = ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["quic_alpn"]) ?? "hq-29"
                summary["quic_insecure"] = ObstacleBridgeRuntimeConfig.boolValue(from: runtimeConfig["quic_insecure"]) ?? false
            }

            if settings.transport == "myudp" {
                summary["udp_runtime"] = "ready"
            }

            summary["admin_web_enabled"] = ObstacleBridgeRuntimeConfig.boolValue(from: runtimeConfig["admin_web"]) ?? false
            summary["admin_web_bind"] = bindHost
            summary["admin_web_port"] = statusPort
            bootstrapState = summary
        } catch {
            bootstrapState = [
                "status": "failed",
                "overlay_transport": ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["overlay_transport"]) ?? "myudp",
                "error": error.localizedDescription,
                "admin_web_bind": bindHost,
                "admin_web_port": statusPort,
            ]
        }
    }

    static func stringValue(from value: Any?) -> String? {
        ObstacleBridgeRuntimeConfig.stringValue(from: value)
    }

    private static func intValue(from value: Any?) -> Int? {
        ObstacleBridgeRuntimeConfig.intValue(from: value)
    }

    private static func doubleValue(from value: Any?) -> Double? {
        ObstacleBridgeRuntimeConfig.doubleValue(from: value)
    }

    private static func boolValue(from value: Any?) -> Bool? {
        ObstacleBridgeRuntimeConfig.boolValue(from: value)
    }

    private static func peerHost(for transport: String, payload: [String: Any]) -> String? {
        ObstacleBridgeRuntimeConfig.peerHost(for: transport, payload: payload)
    }

    private func startSharedWebSocketOverlayTransportOwnerIfNeeded() {
        guard let runtime = sharedWebSocketOverlayRuntime,
              (Self.stringValue(from: runtimeConfig["overlay_transport"]) ?? "").lowercased() == "ws"
        else {
            return
        }
        let peerHost = Self.stringValue(from: runtimeConfig["ws_peer"]) ?? ""
        let peerAddresses = ObstacleBridgeRuntimeConfig.wsPeerAddresses(from: runtimeConfig["ws_peer_addresses"])
        let peerPort = Self.intValue(from: runtimeConfig["ws_peer_port"]) ?? 0
        let peerResolveFamily = Self.stringValue(from: runtimeConfig["ws_peer_resolve_family"]) ?? "prefer-ipv6"
        guard !peerHost.isEmpty, peerPort > 0 else {
            return
        }
        let useTLS = Self.boolValue(from: runtimeConfig["ws_tls"]) ?? false
        let wsPath = Self.stringValue(from: runtimeConfig["ws_path"]) ?? "/"
        let wsSubprotocol = Self.stringValue(from: runtimeConfig["ws_subprotocol"])
        let tunService = ownServerSpecs.first { $0.listenProtocol == "tun" && $0.targetProtocol == "tun" }
        let tunnelRouting = ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: runtimeConfig)
        let muxInstanceID = UInt64.random(in: 1...UInt64.max)
        let muxConnectionSeq = UInt32.random(in: 1...UInt32.max)
        let owner = ObstacleBridgeWebSocketOverlayTransportOwner(
            peerHost: peerHost,
            peerAddresses: peerAddresses,
            peerPort: peerPort,
            peerResolveFamily: peerResolveFamily,
            useTLS: useTLS,
            wsPath: wsPath,
            wsSubprotocol: wsSubprotocol,
            overlayRuntime: runtime,
            reconnectRetryDelayMS: Self.intValue(from: runtimeConfig["overlay_reconnect_retry_delay_ms"]) ?? 30000,
            sessionMaxAppPayload: ObstacleBridgeRuntimeConfig.overlaySessionMaxAppPayload(from: runtimeConfig),
            overlayLayerTransportAdapter: sharedOverlayLayerTransportAdapter,
            startupMuxFrames: remoteServiceCatalogMuxFrames(
                instanceID: muxInstanceID,
                connectionSeq: muxConnectionSeq
            ),
            queue: serviceStateQueue,
            serviceNameByID: Dictionary(uniqueKeysWithValues: ownServerSpecs.map { ($0.svcID, $0.name ?? "") }),
            tunServiceSpec: tunService?.toChannelMuxServiceSpec(),
            tunIfname: tunService?.listenBind,
            tunMTU: tunService?.listenPort ?? 0,
            tunLocalAddress: tunnelRouting?.tunnelAddress,
            tunLocalAddress6: tunnelRouting?.tunnelAddress6,
            sharedTunDisableOutgoingNormalization: tunnelRouting?.sharedTunDisableOutgoingNormalization ?? false,
            sharedTunDisableInflowFilter: tunnelRouting?.sharedTunDisableInflowFilter ?? false,
            sharedTunDisableOutflowFilter: tunnelRouting?.sharedTunDisableOutflowFilter ?? false,
            sharedTunDisableScopedThrottle: tunnelRouting?.sharedTunDisableScopedThrottle ?? false,
            tunPacketSink: { [weak self] packet in
                self?.deliverRemoteTunPacketToLocalAdapter(packet)
            },
            muxInstanceID: muxInstanceID,
            muxConnectionSeq: muxConnectionSeq,
            eventSink: { [weak self] event, fields in
                self?.handleSharedOverlayOwnerEvent(event: event, fields: fields)
            }
        )
        sharedWebSocketOverlayTransportOwner = owner
        owner.start()
    }

    private func startSharedTCPOverlayTransportOwnerIfNeeded() {
        guard let runtime = sharedTcpOverlayRuntime,
              (Self.stringValue(from: runtimeConfig["overlay_transport"]) ?? "").lowercased() == "tcp"
        else {
            return
        }
        let peerHost = Self.stringValue(from: runtimeConfig["tcp_peer"]) ?? ""
        let peerPort = Self.intValue(from: runtimeConfig["tcp_peer_port"]) ?? 0
        let peerResolveFamily = Self.stringValue(from: runtimeConfig["tcp_peer_resolve_family"]) ?? "prefer-ipv6"
        let bindHost = Self.stringValue(from: runtimeConfig["tcp_bind"]) ?? "0.0.0.0"
        let bindPort = Self.intValue(from: runtimeConfig["tcp_own_port"]) ?? 0
        guard (!peerHost.isEmpty && peerPort > 0) || bindPort > 0 else {
            return
        }
        let tunService = ownServerSpecs.first { $0.listenProtocol == "tun" && $0.targetProtocol == "tun" }
        let tunnelRouting = ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: runtimeConfig)
        let muxInstanceID = UInt64.random(in: 1...UInt64.max)
        let muxConnectionSeq = UInt32.random(in: 1...UInt32.max)
        let owner = ObstacleBridgeTcpOverlayTransportOwner(
            peerHost: peerHost,
            peerPort: peerPort,
            peerResolveFamily: peerResolveFamily,
            bindHost: bindHost,
            bindPort: bindPort,
            overlayRuntime: runtime,
            reconnectRetryDelayMS: Self.intValue(from: runtimeConfig["overlay_reconnect_retry_delay_ms"]) ?? 30000,
            sessionMaxAppPayload: ObstacleBridgeRuntimeConfig.overlaySessionMaxAppPayload(from: runtimeConfig),
            overlayLayerTransportAdapter: sharedOverlayLayerTransportAdapter,
            startupMuxFrames: remoteServiceCatalogMuxFrames(
                instanceID: muxInstanceID,
                connectionSeq: muxConnectionSeq
            ),
            queue: serviceStateQueue,
            serviceNameByID: Dictionary(uniqueKeysWithValues: ownServerSpecs.map { ($0.svcID, $0.name ?? "") }),
            tunServiceSpec: tunService?.toChannelMuxServiceSpec(),
            tunIfname: tunService?.listenBind,
            tunMTU: tunService?.listenPort ?? 0,
            tunLocalAddress: tunnelRouting?.tunnelAddress,
            tunLocalAddress6: tunnelRouting?.tunnelAddress6,
            sharedTunDisableOutgoingNormalization: tunnelRouting?.sharedTunDisableOutgoingNormalization ?? false,
            sharedTunDisableInflowFilter: tunnelRouting?.sharedTunDisableInflowFilter ?? false,
            sharedTunDisableOutflowFilter: tunnelRouting?.sharedTunDisableOutflowFilter ?? false,
            sharedTunDisableScopedThrottle: tunnelRouting?.sharedTunDisableScopedThrottle ?? false,
            tunPacketSink: { [weak self] packet in
                self?.deliverRemoteTunPacketToLocalAdapter(packet)
            },
            muxInstanceID: muxInstanceID,
            muxConnectionSeq: muxConnectionSeq,
            eventSink: { [weak self] event, fields in
                self?.handleSharedOverlayOwnerEvent(event: event, fields: fields)
            }
        )
        sharedTcpOverlayTransportOwner = owner
        owner.start()
    }

    private func startSharedQUICOverlayTransportOwnerIfNeeded() {
        guard let runtime = sharedQuicOverlayRuntime,
              (Self.stringValue(from: runtimeConfig["overlay_transport"]) ?? "").lowercased() == "quic"
        else {
            return
        }
        guard #available(iOS 15.0, *) else {
            handleSharedOverlayOwnerEvent(event: "quic_overlay_unavailable", fields: [
                "reason": "quic overlay requires iOS 15.0 or newer"
            ])
            return
        }
        let peerHost = Self.stringValue(from: runtimeConfig["quic_peer"]) ?? ""
        let peerPort = Self.intValue(from: runtimeConfig["quic_peer_port"]) ?? 0
        guard !peerHost.isEmpty, peerPort > 0 else {
            return
        }
        let bindHost = Self.stringValue(from: runtimeConfig["quic_bind"]) ?? "::"
        let bindPort = Self.intValue(from: runtimeConfig["quic_own_port"]) ?? 0
        let peerResolveFamily = Self.stringValue(from: runtimeConfig["quic_peer_resolve_family"]) ?? "prefer-ipv6"
        let alpn = Self.stringValue(from: runtimeConfig["quic_alpn"]) ?? "hq-29"
        let insecure = Self.boolValue(from: runtimeConfig["quic_insecure"]) ?? false
        let tunService = ownServerSpecs.first { $0.listenProtocol == "tun" && $0.targetProtocol == "tun" }
        let tunnelRouting = ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: runtimeConfig)
        let muxInstanceID = UInt64.random(in: 1...UInt64.max)
        let muxConnectionSeq = UInt32.random(in: 1...UInt32.max)
        let owner = ObstacleBridgeQuicOverlayTransportOwner(
            peerHost: peerHost,
            peerPort: peerPort,
            bindHost: bindHost,
            bindPort: bindPort,
            peerResolveFamily: peerResolveFamily,
            alpn: alpn,
            insecure: insecure,
            overlayRuntime: runtime,
            reconnectRetryDelayMS: Self.intValue(from: runtimeConfig["overlay_reconnect_retry_delay_ms"]) ?? 30000,
            sessionMaxAppPayload: ObstacleBridgeRuntimeConfig.overlaySessionMaxAppPayload(from: runtimeConfig),
            overlayLayerTransportAdapter: sharedOverlayLayerTransportAdapter,
            startupMuxFrames: remoteServiceCatalogMuxFrames(
                instanceID: muxInstanceID,
                connectionSeq: muxConnectionSeq
            ),
            queue: serviceStateQueue,
            serviceNameByID: Dictionary(uniqueKeysWithValues: ownServerSpecs.map { ($0.svcID, $0.name ?? "") }),
            tunServiceSpec: tunService?.toChannelMuxServiceSpec(),
            tunIfname: tunService?.listenBind,
            tunMTU: tunService?.listenPort ?? 0,
            tunLocalAddress: tunnelRouting?.tunnelAddress,
            tunLocalAddress6: tunnelRouting?.tunnelAddress6,
            sharedTunDisableOutgoingNormalization: tunnelRouting?.sharedTunDisableOutgoingNormalization ?? false,
            sharedTunDisableInflowFilter: tunnelRouting?.sharedTunDisableInflowFilter ?? false,
            sharedTunDisableOutflowFilter: tunnelRouting?.sharedTunDisableOutflowFilter ?? false,
            sharedTunDisableScopedThrottle: tunnelRouting?.sharedTunDisableScopedThrottle ?? false,
            tunPacketSink: { [weak self] packet in
                self?.deliverRemoteTunPacketToLocalAdapter(packet)
            },
            muxInstanceID: muxInstanceID,
            muxConnectionSeq: muxConnectionSeq,
            eventSink: { [weak self] event, fields in
                self?.handleSharedOverlayOwnerEvent(event: event, fields: fields)
            }
        )
        sharedQuicOverlayTransportOwner = owner
        owner.start()
    }

    private func startSharedUDPOverlayTransportOwnerIfNeeded() throws {
        guard (Self.stringValue(from: runtimeConfig["overlay_transport"]) ?? "myudp").lowercased() == "myudp" else {
            return
        }
        let bindHost = Self.stringValue(from: runtimeConfig["udp_bind"]) ?? "0.0.0.0"
        let bindPort = Self.intValue(from: runtimeConfig["udp_own_port"]) ?? 0
        guard bindPort >= 0 else {
            return
        }
        let peerHost = Self.stringValue(from: runtimeConfig["udp_peer"])
        let peerPort = Self.intValue(from: runtimeConfig["udp_peer_port"])
        let peerResolveFamily = Self.stringValue(from: runtimeConfig["udp_peer_resolve_family"]) ?? "prefer-ipv6"
        let tunService = ownServerSpecs.first { $0.listenProtocol == "tun" && $0.targetProtocol == "tun" }
        let tunnelRouting = ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: runtimeConfig)
        let muxInstanceID = UInt64.random(in: 1...UInt64.max)
        let muxConnectionSeq = UInt32.random(in: 1...UInt32.max)
        let owner = ObstacleBridgeUdpOverlayTransportOwner(
            bindHost: bindHost,
            bindPort: bindPort,
            peerHost: peerHost,
            peerPort: peerPort,
            peerResolveFamily: peerResolveFamily,
            sessionMaxAppPayload: ObstacleBridgeRuntimeConfig.overlaySessionMaxAppPayload(from: runtimeConfig),
            maxInFlight: ObstacleBridgeRuntimeConfig.overlayMaxInflight(from: runtimeConfig),
            overlayLayerTransportAdapter: sharedOverlayLayerTransportAdapter,
            startupMuxFrames: remoteServiceCatalogMuxFrames(
                instanceID: muxInstanceID,
                connectionSeq: muxConnectionSeq
            ),
            queue: serviceStateQueue,
            serviceNameByID: Dictionary(uniqueKeysWithValues: ownServerSpecs.map { ($0.svcID, $0.name ?? "") }),
            tunServiceSpec: tunService?.toChannelMuxServiceSpec(),
            tunIfname: tunService?.listenBind,
            tunMTU: tunService?.listenPort ?? 0,
            tunLocalAddress: tunnelRouting?.tunnelAddress,
            tunLocalAddress6: tunnelRouting?.tunnelAddress6,
            sharedTunDisableOutgoingNormalization: tunnelRouting?.sharedTunDisableOutgoingNormalization ?? false,
            sharedTunDisableInflowFilter: tunnelRouting?.sharedTunDisableInflowFilter ?? false,
            sharedTunDisableOutflowFilter: tunnelRouting?.sharedTunDisableOutflowFilter ?? false,
            sharedTunDisableScopedThrottle: tunnelRouting?.sharedTunDisableScopedThrottle ?? false,
            tunPacketSink: { [weak self] packet in
                self?.deliverRemoteTunPacketToLocalAdapter(packet)
            },
            muxInstanceID: muxInstanceID,
            muxConnectionSeq: muxConnectionSeq,
            eventSink: { [weak self] event, fields in
                self?.handleSharedOverlayOwnerEvent(event: event, fields: fields)
            }
        )
        sharedUdpOverlayTransportOwner = owner
        try owner.start()
    }

    private func ensureSharedMacOSTunAdapter(for tunService: ObstacleBridgeNativeServiceSpec?) {
        let trimmedIfname = tunService?.listenBind.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard let tunService,
              tunService.listenProtocol == "tun",
              tunService.targetProtocol == "tun",
              !trimmedIfname.isEmpty
        else {
            teardownSharedMacOSTunAdapter(runLifecycleHook: true)
            return
        }
        let ifname = trimmedIfname
        let mtu = max(68, tunService.listenPort)
        if let existing = macOSTunHelperClient,
           existing.isOpen,
           existing.requestedIfname == ifname,
           existing.mtu == mtu {
            // Keep the shared adapter alive across overlay reconnects. The shell
            // hooks are tied to adapter lifecycle, not transport peer churn.
            return
        }
        teardownSharedMacOSTunAdapter(runLifecycleHook: true)
        let helperClient = macOSTunHelperClientFactory(
            serviceStateQueue,
            { [weak self] packet in
                self?.deliverLocalTunPacketToActiveOverlay(packet)
            },
            { event, fields in
                NSLog("[ObstacleBridgeHostRunner][%@] %@", event, String(describing: fields))
            }
        )
        macOSTunHelperTransportKind = helperClient.transportKind
        do {
            _ = try helperClient.openTun(ObstacleBridgeTunHelperOpenRequest(
                requestedIfname: ifname,
                mtu: mtu
            ))
            macOSTunHelperClient = helperClient
            macOSTunHelperTransportKind = helperClient.transportKind
            macOSTunHelperRuntimeSnapshot = helperClient.runtimeSnapshot
            macOSTunChannelConnectedHookFired = false
            runMacOSTunLifecycleHook(for: tunService, event: "on_created")
        } catch {
            NSLog(
                "[ObstacleBridgeHostRunner][macos_utun_start_failed] ifname=%@ mtu=%d error=%@",
                ifname,
                mtu,
                error.localizedDescription
            )
            helperClient.recordFailure(stage: "macos_utun_start", error: error.localizedDescription)
            macOSTunHelperRuntimeSnapshot = helperClient.runtimeSnapshot
            macOSTunHelperClient = nil
        }
    }

    private func handleSharedOverlayOwnerEvent(event: String, fields: [String: Any]) {
        NSLog("[ObstacleBridgeHostRunner][%@] %@", event, String(describing: fields))
        guard event == "ws_overlay_connected"
            || event == "tcp_overlay_connected"
            || event == "quic_overlay_connected"
            || event == "udp_overlay_connected"
        else {
            return
        }
        guard let tunService = ownServerSpecs.first(where: { $0.listenProtocol == "tun" && $0.targetProtocol == "tun" })
        else {
            return
        }
        captureMacOSOverlayUnderlayRoute(fields: fields)
        if macOSTunHelperClient?.isOpen != true {
            ensureSharedMacOSTunAdapter(for: tunService)
        }
        guard !macOSTunChannelConnectedHookFired,
              macOSTunHelperClient?.isOpen == true
        else {
            return
        }
        macOSTunChannelConnectedHookFired = true
        runMacOSTunLifecycleHook(for: tunService, event: "on_channel_connected")
    }

    private func macOSTunHookContext(for tunService: ObstacleBridgeNativeServiceSpec, event: String) -> [String: String] {
        let actualIfname = (macOSTunHelperClient?.actualIfname.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false)
            ? macOSTunHelperClient!.actualIfname
            : tunService.listenBind
        let overlayTransport = overlayTransportName()
        let overlayPeer = configuredOverlayPeerEndpoint(for: overlayTransport)
        let normalizedOverlayPeerHost = Self.firstConfiguredIPv4PeerHost(from: overlayPeer.host)
            ?? Self.firstConfiguredPeerHost(from: overlayPeer.host)
        return [
            "service_id": String(tunService.svcID),
            "service_name": tunService.name ?? "svc-\(tunService.svcID)",
            "catalog": "own_servers",
            "event": event,
            "protocol": tunService.listenProtocol,
            "channel_id": "",
            "bind": tunService.listenBind,
            "listen_port": String(tunService.listenPort),
            "target_host": tunService.targetHost,
            "target_port": String(tunService.targetPort),
            "ifname": actualIfname,
            "peer_id": "",
            "peer_endpoint": "",
            "overlay_transport": overlayTransport,
            "overlay_peer_name": "",
            "overlay_peer_host": normalizedOverlayPeerHost,
            "overlay_peer_port": overlayPeer.port > 0 ? String(overlayPeer.port) : "",
            "overlay_underlay_gateway": macOSOverlayUnderlayGatewayV4,
            "overlay_underlay_interface": macOSOverlayUnderlayInterfaceV4,
            "role": "listener",
        ]
    }

    private struct MacOSRouteSnapshot {
        let gateway: String
        let interfaceName: String
    }

    private func captureMacOSOverlayUnderlayRoute(fields: [String: Any]) {
        let fieldPeerHost = Self.stringValue(from: fields["peer_host"]) ?? ""
        let configuredPeerHost = macOSTunHookContextPeerHost()
        let peerCandidates = fieldPeerHost.isEmpty ? configuredPeerHost : fieldPeerHost
        let peerHost = Self.firstConfiguredIPv4PeerHost(from: peerCandidates)
            ?? Self.firstConfiguredPeerHost(from: peerCandidates)
        guard !peerHost.isEmpty,
              peerHost.contains("."),
              !peerHost.contains(":")
        else {
            return
        }
        guard let snapshot = Self.macOSRouteSnapshot(to: peerHost, inet6: false),
              !snapshot.interfaceName.hasPrefix("utun")
        else {
            NSLog("[ObstacleBridgeHostRunner][macos_overlay_underlay_route_missing] peer=%@", peerHost)
            return
        }
        macOSOverlayUnderlayGatewayV4 = snapshot.gateway
        macOSOverlayUnderlayInterfaceV4 = snapshot.interfaceName
        NSLog(
            "[ObstacleBridgeHostRunner][macos_overlay_underlay_route] peer=%@ gateway=%@ interface=%@",
            peerHost,
            snapshot.gateway.isEmpty ? "<none>" : snapshot.gateway,
            snapshot.interfaceName.isEmpty ? "<none>" : snapshot.interfaceName
        )
    }

    private func macOSTunHookContextPeerHost() -> String {
        configuredOverlayPeerEndpoint().host
    }

    private static func macOSRouteSnapshot(to host: String, inet6: Bool) -> MacOSRouteSnapshot? {
        let trimmedHost = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedHost.isEmpty else {
            return nil
        }
#if os(macOS)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/sbin/route")
        process.arguments = inet6 ? ["-n", "get", "-inet6", trimmedHost] : ["-n", "get", trimmedHost]
        let outputPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = outputPipe
        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return nil
        }
        let data = outputPipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        var gateway = ""
        var interfaceName = ""
        for rawLine in output.split(separator: "\n") {
            let line = String(rawLine).trimmingCharacters(in: .whitespacesAndNewlines)
            if line.hasPrefix("gateway:") {
                gateway = String(line.dropFirst("gateway:".count)).trimmingCharacters(in: .whitespacesAndNewlines)
            } else if line.hasPrefix("interface:") {
                interfaceName = String(line.dropFirst("interface:".count)).trimmingCharacters(in: .whitespacesAndNewlines)
            }
        }
        if gateway.isEmpty && interfaceName.isEmpty {
            return nil
        }
        return MacOSRouteSnapshot(gateway: gateway, interfaceName: interfaceName)
#else
        return nil
#endif
    }

    private static func firstConfiguredPeerHost(from raw: String) -> String {
        firstConfiguredPeerHostCandidates(from: raw).first ?? raw.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func firstConfiguredIPv4PeerHost(from raw: String) -> String? {
        for candidate in firstConfiguredPeerHostCandidates(from: raw) {
            let normalized = normalizeIPv4MappedPeerHost(candidate)
            if normalized.contains(".") && !normalized.contains(":") {
                return normalized
            }
        }
        return nil
    }

    private static func firstConfiguredPeerHostCandidates(from raw: String) -> [String] {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return []
        }
        let replaced = trimmed.replacingOccurrences(of: ";", with: ",")
        return replaced
            .split(separator: ",")
            .map { stripPeerHostBrackets(String($0).trimmingCharacters(in: .whitespacesAndNewlines)) }
            .filter { !$0.isEmpty }
    }

    private static func stripPeerHostBrackets(_ raw: String) -> String {
        var value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.hasPrefix("[") && value.hasSuffix("]") && value.count >= 2 {
            value.removeFirst()
            value.removeLast()
        }
        return value
    }

    private static func normalizeIPv4MappedPeerHost(_ raw: String) -> String {
        let trimmed = stripPeerHostBrackets(raw)
        let lower = trimmed.lowercased()
        if lower.hasPrefix("::ffff:") {
            return String(trimmed.dropFirst(7))
        }
        return trimmed
    }

    private static func macOSTunHelperHookEnvSnapshot(from env: [String: String]) -> [String: String] {
        let allowedKeys = Set([
            "MTU",
            "ENABLE_TCPMSS",
            "ENABLE_TUN_TCPDUMP",
            "TCPDUMP_PCAP_PATH",
            "TUN_ADDR",
            "TUN_GW",
            "TUN_SUBNET",
            "TUN_ADDR6",
            "TUN_GW6",
            "TUN_SUBNET6",
            "PEER_ADDR",
            "PEER_ADDR6",
            "DNS1",
            "DNS2",
            "INCLUDED_ROUTES",
            "EXCLUDED_ROUTES",
            "INCLUDED_ROUTES6",
            "EXCLUDED_ROUTES6",
            "WAN_IF",
            "OB_OVERLAY_TRANSPORT",
            "OB_OVERLAY_PEER_NAME",
            "OB_OVERLAY_PEER_HOST",
            "OB_OVERLAY_PEER_PORT",
            "OB_OVERLAY_UNDERLAY_GW",
            "OB_OVERLAY_UNDERLAY_IF",
        ])
        var filtered: [String: String] = [:]
        for key in allowedKeys.sorted() {
            if let value = env[key] {
                filtered[key] = value
            }
        }
        return filtered
    }

    private func renderHookValue(_ value: String, context: [String: String]) -> String {
        var rendered = value
        for (key, replacement) in context {
            rendered = rendered.replacingOccurrences(of: "{\(key)}", with: replacement)
        }
        return rendered
    }

    private func normalizedCIDR(address: String, prefix: Int) -> String? {
        let trimmed = address.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return nil
        }
        if prefix >= 0 && prefix <= 32 {
            var addr = in_addr()
            guard trimmed.withCString({ inet_pton(AF_INET, $0, &addr) }) == 1 else {
                return nil
            }
            let hostOrder = UInt32(bigEndian: addr.s_addr)
            let mask: UInt32 = prefix == 0 ? 0 : (UInt32.max << UInt32(32 - prefix))
            let network = hostOrder & mask
            var networkAddr = in_addr(s_addr: network.bigEndian)
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            guard inet_ntop(AF_INET, &networkAddr, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil else {
                return nil
            }
            return "\(String(cString: buffer))/\(prefix)"
        }
        if prefix >= 0 && prefix <= 128 {
            var addr6 = in6_addr()
            guard trimmed.withCString({ inet_pton(AF_INET6, $0, &addr6) }) == 1 else {
                return nil
            }
            var networkBytes = withUnsafeBytes(of: &addr6) { Array($0) }
            var remaining = prefix
            for index in networkBytes.indices {
                if remaining >= 8 {
                    remaining -= 8
                    continue
                }
                if remaining <= 0 {
                    networkBytes[index] = 0
                } else {
                    let shift = 8 - remaining
                    let mask = UInt8(truncatingIfNeeded: 0xFF << shift)
                    networkBytes[index] &= mask
                    remaining = 0
                }
            }
            var networkAddr6 = in6_addr()
            withUnsafeMutableBytes(of: &networkAddr6) { bytes in
                bytes.copyBytes(from: networkBytes)
            }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &networkAddr6, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil else {
                return nil
            }
            return "\(String(cString: buffer))/\(prefix)"
        }
        return nil
    }

    private func bundledScriptURL(for relativePath: String) -> URL? {
        let normalized = relativePath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty else { return nil }
        let executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
        let resourcesURL = executableURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Resources", isDirectory: true)
        let scriptName = URL(fileURLWithPath: normalized).lastPathComponent
        let bundled = resourcesURL.appendingPathComponent("scripts", isDirectory: true).appendingPathComponent(scriptName)
        if FileManager.default.isExecutableFile(atPath: bundled.path) {
            return bundled
        }
        return nil
    }

    private func resolveHookExecutablePath(_ raw: String) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return raw }
        if trimmed.hasPrefix("./scripts/") || trimmed.hasPrefix("scripts/") {
            if let bundled = bundledScriptURL(for: trimmed) {
                return bundled.path
            }
        }
        if trimmed.hasPrefix("/") {
            return trimmed
        }
        let configBase = URL(fileURLWithPath: runtimeConfigPath).deletingLastPathComponent().deletingLastPathComponent()
        let candidate = configBase.appendingPathComponent(trimmed).path
        if FileManager.default.isExecutableFile(atPath: candidate) {
            return candidate
        }
        return trimmed
    }

    private func defaultMacOSTunHookArgv(for tunService: ObstacleBridgeNativeServiceSpec, event: String, context: [String: String]) -> [String]? {
        let action: String
        if event == "on_created" {
            action = "up"
        } else if event == "on_stopped" {
            action = "down"
        } else {
            return nil
        }
        let serverSide = String(context["catalog"] ?? "") == "remote_servers"
        let script = serverSide ? "./scripts/server-tun-hook-macos.sh" : "./scripts/client-tun-hook-macos.sh"
        return [
            resolveHookExecutablePath(script),
            action,
            context["ifname"] ?? tunService.listenBind,
        ]
    }

    private func configuredMacOSTunHookArgv(
        for tunService: ObstacleBridgeNativeServiceSpec,
        event: String,
        context: [String: String]
    ) -> ([String], ObstacleBridgeChannelMuxCodec.JSONValue?)? {
        guard let hooks = tunService.lifecycleHooks,
              case .object(let listenerHooks)? = hooks["listener"],
              case .object(let commandObject)? = listenerHooks[event],
              case .object(let argvContainer)? = commandObject["argv"],
              case .array(let argvValues)? = argvContainer["darwin"]
        else {
            return nil
        }
        var argv: [String] = argvValues.compactMap { value in
            if case .string(let raw) = value {
                return renderHookValue(raw, context: context)
            }
            return nil
        }
        guard !argv.isEmpty else {
            return nil
        }
        argv[0] = resolveHookExecutablePath(argv[0])
        return (argv, commandObject["env"])
    }

    private func runMacOSTunLifecycleHook(for tunService: ObstacleBridgeNativeServiceSpec, event: String) {
        let context = macOSTunHookContext(for: tunService, event: event)
        let configured = configuredMacOSTunHookArgv(for: tunService, event: event, context: context)
        guard let argv = configured?.0 ?? defaultMacOSTunHookArgv(for: tunService, event: event, context: context) else {
            return
        }

        var env = ProcessInfo.processInfo.environment
        env["OB_OVERLAY_TRANSPORT"] = context["overlay_transport"] ?? ""
        env["OB_OVERLAY_PEER_NAME"] = context["overlay_peer_name"] ?? ""
        env["OB_OVERLAY_PEER_HOST"] = context["overlay_peer_host"] ?? ""
        env["OB_OVERLAY_PEER_PORT"] = context["overlay_peer_port"] ?? ""
        env["OB_OVERLAY_UNDERLAY_GW"] = context["overlay_underlay_gateway"] ?? ""
        env["OB_OVERLAY_UNDERLAY_IF"] = context["overlay_underlay_interface"] ?? ""

        if let tunRouting = ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: runtimeConfig) {
            let tunnelAddress = (tunRouting.tunnelAddress ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            let tunnelPrefix = tunRouting.tunnelPrefix ?? 30
            let tunnelGateway = (tunRouting.tunnelGateway ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            let tunnelAddress6 = (tunRouting.tunnelAddress6 ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            let tunnelPrefix6 = tunRouting.tunnelPrefix6 ?? 126
            let tunnelGateway6 = (tunRouting.tunnelGateway6 ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            let dnsServers = tunRouting.dnsServers ?? []
            let includedRoutes = tunRouting.includedRoutes ?? []
            let includedRoutes6 = tunRouting.includedRoutes6 ?? []
            let effectiveExcludedRoutes = ObstacleBridgeRuntimeConfig.effectiveExcludedRoutes(
                from: runtimeConfig,
                baseIPv4: tunRouting.excludedRoutes ?? [],
                baseIPv6: tunRouting.excludedRoutes6 ?? []
            )
            let mtu = tunRouting.mtu ?? 1600

            env["MTU"] = String(mtu)
            env["ENABLE_TCPMSS"] = (tunRouting.enableTCPMSS ?? false) ? "1" : "0"
            env["ENABLE_TUN_TCPDUMP"] = (tunRouting.enableTunTcpdump ?? false) ? "1" : "0"
            if let pcapPath = tunRouting.tunTcpdumpPcapPath?.trimmingCharacters(in: .whitespacesAndNewlines),
               !pcapPath.isEmpty {
                env["TCPDUMP_PCAP_PATH"] = pcapPath
            }
            if !tunnelAddress.isEmpty {
                env["TUN_ADDR"] = "\(tunnelAddress)/\(tunnelPrefix)"
            }
            if !tunnelGateway.isEmpty {
                env["TUN_GW"] = tunnelGateway
                env["PEER_ADDR"] = tunnelGateway
            }
            if let subnet = normalizedCIDR(address: tunnelAddress, prefix: tunnelPrefix) {
                env["TUN_SUBNET"] = subnet
            }
            if !tunnelAddress6.isEmpty {
                env["TUN_ADDR6"] = "\(tunnelAddress6)/\(tunnelPrefix6)"
            }
            if !tunnelGateway6.isEmpty {
                env["TUN_GW6"] = tunnelGateway6
                env["PEER_ADDR6"] = tunnelGateway6
            }
            if let subnet6 = normalizedCIDR(address: tunnelAddress6, prefix: tunnelPrefix6) {
                env["TUN_SUBNET6"] = subnet6
            }
            for (index, dns) in dnsServers.prefix(2).enumerated() {
                env[index == 0 ? "DNS1" : "DNS2"] = dns
            }
            if !includedRoutes.isEmpty {
                env["INCLUDED_ROUTES"] = includedRoutes.joined(separator: ",")
            }
            if !effectiveExcludedRoutes.ipv4.isEmpty {
                env["EXCLUDED_ROUTES"] = effectiveExcludedRoutes.ipv4.joined(separator: ",")
            }
            if !includedRoutes6.isEmpty {
                env["INCLUDED_ROUTES6"] = includedRoutes6.joined(separator: ",")
            }
            if !effectiveExcludedRoutes.ipv6.isEmpty {
                env["EXCLUDED_ROUTES6"] = effectiveExcludedRoutes.ipv6.joined(separator: ",")
            }
        }

        if case .object(let envObject)? = configured?.1 {
            for (key, value) in envObject {
                switch value {
                case .string(let stringValue):
                    env[key] = renderHookValue(stringValue, context: context)
                case .integer(let integerValue):
                    env[key] = String(integerValue)
                case .double(let doubleValue):
                    env[key] = String(doubleValue)
                case .bool(let boolValue):
                    env[key] = boolValue ? "true" : "false"
                default:
                    break
                }
            }
        }
        let helperEnvSnapshot = Self.macOSTunHelperHookEnvSnapshot(from: env)
        if event == "on_stopped" {
            macOSTunHelperClient?.removeNetwork(action: event, argv: argv, env: helperEnvSnapshot)
        } else {
            macOSTunHelperClient?.applyNetwork(action: event, argv: argv, env: helperEnvSnapshot)
        }
        if let client = macOSTunHelperClient {
            macOSTunHelperRuntimeSnapshot = client.runtimeSnapshot
        }
    }

    private func deliverLocalTunPacketToActiveOverlay(_ packet: Data) {
        if let client = macOSTunHelperClient {
            if client.transportKind == "xpc" {
                macOSTunHelperRuntimeSnapshot.recordPacketToRuntime()
            } else {
                macOSTunHelperRuntimeSnapshot = client.runtimeSnapshot
            }
        }
        currentOverlayOwner()?.owner.sendLocalTunPacket(packet)
    }

    private func deliverRemoteTunPacketToLocalAdapter(_ packet: Data) {
        observeTunProbeReply(packet)
        guard let helperClient = macOSTunHelperClient else { return }
        do {
            try helperClient.writePacket(packet)
            macOSTunHelperRuntimeSnapshot = helperClient.runtimeSnapshot
        } catch {
            NSLog(
                "[ObstacleBridgeHostRunner][macos_utun_write_failed] ifname=%@ packet_bytes=%d error=%@",
                helperClient.actualIfname,
                packet.count,
                error.localizedDescription
            )
            helperClient.recordFailure(
                stage: "macos_utun_write",
                error: error.localizedDescription
            )
            macOSTunHelperRuntimeSnapshot = helperClient.runtimeSnapshot
        }
    }

    private func remoteServiceCatalogMuxFrames(
        instanceID: UInt64 = 0,
        connectionSeq: UInt32 = 0
    ) -> [Data] {
        ObstacleBridgeRuntimeConfig.remoteServiceCatalogMuxFrames(
            from: runtimeConfig,
            instanceID: instanceID,
            connectionSeq: connectionSeq
        )
    }

    private func hasConfiguredOverlayPeer() -> Bool {
        let endpoint = configuredOverlayPeerEndpoint()
        return !endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && endpoint.port > 0
    }

    private func overlayCurrentlyConnected() -> Bool? {
        currentOverlayOwner()?.owner.appReady()
    }

    private func overlayTransportName() -> String {
        (Self.stringValue(from: runtimeConfig["overlay_transport"]) ?? "myudp").lowercased()
    }

    private func configuredOverlayPeerEndpoint(for transport: String? = nil) -> OverlayPeerEndpoint {
        switch (transport ?? overlayTransportName()).lowercased() {
        case "tcp":
            return OverlayPeerEndpoint(
                host: Self.stringValue(from: runtimeConfig["tcp_peer"]) ?? "",
                port: Self.intValue(from: runtimeConfig["tcp_peer_port"]) ?? 0
            )
        case "ws":
            return OverlayPeerEndpoint(
                host: Self.stringValue(from: runtimeConfig["ws_peer"]) ?? "",
                port: Self.intValue(from: runtimeConfig["ws_peer_port"]) ?? 0
            )
        case "quic":
            return OverlayPeerEndpoint(
                host: Self.stringValue(from: runtimeConfig["quic_peer"]) ?? "",
                port: Self.intValue(from: runtimeConfig["quic_peer_port"]) ?? 0
            )
        default:
            return OverlayPeerEndpoint(
                host: Self.stringValue(from: runtimeConfig["udp_peer"]) ?? "",
                port: Self.intValue(from: runtimeConfig["udp_peer_port"]) ?? 0
            )
        }
    }

    private func currentOverlayOwner() -> ActiveOverlayOwner? {
        let transport = overlayTransportName()
        switch transport {
        case "ws":
            guard let owner = sharedWebSocketOverlayTransportOwner else { return nil }
            return ActiveOverlayOwner(transport: transport, owner: owner)
        case "tcp":
            guard let owner = sharedTcpOverlayTransportOwner else { return nil }
            return ActiveOverlayOwner(transport: transport, owner: owner)
        case "quic":
            guard let owner = sharedQuicOverlayTransportOwner else { return nil }
            return ActiveOverlayOwner(transport: transport, owner: owner)
        default:
            guard let owner = sharedUdpOverlayTransportOwner else { return nil }
            return ActiveOverlayOwner(transport: "myudp", owner: owner)
        }
    }

    private func startClientRestartWatchdog() {
        clientRestartWatchdog?.cancel()
        clientRestartWatchdog = nil
        overlayDisconnectedAt = nil

        let timer = DispatchSource.makeTimerSource(queue: serviceStateQueue)
        timer.schedule(deadline: .now() + .milliseconds(250), repeating: .milliseconds(250))
        timer.setEventHandler { [weak self] in
            guard let self else {
                return
            }
            let timeout = Self.doubleValue(from: self.runtimeConfig["client_restart_if_disconnected"]) ?? 0.0
            if timeout <= 0 || !self.hasConfiguredOverlayPeer() {
                self.overlayDisconnectedAt = nil
                return
            }
            guard let connected = self.overlayCurrentlyConnected() else {
                self.overlayDisconnectedAt = nil
                return
            }
            if connected {
                self.overlayDisconnectedAt = nil
                return
            }
            let now = Date().timeIntervalSince1970
            let disconnectedAt = self.overlayDisconnectedAt ?? now
            self.overlayDisconnectedAt = disconnectedAt
            if (now - disconnectedAt) < timeout {
                return
            }
            self.overlayDisconnectedAt = now
            _ = self.requestRestart()
        }
        clientRestartWatchdog = timer
        timer.resume()
    }
}

extension ObstacleBridgeHostRunner: ObstacleBridgeAdminAPIStateProvider {
    func adminStatusSnapshot() -> [String: Any] {
        refreshAdminSnapshotCache(sync: true)
        return snapshot()
    }

    func adminConnectionsSnapshot() -> [String: Any] {
        refreshAdminSnapshotCache(sync: true)
        return connectionsSnapshot()
    }

    func adminTunRoutingSnapshot() -> [String: Any] {
        refreshAdminSnapshotCache(sync: true)
        return tunRoutingSnapshotWithVerification(cachedTunRoutingOrBuild())
    }

    func adminPeersSnapshot() -> [[String: Any]] {
        refreshAdminSnapshotCache(sync: true)
        return peersSnapshot()
    }

    func adminMetaSnapshot() -> [String: Any] {
        refreshAdminSnapshotCache(sync: true)
        return metaSnapshot()
    }

    func adminConfigSnapshot() -> [String: Any] {
        ObstacleBridgeAdminSnapshotSupport.configEnvelope(
            config: maskedRuntimeConfigSnapshot(),
            schema: configStore.schemaSnapshot()
        )
    }

    func adminOnboardingConnectionProfiles() -> [[String: Any]] {
        onboardingConnectionProfiles()
    }

    func adminOnboardingBlueprints() -> [[String: Any]] {
        onboardingBlueprints()
    }

    func adminOnboardingInviteGenerate(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        ObstacleBridgeAdminConfigSupport.inviteGenerateResponse(
            method: request.method,
            body: request.body,
            runtimeConfig: runtimeConfig,
            profiles: onboardingConnectionProfiles(),
            encryptSecrets: ObstacleBridgeConfigSecretCodec.encryptPayload
        )
    }

    func adminOnboardingInvitePreview(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        ObstacleBridgeAdminConfigSupport.invitePreviewResponse(
            method: request.method,
            body: request.body,
            decryptSecrets: ObstacleBridgeConfigSecretCodec.decryptPayload
        )
    }

    func adminConfigChallenge(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        ObstacleBridgeAdminConfigSupport.configChallengeResponse(
            request: request,
            authRequired: adminAuthRequired(),
            authenticated: adminIsAuthenticated(headers: request.headers),
            challengeIssuer: issueConfigChallenge
        )
    }

    func adminAuthRequired() -> Bool {
        if Self.boolValue(from: runtimeConfig["admin_web_auth_disable"]) ?? false {
            return false
        }
        return !adminAuthUsername().isEmpty && !adminAuthPassword().isEmpty
    }

    func adminIsAuthenticated(headers: [String: String]) -> Bool {
        adminAuth.isAuthenticated(headers: headers)
    }

    func adminAuthState(headers: [String: String]) -> [String: Any] {
        adminAuth.authState(headers: headers)
    }

    func adminAuthChallenge(method: String) -> ObstacleBridgeAdminAPIResponse {
        adminAuth.authChallenge(method: method)
    }

    func adminAuthLogin(method: String, body: Data?) -> ObstacleBridgeAdminAPIResponse {
        adminAuth.authLogin(method: method, body: body)
    }

    func adminAuthLogout(method: String, headers: [String: String]) -> ObstacleBridgeAdminAPIResponse {
        adminAuth.authLogout(method: method, headers: headers)
    }

    func adminUpdateConfig(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        let payload: [String: Any]
        switch ObstacleBridgeAdminConfigSupport.jsonObjectBody(method: request.method, expectedMethod: "POST", body: request.body) {
        case .response(let response):
            return response
        case .payload(let value):
            payload = value
        }
        let updates: [String: Any]
        switch ObstacleBridgeAdminConfigSupport.updatesObject(from: payload) {
        case .response(let response):
            return response
        case .payload(let value):
            updates = value
        }
        let restartAfterSave = (payload["restart_after_save"] as? Bool) ?? false
        if let response = ObstacleBridgeAdminConfigSupport.validateConfigChallengePayload(
            payload: payload,
            updates: updates,
            authRequired: adminAuthRequired(),
            challengeValidator: validateConfigChallenge
        ) {
            return response
        }
        do {
            try persistConfigUpdates(updates)
        } catch let error as ObstacleBridgeHostRunnerError {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "error": error.localizedDescription,
            ], statusLine: "HTTP/1.1 400 Bad Request")
        } catch {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "error": "failed to persist runtime config",
            ], statusLine: "HTTP/1.1 400 Bad Request")
        }

        if updates.keys.contains(where: { ["admin_web_auth_disable", "admin_web_username", "admin_web_password", "secure_link_psk"].contains($0) }) {
            authStateQueue.sync {
                resetAuthState()
            }
        }

        if restartAfterSave {
            _ = requestRestart()
        }
        return ObstacleBridgeAdminConfigSupport.configUpdateSuccessResponse(
            maskedConfig: maskedRuntimeConfigSnapshot(),
            restartAfterSave: restartAfterSave,
            restartEmbedded: restartAfterSave
        )
    }

    func adminTunHelperStatus(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        guard request.method.uppercased() == "GET" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        return ObstacleBridgeAdminAPI.jsonResponse([
            "ok": true,
            "tun_helper": macOSTunHelperStatusSnapshot(),
        ])
    }

    func adminTunHelperAction(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        guard request.method.uppercased() == "POST" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        if let forbidden = adminAuth.validateBearer(headers: request.headers) {
            return forbidden
        }
        guard let body = request.body,
              let object = try? JSONSerialization.jsonObject(with: body),
              let payload = object as? [String: Any],
              let rawAction = payload["action"] as? String else {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "error": "expected JSON body with action",
            ], statusLine: "HTTP/1.1 400 Bad Request")
        }

        let action = rawAction.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        var result: [String: Any]
        switch action {
        case "status":
            result = ["ok": true, "action": "status"]
        case "register", "install", "enable":
#if os(macOS)
            result = ObstacleBridgeMacOSTunHelperService.registerResult()
#else
            result = ["ok": false, "action": action, "error": "macOS privileged helper package is not available on iOS"]
#endif
        case "start":
#if os(macOS)
            result = ObstacleBridgeMacOSTunHelperService.startResult()
#else
            result = ["ok": false, "action": action, "error": "macOS privileged helper package is not available on iOS"]
#endif
        case "stop", "unregister", "disable":
#if os(macOS)
            result = ObstacleBridgeMacOSTunHelperService.stopResult(action: action)
#else
            result = ["ok": false, "action": action, "error": "macOS privileged helper package is not available on iOS"]
#endif
        case "open_approval_settings", "approval_settings":
#if os(macOS)
            result = ObstacleBridgeMacOSTunHelperService.openApprovalSettingsResult()
#else
            result = ["ok": false, "action": action, "error": "macOS privileged helper package is not available on iOS"]
#endif
        default:
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "error": "unsupported TUN helper action",
                "action": rawAction,
                "supported_actions": [
                    "status",
                    "register",
                    "start",
                    "stop",
                    "open_approval_settings",
                ],
            ], statusLine: "HTTP/1.1 400 Bad Request")
        }
        result["tun_helper"] = macOSTunHelperStatusSnapshot()
        return ObstacleBridgeAdminAPI.jsonResponse(result)
    }

    func adminTunHelperRepair(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        guard request.method.uppercased() == "POST" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        if let forbidden = adminAuth.validateBearer(headers: request.headers) {
            return forbidden
        }
        return ObstacleBridgeAdminAPI.jsonResponse([
            "ok": false,
            "reason": "repair_supported_only_for_linux_native_helper",
            "repaired": [],
            "failed": [],
            "status": ["tun_helper": macOSTunHelperStatusSnapshot()],
        ], statusLine: "HTTP/1.1 400 Bad Request")
    }

    func adminRequestRestart(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        guard request.method.uppercased() == "POST" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        if let forbidden = adminAuth.validateBearer(headers: request.headers) {
            return forbidden
        }
        return ObstacleBridgeAdminAPI.jsonResponse(requestRestart())
    }

    func adminRequestReconnect(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        guard request.method.uppercased() == "POST" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        if let forbidden = adminAuth.validateBearer(headers: request.headers) {
            return forbidden
        }
        return ObstacleBridgeAdminAPI.jsonResponse(requestReconnect())
    }

    func adminRequestSecureLinkRekey(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        guard request.method.uppercased() == "POST" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        if let forbidden = adminAuth.validateBearer(headers: request.headers) {
            return forbidden
        }
        let payload = withServiceStateQueue {
            currentOverlayOwner()?.owner.requestSecureLinkRekey()
                ?? ["ok": false, "reason": "transport_unavailable"]
        }
        let statusLine = (payload["ok"] as? Bool) == true ? "HTTP/1.1 200 OK" : "HTTP/1.1 400 Bad Request"
        return ObstacleBridgeAdminAPI.jsonResponse(payload, statusLine: statusLine)
    }

    func adminRequestShutdown(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        guard request.method.uppercased() == "POST" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        if let forbidden = adminAuth.validateBearer(headers: request.headers) {
            return forbidden
        }
        return ObstacleBridgeAdminAPI.jsonResponse(requestShutdown())
    }

    func adminLogLines(limit: Int) -> [String] {
        readLogLines(limit: limit)
    }

    func adminRequestRestart() -> [String: Any] {
        requestRestart()
    }

    func adminRequestReconnect() -> [String: Any] {
        requestReconnect()
    }

    func adminRequestShutdown() -> [String: Any] {
        requestShutdown()
    }
}

struct ObstacleBridgeHostRunnerCLI {
    static let defaultRuntimeConfigName = "ObstacleBridge.cfg"

    let runtimeConfigPath: String
    let bindHost: String?
    let statusPort: Int?
    let holdSec: Double

    static func parse(_ args: [String]) throws -> ObstacleBridgeHostRunnerCLI {
        var runtimeConfigPath: String?
        var bindHost: String?
        var statusPort: Int?
        var holdSec = 0.0
        var index = 0
        while index < args.count {
            let arg = args[index]
            switch arg {
            case "--runtime-config":
                index += 1
                guard index < args.count else {
                    throw ObstacleBridgeHostRunnerError.usage(Self.usageText())
                }
                runtimeConfigPath = args[index]
            case "--bind-host":
                index += 1
                guard index < args.count else {
                    throw ObstacleBridgeHostRunnerError.usage(Self.usageText())
                }
                bindHost = args[index]
            case "--status-port":
                index += 1
                guard index < args.count, let port = Int(args[index]) else {
                    throw ObstacleBridgeHostRunnerError.invalidArgument("--status-port requires an integer")
                }
                statusPort = port
            case "--hold-sec":
                index += 1
                guard index < args.count, let seconds = Double(args[index]) else {
                    throw ObstacleBridgeHostRunnerError.invalidArgument("--hold-sec requires a number")
                }
                holdSec = max(0.0, seconds)
            case "--help", "-h":
                throw ObstacleBridgeHostRunnerError.usage(Self.usageText())
            default:
                throw ObstacleBridgeHostRunnerError.invalidArgument("Unknown argument: \(arg)")
            }
            index += 1
        }
        return ObstacleBridgeHostRunnerCLI(
            runtimeConfigPath: runtimeConfigPath ?? defaultRuntimeConfigPath(),
            bindHost: bindHost,
            statusPort: statusPort,
            holdSec: holdSec
        )
    }

    private static func defaultRuntimeConfigPath() -> String {
        URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent(defaultRuntimeConfigName)
            .path
    }

    static func usageText() -> String {
        "Usage: ObstacleBridgeHostRunner [--runtime-config <path>] [--bind-host <host>] [--status-port <port>] [--hold-sec <seconds>]"
    }
}
