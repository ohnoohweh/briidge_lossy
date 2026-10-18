import Foundation
import Testing
@testable import ObstacleBridgeLinuxAdapters
@testable import ObstacleBridgeCore

struct ObstacleBridgeLinuxRuntimeConfigurationTests {
    @Test func managedTunHelperElevatesOnlyTheSeparateHelperProcess() {
        let elevated = ObstacleBridgeLinuxManagedTunHelper.launchCommand(
            executable: "/opt/obstaclebridge/ObstacleBridgeLinux",
            socketPath: "/tmp/helper.sock",
            sessionToken: "test-token",
            elevated: true
        )
        #expect(elevated.path == "/usr/bin/sudo")
        #expect(elevated.arguments == ["--", "/opt/obstaclebridge/ObstacleBridgeLinux", "--tun-helper-server", "/tmp/helper.sock", "test-token", "--idle-sec", "30"])

        let direct = ObstacleBridgeLinuxManagedTunHelper.launchCommand(
            executable: "/opt/obstaclebridge/ObstacleBridgeLinux",
            socketPath: "/tmp/helper.sock",
            sessionToken: "test-token",
            elevated: false
        )
        #expect(direct.path == "/opt/obstaclebridge/ObstacleBridgeLinux")
        #expect(direct.arguments.first == "--tun-helper-server")
        #expect(ObstacleBridgeLinuxManagedTunHelper.socketReadyTimeout(elevated: true) == 60)
        #expect(ObstacleBridgeLinuxManagedTunHelper.socketReadyTimeout(elevated: false) == 2)
        #expect(ObstacleBridgeLinuxManagedTunHelper.usesControllingTerminal(elevated: true))
        #expect(!ObstacleBridgeLinuxManagedTunHelper.usesControllingTerminal(elevated: false))
    }

    @Test func observabilityWritesForegroundLifecycleToConfiguredLogAndBoundedTelemetrySpool() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("obstaclebridge-observability-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let log = directory.appendingPathComponent("runtime.log")
        let producer = ObstacleBridgeLinuxObservability(configuration: [
            "debug_logging": ["log_file": log.path],
            "telemetry_client": ["telemetry_enabled": true, "telemetry_spool_directory": directory.appendingPathComponent("spool").path],
        ], sessionID: "test-session")
        let spoolDirectory = directory.appendingPathComponent("spool")
        producer.recordForegroundLifecycle(state: "started", transport: "myudp")
        producer.recordForegroundLifecycle(state: "connecting", transport: "myudp")
        producer.recordForegroundLifecycle(state: "connecting", transport: "myudp")
        producer.recordForegroundLifecycle(state: "connected", transport: "myudp")
        producer.recordForegroundLifecycle(state: "stopped", transport: "myudp")

        let logContents = String(decoding: try Data(contentsOf: log), as: UTF8.self)
        #expect(logContents.contains("runtime.lifecycle"))
        #expect(logContents.contains("state=connected"))
        let events = try ObstacleBridgeTelemetrySpool(directory: spoolDirectory).recover()
        #expect(events.map(\.event) == ["runtime.lifecycle", "runtime.lifecycle", "runtime.lifecycle", "runtime.lifecycle"])
        #expect(events.compactMap { $0.fields["state"] } == [.string("started"), .string("connecting"), .string("connected"), .string("stopped")])
        #expect(events.allSatisfy { $0.fields["transport"] == .string("myudp") })
    }

    @Test func admitsExplicitHelperControlSocketWithoutAdmittingTunStartup() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: try JSONSerialization.data(withJSONObject: [
            "runner": ["overlay_transport": "tcp"],
            "tcp_session": ["tcp_peer": "127.0.0.1", "tcp_peer_port": 4433],
            "tun_execution": ["tun_execution_mode": "helper", "tun_helper_socket": "/run/obstaclebridge/helper.sock", "tun_helper_session_token": "test-helper-token"],
        ]))
        #expect(config.tunHelperSocketPath == "/run/obstaclebridge/helper.sock")
        #expect(try config.makeTunHelperAdapter() != nil)
    }
    @Test func admitsManagedSwiftHelperSelectionOnlyWithExplicitHelperCredentials() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: try JSONSerialization.data(withJSONObject: [
            "runner": ["overlay_transport": "tcp"],
            "tcp_session": ["tcp_peer": "127.0.0.1", "tcp_peer_port": 4433],
            "tun_execution": [
                "tun_execution_mode": "helper", "tun_helper_socket": "/run/obstaclebridge/helper.sock",
                "tun_helper_session_token": "test-helper-token", "launch_swift_helper": true,
                "tun_helper_executable": "/opt/obstaclebridge/ObstacleBridgeLinux",
            ],
        ]))
        #expect(config.launchSwiftTunHelper)
        #expect(config.tunHelperExecutable == "/opt/obstaclebridge/ObstacleBridgeLinux")
    }

    @Test func nativeHelperWithoutCredentialsGetsEphemeralManagedEndpoint() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: try JSONSerialization.data(withJSONObject: [
            "runner": ["overlay_transport": "tcp"],
            "tcp_session": ["tcp_peer": "127.0.0.1", "tcp_peer_port": 4433],
            "tun_execution": ["tun_execution_mode": "helper", "tun_helper_backend": "linux-native", "tun_helper_socket": ""],
            "TUN_routing": ["enabled_on_startup": true],
        ]))
        #expect(config.launchSwiftTunHelper)
        #expect(config.tunHelperSocketPath?.hasPrefix("/tmp/obstaclebridge-tun-") == true)
        #expect(config.tunHelperSocketPath?.hasSuffix(".sock") == true)
        #expect(config.tunHelperSessionToken?.isEmpty == false)
    }

    @Test func nativeTunnelPlanOwnsConfiguredTunServiceInsteadOfSocketCatalog() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: try JSONSerialization.data(withJSONObject: [
            "runner": ["overlay_transport": "tcp"],
            "tcp_session": ["tcp_peer": "127.0.0.1", "tcp_peer_port": 4433],
            "tun_execution": ["tun_execution_mode": "helper", "tun_helper_backend": "linux-native"],
            "TUN_routing": ["enabled_on_startup": true],
            "channel_mux": ["own_servers": [
                ["name": "shared tunnel", "listen": ["protocol": "tun", "ifname": "obtun0"], "target": ["protocol": "tun", "ifname": "obtun0"]],
                ["name": "web", "listen": ["protocol": "tcp", "bind": "127.0.0.1", "port": 8080], "target": ["protocol": "tcp", "host": "127.0.0.1", "port": 8080]],
            ]],
        ]))
        #expect(config.ownServices.count == 1)
        #expect(config.ownServices[0].listenProtocol == .tcp)
        #expect(config.packetTunnelEnabled)
    }
    @Test func corePeerAddressPortNormalizesLinuxCandidateLists() {
        let configuration = ObstacleBridgeLinuxRuntimeConfiguration(
            transport: .tcp,
            host: "  [::1] ; 127.0.0.1, example.invalid  ",
            port: 443
        )
        #expect(configuration.peerCandidates == ["[::1]", "127.0.0.1", "example.invalid"])
        #expect(configuration.host == "[::1]")
    }

    @Test func configuredSessionReportsMeasuredLowerRequestReplyDelay() throws {
        let lower = ObstacleBridgeLinuxOverlayTransportSession(
            exchange: { payload in payload },
            close: {}
        )
        let session = ObstacleBridgeLinuxConfiguredSession(
            lowerSession: lower,
            secureLink: nil,
            transport: .tcp
        )
        var samples: [Double] = []
        session.onTransportLivenessSample = { samples.append($0) }

        #expect(try session.send(Data("liveness".utf8)) == Data("liveness".utf8))
        #expect(samples.count == 1)
        #expect(samples[0] >= 0)
    }

    @Test func configuredSessionForwardsPeriodicLowerLivenessProbe() throws {
        var probes = 0
        let lower = ObstacleBridgeLinuxOverlayTransportSession(
            exchange: { payload in payload },
            probeLiveness: { probes += 1 },
            close: {}
        )
        let session = ObstacleBridgeLinuxConfiguredSession(
            lowerSession: lower,
            secureLink: nil,
            transport: .tcp
        )
        var samples: [Double] = []
        session.onTransportLivenessSample = { samples.append($0) }

        try session.probeLiveness()
        lower.onLivenessSample?(12.5)

        #expect(session.supportsLivenessProbes)
        #expect(probes == 1)
        #expect(samples == [12.5])
    }

    @Test func parsesSectionedTcpPskConfiguration() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "tcp"],
            "tcp_session": ["tcp_peer": "127.0.0.1", "tcp_peer_port": 4242],
            "secure_link": ["secure_link_mode": "psk", "secure_link_psk": "test-secret"],
        ]))
        #expect(config.transport == .tcp)
        #expect(config.host == "127.0.0.1")
        #expect(config.port == 4242)
        #expect(config.secureLinkPSK == Data("test-secret".utf8))
    }

    @Test func decryptsPythonCompatibleEncryptedSecureLinkPSKBeforeAdmission() throws {
        let encrypted = try ObstacleBridgeLinuxConfigSecretCodec.encryptForTesting(
            "native-peer-secret", nonce: Data(repeating: 7, count: 12)
        )
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "tcp"],
            "tcp_session": ["tcp_peer": "127.0.0.1", "tcp_peer_port": 4242],
            "secure_link": ["secure_link_mode": "psk", "secure_link_psk": encrypted],
        ]))
        #expect(config.secureLinkPSK == Data("native-peer-secret".utf8))
    }

    @Test func parsesTcpListenerConfigurationWithoutOutboundPeer() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "tcp", "listener_mode": true],
            "tcp_session": ["tcp_own_port": 4242],
            "secure_link": ["secure_link_mode": "psk", "secure_link_psk": "listener-secret"],
        ]))
        #expect(config.listenerMode)
        #expect(config.port == 4242)
        #expect(config.host == "listener")
    }

    @Test func parsesCleartextWebSocketListenerConfigurationWithoutOutboundPeer() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "ws", "listener_mode": true],
            "ws_session": ["ws_own_port": 4343, "ws_path": "/overlay"],
            "secure_link": ["secure_link_mode": "psk", "secure_link_psk": "listener-secret"],
        ]))
        #expect(config.listenerMode)
        #expect(config.transport == .ws)
        #expect(config.port == 4343)
        #expect(config.webSocketPath == "/overlay")
        #expect(config.host == "listener")
    }

    @Test func parsesCleartextWebSocketAndDefaultsPath() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "ws"],
            "ws_session": ["ws_peer": "peer.example", "ws_peer_port": 8080],
            "secure_link": ["secure_link_mode": "off"],
        ]))
        #expect(config.transport == .ws)
        #expect(config.webSocketPath == "/")
        #expect(config.secureLinkPSK == nil)
    }

    @Test func parsesVerifiedTLSWebSocketConfigurationWithCustomTrustRoots() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "ws"],
            "ws_session": [
                "ws_peer": "peer.example", "ws_peer_port": 443,
                "ws_tls": true, "ws_ca_cert": "/etc/obstaclebridge/wss-roots.pem",
            ],
        ]))
        #expect(config.webSocketTLS)
        #expect(config.webSocketTrustRootsPath == "/etc/obstaclebridge/wss-roots.pem")
    }

    @Test func requiresDistinctIdentityMaterialForWSSListener() throws {
        #expect(throws: ObstacleBridgeLinuxRuntimeConfigurationError.missingValue("WSS listener requires ws_session.ws_cert and ws_session.ws_key")) {
            try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
                "runner": ["overlay_transport": "ws", "listener_mode": true],
                "ws_session": ["ws_own_port": 443, "ws_tls": true],
                "secure_link": ["secure_link_mode": "psk", "secure_link_psk": "listener-secret"],
            ]))
        }
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "ws", "listener_mode": true],
            "ws_session": ["ws_own_port": 443, "ws_tls": true, "ws_cert": "/run/cert.pem", "ws_key": "/run/key.pem"],
            "secure_link": ["secure_link_mode": "psk", "secure_link_psk": "listener-secret"],
        ]))
        #expect(config.webSocketCertificatePath == "/run/cert.pem")
        #expect(config.webSocketPrivateKeyPath == "/run/key.pem")
    }

    @Test func parsesWebSocketTextPayloadMode() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "ws"],
            "ws_session": ["ws_peer": "peer.example", "ws_peer_port": 8080, "ws_payload_mode": "json-base64"],
        ]))
        #expect(config.webSocketPayloadMode == "json-base64")
    }

    @Test func parsesManualWebSocketProxyPolicy() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "ws"],
            "ws_session": ["ws_peer": "peer.example", "ws_peer_port": 8080, "ws_proxy_mode": "manual", "ws_proxy_host": "proxy.example", "ws_proxy_port": 3128],
        ]))
        #expect(config.webSocketProxy.mode == .manual)
        #expect(config.webSocketProxy.host == "proxy.example")
        #expect(config.webSocketProxy.port == 3128)
    }

    @Test func environmentProxyPolicySelectsAndBypassesEndpoints() throws {
        let policy = ObstacleBridgeLinuxHTTPProxy()
        #expect(try policy.endpoint(targetHost: "peer.example", secure: true, environment: ["HTTPS_PROXY": "http://proxy.example:8443"])?.0 == "proxy.example")
        #expect(try policy.endpoint(targetHost: "peer.example", secure: true, environment: ["HTTPS_PROXY": "http://proxy.example:8443"])?.1 == 8443)
        #expect(try policy.endpoint(targetHost: "api.internal", secure: false, environment: ["HTTP_PROXY": "proxy.example:8080", "NO_PROXY": ".internal"]) == nil)
        #expect(try policy.endpoint(targetHost: "127.0.0.1", secure: false, environment: ["HTTP_PROXY": "proxy.example:8080"]) == nil)
        #expect(try policy.endpoint(targetHost: "[::1]", secure: true, environment: ["HTTPS_PROXY": "proxy.example:8443"]) == nil)
    }

    @Test func proxyURLCredentialsProduceBasicAuthorizationWithoutChangingEndpoint() throws {
        let policy = ObstacleBridgeLinuxHTTPProxy(mode: .manual, host: "user%40name:pa%3Ass@proxy.example", port: 8081)
        let endpoint = try policy.endpoint(targetHost: "peer.example", secure: true)
        #expect(endpoint?.0 == "proxy.example")
        #expect(endpoint?.1 == 8081)
        #expect(policy.basicAuthorization(targetHost: "peer.example", secure: true) == "Basic dXNlckBuYW1lOnBhOnNz")
    }

    @Test func parsesBoundedMuxCompressionConfiguration() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "tcp"],
            "tcp_session": ["tcp_peer": "peer.example", "tcp_peer_port": 4242],
            "compress_layer": true,
            "compress_layer_level": 99,
            "compress_layer_min_bytes": -1,
            "compress_layer_types": "data, open, unknown",
        ]))
        #expect(config.compressionPolicy.enabled)
        #expect(config.compressionPolicy.level == 9)
        #expect(config.compressionPolicy.minimumBodyBytes == 0)
        #expect(config.compressionPolicy.allowedMessageTypes == [0, 1])
        #expect(config.receiveIdleTimeoutMilliseconds == 5_000)
        #expect(throws: ObstacleBridgeLinuxRuntimeConfigurationError.unsupportedCompressionAlgorithm("Linux compress_layer_algo=brotli is unavailable")) {
            try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
                "runner": ["overlay_transport": "tcp"],
                "tcp_session": ["tcp_peer": "peer.example", "tcp_peer_port": 4242],
                "compress_layer_algo": "brotli",
            ]))
        }
    }

    @Test func parsesSectionedMyudpConfiguration() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "myudp"],
            "udp_session": ["udp_peer": "127.0.0.1", "udp_peer_port": 4242],
        ]))
        #expect(config.transport == .myudp)
        #expect(config.host == "127.0.0.1")
        #expect(config.port == 4242)
    }

    @Test func parsesSectionedQuicConfigurationWithExplicitTrustPosture() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "quic"],
            "quic_session": ["quic_peer": "127.0.0.1", "quic_peer_port": 4242, "quic_alpn": "hq-29", "quic_insecure": true, "quic_ca_cert": "/etc/obstaclebridge/roots.pem"],
        ]))
        #expect(config.transport == .quic)
        #expect(config.host == "127.0.0.1")
        #expect(config.port == 4242)
        #expect(config.quicALPN == "hq-29")
        #expect(config.quicInsecure)
        #expect(config.quicTrustRootsPath == "/etc/obstaclebridge/roots.pem")
    }

    @Test func parsesAuthenticatedMyudpListenerConfigurationWithoutOutboundPeer() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "myudp", "listener_mode": true],
            "udp_session": ["udp_own_port": 4242],
            "secure_link": ["secure_link_mode": "psk", "secure_link_psk": "listener-secret"],
        ]))
        #expect(config.listenerMode)
        #expect(config.transport == .myudp)
        #expect(config.port == 4242)
        #expect(config.host == "listener")
        #expect(config.secureLinkPSK == Data("listener-secret".utf8))
    }

    @Test func myudpListenerAdmitsRemoteCatalogOnlyWhenExplicitlyEnabled() throws {
        let service: [String: Any] = [
            "name": "peer-side-http", "listen": ["protocol": "tcp", "bind": "127.0.0.1", "port": 8088],
            "target": ["protocol": "tcp", "host": "127.0.0.1", "port": 80],
        ]
        let base: [String: Any] = [
            "runner": ["overlay_transport": "myudp", "listener_mode": true],
            "udp_session": ["udp_own_port": 4242],
            "secure_link": ["secure_link_mode": "psk", "secure_link_psk": "listener-secret"],
            "channel_mux": ["remote_servers": [service]],
        ]
        #expect(try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json(base)).remoteServices.isEmpty)
        var admitted = base
        admitted["channel_mux"] = ["remote_servers": [service], "channel_mux_listener_publish_remote_services": true]
        let configuration = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json(admitted))
        #expect(configuration.listenerRemoteServicePublicationEnabled)
        #expect(configuration.remoteServices.count == 1)
    }

    @Test func parsesStructuredOwnAndRemoteServices() throws {
        let config = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "tcp"],
            "tcp_session": ["tcp_peer": "127.0.0.1", "tcp_peer_port": 4242],
            "channel_mux": [
                "own_servers": [[
                    "name": "tcp-echo",
                    "listen": ["protocol": "tcp", "bind": "127.0.0.1", "port": 7001],
                    "target": ["protocol": "tcp", "host": "127.0.0.1", "port": 7002],
                ]],
                "remote_servers": [[
                    "listen": ["protocol": "udp", "bind": "127.0.0.1", "port": 8001],
                    "target": ["protocol": "udp", "host": "127.0.0.1", "port": 8002],
                ]],
            ],
        ]))
        #expect(config.ownServices.count == 1)
        #expect(config.ownServices[0].name == "tcp-echo")
        #expect(config.ownServices[0].listenProtocol == .tcp)
        #expect(config.remoteServices[0].targetProtocol == .udp)
    }

    @Test func rejectsUnsupportedOrMismatchedServiceDefinitions() {
        #expect(throws: ObstacleBridgeLinuxRuntimeConfigurationError.invalidService("runtime config has invalid own_servers service at index 0")) {
            try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
                "runner": ["overlay_transport": "tcp"],
                "tcp_session": ["tcp_peer": "127.0.0.1", "tcp_peer_port": 4242],
                "own_servers": [[
                    "listen": ["protocol": "tcp", "bind": "127.0.0.1", "port": 7001],
                    "target": ["protocol": "udp", "host": "127.0.0.1", "port": 7002],
                ]],
            ]))
        }
    }

    @Test func rejectsUnsafeRuntimeChoicesBeforeNetworking() throws {
        #expect(throws: ObstacleBridgeLinuxRuntimeConfigurationError.missingValue("runtime config requires quic_session.quic_peer")) {
            try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json(["runner": ["overlay_transport": "quic"]]))
        }
        #expect(throws: ObstacleBridgeLinuxRuntimeConfigurationError.unavailableTransport("Linux QUIC listener mode is unavailable until LSW-005B.2 qualifies the backend's inbound-stream ownership")) {
            try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
                "runner": ["overlay_transport": "quic", "listener_mode": true],
                "quic_session": ["quic_own_port": 4242],
            ]))
        }
        #expect(throws: ObstacleBridgeLinuxRuntimeConfigurationError.missingPSK) {
            try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
                "runner": ["overlay_transport": "tcp"],
                "tcp_session": ["tcp_peer": "peer.example", "tcp_peer_port": 443],
                "secure_link": ["secure_link_mode": "psk"],
            ]))
        }
        #expect(throws: ObstacleBridgeLinuxRuntimeConfigurationError.unavailableTransport("Linux Swift TUN requires an explicit helper socket and session token; no unauthenticated Python fallback is used")) {
            try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
                "runner": ["overlay_transport": "tcp"],
                "tcp_session": ["tcp_peer": "peer.example", "tcp_peer_port": 443],
                "TUN_routing": ["enabled_on_startup": true],
            ]))
        }
        let proxyProvider = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "tcp"],
            "tcp_session": ["tcp_peer": "peer.example", "tcp_peer_port": 443],
            "proxy_provider": ["enabled": true, "proxy_provider_http_port": 13881, "proxy_provider_socks5_port": 13882],
        ]))
        #expect(proxyProvider.proxyProvider.enabled)
        #expect(proxyProvider.proxyProvider.httpPort == 13881)
        #expect(proxyProvider.proxyProvider.socks5Port == 13882)
        let operatorSupervised = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "tcp", "service_mode": true],
            "tcp_session": ["tcp_peer": "peer.example", "tcp_peer_port": 443],
        ]))
        #expect(operatorSupervised.transport == .tcp)
    }

    @Test func coreConfigurationPortKeepsGroupedPrecedenceForLinuxAdmission() throws {
        let payload: [String: Any] = [
            "overlay_transport": "myudp",
            "tcp_peer": "flat.invalid",
            "tcp_peer_port": "4444",
            "runner": ["overlay_transport": "tcp"],
            "tcp_session": ["tcp_peer": "grouped.example", "tcp_peer_port": "4242"],
        ]
        let flat = ObstacleBridgeRuntimeConfigPort.flatten(payload)
        #expect(flat["overlay_transport"] as? String == "tcp")
        #expect(flat["tcp_peer"] as? String == "grouped.example")
        #expect(flat["tcp_peer_port"] as? Int == 4242)
        let configuration = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json(payload))
        #expect(configuration.transport == .tcp)
        #expect(configuration.host == "grouped.example")
        #expect(configuration.port == 4242)
    }

    @Test func coreTunnelRoutingRecordRetainsIPv4AndIPv6Configuration() {
        let routing = ObstacleBridgeRuntimeConfigPort.tunnelRouting(from: [
            "TUN_routing": [
                "enabled_on_startup": true,
                "tunnel_address": "192.0.2.1", "tunnel_address6": "2001:db8::1", "mtu": "1400",
                "included_routes": ["10.0.0.0/8"], "excluded_routes": ["127.0.0.0/8"],
                "included_routes6": ["2001:db8::/32"], "excluded_routes6": ["::1/128"],
            ],
        ])
        #expect(routing.enabledOnStartup)
        #expect(routing.tunnelAddress == "192.0.2.1")
        #expect(routing.tunnelAddress6 == "2001:db8::1")
        #expect(routing.mtu == 1400)
        #expect(routing.includedRoutes == ["10.0.0.0/8"])
        #expect(routing.excludedRoutes6 == ["::1/128"])
    }

    @Test func linuxAdmissionAcceptsIPv6DefaultRouteAndHostExclusions() throws {
        let configuration = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: json([
            "runner": ["overlay_transport": "tcp"],
            "tcp_session": ["tcp_peer": "192.0.2.44", "tcp_peer_port": 443],
            "TUN_routing": [
                "included_routes6": ["::/0"],
                "excluded_routes6": ["::1/128", "fe80::/10"],
            ],
        ]))

        let plan = try #require(configuration.packetTunnelPlan)
        #expect(plan.includedRoutes6 == ["::/0"])
        #expect(plan.excludedRoutes6 == ["::1/128", "fe80::/10", "::ffff:192.0.2.44/128"])
    }

    @Test func coreTunnelRoutingRecordRejectsInvalidCIDR() throws {
        let routing = ObstacleBridgeRuntimeConfigPort.tunnelRouting(from: [
            "TUN_routing": ["included_routes": ["not-an-address/24"]],
        ])
        #expect(routing.invalidRoute == "not-an-address/24")
        #expect(throws: ObstacleBridgeLinuxRuntimeConfigurationError.invalidValue("runtime config has invalid TUN route not-an-address/24")) {
            let data = try JSONSerialization.data(withJSONObject: [
                "runner": ["overlay_transport": "tcp"],
                "tcp_session": ["tcp_peer": "127.0.0.1", "tcp_peer_port": 443],
                "TUN_routing": ["included_routes": ["not-an-address/24"]],
            ])
            _ = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: data)
        }
    }

    @Test func coreTunnelRoutingRecordDerivesIPv4AndIPv6PeerExclusions() {
        let routing = ObstacleBridgeRuntimeConfigPort.tunnelRouting(from: [
            "runner": ["overlay_transport": "tcp"],
            "tcp_session": [
                "tcp_peer": "192.0.2.44", "tcp_peer_port": 443,
                "tcp_resolve_family": "prefer-ipv6", "tcp_bind_host": "::",
            ],
            "TUN_routing": [
                "excluded_routes": ["127.0.0.0/8"],
                "excluded_routes6": ["::1/128"],
            ],
        ])
        #expect(routing.peerExcludedRoutes == ["192.0.2.44/32"])
        #expect(routing.peerExcludedRoutes6 == ["::ffff:192.0.2.44/128"])
        #expect(routing.effectiveExcludedRoutes == ["127.0.0.0/8", "192.0.2.44/32"])
        #expect(routing.effectiveExcludedRoutes6 == ["::1/128", "::ffff:192.0.2.44/128"])
    }

    @Test func corePacketTunnelPlanMergesDefaultsOverridesAndPeerExclusions() throws {
        let plan = try #require(ObstacleBridgeRuntimeConfigPort.packetTunnelPlan(from: [
            "runner": ["overlay_transport": "tcp"],
            "tcp_session": ["tcp_peer": "192.0.2.44", "tcp_peer_port": 443, "tcp_bind": "::"],
            "TUN_routing": ["mtu": 1400, "dns_servers": ["9.9.9.9"], "excluded_routes": ["10.0.0.0/8"]],
        ]))
        #expect(plan.includedRoutes == ["0.0.0.0/0"])
        #expect(plan.excludedRoutes == ["10.0.0.0/8", "192.0.2.44/32"])
        #expect(plan.dnsServers == ["9.9.9.9"])
        #expect(plan.mtu == 1400)
        #expect(plan.routeDiagnostics.baseExcludedRoutes == ["10.0.0.0/8"])
        #expect(plan.routeDiagnostics.peerExcludedRoutes == ["192.0.2.44/32"])
        #expect(plan.routeDiagnostics.peerExcludedRoutes6 == ["::ffff:192.0.2.44/128"])
    }

    @Test func linuxAdmissionRetainsDisabledCorePacketTunnelPlan() throws {
        let data = try JSONSerialization.data(withJSONObject: [
            "runner": ["overlay_transport": "tcp"],
            "tcp_session": ["tcp_peer": "192.0.2.44", "tcp_peer_port": 443],
            "TUN_routing": ["enabled_on_startup": false, "mtu": 1400],
        ])
        let configuration = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: data)
        let plan = try #require(configuration.packetTunnelPlan)
        #expect(!plan.enabledOnStartup)
        #expect(!configuration.packetTunnelEnabled)
        #expect(plan.mtu == 1400)
        #expect(plan.excludedRoutes == ["127.0.0.0/8", "192.0.2.44/32"])
    }

    @Test func linuxAdmissionAllowsEnabledPlanOnlyWithHelperOwner() throws {
        let data = try JSONSerialization.data(withJSONObject: [
            "runner": ["overlay_transport": "tcp"],
            "tcp_session": ["tcp_peer": "192.0.2.44", "tcp_peer_port": 443],
            "tun_execution": ["tun_execution_mode": "helper", "tun_helper_socket": "/tmp/obstaclebridge-helper.sock", "tun_helper_session_token": "test-helper-token"],
            "TUN_routing": ["enabled_on_startup": true],
        ])
        let configuration = try ObstacleBridgeLinuxRuntimeConfiguration.parse(data: data)
        #expect(configuration.packetTunnelPlan?.enabledOnStartup == true)
        #expect(configuration.packetTunnelEnabled)
        #expect(configuration.tunHelperSocketPath == "/tmp/obstaclebridge-helper.sock")
    }

    @Test func coreConfigurationPortPublishesSecretMetadataAndRedactsValues() throws {
        #expect(ObstacleBridgeRuntimeConfigPort.secretKeys() == Set(["admin_web_password", "secure_link_psk", "tun_helper_session_token"]))
        let redacted = ObstacleBridgeRuntimeConfigPort.redactedConfiguration([
            "admin_web": ["admin_web_password": "admin-secret"],
            "secure_link": ["secure_link_psk": "link-secret"],
            "tun_execution": ["tun_helper_session_token": "helper-secret"],
        ])
        let admin = try #require(redacted["admin_web"] as? [String: Any])
        let secure = try #require(redacted["secure_link"] as? [String: Any])
        let tunExecution = try #require(redacted["tun_execution"] as? [String: Any])
        #expect(admin["admin_web_password"] as? String == "***hidden***")
        #expect(admin["admin_web_password_present"] as? Bool == true)
        #expect(secure["secure_link_psk"] as? String == "***hidden***")
        #expect(secure["secure_link_psk_present"] as? Bool == true)
        #expect(tunExecution["tun_helper_session_token"] as? String == "***hidden***")
        #expect(tunExecution["tun_helper_session_token_present"] as? Bool == true)
    }

    @Test func coreBootstrapSelectsLinuxClientTransportAndLayers() throws {
        let bootstrap = try ObstacleBridgeRuntimeConfigPort.overlayBootstrap(from: [
            "runner": ["overlay_transport": "tcp"],
            "tcp_session": ["tcp_peer": "192.0.2.44", "tcp_peer_port": 443],
            "secure_link": ["secure_link": true, "secure_link_mode": "psk", "secure_link_psk": "secret"],
            "compress_layer": ["compress_layer": true, "compress_layer_algo": "zlib"],
        ])
        #expect(bootstrap.transport == "tcp")
        #expect(bootstrap.transports == ["tcp"])
        #expect(bootstrap.layersTopDown == ["compress_layer", "secure_link_psk", "tcp"])
        #expect(bootstrap.compressWrapped)
        #expect(bootstrap.secureLinkMode == "psk")
    }

    @Test func coreCatalogFramesEncodeConfiguredRemoteServices() throws {
        let frames = ObstacleBridgeRuntimeConfigPort.remoteServiceCatalogFrames(
            from: [
                "channel_mux": [
                    "remote_servers": [[
                        "name": "echo",
                        "listen": ["protocol": "tcp", "bind": "127.0.0.1", "port": "7001"],
                        "target": ["protocol": "tcp", "host": "example.test", "port": 7002],
                    ]],
                ],
            ],
            instanceID: 9, connectionSequence: 3
        )
        #expect(frames.count == 1)
        #expect(frames.first?.messageType == .remoteServicesSetV2)
        let catalog = try ObstacleBridgeServiceCodec.decodeRemoteServices(try #require(frames.first?.body))
        #expect(catalog.instanceID == 9)
        #expect(catalog.connectionSequence == 3)
        #expect(catalog.services.first?.name == "echo")
        #expect(catalog.services.first?.targetHost == "example.test")
    }

    @Test func runtimeStatusReportsAdmissionStateWithoutLeakingPsk() throws {
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(
            transport: .tcp,
            host: "first.example,second.example",
            port: 4242,
            secureLinkPSK: Data("must-not-appear".utf8)
        ))
        let status = runtime.status()
        #expect(status.transport == "tcp")
        #expect(status.state == "disconnected")
        #expect(status.configuredCandidates == ["first.example", "second.example"])
        #expect(status.activeHost == nil)
        #expect(status.secureLinkMode == "psk")
        #expect(status.secureLinkState == "disconnected")
        #expect(!status.appReady)
        let encoded = try JSONEncoder().encode(status)
        #expect(!String(decoding: encoded, as: UTF8.self).contains("must-not-appear"))
    }

    private func json(_ value: [String: Any]) -> Data {
        try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    }
}
