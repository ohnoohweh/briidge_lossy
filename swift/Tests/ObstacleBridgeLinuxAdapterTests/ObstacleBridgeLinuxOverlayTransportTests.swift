import Foundation
import Testing
@testable import ObstacleBridgeLinuxAdapters
@testable import ObstacleBridgeCore

struct ObstacleBridgeLinuxOverlayTransportTests {
    @Test func tcpPSKListenerAuthenticatesAndEchoesProtectedClientPayload() throws {
        let psk = Data("tcp-listener-psk".utf8)
        let listener = try ObstacleBridgeLinuxTCPPSKListener(port: 0)
        defer { listener.close() }
        let served = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            _ = try? listener.serveOne(psk: psk, serverNonce: Data(0..<32))
            served.signal()
        }
        let lower = try ObstacleBridgeLinuxOverlayTransportClient(host: "127.0.0.1", port: listener.port, transport: .tcp)
        let session = try lower.openSession()
        let client = try ObstacleBridgeSecureLinkPSKClient(psk: psk)
        let nonce = Data(0x20..<0x40)
        let proof = try client.handleServerHello(session.exchange(try client.begin(sessionID: 9, clientNonce: nonce)))
        try client.handleServerAcknowledgement(session.exchange(proof))
        #expect(try client.unprotect(session.exchange(client.protect(Data("python-client".utf8)))) == Data("python-client".utf8))
        session.close()
        #expect(served.wait(timeout: .now() + 2) == .success)
    }

    @Test func tcpFramingRoundTripsAgainstPythonPeer() throws {
        let peer = try PythonOverlayPeer(mode: "tcp")
        defer { peer.stop() }
        let client = try ObstacleBridgeLinuxOverlayTransportClient(host: "127.0.0.1", port: peer.port, transport: .tcp)
        let payload = Data("swift-linux-tcp".utf8)
        #expect(try client.roundTrip(payload) == payload)
        #expect(client.snapshot.state == "connected")
    }

    @Test func tcpDuplexSessionReceivesPeerFrameBeforeLocalSend() throws {
        let peer = try PythonOverlayPeer(mode: "tcp-duplex")
        defer { peer.stop() }
        let client = try ObstacleBridgeLinuxOverlayTransportClient(host: "127.0.0.1", port: peer.port, transport: .tcp)
        let session = try client.openSession()
        defer { session.close() }
        #expect(try session.receive() == Data("python-first".utf8))
        try session.send(Data("swift-second".utf8))
        #expect(try session.receive() == Data("python:swift-second".utf8))
    }

    @Test func webSocketDuplexSessionReceivesPeerFrameBeforeLocalSend() throws {
        let peer = try PythonOverlayPeer(mode: "ws-duplex")
        defer { peer.stop() }
        let client = try ObstacleBridgeLinuxOverlayTransportClient(host: "127.0.0.1", port: peer.port, transport: .ws, wsPath: "/overlay")
        let session = try client.openSession(); defer { session.close() }
        #expect(try session.receive() == Data("python-first".utf8))
    }

    @Test func myudpDuplexSessionReceivesPeerFrameAfterAddressRegistration() throws {
        let peer = try PythonOverlayPeer(mode: "myudp-duplex")
        defer { peer.stop() }
        let client = try ObstacleBridgeLinuxOverlayTransportClient(host: "127.0.0.1", port: peer.port, transport: .myudp)
        let session = try client.openSession(); defer { session.close() }
        try session.send(Data("register".utf8))
        #expect(try session.receive() == Data("python-first".utf8))
    }

    @Test func webSocketUpgradeAndBinaryFrameRoundTripAgainstPythonPeer() throws {
        let peer = try PythonOverlayPeer(mode: "ws")
        defer { peer.stop() }
        let client = try ObstacleBridgeLinuxOverlayTransportClient(host: "127.0.0.1", port: peer.port, transport: .ws, wsPath: "/overlay")
        let payload = try ObstacleBridgeSecureLinkPSKCrypto.serverProof(
            psk: Data(repeating: 7, count: 32),
            sessionID: 9,
            clientNonce: Data(repeating: 1, count: 32),
            serverNonce: Data(repeating: 2, count: 32)
        )
        #expect(try client.roundTrip(payload) == payload)
        #expect(client.snapshot.state == "connected")
    }

    @Test func webSocketTextFramesNegotiateAndRoundTripAgainstPythonPeer() throws {
        for mode in ["base64", "json-base64", "semi-text-shape"] {
            let peer = try PythonOverlayPeer(mode: "ws-text-\(mode)")
            defer { peer.stop() }
            let client = try ObstacleBridgeLinuxOverlayTransportClient(host: "127.0.0.1", port: peer.port, transport: .ws, wsPath: "/overlay", wsPayloadMode: mode)
            #expect(try client.roundTrip(Data("swift-text".utf8)) == Data("swift-text".utf8))
        }
    }

    @Test func unqualifiedTransportsAreRejectedBeforeSocketCreation() {
        #expect(throws: ObstacleBridgeLinuxOverlayTransportError.unavailableTransport("Linux QUIC is unavailable: the Network.framework owner has no qualified Linux backend")) {
            try ObstacleBridgeLinuxOverlayTransportClient(host: "127.0.0.1", port: 1, transport: .quic)
        }
    }

    @Test func myudpDataFrameRoundTripsAgainstPythonPeer() throws {
        let peer = try PythonOverlayPeer(mode: "myudp")
        defer { peer.stop() }
        let client = try ObstacleBridgeLinuxOverlayTransportClient(host: "127.0.0.1", port: peer.port, transport: .myudp)
        #expect(try client.roundTrip(Data("myudp".utf8)) == Data("myudp".utf8))
        #expect(client.snapshot.state == "connected")
    }

    @Test func myudpTransportUsesSequentialRolloverAgainstPythonPeer() throws {
        let peer = try PythonOverlayPeer(mode: "myudp-rollover")
        defer { peer.stop() }
        let session = try ObstacleBridgeLinuxMyUDPTransportSession(host: "127.0.0.1", port: peer.port, nextDataCounter: .max)
        defer { session.close() }
        #expect(try session.exchange(Data("max".utf8)) == Data("python:65535:max".utf8))
        #expect(try session.exchange(Data("wrapped".utf8)) == Data("python:1:wrapped".utf8))
    }

    @Test func myudpTransportExchangeRecoversDroppedDataThroughCoreTimerEffect() throws {
        let peer = try PythonOverlayPeer(mode: "myudp-drop-first-data")
        defer { peer.stop() }
        let session = try ObstacleBridgeLinuxMyUDPTransportSession(host: "127.0.0.1", port: peer.port)
        defer { session.close() }
        #expect(try session.exchange(Data("retransmit-me".utf8)) == Data("retransmit-me".utf8))
    }

    @Test func myudpTransportReassemblesDuplicatedOutOfOrderPythonChunks() throws {
        let peer = try PythonOverlayPeer(mode: "myudp-reordered-inbound")
        defer { peer.stop() }
        let session = try ObstacleBridgeLinuxMyUDPTransportSession(host: "127.0.0.1", port: peer.port)
        defer { session.close() }
        _ = try session.send(Data("register".utf8))
        #expect(try session.receive().payload == Data("python-reordered".utf8))
    }

    @Test func myudpTransportRejectsMalformedPythonDatagramAndClosedSession() throws {
        let peer = try PythonOverlayPeer(mode: "myudp-malformed")
        defer { peer.stop() }
        let session = try ObstacleBridgeLinuxMyUDPTransportSession(host: "127.0.0.1", port: peer.port)
        _ = try session.send(Data("register".utf8))
        #expect(throws: ObstacleBridgeLinuxMyUDPError.invalidReply) { try session.receive() }
        session.close()
        #expect(throws: ObstacleBridgeLinuxMyUDPError.ioFailure(EBADF)) { try session.serviceTimers() }
    }

    @Test func configuredMyudpSecureLinkSessionCarriesProtectedDataAgainstPythonPeer() throws {
        let peer = try PythonOverlayPeer(mode: "myudp-securelink")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(
            transport: .myudp,
            host: "127.0.0.1",
            port: peer.port,
            secureLinkPSK: Data("linux-swift-psk".utf8)
        ))
        let session = try runtime.connect(sessionID: 42, clientNonce: Data(repeating: 3, count: 32))
        defer { runtime.disconnect() }
        #expect(try session.send(Data("myudp-secure".utf8)) == Data("python:myudp-secure".utf8))
        #expect(runtime.status().appReady)
    }

    @Test func tcpSecureLinkReceivesProtectedPeerFrameBeforeLocalSend() throws {
        try secureLinkPeerFirstReceive(mode: "tcp-securelink-duplex", transport: .tcp)
    }

    @Test func webSocketSecureLinkReceivesProtectedPeerFrameBeforeLocalSend() throws {
        try secureLinkPeerFirstReceive(mode: "ws-securelink-duplex", transport: .ws)
    }

    @Test func myudpSecureLinkReceivesProtectedPeerFrameBeforeLocalSend() throws {
        try secureLinkPeerFirstReceive(mode: "myudp-securelink-duplex", transport: .myudp)
    }

    @Test func protectedUnsolicitedChannelMuxFrameReachesOneReceiveOwner() throws {
        for (mode, transport) in [("tcp-securelink-mux-duplex", ObstacleBridgeLinuxTransport.tcp), ("ws-securelink-mux-duplex", .ws)] {
            let peer = try PythonOverlayPeer(mode: mode)
            defer { peer.stop() }
            let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(
                transport: transport, host: "127.0.0.1", port: peer.port,
                secureLinkPSK: Data("linux-swift-psk".utf8)
            ))
            let session = try runtime.connect(sessionID: 67, clientNonce: Data(repeating: 7, count: 32))
            defer { runtime.disconnect() }
            let mux = try ObstacleBridgeLinuxChannelMuxSession(runtime: runtime, session: session)
            let delivered = DispatchSemaphore(value: 0)
            var received: ObstacleBridgeChannelMuxFrame?
            mux.onUnsolicitedFrame = { frame in received = frame; delivered.signal() }
            mux.activateReceiveOwner()
            let worker = ObstacleBridgeLinuxReceiveWorker(epoch: runtime.connectionEpoch, receive: { try session.receiveInbound() }, cancelReceive: { session.cancelReceive() }) { _, wire in
                if let frame = try? ObstacleBridgeChannelMuxCodec.decode(wire) { mux.receive(frame) }
            }
            worker.start()
            #expect(delivered.wait(timeout: .now() + 3) == .success)
            #expect(received == .init(channelID: 7, protocolType: .udp, counter: 1, messageType: .data, body: Data("hello".utf8)))
            worker.stop()
        }
    }

    @Test func linuxChannelMuxReassemblesCoreControlChunksBeforeDelivery() throws {
        let peer = try PythonOverlayPeer(mode: "tcp")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .tcp, host: "127.0.0.1", port: peer.port))
        let session = try runtime.connect(sessionID: 68, clientNonce: Data(repeating: 8, count: 32))
        defer { runtime.disconnect() }
        let mux = try ObstacleBridgeLinuxChannelMuxSession(runtime: runtime, session: session)
        let payload = Data(repeating: 0x42, count: 40)
        let chunks = try ObstacleBridgeControlChunkCodec.chunk(transactionID: 5, maximumApplicationPayload: 32, payload: payload)
        let delivered = DispatchSemaphore(value: 0)
        var received: ObstacleBridgeChannelMuxFrame?
        mux.onUnsolicitedFrame = { frame in received = frame; delivered.signal() }
        for chunk in chunks.reversed() {
            mux.receive(.init(channelID: 3, protocolType: .tcp, counter: 2, messageType: .openChunk, body: chunk))
        }
        #expect(delivered.wait(timeout: .now() + 1) == .success)
        #expect(received == .init(channelID: 3, protocolType: .tcp, counter: 2, messageType: .open, body: payload))
    }

    @Test func myudpSecureLinkCarriesChannelMuxFrameAgainstPythonPeer() throws {
        let peer = try PythonOverlayPeer(mode: "myudp-secure-mux")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .myudp, host: "127.0.0.1", port: peer.port, secureLinkPSK: Data("linux-swift-psk".utf8)))
        let session = try runtime.connect(sessionID: 50, clientNonce: Data(repeating: 4, count: 32))
        defer { runtime.disconnect() }
        let mux = try ObstacleBridgeLinuxChannelMuxSession(runtime: runtime, session: session)
        let frame = ObstacleBridgeChannelMuxFrame(channelID: 1, protocolType: .udp, counter: 1, messageType: .data, body: Data("mux-myudp".utf8))
        #expect(try mux.exchange(frame) == frame)
    }

    @Test func myudpSupervisorRotatesCandidateAfterFailedEpoch() throws {
        let peer = try PythonOverlayPeer(mode: "myudp")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .myudp, host: "127.0.0.2,127.0.0.1", port: peer.port))
        let supervisor = ObstacleBridgeLinuxReconnectSupervisor(runtime: runtime, policy: .init(initialDelayMilliseconds: 5, maximumDelayMilliseconds: 10, maximumAttempts: 2))
        let connected = DispatchSemaphore(value: 0)
        supervisor.onSnapshot = { if $0.state == "connected" { connected.signal() } }
        supervisor.start(probe: Data("rotate-myudp".utf8), sessionID: 130, clientNonce: Data(repeating: 12, count: 32))
        #expect(connected.wait(timeout: .now() + 3) == .success)
        #expect(supervisor.snapshot.attempts == 2)
        #expect(runtime.status().activeHost == "127.0.0.1")
        supervisor.stop()
    }

    @Test func myudpSupervisorUsesCoreTimerRecoveryBeforeReconnect() throws {
        let peer = try PythonOverlayPeer(mode: "myudp-drop-first")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .myudp, host: "127.0.0.1,127.0.0.1", port: peer.port))
        let supervisor = ObstacleBridgeLinuxReconnectSupervisor(runtime: runtime, policy: .init(initialDelayMilliseconds: 5, maximumDelayMilliseconds: 10, maximumAttempts: 2))
        let connected = DispatchSemaphore(value: 0)
        supervisor.onSnapshot = { if $0.state == "connected" { connected.signal() } }
        supervisor.start(probe: Data("silent-myudp".utf8), sessionID: 140, clientNonce: Data(repeating: 13, count: 32))
        #expect(connected.wait(timeout: .now() + 3) == .success)
        #expect(supervisor.snapshot.attempts == 1)
        supervisor.stop()
    }

    @Test func tcpSecureLinkPskSessionAuthenticatesAndCarriesDataAgainstPythonPeer() throws {
        try secureLinkSessionRoundTrip(mode: "tcp-securelink", transport: .tcp)
    }

    @Test func webSocketSecureLinkPskSessionAuthenticatesAndCarriesDataAgainstPythonPeer() throws {
        try secureLinkSessionRoundTrip(mode: "ws-securelink", transport: .ws)
    }

    @Test func tcpSecureLinkWrongPskFailsClosedAgainstPythonPeer() throws {
        let peer = try PythonOverlayPeer(mode: "tcp-securelink")
        defer { peer.stop() }
        let lower = try ObstacleBridgeLinuxOverlayTransportClient(host: "127.0.0.1", port: peer.port, transport: .tcp)
        let session = try lower.openSession()
        defer { session.close() }
        let client = try ObstacleBridgeSecureLinkPSKClient(psk: Data("wrong-linux-swift-psk".utf8))
        let hello = try client.begin(sessionID: 77, clientNonce: Data(repeating: 7, count: 32))
        #expect(throws: ObstacleBridgeSecureLinkPSKClientError.authenticationFailed) {
            try client.handleServerHello(session.exchange(hello))
        }
        #expect(!client.isAuthenticated)
        #expect(throws: ObstacleBridgeSecureLinkPSKClientError.invalidState) {
            try client.protect(Data("must-not-forward".utf8))
        }
    }

    @Test func tcpAndWebSocketSecureLinkRejectMalformedPythonPeerFrames() throws {
        for (mode, transport) in [
            ("tcp-securelink-malformed", ObstacleBridgeLinuxTransport.tcp),
            ("ws-securelink-malformed", .ws),
        ] {
            try secureLinkPeerRejectsMalformedFrame(mode: mode, transport: transport)
        }
    }

    @Test func tcpAndWebSocketSecureLinkRejectReplayedPythonPeerFrames() throws {
        for (mode, transport) in [
            ("tcp-securelink-replay", ObstacleBridgeLinuxTransport.tcp),
            ("ws-securelink-replay", .ws),
        ] {
            try secureLinkPeerRejectsReplay(mode: mode, transport: transport)
        }
    }

    @Test func myudpSecureLinkRejectsMalformedPythonPeerFrames() throws {
        try secureLinkPeerRejectsMalformedFrame(mode: "myudp-securelink-malformed", transport: .myudp)
    }

    @Test func myudpSecureLinkRejectsReplayedPythonPeerFrames() throws {
        try secureLinkPeerRejectsReplay(mode: "myudp-securelink-replay", transport: .myudp)
    }

    @Test func admittedTransportsRekeyAgainstPythonPeerAndKeepTrafficFlowing() throws {
        for (mode, transport) in [
            ("tcp-securelink-rekey", ObstacleBridgeLinuxTransport.tcp),
            ("ws-securelink-rekey", .ws),
            ("myudp-securelink-rekey", .myudp),
        ] {
            try secureLinkSessionRekeys(mode: mode, transport: transport)
        }
    }

    @Test func tcpSecureLinkReconnectsWithFreshPythonPeerSession() throws {
        try secureLinkSessionReconnects(mode: "tcp-securelink-reconnect", transport: .tcp)
    }

    @Test func webSocketSecureLinkReconnectsWithFreshPythonPeerSession() throws {
        try secureLinkSessionReconnects(mode: "ws-securelink-reconnect", transport: .ws)
    }

    @Test func myudpSecureLinkReconnectsWithFreshPythonPeerSession() throws {
        try secureLinkSessionReconnects(mode: "myudp-securelink-reconnect", transport: .myudp)
    }

    @Test func admittedTransportsRejectStalePythonPeerFramesAfterReconnect() throws {
        for (mode, transport) in [
            ("tcp-securelink-reconnect-stale", ObstacleBridgeLinuxTransport.tcp),
            ("ws-securelink-reconnect-stale", .ws),
            ("myudp-securelink-reconnect-stale", .myudp),
        ] {
            try secureLinkSessionRejectsStaleReconnectFrame(mode: mode, transport: transport)
        }
    }

    private func secureLinkSessionReconnects(mode: String, transport: ObstacleBridgeLinuxTransport) throws {
        let peer = try PythonOverlayPeer(mode: mode)
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(
            transport: transport, host: "127.0.0.1", port: peer.port,
            webSocketPath: "/overlay", secureLinkPSK: Data("linux-swift-psk".utf8)
        ))
        let first = try runtime.connect(sessionID: 92, clientNonce: Data(repeating: 11, count: 32))
        #expect(try first.send(Data("first-epoch".utf8)) == Data("python:first-epoch".utf8))
        let second = try runtime.reconnect(sessionID: 93, clientNonce: Data(repeating: 12, count: 32))
        #expect(first.snapshot.state == "disconnected")
        #expect(try second.send(Data("second-epoch".utf8)) == Data("python:second-epoch".utf8))
        runtime.disconnect()
    }

    @Test func configDrivenRuntimePumpsProtectedDataAgainstPythonPeers() throws {
        for (mode, transport) in [("tcp-securelink", ObstacleBridgeLinuxTransport.tcp), ("ws-securelink", .ws)] {
            let peer = try PythonOverlayPeer(mode: mode)
            defer { peer.stop() }
            let config = ObstacleBridgeLinuxRuntimeConfiguration(
                transport: transport,
                host: "127.0.0.1",
                port: peer.port,
                webSocketPath: "/overlay",
                secureLinkPSK: Data("linux-swift-psk".utf8)
            )
            let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: config)
            let session = try runtime.connect(sessionID: 42, clientNonce: Data(repeating: 3, count: 32))
            #expect(runtime.status().secureLinkState == "authenticated")
            #expect(runtime.status().appReady)
            #expect(try session.send(Data("runtime-payload".utf8)) == Data("python:runtime-payload".utf8))
            #expect(try session.send(Data("second-payload".utf8)) == Data("python:second-payload".utf8))
            session.close()
            #expect(session.snapshot.state == "disconnected")
            #expect(runtime.snapshot.state == "connected")
            runtime.disconnect()
            #expect(runtime.status().secureLinkState == "disconnected")
            #expect(!runtime.status().appReady)
        }
    }

    @Test func configDrivenRuntimeRotatesToNextConfiguredCandidate() throws {
        let peer = try PythonOverlayPeer(mode: "tcp")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(
            transport: .tcp,
            host: "127.0.0.2,127.0.0.1",
            port: peer.port
        ))
        let session = try runtime.connect(sessionID: 7, clientNonce: Data(repeating: 1, count: 32))
        defer { session.close() }
        #expect(try session.send(Data("candidate-rotation".utf8)) == Data("candidate-rotation".utf8))
        #expect(runtime.snapshot.attempts == 2)
        #expect(runtime.snapshot.state == "connected")
    }

    @Test func configuredRuntimeReconnectsWithFreshTransportEpoch() throws {
        let peer = try PythonOverlayPeer(mode: "tcp-reconnect")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .tcp, host: "127.0.0.1", port: peer.port))
        let first = try runtime.connect(sessionID: 7, clientNonce: Data(repeating: 1, count: 32))
        #expect(try first.send(Data("first".utf8)) == Data("first".utf8))
        let second = try runtime.reconnect(sessionID: 8, clientNonce: Data(repeating: 2, count: 32))
        #expect(first.snapshot.state == "disconnected")
        #expect(try second.send(Data("second".utf8)) == Data("second".utf8))
        runtime.disconnect()
        #expect(second.snapshot.state == "disconnected")
        #expect(runtime.snapshot.state == "disconnected")
    }

    @Test func configuredRuntimeRetriesFailedTransactionOnFreshEpoch() throws {
        let peer = try PythonOverlayPeer(mode: "tcp-drop-then-echo")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .tcp, host: "127.0.0.1", port: peer.port))
        let reply = try runtime.roundTrip(Data("retry".utf8), sessionID: 20, clientNonce: Data(repeating: 4, count: 32), retryCount: 1)
        #expect(reply == Data("retry".utf8))
        #expect(runtime.snapshot.state == "disconnected")
        #expect(runtime.snapshot.attempts == 2)
    }

    @Test func channelMuxFramesUseReadySessionAndRejectStaleEpoch() throws {
        let peer = try PythonOverlayPeer(mode: "tcp-mux-reconnect")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .tcp, host: "127.0.0.1", port: peer.port))
        let session = try runtime.connect(sessionID: 120, clientNonce: Data(repeating: 9, count: 32))
        let catalog = ObstacleBridgeChannelMuxFrame(channelID: 0, protocolType: .tcp, counter: 0, messageType: .remoteServicesSetV2, body: Data("RS3[]".utf8))
        let mux = try ObstacleBridgeLinuxChannelMuxSession(runtime: runtime, session: session, startupFrames: [catalog])
        let frame = ObstacleBridgeChannelMuxFrame(channelID: 7, protocolType: .tcp, counter: 1, messageType: .data, body: Data("mux".utf8))
        #expect(try mux.exchange(frame) == frame)
        let replacement = try runtime.reconnect(sessionID: 121, clientNonce: Data(repeating: 10, count: 32))
        _ = try ObstacleBridgeLinuxChannelMuxSession(runtime: runtime, session: replacement, startupFrames: [catalog])
        #expect(throws: ObstacleBridgeLinuxChannelMuxError.staleEpoch) { try mux.exchange(frame) }
        runtime.disconnect()
    }

    @Test func reconnectSupervisorRecoversAndStopsPendingTimers() throws {
        let peer = try PythonOverlayPeer(mode: "tcp-drop-then-echo")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .tcp, host: "127.0.0.1", port: peer.port))
        let supervisor = ObstacleBridgeLinuxReconnectSupervisor(
            runtime: runtime,
            policy: .init(initialDelayMilliseconds: 10, maximumDelayMilliseconds: 20, maximumAttempts: 2)
        )
        let connected = DispatchSemaphore(value: 0)
        supervisor.onSnapshot = { snapshot in
            if snapshot.state == "connected" { connected.signal() }
        }
        supervisor.start(probe: Data("supervisor".utf8), sessionID: 90, clientNonce: Data(repeating: 6, count: 32))
        #expect(connected.wait(timeout: .now() + 2) == .success)
        #expect(supervisor.snapshot.attempts == 2)
        #expect(supervisor.snapshot.state == "connected")
        supervisor.stop()
        let stopped = expectationSnapshot(supervisor, state: "stopped")
        #expect(stopped)
        #expect(runtime.status().state == "disconnected")
    }

    @Test func reconnectSupervisorReportsBoundedRetryExhaustion() {
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .tcp, host: "127.0.0.1", port: 1))
        let supervisor = ObstacleBridgeLinuxReconnectSupervisor(
            runtime: runtime,
            policy: .init(initialDelayMilliseconds: 5, maximumDelayMilliseconds: 10, maximumAttempts: 2)
        )
        let failed = DispatchSemaphore(value: 0)
        supervisor.onSnapshot = { snapshot in
            if snapshot.state == "failed" { failed.signal() }
        }
        supervisor.start(probe: Data("exhaust".utf8), sessionID: 100, clientNonce: Data(repeating: 7, count: 32))
        #expect(failed.wait(timeout: .now() + 2) == .success)
        #expect(supervisor.snapshot.attempts == 2)
        #expect(supervisor.snapshot.failureReason != nil)
        supervisor.stop()
    }

    @Test func reconnectSupervisorStopCancelsPendingRetry() {
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .tcp, host: "127.0.0.1", port: 1))
        let supervisor = ObstacleBridgeLinuxReconnectSupervisor(
            runtime: runtime,
            policy: .init(initialDelayMilliseconds: 250, maximumDelayMilliseconds: 250, maximumAttempts: 3)
        )
        let retryPending = DispatchSemaphore(value: 0)
        let stopped = DispatchSemaphore(value: 0)
        let secondAttempt = DispatchSemaphore(value: 0)
        supervisor.onSnapshot = { snapshot in
            if snapshot.state == "reconnecting", snapshot.attempts == 1, snapshot.nextRetryMilliseconds == 250 { retryPending.signal() }
            if snapshot.state == "stopped" { stopped.signal() }
            if snapshot.attempts >= 2 { secondAttempt.signal() }
        }
        supervisor.start(probe: Data("cancel".utf8), sessionID: 110, clientNonce: Data(repeating: 8, count: 32))
        #expect(retryPending.wait(timeout: .now() + 2) == .success)
        supervisor.stop()
        #expect(stopped.wait(timeout: .now() + 2) == .success)
        #expect(secondAttempt.wait(timeout: .now() + 0.4) == .timedOut)
        #expect(supervisor.snapshot.attempts == 1)
        #expect(supervisor.snapshot.state == "stopped")
    }

    private func expectationSnapshot(_ supervisor: ObstacleBridgeLinuxReconnectSupervisor, state: String) -> Bool {
        let limit = Date().addingTimeInterval(1)
        while Date() < limit {
            if supervisor.snapshot.state == state { return true }
            Thread.sleep(forTimeInterval: 0.005)
        }
        return false
    }

    private func secureLinkSessionRoundTrip(mode: String, transport: ObstacleBridgeLinuxTransport) throws {
        let peer = try PythonOverlayPeer(mode: mode)
        defer { peer.stop() }
        let lower = try ObstacleBridgeLinuxOverlayTransportClient(
            host: "127.0.0.1", port: peer.port, transport: transport, wsPath: "/overlay"
        )
        let session = try lower.openSession()
        defer { session.close() }
        let secureLink = try ObstacleBridgeSecureLinkPSKClient(psk: Data("linux-swift-psk".utf8))
        let hello = try secureLink.begin(sessionID: 42, clientNonce: Data(repeating: 3, count: 32))
        let proof = try secureLink.handleServerHello(session.exchange(hello))
        try secureLink.handleServerAcknowledgement(session.exchange(proof))
        let reply = try secureLink.unprotect(session.exchange(secureLink.protect(Data("payload".utf8))))
        #expect(reply == Data("python:payload".utf8))
        #expect(secureLink.isAuthenticated)
        #expect(lower.snapshot.state == "connected")
    }

    private func secureLinkPeerFirstReceive(mode: String, transport: ObstacleBridgeLinuxTransport) throws {
        let peer = try PythonOverlayPeer(mode: mode)
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(
            transport: transport, host: "127.0.0.1", port: peer.port,
            secureLinkPSK: Data("linux-swift-psk".utf8)
        ))
        let session = try runtime.connect(sessionID: 66, clientNonce: Data(repeating: 6, count: 32))
        defer { runtime.disconnect() }
        #expect(try session.receiveInbound() == Data("python-first".utf8))
        try session.sendOneWay(Data("swift-second".utf8))
        #expect(try session.receiveInbound() == Data("python:swift-second".utf8))
    }

    private func secureLinkPeerRejectsMalformedFrame(mode: String, transport: ObstacleBridgeLinuxTransport) throws {
        let peer = try PythonOverlayPeer(mode: mode)
        defer { peer.stop() }
        let lower = try ObstacleBridgeLinuxOverlayTransportClient(host: "127.0.0.1", port: peer.port, transport: transport, wsPath: "/overlay")
        let session = try lower.openSession()
        defer { session.close() }
        let client = try ObstacleBridgeSecureLinkPSKClient(psk: Data("linux-swift-psk".utf8))
        let proof = try client.handleServerHello(session.exchange(try client.begin(sessionID: 88, clientNonce: Data(repeating: 8, count: 32))))
        try client.handleServerAcknowledgement(session.exchange(proof))
        #expect(throws: ObstacleBridgeSecureLinkPSKClientError.invalidFrame) {
            try client.unprotect(session.receive())
        }
    }

    private func secureLinkPeerRejectsReplay(mode: String, transport: ObstacleBridgeLinuxTransport) throws {
        let peer = try PythonOverlayPeer(mode: mode)
        defer { peer.stop() }
        let lower = try ObstacleBridgeLinuxOverlayTransportClient(host: "127.0.0.1", port: peer.port, transport: transport, wsPath: "/overlay")
        let session = try lower.openSession()
        defer { session.close() }
        let client = try ObstacleBridgeSecureLinkPSKClient(psk: Data("linux-swift-psk".utf8))
        let proof = try client.handleServerHello(session.exchange(try client.begin(sessionID: 89, clientNonce: Data(repeating: 9, count: 32))))
        try client.handleServerAcknowledgement(session.exchange(proof))
        #expect(try client.unprotect(session.receive()) == Data("python-first".utf8))
        #expect(throws: ObstacleBridgeSecureLinkPSKClientError.replayedFrame) {
            try client.unprotect(session.receive())
        }
    }

    private func secureLinkSessionRekeys(mode: String, transport: ObstacleBridgeLinuxTransport) throws {
        let peer = try PythonOverlayPeer(mode: mode)
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(
            transport: transport, host: "127.0.0.1", port: peer.port,
            webSocketPath: "/overlay", secureLinkPSK: Data("linux-swift-psk".utf8)
        ))
        let session = try runtime.connect(sessionID: 90, clientNonce: Data(repeating: 9, count: 32))
        defer { runtime.disconnect() }
        #expect(try session.send(Data("before-rekey".utf8)) == Data("python:before-rekey".utf8))
        try session.rekey(sessionID: 91, clientNonce: Data(repeating: 10, count: 32))
        #expect(try session.send(Data("after-rekey".utf8)) == Data("python:after-rekey".utf8))
    }

    private func secureLinkSessionRejectsStaleReconnectFrame(mode: String, transport: ObstacleBridgeLinuxTransport) throws {
        let peer = try PythonOverlayPeer(mode: mode)
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: transport, host: "127.0.0.1", port: peer.port, webSocketPath: "/overlay", secureLinkPSK: Data("linux-swift-psk".utf8)))
        let first = try runtime.connect(sessionID: 94, clientNonce: Data(repeating: 13, count: 32))
        #expect(try first.send(Data("retired".utf8)) == Data("python:retired".utf8))
        let second = try runtime.reconnect(sessionID: 95, clientNonce: Data(repeating: 14, count: 32))
        defer { runtime.disconnect() }
        #expect(throws: ObstacleBridgeSecureLinkPSKClientError.invalidFrame) { try second.receiveInbound() }
    }
}

final class PythonOverlayPeer {
    // One test keeps two peers alive while it exercises transport routing;
    // restricting all test fixtures to that maximum avoids Foundation pipe
    // resource exhaustion when Swift Testing schedules the suite concurrently.
    private static let launchSlots = DispatchSemaphore(value: 2)
    let process: Process
    let port: Int
    private var stopped = false

    init(mode: String) throws {
        Self.launchSlots.wait()
        var started = false
        defer { if !started { Self.launchSlots.signal() } }
        let script = Self.script(for: mode)
        let process = Process()
        let stdout = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = ["-u", "-c", script]
        process.standardOutput = stdout
        process.standardError = Pipe()
        try process.run()
        let line = String(data: stdout.fileHandleForReading.availableData, encoding: .utf8) ?? ""
        guard let port = Int(line.trimmingCharacters(in: .whitespacesAndNewlines)), port > 0 else {
            process.terminate()
            process.waitUntilExit()
            throw OverlayTestError.peerDidNotStart
        }
        self.process = process
        self.port = port
        started = true
    }

    func stop() {
        guard !stopped else { return }
        stopped = true
        if process.isRunning { process.terminate() }
        process.waitUntilExit()
        Self.launchSlots.signal()
    }

    private static func script(for mode: String) -> String {
        if mode == "ws-duplex" {
            return """
            import base64, hashlib, socket
            s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(1); print(s.getsockname()[1], flush=True)
            c,_=s.accept(); r=b''
            while b'\\r\\n\\r\\n' not in r: r+=c.recv(4096)
            key=[x.split(b':',1)[1].strip() for x in r.split(b'\\r\\n') if x.lower().startswith(b'sec-websocket-key:')][0]
            accept=base64.b64encode(hashlib.sha1(key+b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
            c.sendall(b'HTTP/1.1 101 Switching Protocols\\r\\nUpgrade: websocket\\r\\nConnection: Upgrade\\r\\nSec-WebSocket-Accept: '+accept+b'\\r\\n\\r\\n')
            p=b'\\0python-first'; c.sendall(bytes([130,len(p)])+p); c.close(); s.close()
            """
        }
        if mode == "myudp-duplex" {
            return """
            import socket, struct, time
            s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('127.0.0.1',0)); print(s.getsockname()[1], flush=True)
            _,peer=s.recvfrom(1452); p=b'python-first'; record=struct.pack('!I',len(p))+p; batch=b'\\x01\\x01'+struct.pack('!H',4+len(record))+struct.pack('!HH',1,len(record))+record
            s.sendto(b'\\x01'+struct.pack('!HQQ',len(batch),0,0)+batch,peer)
            try: s.settimeout(1); s.recvfrom(1452)
            except OSError: pass
            s.close()
            """
        }
        if mode == "tcp-duplex" {
            return """
            import socket, struct
            s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(1); print(s.getsockname()[1], flush=True)
            c,_=s.accept()
            def nread(n):
                b=b''
                while len(b)<n:
                    x=c.recv(n-len(b))
                    if not x: raise RuntimeError('eof')
                    b+=x
                return b
            first=b'python-first'; c.sendall(struct.pack('!I',len(first)+1)+b'\\0'+first)
            n=struct.unpack('!I',nread(4))[0]; body=nread(n); assert body[:1]==b'\\0'
            reply=b'python:'+body[1:]; c.sendall(struct.pack('!I',len(reply)+1)+b'\\0'+reply)
            c.close(); s.close()
            """
        }
        if mode == "myudp-drop-first" {
            return """
            import socket
            s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1',0)); print(s.getsockname()[1], flush=True)
            s.recvfrom(1452)
            data,peer=s.recvfrom(1452); s.sendto(data,peer); s.close()
            """
        }
        if mode == "myudp-drop-first-data" {
            return """
            import socket
            s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1',0)); print(s.getsockname()[1], flush=True)
            def data():
                while True:
                    wire,peer=s.recvfrom(1452)
                    if len(wire)>=21 and wire[0]==1 and wire[19:21]==b'\\x01\\x01': return wire,peer
            data()  # Deliberately drop the initial DATA datagram.
            wire,peer=data(); s.sendto(wire,peer)
            s.close()
            """
        }
        if mode == "myudp-reordered-inbound" {
            return """
            import socket, struct
            s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1',0)); print(s.getsockname()[1], flush=True)
            _,peer=s.recvfrom(1452)
            payload=b'python-reordered'; record=struct.pack('!I',len(payload))+payload
            def wire(counter, chunk):
                batch=b'\\x01\\x01'+struct.pack('!H',4+len(chunk))+struct.pack('!HH',counter,len(chunk))+chunk
                return b'\\x01'+struct.pack('!HQQ',len(batch),0,0)+batch
            later=wire(2,record[5:]); s.sendto(later,peer); s.sendto(later,peer); s.sendto(wire(1,record[:5]),peer)
            deadline=time.monotonic()+1
            s.settimeout(0.05)
            while time.monotonic()<deadline:
                try: s.recvfrom(1452)
                except OSError: pass
            s.close()
            """
        }
        if mode == "myudp-malformed" {
            return """
            import socket
            s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('127.0.0.1',0)); print(s.getsockname()[1], flush=True)
            _,peer=s.recvfrom(1452); s.sendto(b'\\x01',peer); s.close()
            """
        }
        if mode == "myudp-securelink-reconnect" || mode == "myudp-securelink-reconnect-stale" {
            return """
            import hashlib, hmac, socket, struct
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            MODE_STALE = \(mode.contains("-stale") ? "True" : "False")
            s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1',0)); print(s.getsockname()[1], flush=True)
            def recv():
                while True:
                    wire,peer=s.recvfrom(1452)
                    if not (wire[0]==1 and wire[19:21]==b'\\x01\\x01'): continue
                    stream=wire[27:]; size=int.from_bytes(stream[:4],'big'); assert len(stream)==4+size
                    return stream[4:],int.from_bytes(wire[23:25],'big'),peer
            def send(payload,counter,peer):
                record=struct.pack('!I',len(payload))+payload; batch=b'\\x01\\x01'+struct.pack('!H',4+len(record))+struct.pack('!HH',counter,len(record))+record
                s.sendto(b'\\x01'+struct.pack('!HQQ',len(batch),0,0)+batch,peer)
            def header(t,sid,counter): return bytes([1,t,0,0])+sid.to_bytes(8,'big')+counter.to_bytes(8,'big')
            def expand(prk,info,length):
                out=b''; prior=b''
                for i in range(1,(length+31)//32+1): prior=hmac.new(prk,prior+info+bytes([i]),hashlib.sha256).digest(); out+=prior
                return out[:length]
            stale=None
            for epoch in range(2):
                hello,counter,peer=recv(); sid=int.from_bytes(hello[4:12],'big'); cn=hello[20:52]; sn=bytes(range(32)); psk=b'linux-swift-psk'
                proof=hmac.new(psk,b'obstaclebridge-securelink-server-proof-v1|'+sid.to_bytes(8,'big')+cn+sn,hashlib.sha256).digest(); send(header(2,sid,0)+sn+b'\\x01'+proof,counter,peer)
                salt=hashlib.sha256(psk).digest(); info=b'obstaclebridge-securelink-psk-v1|'+sid.to_bytes(8,'big')+cn+sn; material=expand(hmac.new(salt,psk+cn+sn,hashlib.sha256).digest(),info,64); c2s,s2c=material[:32],material[32:]
                client_proof,counter,peer=recv(); assert ChaCha20Poly1305(c2s).decrypt(b'\\0'*4+(1).to_bytes(8,'big'),client_proof[20:],client_proof[:20])==b''; ack=header(4,sid,1); send(ack+ChaCha20Poly1305(s2c).encrypt(b'\\0'*4+(1).to_bytes(8,'big'),b'',ack),counter,peer)
                if MODE_STALE and epoch == 1:
                    send(stale,counter+1,peer)
                    try: s.settimeout(1); s.recvfrom(1452)
                    except OSError: pass
                    continue
                app,counter,peer=recv(); plain=ChaCha20Poly1305(c2s).decrypt(b'\\0'*4+(2).to_bytes(8,'big'),app[20:],app[:20]); response=header(4,sid,2); send(response+ChaCha20Poly1305(s2c).encrypt(b'\\0'*4+(2).to_bytes(8,'big'),b'python:'+plain,response),counter,peer)
                stale=response
            s.close()
            """
        }
        if mode == "myudp-securelink" || mode == "myudp-secure-mux" || mode == "myudp-securelink-duplex" || mode == "myudp-securelink-mux-duplex" || mode == "myudp-securelink-close-after-ack" || mode == "myudp-securelink-malformed" || mode == "myudp-securelink-replay" || mode == "myudp-securelink-rekey" {
            return """
            import hashlib, hmac, socket, struct
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            MODE = "\(mode)"
            PREFIX = \(mode == "myudp-secure-mux" ? "b''" : "b'python:'")
            s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1',0)); print(s.getsockname()[1], flush=True)
            def recv():
                while True:
                    wire,peer=s.recvfrom(1452)
                    if not (wire[0]==1 and wire[19:21]==b'\\x01\\x01'): continue
                    stream=wire[27:]; size=int.from_bytes(stream[:4],'big'); assert len(stream)==4+size
                    return stream[4:],int.from_bytes(wire[23:25],'big'),peer
            def send(payload,counter,peer):
                record=struct.pack('!I',len(payload))+payload; batch=b'\\x01\\x01'+struct.pack('!H',4+len(record))+struct.pack('!HH',counter,len(record))+record
                s.sendto(b'\\x01'+struct.pack('!HQQ',len(batch),0,0)+batch,peer)
            def header(t,sid,counter): return bytes([1,t,0,0])+sid.to_bytes(8,'big')+counter.to_bytes(8,'big')
            def expand(prk,info,length):
                out=b''; prior=b''
                for i in range(1,(length+31)//32+1): prior=hmac.new(prk,prior+info+bytes([i]),hashlib.sha256).digest(); out+=prior
                return out[:length]
            hello,counter,peer=recv(); sid=int.from_bytes(hello[4:12],'big'); cn=hello[20:52]; sn=bytes(range(32)); psk=b'linux-swift-psk'
            proof=hmac.new(psk,b'obstaclebridge-securelink-server-proof-v1|'+sid.to_bytes(8,'big')+cn+sn,hashlib.sha256).digest(); send(header(2,sid,0)+sn+b'\\x01'+proof,counter,peer)
            salt=hashlib.sha256(psk).digest(); info=b'obstaclebridge-securelink-psk-v1|'+sid.to_bytes(8,'big')+cn+sn; material=expand(hmac.new(salt,psk+cn+sn,hashlib.sha256).digest(),info,64); c2s,s2c=material[:32],material[32:]
            client_proof,counter,peer=recv(); assert ChaCha20Poly1305(c2s).decrypt(b'\\0'*4+(1).to_bytes(8,'big'),client_proof[20:],client_proof[:20])==b''; ack=header(4,sid,1); send(ack+ChaCha20Poly1305(s2c).encrypt(b'\\0'*4+(1).to_bytes(8,'big'),b'',ack),counter,peer)
            if MODE == 'myudp-securelink-malformed':
                send(header(4,sid+1,2)+bytes(16),counter+1,peer)
            elif MODE == 'myudp-securelink-replay':
                first=header(4,sid,2); framed=first+ChaCha20Poly1305(s2c).encrypt(b'\\0'*4+(2).to_bytes(8,'big'),b'python-first',first); send(framed,counter+1,peer)
                try: s.settimeout(1); s.recvfrom(1452)
                except OSError: pass
                send(framed,counter+2,peer)
            elif MODE == 'myudp-securelink-rekey':
                app,counter,peer=recv(); plain=ChaCha20Poly1305(c2s).decrypt(b'\\0'*4+(2).to_bytes(8,'big'),app[20:],app[:20]); response=header(4,sid,2); send(response+ChaCha20Poly1305(s2c).encrypt(b'\\0'*4+(2).to_bytes(8,'big'),b'python:'+plain,response),counter,peer)
                rekey,counter,peer=recv(); assert rekey[:2]==b'\\x01\\x05'; sid=int.from_bytes(rekey[4:12],'big'); cn=rekey[20:52]; sn=bytes(range(31,-1,-1)); proof=hmac.new(psk,b'obstaclebridge-securelink-server-proof-v1|'+sid.to_bytes(8,'big')+cn+sn,hashlib.sha256).digest(); send(header(6,sid,0)+sn+b'\\x01'+proof,counter,peer)
                salt=hashlib.sha256(psk).digest(); info=b'obstaclebridge-securelink-psk-v1|'+sid.to_bytes(8,'big')+cn+sn; material=expand(hmac.new(salt,psk+cn+sn,hashlib.sha256).digest(),info,64); c2s,s2c=material[:32],material[32:]
                commit,counter,peer=recv(); expected=hmac.new(psk,b'obstaclebridge-securelink-client-rekey-commit-v1|'+sid.to_bytes(8,'big')+cn+sn,hashlib.sha256).digest(); assert commit[:2]==b'\\x01\\x07' and commit[20:]==expected; send(header(8,sid,0),counter,peer)
                app,counter,peer=recv(); plain=ChaCha20Poly1305(c2s).decrypt(b'\\0'*4+(1).to_bytes(8,'big'),app[20:],app[:20]); response=header(4,sid,1); send(response+ChaCha20Poly1305(s2c).encrypt(b'\\0'*4+(1).to_bytes(8,'big'),b'python:'+plain,response),counter,peer)
            elif MODE == 'myudp-securelink-close-after-ack':
                s.close()
            elif MODE == 'myudp-securelink-mux-duplex':
                first=header(4,sid,2); send(first+ChaCha20Poly1305(s2c).encrypt(b'\\0'*4+(2).to_bytes(8,'big'),b'\\0\\x07\\0\\0\\x01\\0\\0\\x05hello',first),3,peer)
            elif MODE == 'myudp-securelink-duplex':
                first_plain=b'\\0\\x07\\0\\0\\x01\\0\\0\\x05hello' if MODE.endswith('mux-duplex') else b'python-first'
                first=header(4,sid,2); send(first+ChaCha20Poly1305(s2c).encrypt(b'\\0'*4+(2).to_bytes(8,'big'),first_plain,first),3,peer)
                app,counter,peer=recv(); plain=ChaCha20Poly1305(c2s).decrypt(b'\\0'*4+(2).to_bytes(8,'big'),app[20:],app[:20]); response=header(4,sid,3); send(response+ChaCha20Poly1305(s2c).encrypt(b'\\0'*4+(3).to_bytes(8,'big'),b'python:'+plain,response),4,peer)
            else:
                app,counter,peer=recv(); plain=ChaCha20Poly1305(c2s).decrypt(b'\\0'*4+(2).to_bytes(8,'big'),app[20:],app[:20]); response=header(4,sid,2); send(response+ChaCha20Poly1305(s2c).encrypt(b'\\0'*4+(2).to_bytes(8,'big'),PREFIX+plain,response),counter,peer)
            if MODE != 'myudp-securelink-close-after-ack':
                try: s.settimeout(1); s.recvfrom(1452)
                except OSError: pass
            s.close()
            """
        }
        if mode == "myudp-rollover" {
            return """
            import socket, struct
            s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('127.0.0.1',0)); print(s.getsockname()[1],flush=True)
            for response_counter,expected in enumerate((65535,1),1):
                while True:
                    wire,peer=s.recvfrom(1452)
                    if wire[0]==1 and wire[19:21]==b'\\x01\\x01': break
                stream=wire[27:]; size=int.from_bytes(stream[:4],'big'); payload=stream[4:4+size]; observed=int.from_bytes(wire[23:25],'big')
                reply=b'python:'+str(observed).encode()+b':'+payload; record=struct.pack('!I',len(reply))+reply; counter=response_counter
                batch=b'\\x01\\x01'+struct.pack('!H',4+len(record))+struct.pack('!HH',counter,len(record))+record
                s.sendto(b'\\x01'+struct.pack('!HQQ',len(batch),0,0)+batch,peer)
            try: s.settimeout(1); s.recvfrom(1452)
            except OSError: pass
            s.close()
            """
        }
        if mode == "myudp" {
            return """
            import socket
            s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1',0)); print(s.getsockname()[1], flush=True)
            data,peer=s.recvfrom(1452)
            assert len(data)>=27 and data[0]==1 and data[19:21]==b'\\x01\\x01'
            s.sendto(data,peer); s.close()
            """
        }
        if mode == "tcp-securelink-reconnect" || mode == "ws-securelink-reconnect" || mode == "tcp-securelink-reconnect-stale" || mode == "ws-securelink-reconnect-stale" {
            return """
            import base64, hashlib, hmac, socket, struct
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            WS = \(mode.hasPrefix("ws-") ? "True" : "False")
            STALE = \(mode.contains("-stale") ? "True" : "False")
            s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(2); print(s.getsockname()[1], flush=True)
            def nread(c,n):
                b=b''
                while len(b)<n:
                    x=c.recv(n-len(b))
                    if not x: raise RuntimeError('eof')
                    b+=x
                return b
            def read(c):
                if WS:
                    a,b=nread(c,2); assert a==130 and b&128; n=b&127
                    if n==126: n=int.from_bytes(nread(c,2),'big')
                    elif n==127: n=int.from_bytes(nread(c,8),'big')
                    m=nread(c,4); body=bytes(x^m[i%4] for i,x in enumerate(nread(c,n))); assert body[:1]==b'\\0'; return body[1:]
                n=struct.unpack('!I',nread(c,4))[0]; body=nread(c,n); assert body[:1]==b'\\0'; return body[1:]
            def write(c,p):
                if WS:
                    body=b'\\0'+p
                    if len(body)<126: c.sendall(bytes([130,len(body)])+body)
                    else: c.sendall(bytes([130,126])+len(body).to_bytes(2,'big')+body)
                else: c.sendall(struct.pack('!I',len(p)+1)+b'\\0'+p)
            def header(t,sid,counter): return bytes([1,t,0,0])+sid.to_bytes(8,'big')+counter.to_bytes(8,'big')
            def expand(prk,info,length):
                out=b''; prior=b''
                for i in range(1,(length+31)//32+1): prior=hmac.new(prk,prior+info+bytes([i]),hashlib.sha256).digest(); out+=prior
                return out[:length]
            stale=None
            for epoch in range(2):
                c,_=s.accept()
                if WS:
                    request=b''
                    while b'\\r\\n\\r\\n' not in request: request+=c.recv(4096)
                    key=[x.split(b':',1)[1].strip() for x in request.split(b'\\r\\n') if x.lower().startswith(b'sec-websocket-key:')][0]
                    accept=base64.b64encode(hashlib.sha1(key+b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
                    c.sendall(b'HTTP/1.1 101 Switching Protocols\\r\\nUpgrade: websocket\\r\\nConnection: Upgrade\\r\\nSec-WebSocket-Accept: '+accept+b'\\r\\n\\r\\n')
                hello=read(c); sid=int.from_bytes(hello[4:12],'big'); cn=hello[20:52]; sn=bytes(range(32)); psk=b'linux-swift-psk'
                proof=hmac.new(psk,b'obstaclebridge-securelink-server-proof-v1|'+sid.to_bytes(8,'big')+cn+sn,hashlib.sha256).digest(); write(c,header(2,sid,0)+sn+b'\\x01'+proof)
                salt=hashlib.sha256(psk).digest(); info=b'obstaclebridge-securelink-psk-v1|'+sid.to_bytes(8,'big')+cn+sn; material=expand(hmac.new(salt,psk+cn+sn,hashlib.sha256).digest(),info,64); c2s,s2c=material[:32],material[32:]
                client_proof=read(c); assert ChaCha20Poly1305(c2s).decrypt(b'\\0'*4+(1).to_bytes(8,'big'),client_proof[20:],client_proof[:20])==b''; ack=header(4,sid,1); write(c,ack+ChaCha20Poly1305(s2c).encrypt(b'\\0'*4+(1).to_bytes(8,'big'),b'',ack))
                if STALE and epoch == 1:
                    write(c,stale); c.close(); continue
                app=read(c); plain=ChaCha20Poly1305(c2s).decrypt(b'\\0'*4+(2).to_bytes(8,'big'),app[20:],app[:20]); response=header(4,sid,2); write(c,response+ChaCha20Poly1305(s2c).encrypt(b'\\0'*4+(2).to_bytes(8,'big'),b'python:'+plain,response)); c.close()
                stale=response
            s.close()
            """
        }
        if mode == "tcp-reconnect" || mode == "tcp-drop-then-echo" || mode == "tcp-mux-reconnect" {
            return """
            import socket, struct
            DROP_FIRST = \(mode == "tcp-drop-then-echo" ? "True" : "False")
            MUX = \(mode == "tcp-mux-reconnect" ? "True" : "False")
            s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(2); print(s.getsockname()[1], flush=True)
            for i in range(2):
                c,_=s.accept()
                def nread(n):
                    b=b''
                    while len(b)<n:
                        x=c.recv(n-len(b))
                        if not x: raise RuntimeError('eof')
                        b+=x
                    return b
                for j in range(2 if MUX else 1):
                    h=nread(4); n=struct.unpack('!I',h)[0]; b=nread(n); assert b[:1]==b'\\x00'
                    if not DROP_FIRST or i == 1: c.sendall(h+b)
                c.close()
            s.close()
            """
        }
        return """
        import base64, hashlib, hmac, socket, struct
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        MODE = "\(mode)"
        s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(1); print(s.getsockname()[1], flush=True)
        c,_=s.accept()
        def nread(n):
            b=b''
            while len(b)<n:
                x=c.recv(n-len(b))
                if not x: raise RuntimeError('eof')
                b+=x
            return b
        if MODE.startswith('ws'):
            r=b''
            while b'\\r\\n\\r\\n' not in r: r+=c.recv(4096)
            if MODE.startswith('ws-text-'): assert ('x-obstaclebridge-ws-payload-mode: '+MODE[8:]).encode() in r.lower()
            key=[x.split(b':',1)[1].strip() for x in r.split(b'\\r\\n') if x.lower().startswith(b'sec-websocket-key:')][0]
            accept=base64.b64encode(hashlib.sha1(key+b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
            c.sendall(b'HTTP/1.1 101 Switching Protocols\\r\\nUpgrade: websocket\\r\\nConnection: Upgrade\\r\\nSec-WebSocket-Accept: '+accept+b'\\r\\n\\r\\n')
        def read_payload():
            if MODE.startswith('tcp'):
                h=nread(4); n=struct.unpack('!I',h)[0]; b=nread(n); assert b[:1]==b'\\x00'; return b[1:]
            a,b=nread(2); assert a==(129 if MODE.startswith('ws-text-') else 130) and b&128; n=b&127
            if n==126: n=int.from_bytes(nread(2),'big')
            elif n==127: n=int.from_bytes(nread(8),'big')
            m=nread(4); p=bytes(x^m[i%4] for i,x in enumerate(nread(n)))
            if MODE == 'ws-text-base64': return base64.b64decode(p)
            if MODE == 'ws-text-json-base64': return base64.b64decode(__import__('json').loads(p)['data'])
            if MODE == 'ws-text-semi-text-shape':
                a='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-+'; bits=''.join(f'{a.index(chr(x)):06b}' for x in p if chr(x)!=' '); return bytes(int(bits[i:i+8],2) for i in range(0,len(bits)//8*8,8))
            assert p[:1]==b'\\0'; return p[1:]
        def write_payload(p):
            if MODE.startswith('tcp'):
                c.sendall(struct.pack('!I',len(p)+1)+b'\\x00'+p); return
            if MODE == 'ws-text-base64':
                p=base64.b64encode(p); opcode=129
            elif MODE == 'ws-text-json-base64':
                p=__import__('json').dumps({'data':base64.b64encode(p).decode()},separators=(',',':')).encode(); opcode=129
            elif MODE == 'ws-text-semi-text-shape':
                a='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-+'; bits=''.join(f'{x:08b}' for x in p); bits += '0'*((-len(bits))%6); p=' '.join(''.join(a[int(bits[i+j:i+j+6],2)] for j in range(0,min(48,len(bits)-i),6)) for i in range(0,len(bits),48)).encode(); opcode=129
            else:
                p=b'\\0'+p; opcode=130
            if len(p)<126: c.sendall(bytes([opcode,len(p)])+p)
            else: c.sendall(bytes([opcode,126])+len(p).to_bytes(2,'big')+p)
        def header(t,sid,counter): return bytes([1,t,0,0])+sid.to_bytes(8,'big')+counter.to_bytes(8,'big')
        def expand(prk,info,length):
            out=b''; prior=b''
            for i in range(1,(length+31)//32+1):
                prior=hmac.new(prk,prior+info+bytes([i]),hashlib.sha256).digest(); out+=prior
            return out[:length]
        if 'securelink' in MODE or MODE == 'tcp-secure-mux-echo':
            hello=read_payload(); assert hello[:2]==b'\\x01\\x01' and hello[20+32:20+34]==b'\\x01\\x00'
            sid=int.from_bytes(hello[4:12],'big'); cn=hello[20:52]; sn=bytes(range(32)); psk=b'linux-swift-psk'
            proof=hmac.new(psk,b'obstaclebridge-securelink-server-proof-v1|'+sid.to_bytes(8,'big')+cn+sn,hashlib.sha256).digest()
            write_payload(header(2,sid,0)+sn+b'\\x01'+proof)
            salt=hashlib.sha256(psk).digest(); info=b'obstaclebridge-securelink-psk-v1|'+sid.to_bytes(8,'big')+cn+sn
            material=expand(hmac.new(salt,psk+cn+sn,hashlib.sha256).digest(),info,64); c2s,s2c=material[:32],material[32:]
            client_proof=read_payload(); assert ChaCha20Poly1305(c2s).decrypt(b'\\0'*4+(1).to_bytes(8,'big'),client_proof[20:],client_proof[:20])==b''
            ack=header(4,sid,1); write_payload(ack+ChaCha20Poly1305(s2c).encrypt(b'\\0'*4+(1).to_bytes(8,'big'),b'',ack))
            if MODE.endswith('malformed'):
                write_payload(header(4,sid+1,2)+bytes(16))
            elif MODE.endswith('replay'):
                first=header(4,sid,2); framed=first+ChaCha20Poly1305(s2c).encrypt(bytes(4)+(2).to_bytes(8,'big'),b'python-first',first); write_payload(framed); write_payload(framed)
            elif MODE.endswith('close-after-ack'):
                c.close(); s.close()
            elif MODE.endswith('duplex'):
                if MODE == 'tcp-securelink-catalog-duplex':
                    import json
                    rows=[{'svc_id':7,'l_proto':'udp','l_bind':'127.0.0.1','l_port':49100,'r_proto':'udp','r_host':'127.0.0.1','r_port':7,'name':'peer','lifecycle_hooks':None,'options':None}]
                    body=json.dumps(rows,separators=(',',':')).encode()
                    catalog=b'RS3'+(1).to_bytes(8,'big')+(1).to_bytes(4,'big')+len(body).to_bytes(4,'big')+body
                    first_plain=b'\\0\\0\\0\\0\\0\\x04'+len(catalog).to_bytes(2,'big')+catalog
                else:
                    first_plain=b'\\0\\x07\\0\\0\\x01\\0\\0\\x05hello' if MODE.endswith('mux-duplex') else b'python-first'
                first=header(4,sid,2); write_payload(first+ChaCha20Poly1305(s2c).encrypt(b'\\0'*4+(2).to_bytes(8,'big'),first_plain,first))
            elif MODE.endswith('rekey'):
                app=read_payload(); plain=ChaCha20Poly1305(c2s).decrypt(b'\\0'*4+(2).to_bytes(8,'big'),app[20:],app[:20]); response=header(4,sid,2); write_payload(response+ChaCha20Poly1305(s2c).encrypt(b'\\0'*4+(2).to_bytes(8,'big'),b'python:'+plain,response))
                rekey=read_payload(); assert rekey[:2]==b'\\x01\\x05'; sid=int.from_bytes(rekey[4:12],'big'); cn=rekey[20:52]; sn=bytes(range(31,-1,-1)); proof=hmac.new(psk,b'obstaclebridge-securelink-server-proof-v1|'+sid.to_bytes(8,'big')+cn+sn,hashlib.sha256).digest(); write_payload(header(6,sid,0)+sn+b'\\x01'+proof)
                salt=hashlib.sha256(psk).digest(); info=b'obstaclebridge-securelink-psk-v1|'+sid.to_bytes(8,'big')+cn+sn; material=expand(hmac.new(salt,psk+cn+sn,hashlib.sha256).digest(),info,64); c2s,s2c=material[:32],material[32:]
                commit=read_payload(); expected=hmac.new(psk,b'obstaclebridge-securelink-client-rekey-commit-v1|'+sid.to_bytes(8,'big')+cn+sn,hashlib.sha256).digest(); assert commit[:2]==b'\\x01\\x07' and commit[20:]==expected; write_payload(header(8,sid,0))
                app=read_payload(); plain=ChaCha20Poly1305(c2s).decrypt(b'\\0'*4+(1).to_bytes(8,'big'),app[20:],app[:20]); response=header(4,sid,1); write_payload(response+ChaCha20Poly1305(s2c).encrypt(b'\\0'*4+(1).to_bytes(8,'big'),b'python:'+plain,response))
            if not (MODE.endswith('close-after-ack') or MODE.endswith('malformed') or MODE.endswith('replay') or MODE.endswith('rekey')):
                for counter in range(2, 8):
                    app=read_payload(); plain=ChaCha20Poly1305(c2s).decrypt(b'\\0'*4+counter.to_bytes(8,'big'),app[20:],app[:20])
                    if MODE == 'tcp-secure-mux-echo' and len(plain) >= 8 and plain[5] == 1:
                        reply_plain = plain[:5] + b'\\x00\\x00\\x00'
                    elif MODE == 'tcp-secure-mux-echo':
                        reply_plain = plain
                    else:
                        reply_plain = b'python:' + plain
                    response_counter=counter + (1 if MODE.endswith('duplex') else 0)
                    response=header(4,sid,response_counter); write_payload(response+ChaCha20Poly1305(s2c).encrypt(b'\\0'*4+response_counter.to_bytes(8,'big'),reply_plain,response))
        else:
            payload=read_payload(); write_payload(payload)
        c.close(); s.close()
        """
    }
}

private enum OverlayTestError: Error { case peerDidNotStart }
