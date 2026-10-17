import Dispatch
import Foundation
import Testing
#if os(Linux)
import Glibc
#endif
import ObstacleBridgeCore
@testable import ObstacleBridgeLinuxAdapters

struct ObstacleBridgeLinuxLiveRuntimeTests {
    @Test func publishesConnectingBeforeMyudpHandshakeCompletes() {
        // Nothing listens on this loopback port, so SecureLink's initial
        // request waits for the configured receive-idle window.  Admin must
        // still receive the coordinator's connecting transition immediately.
        let runtime = ObstacleBridgeLinuxLiveRuntime(
            configuration: .init(
                transport: .myudp, host: "127.0.0.1", port: 9,
                secureLinkPSK: Data("linux-swift-psk".utf8),
                receiveIdleTimeoutMilliseconds: 1_000
            ),
            policy: .init(initialDelayMilliseconds: 1_000, maximumDelayMilliseconds: 1_000, maximumAttempts: 1)
        )
        let connecting = DispatchSemaphore(value: 0)
        runtime.onSnapshot = { snapshot in
            if snapshot.state == "connecting", snapshot.attempts == 1 { connecting.signal() }
        }
        runtime.start()
        #expect(connecting.wait(timeout: .now() + 0.5) == .success)
        runtime.stop()
    }

    @Test func runtimeHealthPersistsCleanStopAndClassifiesNextLifetime() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let healthURL = directory.appendingPathComponent("runtime-health.json")
        defer { try? FileManager.default.removeItem(at: directory) }
        let configuration = ObstacleBridgeLinuxRuntimeConfiguration(
            transport: .tcp, host: "127.0.0.1", port: 1
        )

        let first = ObstacleBridgeLinuxLiveRuntime(
            configuration: configuration,
            policy: .init(initialDelayMilliseconds: 250, maximumDelayMilliseconds: 250, maximumAttempts: 1),
            runtimeHealthURL: healthURL
        )
        first.start()
        first.stop()
        #expect(ObstacleBridgeRuntimeHealthPersistence.load(from: healthURL)?.previousLifetimeEndedCleanly == true)

        let next = ObstacleBridgeLinuxLiveRuntime(
            configuration: configuration,
            policy: .init(initialDelayMilliseconds: 250, maximumDelayMilliseconds: 250, maximumAttempts: 1),
            runtimeHealthURL: healthURL
        )
        next.start()
        let started = Date().addingTimeInterval(2)
        while next.runtimeHealthMetadataForAdmin().count == 0, Date() < started {
            Thread.sleep(forTimeInterval: 0.01)
        }
        #expect(next.runtimeHealthMetadataForAdmin().previousClean == true)
        #expect(next.runtimeHealthRecentRecordsForAdmin().contains(where: { $0.event == "runtime_stopped" && $0.controlledStop }))
        next.stop()
    }

    @Test func runtimeHealthRecordsKnownShutdownSignalWithoutCallerText() throws {
        let runtime = ObstacleBridgeLinuxLiveRuntime(
            configuration: .init(transport: .tcp, host: "127.0.0.1", port: 1),
            policy: .init(initialDelayMilliseconds: 250, maximumDelayMilliseconds: 250, maximumAttempts: 1)
        )
        runtime.start()
        runtime.recordShutdownSignal(.terminate)
        #expect(runtime.runtimeHealthRecentRecordsForAdmin().contains(where: {
            $0.event == "shutdown_signal:SIGTERM" && !$0.controlledStop
        }))
        runtime.stop()
    }

    /// Pins the subset of Python's peer lifecycle contract supported by the
    /// Linux Swift foreground runtime.  In particular, transport lifecycle
    /// and SecureLink protocol state are separate fields: an authenticated
    /// protected epoch is transport-connected, not SecureLink-connected.
    @Test func peerProjectionCoversConnectedReconnectingFailedAndStoppedStates() throws {
        let initial = ObstacleBridgeLinuxLiveRuntime(
            configuration: .init(transport: .tcp, host: "127.0.0.1", port: 1, secureLinkPSK: Data("linux-swift-psk".utf8)),
            policy: .init(initialDelayMilliseconds: 250, maximumDelayMilliseconds: 250, maximumAttempts: 2)
        )
        let initiallyStopped = initial.status().peer
        #expect(initiallyStopped.lifecycleState == "stopped")
        #expect(initiallyStopped.secureLinkState == "disconnected")
        #expect(!initiallyStopped.ready)
        #expect(!initiallyStopped.authenticated)
        #expect(initiallyStopped.sessionID == nil)
        #expect(initiallyStopped.nextRetryMilliseconds == nil)
        #expect(initiallyStopped.protectedFramesSentTotal == 0)
        #expect(initiallyStopped.protectedFramesReceivedTotal == 0)

        let reconnecting = DispatchSemaphore(value: 0)
        initial.onSnapshot = { snapshot in
            if snapshot.state == "reconnecting", snapshot.nextRetryMilliseconds == 250 { reconnecting.signal() }
        }
        initial.start()
        #expect(reconnecting.wait(timeout: .now() + 3) == .success)
        let retrying = initial.status().peer
        #expect(retrying.lifecycleState == "reconnecting")
        // A lower TCP connection failure occurs before SecureLink can start;
        // Python calls this `waiting_transport`, while the Linux adapter's
        // intentionally smaller vocabulary reports `disconnected`.
        #expect(retrying.secureLinkState == "disconnected")
        #expect(!retrying.ready)
        #expect(!retrying.authenticated)
        #expect(retrying.sessionID == nil)
        #expect(retrying.nextRetryMilliseconds == 250)
        initial.stop()
        let stopped = initial.status().peer
        #expect(stopped.lifecycleState == "stopped")
        #expect(stopped.nextRetryMilliseconds == nil)
        #expect(!stopped.ready)

        let terminal = ObstacleBridgeLinuxLiveRuntime(
            configuration: .init(transport: .tcp, host: "127.0.0.1", port: 1, secureLinkPSK: Data("linux-swift-psk".utf8)),
            policy: .init(initialDelayMilliseconds: 1, maximumDelayMilliseconds: 1, maximumAttempts: 1)
        )
        let failed = DispatchSemaphore(value: 0)
        terminal.onSnapshot = { if $0.state == "failed" { failed.signal() } }
        terminal.start()
        #expect(failed.wait(timeout: .now() + 3) == .success)
        let terminalPeer = terminal.status().peer
        #expect(terminalPeer.lifecycleState == "failed")
        #expect(terminalPeer.secureLinkState == "disconnected")
        #expect(!terminalPeer.ready)
        #expect(terminalPeer.nextRetryMilliseconds == nil)
        #expect(terminal.snapshot.failureReason != nil)
        terminal.stop()

        let pythonPeer = try PythonOverlayPeer(mode: "tcp-securelink")
        defer { pythonPeer.stop() }
        let connected = ObstacleBridgeLinuxLiveRuntime(configuration: .init(
            transport: .tcp, host: "127.0.0.1", port: pythonPeer.port, secureLinkPSK: Data("linux-swift-psk".utf8)
        ))
        let ready = DispatchSemaphore(value: 0)
        connected.onSnapshot = { if $0.state == "connected" { ready.signal() } }
        connected.start()
        #expect(ready.wait(timeout: .now() + 3) == .success)
        let connectedPeer = connected.status().peer
        #expect(connectedPeer.lifecycleState == "connected")
        #expect(connectedPeer.secureLinkState == "authenticated")
        #expect(connectedPeer.ready)
        #expect(connectedPeer.authenticated)
        #expect(connectedPeer.sessionID != nil)
        #expect(connectedPeer.nextRetryMilliseconds == nil)
        #expect(connectedPeer.authenticatedGenerationsTotal == 1)
        connected.stop()
    }

    @Test func liveRuntimePublishesBoundedRetryWindow() {
        let runtime = ObstacleBridgeLinuxLiveRuntime(
            configuration: .init(transport: .tcp, host: "127.0.0.1", port: 1),
            policy: .init(initialDelayMilliseconds: 250, maximumDelayMilliseconds: 500, maximumAttempts: 2)
        )
        let reconnecting = DispatchSemaphore(value: 0)
        runtime.onSnapshot = { if $0.state == "reconnecting", $0.nextRetryMilliseconds == 250 { reconnecting.signal() } }
        runtime.start()
        #expect(reconnecting.wait(timeout: .now() + 3) == .success)
        let peer = runtime.status().peer
        #expect(peer.lifecycleState == "reconnecting")
        #expect(peer.nextRetryMilliseconds == 250)
        #expect(!peer.ready)
        #expect(peer.sessionID == nil)
        runtime.stop()
    }

    @Test func myudpRegistryListenerKeepsTwoUdpPeersIsolated() throws {
        let listener = try ObstacleBridgeLinuxMyUDPListener(port: 0, bindHost: "127.0.0.1")
        let first = try connectUDP(port: listener.port)
        let second = try connectUDP(port: listener.port)
        defer { _ = close(first); _ = close(second) }

        let firstWire = try ObstacleBridgeMyUDPCodec.encodeData(
            payload: try ObstacleBridgeMyUDPCodec.encodeStreamRecord(Data("first-peer".utf8)),
            counter: 1,
            transmittedNanoseconds: 1
        )
        let secondWire = try ObstacleBridgeMyUDPCodec.encodeData(
            payload: try ObstacleBridgeMyUDPCodec.encodeStreamRecord(Data("second-peer".utf8)),
            counter: 1,
            transmittedNanoseconds: 2
        )
        #expect(firstWire.withUnsafeBytes { send(first, $0.baseAddress, firstWire.count, 0) } == firstWire.count)
        #expect(secondWire.withUnsafeBytes { send(second, $0.baseAddress, secondWire.count, 0) } == secondWire.count)

        let firstReceived = try listener.receive()
        let secondReceived = try listener.receive()
        let received = [try #require(firstReceived), try #require(secondReceived)]
        #expect(Set(received.map(\.payload)) == Set([Data("first-peer".utf8), Data("second-peer".utf8)]))
        #expect(Set(received.map(\.peerIdentity)).count == 2)
        #expect(try ObstacleBridgeMyUDPCodec.decodeWire(receiveUDPWire(first)).type == ObstacleBridgeMyUDPCodec.controlType)
        #expect(try ObstacleBridgeMyUDPCodec.decodeWire(receiveUDPWire(second)).type == ObstacleBridgeMyUDPCodec.controlType)
        #expect(try listener.serviceTimers() == 2)
        #expect(try ObstacleBridgeMyUDPCodec.decodeWire(receiveUDPWire(first)).type == ObstacleBridgeMyUDPCodec.idleType)
        #expect(try ObstacleBridgeMyUDPCodec.decodeWire(receiveUDPWire(second)).type == ObstacleBridgeMyUDPCodec.idleType)
        #expect(listener.activePeerCount == 2)
        #expect(Set(listener.expireIdlePeers(nowNanoseconds: .max, idleTimeoutNanoseconds: 1)) == Set(received.map(\.peerIdentity)))
        #expect(listener.activePeerCount == 0)
        listener.close()
        listener.close()
        #expect(throws: ObstacleBridgeLinuxMyUDPError.ioFailure(EBADF)) { try listener.receive() }
    }

    @Test func myudpListenerRejectsDelayedStaleEpochForSameEndpoint() throws {
        let listener = try ObstacleBridgeLinuxMyUDPListener(port: 0, bindHost: "127.0.0.1")
        let peer = try connectUDP(port: listener.port)
        defer { _ = close(peer); listener.close() }
        func sendRecord(_ payload: String, counter: UInt16, epoch: UInt64) throws -> ObstacleBridgeLinuxMyUDPListener.ReceivedRecord? {
            let wire = try ObstacleBridgeMyUDPCodec.encodeData(
                payload: try ObstacleBridgeMyUDPCodec.encodeStreamRecord(Data(payload.utf8)),
                counter: counter,
                transmittedNanoseconds: epoch
            )
            #expect(wire.withUnsafeBytes { send(peer, $0.baseAddress, wire.count, 0) } == wire.count)
            return try listener.receive(epoch: epoch)
        }
        #expect(try sendRecord("old", counter: 1, epoch: 1)?.payload == Data("old".utf8))
        _ = try receiveUDPWire(peer)
        #expect(try sendRecord("fresh", counter: 1, epoch: 2)?.payload == Data("fresh".utf8))
        _ = try receiveUDPWire(peer)
        let staleWire = try ObstacleBridgeMyUDPCodec.encodeData(
            payload: try ObstacleBridgeMyUDPCodec.encodeStreamRecord(Data("stale".utf8)),
            counter: 2,
            transmittedNanoseconds: 1
        )
        #expect(staleWire.withUnsafeBytes { send(peer, $0.baseAddress, staleWire.count, 0) } == staleWire.count)
        #expect(throws: ObstacleBridgeLinuxMyUDPError.invalidReply) { try listener.receive(epoch: 1) }
        #expect(listener.activePeerCount == 1)
    }

    @Test func myudpListenerAuthenticatesIndependentPeersBeforeExposingSessions() throws {
        let listener = try ObstacleBridgeLinuxMyUDPPSKListener(
            port: 0, bindHost: "127.0.0.1", psk: Data("linux-swift-psk".utf8),
            serverNonce: { Data(repeating: 9, count: 32) }
        )
        defer { listener.close() }
        let admitted = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var sessions: [ObstacleBridgeLinuxConfiguredSession] = []
        listener.onAuthenticatedSession = { _, session in
            lock.lock(); sessions.append(session); lock.unlock()
            admitted.signal()
        }
        let pump = DispatchQueue(label: "org.obstaclebridge.tests.myudp-listener")
        pump.async {
            while true {
                do { try listener.pump(); _ = try listener.serviceTimers() }
                catch { return }
            }
        }
        let configuration = ObstacleBridgeLinuxRuntimeConfiguration(
            transport: .myudp, host: "127.0.0.1", port: listener.port,
            secureLinkPSK: Data("linux-swift-psk".utf8)
        )
        let clientsFinished = DispatchSemaphore(value: 0)
        for identifier in 1...2 {
            DispatchQueue.global().async {
                let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: configuration)
                _ = try? runtime.connect(sessionID: UInt64(identifier), clientNonce: Data(repeating: UInt8(identifier), count: 32))
                clientsFinished.signal()
            }
        }
        #expect(admitted.wait(timeout: .now() + 3) == .success)
        #expect(admitted.wait(timeout: .now() + 3) == .success)
        lock.lock(); let admittedSessions = sessions; lock.unlock()
        #expect(admittedSessions.count == 2)
        #expect(listener.activePeerCount == 2)
        #expect(clientsFinished.wait(timeout: .now() + 3) == .success)
        #expect(clientsFinished.wait(timeout: .now() + 3) == .success)
        admittedSessions.forEach { $0.close() }
    }

    @Test func myudpForegroundOwnerRetainsDistinctAuthenticatedPeerProjections() throws {
        let configuration = ObstacleBridgeLinuxRuntimeConfiguration(
            transport: .myudp, host: "listener", port: 0, listenerMode: true,
            secureLinkPSK: Data("linux-swift-psk".utf8)
        )
        let listener = try ObstacleBridgeLinuxMyUDPListenerRuntime(configuration: configuration)
        defer { listener.stop() }
        listener.start()
        let connected = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let finished = DispatchSemaphore(value: 0)
        for identifier in 1...2 {
            DispatchQueue.global().async {
                let clientConfiguration = ObstacleBridgeLinuxRuntimeConfiguration(
                    transport: .myudp, host: "127.0.0.1", port: listener.port,
                    secureLinkPSK: Data("linux-swift-psk".utf8)
                )
                let client = ObstacleBridgeLinuxConfiguredRuntime(configuration: clientConfiguration)
                guard let session = try? client.connect(
                    sessionID: UInt64(identifier),
                    clientNonce: Data(repeating: UInt8(identifier), count: 32)
                ) else { finished.signal(); return }
                connected.signal()
                release.wait()
                session.close()
                finished.signal()
            }
        }
        #expect(connected.wait(timeout: .now() + 3) == .success)
        #expect(connected.wait(timeout: .now() + 3) == .success)
        let deadline = Date().addingTimeInterval(3)
        while listener.peers().count != 2, Date() < deadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        #expect(listener.activePeerCount == 2)
        #expect(listener.peers().count == 2)
        #expect(listener.peers().allSatisfy { $0.snapshot.authenticated })
        #expect(listener.status().appReady)
        release.signal(); release.signal()
        #expect(finished.wait(timeout: .now() + 3) == .success)
        #expect(finished.wait(timeout: .now() + 3) == .success)
    }

    @Test func myudpForegroundOwnerBoundsAuthenticatedPeerAdmission() throws {
        let listener = try ObstacleBridgeLinuxMyUDPListenerRuntime(
            configuration: .init(
                transport: .myudp, host: "listener", port: 0, listenerMode: true,
                secureLinkPSK: Data("linux-swift-psk".utf8)
            ),
            maximumPeers: 1
        )
        defer { listener.stop() }
        listener.start()
        let clientConfiguration = ObstacleBridgeLinuxRuntimeConfiguration(
            transport: .myudp, host: "127.0.0.1", port: listener.port,
            secureLinkPSK: Data("linux-swift-psk".utf8), receiveIdleTimeoutMilliseconds: 25
        )
        let first = ObstacleBridgeLinuxConfiguredRuntime(configuration: clientConfiguration)
        let session = try first.connect(sessionID: 1, clientNonce: Data(repeating: 1, count: 32))
        defer { session.close() }
        let second = ObstacleBridgeLinuxConfiguredRuntime(configuration: clientConfiguration)
        #expect(throws: ObstacleBridgeLinuxMyUDPError.ioFailure(EAGAIN)) {
            _ = try second.connect(sessionID: 2, clientNonce: Data(repeating: 2, count: 32))
        }
        let deadline = Date().addingTimeInterval(1)
        while listener.activePeerCount != 1, Date() < deadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        #expect(listener.activePeerCount == 1)
        #expect(listener.peers().count == 1)
    }

    @Test func myudpForegroundOwnerRejectsAmbiguousListenerServiceBinds() {
        let service = ObstacleBridgeLinuxServiceSpec(
            serviceID: 1, name: "ambiguous", listenProtocol: .tcp,
            listenHost: "127.0.0.1", listenPort: 7001, targetProtocol: .tcp,
            targetHost: "127.0.0.1", targetPort: 7002
        )
        #expect(throws: ObstacleBridgeLinuxRuntimeConfigurationError.unavailableTransport(
            "myudp listener rejects ambiguous own_servers and remote_servers; omit both"
        )) {
            _ = try ObstacleBridgeLinuxMyUDPListenerRuntime(configuration: .init(
                transport: .myudp, host: "listener", port: 0, listenerMode: true,
                secureLinkPSK: Data("linux-swift-psk".utf8), ownServices: [service]
            ))
        }
    }

    @Test func myudpForegroundOwnerExpiresIdleChildWithoutReconnect() throws {
        let listener = try ObstacleBridgeLinuxMyUDPListenerRuntime(
            configuration: .init(
                transport: .myudp, host: "listener", port: 0, listenerMode: true,
                secureLinkPSK: Data("linux-swift-psk".utf8)
            ),
            idleTimeoutMilliseconds: 500
        )
        defer { listener.stop() }
        listener.start()
        let client = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(
            transport: .myudp, host: "127.0.0.1", port: listener.port,
            secureLinkPSK: Data("linux-swift-psk".utf8)
        ))
        let session = try client.connect(sessionID: 1, clientNonce: Data(repeating: 1, count: 32))
        defer { session.close() }
        let connectedDeadline = Date().addingTimeInterval(2)
        while listener.peers().count != 1, Date() < connectedDeadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        #expect(listener.peers().count == 1)
        let expiredDeadline = Date().addingTimeInterval(2)
        while listener.peers().count != 0, Date() < expiredDeadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        #expect(listener.peers().isEmpty)
        #expect(listener.status().state == "disconnected")
    }

    @Test func protectedReceiveFailureWithdrawsEpochAndUsesBoundedReconnect() throws {
        try assertProtectedReceiveFailureReconnects(mode: "tcp-securelink-close-after-ack", transport: .tcp)
    }

    @Test func protectedWebSocketReceiveFailureWithdrawsEpochAndUsesBoundedReconnect() throws {
        try assertProtectedReceiveFailureReconnects(mode: "ws-securelink-close-after-ack", transport: .ws)
    }

    @Test func webSocketHandshakeFailureUsesBoundedCoreRetryLifecycle() throws {
        let peer = try PythonOverlayPeer(mode: "ws-handshake-reject")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxLiveRuntime(
            configuration: .init(
                transport: .ws, host: "127.0.0.1", port: peer.port,
                webSocketProxy: .init(mode: .off)
            ),
            policy: .init(initialDelayMilliseconds: 5, maximumDelayMilliseconds: 10, maximumAttempts: 2)
        )
        let failed = DispatchSemaphore(value: 0)
        runtime.onSnapshot = { if $0.state == "failed" { failed.signal() } }
        runtime.start()
        #expect(failed.wait(timeout: .now() + 3) == .success)
        #expect(runtime.snapshot.attempts == 2)
        #expect(runtime.snapshot.failureReason != nil)
        runtime.stop()
    }

    @Test func protectedMyudpReceiveFailureWithdrawsEpochAndUsesBoundedReconnect() throws {
        try assertProtectedReceiveFailureReconnects(mode: "myudp-securelink-close-after-ack", transport: .myudp)
    }

    @Test func silentMyudpPeerDeliversReceiveDeadlineFailureToLiveRuntime() throws {
        let peer = try PythonOverlayPeer(mode: "myudp-securelink-silent")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxLiveRuntime(
            configuration: .init(transport: .myudp, host: "127.0.0.1", port: peer.port, secureLinkPSK: Data("linux-swift-psk".utf8), receiveIdleTimeoutMilliseconds: 50),
            policy: .init(initialDelayMilliseconds: 10, maximumDelayMilliseconds: 10, maximumAttempts: 2)
        )
        let retrying = DispatchSemaphore(value: 0)
        runtime.onSnapshot = { if $0.state == "reconnecting", $0.nextRetryMilliseconds == 10 { retrying.signal() } }
        runtime.start()
        #expect(retrying.wait(timeout: .now() + 2) == .success)
        #expect(runtime.status().peer.lifecycleState == "reconnecting")
        #expect(runtime.status().peer.nextRetryMilliseconds == 10)
        runtime.stop()
    }

    @Test func stopCancelsStalledPythonSecureLinkHandshakeWithoutWaitingForReceiveTimeout() throws {
        let peer = try PythonOverlayPeer(mode: "tcp-securelink-stall-handshake")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxLiveRuntime(
            configuration: .init(
                transport: .tcp, host: "127.0.0.1", port: peer.port,
                secureLinkPSK: Data("linux-swift-psk".utf8),
                receiveIdleTimeoutMilliseconds: 5_000
            ),
            policy: .init(initialDelayMilliseconds: 10, maximumDelayMilliseconds: 10, maximumAttempts: 2)
        )
        runtime.start()
        // The Python peer accepts the connection and withholds SERVER_HELLO,
        // leaving the serialized queue in the SecureLink handshake receive.
        Thread.sleep(forTimeInterval: 0.1)
        let started = DispatchTime.now().uptimeNanoseconds
        runtime.stop()
        let elapsedMilliseconds = (DispatchTime.now().uptimeNanoseconds - started) / 1_000_000
        #expect(elapsedMilliseconds < 500)
        #expect(runtime.snapshot.state == "stopped")
        #expect(runtime.status().peer.nextRetryMilliseconds == nil)
    }

    @Test func silentProtectedPythonPeersUseDeadlineRetryFreshReadinessAndRejectRetiredEpoch() throws {
        for (mode, transport) in [("tcp-securelink-silent-reconnect-stale", ObstacleBridgeLinuxTransport.tcp), ("ws-securelink-silent-reconnect-stale", .ws)] {
        let peer = try PythonOverlayPeer(mode: mode)
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxLiveRuntime(
            configuration: .init(
                transport: transport, host: "127.0.0.1", port: peer.port,
                webSocketProxy: .init(mode: .off),
                secureLinkPSK: Data("linux-swift-psk".utf8),
                receiveIdleTimeoutMilliseconds: 50
            ),
            policy: .init(initialDelayMilliseconds: 100, maximumDelayMilliseconds: 200, maximumAttempts: 3)
        )
        let retryPresented = DispatchSemaphore(value: 0)
        let freshReady = DispatchSemaphore(value: 0)
        let retiredEpochRejected = DispatchSemaphore(value: 0)
        let observedStateLock = NSLock()
        var freshReadinessWasPublished = false
        runtime.onSnapshot = { snapshot in
            if snapshot.state == "reconnecting", snapshot.nextRetryMilliseconds == 100 { retryPresented.signal() }
            if snapshot.state == "connected", runtime.configuredRuntime.connectionEpoch >= 2 {
                observedStateLock.lock()
                freshReadinessWasPublished = true
                observedStateLock.unlock()
                freshReady.signal()
            }
            observedStateLock.lock()
            let mayReportRetiredEpochRejection = freshReadinessWasPublished
            observedStateLock.unlock()
            if snapshot.state == "reconnecting", runtime.configuredRuntime.connectionEpoch >= 2, mayReportRetiredEpochRejection {
                retiredEpochRejected.signal()
            }
        }
        runtime.start()
        #expect(retryPresented.wait(timeout: .now() + 3) == .success)
        #expect(freshReady.wait(timeout: .now() + 3) == .success)
        observedStateLock.lock()
        let published = freshReadinessWasPublished
        observedStateLock.unlock()
        #expect(published)
        #expect(retiredEpochRejected.wait(timeout: .now() + 3) == .success)
        #expect(!runtime.status().peer.ready)
        runtime.stop()
        }
    }

    @Test func quicLifecycleOwnerReconnectsAgainstPythonAioquicPeer() throws {
        let peer = try PythonOverlayPeer(mode: "quic")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxLiveRuntime(
            configuration: .init(
                transport: .quic, host: "127.0.0.1", port: peer.port,
                quicALPN: "hq-29", quicInsecure: true,
                receiveIdleTimeoutMilliseconds: 5_000
            ),
            policy: .init(initialDelayMilliseconds: 10, maximumDelayMilliseconds: 10, maximumAttempts: 2)
        )
        let firstConnection = DispatchSemaphore(value: 0)
        let reconnected = DispatchSemaphore(value: 0)
        runtime.onSnapshot = { snapshot in
            guard snapshot.state == "connected" else { return }
            if runtime.configuredRuntime.connectionEpoch == 1 { firstConnection.signal() }
            if runtime.configuredRuntime.connectionEpoch >= 2 { reconnected.signal() }
        }
        runtime.start()
        // The package suite schedules several Python-backed peers at once.
        // QUIC's TLS setup can wait behind those workers on a shared Linux
        // runner, so retain a deterministic but non-contentious qualification
        // window rather than treating scheduler pressure as an owner failure.
        #expect(firstConnection.wait(timeout: .now() + 15) == .success)
        runtime.reconnect()
        #expect(reconnected.wait(timeout: .now() + 15) == .success)
        runtime.stop()
    }

    private func assertProtectedReceiveFailureReconnects(mode: String, transport: ObstacleBridgeLinuxTransport) throws {
        let peer = try PythonOverlayPeer(mode: mode)
        defer { peer.stop() }
        // UDP has no close event.  A peer that closes after SecureLink ACK is
        // therefore observed through the configured receive deadline, while
        // TCP/WS still exercise their immediate EOF path.
        let receiveDeadline = transport == .myudp ? 100 : 5_000
        let runtime = ObstacleBridgeLinuxLiveRuntime(
            configuration: .init(transport: transport, host: "127.0.0.1", port: peer.port, secureLinkPSK: Data("linux-swift-psk".utf8), receiveIdleTimeoutMilliseconds: receiveDeadline),
            policy: .init(initialDelayMilliseconds: 5, maximumDelayMilliseconds: 10, maximumAttempts: 2)
        )
        let failed = DispatchSemaphore(value: 0)
        runtime.onSnapshot = { if $0.state == "failed" { failed.signal() } }
        runtime.start()
        #expect(failed.wait(timeout: .now() + 3) == .success)
        #expect(runtime.snapshot.attempts == 2)
        #expect(runtime.snapshot.failureReason != nil)
        #expect(runtime.status().receiveLoopState == "stopped")
        runtime.stop()
    }

    @Test func protectedPeerInitiatedCatalogReachesLiveServiceOwner() throws {
        let peer = try PythonOverlayPeer(mode: "tcp-securelink-catalog-duplex")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxLiveRuntime(configuration: .init(
            transport: .tcp, host: "127.0.0.1", port: peer.port,
            secureLinkPSK: Data("linux-swift-psk".utf8)
        ))
        runtime.start()
        #expect(waitUntil { (runtime.remoteServicePorts()[7] ?? 0) > 0 })
        runtime.stop()
    }

    @Test func protectedPythonPeerCatalogReplacementWithdrawsPriorListener() throws {
        let peer = try PythonOverlayPeer(mode: "tcp-securelink-catalog-replace-duplex")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxLiveRuntime(configuration: .init(
            transport: .tcp, host: "127.0.0.1", port: peer.port,
            secureLinkPSK: Data("linux-swift-psk".utf8)
        ))
        runtime.start()
        defer { runtime.stop() }
        #expect(waitUntil { (runtime.remoteServicePorts()[7] ?? 0) > 0 })
        #expect(waitUntil {
            let ports = runtime.remoteServicePorts()
            return ports[7] == nil && (ports[8] ?? 0) > 0
        })
        Thread.sleep(forTimeInterval: 0.25)
        #expect(runtime.remoteServicePorts().keys.sorted() == [8])
    }

    @Test func liveRuntimeOwnsOneCleartextReceiveWorkerAndCancelsItOnStop() throws {
        let peer = try PythonOverlayPeer(mode: "tcp-duplex")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxLiveRuntime(configuration: .init(
            transport: .tcp, host: "127.0.0.1", port: peer.port
        ))
        let connected = DispatchSemaphore(value: 0)
        runtime.onSnapshot = { if $0.state == "connected" { connected.signal() } }
        runtime.start()
        #expect(connected.wait(timeout: .now() + 3) == .success)
        #expect(waitUntil { runtime.status().receiveLoopState == "running" })
        #expect(runtime.status().receiveEpoch == runtime.configuredRuntime.connectionEpoch)
        #expect(waitUntil { runtime.status().receivedFrames >= 1 })
        runtime.stop()
        #expect(runtime.status().receiveLoopState == "stopped")
        #expect(runtime.status().receiveQueueDepth == 0)
    }

    @Test func liveRuntimeOwnsAuthenticatedSessionAndStops() throws {
        let peer = try PythonOverlayPeer(mode: "tcp-securelink")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxLiveRuntime(configuration: .init(
            transport: .tcp,
            host: "127.0.0.1",
            port: peer.port,
            secureLinkPSK: Data("linux-swift-psk".utf8)
        ))
        let connected = DispatchSemaphore(value: 0)
        runtime.onSnapshot = { if $0.state == "connected" { connected.signal() } }
        runtime.start()
        #expect(connected.wait(timeout: .now() + 3) == .success)
        #expect(runtime.configuredRuntime.status().appReady)
        #expect(try runtime.send(Data("live-runtime".utf8)) == Data("python:live-runtime".utf8))
        runtime.stop()
        #expect(runtime.snapshot.state == "stopped")
        #expect(runtime.configuredRuntime.status().state == "disconnected")
        #expect(!runtime.configuredRuntime.status().appReady)
    }

    @Test func liveRuntimeReportsRetryExhaustionAndCancelsItOnStop() {
        let runtime = ObstacleBridgeLinuxLiveRuntime(
            configuration: .init(transport: .tcp, host: "127.0.0.1", port: 1),
            policy: .init(initialDelayMilliseconds: 5, maximumDelayMilliseconds: 10, maximumAttempts: 2)
        )
        let failed = DispatchSemaphore(value: 0)
        runtime.onSnapshot = { if $0.state == "failed" { failed.signal() } }
        runtime.start()
        #expect(failed.wait(timeout: .now() + 3) == .success)
        #expect(runtime.snapshot.attempts == 2)
        #expect(runtime.snapshot.failureReason != nil)
        runtime.stop()
        #expect(runtime.snapshot.state == "stopped")
    }

    @Test func liveRuntimeStartsConfiguredLocalServiceOnlyAfterAuthentication() throws {
        let peer = try PythonOverlayPeer(mode: "tcp-securelink")
        defer { peer.stop() }
        let service = ObstacleBridgeLinuxServiceSpec(serviceID: 1, name: "test", listenProtocol: .tcp, listenHost: "127.0.0.1", listenPort: 0, targetProtocol: .tcp, targetHost: "127.0.0.1", targetPort: 7)
        let runtime = ObstacleBridgeLinuxLiveRuntime(configuration: .init(
            transport: .tcp, host: "127.0.0.1", port: peer.port,
            secureLinkPSK: Data("linux-swift-psk".utf8), ownServices: [service]
        ))
        let connected = DispatchSemaphore(value: 0)
        runtime.onSnapshot = { if $0.state == "connected" { connected.signal() } }
        runtime.start()
        #expect(connected.wait(timeout: .now() + 3) == .success)
        #expect(runtime.localServicePorts()[1] ?? 0 > 0)
        runtime.stop()
        #expect(runtime.localServicePorts().isEmpty)
    }

    @Test func liveRuntimeInstallsAndWithdrawsPeerRemoteCatalog() throws {
        let peer = try PythonOverlayPeer(mode: "tcp-securelink")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxLiveRuntime(configuration: .init(
            transport: .tcp, host: "127.0.0.1", port: peer.port, secureLinkPSK: Data("linux-swift-psk".utf8)
        ))
        let connected = DispatchSemaphore(value: 0)
        runtime.onSnapshot = { if $0.state == "connected" { connected.signal() } }
        runtime.start()
        #expect(connected.wait(timeout: .now() + 3) == .success)
        let remote = ObstacleBridgeLinuxServiceSpec(serviceID: 7, name: "peer", listenProtocol: .udp, listenHost: "127.0.0.1", listenPort: availableUDPPort(), targetProtocol: .udp, targetHost: "127.0.0.1", targetPort: 7)
        let catalog = try ObstacleBridgeLinuxServiceCatalog.encode(instanceID: 4, connectionSequence: 1, services: [remote])
        runtime.receiveChannelMuxFrame(.init(channelID: 0, protocolType: .udp, counter: 0, messageType: .remoteServicesSetV2, body: catalog))
        #expect(waitUntil { (runtime.remoteServicePorts()[7] ?? 0) > 0 })

        let withdrawal = try ObstacleBridgeLinuxServiceCatalog.encode(instanceID: 4, connectionSequence: 2, services: [])
        runtime.receiveChannelMuxFrame(.init(channelID: 0, protocolType: .udp, counter: 1, messageType: .remoteServicesSetV2, body: withdrawal))
        #expect(waitUntil { runtime.remoteServicePorts().isEmpty })
        runtime.stop()
    }

    @Test func liveRuntimeRoutesLocalTcpServiceFramesThroughAuthenticatedPythonPeer() throws {
        let peer = try PythonOverlayPeer(mode: "tcp-secure-mux-echo")
        defer { peer.stop() }
        let service = ObstacleBridgeLinuxServiceSpec(serviceID: 1, name: "echo", listenProtocol: .tcp, listenHost: "127.0.0.1", listenPort: 0, targetProtocol: .tcp, targetHost: "127.0.0.1", targetPort: 7)
        let runtime = ObstacleBridgeLinuxLiveRuntime(configuration: .init(
            transport: .tcp, host: "127.0.0.1", port: peer.port, secureLinkPSK: Data("linux-swift-psk".utf8), ownServices: [service]
        ))
        let connected = DispatchSemaphore(value: 0)
        runtime.onSnapshot = { if $0.state == "connected" { connected.signal() } }
        runtime.start()
        #expect(connected.wait(timeout: .now() + 3) == .success)
        let fd = try connectTCP(port: try #require(runtime.localServicePorts()[1]))
        let payload = Data("mux-through-python".utf8)
        #expect(payload.withUnsafeBytes { write(fd, $0.baseAddress, payload.count) } == payload.count)
        var received = [UInt8](repeating: 0, count: payload.count)
        #expect(read(fd, &received, received.count) == payload.count)
        #expect(Data(received) == payload)
        _ = close(fd)
        #expect(waitUntil { runtime.status().activeTCPChannels == 0 })
        runtime.stop()
    }

    @Test func liveRuntimeRoutesLocalUdpServiceFramesThroughAuthenticatedPythonPeer() throws {
        let peer = try PythonOverlayPeer(mode: "tcp-secure-mux-echo")
        defer { peer.stop() }
        let service = ObstacleBridgeLinuxServiceSpec(serviceID: 1, name: "echo", listenProtocol: .udp, listenHost: "127.0.0.1", listenPort: availableUDPPort(), targetProtocol: .udp, targetHost: "127.0.0.1", targetPort: 7)
        let runtime = ObstacleBridgeLinuxLiveRuntime(configuration: .init(
            transport: .tcp, host: "127.0.0.1", port: peer.port, secureLinkPSK: Data("linux-swift-psk".utf8), ownServices: [service]
        ))
        let connected = DispatchSemaphore(value: 0)
        runtime.onSnapshot = { if $0.state == "connected" { connected.signal() } }
        runtime.start()
        #expect(connected.wait(timeout: .now() + 3) == .success)
        let fd = try connectUDP(port: try #require(runtime.localServicePorts()[1]))
        defer { _ = close(fd) }
        let payload = Data("udp-through-python".utf8)
        #expect(payload.withUnsafeBytes { send(fd, $0.baseAddress, payload.count, 0) } == payload.count)
        var received = [UInt8](repeating: 0, count: payload.count)
        #expect(recv(fd, &received, received.count, 0) == payload.count)
        #expect(Data(received) == payload)
        runtime.stop()
    }

    @Test func liveRuntimeReassemblesForcedUdpFragmentsThroughAuthenticatedPythonPeer() throws {
        let peer = try PythonOverlayPeer(mode: "tcp-secure-mux-echo")
        defer { peer.stop() }
        let service = ObstacleBridgeLinuxServiceSpec(serviceID: 1, name: "fragmented-echo", listenProtocol: .udp, listenHost: "127.0.0.1", listenPort: availableUDPPort(), targetProtocol: .udp, targetHost: "127.0.0.1", targetPort: 7)
        let runtime = ObstacleBridgeLinuxLiveRuntime(configuration: .init(
            transport: .tcp, host: "127.0.0.1", port: peer.port,
            secureLinkPSK: Data("linux-swift-psk".utf8),
            channelMuxMaximumApplicationPayload: 160,
            ownServices: [service]
        ))
        let connected = DispatchSemaphore(value: 0)
        runtime.onSnapshot = { if $0.state == "connected" { connected.signal() } }
        runtime.start()
        defer { runtime.stop() }
        #expect(connected.wait(timeout: .now() + 3) == .success)
        let fd = try connectUDP(port: try #require(runtime.localServicePorts()[1]))
        defer { _ = close(fd) }
        let payload = Data((0..<240).map { UInt8($0 & 0xFF) })
        #expect(payload.withUnsafeBytes { send(fd, $0.baseAddress, payload.count, 0) } == payload.count)
        var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        #expect(poll(&descriptor, 1, 3_000) > 0)
        guard descriptor.revents & Int16(POLLIN) != 0 else { return }
        var received = [UInt8](repeating: 0, count: payload.count)
        #expect(recv(fd, &received, received.count, 0) == payload.count)
        #expect(Data(received) == payload)
    }

    private func waitUntil(_ predicate: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(2)
        while Date() < deadline {
            if predicate() { return true }
            Thread.sleep(forTimeInterval: 0.01)
        }
        return predicate()
    }

    private func availableUDPPort() -> Int {
        let fd = socket(AF_INET, Int32(SOCK_DGRAM.rawValue), 0)
        defer { _ = close(fd) }
        var address = sockaddr_in(); address.sin_family = sa_family_t(AF_INET); address.sin_port = 0
        _ = "127.0.0.1".withCString { inet_pton(AF_INET, $0, &address.sin_addr) }
        _ = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        var actual = sockaddr_in(); var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &actual) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) } }
        return Int(UInt16(bigEndian: actual.sin_port))
    }

    private func connectTCP(port: Int) throws -> Int32 {
        let fd = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        guard fd >= 0 else { throw SocketError.failure }
        var timeout = timeval(tv_sec: 3, tv_usec: 0)
        _ = withUnsafePointer(to: &timeout) { setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, $0, socklen_t(MemoryLayout<timeval>.size)) }
        var address = sockaddr_in(); address.sin_family = sa_family_t(AF_INET); address.sin_port = in_port_t(UInt16(port).bigEndian)
        _ = "127.0.0.1".withCString { inet_pton(AF_INET, $0, &address.sin_addr) }
        let result = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Glibc.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard result == 0 else { _ = close(fd); throw SocketError.failure }
        return fd
    }

    private func connectUDP(port: Int) throws -> Int32 {
        let fd = socket(AF_INET, Int32(SOCK_DGRAM.rawValue), 0)
        guard fd >= 0 else { throw SocketError.failure }
        var timeout = timeval(tv_sec: 3, tv_usec: 0)
        _ = withUnsafePointer(to: &timeout) { setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, $0, socklen_t(MemoryLayout<timeval>.size)) }
        var address = sockaddr_in(); address.sin_family = sa_family_t(AF_INET); address.sin_port = in_port_t(UInt16(port).bigEndian)
        _ = "127.0.0.1".withCString { inet_pton(AF_INET, $0, &address.sin_addr) }
        let result = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Glibc.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard result == 0 else { _ = close(fd); throw SocketError.failure }
        return fd
    }

    private func receiveUDPWire(_ fd: Int32) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 1_452)
        let count = recv(fd, &bytes, bytes.count, 0)
        guard count > 0 else { throw SocketError.failure }
        return Data(bytes.prefix(Int(count)))
    }

    private enum SocketError: Error { case failure }
}
