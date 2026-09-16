import Dispatch
import Foundation
import Testing
#if os(Linux)
import Glibc
#endif
import ObstacleBridgeCore
@testable import ObstacleBridgeLinuxAdapters

struct ObstacleBridgeLinuxLiveRuntimeTests {
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

    @Test func protectedReceiveFailureWithdrawsEpochAndUsesBoundedReconnect() throws {
        try assertProtectedReceiveFailureReconnects(mode: "tcp-securelink-close-after-ack", transport: .tcp)
    }

    @Test func protectedWebSocketReceiveFailureWithdrawsEpochAndUsesBoundedReconnect() throws {
        try assertProtectedReceiveFailureReconnects(mode: "ws-securelink-close-after-ack", transport: .ws)
    }

    @Test func protectedMyudpReceiveFailureWithdrawsEpochAndUsesBoundedReconnect() throws {
        try assertProtectedReceiveFailureReconnects(mode: "myudp-securelink-close-after-ack", transport: .myudp)
    }

    @Test func silentMyudpPeerDeliversReceiveDeadlineFailureToLiveRuntime() throws {
        let peer = try PythonOverlayPeer(mode: "myudp-securelink-silent")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxLiveRuntime(
            configuration: .init(transport: .myudp, host: "127.0.0.1", port: peer.port, secureLinkPSK: Data("linux-swift-psk".utf8), receiveIdleTimeoutMilliseconds: 50),
            policy: .init(initialDelayMilliseconds: 10, maximumDelayMilliseconds: 10, maximumAttempts: 1)
        )
        let failed = DispatchSemaphore(value: 0)
        runtime.onSnapshot = { if $0.state == "failed" { failed.signal() } }
        runtime.start()
        #expect(failed.wait(timeout: .now() + 2) == .success)
        #expect(runtime.snapshot.failureReason != nil)
        runtime.stop()
    }

    @Test func silentProtectedPythonPeersUseDeadlineRetryAndFreshReadyEpoch() throws {
        for (mode, transport) in [("tcp-securelink-silent-reconnect", ObstacleBridgeLinuxTransport.tcp), ("ws-securelink-silent-reconnect", .ws)] {
        let peer = try PythonOverlayPeer(mode: mode)
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxLiveRuntime(
            configuration: .init(
                transport: transport, host: "127.0.0.1", port: peer.port,
                secureLinkPSK: Data("linux-swift-psk".utf8),
                receiveIdleTimeoutMilliseconds: 50
            ),
            policy: .init(initialDelayMilliseconds: 100, maximumDelayMilliseconds: 200, maximumAttempts: 3)
        )
        let retryPresented = DispatchSemaphore(value: 0)
        let freshReady = DispatchSemaphore(value: 0)
        runtime.onSnapshot = { snapshot in
            if snapshot.state == "reconnecting", snapshot.nextRetryMilliseconds == 100 { retryPresented.signal() }
            if snapshot.state == "connected", runtime.configuredRuntime.connectionEpoch >= 2 {
                freshReady.signal()
            }
        }
        runtime.start()
        #expect(retryPresented.wait(timeout: .now() + 3) == .success)
        #expect(freshReady.wait(timeout: .now() + 3) == .success)
        runtime.stop()
        }
    }

    private func assertProtectedReceiveFailureReconnects(mode: String, transport: ObstacleBridgeLinuxTransport) throws {
        let peer = try PythonOverlayPeer(mode: mode)
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxLiveRuntime(
            configuration: .init(transport: transport, host: "127.0.0.1", port: peer.port, secureLinkPSK: Data("linux-swift-psk".utf8)),
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
        defer { _ = close(fd) }
        let payload = Data("mux-through-python".utf8)
        #expect(payload.withUnsafeBytes { write(fd, $0.baseAddress, payload.count) } == payload.count)
        var received = [UInt8](repeating: 0, count: payload.count)
        #expect(read(fd, &received, received.count) == payload.count)
        #expect(Data(received) == payload)
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
