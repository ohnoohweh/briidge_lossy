import Dispatch
import Foundation
import Testing
#if os(Linux)
import Glibc
#endif
@testable import ObstacleBridgeLinuxAdapters

struct ObstacleBridgeLinuxLiveRuntimeTests {
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

    private enum SocketError: Error { case failure }
}
