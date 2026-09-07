import Dispatch
import Foundation
import Testing
#if os(Linux)
import Glibc
#endif
@testable import ObstacleBridgeLinuxAdapters
@testable import ObstacleBridgePortable

struct ObstacleBridgeLinuxServiceSocketOwnerTests {
    @Test func tcpListenerPublishesOpenAndDataFrames() throws {
        let received = LockedFrames()
        let ready = DispatchSemaphore(value: 0)
        let owner = ObstacleBridgeLinuxServiceSocketOwner(spec: service(protocolType: .tcp)) { _, frames in
            received.append(frames)
            if received.all.count >= 2 { ready.signal() }
        }
        try owner.start()
        defer { owner.stop() }
        let fd = try connect(port: owner.port, type: SOCK_STREAM)
        defer { _ = close(fd) }
        let payload = Data("tcp-payload".utf8)
        #expect(payload.withUnsafeBytes { write(fd, $0.baseAddress, payload.count) } == payload.count)
        #expect(ready.wait(timeout: .now() + 3) == .success)
        let frames = received.all
        #expect(frames.map(\.messageType) == [.open, .data])
        if frames.count == 2 { #expect(frames[1].body == payload) }
    }

    @Test func udpListenerPublishesOpenAndDataFrames() throws {
        let received = LockedFrames()
        let ready = DispatchSemaphore(value: 0)
        let owner = ObstacleBridgeLinuxServiceSocketOwner(spec: service(protocolType: .udp)) { _, frames in
            received.append(frames)
            if received.all.count >= 2 { ready.signal() }
        }
        try owner.start()
        defer { owner.stop() }
        let fd = try connect(port: owner.port, type: SOCK_DGRAM)
        defer { _ = close(fd) }
        let payload = Data("udp-payload".utf8)
        #expect(payload.withUnsafeBytes { send(fd, $0.baseAddress, payload.count, 0) } == payload.count)
        #expect(ready.wait(timeout: .now() + 3) == .success)
        #expect(received.all.map(\.messageType) == [.open, .data])
        #expect(received.all[0].protocolType == .udp)
        #expect(received.all[1].body == payload)
    }

    private func service(protocolType: ObstacleBridgeChannelMuxProtocol) -> ObstacleBridgeLinuxServiceSpec {
        .init(serviceID: 1, name: "test", listenProtocol: protocolType, listenHost: "127.0.0.1", listenPort: 0, targetProtocol: protocolType, targetHost: "127.0.0.1", targetPort: 7)
    }

    private func connect(port: Int, type: __socket_type) throws -> Int32 {
        let fd = socket(AF_INET, Int32(type.rawValue), 0)
        guard fd >= 0 else { throw Errno.failure }
        var address = sockaddr_in(); address.sin_family = sa_family_t(AF_INET); address.sin_port = in_port_t(UInt16(port).bigEndian)
        _ = "127.0.0.1".withCString { inet_pton(AF_INET, $0, &address.sin_addr) }
        let result = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Glibc.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard result == 0 else { _ = close(fd); throw Errno.failure }
        return fd
    }

    private enum Errno: Error { case failure }
}

private final class LockedFrames: @unchecked Sendable {
    private let lock = NSLock()
    private var value: [ObstacleBridgeChannelMuxFrame] = []
    var all: [ObstacleBridgeChannelMuxFrame] { lock.lock(); defer { lock.unlock() }; return value }
    func append(_ frames: [ObstacleBridgeChannelMuxFrame]) { lock.lock(); value.append(contentsOf: frames); lock.unlock() }
}
