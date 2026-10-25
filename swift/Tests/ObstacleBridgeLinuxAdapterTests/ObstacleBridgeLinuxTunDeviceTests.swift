import Foundation
import Testing
@testable import ObstacleBridgeLinuxAdapters
import ObstacleBridgeDesktopShared
#if os(Linux)
import Glibc
#endif

struct ObstacleBridgeLinuxTunDeviceTests {
    private func ipv4Packet() -> Data { Data([0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]) }

    @Test func rejectsUnsafeInterfaceNamesAndPackets() throws {
        #expect(throws: ObstacleBridgeLinuxTunDeviceError.invalidInterfaceName) {
            _ = try ObstacleBridgeLinuxTunDevice(interfaceName: "invalid/interface", mtu: 1500, packetSink: { _ in })
        }
        #expect(throws: ObstacleBridgeLinuxTunDeviceError.invalidMTU) {
            _ = try ObstacleBridgeLinuxTunDevice(interfaceName: "obtest0", mtu: 67, packetSink: { _ in })
        }
        let pair = try makeSocketPair()
        defer { close(pair.1) }
        let device = try ObstacleBridgeLinuxTunDevice(testFileDescriptor: pair.0, packetSink: { _ in })
        defer { device.stop() }
        #expect(throws: ObstacleBridgeLinuxTunDeviceError.invalidPacketVersion(0)) { try device.writePacket(Data([0])) }
    }

    @Test func ownsBidirectionalNonBlockingPacketIO() throws {
        let pair = try makeSocketPair()
        defer { close(pair.1) }
        let received = expectation()
        let lock = NSLock()
        var packets: [Data] = []
        let device = try ObstacleBridgeLinuxTunDevice(testFileDescriptor: pair.0, packetSink: {
            lock.lock(); packets.append($0); lock.unlock(); received.signal()
        })
        defer { device.stop() }

        let inbound = ipv4Packet()
        try writeAll(inbound, to: pair.1)
        #expect(received.wait(timeout: .now() + 1) == .success)
        lock.lock(); let captured = packets; lock.unlock()
        #expect(captured == [inbound])

        let outbound = Data([0x60, 0, 0, 0, 0, 0, 17, 64] + Array(repeating: 0, count: 32))
        try device.writePacket(outbound)
        #expect(try readExactly(outbound.count, from: pair.1) == outbound)
    }

    @Test func nativeAdminChildUsesInheritedControlAndExitsOnOwnerLoss() throws {
        let control = try makeSocketPair()
        let lifetime = try makeSocketPair()
        let log = try makeDatagramSocketPair()
        let childControl = dup(control.1)
        let childLifetime = dup(lifetime.1)
        let childLog = dup(log.1)
        guard childControl >= 0, childLifetime >= 0, childLog >= 0 else { throw POSIXError(.EMFILE) }
        close(control.1); close(lifetime.1); close(log.1)
        defer { close(control.0) }
        defer { close(log.0) }
        var parentLifetimeFD = lifetime.0
        defer {
            if parentLifetimeFD >= 0 { close(parentLifetimeFD) }
        }
        let stopped = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            defer { stopped.signal() }
            try? ObstacleBridgeNativeAdminWorker.run(
                controlFD: childControl,
                lifetimeFD: childLifetime,
                logFD: childLog,
                generation: 7,
                serviceFactory: { arguments, parentRPC in
                    let service = try ObstacleBridgeNativeAdminLinuxService(arguments: arguments, parentRPC: parentRPC)
                    return .init(port: service.port, stop: { service.stop() })
                }
            )
        }

        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .hello, generation: 7, value: [
            "v": 1, "kind": "worker.hello", "role": "supervisor", "capabilities": ["admin.control"], "generation": 7,
        ]), to: control.0)
        #expect(try readControl(from: control.0)["kind"] as? String == "worker.hello")
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .request, generation: 7, value: ["v": 1, "kind": "admin.start", "args": ["admin_web_bind": "127.0.0.1", "admin_web_port": 0], "log_root_level": 0]), to: control.0)
        let request = try readControl(from: control.0)
        #expect(request["kind"] as? String == "admin.call")
        #expect(request["id"] as? String == "bootstrap-status")
        #expect(request["method"] as? String == "get_status_snapshot")
        #expect((request["args"] as? [Any])?.isEmpty == true)
        #expect(request["kwargs"] as? [String: Any] != nil)
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .response, generation: 7, value: ["v": 1, "kind": "admin.reply", "id": "bootstrap-status", "ok": true, "result": [String: Any]()]), to: control.0)
        let ready = try readControl(from: control.0)
        #expect(ready["kind"] as? String == "admin.ready")
        #expect(ready["implementation"] as? String == "native")
        #expect((ready["port"] as? NSNumber)?.intValue ?? 0 > 0)
        let record = try JSONSerialization.jsonObject(with: readDatagram(from: log.0)) as? [String: Any]
        #expect(record?["name"] as? String == "admin.native")
        #expect(record?["message"] as? String == "native_admin_ready")
        close(parentLifetimeFD)
        parentLifetimeFD = -1
        #expect(stopped.wait(timeout: .now() + 1) == .success)
    }

    @Test func nativeAdminChildBoundsBootstrapStatusReplyWait() throws {
        let control = try makeSocketPair()
        let lifetime = try makeSocketPair()
        let childControl = dup(control.1)
        let childLifetime = dup(lifetime.1)
        guard childControl >= 0, childLifetime >= 0 else { throw POSIXError(.EMFILE) }
        close(control.1); close(lifetime.1)
        defer { close(control.0); close(lifetime.0) }
        let stopped = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            defer { stopped.signal() }
            try? ObstacleBridgeNativeAdminWorker.run(controlFD: childControl, lifetimeFD: childLifetime, generation: 9)
        }

        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .hello, generation: 9, value: [
            "v": 1, "kind": "worker.hello", "role": "supervisor", "capabilities": ["admin.control"], "generation": 9,
        ]), to: control.0)
        #expect(try readControl(from: control.0)["kind"] as? String == "worker.hello")
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .request, generation: 9, value: ["v": 1, "kind": "admin.start", "args": [String: Any]()]), to: control.0)
        #expect(try readControl(from: control.0)["kind"] as? String == "admin.call")
        #expect(stopped.wait(timeout: .now() + 2) == .success)
    }

    @Test func nativeAdminChildRejectsNonUnixStreamCapabilities() throws {
        var descriptors = [Int32](repeating: -1, count: 2)
        guard pipe(&descriptors) == 0 else { throw POSIXError(.EMFILE) }
        defer { close(descriptors[0]); close(descriptors[1]) }
        #expect(throws: (any Error).self) {
            try ObstacleBridgeNativeAdminWorker.run(controlFD: descriptors[0], lifetimeFD: descriptors[1], generation: 1)
        }
    }

    /// This is intentionally opt-in: opening a kernel TUN device requires
    /// CAP_NET_ADMIN and must not make ordinary CI depend on host privileges.
    @Test(.enabled(if: ProcessInfo.processInfo.environment["OBSTACLEBRIDGE_PRIVILEGED_TUN"] == "1"))
    func privilegedKernelTunOpensAndAcceptsIPv4() throws {
        let name = "obq\(getpid() % 100_000)"
        let device = try ObstacleBridgeLinuxTunDevice(interfaceName: name, mtu: 1500, packetSink: { _ in })
        defer { device.stop() }
        try device.start()
        #expect(device.actualInterfaceName == name)
        try device.writePacket(ipv4Packet())
    }

    private func expectation() -> DispatchSemaphore { DispatchSemaphore(value: 0) }

    private func makeSocketPair() throws -> (Int32, Int32) {
        var descriptors = [Int32](repeating: -1, count: 2)
        guard socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, &descriptors) == 0 else { throw POSIXError(.ENFILE) }
        return (descriptors[0], descriptors[1])
    }

    private func makeDatagramSocketPair() throws -> (Int32, Int32) {
        var descriptors = [Int32](repeating: -1, count: 2)
        guard socketpair(AF_UNIX, Int32(SOCK_DGRAM.rawValue), 0, &descriptors) == 0 else { throw POSIXError(.ENFILE) }
        return (descriptors[0], descriptors[1])
    }

    private func readDatagram(from descriptor: Int32) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 8192)
        let count = read(descriptor, &bytes, bytes.count)
        guard count > 0 else { throw POSIXError(.EIO) }
        return Data(bytes.prefix(count))
    }

    private func writeAll(_ data: Data, to descriptor: Int32) throws {
        var offset = 0
        while offset < data.count {
            let result = data.withUnsafeBytes { bytes in
                write(descriptor, bytes.baseAddress!.advanced(by: offset), data.count - offset)
            }
            guard result > 0 else { throw POSIXError(.EIO) }
            offset += result
        }
    }

    private func readExactly(_ count: Int, from descriptor: Int32) throws -> Data {
        var output = [UInt8](repeating: 0, count: count)
        var offset = 0
        while offset < count {
            let result = output.withUnsafeMutableBytes { bytes in
                read(descriptor, bytes.baseAddress!.advanced(by: offset), count - offset)
            }
            guard result > 0 else { throw POSIXError(.EIO) }
            offset += result
        }
        return Data(output)
    }

    private func readControl(from descriptor: Int32) throws -> [String: Any] {
        let header = try readExactly(ObstacleBridgeWorkerIPC.headerBytes, from: descriptor)
        guard let size = try ObstacleBridgeWorkerIPC.frameSize(header),
              let frame = try ObstacleBridgeWorkerIPC.decode(header + readExactly(size, from: descriptor)).0
        else { throw POSIXError(.EIO) }
        return try ObstacleBridgeWorkerIPC.decodeControl(frame)
    }
}
