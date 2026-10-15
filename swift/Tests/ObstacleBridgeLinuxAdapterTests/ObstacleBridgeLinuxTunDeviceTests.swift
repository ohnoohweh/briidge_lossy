import Foundation
import Testing
@testable import ObstacleBridgeLinuxAdapters
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

    private func writeAll(_ data: Data, to descriptor: Int32) throws {
        let result = data.withUnsafeBytes { write(descriptor, $0.baseAddress, data.count) }
        guard result == data.count else { throw POSIXError(.EIO) }
    }

    private func readExactly(_ count: Int, from descriptor: Int32) throws -> Data {
        var output = [UInt8](repeating: 0, count: count)
        let result = read(descriptor, &output, count)
        guard result == count else { throw POSIXError(.EIO) }
        return Data(output)
    }
}
