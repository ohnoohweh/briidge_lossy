import Foundation
import ObstacleBridgeCore
#if os(Linux)
import Glibc
@_silgen_name("ioctl")
private func linuxTunIoctl(_ fileDescriptor: Int32, _ request: UInt, _ argument: UnsafeMutableRawPointer) -> Int32
#endif

/// Errors emitted by the Linux `/dev/net/tun` packet-device owner.
public enum ObstacleBridgeLinuxTunDeviceError: Error, Equatable, LocalizedError {
    case unsupportedPlatform
    case invalidInterfaceName
    case invalidMTU
    case openFailed(Int32)
    case configureFailed(Int32)
    case nonBlockingConfigurationFailed(Int32)
    case invalidPacketVersion(Int)
    case notRunning
    case readFailed(Int32)
    case writeFailed(Int32)

    public var errorDescription: String? {
        switch self {
        case .unsupportedPlatform: return "Linux TUN packet devices are supported only on Linux"
        case .invalidInterfaceName: return "Linux TUN interface name must be 1-15 ASCII letters, digits, dots, underscores, or hyphens"
        case .invalidMTU: return "Linux TUN MTU must be between 68 and 65535"
        case .openFailed(let code): return "unable to open /dev/net/tun errno=\(code)"
        case .configureFailed(let code): return "unable to configure /dev/net/tun errno=\(code)"
        case .nonBlockingConfigurationFailed(let code): return "unable to configure non-blocking /dev/net/tun I/O errno=\(code)"
        case .invalidPacketVersion(let version): return "Linux TUN packets must be IPv4 or IPv6, got version \(version)"
        case .notRunning: return "Linux TUN packet device is not running"
        case .readFailed(let code): return "Linux TUN packet read failed errno=\(code)"
        case .writeFailed(let code): return "Linux TUN packet write failed errno=\(code)"
        }
    }
}

/// Linux resource owner for one `IFF_TUN | IFF_NO_PI` packet device.
///
/// This adapter deliberately owns only packet I/O. Route, DNS, underlay, and
/// teardown policy remain with the configured helper contract (LSW-006).
public final class ObstacleBridgeLinuxTunDevice: ObstacleBridgeLinuxPacketDevice, @unchecked Sendable {
    public typealias PacketSink = (Data) -> Void
    public typealias DiagnosticSink = (String, [String: Any]) -> Void

    private static let tunSetIFF: UInt = 0x4004_54ca
    private static let iffTun: UInt16 = 0x0001
    private static let iffNoPacketInfo: UInt16 = 0x1000
    private static let interfaceNameCapacity = 16

    public let requestedInterfaceName: String
    public let mtu: Int
    public private(set) var actualInterfaceName: String
    private let queue: DispatchQueue
    private let packetSink: PacketSink
    private let diagnosticSink: DiagnosticSink
    private let lock = NSLock()
    private var fd: Int32 = -1
    private var readSource: DispatchSourceRead?

    public init(
        interfaceName: String,
        mtu: Int,
        queue: DispatchQueue = DispatchQueue(label: "org.obstaclebridge.linux.tun"),
        packetSink: @escaping PacketSink,
        diagnosticSink: @escaping DiagnosticSink = { _, _ in }
    ) throws {
        guard Self.isValidInterfaceName(interfaceName) else { throw ObstacleBridgeLinuxTunDeviceError.invalidInterfaceName }
        guard (68...65_535).contains(mtu) else { throw ObstacleBridgeLinuxTunDeviceError.invalidMTU }
        self.requestedInterfaceName = interfaceName
        self.actualInterfaceName = interfaceName
        self.mtu = mtu
        self.queue = queue
        self.packetSink = packetSink
        self.diagnosticSink = diagnosticSink
    }

    /// Opens and configures the kernel packet device. Calling this more than
    /// once is idempotent so runtime lifecycle ownership can safely retry
    /// higher-level startup without duplicating descriptor readers.
    public func start() throws {
#if os(Linux)
        lock.lock()
        if fd >= 0 { lock.unlock(); return }
        lock.unlock()
        let opened = try Self.openTun(interfaceName: requestedInterfaceName)
        install(fileDescriptor: opened.0, actualInterfaceName: opened.1)
#else
        throw ObstacleBridgeLinuxTunDeviceError.unsupportedPlatform
#endif
    }

    public func stop() {
        lock.lock()
        let source = readSource
        readSource = nil
        let descriptor = fd
        fd = -1
        lock.unlock()
        source?.cancel()
        if source == nil, descriptor >= 0 {
#if os(Linux)
            _ = close(descriptor)
#endif
        }
    }

    public func writePacket(_ packet: Data) throws {
        guard let first = packet.first else { throw ObstacleBridgeLinuxTunDeviceError.invalidPacketVersion(-1) }
        let version = Int(first >> 4)
        guard version == 4 || version == 6 else { throw ObstacleBridgeLinuxTunDeviceError.invalidPacketVersion(version) }
        lock.lock(); let descriptor = fd; lock.unlock()
        guard descriptor >= 0 else { throw ObstacleBridgeLinuxTunDeviceError.notRunning }
#if os(Linux)
        var offset = 0
        while offset < packet.count {
            let written = packet.withUnsafeBytes { buffer in
                write(descriptor, buffer.baseAddress!.advanced(by: offset), packet.count - offset)
            }
            guard written > 0 else { throw ObstacleBridgeLinuxTunDeviceError.writeFailed(errno) }
            offset += Int(written)
        }
#else
        _ = descriptor
        throw ObstacleBridgeLinuxTunDeviceError.unsupportedPlatform
#endif
    }

    deinit { stop() }

    /// Test-only descriptor admission lets unit tests exercise the actual
    /// non-blocking read/write lifetime without privileged kernel setup.
    init(testFileDescriptor: Int32, interfaceName: String = "obtest0", mtu: Int = 1500, queue: DispatchQueue = DispatchQueue(label: "org.obstaclebridge.linux.tun.test"), packetSink: @escaping PacketSink, diagnosticSink: @escaping DiagnosticSink = { _, _ in }) throws {
        guard testFileDescriptor >= 0 else { throw ObstacleBridgeLinuxTunDeviceError.openFailed(EBADF) }
        guard Self.isValidInterfaceName(interfaceName) else { throw ObstacleBridgeLinuxTunDeviceError.invalidInterfaceName }
        self.requestedInterfaceName = interfaceName
        self.actualInterfaceName = interfaceName
        self.mtu = mtu
        self.queue = queue
        self.packetSink = packetSink
        self.diagnosticSink = diagnosticSink
        install(fileDescriptor: testFileDescriptor, actualInterfaceName: interfaceName)
    }

    private func install(fileDescriptor: Int32, actualInterfaceName: String) {
#if os(Linux)
        let flags = fcntl(fileDescriptor, F_GETFL)
        guard flags >= 0, fcntl(fileDescriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
            _ = close(fileDescriptor)
            diagnosticSink("linux_tun_start_failed", ["errno": errno])
            return
        }
        lock.lock()
        guard fd < 0 else { lock.unlock(); _ = close(fileDescriptor); return }
        fd = fileDescriptor
        self.actualInterfaceName = actualInterfaceName
        let source = DispatchSource.makeReadSource(fileDescriptor: fileDescriptor, queue: queue)
        source.setEventHandler { [weak self] in self?.drainReadable() }
        source.setCancelHandler { [weak self] in
            guard let self else { return }
            self.lock.lock()
            let descriptor = self.fd
            self.fd = -1
            self.lock.unlock()
            if descriptor >= 0 { _ = close(descriptor) }
        }
        readSource = source
        lock.unlock()
        source.resume()
        diagnosticSink("linux_tun_started", ["requested_ifname": requestedInterfaceName, "actual_ifname": actualInterfaceName, "mtu": mtu])
#else
        _ = fileDescriptor
#endif
    }

    private func drainReadable() {
#if os(Linux)
        lock.lock(); let descriptor = fd; lock.unlock()
        guard descriptor >= 0 else { return }
        var buffer = [UInt8](repeating: 0, count: min(65_535, max(1_500, mtu + 256)))
        while true {
            let count = read(descriptor, &buffer, buffer.count)
            if count > 0 {
                let packet = Data(buffer.prefix(Int(count)))
                guard let first = packet.first, first >> 4 == 4 || first >> 4 == 6 else {
                    diagnosticSink("linux_tun_packet_rejected", ["reason": "invalid_ip_version", "packet_bytes": packet.count])
                    continue
                }
                packetSink(packet)
                continue
            }
            if count == 0 { return }
            if errno == EAGAIN || errno == EWOULDBLOCK { return }
            diagnosticSink("linux_tun_read_failed", ["errno": errno, "ifname": actualInterfaceName])
            return
        }
#endif
    }

#if os(Linux)
    private static func openTun(interfaceName: String) throws -> (Int32, String) {
        let descriptor = "/dev/net/tun".withCString { open($0, O_RDWR | O_NONBLOCK | O_CLOEXEC) }
        guard descriptor >= 0 else { throw ObstacleBridgeLinuxTunDeviceError.openFailed(errno) }
        var request = [UInt8](repeating: 0, count: 40) // Linux `struct ifreq`.
        let name = Array(interfaceName.utf8)
        request.replaceSubrange(0..<name.count, with: name)
        let flags = (iffTun | iffNoPacketInfo).littleEndian
        withUnsafeBytes(of: flags) { request.replaceSubrange(interfaceNameCapacity..<(interfaceNameCapacity + $0.count), with: $0) }
        let result = request.withUnsafeMutableBytes { buffer in
            linuxTunIoctl(descriptor, tunSetIFF, buffer.baseAddress!)
        }
        guard result == 0 else { let code = errno; _ = close(descriptor); throw ObstacleBridgeLinuxTunDeviceError.configureFailed(code) }
        let actual = String(decoding: request.prefix(interfaceNameCapacity).prefix { $0 != 0 }, as: UTF8.self)
        return (descriptor, actual.isEmpty ? interfaceName : actual)
    }
#endif

    private static func isValidInterfaceName(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        return !bytes.isEmpty && bytes.count < interfaceNameCapacity && bytes.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) || $0 == 46 || $0 == 45 || $0 == 95
        }
    }
}
