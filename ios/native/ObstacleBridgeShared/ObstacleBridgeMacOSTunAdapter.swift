import Foundation
#if canImport(Darwin)
import Darwin
#endif

enum ObstacleBridgeMacOSTunAdapterError: Error, LocalizedError {
    case unsupportedPlatform
    case controlLookupFailed
    case connectFailed(Int32)
    case invalidPacketVersion(Int)
    case writeFailed(Int32)

    var errorDescription: String? {
        switch self {
        case .unsupportedPlatform:
            return "macOS utun adapter is supported only on macOS"
        case .controlLookupFailed:
            return "Unable to resolve com.apple.net.utun_control"
        case .connectFailed(let code):
            return "Unable to connect utun control socket errno=\(code)"
        case .invalidPacketVersion(let version):
            return "Unsupported IP version for utun packet: \(version)"
        case .writeFailed(let code):
            return "utun write failed errno=\(code)"
        }
    }
}

final class ObstacleBridgeMacOSTunAdapter {
#if os(macOS)
    private struct CtlInfo {
        var ctlID: UInt32 = 0
        var ctlName: (Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                      Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                      Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                      Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                      Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                      Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                      Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                      Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                      Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                      Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                      Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                      Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8) = (
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        )
    }

    private struct SockaddrCtl {
        var scLen: UInt8 = 0
        var scFamily: UInt8 = 0
        var ssSysaddr: UInt16 = 0
        var scID: UInt32 = 0
        var scUnit: UInt32 = 0
        var scReserved: (UInt32, UInt32, UInt32, UInt32, UInt32) = (0, 0, 0, 0, 0)
    }

    private static let ctlIOCGInfo: UInt = 0xC0644E03
    private static let afSysControl: UInt16 = 2
    private static let utunOptIfname: Int32 = 2
    private static let utunControlName = "com.apple.net.utun_control"
#endif

    let requestedIfname: String
    let mtu: Int
    private(set) var actualIfname: String
    private let queue: DispatchQueue
    private let packetSink: (Data) -> Void
    private let eventSink: ((String, [String: Any]) -> Void)?

    private var fd: Int32 = -1
    private var readSource: DispatchSourceRead?
    private var started = false

    init(
        ifname: String,
        mtu: Int,
        queue: DispatchQueue,
        packetSink: @escaping (Data) -> Void,
        eventSink: ((String, [String: Any]) -> Void)? = nil
    ) {
        self.requestedIfname = ifname
        self.actualIfname = ifname
        self.mtu = max(68, mtu)
        self.queue = queue
        self.packetSink = packetSink
        self.eventSink = eventSink
    }

    func start() throws {
#if os(macOS)
        guard !started else { return }
        let socketFD = Darwin.socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)
        guard socketFD >= 0 else {
            throw ObstacleBridgeMacOSTunAdapterError.controlLookupFailed
        }
        do {
            let controlID = try Self.lookupControlID(fd: socketFD)
            try Self.connectUTUN(fd: socketFD, controlID: controlID)
            actualIfname = Self.queryIfname(fd: socketFD, fallback: requestedIfname)
            _ = Darwin.fcntl(socketFD, F_SETFL, O_NONBLOCK)
            try Self.configureInterface(ifname: actualIfname, mtu: mtu)
            fd = socketFD
            let source = DispatchSource.makeReadSource(fileDescriptor: socketFD, queue: queue)
            source.setEventHandler { [weak self] in
                self?.drainReadable()
            }
            source.setCancelHandler { [weak self] in
                guard let self else { return }
                if self.fd >= 0 {
                    Darwin.close(self.fd)
                    self.fd = -1
                }
            }
            readSource = source
            started = true
            source.resume()
            eventSink?("macos_utun_started", [
                "requested_ifname": requestedIfname,
                "actual_ifname": actualIfname,
                "mtu": mtu,
            ])
        } catch {
            Darwin.close(socketFD)
            throw error
        }
#else
        throw ObstacleBridgeMacOSTunAdapterError.unsupportedPlatform
#endif
    }

    func stop() {
        guard started else { return }
        started = false
        readSource?.cancel()
        readSource = nil
        eventSink?("macos_utun_stopped", [
            "actual_ifname": actualIfname,
        ])
    }

    func write(packet: Data) throws {
#if os(macOS)
        guard started, fd >= 0 else { return }
        let frame = try Self.utunFrame(for: packet)
        let written = frame.withUnsafeBytes { rawBuffer -> Int in
            guard let base = rawBuffer.baseAddress else { return -1 }
            return Darwin.write(fd, base, rawBuffer.count)
        }
        guard written == frame.count else {
            throw ObstacleBridgeMacOSTunAdapterError.writeFailed(errno)
        }
#else
        _ = packet
        throw ObstacleBridgeMacOSTunAdapterError.unsupportedPlatform
#endif
    }

    private func drainReadable() {
#if os(macOS)
        guard started, fd >= 0 else { return }
        let readSize = max(72, min(65535, mtu + 4))
        var buffer = [UInt8](repeating: 0, count: readSize)
        while true {
            let count = Darwin.read(fd, &buffer, buffer.count)
            if count > 0 {
                let frame = Data(buffer[0..<count])
                if let packet = Self.packet(fromUTUNFrame: frame), !packet.isEmpty {
                    packetSink(packet)
                }
                continue
            }
            if count == 0 { return }
            if errno == EAGAIN || errno == EWOULDBLOCK { return }
            eventSink?("macos_utun_read_failed", [
                "actual_ifname": actualIfname,
                "errno": errno,
            ])
            return
        }
#endif
    }

    static func packet(fromUTUNFrame frame: Data) -> Data? {
        guard frame.count >= 4 else { return nil }
        return frame.dropFirst(4)
    }

    static func utunFrame(for packet: Data) throws -> Data {
        guard let first = packet.first else {
            throw ObstacleBridgeMacOSTunAdapterError.invalidPacketVersion(-1)
        }
        let version = Int(first >> 4)
        let family: UInt32
        switch version {
        case 4:
            family = UInt32(AF_INET)
        case 6:
            family = UInt32(AF_INET6)
        default:
            throw ObstacleBridgeMacOSTunAdapterError.invalidPacketVersion(version)
        }
        var header = family.bigEndian
        var data = Data(bytes: &header, count: MemoryLayout<UInt32>.size)
        data.append(packet)
        return data
    }

#if os(macOS)
    private static func lookupControlID(fd: Int32) throws -> UInt32 {
        var info = CtlInfo()
        Self.utunControlName.withCString { namePtr in
            withUnsafeMutablePointer(to: &info.ctlName) { tuplePtr in
                tuplePtr.withMemoryRebound(to: Int8.self, capacity: 96) { destPtr in
                    memset(destPtr, 0, 96)
                    strncpy(destPtr, namePtr, 95)
                }
            }
        }
        let result = Darwin.ioctl(fd, Self.ctlIOCGInfo, &info)
        guard result == 0, info.ctlID != 0 else {
            throw ObstacleBridgeMacOSTunAdapterError.controlLookupFailed
        }
        return info.ctlID
    }

    private static func connectUTUN(fd: Int32, controlID: UInt32) throws {
        var addr = SockaddrCtl()
        addr.scLen = UInt8(MemoryLayout<SockaddrCtl>.stride)
        addr.scFamily = UInt8(AF_SYSTEM)
        addr.ssSysaddr = Self.afSysControl
        addr.scID = controlID
        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<SockaddrCtl>.stride))
            }
        }
        guard result == 0 else {
            throw ObstacleBridgeMacOSTunAdapterError.connectFailed(errno)
        }
    }

    private static func queryIfname(fd: Int32, fallback: String) -> String {
        var buffer = [CChar](repeating: 0, count: 64)
        var length = socklen_t(buffer.count)
        let status = Darwin.getsockopt(fd, SYSPROTO_CONTROL, Self.utunOptIfname, &buffer, &length)
        guard status == 0, let name = String(validatingUTF8: buffer), !name.isEmpty else {
            return fallback
        }
        return name
    }

    private static func configureInterface(ifname: String, mtu: Int) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/sbin/ifconfig")
        process.arguments = [ifname, "mtu", String(mtu), "up"]
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw NSError(domain: "ObstacleBridgeMacOSTunAdapter", code: Int(process.terminationStatus))
        }
    }
#endif
}
