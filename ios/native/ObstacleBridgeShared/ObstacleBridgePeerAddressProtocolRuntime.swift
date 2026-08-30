import Foundation

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

final class ObstacleBridgePeerAddressProtocolRuntime {
    struct InboundSnapshot {
        var consumed: Bool
        var emittedFrames: [Data]
    }

    private static let magic = Data([0x4f, 0x42, 0x50, 0x41]) // OBPA
    private static let version: UInt8 = 2
    private static let typeRequest: UInt8 = 1
    private static let typeReply: UInt8 = 2
    private static let headerSize = 7

    private let clientMode: Bool
    private(set) var observedPublicIP = ""
    private(set) var observedPublicPort: Int?
    private var requestSent = false

    init(clientMode: Bool) {
        self.clientMode = clientMode
    }

    func handleTransportConnected() -> [Data] {
        guard clientMode, !requestSent else { return [] }
        requestSent = true
        return [Self.header(type: Self.typeRequest, family: 0)]
    }

    func handleTransportDisconnected() {
        requestSent = false
        observedPublicIP = ""
        observedPublicPort = nil
    }

    func handleInboundFrame(
        _ payload: Data,
        observedPeerHost: String? = nil,
        observedPeerPort: Int? = nil
    ) -> InboundSnapshot {
        guard payload.count >= Self.headerSize,
              payload.prefix(4) == Self.magic,
              payload[4] == Self.version
        else {
            return InboundSnapshot(consumed: false, emittedFrames: [])
        }
        let frameType = payload[5]
        let family = payload[6]
        let body = Data(payload.dropFirst(Self.headerSize))
        if frameType == Self.typeRequest, family == 0, body.isEmpty, !clientMode {
            guard let host = observedPeerHost,
                  let port = observedPeerPort,
                  (1...65535).contains(port),
                  let encoded = Self.encodeAddress(host)
            else {
                return InboundSnapshot(consumed: true, emittedFrames: [])
            }
            return InboundSnapshot(
                consumed: true,
                emittedFrames: [Self.header(type: Self.typeReply, family: encoded.family) + encoded.bytes + Self.encodePort(port)]
            )
        }
        if frameType == Self.typeReply, clientMode,
           let decoded = Self.decodeEndpoint(family: family, bytes: body) {
            observedPublicIP = decoded.host
            observedPublicPort = decoded.port
            return InboundSnapshot(consumed: true, emittedFrames: [])
        }
        return InboundSnapshot(consumed: false, emittedFrames: [])
    }

    private static func header(type: UInt8, family: UInt8) -> Data {
        magic + Data([version, type, family])
    }

    private static func encodePort(_ port: Int) -> Data {
        let networkPort = UInt16(port).bigEndian
        return withUnsafeBytes(of: networkPort) { Data($0) }
    }

    private static func encodeAddress(_ rawHost: String) -> (family: UInt8, bytes: Data)? {
        let host = rawHost.split(separator: "%", maxSplits: 1).first.map(String.init) ?? rawHost
        var ipv4 = in_addr()
        if inet_pton(AF_INET, host, &ipv4) == 1 {
            return (4, withUnsafeBytes(of: &ipv4) { Data($0) })
        }
        var ipv6 = in6_addr()
        if inet_pton(AF_INET6, host, &ipv6) == 1 {
            let bytes = withUnsafeBytes(of: &ipv6) { Data($0) }
            // Dual-stack listeners represent IPv4 clients as ::ffff:a.b.c.d.
            // Encode those as IPv4 so the reflected address matches the path.
            if bytes.prefix(10).allSatisfy({ $0 == 0 }), bytes[10] == 0xff, bytes[11] == 0xff {
                return (4, Data(bytes.suffix(4)))
            }
            return (6, bytes)
        }
        return nil
    }

    private static func decodeEndpoint(family: UInt8, bytes: Data) -> (host: String, port: Int)? {
        let addressFamily: Int32
        let expectedSize: Int
        if family == 4 {
            addressFamily = AF_INET
            expectedSize = MemoryLayout<in_addr>.size
        } else if family == 6 {
            addressFamily = AF_INET6
            expectedSize = MemoryLayout<in6_addr>.size
        } else {
            return nil
        }
        guard bytes.count == expectedSize + 2 else { return nil }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let host = Data(bytes.prefix(expectedSize)).withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress,
                  inet_ntop(addressFamily, base, &buffer, socklen_t(buffer.count)) != nil
            else {
                return nil
            }
            return String(cString: buffer)
        }
        guard let host else { return nil }
        let portBytes = bytes.suffix(2)
        let port = portBytes.reduce(UInt16(0)) { ($0 << 8) | UInt16($1) }
        guard port > 0 else { return nil }
        return (host, Int(port))
    }
}
