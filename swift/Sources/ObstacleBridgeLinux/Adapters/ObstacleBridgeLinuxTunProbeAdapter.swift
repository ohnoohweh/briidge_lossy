import Foundation
import ObstacleBridgeCore
#if os(Linux)
import Glibc
#endif

/// POSIX resolver boundary for Core-owned TUN probe selection.  It deliberately
/// has no packet-device descriptor: Linux TUN probing remains fail-closed until
/// the privileged device owner is admitted by LSW-005.
public enum ObstacleBridgeLinuxTunProbeAdapter {
    public static func resolve(target: String, tunnelAddress: String = "", tunnelAddress6: String = "") -> (target: String?, family: Int32, error: String) {
        let families = ObstacleBridgeTunProbeDiagnosticsSupport.sourceProbeFamilies(
            tunnelAddress: tunnelAddress, tunnelAddress6: tunnelAddress6
        )
        return ObstacleBridgeTunProbeDiagnosticsSupport.resolveTunProbeTarget(target, candidateFamilies: families) { host, family in
            resolvePOSIX(host: host, family: family)
        }
    }

    public static func packetDeviceUnavailable() -> Error {
        ObstacleBridgeLinuxRuntimeConfigurationError.unavailableTransport(
            "Linux Swift TUN probing is unavailable until LSW-005 admits a /dev/net/tun packet-device owner"
        )
    }

    private static func resolvePOSIX(host: String, family: Int32) -> String? {
        var hints = addrinfo(ai_flags: AI_ADDRCONFIG, ai_family: family, ai_socktype: 0, ai_protocol: 0, ai_addrlen: 0, ai_addr: nil, ai_canonname: nil, ai_next: nil)
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &result) == 0, let first = result else { return nil }
        defer { freeaddrinfo(first) }
        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let info = cursor {
            var storage = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(info.pointee.ai_addr, info.pointee.ai_addrlen, &storage, socklen_t(storage.count), nil, 0, NI_NUMERICHOST) == 0 {
                return String(cString: storage)
            }
            cursor = info.pointee.ai_next
        }
        return nil
    }
}
