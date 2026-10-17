import Foundation
import ObstacleBridgeCore
#if os(Linux)
import Glibc
#endif

/// Explicit Linux disposition for a Core packet-tunnel plan. This adapter is
/// intentionally not a privileged packet-device or route/DNS owner.
public enum ObstacleBridgeLinuxPacketTunnelPlanDisposition: Equatable, Sendable {
    case retainedDisabled(ObstacleBridgeRuntimeConfigPort.PacketTunnelPlan)
    case unavailableEnabled(String)
}

/// POSIX resolver boundary for Core-owned TUN probe selection.  It deliberately
/// has no packet-device descriptor: Linux TUN probing remains fail-closed until
/// the privileged device owner is admitted by LSW-005.
public enum ObstacleBridgeLinuxTunProbeAdapter {
    public static func packetTunnelPlanDisposition(
        _ plan: ObstacleBridgeRuntimeConfigPort.PacketTunnelPlan
    ) -> ObstacleBridgeLinuxPacketTunnelPlanDisposition {
        guard plan.enabledOnStartup else { return .retainedDisabled(plan) }
        return .unavailableEnabled(
            "Linux Swift packet-tunnel execution is unavailable until LSW-005 admits a /dev/net/tun owner and LSW-006 qualifies route and DNS execution"
        )
    }

    /// Creates the Core-owned probe state used by a future admitted packet-device
    /// reader.  The adapter supplies POSIX inputs; it never owns matching or
    /// diagnostic counters.
    public static func makeRuntime(identifier: UInt16 = 1, historyRetentionSeconds: TimeInterval = 60) -> ObstacleBridgeTunProbeRuntime {
        ObstacleBridgeTunProbeRuntime(identifier: identifier, historyRetentionSeconds: historyRetentionSeconds)
    }

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

    public static func packetInjected(_ launch: ObstacleBridgeTunProbeRuntime.Launch, runtime: ObstacleBridgeTunProbeRuntime) {
        runtime.packetInjected(launch.token)
    }

    public static func receivedPacket(_ packet: Data, at monotonicNS: UInt64, runtime: ObstacleBridgeTunProbeRuntime) -> ObstacleBridgeTunProbeRuntime.Observation {
        runtime.receive(packet, receivedMonotonicNS: monotonicNS)
    }

    public static func timeout(_ launch: ObstacleBridgeTunProbeRuntime.Launch, at monotonicNS: UInt64, runtime: ObstacleBridgeTunProbeRuntime) -> [String: Any]? {
        runtime.timeout(launch.token, at: monotonicNS)
    }

    public static func packetDeviceFailed(_ launch: ObstacleBridgeTunProbeRuntime.Launch, detail: String, at monotonicNS: UInt64, runtime: ObstacleBridgeTunProbeRuntime) -> [String: Any]? {
        runtime.packetDeviceFailed(launch.token, detail: detail, at: monotonicNS)
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
                return String(
                    decoding: storage.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) },
                    as: UTF8.self
                )
            }
            cursor = info.pointee.ai_next
        }
        return nil
    }
}
