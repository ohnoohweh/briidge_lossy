import Foundation

/// Native device owner for the Swift TUN helper server. This is intentionally
/// narrower than the Python `linux-native` backend: it owns `/dev/net/tun`
/// and packet I/O now, but fails closed for network policy until the complete
/// route/DNS/firewall/hook lifecycle can be implemented equivalently.
public final class ObstacleBridgeLinuxNativeTunHelperBackend: ObstacleBridgeLinuxTunHelperServerBackend, @unchecked Sendable {
    public typealias PacketSink = (Data) -> Void
    private let lock = NSLock()
    private var packetSink: PacketSink
    private var device: ObstacleBridgeLinuxTunDevice?
    private var packetsFromRuntime = 0
    private var packetsToRuntime = 0
    private var lastFailure: [String: Any] = [:]
    private var tunEnabled = true

    public init(packetSink: @escaping PacketSink = { _ in }) { self.packetSink = packetSink }

    public func setPacketSink(_ sink: @escaping PacketSink) { lock.lock(); packetSink = sink; lock.unlock() }

    public func openTun(_ payload: [String: Any]) throws -> [String: Any] {
        guard let requested = payload["ifname"] as? String, !requested.isEmpty else {
            throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("OPEN_TUN requires ifname")
        }
        let mtu = (payload["mtu"] as? Int) ?? 1_500
        lock.lock()
        if let device { let reply = snapshotLocked(device: device); lock.unlock(); return reply }
        lock.unlock()
        let device = try ObstacleBridgeLinuxTunDevice(interfaceName: requested, mtu: mtu, packetSink: { [weak self] packet in
            self?.lock.lock(); self?.packetsToRuntime += 1; self?.lock.unlock()
            self?.lock.lock(); let sink = self?.packetSink; self?.lock.unlock()
            sink?(packet)
        })
        try device.start()
        lock.lock(); self.device = device; let reply = snapshotLocked(device: device); lock.unlock()
        return reply
    }

    public func applyNetwork(_ payload: [String: Any]) throws -> [String: Any] {
        throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("Swift native helper network policy is not implemented; refusing route, DNS, firewall, and hook mutation")
    }

    public func removeNetwork(_ payload: [String: Any]) throws -> [String: Any] {
        throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("Swift native helper network policy is not implemented; refusing route, DNS, firewall, and hook mutation")
    }

    public func setTunEnabled(_ payload: [String: Any]) throws -> [String: Any] {
        let value = payload["enabled"]
        let enabled: Bool
        if let boolean = value as? Bool { enabled = boolean }
        else if let number = value as? NSNumber { enabled = number.boolValue }
        else if let text = value as? String {
            switch text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
            case "1", "true", "yes", "on": enabled = true
            case "0", "false", "no", "off": enabled = false
            default: throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("SET_TUN_ENABLED requires a boolean enabled value")
            }
        } else { throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("SET_TUN_ENABLED requires a boolean enabled value") }
        lock.lock(); tunEnabled = enabled; let snapshot = self.device.map(snapshotLocked) ?? closedSnapshotLocked(); lock.unlock()
        return snapshot.merging(["tun_enabled": enabled]) { _, new in new }
    }

    public func writePacket(_ packet: Data) throws {
        lock.lock(); let device = self.device; lock.unlock()
        guard let device else { throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("TUN device is not open") }
        try device.writePacket(packet)
        lock.lock(); packetsFromRuntime += 1; lock.unlock()
    }

    public func snapshot() throws -> [String: Any] {
        lock.lock(); defer { lock.unlock() }
        guard let device else {
            return closedSnapshotLocked()
        }
        return snapshotLocked(device: device)
    }

    public func stop() {
        lock.lock(); let device = self.device; self.device = nil; lock.unlock()
        device?.stop()
    }

    public func recordFailure(stage: String, error: String) {
        lock.lock(); lastFailure = ["stage": stage, "error": error]; lock.unlock()
    }

    private func snapshotLocked(device: ObstacleBridgeLinuxTunDevice) -> [String: Any] {
        ["backend": "linux-swift-native", "opened": true, "ifname": device.actualInterfaceName, "mtu": device.mtu, "packets_from_runtime": packetsFromRuntime, "packets_to_runtime": packetsToRuntime, "last_failure": lastFailure, "tun_enabled": tunEnabled]
    }
    private func closedSnapshotLocked() -> [String: Any] { ["backend": "linux-swift-native", "opened": false, "packets_from_runtime": packetsFromRuntime, "packets_to_runtime": packetsToRuntime, "last_failure": lastFailure, "tun_enabled": tunEnabled] }
}
