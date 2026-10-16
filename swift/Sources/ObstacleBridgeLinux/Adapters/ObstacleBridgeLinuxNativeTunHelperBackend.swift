import Foundation

/// Native device owner for the Swift TUN helper server. This is intentionally
/// narrower than the Python `linux-native` backend: it owns `/dev/net/tun`
/// and packet I/O now, but fails closed for network policy until the complete
/// route/DNS/firewall/hook lifecycle can be implemented equivalently.
public final class ObstacleBridgeLinuxNativeTunHelperBackend: ObstacleBridgeLinuxTunHelperServerBackend, @unchecked Sendable {
    public typealias PacketSink = (Data) -> Void
    private let lock = NSLock()
    private let packetSink: PacketSink
    private var device: ObstacleBridgeLinuxTunDevice?
    private var packetsFromRuntime = 0
    private var packetsToRuntime = 0

    public init(packetSink: @escaping PacketSink = { _ in }) { self.packetSink = packetSink }

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
            self?.packetSink(packet)
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
        throw ObstacleBridgeLinuxTunHelperAdapterError.unavailable("Swift native helper suspend/resume is not implemented")
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
            return ["backend": "linux-swift-native", "opened": false, "packets_from_runtime": packetsFromRuntime, "packets_to_runtime": packetsToRuntime]
        }
        return snapshotLocked(device: device)
    }

    public func stop() {
        lock.lock(); let device = self.device; self.device = nil; lock.unlock()
        device?.stop()
    }

    private func snapshotLocked(device: ObstacleBridgeLinuxTunDevice) -> [String: Any] {
        ["backend": "linux-swift-native", "opened": true, "ifname": device.actualInterfaceName, "mtu": device.mtu, "packets_from_runtime": packetsFromRuntime, "packets_to_runtime": packetsToRuntime]
    }
}
