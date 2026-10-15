import Testing
@testable import ObstacleBridgeLinuxAdapters
@testable import ObstacleBridgeCore

struct ObstacleBridgeLinuxTunProbeAdapterTests {
    @Test func resolvesLiteralIPv4AndIPv6ThroughCoreFamilySelection() {
        let ipv4 = ObstacleBridgeLinuxTunProbeAdapter.resolve(target: "198.51.100.7", tunnelAddress: "198.18.0.1")
        #expect(ipv4.target == "198.51.100.7")
        #expect(ipv4.family == ObstacleBridgeTunProbeDiagnosticsSupport.ipv4Family)
        let ipv6 = ObstacleBridgeLinuxTunProbeAdapter.resolve(target: "2001:db8::7", tunnelAddress6: "fd00::1")
        #expect(ipv6.target == "2001:db8::7")
        #expect(ipv6.family == ObstacleBridgeTunProbeDiagnosticsSupport.ipv6Family)
    }

    @Test func packetDeviceRemainsFailClosed() {
        #expect(String(describing: ObstacleBridgeLinuxTunProbeAdapter.packetDeviceUnavailable()).contains("/dev/net/tun"))
    }
}
