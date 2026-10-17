import Foundation
import Testing
@testable import ObstacleBridgeLinuxAdapters
@testable import ObstacleBridgeCore

struct ObstacleBridgeLinuxTunProbeAdapterTests {
    @Test func packetTunnelPlansRemainDisabledWithoutPrivilegedOwner() throws {
        let disabled = try #require(ObstacleBridgeRuntimeConfigPort.packetTunnelPlan(from: [
            "TUN_routing": ["enabled_on_startup": false],
        ]))
        #expect(ObstacleBridgeLinuxTunProbeAdapter.packetTunnelPlanDisposition(disabled) == .retainedDisabled(disabled))

        let enabled = try #require(ObstacleBridgeRuntimeConfigPort.packetTunnelPlan(from: [
            "TUN_routing": ["enabled_on_startup": true],
        ]))
        guard case .unavailableEnabled(let reason) = ObstacleBridgeLinuxTunProbeAdapter.packetTunnelPlanDisposition(enabled) else {
            Issue.record("enabled packet-tunnel plan must fail closed")
            return
        }
        #expect(reason.contains("/dev/net/tun"))
    }

    @Test func resolvesLiteralIPv4AndIPv6ThroughCoreFamilySelection() {
        let ipv4 = ObstacleBridgeLinuxTunProbeAdapter.resolve(target: "198.51.100.7", tunnelAddress: "198.18.0.1")
        #expect(ipv4.target == "198.51.100.7")
        #expect(ipv4.family == ObstacleBridgeTunProbeDiagnosticsSupport.ipv4Family)
        let ipv6 = ObstacleBridgeLinuxTunProbeAdapter.resolve(target: "2001:db8::7", tunnelAddress6: "fd00::1")
        #expect(ipv6.target == "2001:db8::7")
        #expect(ipv6.family == ObstacleBridgeTunProbeDiagnosticsSupport.ipv6Family)
    }

    @Test func resolvesDNSAndReportsResolverFailureThroughPOSIX() {
        let localhost = ObstacleBridgeLinuxTunProbeAdapter.resolve(target: "localhost", tunnelAddress: "127.0.0.1")
        #expect(localhost.target == "127.0.0.1")
        #expect(localhost.family == ObstacleBridgeTunProbeDiagnosticsSupport.ipv4Family)
        let localhostV6 = ObstacleBridgeLinuxTunProbeAdapter.resolve(target: "localhost", tunnelAddress6: "fd00::1")
        #expect(localhostV6.target == "::1")
        #expect(localhostV6.family == ObstacleBridgeTunProbeDiagnosticsSupport.ipv6Family)
        let failed = ObstacleBridgeLinuxTunProbeAdapter.resolve(target: "not-a-host.invalid", tunnelAddress: "127.0.0.1")
        #expect(failed.target == nil)
        #expect(failed.error.contains("unable to resolve"))
    }

    @Test func forwardsMatchedAndUnmatchedRepliesToCoreRuntime() throws {
        let runtime = ObstacleBridgeLinuxTunProbeAdapter.makeRuntime(identifier: 77)
        let launch = try #require(runtime.begin(
            probeKind: "peer", target: "198.51.100.7", resolvedTarget: "198.51.100.7",
            family: ObstacleBridgeTunProbeDiagnosticsSupport.ipv4Family, sourceIP: "198.18.0.1",
            ifname: "obtun0", sentMonotonicNS: 1_000_000, nonce: Data(repeating: 9, count: 8)
        ))
        ObstacleBridgeLinuxTunProbeAdapter.packetInjected(launch, runtime: runtime)
        #expect(!ObstacleBridgeLinuxTunProbeAdapter.receivedPacket(Data([0]), at: 2_000_000, runtime: runtime).matched)
        var reply = launch.packet
        reply[20] = 0
        let source = reply.subdata(in: 12..<16)
        reply.replaceSubrange(12..<16, with: reply.subdata(in: 16..<20))
        reply.replaceSubrange(16..<20, with: source)
        let observation = ObstacleBridgeLinuxTunProbeAdapter.receivedPacket(reply, at: 4_000_000, runtime: runtime)
        #expect(observation.matched)
        #expect(observation.result?["ok"] as? Bool == true)
        #expect(runtime.counterSnapshot()["probe_reply_matched"] == 1)
        let later = try #require(runtime.begin(
            probeKind: "peer", target: "198.51.100.7", resolvedTarget: "198.51.100.7",
            family: ObstacleBridgeTunProbeDiagnosticsSupport.ipv4Family, sourceIP: "198.18.0.1",
            ifname: "obtun0", sentMonotonicNS: 5_000_000, nonce: Data(repeating: 6, count: 8)
        ))
        let timeout = try #require(ObstacleBridgeLinuxTunProbeAdapter.timeout(later, at: 64_000_000, runtime: runtime))
        #expect(timeout["last_success_rtt_ms"] as? Double == 3)
        #expect(timeout["last_success_ago_s"] as? Double == 0.06)
    }

    @Test func forwardsTimeoutAndPacketDeviceFailureToCoreRuntime() throws {
        let runtime = ObstacleBridgeLinuxTunProbeAdapter.makeRuntime(identifier: 78)
        let timeoutLaunch = try #require(runtime.begin(
            probeKind: "peer", target: "198.51.100.8", resolvedTarget: "198.51.100.8",
            family: ObstacleBridgeTunProbeDiagnosticsSupport.ipv4Family, sourceIP: "198.18.0.1",
            ifname: "obtun0", sentMonotonicNS: 1_000_000, nonce: Data(repeating: 8, count: 8)
        ))
        let timeout = try #require(ObstacleBridgeLinuxTunProbeAdapter.timeout(timeoutLaunch, at: 2_000_000, runtime: runtime))
        #expect(timeout["state"] as? String == "failed")
        let failureLaunch = try #require(runtime.begin(
            probeKind: "peer", target: "198.51.100.9", resolvedTarget: "198.51.100.9",
            family: ObstacleBridgeTunProbeDiagnosticsSupport.ipv4Family, sourceIP: "198.18.0.1",
            ifname: "obtun0", sentMonotonicNS: 3_000_000, nonce: Data(repeating: 7, count: 8)
        ))
        let failure = try #require(ObstacleBridgeLinuxTunProbeAdapter.packetDeviceFailed(failureLaunch, detail: "packet device write failed", at: 4_000_000, runtime: runtime))
        #expect(failure["detail"] as? String == "packet device write failed")
        #expect(runtime.counterSnapshot()["probe_timeout"] == 1)
        #expect(runtime.counterSnapshot()["probe_exception"] == 1)
    }

    @Test func expiresCachedSuccessHistoryAtCoreRetentionBoundary() throws {
        let runtime = ObstacleBridgeLinuxTunProbeAdapter.makeRuntime(identifier: 79, historyRetentionSeconds: 0.01)
        let launch = try #require(runtime.begin(
            probeKind: "peer", target: "198.51.100.10", resolvedTarget: "198.51.100.10",
            family: ObstacleBridgeTunProbeDiagnosticsSupport.ipv4Family, sourceIP: "198.18.0.1",
            ifname: "obtun0", sentMonotonicNS: 1_000_000, nonce: Data(repeating: 5, count: 8)
        ))
        var reply = launch.packet
        reply[20] = 0
        let source = reply.subdata(in: 12..<16)
        reply.replaceSubrange(12..<16, with: reply.subdata(in: 16..<20))
        reply.replaceSubrange(16..<20, with: source)
        #expect(ObstacleBridgeLinuxTunProbeAdapter.receivedPacket(reply, at: 4_000_000, runtime: runtime).matched)
        let later = try #require(runtime.begin(
            probeKind: "peer", target: "198.51.100.10", resolvedTarget: "198.51.100.10",
            family: ObstacleBridgeTunProbeDiagnosticsSupport.ipv4Family, sourceIP: "198.18.0.1",
            ifname: "obtun0", sentMonotonicNS: 5_000_000, nonce: Data(repeating: 4, count: 8)
        ))
        let timeout = try #require(ObstacleBridgeLinuxTunProbeAdapter.timeout(later, at: 20_000_000, runtime: runtime))
        #expect(timeout["last_success_ago_s"] is NSNull)
        #expect(timeout["last_success_rtt_ms"] is NSNull)
    }

    @Test func packetDeviceRemainsFailClosed() {
        #expect(String(describing: ObstacleBridgeLinuxTunProbeAdapter.packetDeviceUnavailable()).contains("/dev/net/tun"))
    }
}
