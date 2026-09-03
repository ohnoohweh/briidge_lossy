from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SWIFT_ROOT = ROOT / "ios" / "native"


def _read(*parts: str) -> str:
    return (SWIFT_ROOT.joinpath(*parts)).read_text(encoding="utf-8")


def test_swift_overlay_transport_owners_publish_layered_readiness() -> None:
    owner_paths = [
        ("ObstacleBridgeShared", "ObstacleBridgeUdpOverlayTransportOwner.swift"),
        ("ObstacleBridgeShared", "ObstacleBridgeTcpOverlayTransportOwner.swift"),
        ("ObstacleBridgeShared", "ObstacleBridgeWebSocketOverlayTransportOwner.swift"),
        ("ObstacleBridgeShared", "ObstacleBridgeQuicOverlayTransportOwner.swift"),
    ]
    for path in owner_paths:
        source = _read(*path)
        assert 'func connectionLayersSnapshot() -> [[String: Any]]' in source
        assert 'func appReady() -> Bool' in source
        assert 'func inflowAllowed() -> Bool' in source
        assert '"connection_layers": connectionLayers' in source or 'snapshot["connection_layers"] = connectionLayers' in source
        assert '"app_ready": ObstacleBridgeOverlayLayerTransportAdapter.appReady(from: connectionLayers)' in source or 'snapshot["app_ready"] = ObstacleBridgeOverlayLayerTransportAdapter.appReady(from: connectionLayers)' in source
        assert 'self?.inflowAllowed() ?? false' in source
        assert 'overlayConnected: inflowAllowed()' in source
        assert "connectionRotationDue(candidateCount:" in source
        assert "lifecycle_restart_required" in source
        assert "ObstacleBridgeOverlayLayerTransportAdapter.outerReadinessGrace" in source


def test_swift_layered_readiness_gates_inflow_on_outer_app_ready() -> None:
    adapter = _read("ObstacleBridgeShared", "ObstacleBridgeOverlayLayerTransportAdapter.swift")

    assert "static func appReady(from layers: [[String: Any]]) -> Bool" in adapter
    assert "static func inflowAllowed(from layers: [[String: Any]]) -> Bool" in adapter
    assert 'state = "reauthenticating"' in adapter
    assert 'return (last["app_ready"] as? Bool) ?? false' in adapter
    assert "return appReady(from: layers)" in adapter
    assert "struct ObstacleBridgeConnectionLifecycleEvent" in adapter
    assert "struct ObstacleBridgeConnectionRotationResult" in adapter
    assert "func connectionRotationDue(candidateCount: Int)" in adapter
    assert "static let outerReadinessGrace: TimeInterval = 15.0" in adapter
    assert "connectionRotationDelay: TimeInterval = ObstacleBridgeOverlayLayerTransportAdapter.outerReadinessGrace" in adapter
    assert 'layers[index]["lifecycle_state"] = outerLifecycle.state.rawValue' in adapter
    assert '"layer": "peer_address_protocol"' in adapter
    assert '"app_ready": transportLifecycle.state == .connected' in adapter


def test_swift_authenticated_secure_link_cannot_outlive_observed_transport_disconnect() -> None:
    adapter = _read("ObstacleBridgeShared", "ObstacleBridgeOverlayLayerTransportAdapter.swift")
    python_secure_link = (ROOT / "src" / "obstacle_bridge" / "bridge_securelink.py").read_text(encoding="utf-8")

    # Both runtimes fail closed after a missed normal disconnect callback:
    # Python has a bounded watchdog; Swift clears on its next observation.
    assert "def _inner_transport_ready(self) -> bool:" in python_secure_link
    assert 'phase="transport"' in python_secure_link
    assert "authenticated secure-link transport readiness timed out" in python_secure_link
    assert "enforceAuthenticatedTransportReadiness(transportConnected: transportConnected)" in adapter
    assert "private func enforceAuthenticatedTransportReadiness(transportConnected: Bool)" in adapter
    assert "secureLinkAdapter?.statusSnapshot().authenticated == true" in adapter
    assert "handleTransportDisconnected()" in adapter


def test_swift_channelmux_and_tun_probe_boundaries_reject_pre_connected_traffic() -> None:
    channel_core = _read("ObstacleBridgeShared", "ObstacleBridgeOverlayChannelCore.swift")
    provider = _read("IPServer", "PacketTunnelProvider.swift")

    assert "guard overlayConnected else" in channel_core
    assert 'reason: "overlay_not_connected"' in channel_core
    assert "guard started, tunnelInflowAllowed() else" in provider
    assert "TUN verification waits for the connected overlay state." in provider
    assert "Name resolution waits for the connected overlay state." in provider
    assert "swift_simple_udp_packetflow_dropped_before_overlay_ready" in provider
    assert "func tunConnectivityTestsAllowed() -> Bool" in provider
    assert "static func tunConnectivityTestsAllowed(" in channel_core
    assert "framesAdmittedBeforeSecureLink(" in channel_core
    assert "tunPostMuxTransportDelayThresholdMS: Double = 2_000.0" in channel_core


def test_swift_admin_surfaces_consume_layered_readiness() -> None:
    host_runner = _read("ObstacleBridgeApp", "ObstacleBridgeHostRunner.swift")
    packet_tunnel = _read("IPServer", "PacketTunnelProvider.swift")
    admin_support = _read("ObstacleBridgeShared", "ObstacleBridgeAdminSnapshotSupport.swift")

    assert "func connectionLayersSnapshot() -> [[String: Any]]" in host_runner
    assert "func appReady() -> Bool" in host_runner
    assert 'currentOverlayOwner()?.owner.appReady()' in host_runner
    assert '"connection_layers": connectionLayers' in host_runner
    assert '"observed_public_ip": sharedOverlayLayerTransportAdapter?.observedPublicIPSnapshot() ?? ""' in host_runner
    assert '"observed_public_port": sharedOverlayLayerTransportAdapter?.observedPublicPortSnapshot() ?? NSNull()' in host_runner

    assert "static func connectionLayers(from transportRuntime: [String: Any], preferredKind: String? = nil) -> [[String: Any]]" in admin_support
    assert "static func appReady(from transportRuntime: [String: Any], preferredKind: String? = nil) -> Bool" in admin_support

    assert "let connectionLayers = ObstacleBridgeAdminSnapshotSupport.connectionLayers(" in packet_tunnel
    assert '"connection_layers": connectionLayers' in packet_tunnel
    assert "let layeredReady = ObstacleBridgeAdminSnapshotSupport.appReady(" in packet_tunnel
    assert '"observed_public_ip": sharedOverlayLayerTransportAdapter?.observedPublicIPSnapshot() ?? ""' in packet_tunnel
    assert '"observed_public_port": sharedOverlayLayerTransportAdapter?.observedPublicPortSnapshot() ?? NSNull()' in packet_tunnel
