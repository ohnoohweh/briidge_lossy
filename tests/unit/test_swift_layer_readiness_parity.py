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
        assert '"connection_layers": connectionLayers' in source or 'snapshot["connection_layers"] = connectionLayers' in source
        assert '"app_ready": ObstacleBridgeOverlayLayerTransportAdapter.appReady(from: connectionLayers)' in source or 'snapshot["app_ready"] = ObstacleBridgeOverlayLayerTransportAdapter.appReady(from: connectionLayers)' in source
        assert 'self?.appReady() ?? false' in source


def test_swift_admin_surfaces_consume_layered_readiness() -> None:
    host_runner = _read("ObstacleBridgeApp", "ObstacleBridgeHostRunner.swift")
    packet_tunnel = _read("IPServer", "PacketTunnelProvider.swift")
    admin_support = _read("ObstacleBridgeShared", "ObstacleBridgeAdminSnapshotSupport.swift")

    assert "func connectionLayersSnapshot() -> [[String: Any]]" in host_runner
    assert "func appReady() -> Bool" in host_runner
    assert 'currentOverlayOwner()?.owner.appReady()' in host_runner
    assert '"connection_layers": connectionLayers' in host_runner

    assert "static func connectionLayers(from transportRuntime: [String: Any], preferredKind: String? = nil) -> [[String: Any]]" in admin_support
    assert "static func appReady(from transportRuntime: [String: Any], preferredKind: String? = nil) -> Bool" in admin_support

    assert '"connection_layers": ObstacleBridgeAdminSnapshotSupport.connectionLayers(' in packet_tunnel
    assert "let layeredReady = ObstacleBridgeAdminSnapshotSupport.appReady(" in packet_tunnel
