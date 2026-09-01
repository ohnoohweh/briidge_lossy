from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SWIFT_WS_OWNER = (
    ROOT
    / "ios"
    / "native"
    / "ObstacleBridgeShared"
    / "ObstacleBridgeWebSocketOverlayTransportOwner.swift"
)


def _source() -> str:
    return SWIFT_WS_OWNER.read_text(encoding="utf-8")


def test_swift_ws_owner_rejects_stale_open_callbacks() -> None:
    source = _source()
    assert "guard self.started, self.websocketTask === webSocketTask else { return }" in source


def test_swift_ws_owner_rejects_stale_close_callbacks() -> None:
    source = _source()
    assert "guard self.websocketTask === webSocketTask else { return }" in source


def test_swift_ws_owner_rejects_stale_completion_callbacks() -> None:
    source = _source()
    assert "guard self.websocketTask === task as? URLSessionWebSocketTask else { return }" in source


def test_swift_ws_owner_rejects_stale_receive_callbacks() -> None:
    source = _source()
    assert "guard let self, self.started, self.websocketTask === task else { return }" in source


def test_swift_ws_owner_flushes_only_current_task() -> None:
    source = _source()
    assert "let generation = websocketTransportGeneration" in source
    assert "guard let self, self.websocketTransportGeneration == generation else { return }" in source


def test_swift_ws_owner_uses_literal_endpoint_with_logical_http_and_tls_name() -> None:
    source = _source()
    assert "let usesAddressOverride = !peerAddresses.isEmpty" in source
    assert "peerNameHost: usesAddressOverride ? peerHost : nil" in source
    assert "NWConnection(to: .url(physicalURL), using: parameters)" in source
    assert 'headers.append((name: "Host", value: "\\(logicalHost):\\(peerPort)"))' in source
    assert "peerHost.withCString { serverName in" in source
    assert "sec_protocol_options_set_tls_server_name(tlsOptions.securityProtocolOptions, serverName)" in source


def test_swift_ws_owner_empty_address_list_preserves_dns_resolution() -> None:
    source = _source()
    assert "if !peerAddresses.isEmpty {" in source
    assert "host: peerHost," in source
    assert "strictFamily: false," in source


def test_swift_ws_owner_starts_every_connection_attempt_with_a_fresh_tun_epoch() -> None:
    source = _source()
    connect_overlay = source[source.index("    private func connectOverlay() {") : source.index("    private func connectNetworkWebSocket(")]

    assert "resetOverlayTransportEpoch()" in connect_overlay
    assert connect_overlay.index("resetOverlayTransportEpoch()") < connect_overlay.index(
        "websocketTransportGeneration += 1"
    )
