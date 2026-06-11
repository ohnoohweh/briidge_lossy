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
    assert "guard started, overlayConnected, websocketTask === task, !outboundSendInFlight, !pendingOutboundMessages.isEmpty else {" in source
