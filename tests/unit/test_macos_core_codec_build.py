"""Guards the macOS flat build's first Core codec migration."""

from pathlib import Path


def test_macos_build_uses_core_websocket_payload_codec_once() -> None:
    script = (Path(__file__).resolve().parents[2] / "ios/scripts/build_macos_app.sh").read_text(encoding="utf-8")
    assert 'swift/Sources/ObstacleBridgeCore/ObstacleBridgeWebSocketPayloadCodec.swift' in script
    assert 'ios/native/ObstacleBridgeShared/ObstacleBridgeWebSocketPayloadCodec.swift' not in script
