from __future__ import annotations

import json
import sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "ios" / "src"))

from obstacle_bridge.onboarding import encode_invite_token
from obstacle_bridge_ios.onboarding import preview_import_text


def test_preview_invite_token_masks_psk_and_returns_updates() -> None:
    token = encode_invite_token(
        {
            "version": 1,
            "admin_web_name": "Imported Node",
            "connection": {
                "transport": "tcp",
                "endpoint_host": "bridge.example.net",
                "endpoint_port": 4433,
            },
            "secure_link_mode": "psk",
            "secure_link_psk": "ios-secret-123",
            "compress_layer": True,
            "compress_layer_algo": "zlib",
            "compress_layer_level": 5,
            "compress_layer_min_bytes": 96,
            "compress_layer_types": "data,data_ack",
            "TUN_routing": {"dns_servers": ["9.9.9.9"], "included_routes": ["0.0.0.0/0"]},
        }
    )

    doc = preview_import_text(token)

    assert doc["kind"] == "invite"
    assert doc["preview"]["secure_link_psk"] == "***hidden***"
    assert doc["preview"]["secure_link_psk_present"] is True
    assert doc["suggested_updates"]["overlay_transport"] == "tcp"
    assert doc["suggested_updates"]["tcp_peer"] == "bridge.example.net"
    assert doc["suggested_updates"]["tcp_peer_port"] == 4433
    assert doc["suggested_updates"]["secure_link_psk"] == "ios-secret-123"
    assert doc["suggested_updates"]["admin_web_name"] == "Imported Node"
    assert doc["suggested_updates"]["compress_layer"] is True
    assert doc["suggested_updates"]["compress_layer_level"] == 5
    assert doc["suggested_updates"]["compress_layer_types"] == "data,data_ack"
    assert doc["suggested_updates"]["TUN_routing"]["dns_servers"] == ["9.9.9.9"]


def test_preview_json_config_snippet_uses_runtime_validation() -> None:
    snippet = json.dumps(
        {
            "overlay_transport": "ws",
            "ws_peer": "bridge.example.net",
            "ws_peer_port": 443,
            "secure_link_mode": "psk",
            "admin_web": False,
        }
    )

    doc = preview_import_text(snippet)

    assert doc["kind"] == "config"
    assert doc["preview"]["overlay_transport"] == "ws"
    assert doc["preview"]["secure_link_mode"] == "psk"
    assert doc["preview"]["admin_web"] is False
    assert doc["suggested_updates"]["ws_peer"] == "bridge.example.net"


def test_preview_invite_token_rejects_legacy_encrypted_psk_from_other_host() -> None:
    token = encode_invite_token(
        {
            "version": 1,
            "connection": {
                "transport": "tcp",
                "endpoint_host": "bridge.example.net",
                "endpoint_port": 4433,
            },
            "secure_link_mode": "psk",
            "secure_link_psk": "enc:v1:not-portable-across-hosts",
        }
    )

    with pytest.raises(ValueError, match="legacy encrypted secure_link_psk"):
        preview_import_text(token)
