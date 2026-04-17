from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "ios" / "src"))

from obstacle_bridge.bridge import _encrypt_config_secret
from obstacle_bridge.onboarding import encode_invite_token
from obstacle_bridge_ios.app import ObstacleBridgeIOSApp
from obstacle_bridge_ios.profiles import ProfileStore
from obstacle_bridge_ios.secure_store import InMemorySecretStore


def test_app_import_and_store_profile_keeps_plaintext_secrets_out_of_disk(tmp_path: Path) -> None:
    app = ObstacleBridgeIOSApp()
    app.profile_store = ProfileStore(tmp_path, secret_store=InMemorySecretStore())

    invite_token = encode_invite_token(
        {
            "version": 1,
            "connection": {
                "transport": "tcp",
                "endpoint_host": "bridge.example.net",
                "endpoint_port": 4433,
            },
            "secure_link_mode": "psk",
            "secure_link_psk": _encrypt_config_secret("ios-m1-psk"),
        }
    )

    stored = app.import_and_store_profile(
        invite_token,
        profile_id="ios-m1-site-a",
        display_name="Site A",
    )

    assert stored["profile_id"] == "ios-m1-site-a"
    profile_path = tmp_path / "ios-m1-site-a.json"
    on_disk_text = profile_path.read_text(encoding="utf-8")
    on_disk = json.loads(on_disk_text)

    assert on_disk["obstacle_bridge"]["secure_link_psk"] == ""
    assert on_disk["obstacle_bridge"]["secure_link_psk_present"] is True
    assert "ios-m1-psk" not in on_disk_text


def test_app_preview_import_handles_runtime_config_json() -> None:
    app = ObstacleBridgeIOSApp()

    preview = app.preview_import(
        json.dumps(
            {
                "overlay_transport": "ws",
                "ws_peer": "bridge.example.net",
                "ws_peer_port": 443,
                "secure_link_mode": "psk",
                "admin_web": False,
            }
        )
    )

    assert preview["kind"] == "config"
    assert preview["preview"]["overlay_transport"] == "ws"
