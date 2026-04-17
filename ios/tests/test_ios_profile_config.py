from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ios" / "src"))

from obstacle_bridge_ios.profiles import ProfileStore
from obstacle_bridge_ios.secure_store import InMemorySecretStore


def test_profile_store_keeps_plaintext_secrets_out_of_profile_files(tmp_path: Path) -> None:
    secret_store = InMemorySecretStore()
    store = ProfileStore(tmp_path, secret_store=secret_store)

    stored = store.save_profile(
        {
            "profile_id": "ios-site-a",
            "display_name": "Site A",
            "obstacle_bridge": {
                "overlay_transport": "tcp",
                "tcp_peer": "bridge.example.net",
                "tcp_peer_port": 4433,
                "secure_link_mode": "psk",
                "secure_link_psk": "super-secret-psk",
                "admin_web_password": "admin-pass",
            },
        }
    )

    profile_path = tmp_path / "ios-site-a.json"
    on_disk = json.loads(profile_path.read_text(encoding="utf-8"))

    assert stored["obstacle_bridge"]["secure_link_psk"] == ""
    assert stored["obstacle_bridge"]["admin_web_password"] == ""
    assert on_disk["obstacle_bridge"]["secure_link_psk"] == ""
    assert on_disk["obstacle_bridge"]["admin_web_password"] == ""
    assert "super-secret-psk" not in profile_path.read_text(encoding="utf-8")
    assert "admin-pass" not in profile_path.read_text(encoding="utf-8")
    assert secret_store.get_secret("ios-site-a", "secure_link_psk") == "super-secret-psk"
    assert secret_store.get_secret("ios-site-a", "admin_web_password") == "admin-pass"

    loaded = store.load_profile("ios-site-a", include_secrets=True)
    assert loaded["obstacle_bridge"]["secure_link_psk"] == "super-secret-psk"
    assert loaded["obstacle_bridge"]["admin_web_password"] == "admin-pass"
