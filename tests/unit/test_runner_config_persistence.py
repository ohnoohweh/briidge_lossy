import argparse
import json

import obstacle_bridge.bridge as bridge
from obstacle_bridge.bridge import ConfigAwareCLI, Runner


def _make_runner(tmp_path):
    runner = Runner.__new__(Runner)
    runner.args = argparse.Namespace(
        config=str(tmp_path / "ObstacleBridge.cfg"),
        admin_web_port=18080,
        admin_web_bind="127.0.0.1",
        admin_web_password="admin-secret",
        secure_link_psk="bridge-secret",
        overlay_transport="myudp",
        _config_sections={"admin_web": ["admin_web_bind", "admin_web_port"]},
    )
    return runner


def test_update_config_persists_to_config_file(tmp_path):
    runner = _make_runner(tmp_path)

    ok, err = runner.update_config({"admin_web_port": 18081})

    assert ok is True
    assert err == ""

    written = json.loads((tmp_path / "ObstacleBridge.cfg").read_text(encoding="utf-8"))
    assert written["admin_web"]["admin_web_port"] == 18081
    assert written["admin_web"]["admin_web_bind"] == "127.0.0.1"
    assert written["misc"]["overlay_transport"] == "myudp"


def test_runtime_config_encrypts_secret_fields_and_loads_them_back(tmp_path, monkeypatch):
    monkeypatch.setattr(bridge.socket, "gethostname", lambda: "unit-test-host")
    runner = _make_runner(tmp_path)
    runner.args._config_sections = {
        "admin_web": ["admin_web_bind", "admin_web_password", "admin_web_port"],
        "secure_link": ["secure_link_psk"],
    }

    ok, err = runner.save_runtime_config()

    assert ok is True
    assert err == ""

    written = json.loads((tmp_path / "ObstacleBridge.cfg").read_text(encoding="utf-8"))
    assert written["admin_web"]["admin_web_password"].startswith("enc:v1:")
    assert written["secure_link"]["secure_link_psk"].startswith("enc:v1:")
    assert written["admin_web"]["admin_web_password"] != "admin-secret"
    assert written["secure_link"]["secure_link_psk"] != "bridge-secret"

    cli = ConfigAwareCLI(description="test")
    loaded = cli._load_json_config(str(tmp_path / "ObstacleBridge.cfg"))

    assert loaded["admin_web"]["admin_web_password"] == "admin-secret"
    assert loaded["secure_link"]["secure_link_psk"] == "bridge-secret"
