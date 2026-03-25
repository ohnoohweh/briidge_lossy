import argparse
import json

from obstacle_bridge.bridge import Runner


def _make_runner(tmp_path):
    runner = Runner.__new__(Runner)
    runner.args = argparse.Namespace(
        config=str(tmp_path / "ObstacleBridge.cfg"),
        admin_web_port=18080,
        admin_web_bind="127.0.0.1",
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
