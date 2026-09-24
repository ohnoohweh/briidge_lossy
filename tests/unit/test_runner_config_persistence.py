import argparse
import json

import obstacle_bridge.bridge as bridge
import obstacle_bridge.bridge_runner as bridge_runner
from obstacle_bridge.bridge import ConfigAwareCLI, Runner


def _make_runner(tmp_path):
    runner = Runner.__new__(Runner)
    runner.args = argparse.Namespace(
        config=str(tmp_path / "ObstacleBridge.cfg"),
        admin_web_port=18080,
        admin_web_bind="127.0.0.1",
        admin_web_password="admin-secret",
        secure_link_psk="bridge-secret",
        telemetry_enabled=True,
        telemetry_endpoint="https://collector.example.test/v1/telemetry",
        telemetry_installation_id="installation-test-id",
        telemetry_mtls_identity_label="telemetry-client-identity",
        telemetry_spool_directory=str(tmp_path / "telemetry-spool"),
        overlay_transport="myudp",
        _config_sections={
            "admin_web": ["admin_web_bind", "admin_web_port"],
            "runner": ["overlay_transport"],
        },
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
    assert written["runner"]["overlay_transport"] == "myudp"
    assert "misc" not in written


def test_runtime_config_save_discards_unregistered_sections(tmp_path):
    runner = _make_runner(tmp_path)
    runner.args._raw_config = {
        "misc": {"stale_option": "ignored"},
        "unregistered_extension": {"option": "ignored"},
    }

    ok, err = runner.save_runtime_config()

    assert ok is True
    assert err == ""

    written = json.loads((tmp_path / "ObstacleBridge.cfg").read_text(encoding="utf-8"))
    assert "misc" not in written
    assert "unregistered_extension" not in written


def test_cli_config_dump_discards_unregistered_effective_values():
    cli = ConfigAwareCLI(description="test")
    cli._sections = {"runner": {"overlay_transport"}}

    dumped = json.loads(cli.dump_effective_config_json(argparse.Namespace(
        overlay_transport="myudp",
        stale_option="ignored",
    )))

    assert dumped == {"runner": {"overlay_transport": "myudp"}}


def test_update_config_accepts_grouped_tun_routing_section(tmp_path):
    runner = _make_runner(tmp_path)
    runner.args.tunnel_address = "192.168.106.2"
    runner.args.tunnel_prefix = 24
    runner.args.tunnel_gateway = "192.168.106.1"
    runner.args.dns_servers = ["1.1.1.1"]
    runner.args.log_TUN_routing = "CRITICAL"
    runner.args._config_sections = {
        "admin_web": ["admin_web_bind", "admin_web_port"],
        "TUN_routing": ["tunnel_address", "tunnel_prefix", "tunnel_gateway", "dns_servers", "log_TUN_routing"],
    }

    ok, err = runner.update_config({"TUN_routing": {"dns_servers": ["192.168.106.1"]}})

    assert ok is True
    assert err == ""
    assert runner.args.dns_servers == ["192.168.106.1"]

    written = json.loads((tmp_path / "ObstacleBridge.cfg").read_text(encoding="utf-8"))
    assert written["TUN_routing"]["dns_servers"] == ["192.168.106.1"]
    assert written["TUN_routing"]["tunnel_address"] == "192.168.106.2"
    assert written["TUN_routing"]["tunnel_gateway"] == "192.168.106.1"


def test_runtime_config_encrypts_secret_fields_and_loads_them_back(tmp_path, monkeypatch):
    monkeypatch.setattr(bridge.socket, "gethostname", lambda: "unit-test-host")
    runner = _make_runner(tmp_path)
    runner.args._config_sections = {
        "admin_web": ["admin_web_bind", "admin_web_password", "admin_web_port"],
        "secure_link": ["secure_link_psk"],
        "telemetry": [
            "telemetry_enabled",
            "telemetry_endpoint",
            "telemetry_installation_id",
            "telemetry_mtls_identity_label",
            "telemetry_spool_directory",
        ],
    }

    ok, err = runner.save_runtime_config()

    assert ok is True
    assert err == ""

    written = json.loads((tmp_path / "ObstacleBridge.cfg").read_text(encoding="utf-8"))
    assert written["admin_web"]["admin_web_password"].startswith("enc:v1:")
    assert written["secure_link"]["secure_link_psk"].startswith("enc:v1:")
    assert written["admin_web"]["admin_web_password"] != "admin-secret"
    assert written["secure_link"]["secure_link_psk"] != "bridge-secret"
    for key in {
        "telemetry_endpoint",
        "telemetry_installation_id",
        "telemetry_mtls_identity_label",
        "telemetry_spool_directory",
    }:
        assert not written["telemetry"][key].startswith("enc:v1:")

    cli = ConfigAwareCLI(description="test")
    loaded = cli._load_json_config(str(tmp_path / "ObstacleBridge.cfg"))

    assert loaded["admin_web"]["admin_web_password"] == "admin-secret"
    assert loaded["secure_link"]["secure_link_psk"] == "bridge-secret"
    assert loaded["telemetry"]["telemetry_endpoint"] == "https://collector.example.test/v1/telemetry"
    assert loaded["telemetry"]["telemetry_installation_id"] == "installation-test-id"
    assert loaded["telemetry"]["telemetry_mtls_identity_label"] == "telemetry-client-identity"
    assert loaded["telemetry"]["telemetry_spool_directory"] == str(tmp_path / "telemetry-spool")


def test_runtime_config_allows_empty_secret_fields_without_crypto_backend(tmp_path, monkeypatch):
    monkeypatch.setattr(bridge, "hashes", None)
    monkeypatch.setattr(bridge, "HKDF", None)
    runner = _make_runner(tmp_path)
    runner.args.admin_web_password = ""
    runner.args.secure_link_psk = ""
    runner.args.telemetry_endpoint = ""
    runner.args.telemetry_installation_id = ""
    runner.args.telemetry_mtls_identity_label = ""
    runner.args.telemetry_spool_directory = ""
    runner.args._config_sections = {
        "admin_web": ["admin_web_bind", "admin_web_password", "admin_web_port"],
        "secure_link": ["secure_link_psk"],
        "telemetry": [
            "telemetry_enabled",
            "telemetry_endpoint",
            "telemetry_installation_id",
            "telemetry_mtls_identity_label",
            "telemetry_spool_directory",
        ],
    }

    ok, err = runner.save_runtime_config()

    assert ok is True
    assert err == ""

    written = json.loads((tmp_path / "ObstacleBridge.cfg").read_text(encoding="utf-8"))
    assert written["admin_web"]["admin_web_password"] == ""
    assert written["secure_link"]["secure_link_psk"] == ""
    for key in {
        "telemetry_endpoint",
        "telemetry_installation_id",
        "telemetry_mtls_identity_label",
        "telemetry_spool_directory",
    }:
        assert written["telemetry"][key] == ""


def test_update_config_disabling_admin_web_auth_clears_credentials(tmp_path):
    runner = _make_runner(tmp_path)
    runner.args.admin_web_auth_disable = False
    runner.args.admin_web_username = "admin"
    runner.args._config_sections = {
        "admin_web": [
            "admin_web_bind",
            "admin_web_port",
            "admin_web_auth_disable",
            "admin_web_username",
            "admin_web_password",
        ]
    }

    ok, err = runner.update_config({"admin_web_auth_disable": True, "admin_web_password": ""})

    assert ok is True
    assert err == ""
    assert runner.args.admin_web_auth_disable is True
    assert runner.args.admin_web_username == ""
    assert runner.args.admin_web_password == ""

    written = json.loads((tmp_path / "ObstacleBridge.cfg").read_text(encoding="utf-8"))
    assert written["admin_web"]["admin_web_auth_disable"] is True
    assert written["admin_web"]["admin_web_username"] == ""
    assert written["admin_web"]["admin_web_password"] == ""


def test_ios_runtime_config_persists_secret_fields_as_plaintext(tmp_path, monkeypatch):
    monkeypatch.setattr(bridge_runner, "_admin_ui_platform", lambda: "ios")
    monkeypatch.setattr(bridge, "ChaCha20Poly1305", None)
    runner = _make_runner(tmp_path)
    runner.args._config_sections = {
        "admin_web": ["admin_web_bind", "admin_web_password", "admin_web_port"],
        "secure_link": ["secure_link_psk"],
        "telemetry": [
            "telemetry_enabled",
            "telemetry_endpoint",
            "telemetry_installation_id",
            "telemetry_mtls_identity_label",
            "telemetry_spool_directory",
        ],
    }

    ok, err = runner.save_runtime_config()

    assert ok is True
    assert err == ""

    written = json.loads((tmp_path / "ObstacleBridge.cfg").read_text(encoding="utf-8"))
    assert written["admin_web"]["admin_web_password"] == "admin-secret"
    assert written["secure_link"]["secure_link_psk"] == "bridge-secret"
    assert written["telemetry"]["telemetry_endpoint"] == "https://collector.example.test/v1/telemetry"
    assert written["telemetry"]["telemetry_installation_id"] == "installation-test-id"
    assert written["telemetry"]["telemetry_mtls_identity_label"] == "telemetry-client-identity"
    assert written["telemetry"]["telemetry_spool_directory"] == str(tmp_path / "telemetry-spool")
