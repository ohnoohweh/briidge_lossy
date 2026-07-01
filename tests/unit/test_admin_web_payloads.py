import argparse
import asyncio
import base64
import json
import os
import pathlib
import sys
import time
import unittest
from unittest import mock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from obstacle_bridge.bridge import AdminWebUI
from obstacle_bridge import bridge_runner


class _RunnerStub:
    def __init__(self):
        self.args = argparse.Namespace(
            admin_web_name="Lab Node",
            admin_web_password="admin-secret",
            secure_link_psk="bridge-secret",
        )
        self.restart_requested = False

    def get_config_snapshot(self, include_secrets: bool = False):
        blocked = {"config", "dump_config", "save_config", "save_format", "force", "help"}
        secret_keys = AdminWebUI._secret_config_keys()
        data = {}
        for k, v in vars(self.args).items():
            if k.startswith("_") or k in blocked:
                continue
            if k in secret_keys and not include_secrets:
                data[k] = ""
                continue
            data[k] = v
        return data

    def get_config_schema_snapshot(self):
        keys = [k for k in vars(self.args).keys() if not k.startswith("_")]
        rows = []
        for key in sorted(keys):
            row = {"key": key, "description": "(no description)", "default": None}
            if key in AdminWebUI._secret_config_keys():
                row["secret"] = True
            if key in AdminWebUI._readonly_config_keys():
                row["readonly"] = True
            rows.append(row)
        return {"misc": rows}

    def update_config(self, updates):
        for key, value in updates.items():
            if key in AdminWebUI._readonly_config_keys():
                return (False, f"{key} is read-only")
            if not hasattr(self.args, key):
                return (False, f"unknown config key: {key}")
            setattr(self.args, key, value)
        return (True, "")

    def get_status_snapshot(self):
        return {
            "peer_state": "CONNECTED",
            "connection_failure_reason": None,
            "connection_failure_detail": None,
            "connection_failure_unix_ts": None,
            "connection_last_event": "",
            "connection_last_event_unix_ts": None,
            "connection_failure_transport": None,
            "secure_link_material_generation": 3,
            "secure_link_last_reload_unix_ts": 1700000100.0,
            "secure_link_last_reload_scope": "revocation",
            "secure_link_last_reload_result": "applied",
            "secure_link_last_reload_detail": "revoked_serials=1",
            "secure_link_peers_dropped_total": 2,
            "compress_layer": {
                "enabled": True,
                "sessions_enabled": 1,
                "algorithm": "zlib",
                "algorithms": ["zlib"],
                "transports": ["tcp"],
                "compress_attempts_total": 12,
                "compress_applied_total": 7,
                "compress_skipped_no_gain_total": 5,
                "compress_input_bytes_total": 2048,
                "compress_output_bytes_total": 1024,
                "decompress_ok_total": 9,
                "decompress_fail_total": 0,
                "compression_saving_ratio": 0.5,
            },
        }

    def get_peer_connections_snapshot(self):
        return {
            "count": 1,
            "peers": [
                {
                    "id": "0:1",
                    "transport": "tcp",
                    "state": "connected",
                    "connected": True,
                    "peer": "127.0.0.1:1234",
                    "rtt_est_ms": 42.0,
                    "transmit_delay_sample_ms": 101.0,
                    "transmit_delay_est_ms": 123.0,
                    "secure_link": {
                        "enabled": True,
                        "mode": "psk",
                        "state": "authenticated",
                        "authenticated": True,
                        "session_id": 42,
                        "rekey_in_progress": False,
                        "last_rekey_trigger": "operator",
                        "rekey_due_unix_ts": None,
                        "failure_code": None,
                        "failure_reason": None,
                        "failure_detail": None,
                        "failure_unix_ts": None,
                        "failure_session_id": None,
                        "handshake_attempts_total": 1,
                        "last_event": "authenticated",
                        "last_event_unix_ts": 1700000000.0,
                        "last_authenticated_unix_ts": 1700000000.0,
                        "connected_since_unix_ts": 1699999900.0,
                        "authenticated_sessions_total": 1,
                        "rekeys_completed_total": 0,
                        "transport": "tcp",
                    },
                    "compress_layer": {
                        "enabled": True,
                        "algorithm": "zlib",
                        "transport": "tcp",
                        "level": 3,
                        "min_bytes": 64,
                        "compress_attempts_total": 12,
                        "compress_applied_total": 7,
                        "compress_skipped_no_gain_total": 5,
                        "compress_input_bytes_total": 2048,
                        "compress_output_bytes_total": 1024,
                        "decompress_ok_total": 9,
                        "decompress_fail_total": 0,
                    },
                    "throttle": {
                        "applicable": True,
                        "active": True,
                        "stalled": False,
                        "backpressure_active": True,
                        "disabled": False,
                        "budget_bytes": 12000,
                        "used_bytes": 10800,
                        "remaining_bytes": 1200,
                        "aggregate": {
                            "scope_id": "aggregate",
                            "budget_bytes": 12000,
                            "used_bytes": 10800,
                            "remaining_bytes": 1200,
                            "prev_window_bytes": 13333,
                            "throttle_drop_count": 0,
                        },
                        "scope": {
                            "scope_id": "udp:client:301",
                            "budget_bytes": 12000,
                            "used_bytes": 10800,
                            "remaining_bytes": 1200,
                            "prev_window_bytes": 13333,
                            "throttle_drop_count": 0,
                        },
                    },
                }
            ],
        }

    def get_connections_snapshot(self):
        return {
            "udp": [],
            "tcp": [],
            "tun": [
                {
                    "peer_id": "0:1",
                    "protocol": "tun",
                    "role": "server",
                    "state": "listening",
                    "chan_id": None,
                    "svc_id": 3,
                    "service_name": "shared-tun",
                    "local": {"ifname": "obtun0", "mtu": 1500},
                    "remote_destination": {"ifname": "obtun1", "mtu": 1500},
                    "stats": {"rx_bytes": 0, "tx_bytes": 0, "rx_msgs": 0, "tx_msgs": 0},
                    "shared_tun_ownership": {
                        "mode": "server_shared",
                        "peer_count": 2,
                        "address_count": 4,
                        "peer_refs": ["linux-client", "ios-client"],
                        "peers": [
                            {"peer_ref": "linux-client", "ipv4": ["192.168.107.2"], "ipv6": ["fd20:107::2"]},
                            {"peer_ref": "ios-client", "ipv4": ["192.168.107.4"], "ipv6": ["fd20:107::4"]},
                        ],
                        "active_peer_bindings": [
                            {
                                "peer_id": 7,
                                "peer_ref": "linux-client",
                                "preferred_chan_id": 301,
                                "bound_chan_ids": [301],
                                "ipv4": ["192.168.107.2"],
                                "ipv6": ["fd20:107::2"],
                                "address_count": 2,
                            },
                        ],
                        "drop_counters": {
                            "total": 3,
                            "by_reason": {
                                "unknown_destination": 2,
                                "source_not_owned_by_peer": 1,
                            },
                        },
                        "recent_drops": [
                            {
                                "reason": "unknown_destination",
                                "direction": "local_to_peer",
                                "peer_id": None,
                                "chan_id": None,
                                "ip_version": 4,
                                "source_ip": None,
                                "destination_ip": "192.168.107.9",
                                "route_class": "unicast",
                                "packet_bytes": 21,
                            }
                        ],
                    },
                }
            ],
            "counts": {
                "udp": 0,
                "tcp": 0,
                "tun": 0,
                "udp_listening": 0,
                "tcp_listening": 0,
                "tun_listening": 1,
            },
        }

    def _restart_requires_delay(self):
        return True

    def request_restart(self):
        self.restart_requested = True


class _RunnerCertStub(_RunnerStub):
    def get_peer_connections_snapshot(self):
        payload = super().get_peer_connections_snapshot()
        payload["peers"][0]["secure_link"] = {
            "enabled": True,
            "mode": "cert",
            "state": "authenticated",
            "authenticated": True,
            "session_id": 84,
            "rekey_in_progress": False,
            "last_rekey_trigger": "operator",
            "rekey_due_unix_ts": None,
            "failure_code": None,
            "failure_reason": None,
            "failure_detail": None,
            "failure_unix_ts": None,
            "failure_session_id": None,
            "handshake_attempts_total": 1,
            "last_event": "authenticated",
            "last_event_unix_ts": 1700000000.0,
            "last_authenticated_unix_ts": 1700000000.0,
            "connected_since_unix_ts": 1699999900.0,
            "authenticated_sessions_total": 1,
            "rekeys_completed_total": 0,
            "transport": "tcp",
            "peer_subject_id": "bridge-server-01",
            "peer_subject_name": "Bridge Server 01",
            "peer_roles": ["server"],
            "peer_deployment_id": "lab-a",
            "peer_serial": "server_valid",
            "issuer_id": "deployment-admin-a",
            "trust_anchor_id": "abc123root",
            "trust_validation_state": "trusted",
            "trust_failure_reason": "",
            "trust_failure_detail": "",
            "active_material_generation": 3,
            "last_material_reload_unix_ts": 1700000100.0,
            "last_material_reload_scope": "revocation",
            "last_material_reload_result": "applied",
            "last_material_reload_detail": "revoked_serials=1",
            "trust_enforced_unix_ts": None,
            "disconnect_reason": "",
            "disconnect_detail": "",
        }
        return payload


class _WriterStub:
    def __init__(self):
        self.buffer = bytearray()
        self.closed = False

    def write(self, data):
        self.buffer.extend(data)

    async def drain(self):
        return None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


class _ServerStub:
    def __init__(self):
        self.closed = False
        self.wait_closed_calls = 0

    def close(self):
        self.closed = True

    async def wait_closed(self):
        self.wait_closed_calls += 1
        return None


def _http_json_body(writer: _WriterStub) -> dict:
    return json.loads(writer.buffer.decode("utf-8").split("\r\n\r\n", 1)[1])


class AdminWebPayloadTests(unittest.TestCase):
    @staticmethod
    def _canonical_webadmin_paths() -> list[pathlib.Path]:
        repo_root = pathlib.Path(__file__).resolve().parents[2]
        return [repo_root / "admin_web" / "app.js"]

    def test_setup_build_stages_admin_web_assets_from_repo_root(self):
        repo_root = pathlib.Path(__file__).resolve().parents[2]
        setup_py = (repo_root / "setup.py").read_text(encoding="utf-8")
        manifest = (repo_root / "MANIFEST.in").read_text(encoding="utf-8")
        self.assertIn('CANONICAL_ADMIN_WEB_DIR = ROOT / "admin_web"', setup_py)
        self.assertIn('PACKAGE_ADMIN_WEB_REL = Path("obstacle_bridge") / "admin_web"', setup_py)
        self.assertIn("def _stage_admin_web_assets(self):", setup_py)
        self.assertIn("recursive-include admin_web *.js *.html *.css", manifest)

    def test_stop_closes_server_and_active_client_writers(self):
        args = argparse.Namespace(
            admin_web=True,
            admin_web_bind="127.0.0.1",
            admin_web_port=18090,
            admin_web_path="/",
            admin_web_dir="./admin_web",
            admin_web_name="Lab Node",
            admin_web_auth_disable=True,
            admin_web_username="",
            admin_web_password="",
            overlay_transport="tcp",
            dashboard=False,
        )
        ui = AdminWebUI(args, _RunnerStub())
        server = _ServerStub()
        writer_a = _WriterStub()
        writer_b = _WriterStub()
        ui.server = server
        ui._active_client_writers.update({writer_a, writer_b})

        asyncio.run(ui._stop_server_current_loop())

        self.assertTrue(server.closed)
        self.assertEqual(server.wait_closed_calls, 0)
        self.assertTrue(writer_a.closed)
        self.assertTrue(writer_b.closed)
        self.assertEqual(ui._active_client_writers, set())

    def test_resolve_static_base_falls_back_to_packaged_admin_web(self):
        args = argparse.Namespace(
            admin_web=True,
            admin_web_bind="127.0.0.1",
            admin_web_port=18080,
            admin_web_path="/",
            admin_web_dir="./definitely-missing-admin-web",
            admin_web_name="Lab Node",
            admin_web_auth_disable=True,
            admin_web_username="",
            admin_web_password="",
            admin_web_security_advisor_disable=False,
            admin_web_security_advisor_startup_disable=False,
            admin_web_first_tab="home",
            secure_link_mode="off",
            secure_link_psk="",
            overlay_transport="ws",
        )

        ui = AdminWebUI(args, _RunnerStub())

        base = ui._resolve_static_base()

        self.assertTrue(base.is_dir())
        self.assertTrue((base / "index.html").is_file())
        self.assertTrue(base.is_dir())
        self.assertTrue((base / "index.html").is_file())
        self.assertEqual(base.name, "admin_web")

    def test_token_generator_ui_requires_admin_web_name_before_generation(self):
        repo_root = pathlib.Path(__file__).resolve().parents[2]
        index_html = (repo_root / "admin_web" / "index.html").read_text(encoding="utf-8")
        app_js = (repo_root / "admin_web" / "app.js").read_text(encoding="utf-8")

        self.assertIn("Name To Include In Invite Token", index_html)
        self.assertIn('id="onboardingTokenAdminName"', index_html)
        self.assertIn("TUN Routing For Invite Token", index_html)
        self.assertIn('id="tokenTunAddress"', index_html)
        self.assertIn("Enter the name to include in the invite token before continuing.", app_js)
        self.assertIn("Enter the name to include in the invite token before generating it.", app_js)
        self.assertIn("admin_web_name: tokenAdminName", app_js)
        self.assertIn("TUN_routing: tunRouting", app_js)

    def test_config_snapshot_hides_secure_link_psk_and_marks_it_read_only(self):
        args = argparse.Namespace(
            admin_web=True,
            admin_web_bind="127.0.0.1",
            admin_web_port=18080,
            admin_web_path="/",
            admin_web_dir="./admin_web",
            admin_web_name="Lab Node",
            admin_web_auth_disable=True,
            admin_web_username="",
            admin_web_password="",
            overlay_transport="tcp",
            dashboard=False,
            secure_link_psk="bridge-secret",
        )
        ui = AdminWebUI(args, _RunnerStub())
        config = ui.runner.get_config_snapshot()
        schema = ui.runner.get_config_schema_snapshot()
        self.assertEqual(config["secure_link_psk"], "")
        self.assertEqual(config["admin_web_password"], "")
        secure_rows = [row for rows in schema.values() for row in rows if row["key"] == "secure_link_psk"]
        self.assertEqual(len(secure_rows), 1)
        self.assertTrue(secure_rows[0]["secret"])
        # secure_link_psk should be write-only (hidden) but settable like admin_web_password
        # it must not be marked readonly in the schema
        self.assertFalse(secure_rows[0].get("readonly", False))

    def test_update_config_rejects_secure_link_psk(self):
        args = argparse.Namespace(
            admin_web=True,
            admin_web_bind="127.0.0.1",
            admin_web_port=18080,
            admin_web_path="/",
            admin_web_dir="./admin_web",
            admin_web_name="Lab Node",
            admin_web_auth_disable=True,
            admin_web_username="",
            admin_web_password="",
            overlay_transport="tcp",
            dashboard=False,
            secure_link_psk="bridge-secret",
        )
        ui = AdminWebUI(args, _RunnerStub())
        ok, err = ui.runner.update_config({"secure_link_psk": "new-secret"})
        self.assertTrue(ok)
        # ensure the runner applied the new secret
        self.assertEqual(ui.runner.args.secure_link_psk, "new-secret")

    def test_build_status_payload_omits_peer_scoped_secure_link_summary(self):
        args = argparse.Namespace(
            admin_web=True,
            admin_web_bind="127.0.0.1",
            admin_web_port=18080,
            admin_web_path="/",
            admin_web_dir="./admin_web",
            admin_web_name="Lab Node",
            admin_web_auth_disable=True,
            admin_web_username="",
            admin_web_password="",
            overlay_transport="tcp",
            dashboard=False,
        )
        ui = AdminWebUI(args, _RunnerStub())
        payload = ui._build_status_payload()
        self.assertNotIn("secure_link", payload)
        self.assertEqual(payload["admin_web_name"], "Lab Node")
        self.assertEqual(payload["secure_link_material_generation"], 3)
        self.assertEqual(payload["secure_link_last_reload_scope"], "revocation")
        self.assertEqual(payload["secure_link_last_reload_result"], "applied")
        self.assertEqual(payload["secure_link_peers_dropped_total"], 2)
        self.assertNotIn("open_connections", payload)
        self.assertNotIn("traffic", payload)
        self.assertNotIn("compress_layer", payload)
        self.assertNotIn("decode_errors", payload)
        self.assertIn("admin_ui", payload)
        self.assertEqual(payload["admin_ui"]["first_start_detected"], False)
        self.assertEqual(payload["admin_ui"]["config_file_state"], "unknown")
        self.assertEqual(payload["admin_ui"]["platform"], sys.platform)

    def test_build_status_payload_preserves_connection_failure_fields(self):
        args = argparse.Namespace(
            admin_web=True,
            admin_web_bind="127.0.0.1",
            admin_web_port=18080,
            admin_web_path="/",
            admin_web_dir="./admin_web",
            admin_web_name="Lab Node",
            admin_web_auth_disable=True,
            admin_web_username="",
            admin_web_password="",
            overlay_transport="ws",
            dashboard=False,
        )
        runner = _RunnerStub()
        runner.get_status_snapshot = lambda: {
            "peer_state": "FAILED",
            "connection_failure_reason": "http_preflight_failed",
            "connection_failure_detail": "unexpected HTTP status 426",
            "connection_failure_unix_ts": 1700000200.0,
            "connection_last_event": "connect_failed",
            "connection_last_event_unix_ts": 1700000200.0,
            "connection_failure_transport": "ws",
            "secure_link_material_generation": 0,
            "secure_link_last_reload_unix_ts": None,
            "secure_link_last_reload_scope": "",
            "secure_link_last_reload_result": "",
            "secure_link_last_reload_detail": "",
            "secure_link_peers_dropped_total": 0,
        }
        ui = AdminWebUI(args, runner)
        payload = ui._build_status_payload()
        self.assertEqual(payload["peer_state"], "FAILED")
        self.assertEqual(payload["connection_failure_reason"], "http_preflight_failed")
        self.assertEqual(payload["connection_failure_detail"], "unexpected HTTP status 426")
        self.assertEqual(payload["connection_last_event"], "connect_failed")
        self.assertEqual(payload["connection_failure_transport"], "ws")

    def test_build_status_payload_prefers_admin_ui_platform_override(self):
        args = argparse.Namespace(
            admin_web=True,
            admin_web_bind="127.0.0.1",
            admin_web_port=18080,
            admin_web_path="/",
            admin_web_dir="./admin_web",
            admin_web_name="Lab Node",
            admin_web_auth_disable=True,
            admin_web_username="",
            admin_web_password="",
            overlay_transport="tcp",
            dashboard=False,
        )
        ui = AdminWebUI(args, _RunnerStub())
        with mock.patch.dict(os.environ, {"OBSTACLEBRIDGE_ADMIN_UI_PLATFORM": "ios"}, clear=False):
            payload = ui._build_status_payload()
        self.assertEqual(payload["admin_ui"]["platform"], "ios")
        self.assertEqual(payload["admin_ui"]["runtime_dependencies"]["missing"], [])
        self.assertTrue(payload["admin_ui"]["runtime_dependencies"]["ok"])
        self.assertEqual(payload["admin_ui"]["runtime_dependencies"]["install_hint"], "")

    def test_build_tun_routing_payload_exposes_dedicated_shared_tun_view(self):
        args = argparse.Namespace(
            admin_web=True,
            admin_web_bind="127.0.0.1",
            admin_web_port=18080,
            admin_web_path="/",
            admin_web_dir="./admin_web",
            admin_web_name="Lab Node",
            admin_web_auth_disable=True,
            admin_web_username="",
            admin_web_password="",
            overlay_transport="tcp",
            dashboard=False,
        )
        ui = AdminWebUI(args, _RunnerStub())

        payload = ui._build_tun_routing_payload()

        self.assertEqual(payload["summary"]["tun_total"], 1)
        self.assertEqual(payload["summary"]["tun_open"], 0)
        self.assertEqual(payload["summary"]["tun_listening"], 1)
        self.assertEqual(payload["summary"]["shared_services"], 1)
        self.assertEqual(payload["summary"]["shared_active_peer_bindings"], 1)
        self.assertEqual(payload["summary"]["shared_drop_total"], 3)
        self.assertEqual(len(payload["shared_tun"]), 1)
        self.assertEqual(payload["shared_tun"][0]["service_name"], "shared-tun")
        self.assertEqual(payload["shared_tun"][0]["shared_tun_ownership"]["peer_count"], 2)
        self.assertEqual(payload["shared_tun"][0]["shared_tun_ownership"]["drop_counters"]["by_reason"]["unknown_destination"], 2)

    def test_build_tun_routing_payload_deduplicates_shared_tun_listener_and_open_row(self):
        args = argparse.Namespace(
            admin_web=True,
            admin_web_bind="127.0.0.1",
            admin_web_port=18080,
            admin_web_path="/",
            admin_web_dir="./admin_web",
            admin_web_name="Lab Node",
            admin_web_auth_disable=True,
            admin_web_username="",
            admin_web_password="",
            overlay_transport="tcp",
            dashboard=False,
        )
        runner = _RunnerStub()
        shared = {
            "mode": "server_shared",
            "peer_count": 1,
            "active_peer_bindings": [{"peer_id": 7}],
            "drop_counters": {"total": 0, "by_reason": {}},
        }
        runner.get_connections_snapshot = lambda: {
            "udp": [],
            "tcp": [],
            "tun": [
                {
                    "protocol": "tun",
                    "state": "connected",
                    "chan_id": 11,
                    "svc_id": 1,
                    "service_name": "shared-tun",
                    "local": {"ifname": "obtun0", "mtu": 1600},
                    "shared_tun_ownership": dict(shared),
                },
                {
                    "protocol": "tun",
                    "state": "listening",
                    "chan_id": None,
                    "svc_id": 1,
                    "service_name": "shared-tun",
                    "local": {"ifname": "obtun0", "mtu": 1600},
                    "shared_tun_ownership": {**shared, "active_peer_bindings": []},
                },
            ],
            "counts": {"udp": 0, "tcp": 0, "tun": 1, "udp_listening": 0, "tcp_listening": 0, "tun_listening": 1},
        }
        ui = AdminWebUI(args, runner)

        payload = ui._build_tun_routing_payload()

        self.assertEqual(payload["summary"]["tun_total"], 2)
        self.assertEqual(payload["summary"]["tun_open"], 1)
        self.assertEqual(payload["summary"]["tun_listening"], 1)
        self.assertEqual(payload["summary"]["shared_services"], 1)
        self.assertEqual(payload["summary"]["shared_active_peer_bindings"], 1)
        self.assertEqual(len(payload["shared_tun"]), 1)
        self.assertEqual(payload["shared_tun"][0]["state"], "connected")

    def test_build_tun_routing_payload_exposes_effective_overlay_peer_excluded_routes(self):
        args = argparse.Namespace(
            admin_web=True,
            admin_web_bind="127.0.0.1",
            admin_web_port=18080,
            admin_web_path="/",
            admin_web_dir="./admin_web",
            admin_web_name="Lab Node",
            admin_web_auth_disable=True,
            admin_web_username="",
            admin_web_password="",
            overlay_transport="ws",
            ws_peer="38.180.143.5",
            ws_peer_port=8080,
            ws_bind="::",
            ws_peer_resolve_family="ipv4",
            dashboard=False,
            included_routes=["0.0.0.0/0"],
            excluded_routes=["127.0.0.0/8"],
            included_routes6=["::/0"],
            excluded_routes6=["::1/128"],
            tunnel_address="192.168.106.2",
            tunnel_prefix=24,
            tunnel_gateway="192.168.106.1",
            tunnel_address6="fd20:106::2",
            tunnel_prefix6=64,
            tunnel_gateway6="fd20:106::1",
            dns_servers=["1.1.1.1"],
            mtu=1600,
        )
        ui = AdminWebUI(args, _RunnerStub())

        payload = ui._build_tun_routing_payload()

        self.assertEqual(payload["included_routes"], ["0.0.0.0/0"])
        self.assertEqual(payload["excluded_routes"], ["127.0.0.0/8", "38.180.143.5/32"])
        self.assertEqual(payload["included_routes6"], ["::/0"])
        self.assertEqual(payload["excluded_routes6"], ["::1/128", "::ffff:38.180.143.5/128"])

    def test_meta_payload_suppresses_runtime_dependency_warnings_on_ios(self):
        args = argparse.Namespace(
            admin_web=True,
            admin_web_bind="127.0.0.1",
            admin_web_port=18080,
            admin_web_path="/",
            admin_web_dir="./admin_web",
            admin_web_name="Lab Node",
            admin_web_auth_disable=True,
            admin_web_username="",
            admin_web_password="",
            overlay_transport="tcp",
            dashboard=False,
        )
        ui = AdminWebUI(args, _RunnerStub())
        with mock.patch.dict(os.environ, {"OBSTACLEBRIDGE_ADMIN_UI_PLATFORM": "ios"}, clear=False):
            payload = ui._build_meta_payload()
        self.assertEqual(payload["runtime_dependencies"]["missing"], [])
        self.assertTrue(payload["runtime_dependencies"]["ok"])
        self.assertEqual(payload["runtime_dependencies"]["install_hint"], "")
        self.assertNotIn("crypto_extract", payload)

    def test_runtime_dependency_warning_text_is_backend_driven(self):
        repo_root = pathlib.Path(__file__).resolve().parents[2]
        for app_path in self._canonical_webadmin_paths():
            with self.subTest(app_path=str(app_path.relative_to(repo_root))):
                text = app_path.read_text(encoding="utf-8")
                self.assertIn("const missing = Array.isArray(deps?.missing) ? deps.missing : [];", text)
                self.assertNotIn("platform === 'ios'", text)

    def test_status_frontend_renders_transmit_delay_next_to_rtt(self):
        repo_root = pathlib.Path(__file__).resolve().parents[2]
        for app_path in self._canonical_webadmin_paths():
            with self.subTest(app_path=str(app_path.relative_to(repo_root))):
                text = app_path.read_text(encoding="utf-8")
                self.assertIn("renderMetric('RTT Est (ms)', fmtNumber(row.rtt_est_ms))", text)
                self.assertIn("renderMetric('Transmit Delay Est (ms)', fmtNumber(row.transmit_delay_est_ms))", text)
                self.assertIn("renderMetric('Throttle', fmtThrottleSummary(row.throttle))", text)

    def test_tun_routing_frontend_uses_dedicated_tab_and_api(self):
        repo_root = pathlib.Path(__file__).resolve().parents[2]
        index_html = (repo_root / "admin_web" / "index.html").read_text(encoding="utf-8")
        app_js = (repo_root / "admin_web" / "app.js").read_text(encoding="utf-8")

        self.assertIn('data-tab="tun-routing"', index_html)
        self.assertIn('id="tab-tun-routing"', index_html)
        self.assertIn('id="tunRoutingConnectionsBody"', index_html)
        self.assertIn('id="tunRoutingSharedBody"', index_html)
        self.assertIn('id="tunRoutingIncludedRoutes"', index_html)
        self.assertIn('id="tunRoutingExcludedRoutes"', index_html)
        self.assertIn('id="tunRoutingIncludedRoutes6"', index_html)
        self.assertIn('id="tunRoutingExcludedRoutes6"', index_html)
        self.assertNotIn('id="tunConnectionsBody"', index_html)
        self.assertNotIn('id="tunOpen"', index_html)
        self.assertIn("apiFetch('/api/tun-routing/status'", app_js)
        self.assertIn("applyTunRoutingDoc(j);", app_js)
        self.assertIn("setText('tunRoutingIncludedRoutes', fmtTunRoutingRouteList(j.included_routes));", app_js)
        self.assertIn("setText('tunRoutingExcludedRoutes', fmtTunRoutingRouteList(j.excluded_routes));", app_js)
        self.assertIn("setText('tunRoutingIncludedRoutes6', fmtTunRoutingRouteList(j.included_routes6));", app_js)
        self.assertIn("setText('tunRoutingExcludedRoutes6', fmtTunRoutingRouteList(j.excluded_routes6));", app_js)
        self.assertIn("topics.push('tun_routing')", app_js)
        self.assertNotIn("applyTunRoutingConfigSummary(", app_js)

    def test_admin_web_navigation_uses_operator_labels_for_peer_and_udp_tcp_tabs(self):
        repo_root = pathlib.Path(__file__).resolve().parents[2]
        index_html = (repo_root / "admin_web" / "index.html").read_text(encoding="utf-8")

        self.assertIn('<button class="nav-tab active" data-tab="status" type="button">Peers</button>', index_html)
        self.assertIn('<button class="nav-tab" data-tab="connections" type="button">UDP / TCP</button>', index_html)
        self.assertIn('<button class="nav-tab" data-tab="proxy" type="button">Proxy</button>', index_html)
        self.assertIn("<span>Open Peers on startup</span>", index_html)
        self.assertIn("<h2>Peers</h2>", index_html)
        self.assertIn("<h2>UDP / TCP</h2>", index_html)
        self.assertNotIn('data-tab="status" type="button">Status</button>', index_html)
        self.assertNotIn('data-tab="connections" type="button">Connections</button>', index_html)

    def test_admin_web_proxy_tab_renders_config_runtime_and_throughput(self):
        repo_root = pathlib.Path(__file__).resolve().parents[2]
        index_html = (repo_root / "admin_web" / "index.html").read_text(encoding="utf-8")
        app_js = (repo_root / "admin_web" / "app.js").read_text(encoding="utf-8")

        self.assertIn('id="tab-proxy"', index_html)
        self.assertIn('proxy-summary-row-status', index_html)
        self.assertIn('proxy-summary-row-endpoints', index_html)
        self.assertIn('proxy-summary-row-counters', index_html)
        self.assertIn('proxy-summary-row-error', index_html)
        self.assertIn('proxy-summary-row-throughput', index_html)
        self.assertIn('id="proxyProtocolSockets"', index_html)
        self.assertIn('proxy-protocol-card', index_html)
        self.assertIn('id="proxyActiveConnections"', index_html)
        self.assertIn('id="proxyRxRate"', index_html)
        self.assertIn('id="proxyTxRate"', index_html)
        self.assertIn('id="proxyRxRateFill"', index_html)
        self.assertIn('id="proxyTxRateFill"', index_html)
        self.assertIn('id="proxyListenersGrid"', index_html)
        self.assertIn('class="proxy-rate-pair"', index_html)
        self.assertIn("function applyProxyDoc()", app_js)
        self.assertIn("function proxyListenerRate(listenerName, snapshot)", app_js)
        self.assertIn("function proxyRatePercents(rxRate, txRate)", app_js)
        self.assertIn("function renderProxyTrafficPair(rxBytes, txBytes, rxRate, txRate)", app_js)
        self.assertIn('proxy-sockets-card', app_js)
        self.assertIn('proxy-mini-grid', app_js)
        self.assertIn("root.proxy_provider_enabled", app_js)
        self.assertIn("root.proxy_provider_http_port", app_js)
        self.assertIn("root.proxy_provider_socks5_port", app_js)
        self.assertIn("function renderProxyProtocolSockets(cfg)", app_js)
        self.assertIn("protocolSockets.innerHTML = renderProxyProtocolSockets(cfg);", app_js)
        self.assertIn("setText('proxyActiveConnections', fmtInteger(totals.active));", app_js)
        self.assertIn("setText('proxyRxRate', fmtBytesPerSecond(totals.rxRate));", app_js)
        self.assertIn("setText('proxyTxRate', fmtBytesPerSecond(totals.txRate));", app_js)
        self.assertIn("setPercentWidth('proxyRxRateFill', summaryRates.rxPct);", app_js)
        self.assertIn("setPercentWidth('proxyTxRateFill', summaryRates.txPct);", app_js)
        self.assertIn("if (isTabActive('proxy')) activeTabs.push('proxy');", app_js)
        self.assertIn("if (!isTabActive('proxy')) return;", app_js)

    def test_restart_endpoint_uses_immediate_mode_for_embedded_restart(self):
        args = argparse.Namespace(
            admin_web=True,
            admin_web_bind="127.0.0.1",
            admin_web_port=18080,
            admin_web_path="/",
            admin_web_dir="./admin_web",
            admin_web_name="Lab Node",
            admin_web_auth_disable=True,
            admin_web_username="",
            admin_web_password="",
            overlay_transport="myudp",
            dashboard=False,
            admin_web_token="",
        )
        runner = _RunnerStub()
        calls = []
        runner._embedded_restart_callback = lambda: calls.append("runner")
        ui = AdminWebUI(args, runner)

        async def run_flow():
            writer = _WriterStub()
            await ui._handle_restart(writer, "POST", {})
            doc = _http_json_body(writer)
            self.assertTrue(doc["ok"])
            self.assertTrue(doc["restart_embedded"])
            self.assertEqual(doc["restart_mode"], "immediate")
            self.assertEqual(doc["restart_delay_sec"], 0)
            self.assertEqual(calls, ["runner"])
            self.assertFalse(runner.restart_requested)

        asyncio.run(run_flow())

    def test_restart_endpoint_prefers_admin_web_embedded_restart_callback(self):
        args = argparse.Namespace(
            admin_web=True,
            admin_web_bind="127.0.0.1",
            admin_web_port=18080,
            admin_web_path="/",
            admin_web_dir="./admin_web",
            admin_web_name="Lab Node",
            admin_web_auth_disable=True,
            admin_web_username="",
            admin_web_password="",
            overlay_transport="myudp",
            dashboard=False,
            admin_web_token="",
        )
        runner = _RunnerStub()
        calls = []
        ui = AdminWebUI(args, runner)
        ui._embedded_restart_callback = lambda: calls.append("ui")

        async def run_flow():
            writer = _WriterStub()
            await ui._handle_restart(writer, "POST", {})
            doc = _http_json_body(writer)
            self.assertTrue(doc["ok"])
            self.assertTrue(doc["restart_embedded"])
            self.assertEqual(calls, ["ui"])
            self.assertFalse(runner.restart_requested)

        asyncio.run(run_flow())

    def test_embedded_restart_frontend_arms_fallback_countdown(self):
        repo_root = pathlib.Path(__file__).resolve().parents[2]
        for app_path in self._canonical_webadmin_paths():
            with self.subTest(app_path=str(app_path.relative_to(repo_root))):
                text = app_path.read_text(encoding="utf-8")
                self.assertIn("if (delaySec === 0 && j.restart_embedded)", text)
                self.assertIn("delaySec = 20;", text)
                self.assertIn("startRestartCountdown(delaySec, { embedded: Boolean(j.restart_embedded) });", text)
                self.assertIn("function scheduleRestartProbe(maxProbeSeconds = 180)", text)
                self.assertIn("fetch('/api/meta', {", text)

    def test_config_save_requires_challenge_bound_to_update_block(self):
        args = argparse.Namespace(
            admin_web=True,
            admin_web_bind="127.0.0.1",
            admin_web_port=18080,
            admin_web_path="/",
            admin_web_dir="./admin_web",
            admin_web_name="Lab Node",
            admin_web_auth_disable=False,
            admin_web_username="admin",
            admin_web_password="admin-secret",
            overlay_transport="tcp",
            dashboard=False,
            secure_link_psk="bridge-secret",
        )
        runner = _RunnerStub()
        ui = AdminWebUI(args, runner)
        headers = {"cookie": f"{ui._session_cookie_name()}=session-token"}
        ui._auth_sessions["session-token"] = time.time() + 60

        async def run_flow():
            challenge_writer = _WriterStub()
            await ui._handle_config_challenge(
                challenge_writer,
                "POST",
                headers,
                json.dumps({"updates": {"secure_link_psk": "new-secret", "admin_web_name": "New Node"}}).encode("utf-8"),
            )
            challenge_doc = json.loads(challenge_writer.buffer.decode("utf-8").split("\r\n\r\n", 1)[1])
            proof = ui._build_config_change_response(
                challenge_doc["seed"],
                args.admin_web_username,
                args.admin_web_password,
                challenge_doc["updates_digest"],
            )

            config_writer = _WriterStub()
            await ui._handle_config(
                config_writer,
                "POST",
                json.dumps({
                    "updates": {"secure_link_psk": "new-secret", "admin_web_name": "New Node"},
                    "challenge_id": challenge_doc["challenge_id"],
                    "proof": proof,
                }).encode("utf-8"),
            )
            ok_doc = json.loads(config_writer.buffer.decode("utf-8").split("\r\n\r\n", 1)[1])
            self.assertTrue(ok_doc["ok"])
            self.assertEqual(runner.args.secure_link_psk, "new-secret")
            self.assertEqual(runner.args.admin_web_name, "New Node")

            ui._auth_sessions["session-token"] = time.time() + 60

            tamper_challenge_writer = _WriterStub()
            await ui._handle_config_challenge(
                tamper_challenge_writer,
                "POST",
                headers,
                json.dumps({"updates": {"secure_link_psk": "tampered-secret"}}).encode("utf-8"),
            )
            tamper_challenge_doc = json.loads(tamper_challenge_writer.buffer.decode("utf-8").split("\r\n\r\n", 1)[1])

            tamper_writer = _WriterStub()
            await ui._handle_config(
                tamper_writer,
                "POST",
                json.dumps({
                    "updates": {"secure_link_psk": "tampered-secret"},
                    "challenge_id": tamper_challenge_doc["challenge_id"],
                    "proof": proof,
                }).encode("utf-8"),
            )
            tamper_doc = json.loads(tamper_writer.buffer.decode("utf-8").split("\r\n\r\n", 1)[1])
            self.assertFalse(tamper_doc["ok"])
            self.assertEqual(tamper_doc["error"], "configuration change confirmation failed")

        asyncio.run(run_flow())

    def test_secure_link_psk_reveal_requires_password_proof_and_returns_encrypted_envelope(self):
        args = argparse.Namespace(
            admin_web=True,
            admin_web_bind="127.0.0.1",
            admin_web_port=18080,
            admin_web_path="/",
            admin_web_dir="./admin_web",
            admin_web_name="Lab Node",
            admin_web_auth_disable=False,
            admin_web_username="admin",
            admin_web_password="admin-secret",
            overlay_transport="tcp",
            dashboard=False,
            secure_link_psk="bridge-secret",
        )
        runner = _RunnerStub()
        ui = AdminWebUI(args, runner)
        headers = {"cookie": f"{ui._session_cookie_name()}=session-token"}
        ui._auth_sessions["session-token"] = time.time() + 60

        async def run_flow():
            challenge_writer = _WriterStub()
            await ui._handle_config_secret_secure_link_psk_challenge(challenge_writer, "POST", headers)
            challenge_doc = _http_json_body(challenge_writer)
            self.assertTrue(challenge_doc["ok"])
            self.assertEqual(challenge_doc["secret_name"], "secure_link_psk")

            proof = ui._build_secret_reveal_response(
                challenge_doc["seed"],
                args.admin_web_username,
                args.admin_web_password,
                challenge_doc["secret_name"],
            )
            reveal_writer = _WriterStub()
            await ui._handle_config_secret_secure_link_psk(
                reveal_writer,
                "POST",
                json.dumps({"challenge_id": challenge_doc["challenge_id"], "proof": proof}).encode("utf-8"),
            )
            reveal_doc = _http_json_body(reveal_writer)
            self.assertTrue(reveal_doc["ok"])
            encrypted = reveal_doc["encrypted"]
            self.assertNotIn("bridge-secret", json.dumps(reveal_doc))

            salt = base64.b64decode(encrypted["salt"])
            nonce = base64.b64decode(encrypted["nonce"])
            aad = base64.b64decode(encrypted["aad"])
            ciphertext = base64.b64decode(encrypted["ciphertext"])
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=int(encrypted["iterations"]),
            )
            key = kdf.derive(args.admin_web_password.encode("utf-8"))
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad).decode("utf-8")
            self.assertEqual(plaintext, "bridge-secret")

        asyncio.run(run_flow())

    def test_secure_link_psk_reveal_insecure_context_notice_prefers_own_server_path(self):
        repo_root = pathlib.Path(__file__).resolve().parents[2]
        for app_path in self._canonical_webadmin_paths():
            with self.subTest(app_path=str(app_path.relative_to(repo_root))):
                text = app_path.read_text(encoding="utf-8")
                self.assertIn("openConfigNoticeGate('Cannot Reveal secure_link_psk'", text)
                self.assertIn("own-server configuration/server role", text)
                self.assertIn("protected overlay path", text)
                self.assertIn("Remote plain HTTP can let an active network attacker replace the WebAdmin JavaScript", text)

    def test_service_catalog_modal_preserves_last_valid_draft_on_validation_error(self):
        repo_root = pathlib.Path(__file__).resolve().parents[2]
        for app_path in self._canonical_webadmin_paths():
            with self.subTest(app_path=str(app_path.relative_to(repo_root))):
                text = app_path.read_text(encoding="utf-8")
                self.assertIn("if (!syncServiceCatalogEditor(key)) return;", text)
                self.assertNotIn('sink.value = \'"__invalid_service_catalog__"\'', text)

    def test_service_catalog_remove_does_not_resync_stale_modal_values(self):
        repo_root = pathlib.Path(__file__).resolve().parents[2]
        for app_path in self._canonical_webadmin_paths():
            with self.subTest(app_path=str(app_path.relative_to(repo_root))):
                text = app_path.read_text(encoding="utf-8")
                self.assertIn("function closeServiceCatalogModal(root, key, { rerender = true, syncBeforeClose = true } = {})", text)
                self.assertIn("closeServiceCatalogModal(root, key, { rerender: false, syncBeforeClose: false });", text)
                self.assertIn("renderServiceCatalogModal(root, key, Math.min(rowIndex, specs.length - 1));", text)

    def test_build_peers_payload_includes_secure_link_rows(self):
        args = argparse.Namespace(
            admin_web=True,
            admin_web_bind="127.0.0.1",
            admin_web_port=18080,
            admin_web_path="/",
            admin_web_dir="./admin_web",
            admin_web_name="Lab Node",
            admin_web_auth_disable=True,
            admin_web_username="",
            admin_web_password="",
        )
        ui = AdminWebUI(args, _RunnerStub())
        payload = ui._build_peers_payload()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["count"], 1)
        peer = payload["peers"][0]
        self.assertIn("secure_link", peer)
        self.assertIn("compress_layer", peer)
        self.assertEqual(peer["secure_link"]["state"], "authenticated")
        self.assertEqual(peer["secure_link"]["session_id"], 42)
        self.assertIsNone(peer["secure_link"]["failure_code"])
        self.assertIsNone(peer["secure_link"]["failure_detail"])
        self.assertEqual(peer["secure_link"]["last_rekey_trigger"], "operator")
        self.assertIsNone(peer["secure_link"]["rekey_due_unix_ts"])
        self.assertEqual(peer["secure_link"]["last_event"], "authenticated")
        self.assertEqual(peer["secure_link"]["handshake_attempts_total"], 1)
        self.assertEqual(peer["secure_link"]["authenticated_sessions_total"], 1)
        self.assertEqual(peer["secure_link"]["connected_since_unix_ts"], 1699999900.0)
        self.assertEqual(peer["rtt_est_ms"], 42.0)
        self.assertEqual(peer["transmit_delay_sample_ms"], 101.0)
        self.assertEqual(peer["transmit_delay_est_ms"], 123.0)
        self.assertTrue(peer["throttle"]["applicable"])
        self.assertTrue(peer["throttle"]["active"])
        self.assertEqual(peer["throttle"]["remaining_bytes"], 1200)
        self.assertTrue(peer["compress_layer"]["enabled"])
        self.assertEqual(peer["compress_layer"]["algorithm"], "zlib")
        self.assertEqual(peer["compress_layer"]["compress_applied_total"], 7)

    def test_runner_peer_snapshot_coalesces_null_overlay_metrics(self):
        class _Mux:
            def snapshot_connections(self):
                return {"udp": [], "tcp": [], "tun": [], "counts": {}}

        class _Session:
            _last_rx_wall_ns = time.monotonic_ns()

            def get_metrics(self):
                return bridge_runner.SessionMetrics(
                    rtt_est_ms=42.0,
                    transmit_delay_sample_ms=101.0,
                    transmit_delay_est_ms=123.0,
                    inflight=0,
                )

            def get_overlay_peers_snapshot(self):
                return [
                    {
                        "peer_id": 1,
                        "connected": True,
                        "state": "connected",
                        "peer": ("127.0.0.1", 1234),
                        "rtt_est_ms": None,
                        "transmit_delay_sample_ms": None,
                        "transmit_delay_est_ms": None,
                        "last_incoming_age_seconds": None,
                    }
                ]

            def is_connected(self):
                return True

        runner = bridge_runner.Runner.__new__(bridge_runner.Runner)
        runner.args = argparse.Namespace()
        runner._sessions = [_Session()]
        runner._muxes = [_Mux()]
        runner._session_labels = ["ws"]
        runner._peer_traffic_rate_state = {}

        payload = runner.get_peer_connections_snapshot()
        peer = payload["peers"][0]
        self.assertEqual(peer["rtt_est_ms"], 42.0)
        self.assertEqual(peer["transmit_delay_sample_ms"], 101.0)
        self.assertEqual(peer["transmit_delay_est_ms"], 123.0)
        self.assertIsNotNone(peer["last_incoming_age_seconds"])

    def test_runner_peer_snapshot_preserves_null_listener_overlay_metrics(self):
        class _Mux:
            def snapshot_connections(self):
                return {"udp": [], "tcp": [], "tun": [], "counts": {}}

        class _InnerSession:
            def get_metrics(self):
                return bridge_runner.SessionMetrics(
                    rtt_est_ms=42.0,
                    transmit_delay_sample_ms=101.0,
                    transmit_delay_est_ms=123.0,
                    inflight=0,
                )

        class _Session:
            inner_session = _InnerSession()

            def get_overlay_peers_snapshot(self):
                return [
                    {
                        "peer_id": -1,
                        "listening": True,
                        "rtt_est_ms": None,
                        "transmit_delay_sample_ms": None,
                        "transmit_delay_est_ms": None,
                        "last_incoming_age_seconds": None,
                    }
                ]

            def is_connected(self):
                return False

        runner = bridge_runner.Runner.__new__(bridge_runner.Runner)
        runner.args = argparse.Namespace()
        runner._sessions = [_Session()]
        runner._muxes = [_Mux()]
        runner._session_labels = ["myudp"]
        runner._peer_traffic_rate_state = {}

        payload = runner.get_peer_connections_snapshot()
        peer = payload["peers"][0]
        self.assertFalse(peer["connected"])
        self.assertEqual(peer["state"], "listening")
        self.assertIsNone(peer["rtt_est_ms"])
        self.assertIsNone(peer["transmit_delay_sample_ms"])
        self.assertIsNone(peer["transmit_delay_est_ms"])
        self.assertIsNone(peer["last_incoming_age_seconds"])

    def test_build_peers_payload_includes_cert_identity_and_trust_fields(self):
        args = argparse.Namespace(
            admin_web=True,
            admin_web_bind="127.0.0.1",
            admin_web_port=18080,
            admin_web_path="/",
            admin_web_dir="./admin_web",
            admin_web_name="Lab Node",
            admin_web_auth_disable=True,
            admin_web_username="",
            admin_web_password="",
        )
        ui = AdminWebUI(args, _RunnerCertStub())
        payload = ui._build_peers_payload()
        peer = payload["peers"][0]
        secure = peer["secure_link"]
        self.assertEqual(secure["mode"], "cert")
        self.assertEqual(secure["peer_subject_id"], "bridge-server-01")
        self.assertEqual(secure["peer_subject_name"], "Bridge Server 01")
        self.assertEqual(secure["peer_roles"], ["server"])
        self.assertEqual(secure["peer_deployment_id"], "lab-a")
        self.assertEqual(secure["peer_serial"], "server_valid")
        self.assertEqual(secure["issuer_id"], "deployment-admin-a")
        self.assertEqual(secure["trust_anchor_id"], "abc123root")
        self.assertEqual(secure["trust_validation_state"], "trusted")
        self.assertEqual(secure["active_material_generation"], 3)
        self.assertEqual(secure["last_material_reload_scope"], "revocation")
        self.assertEqual(secure["last_material_reload_result"], "applied")

    def test_onboarding_connection_profiles_expose_configured_transports(self):
        args = argparse.Namespace(
            admin_web=True,
            admin_web_bind="127.0.0.1",
            admin_web_port=18080,
            admin_web_path="/",
            admin_web_dir="./admin_web",
            admin_web_name="Lab Node",
            overlay_transport=["udp", "ws"],
            secure_link_mode="psk",
            udp_bind="0.0.0.0",
            udp_own_port=16666,
            udp_peer="",
            udp_peer_port=16666,
            ws_bind="0.0.0.0",
            ws_own_port=8080,
            ws_peer="peer.example.net",
            ws_peer_port=8443,
            ws_path="/bridge",
            ws_tls=True,
        )
        ui = AdminWebUI(args, _RunnerStub())
        profiles = ui._build_onboarding_connection_profiles()
        self.assertGreaterEqual(len(profiles), 2)
        labels = [str(item.get("label", "")) for item in profiles]
        self.assertTrue(any("UDP listen" in label for label in labels))
        ws_profiles = [item for item in profiles if item.get("transport") == "ws" and item.get("source") == "config"]
        self.assertEqual(len(ws_profiles), 1)
        self.assertEqual(ws_profiles[0]["role"], "client")
        self.assertEqual(ws_profiles[0]["endpoint_host"], "peer.example.net")
        self.assertEqual(ws_profiles[0]["endpoint_port"], 8443)

    def test_onboarding_invite_roundtrip_and_suggested_updates(self):
        payload = {
            "version": 1,
            "connection": {
                "transport": "tcp",
                "endpoint_host": "bridge.example.net",
                "endpoint_port": 4433,
            },
            "admin_web_name": "Bridge Peer",
            "admin_web_port": 18090,
            "secure_link_mode": "psk",
            "compress_layer": True,
            "compress_layer_algo": "zlib",
            "compress_layer_level": 4,
            "compress_layer_min_bytes": 96,
            "compress_layer_types": "data,data_ack",
            "TUN_routing": {"dns_servers": ["1.1.1.1"]},
            "mux_tcp_bp_threshold": 2,
            "mux_tcp_bp_latency_ms": 250,
            "mux_tcp_bp_poll_interval_ms": 40,
            "proxy_provider": {
                "enabled": True,
                "bind": "127.0.0.1",
                "http_port": 18181,
                "socks5_port": 18182,
                "protocols": ["http-connect", "socks5-connect"],
                "auth": {"mode": "token", "username": "obproxy", "token": "local-token"},
                "egress": {"mode": "direct", "address_families": ["ipv4", "ipv6"]},
                "policy": {"allow_private_destinations": False, "blocked_host_patterns": []},
            },
            "own_servers": [
                {
                    "name": "api",
                    "listen": {"protocol": "tcp", "bind": "0.0.0.0", "port": 8080},
                    "target": {"protocol": "tcp", "host": "127.0.0.1", "port": 8080},
                }
            ],
        }
        token = AdminWebUI._encode_onboarding_token(payload)
        self.assertTrue(token.startswith(AdminWebUI.ONBOARDING_TOKEN_PREFIX))
        parsed = AdminWebUI._decode_onboarding_token(token)
        self.assertEqual(parsed["connection"]["transport"], "tcp")
        updates = AdminWebUI._onboarding_updates_from_invite(parsed)
        self.assertEqual(updates["overlay_transport"], "tcp")
        self.assertEqual(updates["tcp_peer"], "bridge.example.net")
        self.assertEqual(updates["tcp_peer_port"], 4433)
        self.assertEqual(updates["secure_link_mode"], "psk")
        self.assertEqual(updates["admin_web_name"], "Bridge Peer")
        self.assertEqual(updates["admin_web_port"], 18090)
        self.assertTrue(updates["compress_layer"])
        self.assertEqual(updates["compress_layer_algo"], "zlib")
        self.assertEqual(updates["compress_layer_level"], 4)
        self.assertEqual(updates["compress_layer_min_bytes"], 96)
        self.assertEqual(updates["compress_layer_types"], "data,data_ack")
        self.assertEqual(updates["TUN_routing"]["dns_servers"], ["1.1.1.1"])
        self.assertEqual(updates["mux_tcp_bp_threshold"], 2)
        self.assertEqual(updates["mux_tcp_bp_latency_ms"], 250)
        self.assertEqual(updates["mux_tcp_bp_poll_interval_ms"], 40)
        self.assertTrue(updates["proxy_provider"]["enabled"])
        self.assertEqual(updates["proxy_provider"]["http_port"], 18181)
        self.assertEqual(updates["proxy_provider"]["socks5_port"], 18182)
        self.assertEqual(updates["proxy_provider"]["auth"]["username"], "obproxy")
        self.assertIn("own_servers", updates)

    def test_onboarding_blueprints_group_active_peer_connections(self):
        args = argparse.Namespace(
            admin_web=True,
            admin_web_bind="127.0.0.1",
            admin_web_port=18090,
            admin_web_path="/",
            admin_web_dir="./admin_web",
            admin_web_name="Lab Node",
            overlay_transport="udp",
            secure_link_mode="off",
        )

        class _RunnerWithConnections(_RunnerStub):
            def get_connections_snapshot(self):
                return {
                    "udp": [
                        {
                            "peer_id": "2:7",
                            "state": "connected",
                            "local_port": 15000,
                            "remote_destination": {"host": "10.0.0.8", "port": 16000},
                        }
                    ],
                    "tcp": [
                        {
                            "peer_id": "2:7",
                            "state": "connected",
                            "local_port": 25000,
                            "remote_destination": {"host": "10.0.0.8", "port": 26000},
                        }
                    ],
                    "counts": {"udp": 1, "tcp": 1, "udp_listening": 0, "tcp_listening": 0},
                }

        ui = AdminWebUI(args, _RunnerWithConnections())
        blueprints = ui._build_onboarding_blueprints()
        self.assertEqual(len(blueprints), 1)
        self.assertEqual(blueprints[0]["peer_id"], "2:7")
        self.assertEqual(len(blueprints[0]["own_servers"]), 2)

    def test_onboarding_invite_preview_hides_psk_and_updates_keep_plaintext(self):
        args = argparse.Namespace(
            admin_web=True,
            admin_web_bind="127.0.0.1",
            admin_web_port=18090,
            admin_web_path="/",
            admin_web_dir="./admin_web",
            admin_web_name="Lab Node",
            overlay_transport="tcp",
            secure_link_mode="psk",
            secure_link_psk="lab-secret-12345",
            secure_link_require=False,
            mux_tcp_bp_threshold=2,
            mux_tcp_bp_latency_ms=250,
            mux_tcp_bp_poll_interval_ms=40,
            proxy_provider_enabled=True,
            proxy_provider_bind="127.0.0.1",
            proxy_provider_http_port=18181,
            proxy_provider_socks5_port=18182,
            proxy_provider_protocols=["http-connect", "socks5-connect"],
            proxy_provider_auth={"mode": "token", "username": "obproxy", "token": "local-token"},
            proxy_provider_egress={"mode": "direct", "address_families": ["ipv4", "ipv6"]},
            proxy_provider_policy={"allow_private_destinations": False, "blocked_host_patterns": []},
            log_proxy_provider="INFO",
            admin_web_username="admin",
        )
        ui = AdminWebUI(args, _RunnerStub())

        async def run_flow():
            profile_id = str((ui._build_onboarding_connection_profiles() or [{}])[0].get("id", ""))
            generate_writer = _WriterStub()
            await ui._handle_onboarding_invite_generate(
                generate_writer,
                "POST",
                json.dumps(
                    {
                        "connection_id": profile_id,
                        "admin_web_name": "Token Alias",
                        "TUN_routing": {
                            "dns_servers": ["9.9.9.9"],
                            "tunnel_address": ["192.168.250.1"],
                            "tunnel_prefix": 30,
                            "tunnel_gateway": "192.168.250.2",
                        },
                    }
                ).encode("utf-8"),
            )
            generated = _http_json_body(generate_writer)
            self.assertTrue(generated["ok"])
            invite_token = str(generated.get("invite_token", "") or "")
            self.assertTrue(invite_token)
            self.assertEqual(generated["preview"].get("generated_by"), "Token Alias")
            self.assertEqual(generated["preview"].get("admin_web_name"), "Token Alias")
            self.assertEqual(generated["preview"].get("admin_web_port"), 18090)
            self.assertTrue(generated["preview"].get("compress_layer"))
            self.assertEqual(generated["preview"].get("compress_layer_algo"), "zlib")
            self.assertIn("TUN_routing", generated["preview"])
            self.assertEqual(generated["preview"]["TUN_routing"]["dns_servers"], ["9.9.9.9"])
            self.assertEqual(generated["preview"]["TUN_routing"]["tunnel_gateway"], "192.168.250.2")
            self.assertEqual(generated["preview"]["mux_tcp_bp_threshold"], 2)
            self.assertEqual(generated["preview"]["mux_tcp_bp_latency_ms"], 250)
            self.assertEqual(generated["preview"]["mux_tcp_bp_poll_interval_ms"], 40)
            self.assertTrue(generated["preview"]["proxy_provider"]["enabled"])
            self.assertEqual(generated["preview"]["proxy_provider"]["http_port"], 18181)
            self.assertEqual(generated["preview"]["proxy_provider"]["socks5_port"], 18182)
            self.assertEqual(generated["preview"]["proxy_provider"]["auth"]["username"], "obproxy")
            self.assertEqual(generated["preview"]["proxy_provider"]["log_proxy_provider"], "INFO")

            preview_writer = _WriterStub()
            await ui._handle_onboarding_invite_preview(
                preview_writer,
                "POST",
                json.dumps({"invite_token": invite_token}).encode("utf-8"),
            )
            preview = _http_json_body(preview_writer)
            self.assertTrue(preview["ok"])
            self.assertEqual(preview["preview"].get("secure_link_psk"), "***hidden***")
            self.assertTrue(preview["preview"].get("secure_link_psk_present"))
            self.assertEqual(preview["suggested_updates"].get("secure_link_psk"), "lab-secret-12345")
            self.assertEqual(preview["suggested_updates"].get("admin_web_name"), "Token Alias")
            self.assertEqual(preview["suggested_updates"].get("admin_web_port"), 18090)
            self.assertEqual(preview["suggested_updates"]["TUN_routing"]["dns_servers"], ["9.9.9.9"])
            self.assertEqual(preview["suggested_updates"]["mux_tcp_bp_threshold"], 2)
            self.assertEqual(preview["suggested_updates"]["mux_tcp_bp_latency_ms"], 250)
            self.assertEqual(preview["suggested_updates"]["mux_tcp_bp_poll_interval_ms"], 40)
            self.assertTrue(preview["suggested_updates"]["proxy_provider"]["enabled"])
            self.assertEqual(preview["suggested_updates"]["proxy_provider"]["http_port"], 18181)
            self.assertEqual(preview["suggested_updates"]["proxy_provider"]["auth"]["token"], "local-token")

        asyncio.run(run_flow())
