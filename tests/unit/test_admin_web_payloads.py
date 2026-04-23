import argparse
import asyncio
import base64
import json
import time
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from obstacle_bridge.bridge import AdminWebUI


class _RunnerStub:
    def __init__(self):
        self.args = argparse.Namespace(
            admin_web_name="Lab Node",
            admin_web_password="admin-secret",
            secure_link_psk="bridge-secret",
        )

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
                }
            ],
        }


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


def _http_json_body(writer: _WriterStub) -> dict:
    return json.loads(writer.buffer.decode("utf-8").split("\r\n\r\n", 1)[1])


class AdminWebPayloadTests(unittest.TestCase):
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
        self.assertEqual(base.name, "admin_web")

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
        self.assertTrue(peer["compress_layer"]["enabled"])
        self.assertEqual(peer["compress_layer"]["algorithm"], "zlib")
        self.assertEqual(peer["compress_layer"]["compress_applied_total"], 7)

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
            "secure_link_mode": "psk",
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
        self.assertIn("own_servers", updates)

    def test_onboarding_blueprints_group_active_peer_connections(self):
        args = argparse.Namespace(
            admin_web=True,
            admin_web_bind="127.0.0.1",
            admin_web_port=18080,
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
            admin_web_port=18080,
            admin_web_path="/",
            admin_web_dir="./admin_web",
            admin_web_name="Lab Node",
            overlay_transport="tcp",
            secure_link_mode="psk",
            secure_link_psk="lab-secret-12345",
            secure_link_require=False,
            admin_web_username="admin",
        )
        ui = AdminWebUI(args, _RunnerStub())

        async def run_flow():
            profile_id = str((ui._build_onboarding_connection_profiles() or [{}])[0].get("id", ""))
            generate_writer = _WriterStub()
            await ui._handle_onboarding_invite_generate(
                generate_writer,
                "POST",
                json.dumps({"connection_id": profile_id}).encode("utf-8"),
            )
            generated = _http_json_body(generate_writer)
            self.assertTrue(generated["ok"])
            invite_token = str(generated.get("invite_token", "") or "")
            self.assertTrue(invite_token)

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

        asyncio.run(run_flow())
