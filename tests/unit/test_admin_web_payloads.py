import argparse
import unittest

from obstacle_bridge.bridge import AdminWebUI


class _RunnerStub:
    def __init__(self):
        self.args = argparse.Namespace(admin_web_name="Lab Node")

    def get_status_snapshot(self):
        return {
            "peer_state": "CONNECTED",
            "secure_link_material_generation": 3,
            "secure_link_last_reload_unix_ts": 1700000100.0,
            "secure_link_last_reload_scope": "revocation",
            "secure_link_last_reload_result": "applied",
            "secure_link_last_reload_detail": "revoked_serials=1",
            "secure_link_peers_dropped_total": 2,
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
                        "authenticated_sessions_total": 1,
                        "rekeys_completed_total": 0,
                        "transport": "tcp",
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


class AdminWebPayloadTests(unittest.TestCase):
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
        self.assertEqual(peer["secure_link"]["state"], "authenticated")
        self.assertEqual(peer["secure_link"]["session_id"], 42)
        self.assertIsNone(peer["secure_link"]["failure_code"])
        self.assertIsNone(peer["secure_link"]["failure_detail"])
        self.assertEqual(peer["secure_link"]["last_rekey_trigger"], "operator")
        self.assertIsNone(peer["secure_link"]["rekey_due_unix_ts"])
        self.assertEqual(peer["secure_link"]["last_event"], "authenticated")
        self.assertEqual(peer["secure_link"]["handshake_attempts_total"], 1)
        self.assertEqual(peer["secure_link"]["authenticated_sessions_total"], 1)

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
