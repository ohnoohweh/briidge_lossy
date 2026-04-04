import argparse
import unittest

from obstacle_bridge.bridge import AdminWebUI


class _RunnerStub:
    def __init__(self):
        self.args = argparse.Namespace(admin_web_name="Lab Node")

    def get_status_snapshot(self):
        return {
            "peer_state": "CONNECTED",
            "secure_link": {
                "enabled": True,
                "mode": "psk",
                "state": "authenticated",
                "authenticated": True,
                "authenticated_peers": 1,
                "failure_code": None,
                "failure_reason": None,
                "failure_detail": None,
                "failure_unix_ts": None,
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
                        "failure_code": None,
                        "failure_reason": None,
                        "failure_detail": None,
                        "failure_unix_ts": None,
                        "transport": "tcp",
                    },
                }
            ],
        }


class AdminWebPayloadTests(unittest.TestCase):
    def test_build_status_payload_includes_secure_link_summary(self):
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
        self.assertIn("secure_link", payload)
        self.assertEqual(payload["secure_link"]["state"], "authenticated")
        self.assertTrue(payload["secure_link"]["authenticated"])
        self.assertIsNone(payload["secure_link"]["failure_code"])
        self.assertIsNone(payload["secure_link"]["failure_detail"])
        self.assertEqual(payload["admin_web_name"], "Lab Node")

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
