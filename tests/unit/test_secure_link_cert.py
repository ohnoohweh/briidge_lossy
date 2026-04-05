#!/usr/bin/env python3
import atexit
import argparse
import asyncio
import json
import pathlib
import shutil
import tempfile
import unittest

from obstacle_bridge.bridge import SecureLinkPskSession
from tests.fixtures.secure_link_cert import materialize_secure_link_cert_fixture_set


_FIXTURES_TMPDIR = tempfile.TemporaryDirectory()
atexit.register(_FIXTURES_TMPDIR.cleanup)
FIXTURES = materialize_secure_link_cert_fixture_set(pathlib.Path(_FIXTURES_TMPDIR.name))


class FakeInnerSession:
    def __init__(self, *, connected=False):
        self._peer = None
        self._connected = connected
        self._on_app = None
        self._on_state = None
        self._on_peer_rx = None
        self._on_peer_tx = None
        self._on_peer_set = None
        self._on_peer_disconnect = None
        self._on_app_from_peer_bytes = None
        self._on_transport_epoch_change = None
        self.sent = []
        self._passthrough_enabled = False

    def connect_peer(self, peer):
        self._peer = peer

    async def start(self):
        return None

    async def stop(self):
        self._connected = False
        if callable(self._on_state):
            self._on_state(False)

    async def wait_connected(self, timeout=None):
        return self._connected

    def is_connected(self):
        return self._connected

    def send_app(self, payload: bytes, peer_id=None):
        self.sent.append((bytes(payload), peer_id))
        if self._peer is None or not callable(self._peer._on_app):
            return len(payload)
        loop = asyncio.get_running_loop()
        if self._peer._on_peer_rx:
            try:
                self._peer._on_peer_rx(len(payload))
            except Exception:
                pass
        loop.call_soon(self._peer._on_app, bytes(payload), peer_id)
        return len(payload)

    def set_on_app_payload(self, cb): self._on_app = cb
    def set_on_state_change(self, cb): self._on_state = cb
    def set_on_peer_rx(self, cb): self._on_peer_rx = cb
    def set_on_peer_tx(self, cb): self._on_peer_tx = cb
    def set_on_peer_set(self, cb): self._on_peer_set = cb
    def set_on_peer_disconnect(self, cb): self._on_peer_disconnect = cb
    def set_on_app_from_peer_bytes(self, cb): self._on_app_from_peer_bytes = cb
    def set_on_transport_epoch_change(self, cb): self._on_transport_epoch_change = cb
    def set_app_payload_passthrough(self, enabled: bool): self._passthrough_enabled = bool(enabled)

    def get_metrics(self):
        from obstacle_bridge.bridge import SessionMetrics
        return SessionMetrics()

    def get_overlay_peers_snapshot(self):
        return [{
            "peer_id": 0,
            "connected": bool(self._connected),
            "state": "connected" if self._connected else "connecting",
            "peer": "127.0.0.1:4433",
            "mux_chans": [],
            "rtt_est_ms": None,
        }]

    def emit_state(self, connected: bool):
        self._connected = connected
        if callable(self._on_state):
            self._on_state(connected)


def _args(**overrides):
    base = dict(
        secure_link=True,
        secure_link_mode="cert",
        secure_link_psk="",
        secure_link_require=False,
        secure_link_rekey_after_frames=0,
        secure_link_rekey_after_seconds=0.0,
        secure_link_retry_backoff_initial_ms=1000,
        secure_link_retry_backoff_max_ms=5000,
        secure_link_root_pub=str(FIXTURES / "root_a_pub.pem"),
        secure_link_cert_body=str(FIXTURES / "client_valid_cert_body.json"),
        secure_link_cert_sig=str(FIXTURES / "client_valid_cert.sig"),
        secure_link_private_key=str(FIXTURES / "client_valid_key.pem"),
        secure_link_revoked_serials="",
        secure_link_cert_reload_on_restart=True,
        tcp_peer=None,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


class SecureLinkCertSessionTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _pack_mux(chan_id: int, data: bytes, *, counter: int = 1) -> bytes:
        from obstacle_bridge.bridge import ChannelMux
        hdr = ChannelMux.MUX_HDR
        return hdr.pack(chan_id, 1, counter, 1, len(data)) + data

    async def _start_pair(self, client_args: argparse.Namespace, server_args: argparse.Namespace):
        client_inner = FakeInnerSession()
        server_inner = FakeInnerSession()
        client_inner.connect_peer(server_inner)
        server_inner.connect_peer(client_inner)
        client = SecureLinkPskSession(client_inner, client_args, "tcp")
        server = SecureLinkPskSession(server_inner, server_args, "tcp")
        await client.start()
        await server.start()
        server_inner.emit_state(True)
        client_inner.emit_state(True)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        return client, server, client_inner, server_inner

    def _copy_fixture_dir(self) -> pathlib.Path:
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        root = pathlib.Path(tmpdir.name)
        for item in FIXTURES.iterdir():
            if item.is_file():
                shutil.copy2(item, root / item.name)
        return root

    async def test_cert_mode_happy_path_authenticates_and_exposes_peer_identity(self):
        client, server, _client_inner, _server_inner = await self._start_pair(
            _args(
                tcp_peer="127.0.0.1",
                secure_link_cert_body=str(FIXTURES / "client_valid_cert_body.json"),
                secure_link_cert_sig=str(FIXTURES / "client_valid_cert.sig"),
                secure_link_private_key=str(FIXTURES / "client_valid_key.pem"),
            ),
            _args(
                secure_link_cert_body=str(FIXTURES / "server_valid_cert_body.json"),
                secure_link_cert_sig=str(FIXTURES / "server_valid_cert.sig"),
                secure_link_private_key=str(FIXTURES / "server_valid_key.pem"),
            ),
        )

        server_payloads = []
        client_payloads = []
        server.set_on_app_payload(lambda payload, peer_id=None: server_payloads.append(payload))
        client.set_on_app_payload(lambda payload, peer_id=None: client_payloads.append(payload))

        hello_mux = self._pack_mux(11, b"hello-cert")
        self.assertEqual(client.send_app(hello_mux), len(hello_mux))
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        self.assertTrue(client.is_connected())
        self.assertTrue(server.is_connected())
        self.assertEqual(server_payloads, [hello_mux])

        reply_mux = self._pack_mux(11, b"world-cert", counter=2)
        self.assertEqual(server.send_app(reply_mux, peer_id=1), len(reply_mux))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        self.assertEqual(client_payloads, [reply_mux])

        client_peer = client.get_overlay_peers_snapshot()[0]["secure_link"]
        server_status = server.get_secure_link_status_snapshot()
        self.assertEqual(client_peer["mode"], "cert")
        self.assertEqual(client_peer["state"], "authenticated")
        self.assertEqual(client_peer["trust_validation_state"], "trusted")
        self.assertEqual(client_peer["peer_subject_id"], "bridge-server-01")
        self.assertEqual(client_peer["peer_subject_name"], "Bridge Server 01")
        self.assertEqual(client_peer["peer_roles"], ["server"])
        self.assertEqual(client_peer["peer_deployment_id"], "lab-a")
        self.assertEqual(client_peer["peer_serial"], "server_valid")
        self.assertEqual(client_peer["issuer_id"], "deployment-admin-a")
        self.assertTrue(client_peer["trust_anchor_id"])
        self.assertEqual(server_status["peer_subject_id"], "bridge-client-01")
        self.assertEqual(server_status["peer_roles"], ["client"])

        client_status = client.get_secure_link_status_snapshot()
        self.assertEqual(client_status["mode"], "cert")
        self.assertEqual(client_status["state"], "authenticated")
        self.assertEqual(client_status["peer_subject_id"], "bridge-server-01")
        self.assertEqual(client_status["trust_validation_state"], "trusted")

    async def test_cert_mode_root_mismatch_fails_closed(self):
        client, server, _client_inner, _server_inner = await self._start_pair(
            _args(
                tcp_peer="127.0.0.1",
                secure_link_root_pub=str(FIXTURES / "root_b_pub.pem"),
                secure_link_cert_body=str(FIXTURES / "client_root_b_cert_body.json"),
                secure_link_cert_sig=str(FIXTURES / "client_root_b_cert.sig"),
                secure_link_private_key=str(FIXTURES / "client_root_b_key.pem"),
            ),
            _args(
                secure_link_cert_body=str(FIXTURES / "server_valid_cert_body.json"),
                secure_link_cert_sig=str(FIXTURES / "server_valid_cert.sig"),
                secure_link_private_key=str(FIXTURES / "server_valid_key.pem"),
            ),
        )

        await asyncio.sleep(0)
        await asyncio.sleep(0)
        self.assertFalse(client.is_connected())
        self.assertFalse(server.is_connected())
        self.assertEqual(client.send_app(b"blocked"), 0)

        client_status = client.get_secure_link_status_snapshot()
        self.assertEqual(client_status["state"], "failed")
        self.assertEqual(client_status["failure_reason"], "unknown_root")
        self.assertEqual(client_status["trust_validation_state"], "failed")
        self.assertEqual(client_status["trust_failure_reason"], "unknown_root")

    async def test_cert_mode_wrong_role_is_rejected(self):
        client, _server, _client_inner, _server_inner = await self._start_pair(
            _args(
                tcp_peer="127.0.0.1",
                secure_link_cert_body=str(FIXTURES / "client_wrong_role_cert_body.json"),
                secure_link_cert_sig=str(FIXTURES / "client_wrong_role_cert.sig"),
                secure_link_private_key=str(FIXTURES / "client_wrong_role_key.pem"),
            ),
            _args(
                secure_link_cert_body=str(FIXTURES / "server_valid_cert_body.json"),
                secure_link_cert_sig=str(FIXTURES / "server_valid_cert.sig"),
                secure_link_private_key=str(FIXTURES / "server_valid_key.pem"),
            ),
        )
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        status = client.get_secure_link_status_snapshot()
        self.assertEqual(status["state"], "failed")
        self.assertEqual(status["failure_reason"], "wrong_role")

    async def test_cert_mode_expired_not_yet_valid_and_deployment_mismatch_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "expired"):
            SecureLinkPskSession(
                FakeInnerSession(),
                _args(
                    tcp_peer="127.0.0.1",
                    secure_link_cert_body=str(FIXTURES / "client_expired_cert_body.json"),
                    secure_link_cert_sig=str(FIXTURES / "client_expired_cert.sig"),
                    secure_link_private_key=str(FIXTURES / "client_expired_key.pem"),
                ),
                "tcp",
            )
        with self.assertRaisesRegex(ValueError, "not valid yet"):
            SecureLinkPskSession(
                FakeInnerSession(),
                _args(
                    tcp_peer="127.0.0.1",
                    secure_link_cert_body=str(FIXTURES / "client_future_cert_body.json"),
                    secure_link_cert_sig=str(FIXTURES / "client_future_cert.sig"),
                    secure_link_private_key=str(FIXTURES / "client_future_key.pem"),
                ),
                "tcp",
            )

        client, _server, _client_inner, _server_inner = await self._start_pair(
            _args(
                tcp_peer="127.0.0.1",
                secure_link_cert_body=str(FIXTURES / "client_other_deploy_cert_body.json"),
                secure_link_cert_sig=str(FIXTURES / "client_other_deploy_cert.sig"),
                secure_link_private_key=str(FIXTURES / "client_other_deploy_key.pem"),
            ),
            _args(
                secure_link_cert_body=str(FIXTURES / "server_valid_cert_body.json"),
                secure_link_cert_sig=str(FIXTURES / "server_valid_cert.sig"),
                secure_link_private_key=str(FIXTURES / "server_valid_key.pem"),
            ),
        )
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        status = client.get_secure_link_status_snapshot()
        self.assertEqual(status["state"], "failed")
        self.assertEqual(status["failure_reason"], "deployment_mismatch")

    async def test_cert_mode_revoked_serial_is_rejected(self):
        client, _server, _client_inner, _server_inner = await self._start_pair(
            _args(
                tcp_peer="127.0.0.1",
                secure_link_cert_body=str(FIXTURES / "client_valid_cert_body.json"),
                secure_link_cert_sig=str(FIXTURES / "client_valid_cert.sig"),
                secure_link_private_key=str(FIXTURES / "client_valid_key.pem"),
            ),
            _args(
                secure_link_cert_body=str(FIXTURES / "server_valid_cert_body.json"),
                secure_link_cert_sig=str(FIXTURES / "server_valid_cert.sig"),
                secure_link_private_key=str(FIXTURES / "server_valid_key.pem"),
                secure_link_revoked_serials=str(FIXTURES / "revoked_serials.json"),
            ),
        )
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        status = client.get_secure_link_status_snapshot()
        self.assertEqual(status["state"], "failed")
        self.assertEqual(status["failure_reason"], "revoked_serial")

    async def test_cert_mode_operator_rekey_rotates_session(self):
        client, server, _client_inner, _server_inner = await self._start_pair(
            _args(
                tcp_peer="127.0.0.1",
                secure_link_cert_body=str(FIXTURES / "client_valid_cert_body.json"),
                secure_link_cert_sig=str(FIXTURES / "client_valid_cert.sig"),
                secure_link_private_key=str(FIXTURES / "client_valid_key.pem"),
            ),
            _args(
                secure_link_cert_body=str(FIXTURES / "server_valid_cert_body.json"),
                secure_link_cert_sig=str(FIXTURES / "server_valid_cert.sig"),
                secure_link_private_key=str(FIXTURES / "server_valid_key.pem"),
            ),
        )

        first_mux = self._pack_mux(11, b"prime-cert-rekey")
        self.assertEqual(client.send_app(first_mux), len(first_mux))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        old_session_id = client.get_overlay_peers_snapshot()[0]["secure_link"]["session_id"]

        ok, reason = client.request_secure_link_rekey()
        self.assertTrue(ok)
        self.assertEqual(reason, "rekey_started")
        for _ in range(8):
            await asyncio.sleep(0)
            if client.get_overlay_peers_snapshot()[0]["secure_link"]["session_id"] != old_session_id:
                break

        new_session_id = client.get_overlay_peers_snapshot()[0]["secure_link"]["session_id"]
        self.assertNotEqual(old_session_id, new_session_id)
        self.assertEqual(client.get_secure_link_status_snapshot()["last_event"], "rekey_completed")
        self.assertGreaterEqual(client.get_secure_link_status_snapshot()["rekeys_completed_total"], 1)
        self.assertTrue(server.is_connected())

    async def test_revocation_reload_drops_existing_authenticated_peer(self):
        temp_root = self._copy_fixture_dir()
        revoked_path = temp_root / "revoked_runtime.json"
        revoked_path.write_text("[]\n", encoding="utf-8")
        client, server, _client_inner, _server_inner = await self._start_pair(
            _args(
                tcp_peer="127.0.0.1",
                secure_link_cert_body=str(temp_root / "client_valid_cert_body.json"),
                secure_link_cert_sig=str(temp_root / "client_valid_cert.sig"),
                secure_link_private_key=str(temp_root / "client_valid_key.pem"),
                secure_link_revoked_serials=str(revoked_path),
            ),
            _args(
                secure_link_cert_body=str(temp_root / "server_valid_cert_body.json"),
                secure_link_cert_sig=str(temp_root / "server_valid_cert.sig"),
                secure_link_private_key=str(temp_root / "server_valid_key.pem"),
                secure_link_revoked_serials=str(revoked_path),
            ),
        )

        first_mux = self._pack_mux(11, b"prime-cert-reload")
        self.assertEqual(client.send_app(first_mux), len(first_mux))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        self.assertTrue(client.is_connected())
        revoked_path.write_text(json.dumps(["client_valid"]), encoding="utf-8")

        result = server.request_secure_link_reload(scope="revocation")
        self.assertTrue(result["ok"])
        self.assertEqual(result["scope"], "revocation")
        self.assertEqual(result["dropped"], 1)

        await asyncio.sleep(0)
        await asyncio.sleep(0)
        server_peer = server.get_secure_link_status_snapshot()
        self.assertEqual(server_peer["state"], "failed")
        self.assertEqual(server_peer["trust_failure_reason"], "revoked_serial")
        self.assertEqual(server_peer["disconnect_reason"], "revocation_applied")
        self.assertEqual(server_peer["last_material_reload_scope"], "revocation")
        self.assertEqual(server_peer["last_material_reload_result"], "applied")
        self.assertGreaterEqual(int(server_peer["active_material_generation"] or 0), 2)

    async def test_local_identity_reload_failure_is_atomic(self):
        temp_root = self._copy_fixture_dir()
        client, server, _client_inner, _server_inner = await self._start_pair(
            _args(
                tcp_peer="127.0.0.1",
                secure_link_cert_body=str(temp_root / "client_valid_cert_body.json"),
                secure_link_cert_sig=str(temp_root / "client_valid_cert.sig"),
                secure_link_private_key=str(temp_root / "client_valid_key.pem"),
                secure_link_retry_backoff_initial_ms=0,
                secure_link_retry_backoff_max_ms=0,
            ),
            _args(
                secure_link_cert_body=str(temp_root / "server_valid_cert_body.json"),
                secure_link_cert_sig=str(temp_root / "server_valid_cert.sig"),
                secure_link_private_key=str(temp_root / "server_valid_key.pem"),
            ),
        )
        before_state = client.get_secure_link_status_snapshot()["state"]
        bad_cert_body = temp_root / "client_valid_cert_body.json"
        bad_cert_body.write_text("{bad json", encoding="utf-8")
        result = client.request_secure_link_reload(scope="local_identity")
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "reload_failed")
        self.assertEqual(client.get_secure_link_status_snapshot()["last_material_reload_result"], "failed")
        self.assertEqual(client.get_secure_link_status_snapshot()["active_material_generation"], 1)
        self.assertEqual(client.get_secure_link_status_snapshot()["state"], before_state)

    async def test_local_identity_reload_applies_and_reauthenticates(self):
        temp_root = self._copy_fixture_dir()
        client, server, _client_inner, _server_inner = await self._start_pair(
            _args(
                tcp_peer="127.0.0.1",
                secure_link_cert_body=str(temp_root / "client_valid_cert_body.json"),
                secure_link_cert_sig=str(temp_root / "client_valid_cert.sig"),
                secure_link_private_key=str(temp_root / "client_valid_key.pem"),
            ),
            _args(
                secure_link_cert_body=str(temp_root / "server_valid_cert_body.json"),
                secure_link_cert_sig=str(temp_root / "server_valid_cert.sig"),
                secure_link_private_key=str(temp_root / "server_valid_key.pem"),
            ),
        )
        first_mux = self._pack_mux(11, b"prime-cert-local-reload")
        self.assertEqual(client.send_app(first_mux), len(first_mux))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        old_generation = int(client.get_secure_link_status_snapshot()["active_material_generation"] or 0)
        old_sessions = int(client.get_secure_link_status_snapshot()["authenticated_sessions_total"] or 0)

        result = client.request_secure_link_reload(scope="local_identity")
        self.assertTrue(result["ok"])
        self.assertEqual(result["scope"], "local_identity")
        self.assertGreaterEqual(result["dropped"], 1)

        status = client.get_secure_link_status_snapshot()
        self.assertEqual(status["last_material_reload_scope"], "local_identity")
        self.assertEqual(status["last_material_reload_result"], "applied")
        self.assertGreater(int(status["active_material_generation"] or 0), old_generation)
        self.assertEqual(status["disconnect_reason"], "local_identity_reloaded")
        self.assertGreaterEqual(int(status["authenticated_sessions_total"] or 0), old_sessions)


if __name__ == "__main__":
    unittest.main()
