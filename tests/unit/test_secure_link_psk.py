#!/usr/bin/env python3
import argparse
import asyncio
import unittest

from obstacle_bridge.bridge import ChaCha20Poly1305, SecureLinkPskSession


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
        secure_link_mode='psk',
        secure_link_psk='lab-secret',
        secure_link_require=False,
        secure_link_rekey_after_frames=0,
        tcp_peer=None,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


class SecureLinkPskSessionTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _pack_mux(chan_id: int, data: bytes, *, counter: int = 1) -> bytes:
        from obstacle_bridge.bridge import ChannelMux
        hdr = ChannelMux.MUX_HDR
        return hdr.pack(chan_id, 1, counter, 1, len(data)) + data

    @staticmethod
    def _unpack_mux(payload: bytes):
        from obstacle_bridge.bridge import ChannelMux
        hdr = ChannelMux.MUX_HDR
        chan_id, proto, counter, mtype, dlen = hdr.unpack(payload[:hdr.size])
        return chan_id, proto, counter, mtype, payload[hdr.size:hdr.size + dlen]

    async def test_psk_handshake_and_protected_data_flow_over_wrapped_inner_session(self):
        client_inner = FakeInnerSession()
        server_inner = FakeInnerSession()
        client_inner.connect_peer(server_inner)
        server_inner.connect_peer(client_inner)

        client = SecureLinkPskSession(client_inner, _args(tcp_peer='127.0.0.1'), 'tcp')
        server = SecureLinkPskSession(server_inner, _args(), 'tcp')

        client_states = []
        server_states = []
        server_payloads = []
        client_payloads = []

        client.set_on_state_change(client_states.append)
        server.set_on_state_change(server_states.append)
        server.set_on_app_payload(lambda payload, peer_id=None: server_payloads.append(payload))
        client.set_on_app_payload(lambda payload, peer_id=None: client_payloads.append(payload))

        await client.start()
        await server.start()

        server_inner.emit_state(True)
        client_inner.emit_state(True)
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        self.assertTrue(client.is_connected())
        self.assertFalse(server.is_connected())

        hello_mux = self._pack_mux(11, b"hello-secure")
        self.assertEqual(client.send_app(hello_mux), len(hello_mux))
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        self.assertTrue(server.is_connected())
        self.assertEqual(server_payloads, [hello_mux])

        reply_mux = self._pack_mux(11, b"world-secure", counter=2)
        self.assertEqual(server.send_app(reply_mux, peer_id=1), len(reply_mux))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        self.assertEqual(client_payloads, [reply_mux])

        self.assertIn(True, client_states)
        self.assertIn(True, server_states)
        client_peer = client.get_overlay_peers_snapshot()[0]
        self.assertEqual(client_peer["secure_link"]["state"], "authenticated")
        self.assertTrue(client_peer["secure_link"]["authenticated"])
        self.assertIsNone(client_peer["secure_link"]["failure_code"])
        self.assertIsNone(client_peer["secure_link"]["failure_detail"])
        self.assertEqual(client.get_secure_link_status_snapshot()["state"], "authenticated")
        self.assertEqual(server.get_secure_link_status_snapshot()["state"], "authenticated")

    async def test_wrong_psk_prevents_authenticated_session(self):
        client_inner = FakeInnerSession()
        server_inner = FakeInnerSession()
        client_inner.connect_peer(server_inner)
        server_inner.connect_peer(client_inner)

        client = SecureLinkPskSession(client_inner, _args(tcp_peer='127.0.0.1', secure_link_psk='client-secret'), 'tcp')
        server = SecureLinkPskSession(server_inner, _args(secure_link_psk='server-secret'), 'tcp')

        await client.start()
        await server.start()

        server_inner.emit_state(True)
        client_inner.emit_state(True)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        self.assertFalse(client.is_connected())
        self.assertFalse(server.is_connected())
        self.assertEqual(client.send_app(b"blocked"), 0)
        client_peer = client.get_overlay_peers_snapshot()[0]
        self.assertEqual(client_peer["secure_link"]["state"], "failed")
        self.assertEqual(client_peer["secure_link"]["failure_code"], 1)
        self.assertEqual(client_peer["secure_link"]["failure_reason"], "bad_psk")
        self.assertIn("pre-shared secret mismatch", client_peer["secure_link"]["failure_detail"])
        self.assertIsNotNone(client_peer["secure_link"]["failure_unix_ts"])
        self.assertEqual(client.get_secure_link_status_snapshot()["state"], "failed")
        self.assertEqual(client.get_secure_link_status_snapshot()["failure_code"], 1)
        self.assertEqual(client.get_secure_link_status_snapshot()["failure_reason"], "bad_psk")
        self.assertIn("pre-shared secret mismatch", client.get_secure_link_status_snapshot()["failure_detail"])
        self.assertIsNotNone(client.get_secure_link_status_snapshot()["failure_unix_ts"])

    async def test_server_rewrites_mux_channels_per_peer_for_multiple_connections(self):
        server_inner = FakeInnerSession(connected=True)
        server = SecureLinkPskSession(server_inner, _args(), 'tcp')
        delivered = []
        server.set_on_app_payload(lambda payload, peer_id=None: delivered.append((payload, peer_id)))

        await server.start()

        async def handshake(peer_id: int, session_id: int, client_nonce: bytes) -> None:
            hello = server._build_frame(server._SL_TYPE_CLIENT_HELLO, session_id, 0, client_nonce + bytes([server._SL_CAP_PSK_V1, 0]))
            server._on_inner_payload(hello, peer_id=peer_id)
            await asyncio.sleep(0)
            state = server._peer_states[peer_id]
            server_nonce = state.server_nonce
            c2s_key, s2c_key = server._derive_keys(session_id, client_nonce, server_nonce)
            encrypted = ChaCha20Poly1305(c2s_key).encrypt(
                server._nonce(1),
                self._pack_mux(11, f"peer-{peer_id}".encode("ascii")),
                server._hdr_bytes(server._SL_TYPE_DATA, session_id, 1),
            )
            server._on_inner_payload(server._hdr_bytes(server._SL_TYPE_DATA, session_id, 1) + encrypted, peer_id=peer_id)
            await asyncio.sleep(0)
            return s2c_key

        s2c_key_1 = await handshake(101, 5001, b"a" * 32)
        s2c_key_2 = await handshake(202, 5002, b"c" * 32)

        self.assertEqual([peer_id for _payload, peer_id in delivered], [101, 202])
        chan1, _proto1, _ctr1, _mt1, body1 = self._unpack_mux(delivered[0][0])
        chan2, _proto2, _ctr2, _mt2, body2 = self._unpack_mux(delivered[1][0])
        self.assertEqual(body1, b"peer-101")
        self.assertEqual(body2, b"peer-202")
        self.assertNotEqual(chan1, chan2)

        reply1 = self._pack_mux(chan1, b"reply-1", counter=2)
        reply2 = self._pack_mux(chan2, b"reply-2", counter=2)
        self.assertEqual(server.send_app(reply1), len(reply1))
        self.assertEqual(server.send_app(reply2), len(reply2))

        sent_data = [(payload, peer_id) for payload, peer_id in server_inner.sent if server._parse_frame(payload)[0] == server._SL_TYPE_DATA]
        self.assertEqual([peer_id for _payload, peer_id in sent_data], [101, 202])

        payload1, peer_id1 = sent_data[0]
        payload2, peer_id2 = sent_data[1]
        sl_type1, session_id1, counter1, body_enc1 = server._parse_frame(payload1)
        sl_type2, session_id2, counter2, body_enc2 = server._parse_frame(payload2)
        self.assertEqual((sl_type1, session_id1, peer_id1), (server._SL_TYPE_DATA, 5001, 101))
        self.assertEqual((sl_type2, session_id2, peer_id2), (server._SL_TYPE_DATA, 5002, 202))

        plain1 = ChaCha20Poly1305(s2c_key_1).decrypt(server._nonce(counter1), body_enc1, server._hdr_bytes(server._SL_TYPE_DATA, session_id1, counter1))
        plain2 = ChaCha20Poly1305(s2c_key_2).decrypt(server._nonce(counter2), body_enc2, server._hdr_bytes(server._SL_TYPE_DATA, session_id2, counter2))
        out_chan1, _proto1, _ctr1, _mt1, out_body1 = self._unpack_mux(plain1)
        out_chan2, _proto2, _ctr2, _mt2, out_body2 = self._unpack_mux(plain2)
        self.assertEqual((out_chan1, out_body1), (11, b"reply-1"))
        self.assertEqual((out_chan2, out_body2), (11, b"reply-2"))

    async def test_psk_rekey_rotates_session_id_and_keeps_data_flowing(self):
        client_inner = FakeInnerSession()
        server_inner = FakeInnerSession()
        client_inner.connect_peer(server_inner)
        server_inner.connect_peer(client_inner)

        client = SecureLinkPskSession(client_inner, _args(tcp_peer='127.0.0.1', secure_link_rekey_after_frames=1), 'tcp')
        server = SecureLinkPskSession(server_inner, _args(), 'tcp')

        server_payloads = []
        client_payloads = []
        server.set_on_app_payload(lambda payload, peer_id=None: server_payloads.append(payload))
        client.set_on_app_payload(lambda payload, peer_id=None: client_payloads.append(payload))

        await client.start()
        await server.start()

        server_inner.emit_state(True)
        client_inner.emit_state(True)
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        first_mux = self._pack_mux(11, b"before-rekey")
        self.assertEqual(client.send_app(first_mux), len(first_mux))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        old_session_id = client.get_overlay_peers_snapshot()[0]["secure_link"]["session_id"]
        self.assertTrue(client.get_secure_link_status_snapshot()["rekey_in_progress"])

        await asyncio.sleep(0)
        await asyncio.sleep(0)
        self.assertFalse(client.get_secure_link_status_snapshot()["rekey_in_progress"])
        new_session_id = client.get_overlay_peers_snapshot()[0]["secure_link"]["session_id"]
        self.assertNotEqual(old_session_id, new_session_id)

        second_mux = self._pack_mux(11, b"after-rekey", counter=2)
        self.assertEqual(client.send_app(second_mux), len(second_mux))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        self.assertEqual(server_payloads, [first_mux, second_mux])

        reply_mux = self._pack_mux(11, b"server-after-rekey", counter=3)
        self.assertEqual(server.send_app(reply_mux, peer_id=1), len(reply_mux))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        self.assertEqual(client_payloads, [reply_mux])

    async def test_data_counter_zero_is_rejected_as_lifecycle_violation(self):
        client_inner = FakeInnerSession()
        server_inner = FakeInnerSession()
        client_inner.connect_peer(server_inner)
        server_inner.connect_peer(client_inner)

        client = SecureLinkPskSession(client_inner, _args(tcp_peer='127.0.0.1'), 'tcp')
        server = SecureLinkPskSession(server_inner, _args(), 'tcp')

        await client.start()
        await server.start()

        server_inner.emit_state(True)
        client_inner.emit_state(True)
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        state = client._peer_states[0]
        bad_payload = self._pack_mux(11, b"bad-counter")
        aad = client._hdr_bytes(client._SL_TYPE_DATA, state.session_id, 0)
        ciphertext = ChaCha20Poly1305(state.c2s_key).encrypt(client._nonce(0), bad_payload, aad)
        server._on_inner_payload(aad + ciphertext, peer_id=1)
        await asyncio.sleep(0)

        server_status = server.get_secure_link_status_snapshot()
        self.assertEqual(server_status["state"], "failed")
        self.assertEqual(server_status["failure_code"], client._SL_AUTH_FAIL_LIFECYCLE)
        self.assertEqual(server_status["failure_reason"], "lifecycle")

    async def test_counter_exhaustion_fails_closed_before_nonce_wrap(self):
        client_inner = FakeInnerSession()
        server_inner = FakeInnerSession()
        client_inner.connect_peer(server_inner)
        server_inner.connect_peer(client_inner)

        client = SecureLinkPskSession(client_inner, _args(tcp_peer='127.0.0.1'), 'tcp')
        server = SecureLinkPskSession(server_inner, _args(), 'tcp')

        await client.start()
        await server.start()

        server_inner.emit_state(True)
        client_inner.emit_state(True)
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        state = client._peer_states[0]
        state.tx_counter = client._SL_MAX_DATA_COUNTER + 1
        self.assertEqual(client.send_app(self._pack_mux(11, b"too-late")), 0)

        client_peer = client.get_overlay_peers_snapshot()[0]
        self.assertEqual(client_peer["secure_link"]["state"], "failed")
        self.assertEqual(client_peer["secure_link"]["failure_code"], client._SL_AUTH_FAIL_LIFECYCLE)
        self.assertEqual(client_peer["secure_link"]["failure_reason"], "lifecycle")
        self.assertIn("lifecycle invariant", client_peer["secure_link"]["failure_detail"])

    async def test_malformed_frame_after_authentication_fails_closed(self):
        client_inner = FakeInnerSession()
        server_inner = FakeInnerSession()
        client_inner.connect_peer(server_inner)
        server_inner.connect_peer(client_inner)

        client = SecureLinkPskSession(client_inner, _args(tcp_peer='127.0.0.1'), 'tcp')
        server = SecureLinkPskSession(server_inner, _args(), 'tcp')

        await client.start()
        await server.start()

        server_inner.emit_state(True)
        client_inner.emit_state(True)
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        first_mux = self._pack_mux(11, b"healthy")
        self.assertEqual(client.send_app(first_mux), len(first_mux))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        self.assertTrue(server.is_connected())

        server._on_inner_payload(b"\x01\x02\x03", peer_id=1)
        await asyncio.sleep(0)

        server_status = server.get_secure_link_status_snapshot()
        self.assertEqual(server_status["state"], "failed")
        self.assertEqual(server_status["failure_code"], server._SL_AUTH_FAIL_DECODE)
        self.assertEqual(server_status["failure_reason"], "decode")
        self.assertFalse(server.is_connected())
        self.assertEqual(server.send_app(self._pack_mux(11, b"blocked"), peer_id=1), 0)

    async def test_unexpected_rekey_commit_fails_closed(self):
        client_inner = FakeInnerSession()
        server_inner = FakeInnerSession()
        client_inner.connect_peer(server_inner)
        server_inner.connect_peer(client_inner)

        client = SecureLinkPskSession(client_inner, _args(tcp_peer='127.0.0.1'), 'tcp')
        server = SecureLinkPskSession(server_inner, _args(), 'tcp')

        await client.start()
        await server.start()

        server_inner.emit_state(True)
        client_inner.emit_state(True)
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        self.assertEqual(client.send_app(self._pack_mux(11, b"healthy")), len(self._pack_mux(11, b"healthy")))
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        state = server._peer_states[1]
        bogus_commit = server._build_frame(server._SL_TYPE_REKEY_COMMIT, state.session_id, 0, b"bogus")
        server._on_inner_payload(bogus_commit, peer_id=1)
        await asyncio.sleep(0)

        server_status = server.get_secure_link_status_snapshot()
        self.assertEqual(server_status["state"], "failed")
        self.assertEqual(server_status["failure_code"], server._SL_AUTH_FAIL_DECODE)
        self.assertEqual(server_status["failure_reason"], "decode")
        self.assertFalse(server.is_connected())

    async def test_auth_failure_unregisters_server_mux_routes(self):
        server_inner = FakeInnerSession(connected=True)
        server = SecureLinkPskSession(server_inner, _args(), 'tcp')
        delivered = []
        server.set_on_app_payload(lambda payload, peer_id=None: delivered.append((payload, peer_id)))

        await server.start()

        hello = server._build_frame(server._SL_TYPE_CLIENT_HELLO, 5001, 0, b"a" * 32 + bytes([server._SL_CAP_PSK_V1, 0]))
        server._on_inner_payload(hello, peer_id=101)
        await asyncio.sleep(0)
        state = server._peer_states[101]
        encrypted = ChaCha20Poly1305(state.c2s_key).encrypt(
            server._nonce(1),
            self._pack_mux(11, b"peer-101"),
            server._hdr_bytes(server._SL_TYPE_DATA, 5001, 1),
        )
        server._on_inner_payload(server._hdr_bytes(server._SL_TYPE_DATA, 5001, 1) + encrypted, peer_id=101)
        await asyncio.sleep(0)
        self.assertTrue(server._server_chan_to_peer)
        self.assertTrue(server._server_peer_chan_to_mux)

        server._on_inner_payload(b"\x00", peer_id=101)
        await asyncio.sleep(0)

        self.assertFalse(server._server_chan_to_peer)
        self.assertFalse(server._server_peer_chan_to_mux)


if __name__ == '__main__':
    unittest.main()
