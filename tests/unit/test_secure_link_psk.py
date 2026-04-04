#!/usr/bin/env python3
import argparse
import asyncio
import unittest

from obstacle_bridge.bridge import SecureLinkPskSession


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
        if self._peer is None or not callable(self._peer._on_app):
            return 0
        loop = asyncio.get_running_loop()
        if self._peer._on_peer_rx:
            try:
                self._peer._on_peer_rx(len(payload))
            except Exception:
                pass
        loop.call_soon(self._peer._on_app, bytes(payload))
        return len(payload)

    def set_on_app_payload(self, cb): self._on_app = cb
    def set_on_state_change(self, cb): self._on_state = cb
    def set_on_peer_rx(self, cb): self._on_peer_rx = cb
    def set_on_peer_tx(self, cb): self._on_peer_tx = cb
    def set_on_peer_set(self, cb): self._on_peer_set = cb
    def set_on_peer_disconnect(self, cb): self._on_peer_disconnect = cb
    def set_on_app_from_peer_bytes(self, cb): self._on_app_from_peer_bytes = cb
    def set_on_transport_epoch_change(self, cb): self._on_transport_epoch_change = cb

    def get_metrics(self):
        from obstacle_bridge.bridge import SessionMetrics
        return SessionMetrics()

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
        tcp_peer=None,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


class SecureLinkPskSessionTests(unittest.IsolatedAsyncioTestCase):
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

        self.assertEqual(client.send_app(b"hello-secure"), len(b"hello-secure"))
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        self.assertTrue(server.is_connected())
        self.assertEqual(server_payloads, [b"hello-secure"])

        self.assertEqual(server.send_app(b"world-secure"), len(b"world-secure"))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        self.assertEqual(client_payloads, [b"world-secure"])

        self.assertIn(True, client_states)
        self.assertIn(True, server_states)

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

        self.assertFalse(client.is_connected())
        self.assertFalse(server.is_connected())
        self.assertEqual(client.send_app(b"blocked"), 0)


if __name__ == '__main__':
    unittest.main()
