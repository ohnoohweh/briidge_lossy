from __future__ import annotations

import unittest

from obstacle_bridge.bridge_peer_address import PeerAddressProtocolSession


class _FakeInnerSession:
    def __init__(self, *, peer_id: int, observed_host: str) -> None:
        self.peer_id = peer_id
        self.observed_host = observed_host
        self.peer = None
        self.on_app = None
        self.on_state = None

    def connect(self, peer: "_FakeInnerSession") -> None:
        self.peer = peer

    def set_on_app_payload(self, cb) -> None:
        self.on_app = cb

    def set_on_state_change(self, cb) -> None:
        self.on_state = cb

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    def is_connected(self) -> bool:
        return True

    def send_app(self, payload: bytes, peer_id=None) -> int:
        if self.peer is not None and callable(self.peer.on_app):
            delivered_peer_id = self.peer.peer_id if peer_id is None else peer_id
            self.peer.on_app(bytes(payload), peer_id=delivered_peer_id)
        return len(payload)

    def get_overlay_peers_snapshot(self) -> list[dict]:
        return [{"peer_id": self.peer_id, "connected": True, "peer": {"host": self.observed_host, "port": 443}}]

    def get_connection_layers_snapshot(self) -> list[dict]:
        return [{"layer": "transport", "connected": True, "app_ready": True}]


class PeerAddressProtocolSessionTests(unittest.IsolatedAsyncioTestCase):
    async def _reflect(self, observed_host: str, expected: str) -> None:
        client_inner = _FakeInnerSession(peer_id=0, observed_host="203.0.113.20")
        server_inner = _FakeInnerSession(peer_id=7, observed_host=observed_host)
        client_inner.connect(server_inner)
        server_inner.connect(client_inner)
        client = PeerAddressProtocolSession(client_inner, transport_name="tcp", client_mode=True)
        server = PeerAddressProtocolSession(server_inner, transport_name="tcp", client_mode=False)
        delivered: list[bytes] = []
        client.set_on_app_payload(lambda payload, peer_id=None: delivered.append(payload))
        server.set_on_app_payload(lambda payload, peer_id=None: delivered.append(payload))
        await client.start()
        await server.start()

        client._on_inner_state_change(True)

        self.assertEqual(client.get_overlay_peers_snapshot()[0]["observed_public_ip"], expected)
        layer = client.get_connection_layers_snapshot()[-1]
        self.assertEqual(layer["layer"], "peer_address_protocol")
        self.assertEqual(layer["state"], "resolved")
        self.assertEqual(delivered, [])
        client._on_inner_payload(b"ordinary-overlay-payload")
        self.assertEqual(delivered, [b"ordinary-overlay-payload"])

    async def test_server_reflects_observed_ipv4_without_delivering_control_frames(self) -> None:
        await self._reflect("198.51.100.44", "198.51.100.44")

    async def test_server_reflects_observed_ipv6_without_delivering_control_frames(self) -> None:
        await self._reflect("2001:db8::44", "2001:db8::44")

    async def test_server_normalizes_ipv4_mapped_ipv6_to_ipv4(self) -> None:
        await self._reflect("::ffff:198.51.100.44", "198.51.100.44")

    def test_malformed_or_unrelated_frames_are_not_consumed(self) -> None:
        wrapper = PeerAddressProtocolSession(_FakeInnerSession(peer_id=0, observed_host=""), transport_name="ws", client_mode=True)
        self.assertIsNone(wrapper._parse_control_frame(b"OBPA\x01\x02\x04short"))
        self.assertIsNone(wrapper._parse_control_frame(b"not-peer-address"))

    def test_transparent_wrapper_delegates_required_session_methods(self) -> None:
        inner = _FakeInnerSession(peer_id=0, observed_host="198.51.100.44")
        metrics = object()
        inner.get_metrics = lambda: metrics
        inner.get_max_app_payload_size = lambda: 1234
        wrapper = PeerAddressProtocolSession(inner, transport_name="myudp", client_mode=True)

        self.assertTrue(wrapper.is_connected())
        self.assertIs(wrapper.get_metrics(), metrics)
        self.assertEqual(wrapper.get_max_app_payload_size(), 1234)
