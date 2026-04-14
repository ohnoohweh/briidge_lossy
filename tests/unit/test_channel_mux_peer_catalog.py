#!/usr/bin/env python3
import asyncio
import unittest
from unittest import mock

from obstacle_bridge.bridge import ChannelMux


class _FakeSession:
    def __init__(self):
        self.app_cb = None
        self.peer_disconnect_cb = None

    def is_connected(self):
        return False

    def set_on_app_payload(self, cb):
        self.app_cb = cb

    def set_on_peer_disconnect(self, cb):
        self.peer_disconnect_cb = cb

    def send_app(self, payload):
        return len(payload)


class ChannelMuxPeerCatalogTests(unittest.IsolatedAsyncioTestCase):
    async def test_peer_catalog_state_is_scoped_by_peer_id(self):
        session = _FakeSession()
        mux = ChannelMux(session, asyncio.get_running_loop())
        svc = ChannelMux.ServiceSpec(
            svc_id=1,
            l_proto="udp",
            l_bind="127.0.0.1",
            l_port=10001,
            r_proto="udp",
            r_host="127.0.0.1",
            r_port=20001,
        )

        await mux._apply_peer_installed_services([svc], peer_id=11)
        await mux._apply_peer_installed_services([svc], peer_id=22)

        self.assertIn(("peer", 11, 1), mux._peer_installed_services)
        self.assertIn(("peer", 22, 1), mux._peer_installed_services)

        await mux._drop_peer_installed_services(peer_id=11)
        self.assertNotIn(("peer", 11, 1), mux._peer_installed_services)
        self.assertIn(("peer", 22, 1), mux._peer_installed_services)

    async def test_peer_disconnect_closes_tcp_udp_listeners_for_that_peer(self):
        session = _FakeSession()
        mux = ChannelMux(session, asyncio.get_running_loop())
        udp_spec = ChannelMux.ServiceSpec(1, "udp", "127.0.0.1", 10001, "udp", "127.0.0.1", 20001)
        tcp_spec = ChannelMux.ServiceSpec(2, "tcp", "127.0.0.1", 10002, "tcp", "127.0.0.1", 20002)
        mux._peer_installed_services = {
            ("peer", 11, 1): udp_spec,
            ("peer", 11, 2): tcp_spec,
            ("peer", 22, 1): ChannelMux.ServiceSpec(1, "udp", "127.0.0.1", 10003, "udp", "127.0.0.1", 20003),
        }

        with mock.patch.object(mux, "_stop_listener_for_service_id", new=mock.AsyncMock()) as stop_listener:
            mux.on_peer_disconnected(11)
            await asyncio.sleep(0)

        self.assertEqual(stop_listener.await_count, 2)
        stop_listener.assert_has_awaits(
            [
                mock.call(("peer", 11, 1), "udp", spec=udp_spec),
                mock.call(("peer", 11, 2), "tcp", spec=tcp_spec),
            ],
            any_order=True,
        )
        self.assertNotIn(("peer", 11, 1), mux._peer_installed_services)
        self.assertNotIn(("peer", 11, 2), mux._peer_installed_services)
        self.assertIn(("peer", 22, 1), mux._peer_installed_services)


if __name__ == "__main__":
    unittest.main()
