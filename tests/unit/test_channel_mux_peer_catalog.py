#!/usr/bin/env python3
import asyncio
import unittest

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


if __name__ == "__main__":
    unittest.main()
