#!/usr/bin/env python3
import argparse
import asyncio
import unittest

from obstacle_bridge.bridge import ChannelMux


class _FakeSession:
    def __init__(self):
        self.app_cb = None

    def is_connected(self):
        return False

    def set_on_app_payload(self, cb):
        self.app_cb = cb

    def send_app(self, payload):
        return len(payload)


class ChannelMuxListenerModeTests(unittest.TestCase):
    def test_listener_mode_ignores_own_servers(self):
        args = argparse.Namespace(
            peer=None,
            own_servers=['udp,16667,0.0.0.0,udp,127.0.0.1,16666'],
            mux_tcp_bp_threshold=1,
            mux_tcp_bp_latency_ms=300,
            mux_tcp_bp_poll_interval_ms=50,
        )

        mux = ChannelMux.from_args(_FakeSession(), asyncio.new_event_loop(), args)
        try:
            self.assertEqual(mux._services, {})
        finally:
            mux.loop.close()

    def test_client_mode_keeps_own_servers(self):
        args = argparse.Namespace(
            peer='127.0.0.1',
            own_servers=['udp,16667,0.0.0.0,udp,127.0.0.1,16666'],
            mux_tcp_bp_threshold=1,
            mux_tcp_bp_latency_ms=300,
            mux_tcp_bp_poll_interval_ms=50,
        )

        mux = ChannelMux.from_args(_FakeSession(), asyncio.new_event_loop(), args)
        try:
            self.assertEqual(len(mux._services), 1)
            spec = mux._services[1]
            self.assertEqual(spec.l_proto, 'udp')
            self.assertEqual(spec.l_port, 16667)
            self.assertEqual(spec.r_proto, 'udp')
            self.assertEqual(spec.r_host, '127.0.0.1')
            self.assertEqual(spec.r_port, 16666)
        finally:
            mux.loop.close()


if __name__ == '__main__':
    unittest.main()
