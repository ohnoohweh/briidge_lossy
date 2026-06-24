#!/usr/bin/env python3
import argparse
import struct
import unittest

from obstacle_bridge.bridge import TcpStreamSession

_MUX_HDR = struct.Struct(">HHBBH")


def _server_args() -> argparse.Namespace:
    return argparse.Namespace(
        tcp_bind="127.0.0.1",
        tcp_own_port=0,
        tcp_peer=None,
        tcp_peer_port=0,
        tcp_peer_resolve_family="ipv4",
        overlay_reconnect_retry_delay_ms=30000,
    )


class TcpMultiPeerMuxRewriteTests(unittest.TestCase):
    def test_inbound_passthrough_keeps_mux_shaped_secure_link_payloads_unmodified(self):
        payload1 = _MUX_HDR.pack(7, 0, 1, 0, 4) + b"test"
        payload2 = _MUX_HDR.pack(7, 0, 1, 0, 4) + b"test"

        rewriting_session = TcpStreamSession(_server_args())
        rewritten1 = rewriting_session._server_rewrite_inbound_app(1, payload1)
        rewritten2 = rewriting_session._server_rewrite_inbound_app(2, payload2)

        self.assertEqual(rewritten1, payload1)
        self.assertNotEqual(rewritten2, payload2)
        self.assertTrue(rewriting_session._server_chan_to_peer)

        passthrough_session = TcpStreamSession(_server_args())
        passthrough_session.set_app_payload_passthrough(True)

        self.assertEqual(passthrough_session._server_rewrite_inbound_app(1, payload1), payload1)
        self.assertEqual(passthrough_session._server_rewrite_inbound_app(2, payload2), payload2)
        self.assertFalse(passthrough_session._server_chan_to_peer)
        self.assertFalse(passthrough_session._server_peer_chan_to_mux)


if __name__ == "__main__":
    unittest.main()
