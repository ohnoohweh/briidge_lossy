#!/usr/bin/env python3
import argparse
import asyncio
import unittest

from obstacle_bridge.bridge import WebSocketSession


def _server_args() -> argparse.Namespace:
    return argparse.Namespace(
        bind443='0.0.0.0',
        port443=0,
        peer=None,
        peer_port=0,
        ws_path='/',
        ws_subprotocol=None,
        ws_tls=False,
        ws_max_size=65535,
        ws_payload_mode='binary',
        ws_static_dir='',
        ws_send_timeout=3.0,
        ws_tcp_user_timeout_ms=10000,
        ws_reconnect_grace=3.0,
    )


class WebSocketMultiPeerMuxRewriteTests(unittest.TestCase):
    def test_inbound_mux_rewrite_allocates_distinct_server_channels_per_peer(self):
        session = WebSocketSession(_server_args())
        payload1 = session._MUX_HDR.pack(7, 0, 1, 0, 4) + b'test'
        payload2 = session._MUX_HDR.pack(7, 0, 1, 0, 4) + b'test'

        rewritten1 = session._server_rewrite_inbound_app(1, payload1)
        rewritten2 = session._server_rewrite_inbound_app(2, payload2)

        chan1 = session._MUX_HDR.unpack(rewritten1[:session._MUX_HDR.size])[0]
        chan2 = session._MUX_HDR.unpack(rewritten2[:session._MUX_HDR.size])[0]

        self.assertNotEqual(chan1, chan2)
        self.assertEqual(session._server_chan_to_peer[chan1], (1, 7))
        self.assertEqual(session._server_chan_to_peer[chan2], (2, 7))

    def test_outbound_mux_rewrite_routes_back_to_original_peer_channel(self):
        session = WebSocketSession(_server_args())
        inbound = session._MUX_HDR.pack(11, 0, 5, 0, 3) + b'abc'
        rewritten = session._server_rewrite_inbound_app(9, inbound)
        mux_chan, proto, counter, mtype, dlen = session._MUX_HDR.unpack(rewritten[:session._MUX_HDR.size])

        routed = session._server_rewrite_outbound_app(rewritten)

        self.assertIsNotNone(routed)
        peer_id, outbound = routed
        self.assertEqual(peer_id, 9)
        self.assertEqual(outbound, inbound)
        self.assertEqual((proto, counter, mtype, dlen), (0, 5, 0, 3))
        self.assertIn(mux_chan, session._server_chan_to_peer)


class WebSocketMultiPeerSendTests(unittest.IsolatedAsyncioTestCase):
    async def test_send_app_routes_to_matching_server_peer_queue(self):
        session = WebSocketSession(_server_args())
        session._loop = asyncio.get_running_loop()
        q1 = asyncio.Queue()
        q2 = asyncio.Queue()
        session._server_peers = {
            1: {'peer_id': 1, 'ws': object(), 'tx_queue': q1, 'tx_task': None, 'rx_task': None},
            2: {'peer_id': 2, 'ws': object(), 'tx_queue': q2, 'tx_task': None, 'rx_task': None},
        }
        session._ensure_server_tx_task = lambda ctx: None
        inbound = session._MUX_HDR.pack(4, 0, 2, 0, 2) + b'hi'
        rewritten = session._server_rewrite_inbound_app(2, inbound)

        sent = session.send_app(rewritten)

        self.assertEqual(sent, len(rewritten))
        queued_wire, on_sent = await q2.get()
        self.assertEqual(queued_wire, bytes([session._K_APP]) + inbound)
        self.assertTrue(callable(on_sent))
        self.assertTrue(q1.empty())


if __name__ == '__main__':
    unittest.main()
