#!/usr/bin/env python3
import argparse
import unittest

from udp_bidirectional_main import WebSocketSession


def _args(ws_payload_mode: str) -> argparse.Namespace:
    return argparse.Namespace(
        bind443="0.0.0.0",
        port443=0,
        peer=None,
        peer_port=0,
        ws_path="/",
        ws_subprotocol=None,
        ws_tls=False,
        ws_max_size=65535,
        ws_payload_mode=ws_payload_mode,
        ws_static_dir="",
    )


class WebSocketPayloadModeTests(unittest.TestCase):
    def test_binary_mode_keeps_bytes_on_send(self):
        session = WebSocketSession(_args("binary"))
        wire = b"\x00hello"
        self.assertEqual(session._encode_ws_message(wire), wire)

    def test_base64_mode_encodes_and_decodes_text_frames(self):
        session = WebSocketSession(_args("base64"))
        wire = b"\x01hello\x00world"
        encoded = session._encode_ws_message(wire)
        self.assertIsInstance(encoded, str)
        self.assertEqual(session._decode_ws_message(encoded), wire)

    def test_text_frames_must_be_valid_base64(self):
        session = WebSocketSession(_args("binary"))
        self.assertIsNone(session._decode_ws_message("not base64 !!!"))

    def test_binary_frames_are_still_accepted_in_base64_mode(self):
        session = WebSocketSession(_args("base64"))
        wire = b"\x02pong"
        self.assertEqual(session._decode_ws_message(wire), wire)


if __name__ == "__main__":
    unittest.main()
