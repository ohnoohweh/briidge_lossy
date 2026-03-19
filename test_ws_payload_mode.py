#!/usr/bin/env python3
import argparse
import unittest
from unittest import mock

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


class _FakeReader:
    def __init__(self, lines, body=b""):
        self._lines = list(lines)
        self._body = body

    async def readline(self):
        if self._lines:
            return self._lines.pop(0)
        return b""

    async def read(self, n=-1):
        if n < 0:
            out, self._body = self._body, b""
            return out
        out = self._body[:n]
        self._body = self._body[n:]
        return out


class _FakeWriter:
    def __init__(self):
        self.buffer = bytearray()
        self.closed = False
        self.wait_closed_called = False

    def write(self, data):
        self.buffer.extend(data)

    async def drain(self):
        return None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        self.wait_closed_called = True


class WebSocketPayloadModeTests(unittest.TestCase):
    def test_binary_mode_keeps_bytes_on_send(self):
        session = WebSocketSession(_args("binary"))
        wire = b"\x00hello"
        self.assertEqual(session._ws_payload_codec.encode(wire), wire)

    def test_base64_mode_encodes_and_decodes_text_frames(self):
        session = WebSocketSession(_args("base64"))
        wire = b"\x01hello\x00world"
        encoded = session._ws_payload_codec.encode(wire)
        self.assertIsInstance(encoded, str)
        self.assertEqual(session._decode_ws_message(encoded), wire)

    def test_json_base64_mode_encodes_and_decodes_text_frames(self):
        session = WebSocketSession(_args("json-base64"))
        wire = b"\x02pong"
        encoded = session._ws_payload_codec.encode(wire)
        self.assertEqual(encoded, '{"data":"AnBvbmc="}')
        self.assertEqual(session._decode_ws_message(encoded), wire)

    def test_invalid_text_frames_are_rejected(self):
        session = WebSocketSession(_args("json-base64"))
        self.assertIsNone(session._decode_ws_message("not json"))

    def test_binary_frames_are_still_accepted_in_text_modes(self):
        for mode in ("base64", "json-base64"):
            session = WebSocketSession(_args(mode))
            wire = b"\x02pong"
            self.assertEqual(session._decode_ws_message(wire), wire)

    def test_early_flush_preserves_websocket_message_boundaries(self):
        session = WebSocketSession(_args("binary"))
        session._ws = object()
        sent = []
        session._schedule_send = sent.append
        session._bump_tx = lambda wire: None
        session._buffer_early(b"\x01first")
        session._buffer_early(b"\x02second")

        session._flush_early()

        self.assertEqual(sent, [b"\x01first", b"\x02second"])
        self.assertEqual(len(session._early_buf), 0)
        self.assertEqual(session._early_buf_bytes, 0)


class WebSocketHttpPreflightTests(unittest.IsolatedAsyncioTestCase):
    async def test_http_preflight_requests_default_page(self):
        session = WebSocketSession(_args("binary"))
        reader = _FakeReader(
            [
                b"HTTP/1.1 200 OK\r\n",
                b"Content-Type: text/html\r\n",
                b"\r\n",
            ],
            body=b"<html></html>",
        )
        writer = _FakeWriter()

        with mock.patch("udp_bidirectional_main.asyncio.open_connection", mock.AsyncMock(return_value=(reader, writer))) as open_conn:
            await session._load_default_http_page(host="127.0.0.1", port=54321, host_header="example.test")

        open_conn.assert_awaited_once_with(host="127.0.0.1", port=54321)
        request = writer.buffer.decode("ascii")
        self.assertIn("GET / HTTP/1.1\r\n", request)
        self.assertIn("Host: example.test\r\n", request)
        self.assertTrue(writer.closed)
        self.assertTrue(writer.wait_closed_called)

    async def test_http_preflight_requires_success_status(self):
        session = WebSocketSession(_args("binary"))
        reader = _FakeReader([b"HTTP/1.1 404 Not Found\r\n", b"\r\n"])
        writer = _FakeWriter()

        with mock.patch("udp_bidirectional_main.asyncio.open_connection", mock.AsyncMock(return_value=(reader, writer))):
            with self.assertRaisesRegex(RuntimeError, "unexpected HTTP status 404"):
                await session._load_default_http_page(host="127.0.0.1", port=54321)


if __name__ == "__main__":
    unittest.main()
