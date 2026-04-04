#!/usr/bin/env python3
import argparse
import asyncio
import socket
import sys
import tempfile
import types
import unittest
from unittest import mock

from obstacle_bridge.bridge import WebSocketSession


def _args(ws_payload_mode: str) -> argparse.Namespace:
    return argparse.Namespace(
        ws_bind="0.0.0.0",
        ws_own_port=0,
        ws_peer=None,
        ws_peer_port=0,
        ws_path="/",
        ws_subprotocol=None,
        ws_tls=False,
        ws_max_size=65535,
        ws_payload_mode=ws_payload_mode,
        ws_static_dir="",
        ws_send_timeout=3.0,
        ws_tcp_user_timeout_ms=10000,
        ws_reconnect_grace=3.0,
        ws_proxy_mode="off",
        ws_proxy_host="",
        ws_proxy_port=8080,
        ws_proxy_auth="none",
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




class _FakeWs:
    def __init__(self):
        self.sent = []
        self.close_calls = 0

    async def send(self, payload):
        self.sent.append(payload)

    async def close(self):
        self.close_calls += 1

    async def recv(self):
        await asyncio.Future()

    async def wait_closed(self):
        return None


class _HangingWs(_FakeWs):
    async def send(self, payload):
        await asyncio.Future()


class _FakeSocket:
    def __init__(self):
        self.calls = []

    def setsockopt(self, level, optname, value):
        self.calls.append((level, optname, value))


class _FakeTransport:
    def __init__(self, sock):
        self._sock = sock

    def get_extra_info(self, name):
        if name == "socket":
            return self._sock
        return None


class _SockoptWs(_FakeWs):
    def __init__(self, sock):
        super().__init__()
        self.transport = _FakeTransport(sock)


class _ProbeTransport:
    def __init__(self):
        self._sockname = ("127.0.0.1", 8080)
        self._peername = ("127.0.0.1", 40000)

    def get_write_buffer_size(self):
        return 0

    def is_closing(self):
        return False

    def get_extra_info(self, name):
        if name == "sockname":
            return self._sockname
        if name == "peername":
            return self._peername
        return None


class _ProbeConnection:
    def __init__(self):
        self.transport = _ProbeTransport()


class _FakeLoop:
    def __init__(self):
        self.calls = []

    def call_soon(self, cb, *args):
        self.calls.append(("soon", 0.0, cb, args))

    def call_later(self, delay, cb, *args):
        self.calls.append(("later", delay, cb, args))


class _FakeResponse:
    def __init__(self, *args):
        self.args = args

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
        session._schedule_send = lambda wire, on_sent=None: sent.append((wire, on_sent))
        session._bump_tx = lambda wire: None
        session._buffer_early(b"\x01first")
        session._buffer_early(b"\x02second")

        session._flush_early()

        self.assertEqual([wire for wire, _ in sent], [b"\x01first", b"\x02second"])
        self.assertEqual([on_sent for _, on_sent in sent], [None, None])
        self.assertEqual(len(session._early_buf), 0)
        self.assertEqual(session._early_buf_bytes, 0)


class WebSocketTxLoopTests(unittest.IsolatedAsyncioTestCase):
    async def test_early_buffered_send_notifies_peer_tx_after_flush(self):
        args = _args("binary")
        args.peer = "127.0.0.1"
        args.peer_port = 54321
        session = WebSocketSession(args)
        session._loop = asyncio.get_running_loop()
        session._peer_tuple = ("127.0.0.1", 54321)
        sent_sizes = []
        session.set_on_peer_tx(sent_sizes.append)

        session._ws = None
        session.send_app(b"hello")
        self.assertEqual(session._early_buf_bytes, 6)

        session._ws = _FakeWs()
        session._flush_early()
        await asyncio.wait_for(session._tx_queue.join(), timeout=1.0)
        session._flush_early()
        await asyncio.wait_for(session._tx_queue.join(), timeout=1.0)

        self.assertEqual(session._tx_bytes, 6)
        self.assertEqual(sent_sizes, [6])
        self.assertEqual(session._ws.sent, [b"\x00hello"])

        session._tx_task.cancel()
        await session._tx_task

    async def test_tx_accounting_happens_after_successful_send(self):
        session = WebSocketSession(_args("binary"))
        session._loop = asyncio.get_running_loop()
        session._ws = _FakeWs()
        sent_sizes = []
        session.set_on_peer_tx(sent_sizes.append)

        session.send_app(b"hello")
        await asyncio.wait_for(session._tx_queue.join(), timeout=1.0)

        self.assertEqual(session._tx_bytes, 6)
        self.assertEqual(sent_sizes, [6])
        self.assertEqual(session._ws.sent, [b"\x00hello"])

        session._tx_task.cancel()
        await session._tx_task

    async def test_tx_timeout_forces_websocket_close(self):
        args = _args("binary")
        args.ws_send_timeout = 0.01
        session = WebSocketSession(args)
        session._loop = asyncio.get_running_loop()
        hanging = _HangingWs()
        session._ws = hanging

        session.send_app(b"hello")
        await asyncio.sleep(0.05)
        await asyncio.wait_for(session._tx_queue.join(), timeout=1.0)

        self.assertEqual(session._tx_bytes, 0)
        self.assertEqual(hanging.close_calls, 1)

        session._tx_task.cancel()
        await session._tx_task


class WebSocketSocketConfigTests(unittest.TestCase):
    def test_configure_ws_socket_sets_keepalive_and_tcp_user_timeout(self):
        session = WebSocketSession(_args("binary"))
        sock = _FakeSocket()
        session._configure_ws_socket(_SockoptWs(sock))

        self.assertIn((socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1), sock.calls)
        tcp_user_timeout = getattr(socket, "TCP_USER_TIMEOUT", None)
        if tcp_user_timeout is not None:
            self.assertIn((socket.IPPROTO_TCP, tcp_user_timeout, 10000), sock.calls)

    def test_configure_ws_socket_skips_missing_socket(self):
        session = WebSocketSession(_args("binary"))
        ws = type("NoSockWs", (), {"transport": None})()
        session._configure_ws_socket(ws)


class WebSocketReconnectGraceTests(unittest.IsolatedAsyncioTestCase):
    async def test_zero_grace_disconnects_immediately(self):
        args = _args("binary")
        args.ws_reconnect_grace = 0.0
        session = WebSocketSession(args)
        session._loop = asyncio.get_running_loop()
        session._run_flag = True
        session._overlay_connected = True

        session._schedule_overlay_disconnect()

        self.assertFalse(session._overlay_connected)
        self.assertIsNone(session._disconnect_task)

    async def test_quick_reconnect_cancels_pending_disconnect(self):
        args = _args("binary")
        args.ws_reconnect_grace = 0.05
        session = WebSocketSession(args)
        session._loop = asyncio.get_running_loop()
        session._run_flag = True
        session._overlay_connected = True
        session._schedule_overlay_disconnect()

        self.assertIsNotNone(session._disconnect_task)

        session._ws = object()
        await session._on_accept(_SockoptWs(_FakeSocket()))
        await asyncio.sleep(0.08)

        self.assertTrue(session._overlay_connected)
        self.assertIsNone(session._disconnect_task)

        session._rx_task.cancel()
        await session._rx_task
        session._tx_task.cancel()
        await session._tx_task

    async def test_disconnect_fires_after_grace_when_not_reconnected(self):
        args = _args("binary")
        args.ws_reconnect_grace = 0.05
        session = WebSocketSession(args)
        session._loop = asyncio.get_running_loop()
        session._run_flag = True
        session._overlay_connected = True
        session._schedule_overlay_disconnect()

        await asyncio.sleep(0.08)

        self.assertFalse(session._overlay_connected)
        self.assertIsNone(session._disconnect_task)


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

        with mock.patch("obstacle_bridge.bridge.asyncio.open_connection", mock.AsyncMock(return_value=(reader, writer))) as open_conn:
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

        with mock.patch("obstacle_bridge.bridge.asyncio.open_connection", mock.AsyncMock(return_value=(reader, writer))):
            with self.assertRaisesRegex(RuntimeError, "unexpected HTTP status 404"):
                await session._load_default_http_page(host="127.0.0.1", port=54321)


class WebSocketCompressionConfigTests(unittest.IsolatedAsyncioTestCase):
    async def test_start_server_disables_websocket_compression(self):
        session = WebSocketSession(_args("binary"))
        session._loop = asyncio.get_running_loop()
        session._run_flag = True

        fake_server = types.SimpleNamespace(
            sockets=[types.SimpleNamespace(getsockname=lambda: ("127.0.0.1", 54321))]
        )
        serve = mock.AsyncMock(return_value=fake_server)
        fake_websockets = types.SimpleNamespace(serve=serve)
        fake_http11 = types.SimpleNamespace(Response=object)
        fake_ds = types.SimpleNamespace(Headers=lambda items: items)

        with mock.patch.dict(
            sys.modules,
            {
                "websockets": fake_websockets,
                "websockets.http11": fake_http11,
                "websockets.datastructures": fake_ds,
            },
        ):
            await session._start_server()

        self.assertIs(session._server, fake_server)
        self.assertEqual(serve.await_args.kwargs["compression"], None)
        if "open_timeout" in serve.await_args.kwargs:
            self.assertIsNone(serve.await_args.kwargs["open_timeout"])
        self.assertEqual(serve.await_args.kwargs["write_limit"], 131072)

    async def test_connect_disables_websocket_compression(self):
        args = _args("binary")
        args.peer = "127.0.0.1"
        args.peer_port = 54321
        session = WebSocketSession(args)
        session._loop = asyncio.get_running_loop()
        session._run_flag = True
        session._peer_tuple = ("127.0.0.1", 54321)
        session._peer_name_host = "overlay.example"
        session._peer_name_port = 54321

        fake_ws = types.SimpleNamespace(
            local_address=("127.0.0.1", 40000),
            remote_address=("127.0.0.1", 54321),
        )
        connect = mock.AsyncMock(return_value=fake_ws)
        fake_websockets = types.SimpleNamespace(connect=connect)

        with mock.patch.dict(sys.modules, {"websockets": fake_websockets}):
            with mock.patch.object(session, "_load_default_http_page", mock.AsyncMock()) as preflight:
                with mock.patch.object(session, "_on_accept", mock.AsyncMock()) as on_accept:
                    await session._connect_to("127.0.0.1", 54321)

        preflight.assert_awaited_once()
        on_accept.assert_awaited_once_with(fake_ws)
        self.assertEqual(connect.await_args.kwargs["compression"], None)

    async def test_connect_uses_proxy_socket_when_proxy_mode_enabled(self):
        args = _args("binary")
        args.ws_peer = "127.0.0.1"
        args.ws_peer_port = 54321
        args.ws_proxy_mode = "manual"
        args.ws_proxy_host = "proxy.example"
        args.ws_proxy_port = 8080
        session = WebSocketSession(args)
        session._loop = asyncio.get_running_loop()
        session._run_flag = True
        session._peer_tuple = ("127.0.0.1", 54321)
        session._peer_name_host = "overlay.example"
        session._peer_name_port = 54321

        fake_sock = mock.Mock()
        fake_ws = types.SimpleNamespace(
            local_address=("127.0.0.1", 40000),
            remote_address=("127.0.0.1", 54321),
        )
        connect = mock.AsyncMock(return_value=fake_ws)
        fake_websockets = types.SimpleNamespace(connect=connect)

        with mock.patch.dict(sys.modules, {"websockets": fake_websockets}):
            with mock.patch.object(session, "_open_ws_proxy_socket", mock.AsyncMock(return_value=fake_sock)) as open_proxy:
                with mock.patch.object(session, "_load_default_http_page", mock.AsyncMock()) as preflight:
                    with mock.patch.object(session, "_on_accept", mock.AsyncMock()) as on_accept:
                        with mock.patch.object(session, "_get_ws_proxy_endpoint", return_value=("proxy.example", 8080)):
                            await session._connect_to("127.0.0.1", 54321)

        open_proxy.assert_awaited_once_with("overlay.example", 54321)
        preflight.assert_not_awaited()
        on_accept.assert_awaited_once_with(fake_ws)
        self.assertIs(connect.await_args.kwargs["sock"], fake_sock)
        self.assertNotIn("host", connect.await_args.kwargs)
        self.assertNotIn("port", connect.await_args.kwargs)


class WebSocketProxyHelpersTests(unittest.TestCase):
    def test_register_cli_defaults_ws_proxy_mode_to_env_on_linux(self):
        parser = argparse.ArgumentParser()
        with mock.patch.object(sys, "platform", "linux"):
            WebSocketSession.register_cli(parser)

        args = parser.parse_args([])

        self.assertEqual(args.ws_proxy_mode, "env")

    def test_register_cli_defaults_ws_proxy_mode_to_system_on_windows(self):
        parser = argparse.ArgumentParser()
        with mock.patch.object(sys, "platform", "win32"):
            WebSocketSession.register_cli(parser)

        args = parser.parse_args([])

        self.assertEqual(args.ws_proxy_mode, "system")

    def test_missing_ws_proxy_mode_uses_platform_default_in_constructor(self):
        args = _args("binary")
        delattr(args, "ws_proxy_mode")

        with mock.patch.object(sys, "platform", "win32"):
            session = WebSocketSession(args)

        self.assertEqual(session._ws_proxy_mode, "system")

    def test_parse_proxy_spec_prefers_matching_scheme(self):
        parsed = WebSocketSession._parse_proxy_spec("http=proxy-http:8080;https=proxy-https:8443", secure=True)
        self.assertEqual(parsed, ("proxy-https", 8443))

    def test_build_proxy_connect_request_includes_authorization(self):
        session = WebSocketSession(_args("binary"))
        request = session._build_proxy_connect_request("2001:db8::1", 443, auth_header="Negotiate abc123").decode("ascii")
        self.assertIn("CONNECT [2001:db8::1]:443 HTTP/1.1\r\n", request)
        self.assertIn("Host: [2001:db8::1]:443\r\n", request)
        self.assertIn("Proxy-Authorization: Negotiate abc123\r\n", request)

    def test_manual_proxy_mode_returns_endpoint_off_windows(self):
        args = _args("binary")
        args.ws_peer = "127.0.0.1"
        args.ws_peer_port = 54321
        args.ws_proxy_mode = "manual"
        args.ws_proxy_host = "proxy.example"
        args.ws_proxy_port = 8080
        session = WebSocketSession(args)
        session._peer_tuple = ("127.0.0.1", 54321)

        with mock.patch.object(sys, "platform", "linux"):
            endpoint = session._get_ws_proxy_endpoint("overlay.example", 54321)

        self.assertEqual(endpoint, ("proxy.example", 8080))

    def test_system_proxy_mode_logs_when_no_endpoint_is_found(self):
        args = _args("binary")
        args.ws_peer = "127.0.0.1"
        args.ws_peer_port = 54321
        args.ws_proxy_mode = "system"
        session = WebSocketSession(args)
        session._peer_tuple = ("127.0.0.1", 54321)
        session._log = mock.Mock()

        with mock.patch.object(sys, "platform", "win32"):
            with mock.patch.object(session, "_win_get_proxy_for_url", return_value=None):
                with self.assertRaisesRegex(RuntimeError, "did not return a proxy"):
                    session._get_ws_proxy_endpoint("overlay.example", 54321)

        debug_messages = [call.args[0] for call in session._log.debug.call_args_list if call.args]
        self.assertTrue(any("endpoint lookup" in msg for msg in debug_messages))
        self.assertTrue(any("system proxy lookup url=" in msg for msg in debug_messages))
        self.assertTrue(any("returned no endpoint" in msg for msg in debug_messages))

    def test_env_proxy_mode_uses_http_proxy_for_ws(self):
        args = _args("binary")
        args.ws_peer = "127.0.0.1"
        args.ws_peer_port = 54321
        args.ws_proxy_mode = "env"
        session = WebSocketSession(args)
        session._peer_tuple = ("127.0.0.1", 54321)

        with mock.patch("obstacle_bridge.bridge.urllib.request.proxy_bypass", return_value=False):
            with mock.patch("obstacle_bridge.bridge.urllib.request.getproxies", return_value={"http": "http://proxy.example:8080"}):
                endpoint = session._get_ws_proxy_endpoint("overlay.example", 54321)

        self.assertEqual(endpoint, ("proxy.example", 8080))

    def test_env_proxy_mode_uses_https_proxy_for_wss(self):
        args = _args("binary")
        args.ws_peer = "127.0.0.1"
        args.ws_peer_port = 54321
        args.ws_proxy_mode = "env"
        args.ws_tls = True
        session = WebSocketSession(args)
        session._peer_tuple = ("127.0.0.1", 54321)

        with mock.patch("obstacle_bridge.bridge.urllib.request.proxy_bypass", return_value=False):
            with mock.patch("obstacle_bridge.bridge.urllib.request.getproxies", return_value={"https": "https://secure-proxy.example:8443"}):
                endpoint = session._get_ws_proxy_endpoint("overlay.example", 54321)

        self.assertEqual(endpoint, ("secure-proxy.example", 8443))

    def test_env_proxy_mode_honors_no_proxy_bypass(self):
        args = _args("binary")
        args.ws_peer = "127.0.0.1"
        args.ws_peer_port = 54321
        args.ws_proxy_mode = "env"
        session = WebSocketSession(args)
        session._peer_tuple = ("127.0.0.1", 54321)

        with mock.patch("obstacle_bridge.bridge.urllib.request.proxy_bypass", return_value=True):
            with mock.patch("obstacle_bridge.bridge.urllib.request.getproxies") as getproxies:
                endpoint = session._get_ws_proxy_endpoint("overlay.example", 54321)

        self.assertIsNone(endpoint)
        getproxies.assert_not_called()

    def test_open_ws_proxy_socket_logs_connect_success(self):
        args = _args("binary")
        args.ws_peer = "127.0.0.1"
        args.ws_peer_port = 54321
        args.ws_proxy_mode = "manual"
        args.ws_proxy_host = "proxy.example"
        args.ws_proxy_port = 8080
        session = WebSocketSession(args)
        session._peer_tuple = ("127.0.0.1", 54321)
        session._log = mock.Mock()

        fake_sock = mock.Mock()
        with mock.patch.object(session, "_get_ws_proxy_endpoint", return_value=("proxy.example", 8080)):
            with mock.patch("socket.create_connection", return_value=fake_sock) as create_connection:
                with mock.patch.object(session, "_read_http_proxy_response", return_value=(200, {})):
                    sock = session._open_ws_proxy_socket_blocking("overlay.example", 54321)

        self.assertIs(sock, fake_sock)
        create_connection.assert_called_once_with(("proxy.example", 8080), timeout=30.0)
        fake_sock.sendall.assert_called_once()
        fake_sock.setblocking.assert_called_once_with(False)
        debug_messages = [call.args[0] for call in session._log.debug.call_args_list if call.args]
        self.assertTrue(any("opening proxy tunnel" in msg for msg in debug_messages))
        self.assertTrue(any("CONNECT attempt=" in msg for msg in debug_messages))
        self.assertTrue(any("CONNECT response status=" in msg for msg in debug_messages))
        self.assertTrue(any("CONNECT tunnel established" in msg for msg in debug_messages))


class WebSocketStaticHttpDebugTests(unittest.IsolatedAsyncioTestCase):
    async def test_start_server_schedules_static_http_probes_for_modern_requests(self):
        args = _args("binary")
        with tempfile.TemporaryDirectory() as tmpdir:
            icon_path = f"{tmpdir}/icon.png"
            with open(icon_path, "wb") as fh:
                fh.write(b"\x89PNG" + b"x" * 32)

            args.ws_static_dir = tmpdir
            session = WebSocketSession(args)
            session._loop = _FakeLoop()
            session._run_flag = True
            session._log = mock.Mock()

            fake_server = types.SimpleNamespace(
                sockets=[types.SimpleNamespace(getsockname=lambda: ("127.0.0.1", 54321))]
            )
            serve = mock.AsyncMock(return_value=fake_server)
            fake_websockets = types.SimpleNamespace(serve=serve)
            fake_http11 = types.SimpleNamespace(Response=_FakeResponse)
            fake_ds = types.SimpleNamespace(Headers=lambda items: items)

            with mock.patch.dict(
                sys.modules,
                {
                    "websockets": fake_websockets,
                    "websockets.http11": fake_http11,
                    "websockets.datastructures": fake_ds,
                },
            ):
                await session._start_server()

            process_request = serve.await_args.kwargs["process_request"]
            request = types.SimpleNamespace(method="GET", path="/icon.png", headers={})
            response = process_request(_ProbeConnection(), request)

            self.assertIsInstance(response, _FakeResponse)
            self.assertEqual(
                [kind for kind, *_ in session._loop.calls],
                ["soon", "later", "later", "later"],
            )
            self.assertEqual(
                [delay for _, delay, _, _ in session._loop.calls],
                [0.0, 0.05, 0.25, 1.0],
            )
            debug_messages = [
                call.args[0]
                for call in session._log.debug.call_args_list
                if call.args
            ]
            self.assertTrue(any("[WS/HTTP]" in msg and "static-hit" in msg for msg in debug_messages))


if __name__ == "__main__":
    unittest.main()
