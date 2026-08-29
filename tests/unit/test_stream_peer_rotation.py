#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import contextlib
import importlib
import unittest
from unittest import mock

from obstacle_bridge.bridge import TcpStreamSession, WebSocketSession


def _tcp_args() -> argparse.Namespace:
    return argparse.Namespace(
        tcp_bind="0.0.0.0",
        tcp_own_port=0,
        tcp_peer="192.0.2.10,198.51.100.20",
        tcp_peer_port=54321,
        tcp_peer_resolve_family="ipv4",
        overlay_reconnect_retry_delay_ms=10,
        tcp_bp_wbuf_threshold=128 * 1024,
        tcp_bp_latency_ms=300,
        tcp_bp_poll_interval_ms=50,
    )


def _ws_args() -> argparse.Namespace:
    return argparse.Namespace(
        ws_bind="0.0.0.0",
        ws_own_port=0,
        ws_peer="192.0.2.10,198.51.100.20",
        ws_peer_port=54321,
        ws_peer_resolve_family="ipv4",
        ws_path="/",
        ws_subprotocol=None,
        ws_tls=False,
        ws_max_size=65535,
        ws_payload_mode="binary",
        ws_static_dir="",
        ws_send_timeout=3.0,
        ws_tcp_user_timeout_ms=10000,
        ws_reconnect_grace=0.0,
        ws_proxy_mode="off",
        ws_proxy_host="",
        ws_proxy_port=8080,
        ws_proxy_auth="none",
        overlay_reconnect_retry_delay_ms=10,
    )


def _quic_args() -> argparse.Namespace:
    return argparse.Namespace(
        quic_bind="::",
        quic_own_port=0,
        quic_peer="192.0.2.10,198.51.100.20",
        quic_peer_port=443,
        quic_peer_resolve_family="ipv4",
        quic_alpn="hq-29",
        quic_cert=None,
        quic_key=None,
        quic_insecure=False,
        quic_max_size=65535,
        overlay_reconnect_retry_delay_ms=10,
    )


def _new_quic_session():
    quic_module = importlib.import_module("obstacle_bridge.bridge_transport_quic")
    QuicSession = quic_module.QuicSession
    fake_symbols = {
        "quic_serve": object(),
        "quic_connect": object(),
        "QuicConnectionProtocol": type("_Proto", (), {}),
        "QuicConfiguration": type("_Cfg", (), {}),
        "StreamDataReceived": type("_StreamDataReceived", (), {}),
        "HandshakeCompleted": type("_HandshakeCompleted", (), {}),
        "ConnectionTerminated": type("_ConnectionTerminated", (), {}),
        "ProtocolNegotiated": type("_ProtocolNegotiated", (), {}),
    }
    with mock.patch.object(quic_module.importlib.util, "find_spec", return_value=object()), \
         mock.patch.object(quic_module, "_load_aioquic_symbols", return_value=fake_symbols):
        return QuicSession(_quic_args())


class StreamPeerRotationTests(unittest.IsolatedAsyncioTestCase):
    async def test_tcp_reconnect_loop_rotates_peer_candidates_permanently(self) -> None:
        session = TcpStreamSession(_tcp_args())
        session._loop = asyncio.get_running_loop()
        session._run_flag = True

        attempts: list[tuple[str, int]] = []

        async def _fake_connect_to(host: str, port: int) -> None:
            attempts.append((host, port))
            session._writer = None

        session._connect_to = _fake_connect_to  # type: ignore[method-assign]

        session._start_reconnect_loop()
        await asyncio.sleep(0.05)

        self.assertGreaterEqual(len(attempts), 3)
        self.assertEqual(attempts[:3], [("192.0.2.10", 54321), ("198.51.100.20", 54321), ("192.0.2.10", 54321)])

        session._run_flag = False
        if session._reconnect_task is not None:
            session._reconnect_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await session._reconnect_task

    async def test_ws_reconnect_loop_rotates_peer_candidates_permanently(self) -> None:
        session = WebSocketSession(_ws_args())
        session._loop = asyncio.get_running_loop()
        session._run_flag = True

        attempts: list[tuple[str, int]] = []

        async def _fake_connect_to(host: str, port: int) -> None:
            attempts.append((host, port))
            session._ws = None

        session._connect_to = _fake_connect_to  # type: ignore[method-assign]

        session._start_reconnect_loop()
        await asyncio.sleep(0.05)

        self.assertGreaterEqual(len(attempts), 3)
        self.assertEqual(attempts[:3], [("192.0.2.10", 54321), ("198.51.100.20", 54321), ("192.0.2.10", 54321)])

        session._run_flag = False
        if session._reconnect_task is not None:
            session._reconnect_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await session._reconnect_task

    async def test_quic_reconnect_loop_rotates_peer_candidates_permanently(self) -> None:
        session = _new_quic_session()
        session._loop = asyncio.get_running_loop()
        session._run_flag = True

        attempts: list[tuple[str, int]] = []

        async def _fake_connect_to(host: str, port: int) -> None:
            attempts.append((host, port))
            session._quic = None

        session._connect_to = _fake_connect_to  # type: ignore[method-assign]

        session._start_reconnect_loop()
        await asyncio.sleep(0.05)

        self.assertGreaterEqual(len(attempts), 3)
        self.assertEqual(attempts[:3], [("192.0.2.10", 443), ("198.51.100.20", 443), ("192.0.2.10", 443)])

        session._run_flag = False
        if session._reconnect_task is not None:
            session._reconnect_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await session._reconnect_task


class StreamCandidateCycleTests(unittest.TestCase):
    def test_stream_rotation_counts_completed_candidate_cycles_and_resets_on_connection(self) -> None:
        for session in (TcpStreamSession(_tcp_args()), WebSocketSession(_ws_args()), _new_quic_session()):
            session._advance_peer_candidate(count_cycle=True)
            self.assertEqual(session._peer_candidate_index, 1)
            self.assertEqual(session._peer_candidate_cycle, 0)

            session._advance_peer_candidate(count_cycle=True)
            self.assertEqual(session._peer_candidate_index, 0)
            self.assertEqual(session._peer_candidate_cycle, 1)

            session._set_overlay_connected(True)
            self.assertEqual(session._peer_candidate_cycle, 0)


class StreamReconnectShutdownTests(unittest.TestCase):
    def _assert_shutdown_does_not_query_stopped_loop(self, session, connected_attr: str) -> None:
        loop = asyncio.new_event_loop()
        session._loop = loop
        session._run_flag = True
        started = asyncio.Event()
        blocker = asyncio.Event()

        async def _fake_connect_to(host: str, port: int) -> None:
            started.set()
            await blocker.wait()

        session._connect_to = _fake_connect_to  # type: ignore[method-assign]
        setattr(session, connected_attr, None)
        session._start_reconnect_loop()
        loop.run_until_complete(started.wait())

        reconnect_task = session._reconnect_task
        self.assertIsNotNone(reconnect_task)
        reconnect_coro = reconnect_task.get_coro()
        loop.close()
        try:
            with mock.patch.object(
                asyncio,
                "current_task",
                side_effect=RuntimeError("no running event loop"),
            ):
                reconnect_coro.close()
        finally:
            # The test deliberately closes the coroutine behind a pending Task
            # after its loop has stopped, matching interpreter shutdown.
            reconnect_task._log_destroy_pending = False  # type: ignore[attr-defined]

    def test_tcp_reconnect_cleanup_survives_stopped_event_loop(self) -> None:
        self._assert_shutdown_does_not_query_stopped_loop(TcpStreamSession(_tcp_args()), "_writer")

    def test_ws_reconnect_cleanup_survives_stopped_event_loop(self) -> None:
        self._assert_shutdown_does_not_query_stopped_loop(WebSocketSession(_ws_args()), "_ws")

    def test_quic_reconnect_cleanup_survives_stopped_event_loop(self) -> None:
        self._assert_shutdown_does_not_query_stopped_loop(_new_quic_session(), "_quic")


if __name__ == "__main__":
    unittest.main()
