#!/usr/bin/env python3
import argparse
import asyncio
import contextlib
import os
import unittest

from obstacle_bridge.bridge import WebSocketSession


def _client_args() -> argparse.Namespace:
    return argparse.Namespace(
        ws_bind="0.0.0.0",
        ws_own_port=0,
        ws_peer="127.0.0.1",
        ws_peer_port=54321,
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


def _install_legacy_reconnect_loop(session: WebSocketSession) -> None:
    # Legacy behavior: once _reconnect_task is assigned (even already done),
    # subsequent disconnects won't spawn a new loop.
    def _legacy_start_reconnect_loop() -> None:
        if not session._peer_tuple or session._reconnect_task is not None or not session._run_flag:
            return
        host, port = session._peer_tuple

        async def _reconnect():
            delay = 0.5
            while session._run_flag:
                if session._ws is not None:
                    return
                await session._connect_to(host, port)
                if session._ws is not None:
                    return
                try:
                    await asyncio.sleep(delay)
                except asyncio.CancelledError:
                    return
                delay = min(delay * 2.0, 10.0)

        session._reconnect_task = session._loop.create_task(_reconnect())  # type: ignore[arg-type]

    session._start_reconnect_loop = _legacy_start_reconnect_loop  # type: ignore[method-assign]


class WebSocketReconnectRegressionTests(unittest.IsolatedAsyncioTestCase):
    async def test_reconnect_loop_restarts_after_second_disconnect(self):
        session = WebSocketSession(_client_args())
        session._loop = asyncio.get_running_loop()
        session._run_flag = True

        if str(os.environ.get("OB_BRIDGE_FORCE_LEGACY_RECONNECT", "")).strip() in {"1", "true", "TRUE"}:
            _install_legacy_reconnect_loop(session)

        connect_attempts = 0

        async def _fake_connect_to(host: str, port: int) -> None:
            nonlocal connect_attempts
            connect_attempts += 1
            session._ws = object()

        session._connect_to = _fake_connect_to  # type: ignore[method-assign]

        # 1) First disconnect -> reconnect loop runs and succeeds once.
        session._ws = None
        session._start_reconnect_loop()
        await asyncio.sleep(0.02)
        self.assertEqual(connect_attempts, 1)

        # Simulate transport drop after a recovered connection.
        session._ws = None

        # 2) Second disconnect must schedule a fresh reconnect loop.
        session._start_reconnect_loop()
        await asyncio.sleep(0.02)
        self.assertEqual(
            connect_attempts,
            2,
            "reconnect loop did not restart after a second disconnect; this matches the legacy bug",
        )

        session._run_flag = False
        if session._reconnect_task is not None:
            session._reconnect_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await session._reconnect_task

    async def test_reconnect_retry_uses_configured_minimum_delay(self):
        args = _client_args()
        args.overlay_reconnect_retry_delay_ms = 80
        session = WebSocketSession(args)
        session._loop = asyncio.get_running_loop()
        session._run_flag = True

        attempt_ts: list[float] = []

        async def _fake_connect_to(host: str, port: int) -> None:
            attempt_ts.append(asyncio.get_running_loop().time())
            # Keep failing so reconnect loop keeps scheduling retries.
            session._ws = None

        session._connect_to = _fake_connect_to  # type: ignore[method-assign]

        session._ws = None
        session._start_reconnect_loop()
        await asyncio.sleep(0.27)

        self.assertGreaterEqual(len(attempt_ts), 3, "expected repeated reconnect attempts")
        gaps = [b - a for a, b in zip(attempt_ts, attempt_ts[1:])]
        # Keep tolerance for scheduler jitter while still proving delay throttling.
        self.assertTrue(all(gap >= 0.06 for gap in gaps), f"retry gaps too small: {gaps!r}")

        session._run_flag = False
        if session._reconnect_task is not None:
            session._reconnect_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await session._reconnect_task


if __name__ == "__main__":
    unittest.main()
