#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from unittest import mock

from obstacle_bridge.bridge_tun_helper_client import TunHelperClient
from obstacle_bridge.bridge_tun_helper_server import (
    TunHelperServer,
    _backend_from_name,
    _resolve_helper_launch_args,
    build_arg_parser,
    run_helper_server,
)


class TunHelperServerEntrypointTests(unittest.IsolatedAsyncioTestCase):
    def test_build_arg_parser_reads_entrypoint_args(self) -> None:
        parser = build_arg_parser()
        args = parser.parse_args(
            [
                "--socket-path",
                "/tmp/obstaclebridge-helper.sock",
                "--session-token",
                "secret-token",
                "--backend",
                "linux-python",
                "--log-tun-helper",
                "DEBUG",
            ]
        )

        self.assertEqual(args.socket_path, "/tmp/obstaclebridge-helper.sock")
        self.assertEqual(args.session_token, "secret-token")
        self.assertEqual(args.backend, "linux-python")
        self.assertEqual(args.tun_helper_log_level, "DEBUG")

    def test_resolve_helper_launch_args_supports_compact_config_file(self) -> None:
        parser = build_arg_parser()
        with tempfile.TemporaryDirectory() as tmp:
            config_path = os.path.join(tmp, "helper-launch.json")
            with open(config_path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "socket_path": "/tmp/obstaclebridge-helper.sock",
                        "session_token": "secret-token",
                        "backend": "linux-native",
                        "log_level": "WARNING",
                    },
                    handle,
                )
            args = parser.parse_args(["--config-path", config_path])
            launch = _resolve_helper_launch_args(args)

        self.assertEqual(launch["socket_path"], "/tmp/obstaclebridge-helper.sock")
        self.assertEqual(launch["session_token"], "secret-token")
        self.assertEqual(launch["backend"], "linux-native")
        self.assertEqual(launch["log_level"], "WARNING")

    def test_backend_factory_rejects_unknown_backend(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported tun helper backend"):
            _backend_from_name("mystery-backend")

    async def test_server_start_chowns_socket_back_to_invoking_user_when_sudo_env_is_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            socket_path = os.path.join(tmp, "tun-helper.sock")

            class _FakeServer:
                def close(self) -> None:
                    return None

                async def wait_closed(self) -> None:
                    return None

            async def _fake_start_unix_server(handler, path):
                del handler
                self.assertEqual(path, socket_path)
                with open(path, "wb"):
                    pass
                return _FakeServer()

            backend = _backend_from_name("linux-python")
            server = TunHelperServer(backend=backend, session_token="secret")

            with mock.patch.dict(os.environ, {"SUDO_UID": "1000", "SUDO_GID": "1001"}, clear=False), \
                 mock.patch("obstacle_bridge.bridge_tun_helper_server.asyncio.start_unix_server", side_effect=_fake_start_unix_server), \
                 mock.patch("obstacle_bridge.bridge_tun_helper_server.os.chown") as chown, \
                 mock.patch("obstacle_bridge.bridge_tun_helper_server.os.chmod") as chmod:
                await server.start(socket_path)
                await server.stop()

            chown.assert_called_once_with(socket_path, 1000, 1001)
            chmod.assert_any_call(socket_path, 0o600)

    async def test_run_helper_server_starts_socket_and_serves_client(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            socket_path = os.path.join(tmp, "tun-helper.sock")
            stop_event = asyncio.Event()
            task = asyncio.create_task(
                run_helper_server(
                    socket_path=socket_path,
                    session_token="secret",
                    backend_name="linux-python",
                    log_level="DEBUG",
                    stop_event=stop_event,
                )
            )
            try:
                for _ in range(50):
                    if os.path.exists(socket_path):
                        break
                    await asyncio.sleep(0.01)
                self.assertTrue(os.path.exists(socket_path))

                client = TunHelperClient(socket_path=socket_path, session_token="secret")
                await client.connect()
                opened = await client.open_tun({"ifname": "obtun0", "mtu": 1500})
                applied = await client.apply_network({"ifname": "obtun0", "mtu": 1500})
                snapshot = await client.snapshot()
                await client.close()

                self.assertEqual(opened["ifname"], "obtun0")
                self.assertEqual(opened["mtu"], 1500)
                self.assertTrue(applied["applied"])
                self.assertEqual(snapshot["backend"], "linux-python-memory")
                self.assertEqual(snapshot["apply_calls"], 1)
                self.assertTrue(snapshot["network_applied"])
            finally:
                stop_event.set()
                await asyncio.wait_for(task, timeout=1.0)
                self.assertFalse(os.path.exists(socket_path))


if __name__ == "__main__":
    unittest.main()
