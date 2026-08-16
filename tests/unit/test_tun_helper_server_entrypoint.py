#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import unittest
import uuid
from unittest import mock

from obstacle_bridge.bridge_tun_helper_client import TunHelperClient
from obstacle_bridge.bridge_tun_helper_windows import WindowsTunHelperBackend
from obstacle_bridge.bridge_tun_helper_server import (
    TunHelperServer,
    _backend_from_name,
    _resolve_helper_launch_args,
    build_arg_parser,
    run_helper_server,
)


def _test_helper_endpoint(tmp_dir: str) -> str:
    if sys.platform == "win32":
        return f"\\\\.\\pipe\\obstaclebridge-test-{uuid.uuid4().hex}"
    return os.path.join(tmp_dir, "tun-helper.sock")


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
        self.assertEqual(launch["authenticated_client_idle_timeout_s"], 5.0)

    def test_resolve_helper_launch_args_reads_idle_timeout_from_config(self) -> None:
        parser = build_arg_parser()
        with tempfile.TemporaryDirectory() as tmp:
            config_path = os.path.join(tmp, "helper-launch.json")
            with open(config_path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "socket_path": "/tmp/obstaclebridge-helper.sock",
                        "session_token": "secret-token",
                        "authenticated_client_idle_timeout_s": 30,
                    },
                    handle,
                )
            args = parser.parse_args(["--config-path", config_path])
            launch = _resolve_helper_launch_args(args)

        self.assertEqual(launch["authenticated_client_idle_timeout_s"], 30.0)

    def test_backend_factory_rejects_unknown_backend(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported tun helper backend"):
            _backend_from_name("mystery-backend")

    def test_backend_factory_accepts_darwin_native_backend(self) -> None:
        if not sys.platform.startswith("darwin"):
            self.skipTest("darwin-native backend import is validated on macOS hosts")
        self.assertEqual(_backend_from_name("darwin-native").__class__.__name__, "DarwinTunHelperBackend")

    def test_backend_factory_accepts_windows_native_backend(self) -> None:
        self.assertIsInstance(_backend_from_name("windows-native"), WindowsTunHelperBackend)

    async def test_server_start_chowns_socket_back_to_invoking_user_when_sudo_env_is_present(self) -> None:
        if sys.platform == "win32":
            self.skipTest("Unix-socket helper permission test is not applicable on Windows")
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
                  mock.patch("obstacle_bridge.bridge_tun_helper_server._start_local_helper_server", side_effect=_fake_start_unix_server), \
                  mock.patch("obstacle_bridge.bridge_tun_helper_server.os.chown", create=True) as chown, \
                 mock.patch("obstacle_bridge.bridge_tun_helper_server.os.chmod") as chmod:
                await server.start(socket_path)
                await server.stop()

            chown.assert_called_once_with(socket_path, 1000, 1001)
            chmod.assert_any_call(socket_path, 0o600)

    async def test_run_helper_server_starts_socket_and_serves_client(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            socket_path = _test_helper_endpoint(tmp)
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
                if not socket_path.startswith("\\\\.\\pipe\\"):
                    for _ in range(50):
                        if os.path.exists(socket_path):
                            break
                        await asyncio.sleep(0.01)
                    self.assertTrue(os.path.exists(socket_path))
                else:
                    await asyncio.sleep(0.05)

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
                self.assertEqual(snapshot["active_authenticated_clients"], 1)
                self.assertTrue(snapshot["network_applied"])
            finally:
                stop_event.set()
                await asyncio.wait_for(task, timeout=1.0)
                if not socket_path.startswith("\\\\.\\pipe\\"):
                    self.assertFalse(os.path.exists(socket_path))


if __name__ == "__main__":
    unittest.main()
