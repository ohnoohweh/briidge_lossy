#!/usr/bin/env python3
import argparse
import os
import unittest
from unittest import mock

import obstacle_bridge.bridge_tun_helper_settings as helper_settings
from obstacle_bridge.bridge_tun_helper_settings import (
    TUN_EXECUTION_SECTION,
    TunExecutionSettings,
)


class TunHelperSettingsTests(unittest.TestCase):
    def test_register_cli_parses_defaults(self) -> None:
        parser = argparse.ArgumentParser()
        TunExecutionSettings.register_cli(parser)

        args = parser.parse_args([])

        self.assertEqual(args.tun_execution_mode, "inline")
        self.assertEqual(args.tun_helper_backend, "linux-native")
        self.assertEqual(args.tun_helper_socket, "")
        self.assertTrue(args.tun_helper_apply_network)
        self.assertEqual(args.tun_helper_log_level, "INFO")

    def test_register_cli_accepts_windows_native_backend_value(self) -> None:
        parser = argparse.ArgumentParser()
        TunExecutionSettings.register_cli(parser)

        args = parser.parse_args(["--tun-helper-backend", "windows-native"])

        self.assertEqual(args.tun_helper_backend, "windows-native")

    def test_from_mapping_reads_sectioned_config(self) -> None:
        settings = TunExecutionSettings.from_mapping(
            {
                TUN_EXECUTION_SECTION: {
                    "mode": "helper",
                    "helper_backend": "linux-python",
                    "helper_socket": "/tmp/ob.sock",
                    "helper_apply_network": False,
                    "helper_log_level": "debug",
                }
            }
        )

        self.assertEqual(settings.mode, "helper")
        self.assertEqual(settings.helper_backend, "linux-python")
        self.assertEqual(settings.helper_socket, "/tmp/ob.sock")
        self.assertFalse(settings.helper_apply_network)
        self.assertEqual(settings.helper_log_level, "DEBUG")

    def test_from_mapping_accepts_cli_dest_names(self) -> None:
        settings = TunExecutionSettings.from_mapping(
            {
                "tun_execution_mode": "helper",
                "tun_helper_backend": "linux-python",
                "tun_helper_socket": "/run/user/1000/ob.sock",
                "tun_helper_apply_network": "false",
                "tun_helper_log_level": "warning",
            }
        )

        self.assertEqual(settings.mode, "helper")
        self.assertEqual(settings.helper_socket, "/run/user/1000/ob.sock")
        self.assertFalse(settings.helper_apply_network)
        self.assertEqual(settings.helper_log_level, "WARNING")

    def test_helper_mode_supported_on_linux_and_macos(self) -> None:
        settings = TunExecutionSettings(mode="helper")

        self.assertTrue(settings.helper_mode_supported(platform="linux"))
        self.assertTrue(settings.helper_mode_supported(platform="darwin"))
        self.assertFalse(settings.helper_mode_supported(platform="win32"))

    def test_helper_mode_supported_on_windows_for_windows_native_backend(self) -> None:
        settings = TunExecutionSettings(mode="helper", helper_backend="windows-native")

        self.assertTrue(settings.helper_mode_supported(platform="win32"))

    def test_ensure_supported_platform_raises_for_unsupported_helper_mode(self) -> None:
        settings = TunExecutionSettings(mode="helper")

        with self.assertRaisesRegex(RuntimeError, "supported on Linux/macOS, and on Windows only for the windows-native backend"):
            settings.ensure_supported_platform(platform="win32")

    def test_resolved_socket_path_defaults_to_process_unique_runtime_path(self) -> None:
        settings = TunExecutionSettings(mode="helper")

        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": "/run/user/1000"}, clear=False), \
             mock.patch("obstacle_bridge.bridge_tun_helper_settings.os.getpid", return_value=43210):
            path = settings.resolved_socket_path()

        self.assertEqual(path, "/run/user/1000/obstaclebridge/tun-helper-43210.sock")

    def test_resolved_socket_path_defaults_to_loopback_tcp_for_windows_native_backend(self) -> None:
        settings = TunExecutionSettings(mode="helper", helper_backend="windows-native")

        with mock.patch("obstacle_bridge.bridge_tun_helper_settings.sys.platform", "win32"), \
             mock.patch("obstacle_bridge.bridge_tun_helper_settings.allocate_local_tcp_endpoint", return_value="tcp://127.0.0.1:42310"):
            path = settings.resolved_socket_path()

        self.assertEqual(path, "tcp://127.0.0.1:42310")

    def test_resolved_runtime_dir_is_separate_from_windows_pipe_endpoint(self) -> None:
        settings = TunExecutionSettings(mode="helper", helper_backend="windows-native")

        with mock.patch("obstacle_bridge.bridge_tun_helper_settings.sys.platform", "win32"), \
             mock.patch("obstacle_bridge.bridge_tun_helper_settings.tempfile.gettempdir", return_value="C:\\Temp"):
            runtime_dir = settings.resolved_runtime_dir()

        self.assertEqual(runtime_dir, os.path.join("C:\\Temp", "obstaclebridge-win-helper"))

    def test_resolved_socket_path_falls_back_when_getuid_is_unavailable(self) -> None:
        settings = TunExecutionSettings(mode="helper")

        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch("obstacle_bridge.bridge_tun_helper_settings.tempfile.gettempdir", return_value="C:\\Temp"), \
             mock.patch("obstacle_bridge.bridge_tun_helper_settings.os.getpid", return_value=43210), \
               mock.patch.object(helper_settings.os, "getuid", new=None, create=True):
            path = settings.resolved_socket_path()
            runtime_dir = settings.resolved_runtime_dir()

        self.assertEqual(path, os.path.join("C:\\Temp", "obstaclebridge-nouid", "tun-helper-43210.sock"))
        self.assertEqual(runtime_dir, os.path.join("C:\\Temp", "obstaclebridge-nouid"))


if __name__ == "__main__":
    unittest.main()
