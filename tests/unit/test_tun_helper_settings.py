#!/usr/bin/env python3
import argparse
import os
import unittest
from unittest import mock

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

    def test_helper_mode_supported_only_on_linux(self) -> None:
        settings = TunExecutionSettings(mode="helper")

        self.assertTrue(settings.helper_mode_supported(platform="linux"))
        self.assertFalse(settings.helper_mode_supported(platform="darwin"))
        self.assertFalse(settings.helper_mode_supported(platform="win32"))

    def test_ensure_supported_platform_raises_for_non_linux_helper_mode(self) -> None:
        settings = TunExecutionSettings(mode="helper")

        with self.assertRaisesRegex(RuntimeError, "currently supported only on Linux"):
            settings.ensure_supported_platform(platform="darwin")

    def test_resolved_socket_path_defaults_to_process_unique_runtime_path(self) -> None:
        settings = TunExecutionSettings(mode="helper")

        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": "/run/user/1000"}, clear=False), \
             mock.patch("obstacle_bridge.bridge_tun_helper_settings.os.getpid", return_value=43210):
            path = settings.resolved_socket_path()

        self.assertEqual(path, "/run/user/1000/obstaclebridge/tun-helper-43210.sock")


if __name__ == "__main__":
    unittest.main()
