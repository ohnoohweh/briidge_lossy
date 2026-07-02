from __future__ import annotations

import argparse
import asyncio
import json
import logging
from pathlib import Path
import unittest
from unittest import mock

from obstacle_bridge import MemoryPacketIO, ObstacleBridgeClient, PacketIO
from obstacle_bridge.bridge import (
    ConfigAwareCLI,
    RUNTIME_CLI_DESCRIPTION,
    Runner,
    build_runtime_args_from_config,
    default_runtime_registrars,
    parse_runtime_args,
)


class EmbeddableRuntimeArgsTests(unittest.TestCase):
    def test_build_runtime_args_from_flat_config(self) -> None:
        args = build_runtime_args_from_config(
            {
                "overlay_transport": "ws",
                "ws_peer": "bridge.example.com",
                "ws_peer_port": 443,
                "admin_web": False,
            }
        )

        self.assertEqual(args.overlay_transport, "ws")
        self.assertEqual(args.ws_peer, "bridge.example.com")
        self.assertEqual(args.ws_peer_port, 443)
        self.assertFalse(args.admin_web)
        self.assertEqual(args._config_file_state, "loaded")
        self.assertIn("runner", args._config_sections)

    def test_build_runtime_args_from_sectioned_config(self) -> None:
        args = build_runtime_args_from_config(
            {
                "runner": {"overlay_transport": "tcp"},
                "tcp_session": {"tcp_peer": "peer.example", "tcp_peer_port": 8443},
            }
        )

        self.assertEqual(args.overlay_transport, "tcp")
        self.assertEqual(args.tcp_peer, "peer.example")
        self.assertEqual(args.tcp_peer_port, 8443)
        self.assertIn("overlay_transport", args._config_sections["runner"])
        self.assertIn("tcp_peer", args._config_sections["tcp_session"])
        self.assertNotIn("tcp_peer", args._config_sections["runner"])

    def test_build_runtime_args_accepts_channel_mux_egress_alias(self) -> None:
        args = build_runtime_args_from_config(
            {
                "channel_mux": {
                    "egress": {
                        "mode": "system",
                        "proxy_auth": "none",
                    }
                }
            }
        )

        self.assertEqual(args.channel_mux_egress["mode"], "system")
        self.assertEqual(args.channel_mux_egress["proxy_auth"], "none")
        self.assertIn("channel_mux_egress", args._config_sections["channel_mux"])

    def test_build_runtime_args_prefers_runner_overlay_transport_over_legacy_root_value(self) -> None:
        args = build_runtime_args_from_config(
            {
                "overlay_transport": "ws",
                "runner": {"overlay_transport": "tcp"},
                "tcp_session": {"tcp_peer": "peer.example", "tcp_peer_port": 8443},
            }
        )

        self.assertEqual(args.overlay_transport, "tcp")

    def test_build_runtime_args_from_onboarding_config_marks_first_start(self) -> None:
        args = build_runtime_args_from_config(
            {
                "runner": {"overlay_transport": "myudp"},
                "channel_mux": {"own_servers": [], "remote_servers": []},
                "iOS_TUN_connector": {"packetflow_connector": "swift_udp"},
            }
        )

        self.assertEqual(args._config_file_state, "empty")
        self.assertTrue(args._first_start_detected)

    def test_build_runtime_args_preserves_ios_tun_connector_section(self) -> None:
        args = build_runtime_args_from_config(
            {
                "iOS_TUN_connector": {
                    "packetflow_connector": "swift_udp",
                    "peer_host": "10.10.1.12",
                    "peer_port": 5555,
                    "bind_host": "0.0.0.0",
                    "bind_port": 5555,
                    "ifname": "ios-utun",
                    "mtu": 1600,
                }
            }
        )

        self.assertEqual(args.packetflow_connector, "swift_udp")
        self.assertEqual(args.peer_host, "10.10.1.12")
        self.assertEqual(args.peer_port, 5555)
        self.assertIn("iOS_TUN_connector", args._config_sections)

    def test_dump_effective_config_preserves_unedited_ios_tun_connector_fields(self) -> None:
        config = {
            "iOS_TUN_connector": {
                "packetflow_connector": "swift_udp",
                "peer_host": "10.10.1.12",
                "peer_port": 5555,
                "bind_host": "0.0.0.0",
                "bind_port": 5555,
                "ifname": "ios-utun",
                "mtu": 1600,
            }
        }
        cli = ConfigAwareCLI(description=RUNTIME_CLI_DESCRIPTION)
        parser = cli._build_full_parser(default_runtime_registrars())
        cli._raw_config = dict(config)
        cli._apply_config_defaults_from_json(parser, dict(config))
        args = parser.parse_args([])

        grouped = json.loads(cli.dump_effective_config_json(args))

        self.assertEqual(grouped["iOS_TUN_connector"]["packetflow_connector"], "swift_udp")
        self.assertEqual(grouped["iOS_TUN_connector"]["peer_host"], "10.10.1.12")
        self.assertEqual(grouped["iOS_TUN_connector"]["peer_port"], 5555)
        self.assertEqual(grouped["iOS_TUN_connector"]["bind_host"], "0.0.0.0")
        self.assertEqual(grouped["iOS_TUN_connector"]["bind_port"], 5555)
        self.assertEqual(grouped["iOS_TUN_connector"]["ifname"], "ios-utun")
        self.assertEqual(grouped["iOS_TUN_connector"]["mtu"], 1600)

    def test_runner_schema_snapshot_includes_ios_tun_connector_fields(self) -> None:
        args = build_runtime_args_from_config(
            {
                "iOS_TUN_connector": {
                    "packetflow_connector": "swift_udp",
                    "peer_host": "10.10.1.12",
                    "peer_port": 5555,
                }
            }
        )
        runner = Runner.__new__(Runner)
        runner.args = args

        schema = runner.get_config_schema_snapshot()
        ios_tun_connector_rows = {row["key"]: row for row in schema["iOS_TUN_connector"]}

        self.assertIn("packetflow_connector", ios_tun_connector_rows)
        self.assertIn("peer_host", ios_tun_connector_rows)
        self.assertIn("peer_port", ios_tun_connector_rows)
        self.assertEqual(
            ios_tun_connector_rows["packetflow_connector"]["choices"],
            ["", "udp", "direct", "simple_udp_peer", "swift_udp", "swift_udp_peer", "swift_host_runner"],
        )

    def test_runner_schema_snapshot_includes_proxy_provider_fields(self) -> None:
        args = build_runtime_args_from_config(
            {
                "proxy_provider": {
                    "enabled": True,
                    "bind": "127.0.0.1",
                    "http_port": 13181,
                    "socks5_port": 13182,
                    "protocols": ["http-connect", "socks5-connect"],
                    "auth": {
                        "mode": "token",
                        "username": "obproxy",
                        "token": "local-token",
                    },
                    "egress": {
                        "mode": "system",
                        "address_families": ["ipv4", "ipv6"],
                    },
                    "policy": {
                        "allow_private_destinations": False,
                        "blocked_host_patterns": [],
                    },
                }
            }
        )
        runner = Runner.__new__(Runner)
        runner.args = args

        self.assertTrue(args.proxy_provider_enabled)
        self.assertEqual(args.proxy_provider_bind, "127.0.0.1")
        self.assertEqual(args.proxy_provider_http_port, 13181)
        self.assertEqual(args.proxy_provider_socks5_port, 13182)
        self.assertEqual(args.proxy_provider_protocols, ["http-connect", "socks5-connect"])
        self.assertEqual(args.proxy_provider_auth["username"], "obproxy")
        self.assertTrue(args.enabled)
        self.assertEqual(args.http_port, 13181)

        config = runner.get_config_snapshot()
        schema = runner.get_config_schema_snapshot()
        proxy_provider_rows = {row["key"]: row for row in schema["proxy_provider"]}

        self.assertTrue(config["proxy_provider_enabled"])
        self.assertEqual(config["proxy_provider_http_port"], 13181)
        self.assertEqual(config["proxy_provider_socks5_port"], 13182)
        self.assertEqual(config["proxy_provider_auth"]["token"], "local-token")
        self.assertTrue(
            {
                "proxy_provider_enabled",
                "proxy_provider_bind",
                "proxy_provider_http_port",
                "proxy_provider_socks5_port",
                "proxy_provider_protocols",
                "proxy_provider_auth",
                "proxy_provider_egress",
                "proxy_provider_policy",
            }.issubset(set(proxy_provider_rows.keys())),
        )
        self.assertIn("log_proxy_provider", proxy_provider_rows)
        self.assertEqual(proxy_provider_rows["proxy_provider_enabled"]["default"], False)
        self.assertEqual(proxy_provider_rows["proxy_provider_http_port"]["default"], 13881)
        self.assertEqual(proxy_provider_rows["proxy_provider_socks5_port"]["default"], 13882)
        self.assertEqual(
            proxy_provider_rows["proxy_provider_protocols"]["choices"],
            ["http-connect", "socks5-connect", "http", "socks5"],
        )

    def test_build_runtime_args_preserves_explicit_config_path_for_embedders(self) -> None:
        args = build_runtime_args_from_config(
            {"admin_web": True},
            config_path="/tmp/obstaclebridge-ios/ObstacleBridge.cfg",
        )

        self.assertEqual(args.config, "/tmp/obstaclebridge-ios/ObstacleBridge.cfg")
        self.assertEqual(args._config_path, str(Path("/tmp/obstaclebridge-ios/ObstacleBridge.cfg").resolve()))

    def test_parse_runtime_args_exposes_cli_metadata(self) -> None:
        args = parse_runtime_args(
            ["--config", "missing-test.cfg", "--overlay-transport", "tcp", "--admin-web-bind", "127.0.0.1"],
            apply_logging=False,
        )

        self.assertEqual(args.overlay_transport, "tcp")
        self.assertIn("admin_web", args._config_sections)
        self.assertIn("overlay_transport", args._config_defaults)


class ProxyProviderRunnerLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_runner_starts_proxy_provider_and_exposes_status_snapshot(self) -> None:
        args = build_runtime_args_from_config(
            {
                "proxy_provider": {
                    "enabled": True,
                    "bind": "127.0.0.1",
                    "http_port": 0,
                    "socks5_port": 0,
                    "protocols": ["http-connect", "socks5-connect"],
                    "auth": {"mode": "none", "username": "", "token": ""},
                }
            }
        )
        runner = Runner(args)

        await runner._start_proxy_provider()
        try:
            snapshot = runner.get_status_snapshot()["proxy_provider"]
            self.assertTrue(snapshot["enabled"])
            self.assertEqual(set(snapshot["listeners"].keys()), {"http", "socks5"})
            self.assertTrue(snapshot["listeners"]["http"]["http_enabled"])
            self.assertFalse(snapshot["listeners"]["http"]["socks5_enabled"])
            self.assertFalse(snapshot["listeners"]["socks5"]["http_enabled"])
            self.assertTrue(snapshot["listeners"]["socks5"]["socks5_enabled"])
        finally:
            await runner._stop_proxy_provider()


class PacketIOTests(unittest.IsolatedAsyncioTestCase):
    async def test_memory_packet_io_round_trip_boundaries(self) -> None:
        packet_io = MemoryPacketIO()
        self.assertIsInstance(packet_io, PacketIO)

        packet_io.feed_incoming(b"first")
        packet_io.feed_incoming(b"second")

        self.assertEqual(await packet_io.read_packets(), [b"first", b"second"])

        await packet_io.write_packets([bytearray(b"out")])
        self.assertEqual(packet_io.drain_outgoing(), [b"out"])


class RunnerEmbeddedRestartTests(unittest.IsolatedAsyncioTestCase):
    async def test_request_restart_uses_embedded_callback_when_present(self) -> None:
        runner = Runner.__new__(Runner)
        runner.log = logging.getLogger("test.runner.embedded_restart")
        runner._restart_requested_flag = False
        runner._restart_exit_code = 0
        runner._restart_requested = None
        runner._restart_requires_delay = lambda: False
        called = asyncio.Event()

        async def restart_cb() -> None:
            called.set()

        runner._embedded_restart_callback = restart_cb

        runner.request_restart()

        await asyncio.wait_for(called.wait(), timeout=1.0)
        self.assertFalse(runner._restart_requested_flag)


class ObstacleBridgeClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_client_lifecycle_uses_runner_without_process_entrypoint(self) -> None:
        class _Runner:
            def __init__(self, args: argparse.Namespace) -> None:
                self.args = args
                self.started = False
                self.stopped = False
                self.packet_io = None

            async def start(self) -> None:
                self.started = True

            async def stop(self) -> None:
                self.stopped = True

            def get_status_snapshot(self) -> dict:
                return {"transport": self.args.overlay_transport}

            def get_connections_snapshot(self) -> dict:
                return {"counts": {"tcp": 0, "udp": 0, "tun": 0}}

            def get_config_snapshot(self, include_secrets: bool = False) -> dict:
                return {"overlay_transport": self.args.overlay_transport}

        packet_io = MemoryPacketIO()
        with mock.patch("obstacle_bridge.core.Runner", _Runner):
            client = ObstacleBridgeClient(
                {"overlay_transport": "tcp", "admin_web": False},
                packet_io=packet_io,
            )

            self.assertEqual(client.snapshot(), {"started": False})

            await client.start()
            self.assertIs(client.runner.packet_io, packet_io)
            self.assertTrue(client.runner.started)
            self.assertEqual(client.snapshot()["status"], {"transport": "tcp"})

            await client.update_config({"overlay_transport": "ws", "admin_web": False})
            self.assertEqual(client.snapshot()["status"], {"transport": "ws"})

            runner = client.runner
            await client.stop()
            self.assertTrue(runner.stopped)
            self.assertEqual(client.snapshot(), {"started": False})


if __name__ == "__main__":
    unittest.main()
