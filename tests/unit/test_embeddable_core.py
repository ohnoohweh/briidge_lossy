from __future__ import annotations

import argparse
from pathlib import Path
import unittest
from unittest import mock

from obstacle_bridge import MemoryPacketIO, ObstacleBridgeClient, PacketIO
from obstacle_bridge.bridge import build_runtime_args_from_config, parse_runtime_args


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


class PacketIOTests(unittest.IsolatedAsyncioTestCase):
    async def test_memory_packet_io_round_trip_boundaries(self) -> None:
        packet_io = MemoryPacketIO()
        self.assertIsInstance(packet_io, PacketIO)

        packet_io.feed_incoming(b"first")
        packet_io.feed_incoming(b"second")

        self.assertEqual(await packet_io.read_packets(), [b"first", b"second"])

        await packet_io.write_packets([bytearray(b"out")])
        self.assertEqual(packet_io.drain_outgoing(), [b"out"])


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
