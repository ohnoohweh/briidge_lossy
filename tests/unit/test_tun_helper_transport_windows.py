#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import socket
import sys
import unittest

from obstacle_bridge.bridge_tun_helper_client import TunHelperClient
from obstacle_bridge.bridge_tun_helper_server import TunHelperServer


class _FakeHelperBackend:
    def __init__(self) -> None:
        self._sink = None
        self.open_calls = 0
        self.written_packets: list[bytes] = []
        self.stopped = False

    def set_packet_sink(self, sink) -> None:
        self._sink = sink

    async def open_tun(self, payload):
        self.open_calls += 1
        return {
            "ifname": str(payload.get("ifname") or "obtunw0"),
            "mtu": int(payload.get("mtu") or 1400),
            "backend": "fake-windows-pipe",
        }

    async def apply_network(self, payload):
        return {"applied": True, "ifname": str(payload.get("ifname") or "obtunw0")}

    async def remove_network(self, payload):
        return {"removed": True, "ifname": str(payload.get("ifname") or "obtunw0")}

    async def write_packet(self, packet: bytes):
        self.written_packets.append(bytes(packet))
        if self._sink is not None:
            result = self._sink(b"echo:" + bytes(packet))
            if asyncio.iscoroutine(result):
                await result
        return {"accepted": True}

    async def snapshot(self):
        return {
            "backend": "fake-windows-pipe",
            "open_calls": self.open_calls,
            "written_packets": len(self.written_packets),
            "stopped": self.stopped,
        }

    async def stop(self):
        self.stopped = True


class TunHelperWindowsTransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        if sys.platform != "win32":
            self.skipTest("Windows Named Pipe helper transport test runs only on Windows")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])
        self.socket_path = f"tcp://127.0.0.1:{port}"
        self.backend = _FakeHelperBackend()
        self.server = TunHelperServer(backend=self.backend, session_token="secret")
        await self.server.start(self.socket_path)

    async def asyncTearDown(self) -> None:
        await self.server.stop()

    async def test_client_server_round_trip_over_windows_named_pipe(self) -> None:
        client = TunHelperClient(socket_path=self.socket_path, session_token="secret")
        await client.connect()

        opened = await client.open_tun({"ifname": "obtunw0", "mtu": 1400})
        await client.write_packet(b"pipe-test")
        echoed = await asyncio.wait_for(client.read_packet(), timeout=1.0)
        snapshot = await client.snapshot()
        await client.close()

        self.assertEqual(opened["ifname"], "obtunw0")
        self.assertEqual(opened["backend"], "fake-windows-pipe")
        self.assertEqual(echoed, b"echo:pipe-test")
        self.assertEqual(self.backend.written_packets, [b"pipe-test"])
        self.assertEqual(snapshot["backend"], "fake-windows-pipe")
        self.assertEqual(snapshot["open_calls"], 1)

    async def test_client_can_apply_network_after_open_over_windows_named_pipe(self) -> None:
        client = TunHelperClient(socket_path=self.socket_path, session_token="secret")
        await client.connect()

        opened = await client.open_tun({"ifname": "obtunw0", "mtu": 1400})
        applied = await client.apply_network({"ifname": "obtunw0", "mtu": 1400})
        snapshot = await client.snapshot()
        await client.close()

        self.assertEqual(opened["ifname"], "obtunw0")
        self.assertTrue(applied["applied"])
        self.assertEqual(applied["ifname"], "obtunw0")
        self.assertEqual(snapshot["backend"], "fake-windows-pipe")
        self.assertEqual(snapshot["open_calls"], 1)


if __name__ == "__main__":
    unittest.main()