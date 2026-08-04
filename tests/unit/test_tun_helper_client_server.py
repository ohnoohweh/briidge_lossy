#!/usr/bin/env python3
import asyncio
import os
import sys
import tempfile
import unittest
import uuid

from obstacle_bridge.bridge_tun_helper_client import TunHelperClient
from obstacle_bridge.bridge_tun_helper_server import TunHelperServer


def _test_helper_endpoint(tmp_dir: str) -> str:
    if sys.platform == "win32":
        return f"\\\\.\\pipe\\obstaclebridge-test-{uuid.uuid4().hex}"
    return os.path.join(tmp_dir, "tun-helper.sock")


class _FakeHelperBackend:
    def __init__(self) -> None:
        self._sink = None
        self.open_calls = 0
        self.last_open_payload = {}
        self.last_apply_payload = {}
        self.last_remove_payload = {}
        self.apply_calls = 0
        self.remove_calls = 0
        self.network_applied = False
        self.written_packets: list[bytes] = []
        self.stopped = False

    def set_packet_sink(self, sink) -> None:
        self._sink = sink

    async def open_tun(self, payload):
        self.open_calls += 1
        self.last_open_payload = dict(payload)
        return {
            "ifname": str(payload.get("ifname") or "obtun0"),
            "mtu": int(payload.get("mtu") or 1600),
            "backend": "fake",
        }

    async def write_packet(self, packet: bytes):
        self.written_packets.append(bytes(packet))
        if self._sink is not None:
            result = self._sink(b"echo:" + bytes(packet))
            if asyncio.iscoroutine(result):
                await result
        return {"accepted": True}

    async def apply_network(self, payload):
        self.apply_calls += 1
        self.network_applied = True
        self.last_apply_payload = dict(payload)
        return {"applied": True, "ifname": str(payload.get("ifname") or "obtun0")}

    async def remove_network(self, payload):
        self.remove_calls += 1
        self.network_applied = False
        self.last_remove_payload = dict(payload)
        return {"removed": True, "ifname": str(payload.get("ifname") or "obtun0")}

    async def snapshot(self):
        return {
            "backend": "fake",
            "open_calls": self.open_calls,
            "apply_calls": self.apply_calls,
            "remove_calls": self.remove_calls,
            "network_applied": self.network_applied,
            "written_packets": len(self.written_packets),
            "stopped": self.stopped,
        }

    async def stop(self):
        self.stopped = True


class TunHelperClientServerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.socket_path = _test_helper_endpoint(self._tmp.name)
        self.backend = _FakeHelperBackend()
        self.server = TunHelperServer(backend=self.backend, session_token="secret")
        await self.server.start(self.socket_path)

    async def asyncTearDown(self) -> None:
        await self.server.stop()
        self._tmp.cleanup()

    async def test_client_server_handshake_open_snapshot_and_packet_loop(self) -> None:
        client = TunHelperClient(socket_path=self.socket_path, session_token="secret")
        await client.connect()

        opened = await client.open_tun({"ifname": "obtun0", "mtu": 1600})
        await client.write_packet(b"\x01\x02hello")
        echoed = await asyncio.wait_for(client.read_packet(), timeout=1.0)
        cached_after_packets = client.cached_snapshot()
        snap = await client.snapshot()
        await client.close()

        self.assertEqual(opened["ifname"], "obtun0")
        self.assertEqual(opened["mtu"], 1600)
        self.assertEqual(self.backend.last_open_payload["ifname"], "obtun0")
        self.assertEqual(self.backend.written_packets, [b"\x01\x02hello"])
        self.assertEqual(echoed, b"echo:\x01\x02hello")
        self.assertEqual(cached_after_packets["packets_from_runtime"], 1)
        self.assertEqual(cached_after_packets["packets_to_runtime"], 1)
        self.assertEqual(snap["backend"], "fake")
        self.assertEqual(snap["open_calls"], 1)
        self.assertEqual(snap["written_packets"], 1)

    async def test_client_apply_and_remove_network_round_trip(self) -> None:
        client = TunHelperClient(socket_path=self.socket_path, session_token="secret")
        await client.connect()

        applied = await client.apply_network({"ifname": "obtun0", "mtu": 1600})
        snap_after_apply = await client.snapshot()
        removed = await client.remove_network({"ifname": "obtun0", "mtu": 1600})
        snap_after_remove = await client.snapshot()
        await client.close()

        self.assertTrue(applied["applied"])
        self.assertEqual(self.backend.last_apply_payload["ifname"], "obtun0")
        self.assertEqual(snap_after_apply["apply_calls"], 1)
        self.assertTrue(snap_after_apply["network_applied"])
        self.assertTrue(removed["removed"])
        self.assertEqual(self.backend.last_remove_payload["mtu"], 1600)
        self.assertEqual(snap_after_remove["remove_calls"], 1)
        self.assertFalse(snap_after_remove["network_applied"])

    async def test_client_apply_failure_keeps_connection_open_for_snapshot(self) -> None:
        class _FailingBackend(_FakeHelperBackend):
            async def apply_network(self, payload):
                self.apply_calls += 1
                self.network_applied = False
                self.last_apply_payload = dict(payload)
                raise RuntimeError("dns failed")

            async def snapshot(self):
                payload = await super().snapshot()
                payload["last_failure"] = {
                    "operation": "apply_network",
                    "stage": "dns_apply",
                    "error_type": "RuntimeError",
                    "detail": "dns failed",
                    "cleanup_attempted": True,
                    "cleanup_ok": True,
                    "unix_ts": 1700000400.0,
                }
                return payload

        await self.server.stop()
        self.backend = _FailingBackend()
        self.server = TunHelperServer(backend=self.backend, session_token="secret")
        await self.server.start(self.socket_path)

        client = TunHelperClient(socket_path=self.socket_path, session_token="secret")
        await client.connect()

        with self.assertRaisesRegex(RuntimeError, "dns failed"):
            await client.apply_network({"ifname": "obtun0"})
        snap = await client.snapshot()
        await client.close()

        self.assertEqual(snap["last_failure"]["operation"], "apply_network")
        self.assertEqual(snap["last_failure"]["stage"], "dns_apply")

    async def test_client_rejects_wrong_session_token(self) -> None:
        client = TunHelperClient(socket_path=self.socket_path, session_token="wrong")

        with self.assertRaisesRegex(RuntimeError, "invalid session token"):
            await client.connect()

        await client.close()

    async def test_client_reports_connection_closed_after_server_stop(self) -> None:
        client = TunHelperClient(socket_path=self.socket_path, session_token="secret")
        await client.connect()
        await asyncio.wait_for(self.server.stop(), timeout=1.0)

        with self.assertRaises(ConnectionError):
            await client.snapshot()

        await client.close()

    async def test_server_stops_after_authenticated_client_disconnects(self) -> None:
        client = TunHelperClient(socket_path=self.socket_path, session_token="secret")
        await client.connect()
        await client.open_tun({"ifname": "obtun0", "mtu": 1600})
        await client.apply_network({"ifname": "obtun0", "mtu": 1600})
        await client.close()

        for _ in range(20):
            if self.backend.stopped:
                break
            await asyncio.sleep(0.5)

        self.assertTrue(self.backend.stopped)
        if not self.socket_path.startswith("\\\\.\\pipe\\"):
            self.assertFalse(os.path.exists(self.socket_path))


if __name__ == "__main__":
    unittest.main()
