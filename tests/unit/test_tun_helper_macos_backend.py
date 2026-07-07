#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import errno
import socket
import types
import unittest
from unittest import mock

from obstacle_bridge.bridge_tun_helper_macos import DarwinTunHelperBackend
import obstacle_bridge.bridge_tun_helper_macos as helper_macos


class _FakeSocket:
    def __init__(self) -> None:
        self.closed = False

    def fileno(self) -> int:
        return 77

    def detach(self) -> int:
        return 55

    def close(self) -> None:
        self.closed = True


class DarwinTunHelperBackendTests(unittest.IsolatedAsyncioTestCase):
    async def test_open_write_read_and_stop_wraps_utun_frames(self) -> None:
        packets_seen: list[bytes] = []
        writes: list[tuple[int, bytes]] = []
        closes: list[int] = []
        incoming_packet = b"\x45darwin-helper-ingress"
        incoming_frame = socket.AF_INET.to_bytes(4, "big") + incoming_packet
        read_items = [incoming_frame, BlockingIOError(), OSError(errno.EAGAIN, "again")]

        def _fake_read(fd, size):
            item = read_items.pop(0)
            if isinstance(item, BaseException):
                raise item
            return item

        def _fake_write(fd, data):
            writes.append((fd, bytes(data)))
            return len(data)

        def _fake_close(fd):
            closes.append(fd)

        async def _sink(packet: bytes) -> None:
            packets_seen.append(bytes(packet))

        backend = DarwinTunHelperBackend(read_poll_interval_s=0.001)
        backend.set_packet_sink(_sink)

        with mock.patch.object(helper_macos.sys, "platform", "darwin"), \
             mock.patch.object(helper_macos.bridge_tun_macos.sys, "platform", "darwin"), \
             mock.patch.object(helper_macos.bridge_tun_macos.socket, "socket", return_value=_FakeSocket()), \
             mock.patch.object(helper_macos.bridge_tun_macos, "_lookup_utun_control_id", return_value=123), \
             mock.patch.object(helper_macos.bridge_tun_macos, "_connect_utun"), \
             mock.patch.object(helper_macos.bridge_tun_macos, "_query_utun_ifname", return_value="utun9"), \
             mock.patch.object(helper_macos.bridge_tun_macos, "_set_iface_mtu_and_up"), \
             mock.patch.object(helper_macos.os, "set_blocking"), \
             mock.patch.object(helper_macos.os, "read", side_effect=_fake_read), \
             mock.patch.object(helper_macos.os, "write", side_effect=_fake_write), \
             mock.patch.object(helper_macos.os, "close", side_effect=_fake_close):
            opened = await backend.open_tun({"ifname": "obtun0", "mtu": 1400})
            await asyncio.sleep(0.02)
            wrote = await backend.write_packet(b"\x45darwin-helper-egress")
            snapshot = await backend.snapshot()
            await backend.stop()

        self.assertEqual(opened["backend"], "darwin-native")
        self.assertEqual(opened["ifname"], "utun9")
        self.assertEqual(opened["mtu"], 1400)
        self.assertEqual(wrote["len"], len(b"\x45darwin-helper-egress"))
        self.assertEqual(writes, [(55, socket.AF_INET.to_bytes(4, "big") + b"\x45darwin-helper-egress")])
        self.assertEqual(packets_seen, [incoming_packet])
        self.assertEqual(snapshot["packets_from_runtime"], 1)
        self.assertEqual(snapshot["packets_to_runtime"], 1)
        self.assertIn(55, closes)

    async def test_open_rejects_non_macos_platform(self) -> None:
        backend = DarwinTunHelperBackend()
        with mock.patch.object(helper_macos.sys, "platform", "linux"):
            with self.assertRaisesRegex(RuntimeError, "supported only on macOS"):
                await backend.open_tun({"ifname": "utun0", "mtu": 1400})

    async def test_apply_and_remove_local_network_uses_client_macos_hook_env(self) -> None:
        backend = DarwinTunHelperBackend()
        backend._ifname = "utun4"
        backend._mtu = 1410
        calls: list[tuple[list[str], dict[str, str]]] = []

        def _fake_run_hook(argv, env):
            calls.append((list(argv), dict(env)))
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")

        payload = {
            "ifname": "requested-utun",
            "mtu": 1410,
            "service_catalog": "own_servers",
            "tun_routing": {
                "tunnel_address": "10.20.0.1",
                "tunnel_prefix": 30,
                "tunnel_gateway": "10.20.0.2",
                "included_routes": ["0.0.0.0/0"],
                "excluded_routes": ["127.0.0.0/8", "203.0.113.10/32"],
                "dns_servers": ["9.9.9.9", "1.1.1.1"],
            },
            "listener_hook_env": {"OB_OVERLAY_PEER_HOST": "203.0.113.10"},
        }

        with mock.patch.object(DarwinTunHelperBackend, "_run_hook", side_effect=_fake_run_hook):
            applied = await backend.apply_network(payload)
            removed = await backend.remove_network(payload)

        self.assertTrue(applied["applied"])
        self.assertTrue(removed["removed"])
        self.assertEqual(applied["mtu"], 1410)
        self.assertEqual(applied["packets_from_runtime"], 0)
        self.assertEqual(applied["packets_to_runtime"], 0)
        self.assertEqual(removed["mtu"], 1410)
        self.assertEqual(calls[0][0][-2:], ["up", "utun4"])
        self.assertTrue(calls[0][0][0].endswith("scripts/client-tun-hook-macos.sh"))
        self.assertEqual(calls[0][1]["TUN_ADDR"], "10.20.0.1/30")
        self.assertEqual(calls[0][1]["TUN_GW"], "10.20.0.2")
        self.assertEqual(calls[0][1]["DNS1"], "9.9.9.9")
        self.assertEqual(calls[0][1]["DNS2"], "1.1.1.1")
        self.assertEqual(calls[0][1]["EXCLUDED_ROUTES"], "127.0.0.0/8,203.0.113.10/32")
        self.assertEqual(calls[0][1]["OB_OVERLAY_PEER_HOST"], "203.0.113.10")
        self.assertEqual(calls[1][0][-2:], ["down", "utun4"])

    async def test_apply_server_network_uses_server_macos_hook_env(self) -> None:
        backend = DarwinTunHelperBackend()
        backend._ifname = "utun5"
        calls: list[tuple[list[str], dict[str, str]]] = []

        def _fake_run_hook(argv, env):
            calls.append((list(argv), dict(env)))
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")

        payload = {
            "service_catalog": "remote_servers",
            "tun_routing": {
                "tunnel_address": "10.30.0.1",
                "tunnel_prefix": 30,
                "tunnel_gateway": "10.30.0.2",
                "tunnel_address6": "fd20:30::1",
                "tunnel_prefix6": 126,
                "tunnel_gateway6": "fd20:30::2",
            },
        }

        with mock.patch.object(DarwinTunHelperBackend, "_run_hook", side_effect=_fake_run_hook):
            applied = await backend.apply_network(payload)

        self.assertTrue(applied["applied"])
        self.assertTrue(calls[0][0][0].endswith("scripts/server-tun-hook-macos.sh"))
        self.assertEqual(calls[0][0][-2:], ["up", "utun5"])
        self.assertEqual(calls[0][1]["TUN_ADDR"], "10.30.0.2/30")
        self.assertEqual(calls[0][1]["PEER_ADDR"], "10.30.0.1")
        self.assertEqual(calls[0][1]["TUN_ADDR6"], "fd20:30::2/126")
        self.assertEqual(calls[0][1]["PEER_ADDR6"], "fd20:30::1")


if __name__ == "__main__":
    unittest.main()
