#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import errno
import subprocess
import types
import unittest
from unittest import mock

from obstacle_bridge.bridge_tun_helper_linux import LinuxTunHelperBackend
import obstacle_bridge.bridge_tun_helper_linux as helper_linux


class _FakeSocket:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def fileno(self) -> int:
        return 77


class LinuxTunHelperBackendTests(unittest.IsolatedAsyncioTestCase):
    async def test_open_write_read_and_stop_round_trip(self) -> None:
        packets_seen: list[bytes] = []
        read_items = [
            b"\x45native-helper-ingress",
            BlockingIOError(),
            OSError(errno.EAGAIN, "again"),
        ]
        writes: list[tuple[int, bytes]] = []
        closes: list[int] = []

        def _fake_ioctl(fd, request, payload):
            if request == helper_linux._TUNSETIFF:
                return b"obtun9\x00".ljust(16, b"\x00")
            if request == helper_linux._SIOCGIFFLAGS:
                return (b"\x00" * 16) + (0).to_bytes(2, "little") + (b"\x00" * 14)
            return payload

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

        backend = LinuxTunHelperBackend(read_poll_interval_s=0.001)
        backend.set_packet_sink(_sink)

        with mock.patch.object(helper_linux.sys, "platform", "linux"), \
             mock.patch.object(helper_linux, "fcntl", types.SimpleNamespace(ioctl=_fake_ioctl)), \
             mock.patch.object(helper_linux.os, "open", return_value=55), \
             mock.patch.object(helper_linux.os, "set_blocking"), \
             mock.patch.object(helper_linux.os, "read", side_effect=_fake_read), \
             mock.patch.object(helper_linux.os, "write", side_effect=_fake_write), \
             mock.patch.object(helper_linux.os, "close", side_effect=_fake_close), \
             mock.patch.object(helper_linux.socket, "socket", return_value=_FakeSocket()):
            opened = await backend.open_tun({"ifname": "obtun0", "mtu": 1400})
            await asyncio.sleep(0.02)
            wrote = await backend.write_packet(b"\x45native-helper-egress")
            snapshot = await backend.snapshot()
            await backend.stop()

        self.assertEqual(opened["backend"], "linux-native")
        self.assertEqual(opened["ifname"], "obtun9")
        self.assertEqual(opened["mtu"], 1400)
        self.assertEqual(wrote["len"], len(b"\x45native-helper-egress"))
        self.assertEqual(writes, [(55, b"\x45native-helper-egress")])
        self.assertEqual(packets_seen, [b"\x45native-helper-ingress"])
        self.assertEqual(snapshot["packets_from_runtime"], 1)
        self.assertEqual(snapshot["packets_to_runtime"], 1)
        self.assertIn(55, closes)

    async def test_open_rejects_non_linux_platform(self) -> None:
        backend = LinuxTunHelperBackend()
        with mock.patch.object(helper_linux.sys, "platform", "darwin"):
            with self.assertRaisesRegex(RuntimeError, "supported only on Linux"):
                await backend.open_tun({"ifname": "obtun0", "mtu": 1400})

    async def test_apply_and_remove_network_programs_tunnel_addresses(self) -> None:
        backend = LinuxTunHelperBackend()
        commands: list[tuple[tuple[str, ...], bool]] = []

        def _fake_run(args, check, capture_output, text):
            self.assertEqual(args[0], "ip")
            commands.append((tuple(args[1:]), bool(check)))
            stdout = ""
            if tuple(args[1:]) == ("-4", "route", "show", "default"):
                stdout = "default via 172.20.10.1 dev wlp0s20f3 src 172.20.10.4\n"
            if tuple(args[1:]) == ("-6", "route", "show", "default"):
                stdout = "default via fe80::1 dev wlp0s20f3\n"
            return types.SimpleNamespace(returncode=0, stdout=stdout, stderr="")

        payload = {
            "ifname": "obtun5",
            "tun_routing": {
                "tunnel_address": "198.18.55.2",
                "tunnel_prefix": 24,
                "tunnel_address6": "fd20:155::2",
                "tunnel_prefix6": 64,
            },
        }

        with mock.patch.object(helper_linux.subprocess, "run", side_effect=_fake_run):
            applied = await backend.apply_network(payload)
            snapshot = await backend.snapshot()
            removed = await backend.remove_network(payload)

        self.assertTrue(applied["applied"])
        self.assertEqual(applied["applied_ipv4_cidr"], "198.18.55.2/24")
        self.assertEqual(applied["applied_ipv6_cidr"], "fd20:155::2/64")
        self.assertEqual(snapshot["applied_ipv4_cidr"], "198.18.55.2/24")
        self.assertEqual(snapshot["applied_ipv6_cidr"], "fd20:155::2/64")
        self.assertTrue(removed["removed"])
        self.assertEqual(
            commands,
            [
                (("-4", "addr", "replace", "198.18.55.2/24", "dev", "obtun5"), True),
                (("-6", "addr", "replace", "fd20:155::2/64", "dev", "obtun5"), True),
                (("-4", "route", "show", "default"), False),
                (("-6", "route", "show", "default"), False),
                (("-4", "addr", "del", "198.18.55.2/24", "dev", "obtun5"), False),
                (("-6", "addr", "del", "fd20:155::2/64", "dev", "obtun5"), False),
            ],
        )

    async def test_apply_and_remove_network_programs_non_default_included_routes(self) -> None:
        backend = LinuxTunHelperBackend()
        commands: list[tuple[tuple[str, ...], bool]] = []

        def _fake_run(args, check, capture_output, text):
            self.assertEqual(args[0], "ip")
            commands.append((tuple(args[1:]), bool(check)))
            stdout = ""
            if tuple(args[1:]) == ("-4", "route", "show", "default"):
                stdout = "default via 172.20.10.1 dev wlp0s20f3 src 172.20.10.4\n"
            if tuple(args[1:]) == ("-6", "route", "show", "default"):
                stdout = "default via fe80::1 dev wlp0s20f3\n"
            return types.SimpleNamespace(returncode=0, stdout=stdout, stderr="")

        payload = {
            "ifname": "obtun6",
            "tun_routing": {
                "tunnel_address": "198.18.56.2",
                "tunnel_prefix": 24,
                "tunnel_gateway": "198.18.56.1",
                "included_routes": ["198.18.57.0/24", "198.18.56.0/24"],
                "tunnel_address6": "fd20:156::2",
                "tunnel_prefix6": 64,
                "tunnel_gateway6": "fd20:156::1",
                "included_routes6": ["fd20:157::/64", "fd20:156::/64"],
            },
        }

        with mock.patch.object(helper_linux.subprocess, "run", side_effect=_fake_run):
            applied = await backend.apply_network(payload)
            snapshot = await backend.snapshot()
            removed = await backend.remove_network(payload)

        self.assertEqual(applied["applied_ipv4_routes"], ["198.18.57.0/24"])
        self.assertEqual(applied["applied_ipv6_routes"], ["fd20:157::/64"])
        self.assertEqual(snapshot["applied_ipv4_routes"], ["198.18.57.0/24"])
        self.assertEqual(snapshot["applied_ipv6_routes"], ["fd20:157::/64"])
        self.assertTrue(removed["removed"])
        self.assertEqual(
            commands,
            [
                (("-4", "addr", "replace", "198.18.56.2/24", "dev", "obtun6"), True),
                (("-6", "addr", "replace", "fd20:156::2/64", "dev", "obtun6"), True),
                (("-4", "route", "show", "default"), False),
                (("-6", "route", "show", "default"), False),
                (("-4", "route", "replace", "198.18.57.0/24", "via", "198.18.56.1", "dev", "obtun6", "onlink"), True),
                (("-6", "route", "replace", "fd20:157::/64", "via", "fd20:156::1", "dev", "obtun6", "metric", "1", "onlink"), True),
                (("-4", "route", "del", "198.18.57.0/24", "via", "198.18.56.1", "dev", "obtun6"), False),
                (("-4", "route", "del", "198.18.57.0/24", "dev", "obtun6"), False),
                (("-6", "route", "del", "fd20:157::/64", "via", "fd20:156::1", "dev", "obtun6"), False),
                (("-6", "route", "del", "fd20:157::/64", "dev", "obtun6"), False),
                (("-4", "addr", "del", "198.18.56.2/24", "dev", "obtun6"), False),
                (("-6", "addr", "del", "fd20:156::2/64", "dev", "obtun6"), False),
            ],
        )

    async def test_apply_and_remove_network_programs_dns_with_resolvectl(self) -> None:
        backend = LinuxTunHelperBackend()
        commands: list[tuple[tuple[str, ...], bool]] = []

        def _fake_run(args, check, capture_output, text):
            commands.append((tuple(args), bool(check)))
            stdout = ""
            if tuple(args) == ("ip", "-4", "route", "show", "default"):
                stdout = "default via 172.20.10.1 dev wlp0s20f3 src 172.20.10.4\n"
            if tuple(args) == ("ip", "-6", "route", "show", "default"):
                stdout = "default via fe80::1 dev wlp0s20f3\n"
            return types.SimpleNamespace(returncode=0, stdout=stdout, stderr="")

        payload = {
            "ifname": "obtun8",
            "tun_routing": {
                "tunnel_address": "198.18.60.2",
                "tunnel_prefix": 24,
                "dns_servers": ["9.9.9.9", "1.1.1.1"],
            },
        }

        with mock.patch.object(helper_linux.shutil, "which", return_value="/usr/bin/resolvectl"), \
             mock.patch.object(helper_linux.subprocess, "run", side_effect=_fake_run):
            applied = await backend.apply_network(payload)
            snapshot = await backend.snapshot()
            removed = await backend.remove_network(payload)

        self.assertEqual(applied["applied_dns_servers"], ["9.9.9.9", "1.1.1.1"])
        self.assertEqual(applied["dns_manager"], "resolvectl")
        self.assertEqual(snapshot["applied_dns_servers"], ["9.9.9.9", "1.1.1.1"])
        self.assertEqual(snapshot["dns_manager"], "resolvectl")
        self.assertTrue(removed["removed"])
        self.assertEqual(
            commands,
            [
                (("ip", "-4", "addr", "replace", "198.18.60.2/24", "dev", "obtun8"), True),
                (("ip", "-4", "route", "show", "default"), False),
                (("ip", "-6", "route", "show", "default"), False),
                (("/usr/bin/resolvectl", "dns", "obtun8", "9.9.9.9", "1.1.1.1"), True),
                (("/usr/bin/resolvectl", "domain", "obtun8", "~."), True),
                (("/usr/bin/resolvectl", "default-route", "obtun8", "yes"), True),
                (("/usr/bin/resolvectl", "revert", "obtun8"), False),
                (("ip", "-4", "addr", "del", "198.18.60.2/24", "dev", "obtun8"), False),
            ],
        )

    async def test_apply_network_skips_dns_when_resolvectl_is_unavailable(self) -> None:
        backend = LinuxTunHelperBackend()
        commands: list[tuple[tuple[str, ...], bool]] = []

        def _fake_run(args, check, capture_output, text):
            commands.append((tuple(args), bool(check)))
            stdout = ""
            if tuple(args) == ("ip", "-4", "route", "show", "default"):
                stdout = "default via 172.20.10.1 dev wlp0s20f3 src 172.20.10.4\n"
            if tuple(args) == ("ip", "-6", "route", "show", "default"):
                stdout = "default via fe80::1 dev wlp0s20f3\n"
            return types.SimpleNamespace(returncode=0, stdout=stdout, stderr="")

        payload = {
            "ifname": "obtun10",
            "tun_routing": {
                "tunnel_address": "198.18.61.2",
                "tunnel_prefix": 24,
                "dns_servers": ["9.9.9.9"],
            },
        }

        with mock.patch.object(helper_linux.shutil, "which", return_value=None), \
             mock.patch.object(helper_linux.subprocess, "run", side_effect=_fake_run):
            applied = await backend.apply_network(payload)
            removed = await backend.remove_network(payload)

        self.assertEqual(applied["applied_dns_servers"], [])
        self.assertEqual(applied["dns_manager"], "")
        self.assertTrue(removed["removed"])
        self.assertEqual(
            commands,
            [
                (("ip", "-4", "addr", "replace", "198.18.61.2/24", "dev", "obtun10"), True),
                (("ip", "-4", "route", "show", "default"), False),
                (("ip", "-6", "route", "show", "default"), False),
                (("ip", "-4", "addr", "del", "198.18.61.2/24", "dev", "obtun10"), False),
            ],
        )

    async def test_apply_network_records_failure_and_rolls_back_partial_state(self) -> None:
        backend = LinuxTunHelperBackend()
        commands: list[tuple[tuple[str, ...], bool]] = []

        def _fake_run(args, check, capture_output, text):
            commands.append((tuple(args), bool(check)))
            cmd = tuple(args)
            stdout = ""
            if cmd == ("ip", "-4", "route", "show", "default"):
                stdout = "default via 172.20.10.1 dev wlp0s20f3 src 172.20.10.4\n"
            elif cmd == ("ip", "-6", "route", "show", "default"):
                stdout = "default via fe80::1 dev wlp0s20f3\n"
            elif cmd == ("/usr/bin/resolvectl", "dns", "obtun11", "9.9.9.9"):
                raise subprocess.CalledProcessError(1, args, output="", stderr="dns failed")
            return types.SimpleNamespace(returncode=0, stdout=stdout, stderr="")

        payload = {
            "ifname": "obtun11",
            "tun_routing": {
                "tunnel_address": "198.18.62.2",
                "tunnel_prefix": 24,
                "dns_servers": ["9.9.9.9"],
            },
        }

        with mock.patch.object(helper_linux.shutil, "which", return_value="/usr/bin/resolvectl"), \
             mock.patch.object(helper_linux.subprocess, "run", side_effect=_fake_run):
            with self.assertRaises(subprocess.CalledProcessError):
                await backend.apply_network(payload)
            snapshot = await backend.snapshot()

        self.assertFalse(snapshot["network_applied"])
        self.assertEqual(snapshot["applied_ipv4_cidr"], "")
        self.assertEqual(snapshot["applied_dns_servers"], [])
        self.assertEqual(snapshot["dns_manager"], "")
        self.assertEqual(snapshot["last_failure"]["operation"], "apply_network")
        self.assertEqual(snapshot["last_failure"]["stage"], "dns_apply")
        self.assertEqual(snapshot["last_failure"]["error_type"], "CalledProcessError")
        self.assertTrue(snapshot["last_failure"]["cleanup_attempted"])
        self.assertTrue(snapshot["last_failure"]["cleanup_ok"])
        self.assertIn(
            (("ip", "-4", "addr", "del", "198.18.62.2/24", "dev", "obtun11"), False),
            commands,
        )

    async def test_apply_network_allows_test_injected_failure_and_rolls_back_partial_state(self) -> None:
        backend = LinuxTunHelperBackend()
        commands: list[tuple[tuple[str, ...], bool]] = []

        def _fake_run(args, check, capture_output, text):
            commands.append((tuple(args), bool(check)))
            cmd = tuple(args)
            stdout = ""
            if cmd == ("ip", "-4", "route", "show", "default"):
                stdout = "default via 172.20.10.1 dev wlp0s20f3 src 172.20.10.4\n"
            elif cmd == ("ip", "-6", "route", "show", "default"):
                stdout = "default via fe80::1 dev wlp0s20f3\n"
            elif cmd == ("ip", "-4", "route", "show", "dev", "wlp0s20f3", "proto", "kernel", "scope", "link"):
                stdout = "172.20.10.0/28 proto kernel scope link src 172.20.10.4\n"
            return types.SimpleNamespace(returncode=0, stdout=stdout, stderr="")

        payload = {
            "ifname": "obtun11",
            "tun_routing": {
                "tunnel_address": "198.18.62.2",
                "tunnel_prefix": 24,
                "included_routes": ["0.0.0.0/0"],
                "excluded_routes": ["203.0.113.19/32"],
            },
        }

        with mock.patch.dict(helper_linux.os.environ, {"OBSTACLEBRIDGE_TUN_HELPER_TEST_FAIL": "apply_network:dns_apply"}, clear=False), \
             mock.patch.object(helper_linux.subprocess, "run", side_effect=_fake_run):
            with self.assertRaisesRegex(RuntimeError, "test-injected helper failure"):
                await backend.apply_network(payload)
            snapshot = await backend.snapshot()

        self.assertFalse(snapshot["network_applied"])
        self.assertEqual(snapshot["applied_ipv4_cidr"], "")
        self.assertEqual(snapshot["applied_excluded_ipv4_routes"], [])
        self.assertEqual(snapshot["policy_table4"], 0)
        self.assertEqual(snapshot["last_failure"]["operation"], "apply_network")
        self.assertEqual(snapshot["last_failure"]["stage"], "dns_apply")
        self.assertEqual(snapshot["last_failure"]["error_type"], "RuntimeError")
        self.assertTrue(snapshot["last_failure"]["cleanup_attempted"])
        self.assertTrue(snapshot["last_failure"]["cleanup_ok"])
        self.assertIn(
            (("ip", "-4", "addr", "del", "198.18.62.2/24", "dev", "obtun11"), False),
            commands,
        )

    async def test_apply_and_remove_network_programs_excluded_routes_and_full_tunnel_policy(self) -> None:
        backend = LinuxTunHelperBackend()
        commands: list[tuple[tuple[str, ...], bool]] = []

        def _fake_run(args, check, capture_output, text):
            self.assertEqual(args[0], "ip")
            cmd = tuple(args[1:])
            commands.append((cmd, bool(check)))
            stdout = ""
            if cmd == ("-4", "route", "show", "default"):
                stdout = "default via 172.20.10.1 dev wlp0s20f3 src 172.20.10.4\n"
            elif cmd == ("-6", "route", "show", "default"):
                stdout = "default via fe80::1 dev wlp0s20f3\n"
            elif cmd == ("-4", "route", "show", "dev", "wlp0s20f3", "proto", "kernel", "scope", "link"):
                stdout = "172.20.10.0/28 proto kernel scope link src 172.20.10.4\n"
            elif cmd == ("-6", "route", "show", "dev", "wlp0s20f3", "proto", "kernel"):
                stdout = "fe80::/64 proto kernel metric 1024 pref medium\n"
            elif cmd == ("-4", "route", "show", "dev", "obtun7", "proto", "kernel", "scope", "link"):
                stdout = "198.18.58.0/24 proto kernel scope link src 198.18.58.2\n"
            elif cmd == ("-6", "route", "show", "dev", "obtun7", "proto", "kernel"):
                stdout = "fd20:158::/64 proto kernel metric 256 pref medium\n"
            return types.SimpleNamespace(returncode=0, stdout=stdout, stderr="")

        payload = {
            "ifname": "obtun7",
            "tun_routing": {
                "tunnel_address": "198.18.58.2",
                "tunnel_prefix": 24,
                "tunnel_gateway": "198.18.58.1",
                "included_routes": ["0.0.0.0/0", "198.18.59.0/24"],
                "excluded_routes": ["127.0.0.0/8", "38.180.143.5/32", "192.168.179.0/24"],
                "tunnel_address6": "fd20:158::2",
                "tunnel_prefix6": 64,
                "tunnel_gateway6": "fd20:158::1",
                "included_routes6": ["::/0", "fd20:159::/64"],
                "excluded_routes6": ["::1/128", "2001:db8::5/128"],
            },
        }

        with mock.patch.object(helper_linux.subprocess, "run", side_effect=_fake_run):
            applied = await backend.apply_network(payload)
            snapshot = await backend.snapshot()
            removed = await backend.remove_network(payload)

        self.assertEqual(applied["applied_excluded_ipv4_routes"], ["38.180.143.5/32", "192.168.179.0/24"])
        self.assertEqual(applied["applied_excluded_ipv6_routes"], ["2001:db8::5/128"])
        self.assertTrue(applied["policy_table4"] > 0)
        self.assertTrue(applied["policy_table6"] > 0)
        self.assertIn("to 0.0.0.0/0 lookup", " ".join(applied["policy_rules4"]))
        self.assertIn("to ::/0 lookup", " ".join(applied["policy_rules6"]))
        self.assertEqual(snapshot["applied_excluded_ipv4_routes"], ["38.180.143.5/32", "192.168.179.0/24"])
        self.assertEqual(snapshot["applied_excluded_ipv6_routes"], ["2001:db8::5/128"])
        self.assertTrue(removed["removed"])
        command_only = [cmd for cmd, _check in commands]
        self.assertIn(("-4", "route", "replace", "38.180.143.5/32", "via", "172.20.10.1", "dev", "wlp0s20f3", "src", "172.20.10.4"), command_only)
        self.assertIn(("-4", "route", "replace", "192.168.179.0/24", "via", "172.20.10.1", "dev", "wlp0s20f3", "src", "172.20.10.4"), command_only)
        self.assertIn(("-6", "route", "replace", "2001:db8::5/128", "via", "fe80::1", "dev", "wlp0s20f3"), command_only)
        self.assertIn(("-4", "route", "replace", "table", str(applied["policy_table4"]), "default", "via", "198.18.58.1", "dev", "obtun7", "onlink"), command_only)
        self.assertIn(("-6", "route", "replace", "table", str(applied["policy_table6"]), "default", "via", "fd20:158::1", "dev", "obtun7", "metric", "1", "onlink"), command_only)
        self.assertIn(("-4", "route", "del", "38.180.143.5/32"), command_only)
        self.assertIn(("-6", "route", "del", "2001:db8::5/128"), command_only)

    async def test_apply_and_remove_network_programs_server_firewall_rules(self) -> None:
        backend = LinuxTunHelperBackend()
        commands: list[tuple[tuple[str, ...], bool]] = []
        existing_rules: set[tuple[str, ...]] = set()

        def _rule_key(cmd: tuple[str, ...]) -> tuple[str, ...]:
            if cmd[0] not in {"iptables", "ip6tables"}:
                return cmd
            idx = 1
            parts = [cmd[0]]
            if len(cmd) > 2 and cmd[1] == "-t":
                parts.extend(["-t", cmd[2]])
                idx = 3
            op = cmd[idx]
            chain = cmd[idx + 1]
            return tuple([*parts, "-C" if op in {"-A", "-D", "-C"} else op, chain, *cmd[idx + 2 :]])

        def _fake_run(args, check, capture_output, text):
            cmd = tuple(args)
            commands.append((cmd, bool(check)))
            stdout = ""
            returncode = 0
            if cmd == ("ip", "-4", "route", "show", "default"):
                stdout = "default via 172.20.10.1 dev eth0 src 172.20.10.4\n"
            elif cmd == ("ip", "-6", "route", "show", "default"):
                stdout = "default via fe80::1 dev eth0\n"
            elif cmd[0] in {"iptables", "ip6tables"} and len(cmd) >= 4:
                key = _rule_key(cmd)
                idx = 1 if cmd[1] != "-t" else 3
                op = cmd[idx]
                if op == "-C":
                    if key not in existing_rules:
                        returncode = 1
                elif op == "-A":
                    existing_rules.add(key)
                elif op == "-D":
                    existing_rules.discard(key)
            result = types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")
            if check and returncode != 0:
                raise subprocess.CalledProcessError(returncode, args, output=stdout, stderr="")
            return result

        payload = {
            "ifname": "obtun12",
            "service_catalog": "own_servers",
            "listener_hook_env": {"WAN_IF": "eth0"},
            "tun_routing": {
                "tunnel_address": "198.18.63.2",
                "tunnel_prefix": 24,
                "tunnel_address6": "fd20:163::2",
                "tunnel_prefix6": 64,
                "enable_tcpmss": True,
            },
        }

        with mock.patch.object(helper_linux.subprocess, "run", side_effect=_fake_run):
            applied = await backend.apply_network(payload)
            snapshot = await backend.snapshot()
            removed = await backend.remove_network(payload)

        self.assertEqual(applied["firewall_manager"], "iptables")
        self.assertEqual(applied["firewall_wan_if"], "eth0")
        self.assertTrue(any("iptables -A FORWARD -i obtun12 -o eth0 -j ACCEPT" in rule for rule in applied["applied_firewall_rules"]))
        self.assertTrue(any("ip6tables -t nat -A POSTROUTING -s fd20:163::/64 -o eth0 -j MASQUERADE" in rule for rule in applied["applied_firewall_rules"]))
        self.assertEqual(snapshot["firewall_manager"], "iptables")
        self.assertEqual(snapshot["firewall_wan_if"], "eth0")
        self.assertTrue(removed["removed"])
        command_only = [cmd for cmd, _check in commands]
        self.assertIn(("sysctl", "-w", "net.ipv4.ip_forward=1"), command_only)
        self.assertIn(("sysctl", "-w", "net.ipv6.conf.all.forwarding=1"), command_only)
        self.assertIn(("iptables", "-A", "FORWARD", "-i", "obtun12", "-o", "eth0", "-j", "ACCEPT"), command_only)
        self.assertIn(("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "198.18.63.0/24", "-o", "eth0", "-j", "MASQUERADE"), command_only)
        self.assertIn(("iptables", "-t", "mangle", "-A", "FORWARD", "-i", "obtun12", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"), command_only)
        self.assertIn(("ip6tables", "-A", "FORWARD", "-i", "obtun12", "-o", "eth0", "-j", "ACCEPT"), command_only)
        self.assertIn(("ip6tables", "-t", "nat", "-A", "POSTROUTING", "-s", "fd20:163::/64", "-o", "eth0", "-j", "MASQUERADE"), command_only)
        self.assertEqual(backend.local_snapshot()["firewall_manager"], "")
        self.assertEqual(backend.local_snapshot()["firewall_wan_if"], "")

    async def test_apply_and_remove_network_programs_server_firewall_rules_for_remote_server_catalog(self) -> None:
        backend = LinuxTunHelperBackend()
        commands: list[tuple[tuple[str, ...], bool]] = []
        existing_rules: set[tuple[str, ...]] = set()

        def _rule_key(cmd: tuple[str, ...]) -> tuple[str, ...]:
            if cmd[0] not in {"iptables", "ip6tables"}:
                return cmd
            idx = 1
            parts = [cmd[0]]
            if len(cmd) > 2 and cmd[1] == "-t":
                parts.extend(["-t", cmd[2]])
                idx = 3
            op = cmd[idx]
            chain = cmd[idx + 1]
            return tuple([*parts, "-C" if op in {"-A", "-D", "-C"} else op, chain, *cmd[idx + 2 :]])

        def _fake_run(args, check, capture_output, text):
            cmd = tuple(args)
            commands.append((cmd, bool(check)))
            stdout = ""
            returncode = 0
            if cmd[0] in {"iptables", "ip6tables"} and len(cmd) >= 4:
                key = _rule_key(cmd)
                idx = 1 if cmd[1] != "-t" else 3
                op = cmd[idx]
                if op == "-C":
                    if key not in existing_rules:
                        returncode = 1
                elif op == "-A":
                    existing_rules.add(key)
                elif op == "-D":
                    existing_rules.discard(key)
            result = types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")
            if check and returncode != 0:
                raise subprocess.CalledProcessError(returncode, args, output=stdout, stderr="")
            return result

        payload = {
            "ifname": "obtun13",
            "service_catalog": "remote_servers",
            "listener_hook_env": {"WAN_IF": "eth0"},
            "tun_routing": {
                "tunnel_address": "198.18.64.2",
                "tunnel_prefix": 24,
                "enable_tcpmss": True,
            },
        }

        with mock.patch.object(helper_linux.subprocess, "run", side_effect=_fake_run):
            applied = await backend.apply_network(payload)
            removed = await backend.remove_network(payload)

        self.assertEqual(applied["firewall_manager"], "iptables")
        self.assertEqual(applied["firewall_wan_if"], "eth0")
        self.assertTrue(removed["removed"])
        command_only = [cmd for cmd, _check in commands]
        self.assertIn(("sysctl", "-w", "net.ipv4.ip_forward=1"), command_only)
        self.assertIn(("iptables", "-A", "FORWARD", "-i", "obtun13", "-o", "eth0", "-j", "ACCEPT"), command_only)
        self.assertIn(("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "198.18.64.0/24", "-o", "eth0", "-j", "MASQUERADE"), command_only)
        self.assertEqual(backend.local_snapshot()["firewall_manager"], "")

    def test_repair_runtime_snapshot_replays_cleanup_without_live_helper_process(self) -> None:
        commands: list[tuple[tuple[str, ...], bool]] = []
        existing_rules: set[tuple[str, ...]] = set()

        def _rule_key(cmd: tuple[str, ...]) -> tuple[str, ...]:
            if cmd[0] not in {"iptables", "ip6tables"}:
                return cmd
            idx = 1
            parts = [cmd[0]]
            if len(cmd) > 2 and cmd[1] == "-t":
                parts.extend(["-t", cmd[2]])
                idx = 3
            op = cmd[idx]
            chain = cmd[idx + 1]
            return tuple([*parts, "-C" if op in {"-A", "-D", "-C"} else op, chain, *cmd[idx + 2 :]])

        def _fake_run(args, check, capture_output, text):
            cmd = tuple(args)
            commands.append((cmd, bool(check)))
            returncode = 0
            if cmd[0] in {"iptables", "ip6tables"} and len(cmd) >= 4:
                key = _rule_key(cmd)
                idx = 1 if cmd[1] != "-t" else 3
                op = cmd[idx]
                if op == "-C":
                    returncode = 0 if key in existing_rules else 1
                elif op == "-D":
                    existing_rules.discard(key)
            result = types.SimpleNamespace(returncode=returncode, stdout="", stderr="")
            if check and returncode != 0:
                raise subprocess.CalledProcessError(returncode, args, output="", stderr="")
            return result

        existing_rules.update(
            {
                ("iptables", "-C", "FORWARD", "-i", "obtun0", "-o", "eth0", "-j", "ACCEPT"),
                ("iptables", "-C", "FORWARD", "-i", "eth0", "-o", "obtun0", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"),
                ("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", "198.18.40.0/24", "-o", "eth0", "-j", "MASQUERADE"),
            }
        )
        runtime_snapshot = {
            "backend": "linux-native",
            "ifname": "obtun0",
            "network_applied": True,
            "applied_ipv4_cidr": "198.18.40.1/24",
            "applied_ipv4_routes": ["198.18.41.0/24"],
            "applied_excluded_ipv4_routes": ["203.0.113.210/32"],
            "applied_dns_servers": ["1.1.1.1"],
            "dns_manager": "resolvectl",
            "firewall_manager": "iptables",
            "firewall_wan_if": "eth0",
            "applied_firewall_rules": [
                "iptables -A FORWARD -i obtun0 -o eth0 -j ACCEPT",
                "iptables -A FORWARD -i eth0 -o obtun0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
                "iptables -t nat -A POSTROUTING -s 198.18.40.0/24 -o eth0 -j MASQUERADE",
            ],
            "last_apply_payload": {
                "ifname": "obtun0",
                "listener_hook_env": {"WAN_IF": "eth0"},
                "tun_routing": {
                    "tunnel_address": "198.18.40.1",
                    "tunnel_prefix": 24,
                    "included_routes": ["198.18.41.0/24"],
                    "excluded_routes": ["203.0.113.210/32"],
                },
            },
        }

        with mock.patch.object(helper_linux.subprocess, "run", side_effect=_fake_run), \
             mock.patch.object(helper_linux.LinuxTunHelperBackend, "_resolvectl_path", return_value="/usr/bin/resolvectl"):
            repaired = helper_linux.LinuxTunHelperBackend.repair_runtime_snapshot(runtime_snapshot)

        self.assertTrue(repaired["ok"])
        self.assertEqual(repaired["failed"], [])
        self.assertIn("included_routes", repaired["repaired"])
        self.assertIn("excluded_routes", repaired["repaired"])
        self.assertIn("firewall", repaired["repaired"])
        self.assertIn("dns", repaired["repaired"])
        command_only = [cmd for cmd, _check in commands]
        self.assertIn(("ip", "-4", "route", "del", "198.18.41.0/24", "dev", "obtun0"), command_only)
        self.assertIn(("ip", "-4", "route", "del", "203.0.113.210/32"), command_only)
        self.assertIn(("/usr/bin/resolvectl", "revert", "obtun0"), command_only)
        self.assertIn(("ip", "-4", "addr", "del", "198.18.40.1/24", "dev", "obtun0"), command_only)
        self.assertEqual(repaired["runtime"]["firewall_manager"], "")
        self.assertFalse(repaired["runtime"]["network_applied"])

    def test_verify_runtime_snapshot_repaired_reports_remaining_and_skipped_state(self) -> None:
        runtime_snapshot = {
            "ifname": "obtun0",
            "applied_ipv4_cidr": "198.18.40.1/24",
            "applied_ipv4_routes": ["198.18.41.0/24"],
            "applied_excluded_ipv4_routes": ["203.0.113.210/32"],
            "policy_rules4": ["to 203.0.113.210/32 lookup main"],
            "applied_firewall_rules": ["iptables -A FORWARD -i obtun0 -o eth0 -j ACCEPT"],
            "applied_dns_servers": ["198.18.40.1"],
        }

        def _fake_run(args, check, capture_output, text):
            cmd = tuple(args)
            stdout = ""
            if cmd == ("ip", "-4", "addr", "show", "dev", "obtun0"):
                stdout = "2: obtun0    inet 198.18.40.1/24 scope global obtun0\n"
            elif cmd == ("ip", "-4", "route", "show", "198.18.41.0/24"):
                stdout = "198.18.41.0/24 dev obtun0 scope link\n"
            elif cmd == ("ip", "-4", "route", "show", "203.0.113.210/32"):
                stdout = ""
            elif cmd == ("ip", "-4", "rule", "show"):
                stdout = "10000:   to 203.0.113.210/32 lookup main\n"
            return types.SimpleNamespace(returncode=0, stdout=stdout, stderr="")

        with mock.patch.object(helper_linux.subprocess, "run", side_effect=_fake_run), \
             mock.patch.object(helper_linux.LinuxTunHelperBackend, "_iptables_rule_exists", return_value=True), \
             mock.patch.object(helper_linux.LinuxTunHelperBackend, "_resolvectl_path", return_value=""):
            verification = helper_linux.LinuxTunHelperBackend.verify_runtime_snapshot_repaired(runtime_snapshot)

        self.assertFalse(verification["ok"])
        self.assertTrue(verification["stale_state_remaining"])
        remaining_steps = [item["step"] for item in verification["remaining"]]
        self.assertIn("ipv4_addr", remaining_steps)
        self.assertIn("included_routes", remaining_steps)
        self.assertIn("policy_rules4", remaining_steps)
        self.assertIn("firewall", remaining_steps)
        skipped_steps = [item["step"] for item in verification["skipped"]]
        self.assertIn("dns", skipped_steps)

    def test_iptables_rule_exists_treats_zero_returncode_as_present(self) -> None:
        result = types.SimpleNamespace(returncode=0, stdout="", stderr="")
        with mock.patch.object(helper_linux.LinuxTunHelperBackend, "_run_command", return_value=result):
            present = helper_linux.LinuxTunHelperBackend._iptables_rule_exists(
                "iptables",
                "",
                "FORWARD",
                ["-i", "obtun0", "-o", "eth0", "-j", "ACCEPT"],
            )
        self.assertTrue(present)


if __name__ == "__main__":
    unittest.main()
