#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import unittest
from unittest import mock

from obstacle_bridge.bridge_tun_helper_windows import WindowsTunHelperBackend
import obstacle_bridge.bridge_tun_helper_windows as helper_windows


class WindowsTunHelperBackendTests(unittest.IsolatedAsyncioTestCase):
    async def test_open_write_read_and_stop_wraps_existing_wintun_adapter_path(self) -> None:
        packets_seen: list[bytes] = []
        writes: list[bytes] = []
        closes: list[object] = []

        async def _sink(packet: bytes) -> None:
            packets_seen.append(bytes(packet))

        def _fake_open_tun_device(mux, ifname, mtu, service_key=None):
            del service_key

            class _FakeAdapter:
                def write(self, data: bytes) -> None:
                    writes.append(bytes(data))

                def close(self) -> None:
                    closes.append("adapter")

            dev = mux.TunDevice(fd=None, ifname=ifname + "-real", mtu=int(mtu), service_key=None)
            setattr(dev, "wintun_adapter", _FakeAdapter())
            return dev

        def _fake_register_tun_reader(mux, dev) -> None:
            dev.reader_registered = True
            mux._on_local_tun_packet(dev, b"\x45helper-windows-ingress")

        def _fake_write_tun_packet(mux, dev, data: bytes) -> None:
            del mux
            adapter = getattr(dev, "wintun_adapter", None)
            if adapter is not None:
                adapter.write(bytes(data))

        def _fake_close_tun_device(_mux, dev) -> None:
            close_fn = getattr(getattr(dev, "wintun_adapter", None), "close", None)
            if callable(close_fn):
                close_fn()

        backend = WindowsTunHelperBackend()
        backend.set_packet_sink(_sink)

        with mock.patch.object(helper_windows.bridge_tun_windows, "require_tun_support"), \
             mock.patch.object(helper_windows.bridge_tun_windows, "open_tun_device", side_effect=_fake_open_tun_device), \
             mock.patch.object(helper_windows.bridge_tun_windows, "register_tun_reader", side_effect=_fake_register_tun_reader), \
             mock.patch.object(helper_windows.bridge_tun_windows, "write_tun_packet", side_effect=_fake_write_tun_packet), \
             mock.patch.object(helper_windows.bridge_tun_windows, "close_tun_device", side_effect=_fake_close_tun_device):
            opened = await backend.open_tun({"ifname": "obtunw0", "mtu": 1400})
            await asyncio.sleep(0.02)
            wrote = await backend.write_packet(b"\x45helper-windows-egress")
            snapshot = await backend.snapshot()
            await backend.stop()

        self.assertEqual(opened["backend"], "windows-native")
        self.assertEqual(opened["ifname"], "obtunw0-real")
        self.assertEqual(opened["mtu"], 1400)
        self.assertEqual(wrote["len"], len(b"\x45helper-windows-egress"))
        self.assertEqual(writes, [b"\x45helper-windows-egress"])
        self.assertEqual(packets_seen, [b"\x45helper-windows-ingress"])
        self.assertEqual(snapshot["packets_from_runtime"], 1)
        self.assertEqual(snapshot["packets_to_runtime"], 1)
        self.assertIn("adapter", closes)

    async def test_apply_and_remove_network_programs_addresses_routes_and_dns(self) -> None:
        backend = WindowsTunHelperBackend()
        commands: list[tuple[str, bool]] = []

        def _fake_run_powershell(command: str, *, check: bool = True):
            commands.append((str(command), bool(check)))
            return mock.Mock(returncode=0, stdout="", stderr="")

        payload = {
            "ifname": "obtunw1",
            "listener_hook_env": {"WAN_IF": "Ethernet"},
            "tun_routing": {
                "tunnel_address": "198.18.60.2",
                "tunnel_prefix": 24,
                "included_routes": ["0.0.0.0/0", "198.18.61.0/24", "198.18.60.0/24"],
                "excluded_routes": ["203.0.113.7/32", "127.0.0.0/8"],
                "dns_servers": ["9.9.9.9", "1.1.1.1"],
            },
        }

        with mock.patch.object(backend, "_resolve_interface_index", return_value=55), \
             mock.patch.object(backend, "_snapshot_default_route", side_effect=[{"InterfaceIndex": 12, "NextHop": "172.20.10.1"}, {}]), \
             mock.patch.object(backend, "_run_powershell", side_effect=_fake_run_powershell):
            applied = await backend.apply_network(payload)
            snapshot = await backend.snapshot()
            removed = await backend.remove_network(payload)

        self.assertTrue(applied["applied"])
        self.assertEqual(applied["applied_ipv4_cidr"], "198.18.60.2/24")
        self.assertEqual(applied["applied_ipv4_routes"], ["0.0.0.0/0", "198.18.61.0/24"])
        self.assertEqual(applied["applied_excluded_ipv4_routes"], ["203.0.113.7/32"])
        self.assertEqual(applied["applied_dns_servers"], ["9.9.9.9", "1.1.1.1"])
        self.assertEqual(applied["firewall_manager"], "windows-firewall")
        self.assertEqual(applied["firewall_wan_if"], "Ethernet")
        self.assertEqual(
            applied["applied_firewall_rules"],
            [
                "ObstacleBridge-TunHelper-obtunw1-IPv4-Inbound",
                "ObstacleBridge-TunHelper-obtunw1-IPv4-Outbound",
            ],
        )
        self.assertEqual(snapshot["applied_ipv4_cidr"], "198.18.60.2/24")
        self.assertEqual(snapshot["applied_ipv4_routes"], ["0.0.0.0/0", "198.18.61.0/24"])
        self.assertEqual(snapshot["dns_manager"], "dnsclient")
        self.assertEqual(snapshot["firewall_manager"], "windows-firewall")
        self.assertTrue(removed["removed"])
        joined = "\n".join(command for command, _check in commands)
        self.assertIn("New-NetIPAddress -InterfaceIndex 55 -IPAddress '198.18.60.2' -PrefixLength 24", joined)
        self.assertIn("New-NetRoute -InterfaceIndex 12 -AddressFamily IPv4 -DestinationPrefix '203.0.113.7/32' -NextHop '172.20.10.1'", joined)
        self.assertIn("New-NetRoute -InterfaceIndex 55 -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -NextHop '0.0.0.0'", joined)
        self.assertIn("New-NetRoute -InterfaceIndex 55 -AddressFamily IPv4 -DestinationPrefix '198.18.61.0/24' -NextHop '0.0.0.0'", joined)
        self.assertIn("Set-DnsClientServerAddress -InterfaceIndex 55 -ServerAddresses @('9.9.9.9', '1.1.1.1')", joined)
        self.assertIn("New-NetFirewallRule -DisplayName 'ObstacleBridge-TunHelper-obtunw1-IPv4-Inbound' -Direction 'Inbound' -Action Allow -Enabled True -Profile Any -RemoteAddress '198.18.60.0/24' -InterfaceAlias 'Ethernet'", joined)
        self.assertIn("New-NetFirewallRule -DisplayName 'ObstacleBridge-TunHelper-obtunw1-IPv4-Outbound' -Direction 'Outbound' -Action Allow -Enabled True -Profile Any -RemoteAddress '198.18.60.0/24' -InterfaceAlias 'Ethernet'", joined)
        self.assertIn("Set-DnsClientServerAddress -InterfaceIndex 55 -ResetServerAddresses", joined)
        self.assertIn("Remove-NetRoute -InterfaceIndex 55 -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0'", joined)
        self.assertIn("Remove-NetIPAddress -InterfaceIndex 55 -IPAddress '198.18.60.2'", joined)

    async def test_apply_network_rolls_back_partial_state_when_dns_apply_fails(self) -> None:
        backend = WindowsTunHelperBackend()
        commands: list[tuple[str, bool]] = []

        def _fake_run_powershell(command: str, *, check: bool = True):
            commands.append((str(command), bool(check)))
            if "Set-DnsClientServerAddress -InterfaceIndex 55 -ServerAddresses" in str(command):
                raise RuntimeError("dns failed")
            return mock.Mock(returncode=0, stdout="", stderr="")

        payload = {
            "ifname": "obtunw2",
            "tun_routing": {
                "tunnel_address": "198.18.62.2",
                "tunnel_prefix": 24,
                "included_routes": ["198.18.63.0/24"],
                "dns_servers": ["9.9.9.9"],
            },
        }

        with mock.patch.object(backend, "_resolve_interface_index", return_value=55), \
             mock.patch.object(backend, "_snapshot_default_route", side_effect=[{}, {}]), \
             mock.patch.object(backend, "_run_powershell", side_effect=_fake_run_powershell):
            with self.assertRaisesRegex(RuntimeError, "dns failed"):
                await backend.apply_network(payload)

        snapshot = await backend.snapshot()
        joined = "\n".join(command for command, _check in commands)
        self.assertEqual(snapshot["last_failure"]["operation"], "apply_network")
        self.assertEqual(snapshot["last_failure"]["stage"], "dns_apply")
        self.assertTrue(snapshot["last_failure"]["cleanup_attempted"])
        self.assertEqual(snapshot["applied_ipv4_cidr"], "")
        self.assertEqual(snapshot["applied_ipv4_routes"], [])
        self.assertIn("Remove-NetRoute -InterfaceIndex 55 -AddressFamily IPv4 -DestinationPrefix '198.18.63.0/24'", joined)
        self.assertIn("Remove-NetIPAddress -InterfaceIndex 55 -IPAddress '198.18.62.2'", joined)

    async def test_apply_network_reports_interface_lookup_failure(self) -> None:
        backend = WindowsTunHelperBackend()

        with mock.patch.object(backend, "_resolve_interface_index", side_effect=RuntimeError("missing interface index")):
            with self.assertRaisesRegex(RuntimeError, "missing interface index"):
                await backend.apply_network({"ifname": "obtunw1"})

        snapshot = await backend.snapshot()
        self.assertEqual(snapshot["apply_calls"], 1)
        self.assertEqual(snapshot["last_failure"]["operation"], "apply_network")
        self.assertEqual(snapshot["last_failure"]["stage"], "start")

    def test_repair_runtime_snapshot_replays_cleanup_without_live_helper_process(self) -> None:
        runtime_snapshot = {
            "backend": "windows-native",
            "ifname": "obtunw3",
            "ifindex": 55,
            "network_applied": True,
            "last_apply_payload": {"ifname": "obtunw3", "listener_hook_env": {"WAN_IF": "Ethernet"}},
            "applied_ipv4_cidr": "198.18.70.2/24",
            "applied_ipv4_routes": ["198.18.71.0/24"],
            "applied_excluded_ipv4_routes": ["203.0.113.9/32"],
            "applied_dns_servers": ["9.9.9.9"],
            "dns_manager": "dnsclient",
            "firewall_manager": "windows-firewall",
            "firewall_wan_if": "Ethernet",
            "applied_firewall_rules": [
                "ObstacleBridge-TunHelper-obtunw3-IPv4-Inbound",
                "ObstacleBridge-TunHelper-obtunw3-IPv4-Outbound",
            ],
            "saved_underlay4": {"InterfaceIndex": 12, "NextHop": "172.20.10.1"},
        }
        commands: list[str] = []
        firewall_rules = {
            "ObstacleBridge-TunHelper-obtunw3-IPv4-Inbound": 1,
            "ObstacleBridge-TunHelper-obtunw3-IPv4-Outbound": 1,
        }

        def _fake_run_powershell(command: str, *, check: bool = True):
            del check
            text = str(command)
            commands.append(text)
            if "Get-NetFirewallRule -DisplayName 'ObstacleBridge-TunHelper-obtunw3-IPv4-Inbound'" in text:
                return mock.Mock(returncode=0, stdout=('x' if firewall_rules["ObstacleBridge-TunHelper-obtunw3-IPv4-Inbound"] > 0 else ''), stderr="")
            if "Get-NetFirewallRule -DisplayName 'ObstacleBridge-TunHelper-obtunw3-IPv4-Outbound'" in text:
                return mock.Mock(returncode=0, stdout=('x' if firewall_rules["ObstacleBridge-TunHelper-obtunw3-IPv4-Outbound"] > 0 else ''), stderr="")
            if "Remove-NetFirewallRule -DisplayName 'ObstacleBridge-TunHelper-obtunw3-IPv4-Inbound'" in text:
                firewall_rules["ObstacleBridge-TunHelper-obtunw3-IPv4-Inbound"] = 0
            if "Remove-NetFirewallRule -DisplayName 'ObstacleBridge-TunHelper-obtunw3-IPv4-Outbound'" in text:
                firewall_rules["ObstacleBridge-TunHelper-obtunw3-IPv4-Outbound"] = 0
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch.object(WindowsTunHelperBackend, "_run_powershell", side_effect=_fake_run_powershell):
            repaired = WindowsTunHelperBackend.repair_runtime_snapshot(runtime_snapshot)

        self.assertTrue(repaired["ok"])
        self.assertEqual(repaired["repaired"], ["dns", "included_routes", "excluded_routes", "firewall", "ipv4_addr"])
        runtime_after = dict(repaired["runtime"] or {})
        self.assertFalse(runtime_after["network_applied"])
        self.assertEqual(runtime_after["applied_ipv4_cidr"], "")
        self.assertEqual(runtime_after["applied_ipv4_routes"], [])
        self.assertEqual(runtime_after["applied_excluded_ipv4_routes"], [])
        self.assertEqual(runtime_after["applied_dns_servers"], [])
        self.assertEqual(runtime_after["applied_firewall_rules"], [])
        joined = "\n".join(commands)
        self.assertIn("Set-DnsClientServerAddress -InterfaceIndex 55 -ResetServerAddresses", joined)
        self.assertIn("Remove-NetRoute -InterfaceIndex 55 -AddressFamily IPv4 -DestinationPrefix '198.18.71.0/24'", joined)
        self.assertIn("Remove-NetRoute -InterfaceIndex 12 -AddressFamily IPv4 -DestinationPrefix '203.0.113.9/32'", joined)
        self.assertIn("Remove-NetFirewallRule -DisplayName 'ObstacleBridge-TunHelper-obtunw3-IPv4-Inbound'", joined)
        self.assertIn("Remove-NetFirewallRule -DisplayName 'ObstacleBridge-TunHelper-obtunw3-IPv4-Outbound'", joined)
        self.assertIn("Remove-NetIPAddress -InterfaceIndex 55 -IPAddress '198.18.70.2'", joined)

    def test_verify_runtime_snapshot_repaired_reports_remaining_and_skipped_state(self) -> None:
        runtime_snapshot = {
            "backend": "windows-native",
            "ifname": "obtunw4",
            "ifindex": 55,
            "applied_ipv4_cidr": "198.18.72.2/24",
            "applied_ipv4_routes": ["198.18.73.0/24"],
            "applied_excluded_ipv4_routes": ["203.0.113.11/32"],
            "applied_excluded_ipv6_routes": ["2001:db8:73::/64"],
            "applied_dns_servers": ["9.9.9.9"],
            "applied_firewall_rules": ["ObstacleBridge-TunHelper-obtunw4-IPv4-Inbound"],
            "saved_underlay4": {"InterfaceIndex": 12, "NextHop": "172.20.10.1"},
        }

        def _fake_run_powershell(command: str, *, check: bool = True):
            del check
            text = str(command)
            if "Get-NetIPAddress -InterfaceIndex 55 -IPAddress '198.18.72.2'" in text:
                return mock.Mock(returncode=0, stdout='{"IPAddress":"198.18.72.2"}', stderr="")
            if "Get-NetRoute -InterfaceIndex 55 -AddressFamily IPv4 -DestinationPrefix '198.18.73.0/24'" in text:
                return mock.Mock(returncode=0, stdout='{"DestinationPrefix":"198.18.73.0/24"}', stderr="")
            if "Get-DnsClientServerAddress -InterfaceIndex 55" in text:
                return mock.Mock(returncode=0, stdout='{"ServerAddresses":["9.9.9.9"]}', stderr="")
            if "Get-NetFirewallRule -DisplayName 'ObstacleBridge-TunHelper-obtunw4-IPv4-Inbound'" in text:
                return mock.Mock(returncode=0, stdout='{"DisplayName":"ObstacleBridge-TunHelper-obtunw4-IPv4-Inbound"}', stderr="")
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch.object(WindowsTunHelperBackend, "_run_powershell", side_effect=_fake_run_powershell):
            verification = WindowsTunHelperBackend.verify_runtime_snapshot_repaired(runtime_snapshot)

        self.assertFalse(verification["ok"])
        self.assertTrue(verification["stale_state_remaining"])
        self.assertIn({"step": "ipv4_addr", "detail": "198.18.72.2/24"}, verification["remaining"])
        self.assertIn({"step": "included_routes", "detail": "198.18.73.0/24"}, verification["remaining"])
        self.assertIn({"step": "dns", "detail": "9.9.9.9"}, verification["remaining"])
        self.assertIn({"step": "firewall", "detail": "ObstacleBridge-TunHelper-obtunw4-IPv4-Inbound"}, verification["remaining"])
        self.assertIn({"step": "excluded_routes", "detail": "route interface index unavailable for route verification"}, verification["skipped"])


if __name__ == "__main__":
    unittest.main()