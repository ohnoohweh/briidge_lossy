#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from obstacle_bridge.bridge import ChannelMux, build_runtime_args_from_config
from obstacle_bridge.bridge_tun_helper_client import TunHelperClient
from obstacle_bridge.bridge_tun_helper_linux import LinuxTunHelperInMemoryBackend
from obstacle_bridge.bridge_tun_helper_server import TunHelperServer
from obstacle_bridge.bridge_tun_helper_settings import TunExecutionSettings
from tests.unit.test_channel_mux_listener_mode import _FakeSession


class ChannelMuxTunHelperTests(unittest.IsolatedAsyncioTestCase):
    def _helper_args(self):
        args = build_runtime_args_from_config(
            {
                "tun_execution": {
                    "mode": "helper",
                    "helper_backend": "linux-python",
                }
            }
        )
        args._tun_helper_settings = TunExecutionSettings.from_mapping(vars(args))
        args._tun_helper_backend = LinuxTunHelperInMemoryBackend()
        args._tun_helper_client = None
        return args

    async def test_helper_mode_opens_and_writes_through_backend(self):
        args = self._helper_args()
        session = _FakeSession(connected=True)
        mux = ChannelMux.from_args(session, asyncio.get_running_loop(), args)

        dev = mux._open_tun_device("obtun0", 1600, svc_key=("local", 0, 7))
        mux._write_tun_packet(dev, b"helper-egress")

        self.assertTrue(dev.helper_managed)
        self.assertEqual(dev.fd, -1)
        self.assertEqual(dev.ifname, "obtun0")
        self.assertEqual(dev.mtu, 1600)
        self.assertEqual(args._tun_helper_backend.drain_written_packets(), [b"helper-egress"])
        snapshot = args._tun_helper_backend.local_snapshot()
        self.assertEqual(snapshot["apply_calls"], 1)
        self.assertTrue(snapshot["network_applied"])
        self.assertEqual(snapshot["last_apply_payload"]["ifname"], "obtun0")

    async def test_helper_mode_registers_reader_and_delivers_packets(self):
        args = self._helper_args()
        session = _FakeSession(connected=True)
        mux = ChannelMux.from_args(session, asyncio.get_running_loop(), args)
        dev = mux._open_tun_device("obtun0", 1600, svc_key=("local", 0, 8))
        seen: list[bytes] = []
        delivered = asyncio.Event()

        def _capture(got_dev, packet):
            self.assertIs(got_dev, dev)
            seen.append(bytes(packet))
            delivered.set()

        mux._on_local_tun_packet = _capture  # type: ignore[method-assign]

        mux._register_tun_reader(dev)
        args._tun_helper_backend.local_feed_incoming_packet(b"\x45helper-ingress")
        await asyncio.wait_for(delivered.wait(), timeout=1.0)
        mux._close_tun_device(dev)
        await asyncio.sleep(0)

        self.assertEqual(seen, [b"\x45helper-ingress"])
        self.assertFalse(dev.reader_registered)

    async def test_helper_mode_removes_network_on_close(self):
        args = self._helper_args()
        session = _FakeSession(connected=True)
        mux = ChannelMux.from_args(session, asyncio.get_running_loop(), args)

        dev = mux._open_tun_device("obtun0", 1600, svc_key=("local", 0, 9))
        mux._close_tun_device(dev)

        snapshot = args._tun_helper_backend.local_snapshot()
        self.assertEqual(snapshot["apply_calls"], 1)
        self.assertEqual(snapshot["remove_calls"], 1)
        self.assertFalse(snapshot["network_applied"])
        self.assertEqual(snapshot["last_remove_payload"]["ifname"], "obtun0")

    async def test_helper_mode_records_critical_runtime_health_when_expected_tun_addresses_missing(self):
        args = build_runtime_args_from_config(
            {
                "TUN_routing": {
                    "tunnel_address": "192.168.106.2",
                    "tunnel_prefix": 24,
                    "tunnel_address6": "fd20:106::2",
                    "tunnel_prefix6": 64,
                },
                "tun_execution": {
                    "mode": "helper",
                    "helper_backend": "linux-python",
                },
            }
        )
        args._tun_helper_settings = TunExecutionSettings.from_mapping(vars(args))
        args._tun_helper_backend = LinuxTunHelperInMemoryBackend()
        args._tun_helper_client = None
        session = _FakeSession(connected=True)
        mux = ChannelMux.from_args(session, asyncio.get_running_loop(), args)
        svc_key = ("local", 0, 19)
        spec = ChannelMux.ServiceSpec(
            svc_id=19,
            l_proto="tun",
            l_bind="obtun0",
            l_port=1600,
            r_proto="tun",
            r_host="obtun0",
            r_port=1600,
        )
        mux._local_services[svc_key] = spec
        dev = mux._open_tun_device("obtun0", 1600, svc_key=svc_key)
        mux._svc_tun_devices[svc_key] = dev

        with patch.object(
            mux,
            "_linux_tun_interface_addresses",
            return_value={
                "ipv4": [],
                "ipv6": ["fe80::1/64"],
                "stdout4": "",
                "stdout6": "inet6 fe80::1/64 scope link",
            },
        ), patch.object(mux.log, "critical") as critical:
            await mux._run_tun_runtime_health_check(dev, reason="unit-test", delay_s=0)

        health = dict(mux._tun_runtime_health_by_service.get(svc_key) or {})
        self.assertEqual(health["code"], "tun_addresses_missing")
        self.assertEqual(health["severity"], "critical")
        self.assertEqual(health["expected_ipv4"], "192.168.106.2")
        self.assertEqual(health["expected_ipv6"], "fd20:106::2")
        self.assertEqual(health["reason"], "unit-test")
        critical.assert_called_once()
        mux._close_tun_device(dev)
        await asyncio.sleep(0)

    async def test_helper_mode_accepts_darwin_ifconfig_addresses_for_runtime_health(self):
        args = build_runtime_args_from_config(
            {
                "TUN_routing": {
                    "tunnel_address": "192.168.106.3",
                    "tunnel_prefix": 24,
                    "tunnel_address6": "fd20:106::3",
                    "tunnel_prefix6": 64,
                },
                "tun_execution": {
                    "mode": "helper",
                    "helper_backend": "darwin-native",
                },
            }
        )
        args._tun_helper_settings = TunExecutionSettings.from_mapping(vars(args))
        args._tun_helper_backend = LinuxTunHelperInMemoryBackend()
        args._tun_helper_client = None
        session = _FakeSession(connected=True)
        mux = ChannelMux.from_args(session, asyncio.get_running_loop(), args)
        svc_key = ("local", 0, 20)
        spec = ChannelMux.ServiceSpec(
            svc_id=20,
            l_proto="tun",
            l_bind="utun4",
            l_port=1600,
            r_proto="tun",
            r_host="obtun0",
            r_port=1600,
        )
        mux._local_services[svc_key] = spec
        dev = mux._open_tun_device("utun4", 1600, svc_key=svc_key)
        mux._svc_tun_devices[svc_key] = dev
        ifconfig_output = """utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1600
        inet 192.168.106.3 --> 192.168.106.1 netmask 0xffffff00
        inet6 fd20:106::3 prefixlen 64
        """

        with patch("obstacle_bridge.bridge_channelmux.sys.platform", "darwin"), \
             patch("obstacle_bridge.bridge_channelmux.subprocess.run") as run_mock, \
             patch.object(mux.log, "critical") as critical:
            run_mock.return_value = type("Result", (), {"stdout": ifconfig_output})()
            await mux._run_tun_runtime_health_check(dev, reason="unit-test", delay_s=0)

        self.assertFalse(mux._tun_runtime_health_by_service.get(svc_key))
        critical.assert_not_called()
        mux._close_tun_device(dev)
        await asyncio.sleep(0)

    async def test_helper_mode_network_payload_merges_auto_excluded_overlay_routes(self):
        args = build_runtime_args_from_config(
            {
                "overlay_transport": "myudp",
                "udp_peer": "38.180.143.5,[2001:db8::5]",
                "udp_peer_port": 4433,
                "udp_peer_resolve_family": "prefer-ipv6",
                "udp_bind": "::",
                "TUN_routing": {
                    "excluded_routes": ["127.0.0.0/8"],
                    "excluded_routes6": ["::1/128"],
                },
                "tun_execution": {
                    "mode": "helper",
                    "helper_backend": "linux-python",
                },
            }
        )
        args._tun_helper_settings = TunExecutionSettings.from_mapping(vars(args))
        session = _FakeSession(connected=True)
        mux = ChannelMux.from_args(session, asyncio.get_running_loop(), args)
        dev = ChannelMux.TunDevice(
            fd=-1,
            ifname="obtun0",
            mtu=1600,
            service_key=("local", 0, 11),
            helper_managed=True,
        )

        payload = mux._tun_helper_network_payload(dev)

        self.assertIn("127.0.0.0/8", payload["tun_routing"]["excluded_routes"])
        self.assertIn("38.180.143.5/32", payload["tun_routing"]["excluded_routes"])
        self.assertIn("::1/128", payload["tun_routing"]["excluded_routes6"])
        self.assertIn("2001:db8::5/128", payload["tun_routing"]["excluded_routes6"])
        self.assertIn("::ffff:38.180.143.5/128", payload["tun_routing"]["excluded_routes6"])

    async def test_helper_mode_network_payload_carries_listener_hook_env(self):
        args = build_runtime_args_from_config(
            {
                "own_servers": [
                    {
                        "name": "Server TUN",
                        "listen": {"protocol": "tun", "ifname": "obtun0", "mtu": 1600},
                        "target": {"protocol": "tun", "ifname": "obtun0", "mtu": 1600},
                        "lifecycle_hooks": {
                            "listener": {
                                "on_created": {
                                    "argv": ["./scripts/server-tun-hook.sh", "up", "{ifname}"],
                                    "env": {"WAN_IF": "eth0"},
                                },
                                "on_stopped": {
                                    "argv": ["./scripts/server-tun-hook.sh", "down", "{ifname}"],
                                    "env": {"WAN_IF": "eth0"},
                                },
                            }
                        },
                    }
                ],
                "tun_execution": {
                    "mode": "helper",
                    "helper_backend": "linux-python",
                },
            }
        )
        args._tun_helper_settings = TunExecutionSettings.from_mapping(vars(args))
        session = _FakeSession(connected=True)
        mux = ChannelMux.from_args(session, asyncio.get_running_loop(), args)
        mux._local_services[("local", 0, 1)] = ChannelMux.ServiceSpec(
            svc_id=1,
            l_proto="tun",
            l_bind="obtun0",
            l_port=1600,
            r_proto="tun",
            r_host="obtun0",
            r_port=1600,
            name="Server TUN",
            lifecycle_hooks={
                "listener": {
                    "on_created": {
                        "argv": ["./scripts/server-tun-hook.sh", "up", "{ifname}"],
                        "env": {"WAN_IF": "eth0"},
                    },
                    "on_stopped": {
                        "argv": ["./scripts/server-tun-hook.sh", "down", "{ifname}"],
                        "env": {"WAN_IF": "eth0"},
                    },
                }
            },
        )
        dev = ChannelMux.TunDevice(
            fd=-1,
            ifname="obtun0",
            mtu=1600,
            service_key=("local", 0, 1),
            helper_managed=True,
        )

        payload = mux._tun_helper_network_payload(dev)

        self.assertEqual(payload["service_catalog"], "own_servers")
        self.assertEqual(payload["listener_hook_env"]["WAN_IF"], "eth0")

    async def test_helper_mode_start_skips_runtime_listener_on_created_hook(self):
        args = self._helper_args()
        session = _FakeSession(connected=True)
        mux = ChannelMux.from_args(session, asyncio.get_running_loop(), args)
        spec = ChannelMux.ServiceSpec(
            svc_id=21,
            l_proto="tun",
            l_bind="obtun0",
            l_port=1600,
            r_proto="tun",
            r_host="obtun0",
            r_port=1600,
            lifecycle_hooks={"listener": {"on_created": {"argv": ["hook", "up"]}}},
        )
        svc_key = ("local", 0, 21)
        dev = ChannelMux.TunDevice(fd=-1, ifname="obtun0", mtu=1600, service_key=svc_key, helper_managed=True)

        with patch.object(mux, "_open_tun_device", return_value=dev), \
             patch.object(mux, "_schedule_service_hook") as schedule_hook, \
             patch.object(mux, "_schedule_tun_reader_registration") as schedule_reader:
            opened = mux._start_tun_server_for_sync(spec, svc_key)

        self.assertIs(opened, dev)
        schedule_hook.assert_not_called()
        schedule_reader.assert_called_once_with(dev)

    async def test_helper_mode_stop_skips_runtime_listener_on_stopped_hook(self):
        args = self._helper_args()
        session = _FakeSession(connected=True)
        mux = ChannelMux.from_args(session, asyncio.get_running_loop(), args)
        spec = ChannelMux.ServiceSpec(
            svc_id=22,
            l_proto="tun",
            l_bind="obtun0",
            l_port=1600,
            r_proto="tun",
            r_host="obtun0",
            r_port=1600,
            lifecycle_hooks={"listener": {"on_stopped": {"argv": ["hook", "down"]}}},
        )
        svc_key = ("local", 0, 22)
        dev = mux._open_tun_device("obtun0", 1600, svc_key=svc_key)
        mux._svc_tun_devices[svc_key] = dev

        with patch.object(mux, "_run_service_hook", new=AsyncMock()) as run_hook:
            await mux._stop_listener_for_service_id(svc_key, "tun", spec=spec)

        run_hook.assert_not_awaited()
        snapshot = args._tun_helper_backend.local_snapshot()
        self.assertEqual(snapshot["apply_calls"], 1)
        self.assertEqual(snapshot["remove_calls"], 1)

    async def test_helper_mode_uses_client_when_backend_is_external(self):
        with tempfile.TemporaryDirectory() as tmp:
            socket_path = os.path.join(tmp, "tun-helper.sock")
            backend = LinuxTunHelperInMemoryBackend()
            server = TunHelperServer(backend=backend, session_token="secret")
            await server.start(socket_path)
            client = TunHelperClient(socket_path=socket_path, session_token="secret")
            await client.connect()
            try:
                args = build_runtime_args_from_config(
                    {
                        "tun_execution": {
                            "mode": "helper",
                            "helper_backend": "linux-python",
                            "helper_apply_network": True,
                        }
                    }
                )
                args._tun_helper_settings = TunExecutionSettings.from_mapping(vars(args))
                args._tun_helper_client = client
                session = _FakeSession(connected=True)
                mux = ChannelMux.from_args(session, asyncio.get_running_loop(), args)
                dev = mux._open_tun_device("obtun0", 1600, svc_key=("local", 0, 10))

                mux._write_tun_packet(dev, b"client-helper-egress")
                await asyncio.sleep(0.05)
                self.assertEqual(backend.drain_written_packets(), [b"client-helper-egress"])

                seen: list[bytes] = []
                delivered = asyncio.Event()

                def _capture(got_dev, packet):
                    self.assertIs(got_dev, dev)
                    seen.append(bytes(packet))
                    delivered.set()

                mux._on_local_tun_packet = _capture  # type: ignore[method-assign]
                mux._register_tun_reader(dev)
                await backend.feed_incoming_packet(b"\x45client-helper-ingress")
                await asyncio.wait_for(delivered.wait(), timeout=1.0)
                mux._close_tun_device(dev)
                await asyncio.sleep(0.05)

                snapshot = await client.snapshot()
                self.assertEqual(seen, [b"\x45client-helper-ingress"])
                self.assertEqual(snapshot["apply_calls"], 1)
                self.assertEqual(snapshot["remove_calls"], 1)
            finally:
                await client.close()
                await server.stop()

    async def test_helper_mode_stop_awaits_external_helper_remove_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            socket_path = os.path.join(tmp, "tun-helper.sock")
            backend = LinuxTunHelperInMemoryBackend()
            server = TunHelperServer(backend=backend, session_token="secret")
            await server.start(socket_path)
            client = TunHelperClient(socket_path=socket_path, session_token="secret")
            await client.connect()
            try:
                args = build_runtime_args_from_config(
                    {
                        "tun_execution": {
                            "mode": "helper",
                            "helper_backend": "linux-python",
                            "helper_apply_network": True,
                        }
                    }
                )
                args._tun_helper_settings = TunExecutionSettings.from_mapping(vars(args))
                args._tun_helper_client = client
                session = _FakeSession(connected=True)
                mux = ChannelMux.from_args(session, asyncio.get_running_loop(), args)
                spec = ChannelMux.ServiceSpec(
                    svc_id=14,
                    l_proto="tun",
                    l_bind="obtun0",
                    l_port=1600,
                    r_proto="tun",
                    r_host="obtun0",
                    r_port=1600,
                )
                svc_key = ("local", 0, 14)
                mux._local_services[svc_key] = spec
                dev = mux._open_tun_device("obtun0", 1600, svc_key=svc_key)
                mux._svc_tun_devices[svc_key] = dev

                await mux.stop(reason="unit-test")

                snapshot = await client.snapshot()
                self.assertEqual(snapshot["apply_calls"], 1)
                self.assertEqual(snapshot["remove_calls"], 1)
                self.assertFalse(snapshot["network_applied"])
            finally:
                await client.close()
                await server.stop()

    async def test_helper_mode_refreshes_helper_snapshot_after_apply_failure(self):
        class _FailingBackend(LinuxTunHelperInMemoryBackend):
            def local_apply_network(self, payload):
                self._apply_calls += 1
                self._network_applied = False
                self._last_apply_payload = dict(payload or {})
                self._last_failure = {
                    "operation": "apply_network",
                    "stage": "dns_apply",
                    "error_type": "RuntimeError",
                    "detail": "dns failed",
                    "cleanup_attempted": True,
                    "cleanup_ok": True,
                    "unix_ts": 1700000400.0,
                }
                raise RuntimeError("dns failed")

            def local_snapshot(self):
                payload = super().local_snapshot()
                payload["last_failure"] = dict(getattr(self, "_last_failure", {}))
                return payload

        with tempfile.TemporaryDirectory() as tmp:
            socket_path = os.path.join(tmp, "tun-helper.sock")
            backend = _FailingBackend()
            server = TunHelperServer(backend=backend, session_token="secret")
            await server.start(socket_path)
            client = TunHelperClient(socket_path=socket_path, session_token="secret")
            await client.connect()
            try:
                args = build_runtime_args_from_config(
                    {
                        "tun_execution": {
                            "mode": "helper",
                            "helper_backend": "linux-python",
                            "helper_apply_network": True,
                        }
                    }
                )
                args._tun_helper_settings = TunExecutionSettings.from_mapping(vars(args))
                args._tun_helper_client = client
                session = _FakeSession(connected=True)
                mux = ChannelMux.from_args(session, asyncio.get_running_loop(), args)

                dev = mux._open_tun_device("obtun0", 1600, svc_key=("local", 0, 12))
                await asyncio.sleep(0.05)

                snapshot = client.cached_snapshot()
                self.assertFalse(dev.helper_network_applied)
                self.assertEqual(snapshot["last_failure"]["operation"], "apply_network")
                self.assertEqual(snapshot["last_failure"]["stage"], "dns_apply")
                self.assertEqual(snapshot["last_failure"]["detail"], "dns failed")
            finally:
                await client.close()
                await server.stop()

    async def test_helper_mode_refreshes_helper_snapshot_after_apply_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            socket_path = os.path.join(tmp, "tun-helper.sock")
            backend = LinuxTunHelperInMemoryBackend()
            server = TunHelperServer(backend=backend, session_token="secret")
            await server.start(socket_path)
            client = TunHelperClient(socket_path=socket_path, session_token="secret")
            await client.connect()
            try:
                args = build_runtime_args_from_config(
                    {
                        "tun_execution": {
                            "mode": "helper",
                            "helper_backend": "linux-python",
                            "helper_apply_network": True,
                        }
                    }
                )
                args._tun_helper_settings = TunExecutionSettings.from_mapping(vars(args))
                args._tun_helper_client = client
                session = _FakeSession(connected=True)
                mux = ChannelMux.from_args(session, asyncio.get_running_loop(), args)

                mux._open_tun_device("obtun0", 1600, svc_key=("local", 0, 13))
                await asyncio.sleep(0.05)

                snapshot = client.cached_snapshot()
                self.assertTrue(snapshot["opened"])
                self.assertTrue(snapshot["network_applied"])
                self.assertEqual(snapshot["apply_calls"], 1)
                self.assertEqual(snapshot["ifname"], "obtun0")
            finally:
                await client.close()
                await server.stop()

    async def test_helper_mode_applies_after_external_helper_reports_actual_ifname(self):
        class _RenamingBackend(LinuxTunHelperInMemoryBackend):
            def local_open_tun(self, payload):
                opened = super().local_open_tun(payload)
                self._ifname = "utun42"
                opened["ifname"] = self._ifname
                return opened

        with tempfile.TemporaryDirectory() as tmp:
            socket_path = os.path.join(tmp, "tun-helper.sock")
            backend = _RenamingBackend()
            server = TunHelperServer(backend=backend, session_token="secret")
            await server.start(socket_path)
            client = TunHelperClient(socket_path=socket_path, session_token="secret")
            await client.connect()
            try:
                args = build_runtime_args_from_config(
                    {
                        "tun_execution": {
                            "mode": "helper",
                            "helper_backend": "linux-python",
                            "helper_apply_network": True,
                        }
                    }
                )
                args._tun_helper_settings = TunExecutionSettings.from_mapping(vars(args))
                args._tun_helper_client = client
                session = _FakeSession(connected=True)
                mux = ChannelMux.from_args(session, asyncio.get_running_loop(), args)

                dev = mux._open_tun_device("requested0", 1600, svc_key=("local", 0, 15))
                await asyncio.sleep(0.05)
                mux._close_tun_device(dev)
                await asyncio.sleep(0.05)

                snapshot = await client.snapshot()
                self.assertEqual(dev.ifname, "utun42")
                self.assertEqual(snapshot["apply_calls"], 1)
                self.assertEqual(snapshot["remove_calls"], 1)
                self.assertEqual(snapshot["last_apply_payload"]["ifname"], "utun42")
                self.assertEqual(snapshot["last_remove_payload"]["ifname"], "utun42")
            finally:
                await client.close()
                await server.stop()


if __name__ == "__main__":
    unittest.main()
