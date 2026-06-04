#!/usr/bin/env python3
import argparse
import asyncio
import ipaddress
import unittest
from unittest.mock import AsyncMock, patch

from obstacle_bridge.bridge import ChannelMux, SessionMetrics
from obstacle_bridge.bridge_tun_routing import TunRoutingSettings


class _FakeSession:
    def __init__(
        self,
        *,
        connected=False,
        max_app_payload_size=65535,
        transmit_delay_est_ms=None,
        waiting_count=0,
    ):
        self.app_cb = None
        self.peer_disconnect_cb = None
        self.sent = []
        self.connected = connected
        self.max_app_payload_size = max_app_payload_size
        self._metrics = SessionMetrics(
            transmit_delay_est_ms=transmit_delay_est_ms,
            waiting_count=waiting_count,
        )

    def is_connected(self):
        return self.connected

    def set_on_app_payload(self, cb):
        self.app_cb = cb

    def set_on_peer_disconnect(self, cb):
        self.peer_disconnect_cb = cb

    def send_app(self, payload):
        self.sent.append(payload)
        return len(payload)

    def get_max_app_payload_size(self):
        return self.max_app_payload_size

    def get_metrics(self):
        return self._metrics


def _ipv4_packet(src: str, dst: str, payload: bytes = b"x") -> bytes:
    src_b = ipaddress.IPv4Address(src).packed
    dst_b = ipaddress.IPv4Address(dst).packed
    total_len = 20 + len(payload)
    header = bytes([
        0x45,
        0x00,
        (total_len >> 8) & 0xFF,
        total_len & 0xFF,
        0x00,
        0x00,
        0x00,
        0x00,
        64,
        1,
        0x00,
        0x00,
    ]) + src_b + dst_b
    return header + payload


def _ipv6_packet(src: str, dst: str, payload: bytes = b"x") -> bytes:
    src_b = ipaddress.IPv6Address(src).packed
    dst_b = ipaddress.IPv6Address(dst).packed
    payload_len = len(payload)
    header = bytes([
        0x60,
        0x00,
        0x00,
        0x00,
        (payload_len >> 8) & 0xFF,
        payload_len & 0xFF,
        58,
        64,
    ]) + src_b + dst_b
    return header + payload


class ChannelMuxListenerModeTests(unittest.TestCase):
    def test_tun_routing_defaults_match_bootstrap_shape(self):
        settings = TunRoutingSettings()
        self.assertEqual(settings.tunnel_address, "192.168.106.1")
        self.assertEqual(settings.tunnel_gateway, "192.168.106.2")
        self.assertEqual(settings.included_routes, ["0.0.0.0/0"])
        self.assertEqual(settings.excluded_routes, ["127.0.0.0/8"])
        self.assertEqual(settings.tunnel_address6, "fd20:106::1")
        self.assertEqual(settings.tunnel_gateway6, "fd20:106::2")
        self.assertEqual(settings.included_routes6, ["::/0"])
        self.assertEqual(settings.excluded_routes6, ["::1/128"])
        self.assertEqual(settings.dns_servers, ["1.1.1.1"])
        self.assertEqual(settings.mtu, 1600)
        self.assertEqual(settings.log_TUN_routing, "CRITICAL")

    def test_select_hook_argv_uses_list_directly(self):
        selected = ChannelMux._select_hook_argv({"argv": ["cmd", "arg1"]}, platform_key="linux")
        self.assertEqual(selected, ["cmd", "arg1"])

    def test_select_hook_argv_uses_platform_specific_mapping(self):
        cmd = {
            "argv": {
                "linux": ["ip", "route", "add", "{target_host}/32", "dev", "{ifname}"],
                "windows": ["route", "ADD", "{target_host}", "MASK", "255.255.255.255", "{ifname}"],
                "default": ["echo", "fallback"],
            }
        }
        self.assertEqual(
            ChannelMux._select_hook_argv(cmd, platform_key="linux"),
            ["ip", "route", "add", "{target_host}/32", "dev", "{ifname}"],
        )
        self.assertEqual(
            ChannelMux._select_hook_argv(cmd, platform_key="windows"),
            ["route", "ADD", "{target_host}", "MASK", "255.255.255.255", "{ifname}"],
        )
        self.assertEqual(
            ChannelMux._select_hook_argv(cmd, platform_key="freebsd"),
            ["echo", "fallback"],
        )

    def test_select_hook_argv_rejects_invalid_shape(self):
        with self.assertRaisesRegex(ValueError, "argv list"):
            ChannelMux._select_hook_argv({"argv": "bad"}, platform_key="linux")

    def test_resolve_hook_argv_resolves_relative_executable_against_base_dir(self):
        mux = ChannelMux(_FakeSession(), asyncio.new_event_loop())
        try:
            mux._hook_base_dir = "/opt/obbridge"
            self.assertEqual(
                mux._resolve_hook_argv(["./scripts/server-tun-hook.sh", "up", "obtun1"]),
                ["/opt/obbridge/scripts/server-tun-hook.sh", "up", "obtun1"],
            )
            self.assertEqual(
                mux._resolve_hook_argv(["ip", "link", "show"]),
                ["ip", "link", "show"],
            )
        finally:
            mux.loop.close()

    def test_render_hook_value_replaces_known_placeholders(self):
        rendered = ChannelMux._render_hook_value(
            "route add {target_host} dev {ifname} svc={service_id}",
            {"target_host": "198.18.30.2", "ifname": "obtun0", "service_id": 3},
        )
        self.assertEqual(rendered, "route add 198.18.30.2 dev obtun0 svc=3")

    def test_hook_context_exposes_resolved_overlay_peer(self):
        args = argparse.Namespace(
            own_servers=None,
            remote_servers=None,
            overlay_transport="myudp",
            udp_bind="0.0.0.0",
            udp_peer="127.0.0.1",
            udp_peer_port=4433,
            tunnel_address="192.168.107.1",
            tunnel_prefix=30,
            tunnel_gateway="192.168.107.2",
            included_routes=["0.0.0.0/0"],
            excluded_routes=["127.0.0.0/8"],
            tunnel_address6="fd20:107::1",
            tunnel_prefix6=126,
            tunnel_gateway6="fd20:107::2",
            included_routes6=["::/0"],
            excluded_routes6=["::1/128"],
            dns_servers=["1.1.1.1", "8.8.8.8"],
            mtu=1600,
            mux_tcp_bp_threshold=1,
            mux_tcp_bp_latency_ms=300,
            mux_tcp_bp_poll_interval_ms=50,
        )
        loop = asyncio.new_event_loop()
        mux = ChannelMux.from_args(_FakeSession(), loop, args)
        try:
            spec = ChannelMux.ServiceSpec(3, "tun", "obtun0", 1400, "tun", "obtun1", 1400)
            context = mux._hook_context(spec, ("local", 0, 3), "on_created", "listener")

            self.assertEqual(context["overlay_transport"], "myudp")
            self.assertEqual(context["overlay_peer_name"], "127.0.0.1")
            self.assertEqual(context["overlay_peer_host"], "127.0.0.1")
            self.assertEqual(context["overlay_peer_port"], 4433)
            self.assertEqual(
                ChannelMux._render_hook_value("{overlay_peer_host}:{overlay_peer_port}", context),
                "127.0.0.1:4433",
            )
        finally:
            mux.loop.close()

    def test_hook_context_prefers_live_overlay_peer_over_initial_candidate(self):
        session = _FakeSession()
        session._peer_host = "198.51.100.10"
        session._peer_port = 4433
        args = argparse.Namespace(
            own_servers=None,
            remote_servers=None,
            overlay_transport="myudp",
            udp_bind="::",
            udp_peer="[2001:db8::10],198.51.100.10",
            udp_peer_port=4433,
            tunnel_address="192.168.107.1",
            tunnel_prefix=30,
            tunnel_gateway="192.168.107.2",
            included_routes=["0.0.0.0/0"],
            excluded_routes=["127.0.0.0/8"],
            tunnel_address6="fd20:107::1",
            tunnel_prefix6=126,
            tunnel_gateway6="fd20:107::2",
            included_routes6=["::/0"],
            excluded_routes6=["::1/128"],
            dns_servers=["1.1.1.1", "8.8.8.8"],
            mtu=1600,
            mux_tcp_bp_threshold=1,
            mux_tcp_bp_latency_ms=300,
            mux_tcp_bp_poll_interval_ms=50,
        )
        loop = asyncio.new_event_loop()
        mux = ChannelMux.from_args(session, loop, args)
        try:
            spec = ChannelMux.ServiceSpec(3, "tun", "obtun0", 1400, "tun", "obtun1", 1400)
            context = mux._hook_context(spec, ("local", 0, 3), "on_channel_connected", "listener")

            self.assertEqual(context["overlay_peer_name"], "[2001:db8::10],198.51.100.10")
            self.assertEqual(context["overlay_peer_host"], "198.51.100.10")
            self.assertEqual(context["overlay_peer_port"], 4433)
        finally:
            mux.loop.close()

    def test_tunnel_hook_env_defaults_follow_tun_routing_config(self):
        args = argparse.Namespace(
            own_servers=None,
            remote_servers=None,
            overlay_transport="myudp",
            udp_bind="0.0.0.0",
            udp_peer="127.0.0.1",
            udp_peer_port=4433,
            tunnel_address="192.168.107.1",
            tunnel_prefix=30,
            tunnel_gateway="192.168.107.2",
            included_routes=["0.0.0.0/0"],
            excluded_routes=["127.0.0.0/8"],
            tunnel_address6="fd20:107::1",
            tunnel_prefix6=126,
            tunnel_gateway6="fd20:107::2",
            included_routes6=["::/0"],
            excluded_routes6=["::1/128"],
            dns_servers=["9.9.9.9", "1.1.1.1"],
            mtu=1600,
            mux_tcp_bp_threshold=1,
            mux_tcp_bp_latency_ms=300,
            mux_tcp_bp_poll_interval_ms=50,
        )
        mux = ChannelMux.from_args(_FakeSession(), asyncio.new_event_loop(), args)
        try:
            local_spec = ChannelMux.ServiceSpec(3, "tun", "ios-utun", 1600, "tun", "obtun2", 1600)
            remote_spec = ChannelMux.ServiceSpec(4, "tun", "obtun2", 1600, "tun", "ios-utun", 1600)

            local_env = mux._tunnel_hook_env_defaults(local_spec, ("local", 0, 3))
            remote_env = mux._tunnel_hook_env_defaults(remote_spec, ("peer", 9, 4))

            self.assertEqual(local_env["TUN_ADDR"], "192.168.107.1/30")
            self.assertEqual(local_env["TUN_GW"], "192.168.107.2")
            self.assertEqual(local_env["DNS1"], "9.9.9.9")
            self.assertEqual(remote_env["TUN_ADDR"], "192.168.107.2/30")
            self.assertEqual(remote_env["PEER_ADDR"], "192.168.107.1")
            self.assertEqual(remote_env["TUN_SUBNET"], "192.168.107.0/30")
        finally:
            mux.loop.close()

    def test_parse_structured_tun_service_accepts_shared_tun_ownership_options(self):
        spec = ChannelMux._parse_structured_service_spec(
            {
                "name": "shared-tun",
                "listen": {"protocol": "tun", "ifname": "obtun0", "mtu": 1500},
                "target": {"protocol": "tun", "ifname": "obtun1", "mtu": 1500},
                "options": {
                    "shared_tun_ownership": {
                        "mode": "server_shared",
                        "peers": [
                            {"peer_ref": "linux-client", "ipv4": ["192.168.107.2"], "ipv6": ["fd20:107::2"]},
                            {"peer_ref": "ios-client", "ipv4": ["192.168.107.4/32"], "ipv6": ["fd20:107::4/128"]},
                        ],
                    }
                },
            },
            "--own-servers",
            7,
        )
        self.assertEqual(spec.l_proto, "tun")
        self.assertEqual(spec.r_proto, "tun")
        self.assertEqual(
            spec.options["shared_tun_ownership"]["peers"][0]["peer_ref"],
            "linux-client",
        )

    def test_shared_tun_ownership_snapshot_normalizes_host_addresses(self):
        spec = ChannelMux.ServiceSpec(
            7,
            "tun",
            "obtun0",
            1500,
            "tun",
            "obtun1",
            1500,
            name="shared-tun",
            options={
                "shared_tun_ownership": {
                    "mode": "server_shared",
                    "peers": [
                        {"peer_ref": "linux-client", "ipv4": ["192.168.107.2/32"], "ipv6": ["fd20:107::2/128"]},
                        {"peer_ref": "ios-client", "ipv4": ["192.168.107.4"], "ipv6": ["fd20:107::4"]},
                    ],
                }
            },
        )

        snapshot = ChannelMux._shared_tun_ownership_snapshot_for_spec(spec)

        self.assertEqual(
            snapshot,
            {
                "mode": "server_shared",
                "peer_count": 2,
                "address_count": 4,
                "peer_refs": ["linux-client", "ios-client"],
                "peers": [
                    {
                        "peer_ref": "linux-client",
                        "ipv4": ["192.168.107.2"],
                        "ipv6": ["fd20:107::2"],
                        "address_count": 2,
                    },
                    {
                        "peer_ref": "ios-client",
                        "ipv4": ["192.168.107.4"],
                        "ipv6": ["fd20:107::4"],
                        "address_count": 2,
                    },
                ],
                "owner_by_ipv4": {
                    "192.168.107.2": "linux-client",
                    "192.168.107.4": "ios-client",
                },
                "owner_by_ipv6": {
                    "fd20:107::2": "linux-client",
                    "fd20:107::4": "ios-client",
                },
            },
        )

    def test_shared_tun_ownership_snapshot_returns_none_without_option(self):
        spec = ChannelMux.ServiceSpec(7, "tun", "obtun0", 1500, "tun", "obtun1", 1500)
        self.assertIsNone(ChannelMux._shared_tun_ownership_snapshot_for_spec(spec))

    def test_parse_structured_tun_service_rejects_duplicate_shared_tun_owned_address(self):
        with self.assertRaisesRegex(ValueError, "IPv4 addresses must be unique"):
            ChannelMux._parse_structured_service_spec(
                {
                    "listen": {"protocol": "tun", "ifname": "obtun0", "mtu": 1500},
                    "target": {"protocol": "tun", "ifname": "obtun1", "mtu": 1500},
                    "options": {
                        "shared_tun_ownership": {
                            "mode": "server_shared",
                            "peers": [
                                {"peer_ref": "linux-client", "ipv4": ["192.168.107.2"]},
                                {"peer_ref": "ios-client", "ipv4": ["192.168.107.2/32"]},
                            ],
                        }
                    },
                },
                "--own-servers",
                7,
            )

    def test_parse_structured_tun_service_rejects_non_host_prefix_in_shared_tun_ownership(self):
        with self.assertRaisesRegex(ValueError, "optionally /32 or /128 only"):
            ChannelMux._parse_structured_service_spec(
                {
                    "listen": {"protocol": "tun", "ifname": "obtun0", "mtu": 1500},
                    "target": {"protocol": "tun", "ifname": "obtun1", "mtu": 1500},
                    "options": {
                        "shared_tun_ownership": {
                            "mode": "server_shared",
                            "peers": [
                                {"peer_ref": "linux-client", "ipv4": ["192.168.107.0/30"]},
                            ],
                        }
                    },
                },
                "--own-servers",
                7,
            )

    def test_parse_structured_non_tun_service_rejects_shared_tun_ownership_option(self):
        with self.assertRaisesRegex(ValueError, "supported only on tun->tun services"):
            ChannelMux._parse_structured_service_spec(
                {
                    "listen": {"protocol": "tcp", "bind": "127.0.0.1", "port": 8080},
                    "target": {"protocol": "tcp", "host": "127.0.0.1", "port": 80},
                    "options": {
                        "shared_tun_ownership": {
                            "mode": "server_shared",
                            "peers": [
                                {"peer_ref": "linux-client", "ipv4": ["192.168.107.2"]},
                            ],
                        }
                    },
                },
                "--own-servers",
                7,
            )

    def test_listener_mode_retains_prestarted_server_owned_shared_tun_service(self):
        args = argparse.Namespace(
            own_servers=[
                '{"name":"shared-tun","listen":{"protocol":"tun","ifname":"obtun0","mtu":1400},'
                '"target":{"protocol":"tun","ifname":"obtun0","mtu":1400},'
                '"options":{"shared_tun_ownership":{"mode":"server_shared","peers":['
                '{"peer_ref":"linux-client","ipv4":["192.168.107.2"]}]}}}'
            ],
            remote_servers=None,
            overlay_transport="myudp",
            udp_bind="0.0.0.0",
            udp_own_port=4433,
            udp_peer="",
            udp_peer_port=None,
            mux_tcp_bp_threshold=1,
            mux_tcp_bp_latency_ms=300,
            mux_tcp_bp_poll_interval_ms=50,
        )
        mux = ChannelMux.from_args(_FakeSession(connected=False), asyncio.new_event_loop(), args)
        try:
            self.assertIn(("local", 0, 1), mux._local_services)
            self.assertTrue(ChannelMux._is_server_shared_tun_service(mux._local_services[("local", 0, 1)]))
        finally:
            mux.loop.close()

    def test_listener_mode_still_ignores_ambiguous_non_shared_own_services(self):
        args = argparse.Namespace(
            own_servers=[
                '{"listen":{"protocol":"udp","bind":"127.0.0.1","port":10001},'
                '"target":{"protocol":"udp","host":"127.0.0.1","port":10002}}'
            ],
            remote_servers=None,
            overlay_transport="myudp",
            udp_bind="0.0.0.0",
            udp_own_port=4433,
            udp_peer="",
            udp_peer_port=None,
            mux_tcp_bp_threshold=1,
            mux_tcp_bp_latency_ms=300,
            mux_tcp_bp_poll_interval_ms=50,
        )
        mux = ChannelMux.from_args(_FakeSession(connected=False), asyncio.new_event_loop(), args)
        try:
            self.assertEqual(mux._local_services, {})
        finally:
            mux.loop.close()

    def test_open_payload_roundtrip_preserves_hook_metadata(self):
        mux = ChannelMux(_FakeSession(), asyncio.new_event_loop())
        try:
            spec = ChannelMux.ServiceSpec(
                svc_id=7,
                l_proto='tcp',
                l_bind='0.0.0.0',
                l_port=18080,
                r_proto='tcp',
                r_host='127.0.0.1',
                r_port=8080,
                name='web-service',
                lifecycle_hooks={'client': {'on_connected': {'argv': ['echo', 'ok']}}},
                options={'note': 'metadata'},
            )
            payload = mux._build_open_v4(spec)
            parsed = mux._parse_open_with_meta(payload)
            self.assertIsNotNone(parsed)
            assert parsed is not None
            self.assertEqual(parsed[2], 7)
            self.assertEqual(parsed[9], 'web-service')
            self.assertEqual(parsed[10], {'client': {'on_connected': {'argv': ['echo', 'ok']}}})
            self.assertEqual(parsed[11], {'note': 'metadata'})
        finally:
            mux.loop.close()

    def test_remote_services_roundtrip_preserves_hook_metadata(self):
        mux = ChannelMux(_FakeSession(), asyncio.new_event_loop())
        try:
            spec = ChannelMux.ServiceSpec(
                svc_id=3,
                l_proto='udp',
                l_bind='0.0.0.0',
                l_port=16667,
                r_proto='udp',
                r_host='127.0.0.1',
                r_port=16666,
                name='udp-publish',
                lifecycle_hooks={'listener': {'on_created': {'argv': ['echo', 'created']}}},
                options={'tag': 'alpha'},
            )
            payload = mux._encode_remote_services_set_v2([spec])
            decoded = mux._decode_remote_services_set_v2(payload)
            self.assertIsNotNone(decoded)
            assert decoded is not None
            _iid, _seq, services = decoded
            self.assertEqual(len(services), 1)
            self.assertEqual(services[0].name, 'udp-publish')
            self.assertEqual(services[0].lifecycle_hooks, {'listener': {'on_created': {'argv': ['echo', 'created']}}})
            self.assertEqual(services[0].options, {'tag': 'alpha'})
        finally:
            mux.loop.close()

    def test_remote_tun_services_auto_inject_tun_routing_hook_env(self):
        args = argparse.Namespace(
            own_servers=None,
            remote_servers=None,
            overlay_transport="myudp",
            udp_bind="0.0.0.0",
            udp_peer="127.0.0.1",
            udp_peer_port=4433,
            tunnel_address="192.168.107.1",
            tunnel_prefix=30,
            tunnel_gateway="192.168.107.2",
            included_routes=["0.0.0.0/0"],
            excluded_routes=["127.0.0.0/8"],
            tunnel_address6="fd20:107::1",
            tunnel_prefix6=126,
            tunnel_gateway6="fd20:107::2",
            included_routes6=["::/0"],
            excluded_routes6=["::1/128"],
            dns_servers=["9.9.9.9", "1.1.1.1"],
            mtu=1600,
            mux_tcp_bp_threshold=1,
            mux_tcp_bp_latency_ms=300,
            mux_tcp_bp_poll_interval_ms=50,
        )
        mux = ChannelMux.from_args(_FakeSession(), asyncio.new_event_loop(), args)
        try:
            spec = ChannelMux.ServiceSpec(
                svc_id=3,
                l_proto='tun',
                l_bind='obtun2',
                l_port=1600,
                r_proto='tun',
                r_host='ios-utun',
                r_port=1600,
                name='remote-tun',
                lifecycle_hooks={'listener': {'on_created': {'argv': ['echo', 'created']}}},
                options=None,
            )
            payload = mux._encode_remote_services_set_v2([spec])
            decoded = mux._decode_remote_services_set_v2(payload)
            self.assertIsNotNone(decoded)
            assert decoded is not None
            remote_spec = decoded[2][0]
            env = remote_spec.lifecycle_hooks["listener"]["on_created"]["env"]
            self.assertEqual(env["TUN_ADDR"], "192.168.107.2/30")
            self.assertEqual(env["PEER_ADDR"], "192.168.107.1")
            self.assertEqual(env["TUN_SUBNET"], "192.168.107.0/30")
            self.assertEqual(env["TUN_ADDR6"], "fd20:107::2/126")
            self.assertEqual(env["PEER_ADDR6"], "fd20:107::1")
            self.assertEqual(env["TUN_SUBNET6"], "fd20:107::/126")
        finally:
            mux.loop.close()

    def test_chunked_remote_services_transfer_reassembles_metadata(self):
        session = _FakeSession(connected=True, max_app_payload_size=96)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            spec = ChannelMux.ServiceSpec(
                svc_id=5,
                l_proto='udp',
                l_bind='0.0.0.0',
                l_port=26667,
                r_proto='udp',
                r_host='127.0.0.1',
                r_port=26666,
                name='chunked-remote',
                lifecycle_hooks={'listener': {'on_channel_connected': {'argv': ['echo', 'x' * 220]}}},
                options={'meta': 'y' * 220},
            )
            mux._remote_services_requested = [spec]
            mux._send_remote_services_catalog_if_any()
            self.assertGreater(len(session.sent), 1)
            chunk_frames = []
            for wire in session.sent:
                parsed = mux._unpack_mux(wire)
                self.assertIsNotNone(parsed)
                assert parsed is not None
                _chan, proto, _ctr, mtype, payload_mv = parsed
                self.assertEqual(proto, ChannelMux.Proto.UDP)
                if mtype == ChannelMux.MType.REMOTE_SERVICES_SET_V2_CHUNK:
                    chunk_frames.append(bytes(payload_mv))
            self.assertGreaterEqual(len(chunk_frames), 2)

            assembled = None
            for chunk in chunk_frames:
                assembled = mux._consume_control_chunk(
                    chan_id=0,
                    proto=ChannelMux.Proto.UDP,
                    mtype=ChannelMux.MType.REMOTE_SERVICES_SET_V2_CHUNK,
                    payload=chunk,
                    peer_id=99,
                ) or assembled
            self.assertIsNotNone(assembled)
            decoded = mux._decode_remote_services_set_v2(assembled or b"")
            self.assertIsNotNone(decoded)
            assert decoded is not None
            _iid, _seq, services = decoded
            self.assertEqual(services[0].name, 'chunked-remote')
            self.assertIsInstance(services[0].lifecycle_hooks, dict)
            self.assertIsInstance(services[0].options, dict)
        finally:
            mux.loop.close()

    def test_chunked_open_transfer_reassembles_metadata(self):
        session = _FakeSession(connected=True, max_app_payload_size=96)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            spec = ChannelMux.ServiceSpec(
                svc_id=11,
                l_proto='tcp',
                l_bind='0.0.0.0',
                l_port=31000,
                r_proto='tcp',
                r_host='127.0.0.1',
                r_port=32000,
                name='chunked-open',
                lifecycle_hooks={'client': {'before_connect': {'argv': ['echo', 'z' * 220]}}},
                options={'description': 'q' * 220},
            )
            mux._send_open_for_service(17, ChannelMux.Proto.TCP, spec)
            self.assertGreater(len(session.sent), 1)
            chunk_frames = []
            for wire in session.sent:
                parsed = mux._unpack_mux(wire)
                self.assertIsNotNone(parsed)
                assert parsed is not None
                chan, proto, _ctr, mtype, payload_mv = parsed
                self.assertEqual(chan, 17)
                self.assertEqual(proto, ChannelMux.Proto.TCP)
                if mtype == ChannelMux.MType.OPEN_CHUNK:
                    chunk_frames.append(bytes(payload_mv))
            self.assertGreaterEqual(len(chunk_frames), 2)

            assembled = None
            for chunk in chunk_frames:
                assembled = mux._consume_control_chunk(
                    chan_id=17,
                    proto=ChannelMux.Proto.TCP,
                    mtype=ChannelMux.MType.OPEN_CHUNK,
                    payload=chunk,
                    peer_id=7,
                ) or assembled
            self.assertIsNotNone(assembled)
            parsed_open = mux._parse_open_with_meta(assembled or b"")
            self.assertIsNotNone(parsed_open)
            assert parsed_open is not None
            self.assertEqual(parsed_open[9], 'chunked-open')
            self.assertIsInstance(parsed_open[10], dict)
            self.assertIsInstance(parsed_open[11], dict)
        finally:
            mux.loop.close()

    def test_listener_mode_ignores_own_servers_and_remote_servers(self):
        args = argparse.Namespace(
            peer=None,
            udp_peer=None,
            tcp_peer=None,
            ws_peer=None,
            quic_peer=None,
            overlay_transport='myudp',
            own_servers=[{
                'listen': {'protocol': 'udp', 'bind': '0.0.0.0', 'port': 16667},
                'target': {'protocol': 'udp', 'host': '127.0.0.1', 'port': 16666},
            }],
            remote_servers=[{
                'listen': {'protocol': 'tcp', 'bind': '0.0.0.0', 'port': 3129},
                'target': {'protocol': 'tcp', 'host': '127.0.0.1', 'port': 3128},
            }],
            mux_tcp_bp_threshold=1,
            mux_tcp_bp_latency_ms=300,
            mux_tcp_bp_poll_interval_ms=50,
        )

        mux = ChannelMux.from_args(_FakeSession(), asyncio.new_event_loop(), args)
        try:
            self.assertEqual(mux._local_services, {})
            self.assertEqual(mux._remote_services_requested, [])
        finally:
            mux.loop.close()

    def test_client_mode_keeps_own_servers(self):
        args = argparse.Namespace(
            peer='127.0.0.1',
            udp_peer='127.0.0.1',
            overlay_transport='myudp',
            own_servers=[{
                'listen': {'protocol': 'udp', 'bind': '0.0.0.0', 'port': 16667},
                'target': {'protocol': 'udp', 'host': '127.0.0.1', 'port': 16666},
            }],
            remote_servers=None,
            mux_tcp_bp_threshold=1,
            mux_tcp_bp_latency_ms=300,
            mux_tcp_bp_poll_interval_ms=50,
        )

        mux = ChannelMux.from_args(_FakeSession(), asyncio.new_event_loop(), args)
        try:
            self.assertEqual(len(mux._local_services), 1)
            spec = mux._local_services[('local', 0, 1)]
            self.assertEqual(spec.l_proto, 'udp')
            self.assertEqual(spec.l_port, 16667)
            self.assertEqual(spec.r_proto, 'udp')
            self.assertEqual(spec.r_host, '127.0.0.1')
            self.assertEqual(spec.r_port, 16666)
        finally:
            mux.loop.close()

    def test_parse_remote_servers_accepts_json_string_specs(self):
        specs = [
            '{"listen":{"protocol":"udp","bind":"0.0.0.0","port":16667},"target":{"protocol":"udp","host":"127.0.0.1","port":16666}}',
            '{"listen":{"protocol":"tcp","bind":"::","port":3129},"target":{"protocol":"tcp","host":"::1","port":3128}}',
            '{"listen":{"protocol":"tun","ifname":"obtun0","mtu":1500},"target":{"protocol":"tun","ifname":"obtun1","mtu":1500}}',
        ]

        parsed = ChannelMux._parse_remote_servers(specs)

        self.assertEqual(len(parsed), 3)
        self.assertEqual(parsed[0].svc_id, 1)
        self.assertEqual(parsed[0].l_proto, 'udp')
        self.assertEqual(parsed[1].svc_id, 2)
        self.assertEqual(parsed[1].l_proto, 'tcp')
        self.assertEqual(parsed[1].r_host, '::1')
        self.assertEqual(parsed[2].svc_id, 3)
        self.assertEqual(parsed[2].l_proto, 'tun')
        self.assertEqual(parsed[2].l_bind, 'obtun0')
        self.assertEqual(parsed[2].r_host, 'obtun1')

    def test_parse_remote_servers_accepts_structured_specs(self):
        specs = [
            {
                'name': 'public-http',
                'listen': {'protocol': 'tcp', 'bind': '0.0.0.0', 'port': 80},
                'target': {'protocol': 'tcp', 'host': '127.0.0.1', 'port': 8080},
                'lifecycle_hooks': {
                    'listener': {
                        'on_created': {'argv': ['hook.cmd', 'created']},
                    }
                },
                'options': {'note': 'reserved'},
            },
            {
                'listen': {'protocol': 'tun', 'ifname': 'obtun0', 'mtu': 1400},
                'target': {'protocol': 'tun', 'ifname': 'obtun1', 'mtu': 1400},
            },
        ]

        parsed = ChannelMux._parse_remote_servers(specs)

        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0].name, 'public-http')
        self.assertEqual(parsed[0].l_proto, 'tcp')
        self.assertEqual(parsed[0].l_bind, '0.0.0.0')
        self.assertEqual(parsed[0].l_port, 80)
        self.assertEqual(parsed[0].r_host, '127.0.0.1')
        self.assertEqual(parsed[0].r_port, 8080)
        self.assertEqual(parsed[0].lifecycle_hooks['listener']['on_created']['argv'], ['hook.cmd', 'created'])
        self.assertEqual(parsed[0].options['note'], 'reserved')
        self.assertEqual(parsed[1].l_proto, 'tun')
        self.assertEqual(parsed[1].l_bind, 'obtun0')
        self.assertEqual(parsed[1].l_port, 1400)
        self.assertEqual(parsed[1].r_host, 'obtun1')
        self.assertEqual(parsed[1].r_port, 1400)

    def test_parse_remote_servers_rejects_invalid_specs(self):
        with self.assertRaisesRegex(ValueError, '--remote-servers listen protocol must be udp, tcp or tun'):
            ChannelMux._parse_remote_servers([
                '{"listen":{"protocol":"icmp","bind":"0.0.0.0","port":16667},"target":{"protocol":"udp","host":"127.0.0.1","port":16666}}'
            ])

        with self.assertRaisesRegex(ValueError, '--remote-servers listen port must be an integer in 1..65535'):
            ChannelMux._parse_remote_servers([
                '{"listen":{"protocol":"udp","bind":"0.0.0.0","port":0},"target":{"protocol":"udp","host":"127.0.0.1","port":16666}}'
            ])

        with self.assertRaisesRegex(ValueError, '--remote-servers target port must be an integer in 1..65535'):
            ChannelMux._parse_remote_servers([
                '{"listen":{"protocol":"udp","bind":"0.0.0.0","port":16667},"target":{"protocol":"udp","host":"127.0.0.1","port":"bad"}}'
            ])

        with self.assertRaisesRegex(ValueError, 'JSON value must be a service object or array of service objects'):
            ChannelMux._parse_remote_servers(['123'])

    def test_parse_remote_servers_rejects_invalid_structured_specs(self):
        with self.assertRaisesRegex(ValueError, 'requires object field listen'):
            ChannelMux._parse_remote_servers([{'target': {'protocol': 'tcp', 'host': '127.0.0.1', 'port': 80}}])

        with self.assertRaisesRegex(ValueError, 'structured tcp listen requires bind'):
            ChannelMux._parse_remote_servers([{
                'listen': {'protocol': 'tcp', 'port': 80},
                'target': {'protocol': 'tcp', 'host': '127.0.0.1', 'port': 8080},
            }])

        with self.assertRaisesRegex(ValueError, 'lifecycle_hooks must be an object'):
            ChannelMux._parse_remote_servers([{
                'listen': {'protocol': 'udp', 'bind': '0.0.0.0', 'port': 16667},
                'target': {'protocol': 'udp', 'host': '127.0.0.1', 'port': 16666},
                'lifecycle_hooks': ['bad'],
            }])

    def test_parse_service_specs_treats_empty_config_entries_as_no_services(self):
        self.assertEqual(ChannelMux._parse_own_servers([None]), [])
        self.assertEqual(ChannelMux._parse_remote_servers([None, '  ']), [])


class ChannelMuxRemoteCatalogTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.session = _FakeSession()
        self.mux = ChannelMux(self.session, asyncio.get_running_loop())
        self.mux._overlay_connected = True
        self.mux._accepting_enabled = True

    async def test_sends_control_install_when_overlay_connects(self):
        spec = ChannelMux.ServiceSpec(
            svc_id=1,
            l_proto='udp',
            l_bind='0.0.0.0',
            l_port=16667,
            r_proto='udp',
            r_host='127.0.0.1',
            r_port=16666,
        )
        self.mux._remote_services_requested = [spec]
        self.mux._overlay_connected = False
        self.mux._accepting_enabled = False

        with patch.object(self.mux, '_start_all_services', new=AsyncMock()) as start_all, patch.object(self.mux, '_send_mux') as send_mux:
            await self.mux.on_overlay_state(True)

        start_all.assert_awaited_once()
        send_mux.assert_called_once()
        chan, proto, mtype, payload = send_mux.call_args.args
        self.assertEqual(chan, 0)
        self.assertEqual(proto, ChannelMux.Proto.UDP)
        self.assertEqual(mtype, ChannelMux.MType.REMOTE_SERVICES_SET_V2)
        self.assertEqual(self.mux._decode_remote_services_set_v2(payload)[2], [spec])

    async def test_overlay_connect_replays_tun_on_created_hook_for_active_tun_service(self):
        spec = ChannelMux.ServiceSpec(
            svc_id=3,
            l_proto='tun',
            l_bind='obtun0',
            l_port=1500,
            r_proto='tun',
            r_host='obtun1',
            r_port=1500,
            lifecycle_hooks={'listener': {'on_created': {'argv': ['hook', 'up']}}},
        )
        svc_key = ('local', 0, 3)
        self.mux._local_services[svc_key] = spec
        self.mux._svc_tun_devices[svc_key] = ChannelMux.TunDevice(fd=44, ifname='obtun0', mtu=1500, service_key=svc_key)
        self.mux._overlay_connected = False
        self.mux._accepting_enabled = False

        with patch.object(self.mux, '_start_all_services', new=AsyncMock()) as start_all, \
             patch.object(self.mux, '_send_remote_services_catalog_if_any') as send_catalog, \
             patch.object(self.mux, '_schedule_service_hook') as schedule_hook:
            await self.mux.on_overlay_state(True)

        start_all.assert_awaited_once()
        send_catalog.assert_called_once()
        schedule_hook.assert_any_call(spec, svc_key, 'listener', 'on_created')

    async def test_start_prestarts_listener_shared_tun_service_while_overlay_disconnected(self):
        spec = ChannelMux.ServiceSpec(
            svc_id=9,
            l_proto='tun',
            l_bind='obtun0',
            l_port=1400,
            r_proto='tun',
            r_host='obtun0',
            r_port=1400,
            options={
                'shared_tun_ownership': {
                    'mode': 'server_shared',
                    'peers': [
                        {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2']},
                    ],
                }
            },
        )
        svc_key = ('local', 0, 9)
        self.mux._local_services[svc_key] = spec
        self.mux._overlay_connected = False
        self.mux._accepting_enabled = False

        with patch.object(self.mux, '_start_tun_server_for', new=AsyncMock()) as start_tun, \
             patch.object(self.mux, '_start_all_services', new=AsyncMock()) as start_all, \
             patch.object(self.mux, '_send_remote_services_catalog_if_any') as send_catalog:
            await self.mux.start()

        start_tun.assert_awaited_once_with(spec, svc_key)
        start_all.assert_not_awaited()
        send_catalog.assert_not_called()

    async def test_receiver_starts_udp_and_tcp_listeners_from_remote_catalog(self):
        udp_spec = ChannelMux.ServiceSpec(1, 'udp', '127.0.0.1', 10001, 'udp', '127.0.0.1', 20001)
        tcp_spec = ChannelMux.ServiceSpec(2, 'tcp', '127.0.0.1', 10002, 'tcp', '127.0.0.1', 20002)
        tun_spec = ChannelMux.ServiceSpec(3, 'tun', 'obtun0', 1500, 'tun', 'obtun1', 1500)
        payload = self.mux._encode_remote_services_set_v2([udp_spec, tcp_spec, tun_spec])
        frame = self.mux._pack_mux(0, ChannelMux.Proto.UDP, 0, ChannelMux.MType.REMOTE_SERVICES_SET_V2, payload)

        with patch.object(self.mux, '_start_udp_server_for', new=AsyncMock()) as start_udp, patch.object(self.mux, '_start_tcp_server_for', new=AsyncMock()) as start_tcp, patch.object(self.mux, '_start_tun_server_for', new=AsyncMock()) as start_tun:
            ok = self.mux.on_app_payload_from_peer(frame, peer_id=77)
            self.assertTrue(ok)
            await asyncio.sleep(0)

        start_udp.assert_awaited_once()
        start_tcp.assert_awaited_once()
        start_tun.assert_awaited_once()
        self.assertIn(('peer', 77, 1), self.mux._peer_installed_services)
        self.assertIn(('peer', 77, 2), self.mux._peer_installed_services)
        self.assertIn(('peer', 77, 3), self.mux._peer_installed_services)

    async def test_tun_open_uses_pending_peer_listener_before_async_catalog_start(self):
        remote_tun = ChannelMux.ServiceSpec(
            2,
            'tun',
            'obtun1',
            1500,
            'tun',
            'obtun0',
            1500,
            lifecycle_hooks={'listener': {'on_created': {'argv': ['hook']}}},
        )
        catalog_payload = self.mux._encode_remote_services_set_v2([remote_tun])
        catalog_frame = self.mux._pack_mux(
            0,
            ChannelMux.Proto.UDP,
            0,
            ChannelMux.MType.REMOTE_SERVICES_SET_V2,
            catalog_payload,
        )
        local_tun = ChannelMux.ServiceSpec(5, 'tun', 'obtun0', 1500, 'tun', 'obtun1', 1500)
        open_payload = self.mux._build_open_v4(local_tun)
        svc_key = ('peer', 77, 2)

        def open_tun(ifname, mtu, svc_key=None):
            return ChannelMux.TunDevice(fd=44, ifname=ifname, mtu=mtu, service_key=svc_key)

        with patch.object(self.mux, '_apply_peer_installed_services', new=AsyncMock()) as apply_peer, \
             patch.object(self.mux, '_open_tun_device', side_effect=open_tun) as open_tun_device, \
             patch.object(self.mux, '_register_tun_reader') as register_reader, \
             patch.object(self.mux, '_schedule_service_hook') as schedule_hook:
            self.assertTrue(self.mux.on_app_payload_from_peer(catalog_frame, peer_id=77))
            self.mux._rx_tun_open(1, open_payload, peer_id=77)
            await asyncio.sleep(0)

        apply_peer.assert_awaited_once()
        open_tun_device.assert_called_once_with('obtun1', 1500, svc_key=svc_key)
        register_reader.assert_called_once()
        self.assertIn(svc_key, self.mux._peer_installed_services)
        self.assertIs(self.mux._tun_by_chan[1], self.mux._svc_tun_devices[svc_key])
        schedule_hook.assert_any_call(remote_tun, svc_key, 'listener', 'on_created')

    async def test_tun_open_reuses_mirrored_peer_listener_target_without_opening_remote_ifname(self):
        remote_tun = ChannelMux.ServiceSpec(
            2,
            'tun',
            'Obtun3',
            1600,
            'tun',
            'ios-utun',
            1600,
            lifecycle_hooks={'listener': {'on_created': {'argv': ['hook']}}},
        )
        catalog_payload = self.mux._encode_remote_services_set_v2([remote_tun])
        catalog_frame = self.mux._pack_mux(
            0,
            ChannelMux.Proto.UDP,
            0,
            ChannelMux.MType.REMOTE_SERVICES_SET_V2,
            catalog_payload,
        )
        mirrored_open = ChannelMux.ServiceSpec(5, 'tun', 'ios-utun', 1600, 'tun', 'ios-utun', 1600)
        open_payload = self.mux._build_open_v4(mirrored_open)
        svc_key = ('peer', 77, 2)

        def open_tun(ifname, mtu, svc_key=None):
            return ChannelMux.TunDevice(fd=45, ifname=ifname, mtu=mtu, service_key=svc_key)

        with patch.object(self.mux, '_apply_peer_installed_services', new=AsyncMock()) as apply_peer, \
             patch.object(self.mux, '_open_tun_device', side_effect=open_tun) as open_tun_device, \
             patch.object(self.mux, '_register_tun_reader') as register_reader, \
             patch.object(self.mux, '_schedule_service_hook') as schedule_hook:
            self.assertTrue(self.mux.on_app_payload_from_peer(catalog_frame, peer_id=77))
            self.mux._rx_tun_open(1, open_payload, peer_id=77)
            await asyncio.sleep(0)

        apply_peer.assert_awaited_once()
        open_tun_device.assert_called_once_with('Obtun3', 1600, svc_key=svc_key)
        register_reader.assert_called_once()
        self.assertIn(svc_key, self.mux._peer_installed_services)
        self.assertIs(self.mux._tun_by_chan[1], self.mux._svc_tun_devices[svc_key])
        schedule_hook.assert_any_call(remote_tun, svc_key, 'listener', 'on_created')

    async def test_shared_tun_runtime_binding_tracks_open_and_disconnect_cleanup(self):
        remote_tun = ChannelMux.ServiceSpec(
            2,
            'tun',
            'obtun1',
            1500,
            'tun',
            'obtun0',
            1500,
            options={
                'shared_tun_ownership': {
                    'mode': 'server_shared',
                    'peers': [
                        {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2'], 'ipv6': ['fd20:107::2']},
                    ],
                }
            },
        )
        catalog_payload = self.mux._encode_remote_services_set_v2([remote_tun])
        catalog_frame = self.mux._pack_mux(
            0,
            ChannelMux.Proto.UDP,
            0,
            ChannelMux.MType.REMOTE_SERVICES_SET_V2,
            catalog_payload,
        )
        local_tun = ChannelMux.ServiceSpec(5, 'tun', 'obtun0', 1500, 'tun', 'obtun1', 1500)
        open_payload = self.mux._build_open_v4(local_tun)
        svc_key = ('peer', 77, 2)

        def open_tun(ifname, mtu, svc_key=None):
            return ChannelMux.TunDevice(fd=44, ifname=ifname, mtu=mtu, service_key=svc_key)

        with patch.object(self.mux, '_open_tun_device', side_effect=open_tun), \
             patch.object(self.mux, '_register_tun_reader'), \
             patch.object(self.mux, '_schedule_service_hook'):
            self.assertTrue(self.mux.on_app_payload_from_peer(catalog_frame, peer_id=77))
            await asyncio.sleep(0)
            self.mux._rx_tun_open(1, open_payload, peer_id=77)

        self.assertEqual(
            self.mux._shared_tun_runtime_snapshot_for_service(svc_key),
            {
                'mode': 'server_shared',
                'peer_count': 1,
                'address_count': 2,
                'peer_refs': ['linux-client'],
                'peers': [
                    {
                        'peer_ref': 'linux-client',
                        'ipv4': ['192.168.107.2'],
                        'ipv6': ['fd20:107::2'],
                        'address_count': 2,
                    }
                ],
                'owner_by_ipv4': {'192.168.107.2': 'linux-client'},
                'owner_by_ipv6': {'fd20:107::2': 'linux-client'},
                'active_peer_bindings': [
                    {
                        'peer_id': 77,
                        'preferred_chan_id': 1,
                        'bound_chan_ids': [1],
                    }
                ],
            },
        )

        with patch.object(self.mux, '_stop_listener_for_service_id', new=AsyncMock()) as stop_listener:
            self.mux.on_peer_disconnected(77)
            await asyncio.sleep(0)

        stop_listener.assert_awaited_once_with(svc_key, 'tun', spec=remote_tun)
        self.assertEqual(
            self.mux._shared_tun_runtime_snapshot_for_service(svc_key)["active_peer_bindings"],
            [],
        )

    def test_shared_tun_guard_accepts_owned_ipv4_source(self):
        spec = ChannelMux.ServiceSpec(
            2,
            'tun',
            'obtun1',
            1500,
            'tun',
            'obtun0',
            1500,
            options={
                'shared_tun_ownership': {
                    'mode': 'server_shared',
                    'peers': [
                        {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2'], 'ipv6': ['fd20:107::2']},
                    ],
                }
            },
        )
        svc_key = ('peer', 77, 2)
        dev = ChannelMux.TunDevice(fd=44, ifname='obtun1', mtu=1500, service_key=svc_key)
        self.mux._install_shared_tun_ownership_for_service(svc_key, spec)
        self.mux._chan_owner_peer_id[1] = 77

        allowed, parsed, reason = self.mux._shared_tun_guard_inbound_packet(
            dev=dev,
            chan=1,
            packet=_ipv4_packet('192.168.107.2', '192.168.107.1'),
        )

        self.assertTrue(allowed)
        self.assertEqual(parsed["ip_version"], 4)
        self.assertEqual(parsed["source_ip"], '192.168.107.2')
        self.assertEqual(parsed["destination_ip"], '192.168.107.1')
        self.assertIsNone(reason)

    def test_shared_tun_guard_accepts_owned_ipv4_source_to_broadcast_destination(self):
        spec = ChannelMux.ServiceSpec(
            2,
            'tun',
            'obtun1',
            1500,
            'tun',
            'obtun0',
            1500,
            options={
                'shared_tun_ownership': {
                    'mode': 'server_shared',
                    'peers': [
                        {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2'], 'ipv6': ['fd20:107::2']},
                    ],
                }
            },
        )
        svc_key = ('peer', 77, 2)
        dev = ChannelMux.TunDevice(fd=44, ifname='obtun1', mtu=1500, service_key=svc_key)
        self.mux._install_shared_tun_ownership_for_service(svc_key, spec)
        self.mux._chan_owner_peer_id[1] = 77

        allowed, parsed, reason = self.mux._shared_tun_guard_inbound_packet(
            dev=dev,
            chan=1,
            packet=_ipv4_packet('192.168.107.2', '255.255.255.255'),
        )

        self.assertTrue(allowed)
        self.assertEqual(parsed["source_ip"], '192.168.107.2')
        self.assertEqual(parsed["destination_ip"], '255.255.255.255')
        self.assertIsNone(reason)

    def test_shared_tun_guard_rejects_unowned_ipv4_source(self):
        spec = ChannelMux.ServiceSpec(
            2,
            'tun',
            'obtun1',
            1500,
            'tun',
            'obtun0',
            1500,
            options={
                'shared_tun_ownership': {
                    'mode': 'server_shared',
                    'peers': [
                        {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2'], 'ipv6': ['fd20:107::2']},
                    ],
                }
            },
        )
        svc_key = ('peer', 77, 2)
        dev = ChannelMux.TunDevice(fd=44, ifname='obtun1', mtu=1500, service_key=svc_key)
        self.mux._install_shared_tun_ownership_for_service(svc_key, spec)
        self.mux._chan_owner_peer_id[1] = 77

        allowed, parsed, reason = self.mux._shared_tun_guard_inbound_packet(
            dev=dev,
            chan=1,
            packet=_ipv4_packet('192.168.107.9', '192.168.107.1'),
        )

        self.assertFalse(allowed)
        self.assertEqual(parsed["source_ip"], '192.168.107.9')
        self.assertEqual(reason, 'source_not_owned_by_peer')

    def test_shared_tun_guard_accepts_owned_ipv6_source(self):
        spec = ChannelMux.ServiceSpec(
            2,
            'tun',
            'obtun1',
            1500,
            'tun',
            'obtun0',
            1500,
            options={
                'shared_tun_ownership': {
                    'mode': 'server_shared',
                    'peers': [
                        {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2'], 'ipv6': ['fd20:107::2']},
                    ],
                }
            },
        )
        svc_key = ('peer', 77, 2)
        dev = ChannelMux.TunDevice(fd=44, ifname='obtun1', mtu=1500, service_key=svc_key)
        self.mux._install_shared_tun_ownership_for_service(svc_key, spec)
        self.mux._chan_owner_peer_id[1] = 77

        allowed, parsed, reason = self.mux._shared_tun_guard_inbound_packet(
            dev=dev,
            chan=1,
            packet=_ipv6_packet('fd20:107::2', 'fd20:107::1'),
        )

        self.assertTrue(allowed)
        self.assertEqual(parsed["ip_version"], 6)
        self.assertEqual(parsed["source_ip"], 'fd20:107::2')
        self.assertEqual(reason, None)

    def test_shared_tun_guard_rejects_malformed_packet(self):
        spec = ChannelMux.ServiceSpec(
            2,
            'tun',
            'obtun1',
            1500,
            'tun',
            'obtun0',
            1500,
            options={
                'shared_tun_ownership': {
                    'mode': 'server_shared',
                    'peers': [
                        {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2'], 'ipv6': ['fd20:107::2']},
                    ],
                }
            },
        )
        svc_key = ('peer', 77, 2)
        dev = ChannelMux.TunDevice(fd=44, ifname='obtun1', mtu=1500, service_key=svc_key)
        self.mux._install_shared_tun_ownership_for_service(svc_key, spec)
        self.mux._chan_owner_peer_id[1] = 77

        allowed, parsed, reason = self.mux._shared_tun_guard_inbound_packet(
            dev=dev,
            chan=1,
            packet=b'\x45\x00',
        )

        self.assertFalse(allowed)
        self.assertIsNone(parsed)
        self.assertEqual(reason, 'ipv4_too_short')

    def test_shared_tun_guard_binds_peer_ref_and_rejects_second_owner_claim(self):
        spec = ChannelMux.ServiceSpec(
            2,
            'tun',
            'obtun1',
            1500,
            'tun',
            'obtun0',
            1500,
            options={
                'shared_tun_ownership': {
                    'mode': 'server_shared',
                    'peers': [
                        {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2']},
                        {'peer_ref': 'ios-client', 'ipv4': ['192.168.107.4']},
                    ],
                }
            },
        )
        svc_key = ('peer', 77, 2)
        dev = ChannelMux.TunDevice(fd=44, ifname='obtun1', mtu=1500, service_key=svc_key)
        self.mux._install_shared_tun_ownership_for_service(svc_key, spec)
        self.mux._chan_owner_peer_id[1] = 77

        allowed, parsed, reason = self.mux._shared_tun_guard_inbound_packet(
            dev=dev,
            chan=1,
            packet=_ipv4_packet('192.168.107.2', '192.168.107.1'),
        )

        self.assertTrue(allowed)
        self.assertEqual(parsed["source_ip"], '192.168.107.2')
        self.assertIsNone(reason)
        self.assertEqual(
            self.mux._shared_tun_peer_ref_by_peer[(svc_key, 77)],
            'linux-client',
        )
        self.assertEqual(
            self.mux._shared_tun_peer_id_by_ref[(svc_key, 'linux-client')],
            77,
        )

        allowed, parsed, reason = self.mux._shared_tun_guard_inbound_packet(
            dev=dev,
            chan=1,
            packet=_ipv4_packet('192.168.107.4', '192.168.107.1'),
        )

        self.assertFalse(allowed)
        self.assertEqual(parsed["source_ip"], '192.168.107.4')
        self.assertEqual(reason, 'source_not_owned_by_peer')

    def test_shared_tun_open_requires_prestarted_server_owned_service(self):
        spec = ChannelMux.ServiceSpec(
            2,
            'tun',
            'obtun1',
            1500,
            'tun',
            'obtun0',
            1500,
            options={
                'shared_tun_ownership': {
                    'mode': 'server_shared',
                    'peers': [
                        {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2']},
                    ],
                }
            },
        )
        open_payload = self.mux._build_open_v4(spec)
        with patch.object(self.mux, '_ensure_peer_tun_listener_for_target') as ensure_peer_listener:
            self.mux._rx_tun_open(1, open_payload, peer_id=77)

        ensure_peer_listener.assert_not_called()
        self.assertNotIn(1, self.mux._tun_by_chan)

    def test_shared_tun_open_binds_to_prestarted_server_owned_service(self):
        spec = ChannelMux.ServiceSpec(
            2,
            'tun',
            'obtun1',
            1500,
            'tun',
            'obtun0',
            1500,
            options={
                'shared_tun_ownership': {
                    'mode': 'server_shared',
                    'peers': [
                        {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2']},
                    ],
                }
            },
        )
        svc_key = ('local', 0, 2)
        dev = ChannelMux.TunDevice(fd=55, ifname='obtun0', mtu=1500, service_key=svc_key)
        self.mux._local_services[svc_key] = spec
        self.mux._svc_tun_devices[svc_key] = dev
        self.mux._install_shared_tun_ownership_for_service(svc_key, spec)
        open_payload = self.mux._build_open_v4(spec)

        with patch.object(self.mux, '_ensure_peer_tun_listener_for_target') as ensure_peer_listener:
            self.mux._rx_tun_open(1, open_payload, peer_id=77)

        ensure_peer_listener.assert_not_called()
        self.assertIs(self.mux._tun_by_chan.get(1), dev)

    async def test_remote_catalog_replacement_adds_and_removes_services(self):
        svc1 = ChannelMux.ServiceSpec(1, 'udp', '127.0.0.1', 10001, 'udp', '127.0.0.1', 20001)
        svc2 = ChannelMux.ServiceSpec(2, 'tcp', '127.0.0.1', 10002, 'tcp', '127.0.0.1', 20002)

        with patch.object(self.mux, '_start_udp_server_for', new=AsyncMock()) as start_udp, patch.object(self.mux, '_start_tcp_server_for', new=AsyncMock()) as start_tcp, patch.object(self.mux, '_stop_listener_for_service_id', new=AsyncMock()) as stop_listener:
            await self.mux._apply_peer_installed_services([svc1], peer_id=7)
            await self.mux._apply_peer_installed_services([svc2], peer_id=7)

        start_udp.assert_awaited_once()
        start_tcp.assert_awaited_once()
        stop_listener.assert_awaited_once_with(('peer', 7, 1), 'udp', spec=svc1)
        self.assertNotIn(('peer', 7, 1), self.mux._peer_installed_services)
        self.assertIn(('peer', 7, 2), self.mux._peer_installed_services)

    async def test_per_peer_cleanup_on_disconnect(self):
        svc = ChannelMux.ServiceSpec(1, 'udp', '127.0.0.1', 10001, 'udp', '127.0.0.1', 20001)
        await self.mux._apply_peer_installed_services([svc], peer_id=11)
        await self.mux._apply_peer_installed_services([svc], peer_id=22)

        with patch.object(self.mux, '_stop_listener_for_service_id', new=AsyncMock()) as stop_listener:
            self.mux.on_peer_disconnected(11)
            await asyncio.sleep(0)

        stop_listener.assert_awaited_once_with(('peer', 11, 1), 'udp', spec=svc)
        self.assertNotIn(('peer', 11, 1), self.mux._peer_installed_services)
        self.assertIn(('peer', 22, 1), self.mux._peer_installed_services)

    async def test_peer_installed_tun_stop_runs_listener_on_stopped_before_close(self):
        svc_key = ('peer', 7, 1)
        spec = ChannelMux.ServiceSpec(
            1,
            'tun',
            'obtun1',
            1500,
            'tun',
            'obtun0',
            1500,
            lifecycle_hooks={'listener': {'on_stopped': {'argv': ['echo', 'down']}}},
        )
        dev = object()
        self.mux._peer_installed_services[svc_key] = spec
        self.mux._svc_tun_devices[svc_key] = dev

        with patch.object(self.mux, '_run_service_hook', new=AsyncMock()) as run_hook, patch.object(self.mux, '_close_tun_device') as close_tun:
            await self.mux._drop_peer_installed_services(peer_id=7)

        run_hook.assert_awaited_once_with(spec, svc_key, 'listener', 'on_stopped')
        close_tun.assert_called_once_with(dev)
        self.assertNotIn(svc_key, self.mux._peer_installed_services)
        self.assertNotIn(svc_key, self.mux._svc_tun_devices)


class ChannelMuxSessionBudgetTests(unittest.TestCase):
    def test_safe_tcp_read_uses_session_payload_budget(self):
        session = _FakeSession(max_app_payload_size=512)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            self.assertEqual(mux._SAFE_TCP_READ, 512 - ChannelMux.MUX_HDR.size)
        finally:
            mux.loop.close()

    def test_send_mux_drops_payloads_above_session_budget(self):
        session = _FakeSession(connected=True, max_app_payload_size=32)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._send_mux(
                7,
                ChannelMux.Proto.UDP,
                ChannelMux.MType.REMOTE_SERVICES_SET_V2,
                b"x" * (32 - ChannelMux.MUX_HDR.size + 1),
            )
            self.assertEqual(session.sent, [])
        finally:
            mux.loop.close()

    def test_send_mux_fragments_oversized_udp_data(self):
        session = _FakeSession(connected=True, max_app_payload_size=32)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            payload = b"abcdefghijklmnopqrstuvwxyz"
            mux._send_mux(7, ChannelMux.Proto.UDP, ChannelMux.MType.DATA, payload)

            self.assertGreater(len(session.sent), 1)
            rebuilt = bytearray()
            seen_datagram_ids = set()
            for frame in session.sent:
                parsed = mux._unpack_mux(frame)
                self.assertIsNotNone(parsed)
                chan_id, proto, _counter, mtype, payload_mv = parsed
                self.assertEqual(chan_id, 7)
                self.assertEqual(proto, ChannelMux.Proto.UDP)
                self.assertEqual(mtype, ChannelMux.MType.DATA_FRAG)
                frag = bytes(payload_mv)
                datagram_id, total_len, offset = ChannelMux.UDP_FRAG_HDR.unpack(frag[:ChannelMux.UDP_FRAG_HDR.size])
                seen_datagram_ids.add(datagram_id)
                chunk = frag[ChannelMux.UDP_FRAG_HDR.size:]
                self.assertEqual(total_len, len(payload))
                self.assertLessEqual(len(frame), session.max_app_payload_size)
                self.assertEqual(offset, len(rebuilt))
                rebuilt.extend(chunk)

            self.assertEqual(seen_datagram_ids.__len__(), 1)
            self.assertEqual(bytes(rebuilt), payload)
        finally:
            mux.loop.close()

    def test_reassembles_udp_fragments_before_local_delivery(self):
        session = _FakeSession()
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            payload = b"fragmented-udp-datagram"
            datagram_id = 41
            fragment_size = 5
            with patch.object(mux, '_rx_udp_data') as rx_udp_data:
                for offset in range(0, len(payload), fragment_size):
                    frag_payload = ChannelMux.UDP_FRAG_HDR.pack(
                        datagram_id,
                        len(payload),
                        offset,
                    ) + payload[offset:offset + fragment_size]
                    frame = mux._pack_mux(
                        11,
                        ChannelMux.Proto.UDP,
                        offset // fragment_size,
                        ChannelMux.MType.DATA_FRAG,
                        frag_payload,
                    )
                    mux.on_app_payload_from_peer(frame)

                rx_udp_data.assert_called_once_with(11, payload)
        finally:
            mux.loop.close()

    def test_drops_udp_fragments_above_service_datagram_cap(self):
        session = _FakeSession()
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._udp_service_datagram_cap = 8
            with patch.object(mux, '_rx_udp_data') as rx_udp_data:
                frag_payload = ChannelMux.UDP_FRAG_HDR.pack(7, 16, 0) + b'abcdefgh'
                frame = mux._pack_mux(
                    3,
                    ChannelMux.Proto.UDP,
                    0,
                    ChannelMux.MType.DATA_FRAG,
                    frag_payload,
                )
                mux.on_app_payload_from_peer(frame)
                rx_udp_data.assert_not_called()
        finally:
            mux.loop.close()

    def test_drops_local_udp_datagram_above_service_datagram_cap(self):
        session = _FakeSession(connected=True)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._udp_service_datagram_cap = 4
            spec = ChannelMux.ServiceSpec(1, 'udp', '127.0.0.1', 20001, 'udp', '127.0.0.1', 20002)
            svc_key = ('local', 0, 1)
            with patch.object(mux, '_send_mux') as send_mux:
                mux._on_local_udp_datagram(spec, svc_key, b'abcdef', ('127.0.0.1', 32000))
                send_mux.assert_not_called()
        finally:
            mux.loop.close()

    def test_local_tun_packet_opens_channel_and_sends_data(self):
        session = _FakeSession(connected=True)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._overlay_connected = True
            mux._accepting_enabled = True
            spec = ChannelMux.ServiceSpec(5, 'tun', 'obtun0', 1500, 'tun', 'obtun1', 1500)
            svc_key = ('local', 0, 5)
            mux._local_services[svc_key] = spec
            dev = ChannelMux.TunDevice(fd=10, ifname='obtun0', mtu=1500, service_key=svc_key)
            mux._svc_tun_devices[svc_key] = dev

            mux._on_local_tun_packet(dev, b'\x45hello')

            self.assertEqual(len(session.sent), 2)
            first = mux._unpack_mux(session.sent[0])
            second = mux._unpack_mux(session.sent[1])
            self.assertIsNotNone(first)
            self.assertIsNotNone(second)
            self.assertEqual(first[1], ChannelMux.Proto.TUN)
            self.assertEqual(first[3], ChannelMux.MType.OPEN)
            self.assertEqual(second[1], ChannelMux.Proto.TUN)
            self.assertEqual(second[3], ChannelMux.MType.DATA)
            self.assertEqual(bytes(second[4]), b'\x45hello')
            self.assertIsNotNone(dev.chan_id)
        finally:
            mux.loop.close()

    def test_local_tun_packet_routes_shared_unicast_only_to_designated_peer_channel(self):
        session = _FakeSession(connected=True)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._overlay_connected = True
            mux._accepting_enabled = True
            spec = ChannelMux.ServiceSpec(
                5,
                'tun',
                'obtun0',
                1500,
                'tun',
                'obtun1',
                1500,
                options={
                    'shared_tun_ownership': {
                        'mode': 'server_shared',
                        'peers': [
                            {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2']},
                            {'peer_ref': 'ios-client', 'ipv4': ['192.168.107.4']},
                        ],
                    }
                },
            )
            svc_key = ('local', 0, 5)
            mux._local_services[svc_key] = spec
            dev = ChannelMux.TunDevice(fd=10, ifname='obtun0', mtu=1500, service_key=svc_key)
            mux._svc_tun_devices[svc_key] = dev
            mux._install_shared_tun_ownership_for_service(svc_key, spec)

            mux._chan_owner_peer_id[11] = 77
            mux._bind_tun_channel(11, dev)
            mux._chan_owner_peer_id[22] = 88
            mux._bind_tun_channel(22, dev)
            mux._shared_tun_guard_inbound_packet(
                dev=dev,
                chan=11,
                packet=_ipv4_packet('192.168.107.2', '192.168.107.1'),
            )
            mux._shared_tun_guard_inbound_packet(
                dev=dev,
                chan=22,
                packet=_ipv4_packet('192.168.107.4', '192.168.107.1'),
            )

            with patch.object(mux, '_send_mux') as send_mux:
                mux._on_local_tun_packet(dev, _ipv4_packet('192.168.107.1', '192.168.107.4'))

            send_mux.assert_called_once_with(22, ChannelMux.Proto.TUN, ChannelMux.MType.DATA, _ipv4_packet('192.168.107.1', '192.168.107.4'))
        finally:
            mux.loop.close()

    def test_local_tun_packet_routes_shared_broadcast_only_to_active_peer_channels(self):
        session = _FakeSession(connected=True)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._overlay_connected = True
            mux._accepting_enabled = True
            spec = ChannelMux.ServiceSpec(
                5,
                'tun',
                'obtun0',
                1500,
                'tun',
                'obtun1',
                1500,
                options={
                    'shared_tun_ownership': {
                        'mode': 'server_shared',
                        'peers': [
                            {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2']},
                            {'peer_ref': 'ios-client', 'ipv4': ['192.168.107.4']},
                        ],
                    }
                },
            )
            svc_key = ('local', 0, 5)
            mux._local_services[svc_key] = spec
            dev = ChannelMux.TunDevice(fd=10, ifname='obtun0', mtu=1500, service_key=svc_key)
            mux._svc_tun_devices[svc_key] = dev
            mux._install_shared_tun_ownership_for_service(svc_key, spec)

            mux._chan_owner_peer_id[11] = 77
            mux._bind_tun_channel(11, dev)
            mux._chan_owner_peer_id[22] = 88
            mux._bind_tun_channel(22, dev)
            mux._shared_tun_guard_inbound_packet(
                dev=dev,
                chan=11,
                packet=_ipv4_packet('192.168.107.2', '192.168.107.1'),
            )
            mux._shared_tun_guard_inbound_packet(
                dev=dev,
                chan=22,
                packet=_ipv4_packet('192.168.107.4', '192.168.107.1'),
            )

            with patch.object(mux, '_send_mux') as send_mux:
                mux._on_local_tun_packet(dev, _ipv4_packet('192.168.107.1', '255.255.255.255'))

            self.assertEqual(
                send_mux.call_args_list,
                [
                    unittest.mock.call(11, ChannelMux.Proto.TUN, ChannelMux.MType.DATA, _ipv4_packet('192.168.107.1', '255.255.255.255')),
                    unittest.mock.call(22, ChannelMux.Proto.TUN, ChannelMux.MType.DATA, _ipv4_packet('192.168.107.1', '255.255.255.255')),
                ],
            )
        finally:
            mux.loop.close()

    def test_local_tun_packet_drops_shared_unknown_destination(self):
        session = _FakeSession(connected=True)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._overlay_connected = True
            mux._accepting_enabled = True
            spec = ChannelMux.ServiceSpec(
                5,
                'tun',
                'obtun0',
                1500,
                'tun',
                'obtun1',
                1500,
                options={
                    'shared_tun_ownership': {
                        'mode': 'server_shared',
                        'peers': [
                            {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2']},
                        ],
                    }
                },
            )
            svc_key = ('local', 0, 5)
            mux._local_services[svc_key] = spec
            dev = ChannelMux.TunDevice(fd=10, ifname='obtun0', mtu=1500, service_key=svc_key)
            mux._svc_tun_devices[svc_key] = dev
            mux._install_shared_tun_ownership_for_service(svc_key, spec)
            mux._chan_owner_peer_id[11] = 77
            mux._bind_tun_channel(11, dev)
            mux._shared_tun_guard_inbound_packet(
                dev=dev,
                chan=11,
                packet=_ipv4_packet('192.168.107.2', '192.168.107.1'),
            )

            with patch.object(mux, '_send_mux') as send_mux:
                mux._on_local_tun_packet(dev, _ipv4_packet('192.168.107.1', '192.168.107.9'))

            send_mux.assert_not_called()
        finally:
            mux.loop.close()

    def test_inbound_shared_tun_packet_relays_to_other_owned_peer_channel(self):
        session = _FakeSession(connected=True)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            spec = ChannelMux.ServiceSpec(
                5,
                'tun',
                'obtun0',
                1500,
                'tun',
                'obtun1',
                1500,
                options={
                    'shared_tun_ownership': {
                        'mode': 'server_shared',
                        'peers': [
                            {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2']},
                            {'peer_ref': 'ios-client', 'ipv4': ['192.168.107.4']},
                        ],
                    }
                },
            )
            svc_key = ('local', 0, 5)
            mux._local_services[svc_key] = spec
            dev = ChannelMux.TunDevice(fd=10, ifname='obtun0', mtu=1500, service_key=svc_key)
            mux._svc_tun_devices[svc_key] = dev
            mux._install_shared_tun_ownership_for_service(svc_key, spec)

            mux._chan_owner_peer_id[11] = 77
            mux._bind_tun_channel(11, dev)
            mux._chan_owner_peer_id[22] = 88
            mux._bind_tun_channel(22, dev)
            mux._shared_tun_guard_inbound_packet(
                dev=dev,
                chan=11,
                packet=_ipv4_packet('192.168.107.2', '192.168.107.1'),
            )
            mux._shared_tun_guard_inbound_packet(
                dev=dev,
                chan=22,
                packet=_ipv4_packet('192.168.107.4', '192.168.107.1'),
            )

            with patch.object(mux, '_send_mux') as send_mux, patch.object(mux, '_write_tun_packet') as write_tun:
                mux._rx_tun_data(11, _ipv4_packet('192.168.107.2', '192.168.107.4'))

            send_mux.assert_called_once_with(22, ChannelMux.Proto.TUN, ChannelMux.MType.DATA, _ipv4_packet('192.168.107.2', '192.168.107.4'))
            write_tun.assert_not_called()
        finally:
            mux.loop.close()

    def test_inbound_shared_tun_packet_unknown_destination_still_writes_local_tun(self):
        session = _FakeSession(connected=True)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            spec = ChannelMux.ServiceSpec(
                5,
                'tun',
                'obtun0',
                1500,
                'tun',
                'obtun1',
                1500,
                options={
                    'shared_tun_ownership': {
                        'mode': 'server_shared',
                        'peers': [
                            {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2']},
                            {'peer_ref': 'ios-client', 'ipv4': ['192.168.107.4']},
                        ],
                    }
                },
            )
            svc_key = ('local', 0, 5)
            mux._local_services[svc_key] = spec
            dev = ChannelMux.TunDevice(fd=10, ifname='obtun0', mtu=1500, service_key=svc_key)
            mux._svc_tun_devices[svc_key] = dev
            mux._install_shared_tun_ownership_for_service(svc_key, spec)

            mux._chan_owner_peer_id[11] = 77
            mux._bind_tun_channel(11, dev)
            mux._shared_tun_guard_inbound_packet(
                dev=dev,
                chan=11,
                packet=_ipv4_packet('192.168.107.2', '192.168.107.1'),
            )

            with patch.object(mux, '_send_mux') as send_mux, patch.object(mux, '_write_tun_packet') as write_tun:
                mux._rx_tun_data(11, _ipv4_packet('192.168.107.2', '8.8.8.8'))

            send_mux.assert_not_called()
            write_tun.assert_called_once_with(dev, _ipv4_packet('192.168.107.2', '8.8.8.8'))
        finally:
            mux.loop.close()

    def test_inbound_shared_tun_packet_sender_owned_destination_does_not_self_loop(self):
        session = _FakeSession(connected=True)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            spec = ChannelMux.ServiceSpec(
                5,
                'tun',
                'obtun0',
                1500,
                'tun',
                'obtun1',
                1500,
                options={
                    'shared_tun_ownership': {
                        'mode': 'server_shared',
                        'peers': [
                            {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2']},
                            {'peer_ref': 'ios-client', 'ipv4': ['192.168.107.4']},
                        ],
                    }
                },
            )
            svc_key = ('local', 0, 5)
            mux._local_services[svc_key] = spec
            dev = ChannelMux.TunDevice(fd=10, ifname='obtun0', mtu=1500, service_key=svc_key)
            mux._svc_tun_devices[svc_key] = dev
            mux._install_shared_tun_ownership_for_service(svc_key, spec)

            mux._chan_owner_peer_id[11] = 77
            mux._bind_tun_channel(11, dev)
            mux._shared_tun_guard_inbound_packet(
                dev=dev,
                chan=11,
                packet=_ipv4_packet('192.168.107.2', '192.168.107.1'),
            )

            with patch.object(mux, '_send_mux') as send_mux, patch.object(mux, '_write_tun_packet') as write_tun:
                mux._rx_tun_data(11, _ipv4_packet('192.168.107.2', '192.168.107.2'))

            send_mux.assert_not_called()
            write_tun.assert_called_once_with(dev, _ipv4_packet('192.168.107.2', '192.168.107.2'))
        finally:
            mux.loop.close()

    def test_local_tun_packet_ignores_transmit_delay_without_buffered_frames(self):
        session = _FakeSession(connected=True, transmit_delay_est_ms=3000.0, waiting_count=0)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._overlay_connected = True
            mux._accepting_enabled = True
            spec = ChannelMux.ServiceSpec(5, 'tun', 'obtun0', 1500, 'tun', 'obtun1', 1500)
            svc_key = ('local', 0, 5)
            mux._local_services[svc_key] = spec
            dev = ChannelMux.TunDevice(fd=10, ifname='obtun0', mtu=1500, service_key=svc_key)
            mux._svc_tun_devices[svc_key] = dev

            mux._on_local_tun_packet(dev, b'\x45hello')

            self.assertEqual(len(session.sent), 2)
            self.assertIsNotNone(dev.chan_id)
        finally:
            mux.loop.close()

    def test_local_tun_packet_throttles_when_buffered_frames_exceed_recent_budget(self):
        session = _FakeSession(connected=True, waiting_count=0)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._overlay_connected = True
            mux._accepting_enabled = True
            spec = ChannelMux.ServiceSpec(5, 'tun', 'obtun0', 1500, 'tun', 'obtun1', 1500)
            svc_key = ('local', 0, 5)
            mux._local_services[svc_key] = spec
            dev = ChannelMux.TunDevice(fd=10, ifname='obtun0', mtu=1500, service_key=svc_key)
            mux._svc_tun_devices[svc_key] = dev

            with patch("obstacle_bridge.bridge_channelmux.time.monotonic_ns", side_effect=[0, 100_000_000, 100_000_000]):
                mux._on_local_tun_packet(dev, b'a' * 100)
                session._metrics.waiting_count = 1
                mux._on_local_tun_packet(dev, b'b' * 80)
                mux._on_local_tun_packet(dev, b'c' * 20)

            self.assertEqual(len(session.sent), 3)
            data_frames = [mux._unpack_mux(frame) for frame in session.sent]
            self.assertEqual(data_frames[0][3], ChannelMux.MType.OPEN)
            self.assertEqual(data_frames[1][3], ChannelMux.MType.DATA)
            self.assertEqual(bytes(data_frames[1][4]), b'a' * 100)
            self.assertEqual(data_frames[2][3], ChannelMux.MType.DATA)
            self.assertEqual(bytes(data_frames[2][4]), b'b' * 80)
        finally:
            mux.loop.close()

    def test_tun_device_keeps_symmetric_channel_aliases_routable(self):
        mux = ChannelMux(_FakeSession(), asyncio.new_event_loop())
        try:
            svc_key = ('local', 0, 5)
            dev = ChannelMux.TunDevice(fd=10, ifname='obtun0', mtu=1500, service_key=svc_key)

            mux._bind_tun_channel(2, dev)
            mux._bind_tun_channel(1, dev)

            self.assertIs(mux._tun_by_chan[2], dev)
            self.assertIs(mux._tun_by_chan[1], dev)
            self.assertEqual(dev.chan_id, 2)
            self.assertEqual(mux._tun_chan_by_service[svc_key], 2)
        finally:
            mux.loop.close()

    def test_send_mux_fragments_oversized_tun_packet(self):
        session = _FakeSession(connected=True, max_app_payload_size=32)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            payload = b'abcdefghijklmnopqrstuvwxyz'
            mux._send_mux(9, ChannelMux.Proto.TUN, ChannelMux.MType.DATA, payload)

            self.assertGreater(len(session.sent), 1)
            rebuilt = bytearray()
            for frame in session.sent:
                parsed = mux._unpack_mux(frame)
                self.assertIsNotNone(parsed)
                chan_id, proto, _counter, mtype, payload_mv = parsed
                self.assertEqual(chan_id, 9)
                self.assertEqual(proto, ChannelMux.Proto.TUN)
                self.assertEqual(mtype, ChannelMux.MType.DATA_FRAG)
                frag = bytes(payload_mv)
                _datagram_id, total_len, offset = ChannelMux.UDP_FRAG_HDR.unpack(frag[:ChannelMux.UDP_FRAG_HDR.size])
                chunk = frag[ChannelMux.UDP_FRAG_HDR.size:]
                self.assertEqual(total_len, len(payload))
                self.assertEqual(offset, len(rebuilt))
                rebuilt.extend(chunk)
            self.assertEqual(bytes(rebuilt), payload)
        finally:
            mux.loop.close()

    def test_reassembles_tun_fragments_before_device_write(self):
        session = _FakeSession()
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._tun_by_chan[12] = ChannelMux.TunDevice(fd=44, ifname='obtun0', mtu=64)
            payload = b'fragmented-tun-packet'
            with patch('obstacle_bridge.bridge.os.write') as os_write:
                for offset in range(0, len(payload), 5):
                    frag_payload = ChannelMux.UDP_FRAG_HDR.pack(31, len(payload), offset) + payload[offset:offset + 5]
                    frame = mux._pack_mux(12, ChannelMux.Proto.TUN, offset // 5, ChannelMux.MType.DATA_FRAG, frag_payload)
                    mux.on_app_payload_from_peer(frame)
                os_write.assert_called_once_with(44, payload)
        finally:
            mux.loop.close()


if __name__ == '__main__':
    unittest.main()
